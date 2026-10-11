"""F-2 (audit of 10 October 2026): a passkey row may only come from a verified
registration by its own user. A System Manager must not be able to add a key
they hold to another account, Administrator included, and every change to a
user's passkeys is logged and notified."""

from __future__ import annotations

import secrets
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request
from webauthn.helpers import bytes_to_base64url

from keyless.tests.security_utils import (
	api_auth_header,
	delete_user,
	http,
	insert_passkey,
	make_user,
	new_client,
)

MANAGER = "kl-f2-manager@example.com"
TARGET = "kl-f2-target@example.com"


def passkey_fields(user, **extra):
	return {
		"doctype": "User Passkey",
		"user": user,
		"credential_id": bytes_to_base64url(secrets.token_bytes(16)),
		"public_key": bytes_to_base64url(secrets.token_bytes(32)),
		"user_handle": frappe.db.get_value("User", user, "keyless_user_handle"),
		**extra,
	}


class TestPasskeysOnlyFromRegistration(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(MANAGER, user_type="System User", roles=("System Manager",))
		make_user(TARGET)
		cls.headers = api_auth_header(MANAGER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		frappe.db.delete("Keyless Audit Log", {"user": TARGET})
		delete_user(MANAGER)
		delete_user(TARGET)
		super().tearDownClass()

	def setUp(self):
		# A fresh request with no after_response, so audit rows go straight into
		# this transaction rather than to a callback left by an earlier test.
		set_request(method="POST", path="/api/method/ping")
		self.addCleanup(frappe.set_user, "Administrator")
		self.addCleanup(self.remove_rows)

	def remove_rows(self):
		frappe.db.rollback()
		frappe.db.delete("User Passkey", {"friendly_name": "kl-f2"})
		frappe.db.commit()

	def test_system_manager_cannot_create_via_rest(self):
		for user in (TARGET, "Administrator"):
			with self.subTest(user=user):
				fields = passkey_fields(user, friendly_name="kl-f2")
				response = http(new_client(), "post", "/api/resource/User Passkey", json=fields, headers=self.headers)
				frappe.db.rollback()
				self.assertEqual(response.status_code, 403, response.get_data(as_text=True)[:300])
				self.assertFalse(frappe.db.exists("User Passkey", {"credential_id": fields["credential_id"]}))

	def test_server_code_cannot_insert_without_a_registration(self):
		# Even Administrator with ignore_permissions, as Desk, Data Import or a
		# script would.
		for user in (TARGET, "Administrator"):
			with self.subTest(user=user):
				doc = frappe.get_doc(passkey_fields(user, friendly_name="kl-f2"))
				with self.assertRaises(frappe.PermissionError):
					doc.insert(ignore_permissions=True)

	def test_registration_must_be_for_the_rows_user(self):
		doc = frappe.get_doc(passkey_fields(TARGET, friendly_name="kl-f2"))
		doc.flags.keyless_registered_user = MANAGER
		with self.assertRaises(frappe.PermissionError):
			doc.insert(ignore_permissions=True)

	def test_only_administrator_may_add_an_administrator_passkey(self):
		frappe.set_user(MANAGER)
		with self.assertRaises(frappe.PermissionError):
			insert_passkey(passkey_fields("Administrator", friendly_name="kl-f2"))
		frappe.set_user("Administrator")
		self.assertTrue(insert_passkey(passkey_fields("Administrator", friendly_name="kl-f2")).name)

	def test_user_handle_must_be_the_users(self):
		for handle in (secrets.token_hex(16), frappe.db.get_value("User", MANAGER, "keyless_user_handle")):
			with self.subTest(handle=handle), self.assertRaises(frappe.ValidationError):
				insert_passkey(passkey_fields(TARGET, user_handle=handle, friendly_name="kl-f2"))

	def test_desk_or_rest_delete_by_a_system_manager_is_logged_and_notified(self):
		doc = insert_passkey(passkey_fields(TARGET, friendly_name="kl-f2"))
		frappe.db.commit()
		with patch("frappe.sendmail") as sendmail:
			response = http(new_client(), "delete", f"/api/resource/User Passkey/{doc.name}", headers=self.headers)
		self.assertIn(response.status_code, (200, 202), response.get_data(as_text=True)[:300])
		frappe.db.rollback()
		self.assertFalse(frappe.db.exists("User Passkey", doc.name))
		self.assertTrue(
			frappe.db.exists(
				"Keyless Audit Log", {"user": TARGET, "event": "passkey_revoked", "detail": f"{doc.name} by {MANAGER}"}
			)
		)
		recipients = [str(call.kwargs.get("recipients")) for call in sendmail.call_args_list]
		self.assertTrue(any(TARGET in r for r in recipients), recipients)

	def test_registration_is_logged(self):
		doc = insert_passkey(passkey_fields(TARGET, friendly_name="kl-f2"))
		row = {"user": TARGET, "event": "passkey_registered", "detail": f"{doc.name} by Administrator"}
		self.assertTrue(frappe.db.exists("Keyless Audit Log", row))
