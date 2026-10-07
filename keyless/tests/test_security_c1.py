"""C-1: a User Passkey must not be creatable, re-pointable or rewritable by its owner."""

from __future__ import annotations

import json
import secrets
from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from webauthn.helpers import bytes_to_base64url

from keyless.api import passkey
from keyless.tests.security_utils import api_auth_header, delete_user, http, make_user, new_client

LOW_USER = "kl-c1-low@example.com"
LOCKED_FIELDS = ("user", "credential_id", "public_key", "user_handle")


def _handle_bytes(handle: str) -> bytes:
	return bytes.fromhex(handle) if len(handle) == 32 else handle.encode("utf-8")


class TestUserPasskeyPermissions(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(LOW_USER)
		cls.headers = api_auth_header(LOW_USER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(LOW_USER)
		super().tearDownClass()

	def _make_passkey(self, user=LOW_USER, owner=LOW_USER):
		doc = frappe.get_doc(
			{
				"doctype": "User Passkey",
				"user": user,
				"credential_id": bytes_to_base64url(secrets.token_bytes(16)),
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
				"user_handle": frappe.db.get_value("User", user, "keyless_user_handle"),
				"friendly_name": "test key",
			}
		)
		doc.insert(ignore_permissions=True)
		frappe.db.set_value("User Passkey", doc.name, "owner", owner, update_modified=False)
		frappe.db.commit()
		self.addCleanup(self._cleanup, doc.name)
		return doc

	def _cleanup(self, name):
		frappe.db.delete("User Passkey", {"name": name})
		frappe.db.commit()

	def test_low_privilege_user_cannot_create_passkey_via_rest(self):
		before = frappe.db.count("User Passkey", {"user": LOW_USER})
		response = http(
			new_client(),
			"post",
			"/api/resource/User Passkey",
			json={
				"credential_id": bytes_to_base64url(secrets.token_bytes(16)),
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
			},
			headers=self.headers,
		)
		frappe.db.rollback()
		created = frappe.get_all("User Passkey", filters={"user": LOW_USER}, pluck="name")
		for name in created:
			self.addCleanup(self._cleanup, name)
		self.assertIn(response.status_code, (403, 401), response.get_data(as_text=True)[:300])
		self.assertEqual(len(created), before)

	def test_owner_cannot_repoint_passkey_via_rest(self):
		doc = self._make_passkey()
		response = http(
			new_client(),
			"put",
			f"/api/resource/User Passkey/{doc.name}",
			json={"user": "Administrator"},
			headers=self.headers,
		)
		frappe.db.rollback()
		self.assertIn(response.status_code, (403, 401, 417), response.get_data(as_text=True)[:300])
		self.assertEqual(frappe.db.get_value("User Passkey", doc.name, "user"), LOW_USER)

	def test_owner_cannot_read_or_delete_via_rest(self):
		doc = self._make_passkey()
		client = new_client()
		self.assertIn(
			http(client, "get", f"/api/resource/User Passkey/{doc.name}", headers=self.headers).status_code,
			(403, 401),
		)
		self.assertIn(
			http(client, "delete", f"/api/resource/User Passkey/{doc.name}", headers=self.headers).status_code,
			(403, 401),
		)
		frappe.db.rollback()
		self.assertTrue(frappe.db.exists("User Passkey", doc.name))

	def test_locked_fields_cannot_change_even_with_ignore_permissions(self):
		doc = self._make_passkey()
		new_values = {
			"user": "Administrator",
			"credential_id": bytes_to_base64url(secrets.token_bytes(16)),
			"public_key": bytes_to_base64url(secrets.token_bytes(32)),
			"user_handle": secrets.token_hex(16),
		}
		for field in LOCKED_FIELDS:
			with self.subTest(field=field):
				fresh = frappe.get_doc("User Passkey", doc.name)
				fresh.set(field, new_values[field])
				fresh.flags.ignore_permissions = True
				with self.assertRaises(frappe.ValidationError):
					fresh.save()
				frappe.db.rollback()
				self.assertEqual(frappe.db.get_value("User Passkey", doc.name, field), doc.get(field))

	def test_report_flags_repointed_rows_without_changing_them(self):
		from keyless.security import report_repointed_passkeys

		clean = self._make_passkey()
		repointed = self._make_passkey(user="Administrator", owner=LOW_USER)
		flagged = {row.name for row in report_repointed_passkeys()}
		self.assertIn(repointed.name, flagged)
		self.assertNotIn(clean.name, flagged)
		self.assertEqual(frappe.db.get_value("User Passkey", repointed.name, "user"), "Administrator")

	def test_owner_can_still_revoke_own_passkey_via_keyless_api(self):
		doc = self._make_passkey()
		frappe.set_user(LOW_USER)
		try:
			passkey.revoke_passkey(doc.name)
		finally:
			frappe.set_user("Administrator")
		self.assertFalse(frappe.db.exists("User Passkey", doc.name))

	def test_other_user_cannot_revoke_via_keyless_api(self):
		doc = self._make_passkey(user="Administrator", owner="Administrator")
		frappe.set_user(LOW_USER)
		try:
			with self.assertRaises(frappe.PermissionError):
				passkey.revoke_passkey(doc.name)
		finally:
			frappe.set_user("Administrator")
		self.assertTrue(frappe.db.exists("User Passkey", doc.name))

	def test_owner_can_still_list_own_passkeys_via_keyless_api(self):
		doc = self._make_passkey()
		frappe.set_user(LOW_USER)
		try:
			names = [row.name for row in passkey.list_passkeys()]
		finally:
			frappe.set_user("Administrator")
		self.assertEqual(names, [doc.name])

	def test_friendly_name_is_still_editable(self):
		doc = self._make_passkey()
		fresh = frappe.get_doc("User Passkey", doc.name)
		fresh.friendly_name = "renamed"
		fresh.save(ignore_permissions=True)
		self.assertEqual(frappe.db.get_value("User Passkey", doc.name, "friendly_name"), "renamed")
		frappe.db.rollback()


class TestAssertionUserHandle(FrappeTestCase):
	"""verify_authentication must bind the assertion's userHandle to passkey.user."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(LOW_USER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(LOW_USER)
		super().tearDownClass()

	def setUp(self):
		self.credential_id = bytes_to_base64url(secrets.token_bytes(16))
		frappe.get_doc(
			{
				"doctype": "User Passkey",
				"user": LOW_USER,
				"credential_id": self.credential_id,
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
				"user_handle": frappe.db.get_value("User", LOW_USER, "keyless_user_handle"),
			}
		).insert(ignore_permissions=True)
		self.patches = [
			patch.object(
				passkey,
				"require_enabled",
				return_value=frappe._dict(enable_passkeys=1, passkey_user_verification="required"),
			),
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "authentication", "user": None, "challenge": "Y2hhbGxlbmdl"},
			),
			patch.object(passkey, "client_origin", return_value="http://localhost"),
			patch.object(passkey, "rp_id", return_value="localhost"),
			patch.object(passkey, "log_event"),
			patch(
				"webauthn.verify_authentication_response",
				return_value=SimpleNamespace(new_sign_count=1),
			),
		]
		for p in self.patches:
			p.start()
		self.issue = patch.object(passkey, "issue_session").start()
		self.patches.append(self.issue)

	def tearDown(self):
		patch.stopall()
		frappe.db.rollback()

	def _credential(self, user_handle: bytes | None):
		response = {"clientDataJSON": "e30", "authenticatorData": "AA", "signature": "AA"}
		if user_handle is not None:
			response["userHandle"] = bytes_to_base64url(user_handle)
		return json.dumps({"id": self.credential_id, "rawId": self.credential_id, "type": "public-key", "response": response})

	def test_mismatched_user_handle_is_rejected(self):
		admin_handle = frappe.db.get_value("User", "Administrator", "keyless_user_handle") or secrets.token_hex(16)
		with self.assertRaises(frappe.AuthenticationError):
			passkey.verify_authentication(self._credential(_handle_bytes(admin_handle)), "cid")
		self.issue.assert_not_called()

	def test_missing_user_handle_is_rejected(self):
		with self.assertRaises(frappe.AuthenticationError):
			passkey.verify_authentication(self._credential(None), "cid")
		self.issue.assert_not_called()

	def test_matching_user_handle_signs_in(self):
		handle = frappe.db.get_value("User", LOW_USER, "keyless_user_handle")
		result = passkey.verify_authentication(self._credential(_handle_bytes(handle)), "cid")
		self.assertEqual(result["user"], LOW_USER)
		self.issue.assert_called_once_with(LOW_USER, method="passkey")
