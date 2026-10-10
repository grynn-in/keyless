"""L-4: audit logging must not commit the caller's transaction, must survive a
failed request, and must not store the raw X-Forwarded-For header."""

from __future__ import annotations

import secrets
from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless import notify
from keyless.api import passkey
from keyless.audit import log_event
from keyless.tests.security_utils import (
	api_auth_header,
	delete_user,
	http,
	keyless_settings,
	make_user,
	new_client,
	reset_rate_limits,
)

USER = "kl-l4-user@example.com"


def fake_registration(**kwargs):
	return SimpleNamespace(
		credential_id=secrets.token_bytes(16),
		credential_public_key=secrets.token_bytes(32),
		sign_count=0,
		aaguid=None,
		credential_backed_up=False,
	)


class TestFailedRequest(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER, user_type="System User", roles=("System Manager",))
		cls.headers = api_auth_header(USER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		frappe.db.delete("Keyless Audit Log", {"user": USER})
		delete_user(USER)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		frappe.db.delete("Keyless Audit Log", {"user": USER})
		frappe.db.delete("User Passkey", {"user": USER})
		frappe.db.commit()

	def test_failure_after_logging_leaves_no_partial_writes_but_keeps_the_audit_row(self):
		with (
			keyless_settings(enabled=1, enable_passkeys=1, rp_id="", allowed_origins=""),
			patch.object(passkey.stepup, "require"),
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "registration", "user": USER, "challenge": "Y2hhbGxlbmdl"},
			),
			patch("webauthn.verify_registration_response", side_effect=fake_registration),
			patch.object(notify, "sign_in_methods_changed", side_effect=RuntimeError("mail system down")),
		):
			response = http(
				new_client(),
				"post",
				"/api/method/keyless.api.passkey.verify_registration",
				json={"credential": {"id": "x", "rawId": "x", "type": "public-key", "response": {}}, "challenge_id": "c"},
				headers=self.headers,
			)
		frappe.db.rollback()  # see what the request committed
		self.assertGreaterEqual(response.status_code, 500, response.get_data(as_text=True)[:300])
		self.assertFalse(frappe.db.exists("User Passkey", {"user": USER}), "orphan passkey row was committed")
		self.assertTrue(
			frappe.db.exists("Keyless Audit Log", {"user": USER, "event": "passkey_registered"}),
			"the audit row for the failed request was lost",
		)


class TestNoCommitAndNoRawHeader(FrappeTestCase):
	def tearDown(self):
		frappe.db.rollback()

	def test_logging_does_not_commit_the_callers_work(self):
		set_request(method="POST", path="/api/method/x")
		frappe.local.request_ip = "10.1.1.1"
		todo = frappe.get_doc({"doctype": "ToDo", "description": "kl-l4 must roll back"}).insert()
		log_event("login", user="Administrator", method="test", success=True)
		frappe.db.rollback()
		self.assertFalse(frappe.db.exists("ToDo", todo.name))

	def test_raw_forwarded_for_is_never_stored(self):
		raw = "6.6.6.6, 10.0.0.1"
		set_request(method="POST", path="/api/method/x", headers={"X-Forwarded-For": raw})
		for request_ip in (None, "10.1.1.1"):
			with self.subTest(request_ip=request_ip):
				frappe.local.request_ip = request_ip
				marker = frappe.generate_hash(length=10)
				log_event("login", user="Administrator", method=marker, success=True)
				ip = frappe.db.get_value("Keyless Audit Log", {"method": marker}, "ip_address")
				self.assertNotIn("6.6.6.6", ip or "")
				self.assertEqual(ip or "", request_ip or "")
