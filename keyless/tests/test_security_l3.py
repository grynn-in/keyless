"""L-3: py_webauthn's internal error text stays in the audit log, not the response."""

from __future__ import annotations

import json
import secrets
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse

from keyless.api import passkey
from keyless.tests.security_utils import keyless_settings, reset_rate_limits

INTERNAL = "Unexpected client data origin internal-detail-7f3a"
ON = {"enabled": 1, "enable_passkeys": 1, "rp_id": "", "allowed_origins": ""}


class TestWebAuthnErrorText(FrappeTestCase):
	def setUp(self):
		reset_rate_limits()
		frappe.set_user("Administrator")
		self.addCleanup(frappe.db.rollback)
		set_request(method="POST", path="/api/method/keyless.api.passkey.verify_authentication")
		frappe.local.request_ip = "127.0.0.1"

	def _audit_details(self, event):
		return frappe.get_all("Keyless Audit Log", filters={"event": event}, pluck="detail", order_by="creation desc")

	def test_failed_sign_in_hides_library_text(self):
		handle = frappe.db.get_value("User", "Administrator", "keyless_user_handle")
		if not handle:
			from keyless.user import ensure_user_handle

			handle = ensure_user_handle("Administrator")
		credential_id = bytes_to_base64url(secrets.token_bytes(16))
		frappe.get_doc(
			{
				"doctype": "User Passkey",
				"user": "Administrator",
				"credential_id": credential_id,
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
				"user_handle": handle,
			}
		).insert(ignore_permissions=True)
		cred = {
			"id": credential_id,
			"rawId": credential_id,
			"type": "public-key",
			"response": {"userHandle": bytes_to_base64url(passkey._handle_bytes(handle))},
		}
		with (
			keyless_settings(**ON),
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "authentication", "user": None, "challenge": "Y2hhbGxlbmdl"},
			),
			patch("webauthn.verify_authentication_response", side_effect=InvalidAuthenticationResponse(INTERNAL)),
		):
			with self.assertRaises(frappe.AuthenticationError) as caught:
				passkey.verify_authentication(json.dumps(cred), "cid")
		self.assertNotIn("internal-detail", str(caught.exception))
		self.assertNotIn("internal-detail", json.dumps(frappe.local.message_log, default=str))
		self.assertTrue(any("internal-detail" in (d or "") for d in self._audit_details("passkey_failed")))

	def test_failed_registration_hides_library_text(self):
		cred = {"id": "x", "rawId": "x", "type": "public-key", "response": {}}
		with (
			keyless_settings(**ON),
			patch.object(passkey.stepup, "require"),
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "registration", "user": "Administrator", "challenge": "Y2hhbGxlbmdl"},
			),
			patch("webauthn.verify_registration_response", side_effect=InvalidRegistrationResponse(INTERNAL)),
		):
			with self.assertRaises(frappe.AuthenticationError) as caught:
				passkey.verify_registration(cred, "cid")
		self.assertNotIn("internal-detail", str(caught.exception))
		self.assertTrue(any("internal-detail" in (d or "") for d in self._audit_details("passkey_register_failed")))


class TestAuditEventNames(FrappeTestCase):
	"""log_event swallows its own errors, so an event name the Select does not list
	would silently never be recorded."""

	def test_every_logged_event_is_a_valid_option(self):
		import re
		from pathlib import Path

		app = Path(frappe.get_app_path("keyless"))
		used = set()
		for path in app.rglob("*.py"):
			if "tests" in path.parts:
				continue
			used |= set(re.findall(r'log_event\(\s*"([a-z_]+)"', path.read_text()))
		options = set(frappe.get_meta("Keyless Audit Log").get_field("event").options.split("\n"))
		self.assertTrue(used)
		self.assertEqual(sorted(used - options), [])
