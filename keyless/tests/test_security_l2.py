"""L-2: one shared IP (an office behind NAT) must not lock out everyone after a
handful of sign-ins; per-account limits still hold."""

from __future__ import annotations

import json
import secrets
from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request
from webauthn.helpers import bytes_to_base64url

from keyless.api import otp, passkey
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits

USERS = [f"kl-l2-{i}@example.com" for i in range(4)]
OFFICE_IP = "198.51.100.7"
ON = {
	"enabled": 1,
	"enable_passkeys": 1,
	"enable_email_otp": 1,
	"rate_limit_per_hour": 5,
	"otp_daily_limit": 10,
	"rp_id": "",
	"allowed_origins": "",
}


def from_office(cmd, **form):
	set_request(method="POST", path=f"/api/method/{cmd}")
	frappe.local.request_ip = OFFICE_IP
	frappe.local.form_dict = frappe._dict(cmd=cmd, **form)


class TestSharedIP(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		cls.passkeys = {}
		for user in USERS:
			make_user(user)
			credential_id = bytes_to_base64url(secrets.token_bytes(16))
			frappe.get_doc(
				{
					"doctype": "User Passkey",
					"user": user,
					"credential_id": credential_id,
					"public_key": bytes_to_base64url(secrets.token_bytes(32)),
					"user_handle": frappe.db.get_value("User", user, "keyless_user_handle"),
				}
			).insert(ignore_permissions=True)
			cls.passkeys[user] = credential_id
		frappe.db.commit()

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		for user in USERS:
			delete_user(user)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		self.addCleanup(reset_rate_limits)
		self.settings = keyless_settings(**ON)
		self.settings.__enter__()
		self.addCleanup(self.settings.__exit__, None, None, None)

	def test_many_passkey_sign_ins_from_one_ip(self):
		with (
			patch("webauthn.verify_authentication_response", return_value=SimpleNamespace(new_sign_count=1)),
			patch.object(passkey, "issue_session") as issue,
			patch.object(passkey, "log_event"),
		):
			for i in range(12):
				user = USERS[i % len(USERS)]
				from_office("keyless.api.passkey.authentication_options")
				options = passkey.authentication_options()
				handle = frappe.db.get_value("User", user, "keyless_user_handle")
				cred = {
					"id": self.passkeys[user],
					"rawId": self.passkeys[user],
					"type": "public-key",
					"response": {"userHandle": bytes_to_base64url(passkey._handle_bytes(handle))},
				}
				from_office("keyless.api.passkey.verify_authentication")
				passkey.verify_authentication(json.dumps(cred), options["challenge_id"])
		self.assertEqual(issue.call_count, 12)

	def test_many_people_request_codes_from_one_ip(self):
		with patch.object(otp, "_send_otp_mail"), patch.object(otp, "log_event"):
			for i in range(10):
				email = f"kl-l2-person{i}@example.com"
				from_office("keyless.api.otp.request_otp", email=email)
				self.assertTrue(otp.request_otp(email)["ok"])

	def test_one_account_is_still_limited(self):
		with patch.object(otp, "_send_otp_mail"), patch.object(otp, "log_event"):
			for _ in range(5):
				from_office("keyless.api.otp.request_otp", email=USERS[0])
				otp.request_otp(USERS[0])
			from_office("keyless.api.otp.request_otp", email=USERS[0])
			with self.assertRaises(frappe.RateLimitExceededError):
				otp.request_otp(USERS[0])


class TestAccountLimitsAcrossIPs(FrappeTestCase):
	"""Per-account limits that replace the old low per-IP limits (L-2)."""

	def setUp(self):
		reset_rate_limits()
		self.addCleanup(reset_rate_limits)
		self.ip = 0

	def _new_ip(self, cmd, **form):
		self.ip += 1
		set_request(method="POST", path=f"/api/method/{cmd}")
		frappe.local.request_ip = f"203.0.113.{self.ip}"
		frappe.local.form_dict = frappe._dict(cmd=cmd, **form)

	def test_magic_links_per_account(self):
		from keyless.api import magic_link

		with (
			keyless_settings(enabled=1, enable_magic_link=1, rate_limit_per_hour=3, otp_daily_limit=10),
			patch.object(magic_link, "_send_link_mail"),
			patch.object(magic_link, "log_event"),
		):
			for _ in range(3):
				self._new_ip("keyless.api.magic_link.send_link", email=USERS[0])
				magic_link.send_link(USERS[0])
			self._new_ip("keyless.api.magic_link.send_link", email=USERS[0])
			with self.assertRaises(frappe.RateLimitExceededError):
				magic_link.send_link(USERS[0])

	def test_wrong_backup_codes_per_account(self):
		from keyless.api import backup

		with keyless_settings(enabled=1, enable_backup_codes=1), patch.object(backup, "log_event"):
			for _ in range(backup.BACKUP_FAILURES_PER_HOUR):
				self._new_ip("keyless.api.backup.redeem", email=USERS[0])
				with self.assertRaises(frappe.AuthenticationError):
					backup.redeem(USERS[0], "WRONGCODE1")
			self._new_ip("keyless.api.backup.redeem", email=USERS[0])
			with self.assertRaises(frappe.RateLimitExceededError):
				backup.redeem(USERS[0], "WRONGCODE1")
