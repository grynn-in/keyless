"""M-2: responses must not reveal whether an account exists or has passkeys."""

from __future__ import annotations

import secrets
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request
from webauthn.helpers import bytes_to_base64url

from keyless.api import backup, magic_link, otp, passkey
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits

WITH_PASSKEY = "kl-m2-pk@example.com"
NO_PASSKEY = "kl-m2-nopk@example.com"
UNKNOWN = "kl-m2-nobody@example.com"
ALL_ON = {
	"enabled": 1,
	"enable_passkeys": 1,
	"enable_email_otp": 1,
	"enable_magic_link": 1,
	"enable_backup_codes": 1,
	"hide_user_enumeration": 1,
	"rate_limit_per_hour": 50,
}


def outcome(fn, *args, **kwargs):
	"""What a client would see: the return value, or the error type and message."""
	try:
		return ("ok", fn(*args, **kwargs))
	except Exception as e:
		frappe.clear_messages()
		return ("error", type(e).__name__, str(e))


class EnumerationCase(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(WITH_PASSKEY)
		make_user(NO_PASSKEY)
		frappe.get_doc(
			{
				"doctype": "User Passkey",
				"user": WITH_PASSKEY,
				"credential_id": bytes_to_base64url(secrets.token_bytes(16)),
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
				"user_handle": frappe.db.get_value("User", WITH_PASSKEY, "keyless_user_handle"),
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(WITH_PASSKEY)
		delete_user(NO_PASSKEY)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		self.addCleanup(reset_rate_limits)

	def call(self, fn, cmd, **form):
		set_request(method="POST", path=f"/api/method/{cmd}")
		frappe.local.request_ip = "127.0.0.1"
		frappe.local.form_dict = frappe._dict(cmd=cmd, **form)
		# Dispatch like a request does: frappe.call drops arguments fn does not take.
		return outcome(frappe.call, fn, **form)


class TestPasskeyOptions(EnumerationCase):
	def test_options_do_not_depend_on_the_email(self):
		with keyless_settings(**ALL_ON):
			payloads = []
			for email in (WITH_PASSKEY, NO_PASSKEY, UNKNOWN, None):
				result = self.call(
					passkey.authentication_options, "keyless.api.passkey.authentication_options", email=email
				)
				self.assertEqual(result[0], "ok", result)
				payload = dict(result[1])
				payload.pop("challenge")
				payload.pop("challenge_id")
				payloads.append(payload)
		for payload in payloads[1:]:
			self.assertEqual(payload, payloads[0])
		self.assertFalse(payloads[0].get("allowCredentials"))


class TestEmailFactors(EnumerationCase):
	def _both(self, fn, cmd):
		return [self.call(fn, cmd, email=email) for email in (NO_PASSKEY, UNKNOWN)]

	def test_request_otp_same_for_known_and_unknown(self):
		with keyless_settings(**ALL_ON), patch("frappe.sendmail"):
			known, unknown = self._both(otp.request_otp, "keyless.api.otp.request_otp")
		self.assertEqual(known, unknown)

	def test_send_link_same_for_known_and_unknown(self):
		with keyless_settings(**ALL_ON), patch("frappe.sendmail"):
			known, unknown = self._both(magic_link.send_link, "keyless.api.magic_link.send_link")
		self.assertEqual(known, unknown)

	def test_same_response_when_mail_fails(self):
		failing = patch("frappe.sendmail", side_effect=frappe.OutgoingEmailError("no outgoing account"))
		for fn, cmd in (
			(otp.request_otp, "keyless.api.otp.request_otp"),
			(magic_link.send_link, "keyless.api.magic_link.send_link"),
		):
			with self.subTest(cmd=cmd), keyless_settings(**ALL_ON), failing:
				known, unknown = self._both(fn, cmd)
				self.assertEqual(known, unknown)

	def test_mail_failure_message_does_not_reach_the_client(self):
		# Frappe fails through frappe.throw(), which queues the message for the
		# response before raising; catching the exception alone still leaks it.
		def no_outgoing_account(*args, **kwargs):
			frappe.throw("Please setup default outgoing Email Account", frappe.OutgoingEmailError)

		for fn, cmd in (
			(otp.request_otp, "keyless.api.otp.request_otp"),
			(magic_link.send_link, "keyless.api.magic_link.send_link"),
		):
			with (
				self.subTest(cmd=cmd),
				keyless_settings(**ALL_ON),
				patch("frappe.sendmail", side_effect=no_outgoing_account),
			):
				seen = []
				for email in (NO_PASSKEY, UNKNOWN):
					frappe.clear_messages()
					seen.append((self.call(fn, cmd, email=email), list(frappe.local.message_log)))
				self.assertEqual(seen[0], seen[1])
				self.assertEqual(seen[0][1], [])

	def test_mail_is_queued_not_sent_inline(self):
		for fn, cmd in (
			(otp.request_otp, "keyless.api.otp.request_otp"),
			(magic_link.send_link, "keyless.api.magic_link.send_link"),
		):
			with self.subTest(cmd=cmd), keyless_settings(**ALL_ON), patch("frappe.sendmail") as sendmail:
				self.call(fn, cmd, email=NO_PASSKEY)
				sendmail.assert_called_once()
				self.assertFalse(sendmail.call_args.kwargs.get("now"))


class TestBackupRedeem(EnumerationCase):
	def setUp(self):
		super().setUp()
		for _ in range(3):
			frappe.get_doc(
				{"doctype": "Keyless Backup Code", "user": NO_PASSKEY, "code_hash": backup.digest(secrets.token_hex(5))}
			).insert(ignore_permissions=True)
		self.addCleanup(frappe.db.rollback)

	def _redeem(self, email):
		calls = []
		real = backup.compare

		def counting(value, expected):
			calls.append(1)
			return real(value, expected)

		with keyless_settings(**ALL_ON), patch.object(backup, "compare", side_effect=counting):
			result = self.call(backup.redeem, "keyless.api.backup.redeem", email=email, code="WRONGCODE1")
		return result, len(calls)

	def test_unknown_user_and_wrong_code_look_the_same(self):
		wrong, wrong_work = self._redeem(NO_PASSKEY)
		unknown, unknown_work = self._redeem(UNKNOWN)
		self.assertEqual(wrong, unknown)
		self.assertEqual(wrong_work, unknown_work)
		self.assertGreater(unknown_work, 0)
