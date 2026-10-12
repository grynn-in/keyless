"""F-4 (audit 2026-10-10): sign-in codes and links must go to the account's stored
address, and their state and limits must belong to the account.

The database finds an account without regard to accents (utf8mb4_unicode_ci), so an
address that differs from the stored one only in accents reaches the same account.
Mail went to the address as typed, and codes, links and limits were kept per typed
string, so every spelling of one account had a budget of its own. Addresses with no
account must still get exactly the same answer as before (M-2)."""

from __future__ import annotations

from contextlib import ExitStack
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless.api import backup, magic_link, otp
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits

USER = "kl-f4-user@example.com"
# Differs from USER only in an accent and in case: the database matches it to USER.
VARIANT = "KL-F4-ÜSER@example.com"
UNKNOWN = "kl-f4-nobody@example.com"
UNKNOWN_VARIANT = "kl-f4-nöbody@example.com"
LIMIT = 4  # Rate Limit per Hour for these tests
ON = {
	"enabled": 1,
	"enable_email_otp": 1,
	"enable_magic_link": 1,
	"enable_backup_codes": 1,
	"hide_user_enumeration": 1,
	"rate_limit_per_hour": LIMIT,
	"otp_daily_limit": 1000,
	"max_otp_attempts": 3,
	"otp_expiry_seconds": 300,
	"otp_length": 6,
	"require_passkey_for_system_users": 0,
}


def call(fn, cmd: str, ip: str = "198.51.100.40", **form):
	set_request(method="POST", path=f"/api/method/{cmd}")
	frappe.local.request_ip = ip
	frappe.local.form_dict = frappe._dict(cmd=cmd, **form)
	return fn(**form)


class StoredEmailCase(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(USER)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		self.addCleanup(reset_rate_limits)
		# On Frappe 15, frappe.cache.get_value keeps what it read (even "no code") in
		# frappe.local.cache, which lives for the whole test run here; clear it so a
		# code stored in Redis by this test is seen.
		if isinstance(getattr(frappe.local, "cache", None), dict):
			frappe.local.cache.clear()
		self.assertEqual(
			frappe.db.get_value("User", {"name": VARIANT.lower()}, "name"),
			USER,
			"the test database must match addresses without regard to accents",
		)
		stack = ExitStack()
		stack.enter_context(keyless_settings(**ON))
		self.sendmail = stack.enter_context(patch("frappe.sendmail"))
		self.issue = stack.enter_context(patch.object(otp, "issue_session"))
		stack.enter_context(patch.object(magic_link, "issue_session"))
		for module in (otp, magic_link, backup):
			stack.enter_context(patch.object(module, "log_event"))
		self.addCleanup(stack.close)

	def request_code(self, email, **kw):
		return call(otp.request_otp, "keyless.api.otp.request_otp", email=email, **kw)

	def verify_code(self, email, code, **kw):
		return call(otp.verify_otp, "keyless.api.otp.verify_otp", email=email, otp=code, **kw)

	def send_link(self, email, **kw):
		return call(magic_link.send_link, "keyless.api.magic_link.send_link", email=email, **kw)

	def redeem(self, email, **kw):
		return call(backup.redeem, "keyless.api.backup.redeem", email=email, code="WRONGCODE1", **kw)

	def recipients(self):
		return [c.kwargs.get("recipients") for c in self.sendmail.call_args_list]

	def last_code(self):
		return self.sendmail.call_args.kwargs["args"]["otp"]


class TestMailGoesToStoredAddress(StoredEmailCase):
	def test_code_goes_to_stored_address(self):
		self.assertTrue(self.request_code(VARIANT)["ok"])
		self.assertEqual(self.recipients(), [USER])

	def test_link_goes_to_stored_address(self):
		self.assertTrue(self.send_link(VARIANT)["ok"])
		self.assertEqual(self.recipients(), [USER])

	def test_code_requested_with_a_variant_works_with_the_stored_address(self):
		self.request_code(VARIANT)
		self.verify_code(USER, self.last_code())
		self.issue.assert_called_once_with(USER, method="email_otp")

	def test_normal_sign_in_still_works(self):
		self.request_code(USER)
		self.assertEqual(self.recipients(), [USER])
		with self.assertRaises(frappe.AuthenticationError):
			self.verify_code(USER, "000000")
		self.verify_code(USER, self.last_code())
		self.issue.assert_called_once_with(USER, method="email_otp")


class TestLimitsBelongToTheAccount(StoredEmailCase):
	def test_spellings_share_the_code_request_limit(self):
		for i in range(LIMIT):
			self.request_code((USER, VARIANT)[i % 2])
		with self.assertRaises(frappe.RateLimitExceededError):
			self.request_code(VARIANT)

	def test_spellings_share_the_link_request_limit(self):
		for i in range(LIMIT):
			self.send_link((USER, VARIANT)[i % 2])
		with self.assertRaises(frappe.RateLimitExceededError):
			self.send_link(VARIANT)

	def test_spellings_share_the_wrong_guess_limit(self):
		guesses = ON["max_otp_attempts"] * otp.ACCOUNT_GUESS_FACTOR
		for i in range(guesses):
			with self.assertRaises(frappe.AuthenticationError):
				self.verify_code((USER, VARIANT)[i % 2], "000000")
		with self.assertRaises(frappe.RateLimitExceededError):
			self.verify_code(VARIANT, "000000")

	def test_spellings_share_the_recovery_code_limit(self):
		for i in range(backup.BACKUP_FAILURES_PER_HOUR):
			with self.assertRaises(frappe.AuthenticationError):
				self.redeem((USER, VARIANT)[i % 2])
		with self.assertRaises(frappe.RateLimitExceededError):
			self.redeem(VARIANT)

	def test_owner_elsewhere_is_not_locked_out(self):
		for _ in range(LIMIT):
			self.request_code(VARIANT, ip="198.51.100.66")
		self.assertTrue(self.request_code(USER, ip="192.0.2.10")["ok"])


class TestUnknownAddressesUnchanged(StoredEmailCase):
	def test_same_answer_and_no_mail(self):
		known_code = self.request_code(USER)
		known_link = self.send_link(USER)
		self.sendmail.reset_mock()
		for unknown in (UNKNOWN, UNKNOWN_VARIANT):
			self.assertEqual(self.request_code(unknown), known_code)
			self.assertEqual(self.send_link(unknown), known_link)
		self.sendmail.assert_not_called()

	def test_unknown_spellings_share_a_limit_as_known_ones_do(self):
		# Otherwise sharing a budget across spellings would show that an account exists.
		for i in range(LIMIT):
			self.request_code((UNKNOWN, UNKNOWN_VARIANT)[i % 2])
		with self.assertRaises(frappe.RateLimitExceededError):
			self.request_code(UNKNOWN_VARIANT)

	def test_no_active_user_message_when_enumeration_is_shown(self):
		with keyless_settings(hide_user_enumeration=0):
			with self.assertRaises(frappe.DoesNotExistError):
				self.request_code(UNKNOWN)
			self.assertTrue(self.request_code(VARIANT)["ok"])
		self.assertEqual(self.recipients(), [USER])
