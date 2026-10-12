"""G-5 (audit 2026-10-12): limits kept per address and client IP must treat one IPv6
/64 as one client. A single IPv6 host usually controls a whole /64, so counting each
address separately let it skip the per-IP limit and run an account into its
account-wide backstop. IPv4 addresses are still counted one by one, and the
account-wide limits do not depend on the IP at all."""

from __future__ import annotations

from contextlib import ExitStack
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless.api import backup, magic_link, otp
from keyless.api.common import ACCOUNT_BACKSTOP_FACTOR
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits

USER = "kl-g5-user@example.com"
LIMIT = 3  # Rate Limit per Hour for these tests


def from_ip(cmd: str, ip: str, **form) -> None:
	set_request(method="POST", path=f"/api/method/{cmd}")
	frappe.local.request_ip = ip
	frappe.local.form_dict = frappe._dict(cmd=cmd, **form)


class TestIPv6Prefix(FrappeTestCase):
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
		stack = ExitStack()
		stack.enter_context(
			keyless_settings(
				enabled=1,
				enable_magic_link=1,
				enable_email_otp=1,
				enable_backup_codes=1,
				hide_user_enumeration=1,
				rate_limit_per_hour=LIMIT,
				otp_daily_limit=1000,
			)
		)
		stack.enter_context(patch.object(magic_link, "_send_link_mail"))
		stack.enter_context(patch.object(magic_link, "log_event"))
		stack.enter_context(patch.object(otp, "_send_otp_mail"))
		stack.enter_context(patch.object(otp, "log_event"))
		stack.enter_context(patch.object(backup, "log_event"))
		self.addCleanup(stack.close)

	def _send(self, ip: str):
		from_ip("keyless.api.magic_link.send_link", ip, email=USER)
		return magic_link.send_link(USER)

	def _request_code(self, ip: str):
		from_ip("keyless.api.otp.request_otp", ip, email=USER)
		return otp.request_otp(USER)

	def _redeem(self, ip: str):
		from_ip("keyless.api.backup.redeem", ip, email=USER)
		return backup.redeem(USER, "WRONGCODE1")

	# The attack: one host rotating through its /64.

	def test_magic_links_one_ipv6_64_is_one_client(self):
		for i in range(LIMIT):
			self._send(f"2001:db8:1:2::{i + 1:x}")
		with self.assertRaises(frappe.RateLimitExceededError):
			self._send("2001:db8:1:2:ffff:ffff:ffff:fff0")

	def test_codes_one_ipv6_64_is_one_client(self):
		for i in range(LIMIT):
			self._request_code(f"2001:db8:1:2:{i + 1:x}::1")
		with self.assertRaises(frappe.RateLimitExceededError):
			self._request_code("2001:db8:1:2:abcd::99")

	def test_recovery_codes_one_ipv6_64_is_one_client(self):
		for i in range(backup.BACKUP_FAILURES_PER_HOUR):
			with self.assertRaises(frappe.AuthenticationError):
				self._redeem(f"2001:db8:1:2::{i + 1:x}")
		with self.assertRaises(frappe.RateLimitExceededError):
			self._redeem("2001:db8:1:2::ffff")

	def test_ipv6_spellings_of_one_64_share_a_bucket(self):
		# Upper case, leading zeros and an unabbreviated form are the same network.
		self._send("2001:db8:1:2::1")
		self._send("2001:DB8:1:2::2")
		self._send("2001:0db8:0001:0002:0000:0000:0000:0003")
		with self.assertRaises(frappe.RateLimitExceededError):
			self._send("2001:db8:1:2::4")

	# The legitimate paths still work.

	def test_owner_in_another_ipv6_64_still_gets_a_link(self):
		for i in range(LIMIT):
			self._send(f"2001:db8:1:2::{i + 1:x}")
		self.assertTrue(self._send("2001:db8:1:3::1")["ok"])

	def test_ipv4_addresses_still_counted_one_by_one(self):
		for _ in range(LIMIT):
			self._send("198.51.100.1")
		with self.assertRaises(frappe.RateLimitExceededError):
			self._send("198.51.100.1")
		# A neighbouring IPv4 address is a different client.
		self.assertTrue(self._send("198.51.100.2")["ok"])

	def test_account_backstop_holds_across_ipv6_networks(self):
		for i in range(LIMIT * ACCOUNT_BACKSTOP_FACTOR):
			self._send(f"2001:db8:{i + 1:x}::1")
		with self.assertRaises(frappe.RateLimitExceededError):
			self._send("2001:db8:ffff::1")

	def test_wrong_code_limit_does_not_depend_on_ip(self):
		max_attempts = int(frappe.db.get_single_value("Keyless Settings", "max_otp_attempts") or 5)
		with patch.object(otp, "issue_session"):
			for i in range(max_attempts * otp.ACCOUNT_GUESS_FACTOR):
				from_ip("keyless.api.otp.verify_otp", f"2001:db8:{i + 1:x}::1", email=USER)
				with self.assertRaises(frappe.AuthenticationError):
					otp.verify_otp(USER, "000000")
			from_ip("keyless.api.otp.verify_otp", "198.51.100.9", email=USER)
			with self.assertRaises(frappe.RateLimitExceededError):
				otp.verify_otp(USER, "000000")
