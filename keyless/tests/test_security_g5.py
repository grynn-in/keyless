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
from keyless.api.common import ACCOUNT_BACKSTOP_FACTOR, client_network
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


class TestClientNetwork(FrappeTestCase):
	"""client_network() on its own: the key each kind of client address gets."""

	def setUp(self):
		previous = getattr(frappe.local, "request_ip", None)
		self.addCleanup(setattr, frappe.local, "request_ip", previous)

	def test_ipv4_is_kept_as_is(self):
		self.assertEqual(client_network("198.51.100.7"), "198.51.100.7")
		self.assertEqual(client_network(" 198.51.100.7 "), "198.51.100.7")

	def test_ipv6_counts_as_its_64(self):
		self.assertEqual(client_network("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64")
		self.assertEqual(client_network("2001:db8:1:2::1"), "2001:db8:1:2::/64")
		# The next /64 in the same /56 or /48 is a different client.
		self.assertEqual(client_network("2001:db8:1:3::1"), "2001:db8:1:3::/64")

	def test_ipv6_spellings_give_one_key(self):
		expected = "2001:db8:1:2::/64"
		for spelling in (
			"2001:DB8:1:2::ABCD",
			"2001:0db8:0001:0002:0000:0000:0000:0001",
			"2001:0DB8:0001:0002:FFFF:FFFF:FFFF:FFFF",
			"2001:db8:1:2:0:0:0:9",
		):
			with self.subTest(spelling=spelling):
				self.assertEqual(client_network(spelling), expected)

	def test_ipv4_mapped_ipv6_counts_as_the_ipv4_address(self):
		for spelling in ("::ffff:198.51.100.7", "::FFFF:198.51.100.7", "::ffff:c633:6407"):
			with self.subTest(spelling=spelling):
				self.assertEqual(client_network(spelling), "198.51.100.7")
		# Two mapped addresses are two clients, not one ::/64.
		self.assertNotEqual(client_network("::ffff:198.51.100.7"), client_network("::ffff:198.51.100.8"))

	def test_zone_id_is_dropped(self):
		# A scoped (link-local) address counts as its /64, whatever the zone.
		self.assertEqual(client_network("fe80::1%eth0"), "fe80::/64")
		self.assertEqual(client_network("fe80::2%25"), "fe80::/64")

	def test_value_that_is_not_an_ip_is_used_as_is(self):
		for value in ("not-an-ip", "198.51.100.300", "01.2.3.4", "2001:db8::1::2", "1.2.3.4%x", "unknown"):
			with self.subTest(value=value):
				self.assertEqual(client_network(value), value)

	def test_empty_and_missing(self):
		self.assertEqual(client_network(""), "")
		frappe.local.request_ip = None
		self.assertEqual(client_network(), "")
		self.assertEqual(client_network(None), "")

	def test_defaults_to_the_request_ip(self):
		frappe.local.request_ip = "2001:db8:1:2::42"
		self.assertEqual(client_network(), "2001:db8:1:2::/64")
		frappe.local.request_ip = "198.51.100.7"
		self.assertEqual(client_network(), "198.51.100.7")

	def test_transition_forms_are_not_unwrapped(self):
		# 6to4 (2002::/16), Teredo (2001::/32) and IPv4-compatible (::a.b.c.d) addresses
		# are counted by their /64 like any other IPv6 address; the docs say so.
		self.assertEqual(client_network("2002:c633:6407::1"), "2002:c633:6407::/64")
		self.assertEqual(client_network("2001:0:4136:e378:8000:63bf:3fff:fdd2"), "2001:0:4136:e378::/64")
		self.assertEqual(client_network("::198.51.100.7"), "::/64")
