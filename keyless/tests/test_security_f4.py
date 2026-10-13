"""F-4 (audit 2026-10-10): sign-in codes and links must go to the account's stored
address, and their state and limits must belong to the account.

The database finds an account without regard to accents (utf8mb4_unicode_ci), so an
address that differs from the stored one only in accents reaches the same account.
Mail went to the address as typed, and codes, links and limits were kept per typed
string, so every spelling of one account had a budget of its own. Addresses with no
account must still get exactly the same answer as before (M-2)."""

from __future__ import annotations

from collections import defaultdict
from contextlib import ExitStack
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless.api import backup, common, magic_link, otp
from keyless.tests.security_utils import (
	delete_user,
	http,
	keyless_settings,
	make_user,
	new_client,
	reset_rate_limits,
)
from keyless.tokens import store_magic_key

USER = "kl-f4-user@example.com"
# Differs from USER only in an accent and in case: the database matches it to USER.
VARIANT = "KL-F4-ÜSER@example.com"
UNKNOWN = "kl-f4-nobody@example.com"
UNKNOWN_VARIANT = "kl-f4-nöbody@example.com"
# An account whose name is not its email address (the address was changed later).
RENAMED = "kl-f4-old-address@example.com"
RENAMED_EMAIL = "kl-f4-new-address@example.com"
# An account with no email address stored.
NO_EMAIL = "kl-f4-no-email@example.com"
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
		make_user(RENAMED)
		frappe.db.set_value("User", RENAMED, "email", RENAMED_EMAIL)
		make_user(NO_EMAIL)
		frappe.db.set_value("User", NO_EMAIL, "email", "")
		frappe.db.commit()

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		for user in (USER, RENAMED, NO_EMAIL):
			delete_user(user)
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


class TestNameDiffersFromEmail(StoredEmailCase):
	"""An account found by two unrelated strings (its name and its email address)."""

	def test_mail_goes_to_the_stored_address_whichever_is_typed(self):
		self.request_code(RENAMED)
		self.send_link(RENAMED_EMAIL)
		self.assertEqual(self.recipients(), [RENAMED_EMAIL, RENAMED_EMAIL])

	def test_code_requested_by_name_works_with_the_email(self):
		self.request_code(RENAMED)
		self.verify_code(RENAMED_EMAIL, self.last_code())
		self.issue.assert_called_once_with(RENAMED, method="email_otp")

	def test_name_and_email_do_not_share_a_limit(self):
		# Two unrelated unknown addresses never share a limit, so two strings that
		# reach one account must not either, or the shared 429 would show they are
		# the same account.
		for _ in range(LIMIT):
			self.request_code(RENAMED)
		with self.assertRaises(frappe.RateLimitExceededError):
			self.request_code(RENAMED)
		self.assertTrue(self.request_code(RENAMED_EMAIL)["ok"])


class TestNoStoredEmail(StoredEmailCase):
	def test_nothing_is_mailed_and_the_answer_is_unchanged(self):
		known_code = self.request_code(USER)
		known_link = self.send_link(USER)
		self.sendmail.reset_mock()
		self.assertEqual(self.request_code(NO_EMAIL), known_code)
		self.assertEqual(self.send_link(NO_EMAIL), known_link)
		self.sendmail.assert_not_called()
		for module, event in ((otp, "otp_requested"), (magic_link, "magic_link_sent")):
			calls = [c for c in module.log_event.call_args_list if c.args[:1] == (event,)]
			self.assertEqual(calls[-1].kwargs.get("detail"), "no_email", calls)
			self.assertEqual(calls[-1].kwargs.get("user"), NO_EMAIL)


class TestAccountLookedUpOnce(StoredEmailCase):
	def test_one_lookup_per_request_known_or_not(self):
		for address in (USER, UNKNOWN):
			for send in (self.request_code, self.send_link):
				with patch.object(common, "resolve_enabled_user", wraps=common.resolve_enabled_user) as resolve:
					send(address)
				with self.subTest(address=address, send=send.__name__):
					self.assertEqual(resolve.call_count, 1)


LINK_PATH = "/api/method/keyless.api.magic_link.login_via_link"


class TestMagicLinkRoundTrip(StoredEmailCase):
	"""A link signs in end to end, whether it was stored by this version (the account
	name) or before the upgrade (the address as typed)."""

	def test_link_requested_with_a_variant_signs_in(self):
		client = new_client()
		response = http(client, "post", "/api/method/keyless.api.magic_link.send_link", data={"email": VARIANT})
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		self.assertEqual(self.recipients(), [USER])
		link = self.sendmail.call_args.kwargs["args"]["link"]
		key = parse_qs(urlsplit(link).query)["key"][0]
		response = http(client, "post", LINK_PATH, data={"key": key})
		self.assertIn(response.status_code, (301, 302, 303), response.get_data(as_text=True)[:300])
		magic_link.issue_session.assert_called_once_with(USER, method="magic_link")

	def test_link_stored_before_the_upgrade_still_signs_in(self):
		key = frappe.generate_hash(length=32)
		# Before F-4 the link carried the address as typed (lower-cased), not the account.
		store_magic_key(key, common.normalize_email(VARIANT), 600)
		response = http(new_client(), "post", LINK_PATH, data={"key": key})
		self.assertIn(response.status_code, (301, 302, 303), response.get_data(as_text=True)[:300])
		magic_link.issue_session.assert_called_once_with(USER, method="magic_link")


def limit_key_for(address: str) -> str:
	"""The key request, guess and recovery-code limits for a typed address are kept
	under."""
	return common.limit_key(address)


# Characters to probe: Latin-1 Supplement, Latin Extended-A and -B, Latin Extended
# Additional, fullwidth forms, Latin ligatures, combining marks on a base letter, and
# characters that collations often ignore.
PROBES = (
	[chr(c) for start, end in ((0xA0, 0x250), (0x1E00, 0x1F00), (0xFF01, 0xFF5F), (0xFB00, 0xFB07)) for c in range(start, end)]
	+ ["a" + chr(m) for m in range(0x300, 0x370)]
	+ ["\u00ad", "\u034f", "\u180e", "\u200b", "\u200c", "\u200d", "\u2060", "\u2062", "\ufeff"]
)
# What a probe may plausibly be equal to: nothing, an ASCII letter or digit, or an
# ASCII expansion.
REFERENCES = (
	["", " ", "'", "-", ".", "_", "!", "?"]
	+ [chr(c) for c in range(ord("a"), ord("z") + 1)]
	+ [chr(c) for c in range(ord("0"), ord("9") + 1)]
	+ ["aa", "ae", "dz", "ff", "ffi", "ffl", "fi", "fl", "hv", "ij", "lj", "nj", "oe", "oi", "ou", "ss", "st", "th", "ue"]
)


def _address(fragment: str) -> str:
	return f"kl{fragment}z@example.test"


class TestLimitKeyMatchesDatabase(FrappeTestCase):
	"""Two typed addresses must share a limit exactly when the database treats them as
	the same address. Where the limit key and the database disagree, two spellings of a
	real address and two spellings of an unknown one behave differently, and the 429
	shows which addresses have accounts."""

	def collation(self) -> str:
		name = frappe.db.sql(
			"""select COLLATION_NAME from information_schema.COLUMNS
			where TABLE_SCHEMA = database() and TABLE_NAME = 'tabUser' and COLUMN_NAME = 'email'"""
		)[0][0]
		self.assertRegex(name, r"^[A-Za-z0-9_]+$")
		return name

	def db_rows(self, expression: str, params: list[tuple]) -> list:
		"""Evaluate `expression` (with %s placeholders) for each tuple, in batches."""
		out = []
		for i in range(0, len(params), 400):
			batch = params[i : i + 400]
			flat = [value for row in batch for value in row]
			out.extend(frappe.db.sql("select " + ", ".join([expression] * len(batch)), flat)[0])
		return out

	def test_limit_key_agrees_with_database_equality(self):
		if frappe.db.db_type != "mariadb":
			self.skipTest("measures MariaDB collation")
		collation = self.collation()
		norm = common.normalize_email
		strings = sorted({_address(x) for x in PROBES + REFERENCES})
		weights = self.db_rows(
			f"hex(weight_string(convert(%s using utf8mb4) collate {collation}))", [(norm(s),) for s in strings]
		)
		keys = {s: limit_key_for(s) for s in strings}

		# Pairs to check: every probe against every reference, and every pair the
		# key or the database weights put together.
		pairs = {(_address(p), _address(r)) for p in PROBES for r in REFERENCES}
		groups = defaultdict(list)
		for s, weight in zip(strings, weights, strict=True):
			groups[("w", weight)].append(s)
			groups[("k", keys[s])].append(s)
		for members in groups.values():
			pairs.update((a, b) for a in members for b in members if a < b)
		pairs = sorted((a, b) for a, b in pairs if a != b)

		equal = self.db_rows(
			f"convert(%s using utf8mb4) collate {collation} = convert(%s using utf8mb4) collate {collation}",
			[(norm(a), norm(b)) for a, b in pairs],
		)
		disagree = [
			(a, b, bool(db_equal))
			for (a, b), db_equal in zip(pairs, equal, strict=True)
			if bool(db_equal) != (keys[a] == keys[b])
		]

		def show(s):
			inner = s[2 : -len("z@example.test")]
			return "".join(f"U+{ord(c):04X}" if not c.isascii() or not c.isprintable() else c for c in inner) or "(empty)"

		report = "\n".join(
			f"  {show(a)!s:>14} vs {show(b)!s:<14} database {'equal' if db_equal else 'different'}, key {'different' if db_equal else 'equal'}"
			for a, b, db_equal in disagree[:150]
		)
		self.assertFalse(
			disagree,
			f"{collation}: the limit key and the database disagree on {len(disagree)} of {len(pairs)} pairs"
			f" (first 150):\n{report}",
		)
