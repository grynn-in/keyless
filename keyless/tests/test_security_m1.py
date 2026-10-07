"""M-1: OTP rate limits must hold per account, whatever the client IP, and the
attempt counter must be atomic, survive re-issue and not extend a code's life."""

from __future__ import annotations

import threading
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless import tokens
from keyless.api import otp
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits

USER = "kl-m1-user@example.com"
OTP_ON = {
	"enabled": 1,
	"enable_email_otp": 1,
	"max_otp_attempts": 3,
	"otp_expiry_seconds": 300,
	"otp_length": 6,
	"rate_limit_per_hour": 5,
}


class OTPCase(FrappeTestCase):
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
		self.sent = []
		self.patches = [
			patch.object(otp, "_send_otp_mail", side_effect=lambda email, code, exp: self.sent.append(code)),
			patch.object(otp, "log_event"),
			patch.object(otp, "issue_session"),
		]
		for p in self.patches:
			p.start()
		self.ip = 0

	def tearDown(self):
		for p in self.patches:
			p.stop()
		reset_rate_limits()

	def _new_ip(self):
		# A different client IP every call, as a spoofed X-Forwarded-For would give.
		self.ip += 1
		return f"203.0.113.{self.ip % 250 + 1}"

	def request(self, email=USER):
		set_request(method="POST", path="/api/method/keyless.api.otp.request_otp")
		frappe.local.request_ip = self._new_ip()
		frappe.local.form_dict = frappe._dict(cmd="keyless.api.otp.request_otp", email=email)
		return otp.request_otp(email)

	def verify(self, code, email=USER):
		set_request(method="POST", path="/api/method/keyless.api.otp.verify_otp")
		frappe.local.request_ip = self._new_ip()
		frappe.local.form_dict = frappe._dict(cmd="keyless.api.otp.verify_otp", email=email, otp=code)
		return otp.verify_otp(email, code)


class TestPerAccountLimits(OTPCase):
	def test_request_limit_holds_across_ips_and_spellings(self):
		for target in (USER, "kl-m1-nobody@example.com"):
			with self.subTest(target=target):
				reset_rate_limits()
				with keyless_settings(**OTP_ON):
					spellings = [target, target.upper(), f"  {target} "]
					for i in range(5):
						self.request(spellings[i % 3])
					with self.assertRaises(frappe.RateLimitExceededError):
						self.request(target)

	def test_verify_limit_holds_across_ips(self):
		with keyless_settings(**{**OTP_ON, "max_otp_attempts": 10}):
			self.request()
			refused = False
			for _ in range(40):
				try:
					self.verify("000000")
				except frappe.RateLimitExceededError:
					refused = True
					break
				except frappe.AuthenticationError:
					pass
			self.assertTrue(refused, "wrong guesses from rotating IPs were never limited")

	def test_reissue_does_not_reset_wrong_guess_budget(self):
		with keyless_settings(**{**OTP_ON, "rate_limit_per_hour": 50}):
			for _ in range(2):
				self.request()
				for _ in range(3):
					with self.assertRaises(frappe.AuthenticationError):
						self.verify("000000")
			self.request()
			with self.assertRaises((frappe.AuthenticationError, frappe.RateLimitExceededError)):
				self.verify(self.sent[-1])

	def test_daily_issue_cap(self):
		with keyless_settings(**{**OTP_ON, "rate_limit_per_hour": 50, "otp_daily_limit": 3}):
			for _ in range(3):
				self.request()
			with self.assertRaises(frappe.RateLimitExceededError):
				self.request()

	def test_normal_sign_in_still_works(self):
		with keyless_settings(**OTP_ON):
			self.request()
			with self.assertRaises(frappe.AuthenticationError):
				self.verify("000000")
			self.verify(self.sent[-1])
		otp.issue_session.assert_called_once_with(USER, method="email_otp")


class TestAttemptCounter(FrappeTestCase):
	EMAIL = "kl-m1-race@example.com"

	def setUp(self):
		reset_rate_limits()

	def tearDown(self):
		reset_rate_limits()

	def test_parallel_wrong_guesses_never_exceed_max(self):
		tokens.store_otp(self.EMAIL, "111111", 300)
		site = frappe.local.site
		evaluated = []
		lock = threading.Lock()
		real_compare = tokens.compare
		start = threading.Barrier(12)

		def counting_compare(value, expected):
			with lock:
				evaluated.append(value)
			return real_compare(value, expected)

		def guess():
			frappe.init(site=site)
			frappe.connect()
			try:
				start.wait()
				tokens.verify_and_consume_otp(self.EMAIL, "000000", max_attempts=3)
			finally:
				frappe.destroy()

		with patch.object(tokens, "compare", side_effect=counting_compare):
			threads = [threading.Thread(target=guess) for _ in range(12)]
			for t in threads:
				t.start()
			for t in threads:
				t.join()
		self.assertLessEqual(len(evaluated), 3)

	def test_wrong_guess_does_not_extend_lifetime(self):
		tokens.store_otp(self.EMAIL, "111111", 120)
		self.assertFalse(tokens.verify_and_consume_otp(self.EMAIL, "000000", max_attempts=5))
		ttl = frappe.cache.ttl(frappe.cache.make_key(tokens.OTP_CACHE_PREFIX + self.EMAIL))
		self.assertGreater(ttl, 0)
		self.assertLessEqual(ttl, 120)

	def test_wrong_guess_keeps_code_usable(self):
		tokens.store_otp(self.EMAIL, "111111", 120)
		self.assertFalse(tokens.verify_and_consume_otp(self.EMAIL, "000000", max_attempts=5))
		self.assertTrue(tokens.verify_and_consume_otp(self.EMAIL, "111111", max_attempts=5))
