"""Follow-ups from the code review of #7: counters always expire, limits hold under
parallel requests, and step-up codes share the sign-in limits (hourly and daily)."""

from __future__ import annotations

import threading

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless import tokens
from keyless.api.common import HOUR, take_attempt
from keyless.tests.security_utils import keyless_settings, reset_rate_limits
from keyless.tests.test_security_m3 import USER, StepUpCase, clear_step_up


class TestCounterExpiry(FrappeTestCase):
	def setUp(self):
		reset_rate_limits()
		self.addCleanup(reset_rate_limits)

	def key(self):
		return tokens._rate_key("kl-test", "someone@example.com")

	def test_first_hit_sets_the_expiry(self):
		self.assertEqual(tokens.count_hit("kl-test", "someone@example.com", 600), 1)
		self.assertGreater(frappe.cache.ttl(self.key()), 0)

	def test_counter_left_without_expiry_gets_one(self):
		# What an interrupted INCRBY-then-EXPIRE in the old code could leave behind.
		frappe.cache.set(self.key(), 7)
		self.assertEqual(frappe.cache.ttl(self.key()), -1)
		self.assertEqual(tokens.count_hit("kl-test", "someone@example.com", 600), 8)
		self.assertGreater(frappe.cache.ttl(self.key()), 0)

	def test_give_back_after_the_window_creates_nothing(self):
		tokens.uncount_hit("kl-test", "someone@example.com")
		self.assertFalse(frappe.cache.exists(self.key()))


class TestParallelAttempts(FrappeTestCase):
	"""Counting before checking: parallel requests cannot all pass a limit."""

	def setUp(self):
		reset_rate_limits()
		self.addCleanup(reset_rate_limits)

	def test_only_the_limit_gets_through(self):
		site = frappe.local.site
		passed = []
		lock = threading.Lock()
		start = threading.Barrier(12)

		def attempt():
			frappe.init(site=site)
			frappe.connect()
			try:
				set_request(method="POST", path="/api/method/ping")
				frappe.local.request_ip = "198.51.100.1"
				start.wait()
				try:
					take_attempt("kl-test-guess", "someone@example.com", 3, HOUR, per_ip=False)
				except frappe.RateLimitExceededError:
					return
				with lock:
					passed.append(1)
			finally:
				frappe.destroy()

		threads = [threading.Thread(target=attempt) for _ in range(12)]
		for t in threads:
			t.start()
		for t in threads:
			t.join()
		self.assertEqual(len(passed), 3)


class TestStepUpLimits(StepUpCase):
	def request_code(self):
		from keyless.api import stepup as api

		self.request("keyless.api.stepup.request_email_code")
		return api.request_email_code()

	def test_daily_cap(self):
		self.sign_in()
		clear_step_up()
		with keyless_settings(rate_limit_per_hour=50, otp_daily_limit=2):
			self.request_code()
			self.request_code()
			with self.assertRaises(frappe.RateLimitExceededError):
				self.request_code()

	def test_code_is_sent_without_waiting_for_the_queue(self):
		self.sign_in()
		clear_step_up()
		self.request_code()
		self.assertTrue(self.mails_to(USER)[-1].kwargs.get("now"))

	def test_correct_code_does_not_use_up_the_guess_budget(self):
		from keyless.api import stepup as api

		self.sign_in()
		with keyless_settings(rate_limit_per_hour=50, otp_daily_limit=50, max_otp_attempts=1):
			# max_otp_attempts 1 allows 2 guesses an hour; correct codes are given back.
			for _ in range(4):
				clear_step_up()
				self.request_code()
				self.request("keyless.api.stepup.verify_email_code")
				api.verify_email_code(self.mails_to(USER)[-1].kwargs["args"]["otp"])
