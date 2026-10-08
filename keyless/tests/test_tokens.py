from __future__ import annotations

import time
import unittest
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from keyless.tokens import OTP_CACHE_PREFIX, compare, digest, random_otp, store_otp, verify_and_consume_otp


class TestTokens(FrappeTestCase):
	def test_digest_is_stable_and_peppered(self):
		a = digest("123456")
		b = digest("123456")
		self.assertEqual(a, b)
		self.assertEqual(len(a), 64)
		self.assertNotEqual(a, digest("123457"))

	def test_compare_rejects_wrong_code(self):
		self.assertTrue(compare("999111", digest("999111")))
		self.assertFalse(compare("999112", digest("999111")))

	def test_otp_roundtrip_consumes(self):
		email = "tester@example.com"
		otp = "482193"
		store_otp(email, otp, 300)
		self.assertTrue(verify_and_consume_otp(email, otp, max_attempts=5))
		self.assertFalse(verify_and_consume_otp(email, otp, max_attempts=5))

	def test_otp_lockout_after_attempts(self):
		email = "lockout@example.com"
		store_otp(email, "111111", 300)
		for _ in range(5):
			self.assertFalse(verify_and_consume_otp(email, "000000", max_attempts=5))
		self.assertFalse(verify_and_consume_otp(email, "111111", max_attempts=5))

	def test_wrong_guess_keeps_original_expiry(self):
		email = "expiry@example.com"
		store_otp(email, "222222", 120)
		self.assertFalse(verify_and_consume_otp(email, "000000", max_attempts=5))
		ttl = frappe.cache.ttl(frappe.cache.make_key(f"{OTP_CACHE_PREFIX}{email}"))
		self.assertTrue(0 < ttl <= 120, ttl)
		self.assertTrue(verify_and_consume_otp(email, "222222", max_attempts=5))

	def test_wrong_guess_after_expiry_deletes_code(self):
		email = "expired@example.com"
		store_otp(email, "333333", 120)
		with patch("keyless.tokens.time.time", return_value=time.time() + 121):
			self.assertFalse(verify_and_consume_otp(email, "000000", max_attempts=5))
		self.assertFalse(verify_and_consume_otp(email, "333333", max_attempts=5))

	def test_otp_length_bounds(self):
		self.assertEqual(len(random_otp(6)), 6)
		self.assertEqual(len(random_otp(2)), 4)
		self.assertEqual(len(random_otp(99)), 8)
