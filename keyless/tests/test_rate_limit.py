from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from keyless.api.common import get_rate_limit, get_rate_limit_window, keyless_rate_limit


class TestRateLimit(FrappeTestCase):
	def test_reads_requests_and_window_from_settings(self):
		settings = SimpleNamespace(rate_limit_requests=7, rate_limit_window_seconds=60)
		with patch("keyless.api.common.get_settings", return_value=settings):
			self.assertEqual(get_rate_limit(), 7)
			self.assertEqual(get_rate_limit_window(), 60)

	def test_blank_settings_keep_the_old_hourly_limit(self):
		settings = SimpleNamespace(rate_limit_requests=0, rate_limit_window_seconds=0)
		with patch("keyless.api.common.get_settings", return_value=settings):
			self.assertEqual(get_rate_limit(), 5)
			self.assertEqual(get_rate_limit_window(), 3600)

	def test_decorator_passes_configured_window_to_frappe(self):
		settings = SimpleNamespace(rate_limit_requests=5, rate_limit_window_seconds=60)
		seen = {}

		def fake_rate_limit(limit, seconds):
			seen["limit"], seen["seconds"] = limit(), seconds
			return lambda fn: fn

		with (
			patch("keyless.api.common.get_settings", return_value=settings),
			patch("keyless.api.common.rate_limit", side_effect=fake_rate_limit),
		):
			self.assertEqual(keyless_rate_limit(lambda: "ok")(), "ok")
		self.assertEqual(seen, {"limit": 5, "seconds": 60})

	def test_settings_reject_zero_window(self):
		doc = frappe.get_doc("Keyless Settings")
		doc.rate_limit_window_seconds = 0
		self.assertRaises(frappe.ValidationError, doc.validate)
