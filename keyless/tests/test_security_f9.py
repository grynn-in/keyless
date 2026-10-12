"""F-9 (audit 2026-10-10): Keyless Settings accepted unsafe numbers.

A 4-digit OTP was accepted, attempts and request limits had no upper bound, and
negative values were saved and switched limits off (or, for Audit Retention,
deleted every audit entry). Settings must now be inside fixed bounds, and the
migrate patch brings stored values back inside them without stopping migrate.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import frappe
from frappe.modules.patch_handler import PatchType, get_patches_from_app
from frappe.tests.utils import FrappeTestCase

from keyless.tests.security_utils import keyless_settings

# field: (lowest allowed, highest allowed, default in keyless_settings.json)
BOUNDS = {
	"otp_length": (6, 8, 6),
	"otp_expiry_seconds": (60, 3600, 300),
	"max_otp_attempts": (1, 10, 5),
	"rate_limit_per_hour": (1, 100, 5),
	"otp_daily_limit": (1, 1000, 10),
	"magic_link_expiry_minutes": (2, 60, 10),
	"step_up_window_minutes": (1, 60, 5),
	"audit_retention_days": (1, 3650, 90),
}

PATCH = "keyless.patches.v2_0.clamp_keyless_settings"
PATCH_LOG_TITLE = "Keyless: settings out of range"


class TestSettingsBounds(FrappeTestCase):
	def tearDown(self):
		frappe.db.rollback()
		frappe.clear_document_cache("Keyless Settings", "Keyless Settings")

	def _settings(self, **values):
		doc = frappe.get_single("Keyless Settings")
		doc.update(values)
		return doc

	def test_defaults_are_inside_the_bounds(self):
		doc = frappe.new_doc("Keyless Settings")
		for field, (low, high, default) in BOUNDS.items():
			with self.subTest(field=field):
				self.assertEqual(doc.get(field), default)
				self.assertTrue(low <= default <= high)
		doc.validate()

	def test_defaults_save(self):
		self._settings(**{field: default for field, (_, _, default) in BOUNDS.items()}).save(
			ignore_permissions=True
		)

	def test_bounds_themselves_are_accepted(self):
		for field, (low, high, _) in BOUNDS.items():
			for value in (low, high):
				with self.subTest(field=field, value=value):
					doc = self._settings(**{field: value})
					doc.validate()
					self.assertEqual(doc.get(field), value)

	def test_out_of_range_values_are_refused(self):
		for field, (low, high, _) in BOUNDS.items():
			label = frappe.get_meta("Keyless Settings").get_label(field)
			for value in (low - 1, high + 1, -1, 10**9):
				if value == 0:
					continue  # blank: see test_blank_values_get_the_default
				with self.subTest(field=field, value=value):
					doc = self._settings(**{field: value})
					with self.assertRaisesRegex(frappe.ValidationError, rf"{re.escape(label)}.*\b{low}\b.*\b{high}\b"):
						doc.save(ignore_permissions=True)

	def test_four_digit_otp_is_refused(self):
		with self.assertRaises(frappe.ValidationError):
			self._settings(otp_length=4).save(ignore_permissions=True)

	def test_negative_limits_cannot_switch_limits_off(self):
		for field in ("max_otp_attempts", "rate_limit_per_hour", "otp_daily_limit", "audit_retention_days"):
			with self.subTest(field=field):
				with self.assertRaises(frappe.ValidationError):
					self._settings(**{field: -5}).save(ignore_permissions=True)

	def test_blank_values_get_the_default(self):
		# A cleared field is stored as 0, which the app already reads as the default;
		# saving now writes that default so the form shows what is in force.
		for field, (_, _, default) in BOUNDS.items():
			with self.subTest(field=field):
				doc = self._settings(**{field: 0})
				doc.validate()
				self.assertEqual(doc.get(field), default)

	def test_e2e_suite_settings_still_save(self):
		self._settings(rate_limit_per_hour=50, otp_daily_limit=50, step_up_window_minutes=5).save(
			ignore_permissions=True
		)


class TestClampPatch(FrappeTestCase):
	def setUp(self):
		self.logs_before = set(frappe.get_all("Error Log", filters={"method": PATCH_LOG_TITLE}, pluck="name"))

	def tearDown(self):
		frappe.db.rollback()
		new = set(frappe.get_all("Error Log", filters={"method": PATCH_LOG_TITLE}, pluck="name")) - self.logs_before
		if new:
			frappe.db.delete("Error Log", {"name": ("in", list(new))})
			frappe.db.commit()
		frappe.clear_document_cache("Keyless Settings", "Keyless Settings")

	def _run_patch(self):
		frappe.get_attr(PATCH + ".execute")()

	def _stored(self, field):
		return frappe.db.get_single_value("Keyless Settings", field)

	def _new_logs(self):
		names = set(frappe.get_all("Error Log", filters={"method": PATCH_LOG_TITLE}, pluck="name"))
		return [frappe.get_doc("Error Log", n) for n in names - self.logs_before]

	def test_patch_is_registered_after_model_sync(self):
		self.assertIn(PATCH, get_patches_from_app("keyless", PatchType.post_model_sync))

	def test_out_of_range_values_are_clamped_and_reported(self):
		stored = {
			"otp_length": 4,
			"max_otp_attempts": -1,
			"rate_limit_per_hour": 100000,
			"otp_daily_limit": 0,
			"audit_retention_days": -5,
			"otp_expiry_seconds": 600,  # in range: left alone
		}
		with keyless_settings(**stored):
			self._run_patch()
			self.assertEqual(self._stored("otp_length"), 6)
			self.assertEqual(self._stored("max_otp_attempts"), 1)
			self.assertEqual(self._stored("rate_limit_per_hour"), 100)
			self.assertEqual(self._stored("otp_daily_limit"), 10)
			self.assertEqual(self._stored("audit_retention_days"), 1)
			self.assertEqual(self._stored("otp_expiry_seconds"), 600)
			logs = self._new_logs()
			self.assertEqual(len(logs), 1)
			message = logs[0].error
			for field in ("otp_length", "max_otp_attempts", "rate_limit_per_hour", "otp_daily_limit", "audit_retention_days"):
				self.assertIn(field, message)
			self.assertNotIn("otp_expiry_seconds", message)

	def test_nothing_logged_when_settings_are_in_range(self):
		with keyless_settings(**{field: default for field, (_, _, default) in BOUNDS.items()}):
			self._run_patch()
			self.assertEqual(self._new_logs(), [])

	def test_patch_never_stops_migrate(self):
		with keyless_settings(otp_length=4):
			with patch(PATCH + ".clamp_stored_settings", side_effect=RuntimeError("boom")):
				self._run_patch()  # must not raise
			failures = frappe.get_all(
				"Error Log", filters={"method": "Keyless: settings bounds patch failed"}, pluck="name"
			)
			self.assertTrue(failures)
			frappe.db.delete("Error Log", {"name": ("in", failures)})
			frappe.db.commit()
