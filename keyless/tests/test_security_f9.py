"""F-9 (audit 2026-10-10): Keyless Settings accepted unsafe numbers.

A 4-digit OTP was accepted, attempts and request limits had no upper bound, and
negative values were saved and switched limits off (or, for Audit Retention,
deleted every audit entry). Settings must now be inside fixed bounds, and the
migrate patch brings stored values back inside them without stopping migrate.

Review of #25: Audit Retention below 30 days let a System Manager empty the log
with the daily purge, unnoticed. It is now at least 30 days, a stored value of
0 or less becomes the default (90) rather than the floor, every change of it is
itself an audit event, and the purge applies the same rule to whatever is stored.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import frappe
from frappe.modules.patch_handler import PatchType, get_patches_from_app
from frappe.tests.utils import FrappeTestCase
from frappe.utils import add_days, cint, now_datetime

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
	"audit_retention_days": (30, 3650, 90),
}

PATCH = "keyless.patches.v2_0.clamp_keyless_settings"
PATCH_LOG_TITLE = "Keyless: settings out of range"
RETENTION_EVENT = "audit_retention_changed"


def _audit_rows(event):
	return set(frappe.get_all("Keyless Audit Log", filters={"event": event}, pluck="name"))


class _CleansAuditRows:
	"""keyless_settings() commits on exit, so audit rows written inside it stay;
	delete the ones a test created."""

	def _remember_audit_rows(self):
		self.audit_before = _audit_rows(RETENTION_EVENT)

	def _new_retention_events(self):
		names = _audit_rows(RETENTION_EVENT) - self.audit_before
		return frappe.get_all(
			"Keyless Audit Log",
			filters={"name": ("in", list(names) or [""])},
			fields=["user", "method", "success", "detail"],
		)

	def _delete_new_audit_rows(self):
		new = _audit_rows(RETENTION_EVENT) - self.audit_before
		if new:
			frappe.db.delete("Keyless Audit Log", {"name": ("in", list(new))})
			frappe.db.commit()


class TestSettingsBounds(_CleansAuditRows, FrappeTestCase):
	def setUp(self):
		self._remember_audit_rows()

	def tearDown(self):
		frappe.db.rollback()
		self._delete_new_audit_rows()
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

	def test_retention_below_30_days_is_refused(self):
		# A short retention lets the daily purge empty the audit log.
		for value in (1, 7, 29):
			with self.subTest(value=value):
				with self.assertRaises(frappe.ValidationError):
					self._settings(audit_retention_days=value).save(ignore_permissions=True)

	def test_retention_change_is_an_audit_event(self):
		old = cint(frappe.get_single("Keyless Settings").audit_retention_days)
		new = 45 if old != 45 else 60
		self._settings(audit_retention_days=new).save(ignore_permissions=True)
		events = self._new_retention_events()
		self.assertEqual(len(events), 1)
		self.assertEqual(events[0].user, frappe.session.user)
		self.assertEqual(events[0].method, "settings")
		self.assertTrue(events[0].success)
		self.assertEqual(events[0].detail, f"{old} -> {new} by {frappe.session.user}")

	def test_saving_other_settings_writes_no_retention_event(self):
		old = cint(frappe.get_single("Keyless Settings").audit_retention_days)
		if not old:
			self.skipTest("retention is blank on this site; saving fills it in")
		self._settings(otp_expiry_seconds=600).save(ignore_permissions=True)
		self.assertEqual(self._new_retention_events(), [])

	def test_retention_event_name_is_a_valid_option(self):
		options = frappe.get_meta("Keyless Audit Log").get_field("event").options.split("\n")
		self.assertIn(RETENTION_EVENT, options)


class TestPurgeRetention(FrappeTestCase):
	"""The purge must not trust a stored retention that skipped validate (set by SQL,
	set_single_value, or a site not yet migrated)."""

	def setUp(self):
		self.row = frappe.get_doc(
			{
				"doctype": "Keyless Audit Log",
				"event": "login",
				"user": "Administrator",
				"success": 1,
				"detail": "f9 purge test",
				"event_on": add_days(now_datetime(), -10),
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()

	def tearDown(self):
		frappe.db.delete("Keyless Audit Log", {"name": self.row.name})
		frappe.db.commit()

	def _purge(self):
		from keyless.tasks import purge_old_audit_logs

		purge_old_audit_logs()

	def test_negative_or_short_retention_does_not_empty_the_log(self):
		for stored in (-5, 1, 7):
			with self.subTest(stored=stored):
				with keyless_settings(audit_retention_days=stored):
					self._purge()
				self.assertTrue(frappe.db.exists("Keyless Audit Log", self.row.name))

	def test_purge_still_deletes_rows_past_retention(self):
		old = frappe.get_doc(
			{
				"doctype": "Keyless Audit Log",
				"event": "login",
				"user": "Administrator",
				"success": 1,
				"detail": "f9 purge test old",
				"event_on": add_days(now_datetime(), -40),
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()
		try:
			with keyless_settings(audit_retention_days=30):
				self._purge()
			self.assertFalse(frappe.db.exists("Keyless Audit Log", old.name))
			self.assertTrue(frappe.db.exists("Keyless Audit Log", self.row.name))
		finally:
			frappe.db.delete("Keyless Audit Log", {"name": old.name})
			frappe.db.commit()


class TestClampPatch(_CleansAuditRows, FrappeTestCase):
	def setUp(self):
		self.logs_before = set(frappe.get_all("Error Log", filters={"method": PATCH_LOG_TITLE}, pluck="name"))
		self._remember_audit_rows()

	def tearDown(self):
		frappe.db.rollback()
		self._delete_new_audit_rows()
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
			"audit_retention_days": 7,
			"otp_expiry_seconds": 600,  # in range: left alone
		}
		with keyless_settings(**stored):
			self._run_patch()
			self.assertEqual(self._stored("otp_length"), 6)
			self.assertEqual(self._stored("max_otp_attempts"), 1)
			self.assertEqual(self._stored("rate_limit_per_hour"), 100)
			self.assertEqual(self._stored("audit_retention_days"), 30)
			self.assertEqual(self._stored("otp_expiry_seconds"), 600)
			logs = self._new_logs()
			self.assertEqual(len(logs), 1)
			message = logs[0].error
			for field in ("otp_length", "max_otp_attempts", "rate_limit_per_hour", "audit_retention_days"):
				self.assertIn(field, message)
			self.assertNotIn("otp_expiry_seconds", message)

	def test_negative_retention_becomes_the_default_not_the_floor(self):
		# Clamping to the floor would shorten retention to 30 days; a value of 0 or
		# less was a mistake (or meant "keep"), so it gets the default instead.
		for stored in (-5, -1):
			with self.subTest(stored=stored):
				with keyless_settings(audit_retention_days=stored):
					self._run_patch()
					self.assertEqual(self._stored("audit_retention_days"), 90)
					self.assertTrue(any("audit_retention_days" in log.error for log in self._new_logs()))

	def test_blank_values_are_filled_but_not_reported_as_out_of_range(self):
		with keyless_settings(otp_daily_limit=0, audit_retention_days=None, otp_length=6):
			self._run_patch()
			self.assertEqual(self._stored("otp_daily_limit"), 10)
			self.assertEqual(self._stored("audit_retention_days"), 90)
			for log in self._new_logs():
				self.assertNotIn("otp_daily_limit", log.error)
				self.assertNotIn("audit_retention_days", log.error)

	def test_patch_change_of_retention_is_an_audit_event(self):
		with keyless_settings(audit_retention_days=-5):
			self._run_patch()
			events = self._new_retention_events()
			self.assertEqual(len(events), 1)
			self.assertEqual(events[0].method, "migrate")
			self.assertEqual(events[0].detail, "-5 -> 90 by migrate")

	def test_failure_rolls_back_a_half_applied_clamp(self):
		def half_applied():
			frappe.db.set_single_value("Keyless Settings", "otp_length", 7)
			raise RuntimeError("boom")

		with keyless_settings(otp_length=4):
			with patch(PATCH + ".clamp_stored_settings", side_effect=half_applied):
				self._run_patch()  # must not raise
			self.assertEqual(cint(self._stored("otp_length")), 4)
			failures = frappe.get_all(
				"Error Log", filters={"method": "Keyless: settings bounds patch failed"}, pluck="name"
			)
			self.assertTrue(failures)
			frappe.db.delete("Error Log", {"name": ("in", failures)})
			frappe.db.commit()

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
