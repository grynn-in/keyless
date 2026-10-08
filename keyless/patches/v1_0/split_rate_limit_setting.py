import frappe
from frappe.utils import cint

DOCTYPE = "Keyless Settings"


def execute():
	"""Carry `rate_limit_per_hour` over to `rate_limit_requests` with a 3600 s window.

	Existing sites keep their limit and the one-hour window they had before the
	window became a setting.
	"""
	old = frappe.db.sql(
		"select value from tabSingles where doctype=%s and field='rate_limit_per_hour'", DOCTYPE
	)
	if old:
		frappe.db.set_single_value(DOCTYPE, "rate_limit_requests", cint(old[0][0]) or 5)
		frappe.db.delete("Singles", {"doctype": DOCTYPE, "field": "rate_limit_per_hour"})
	if frappe.db.get_single_value(DOCTYPE, "rate_limit_window_seconds") in (None, 0):
		frappe.db.set_single_value(DOCTYPE, "rate_limit_window_seconds", 3600)
	frappe.clear_document_cache(DOCTYPE, DOCTYPE)
