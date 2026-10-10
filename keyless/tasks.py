"""Scheduler jobs. Challenges, codes and magic links live in Redis and expire there."""

from __future__ import annotations

import frappe
from frappe.utils import add_days, now_datetime


def purge_old_audit_logs():
	try:
		days = frappe.db.get_single_value("Keyless Settings", "audit_retention_days") or 90
		cutoff = add_days(now_datetime(), -int(days))
		frappe.db.delete("Keyless Audit Log", {"event_on": ("<", cutoff)})
		frappe.db.commit()
	except Exception:
		frappe.log_error(title="Keyless audit purge failed", message=frappe.get_traceback())
