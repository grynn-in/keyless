"""Scheduler jobs — Redis TTLs already expire challenges; this is belt-and-braces."""

from __future__ import annotations

import frappe
from frappe.utils import add_days, now_datetime


def purge_expired_challenges():
	# Challenges live in Redis and expire on their own. Nothing to do.
	return


def purge_old_audit_logs():
	try:
		days = frappe.db.get_single_value("Keyless Settings", "audit_retention_days") or 90
		cutoff = add_days(now_datetime(), -int(days))
		frappe.db.delete("Keyless Audit Log", {"event_on": ("<", cutoff)})
		frappe.db.commit()
	except Exception:
		frappe.log_error(title="Keyless audit purge failed", message=frappe.get_traceback())
