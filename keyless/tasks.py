"""Scheduler jobs. Challenges, codes and magic links live in Redis and expire there."""

from __future__ import annotations

import frappe
from frappe.utils import add_days, now_datetime


def purge_old_audit_logs():
	try:
		from keyless.keyless.doctype.keyless_settings.keyless_settings import audit_retention_days

		cutoff = add_days(now_datetime(), -audit_retention_days())
		frappe.db.delete("Keyless Audit Log", {"event_on": ("<", cutoff)})
		frappe.db.commit()
	except Exception:
		frappe.log_error(title="Keyless audit purge failed", message=frappe.get_traceback())
