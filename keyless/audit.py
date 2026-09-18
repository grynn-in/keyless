"""Durable authentication audit trail. Failures are as important as successes."""

from __future__ import annotations

import frappe
from frappe.utils import now_datetime


def _client_ip() -> str | None:
	ip = getattr(frappe.local, "request_ip", None)
	if ip:
		return ip
	try:
		return frappe.get_request_header("X-Forwarded-For") or frappe.get_request_header("X-Real-IP")
	except Exception:
		return None


def log_event(
	event: str,
	*,
	user: str | None = None,
	method: str | None = None,
	success: bool = False,
	detail: str | None = None,
) -> None:
	try:
		doc = frappe.get_doc(
			{
				"doctype": "Keyless Audit Log",
				"event": event,
				"user": user or "Guest",
				"method": method,
				"ip_address": (_client_ip() or "")[:40],
				"user_agent": (frappe.get_request_header("User-Agent") or "")[:140],
				"success": 1 if success else 0,
				"detail": (detail or "")[:140],
				"event_on": now_datetime(),
			}
		)
		doc.flags.ignore_permissions = True
		doc.insert()
		frappe.db.commit()
	except Exception:
		frappe.log_error(title="Keyless audit log failed", message=frappe.get_traceback())
