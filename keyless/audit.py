"""Durable authentication audit trail. Failures are as important as successes.

During a web request, events are buffered and written after the response, in
their own transaction (audit L-4). The request's own work is therefore never
committed early by logging, and an event is still recorded when the request
fails and its work is rolled back. Outside a request (jobs, console, tests)
events are inserted into the caller's transaction and committed with it.
"""

from __future__ import annotations

import frappe
from frappe.utils import now_datetime


def log_event(
	event: str,
	*,
	user: str | None = None,
	method: str | None = None,
	success: bool = False,
	detail: str | None = None,
) -> None:
	try:
		row = {
			"doctype": "Keyless Audit Log",
			"event": event,
			"user": user or "Guest",
			"method": method,
			# Only Frappe's resolved client IP; never the raw X-Forwarded-For header,
			# which the client controls and can make arbitrarily long.
			"ip_address": (getattr(frappe.local, "request_ip", None) or "")[:40],
			"user_agent": (_header("User-Agent") or "")[:140],
			"success": 1 if success else 0,
			"detail": (detail or "")[:140],
			"event_on": now_datetime(),
		}
		after_response = getattr(getattr(frappe.local, "request", None), "after_response", None)
		if after_response is None:
			_insert(row)
			return
		pending = getattr(frappe.local, "keyless_audit_pending", None)
		if pending is None:
			pending = frappe.local.keyless_audit_pending = []
			after_response.add(_flush)
		pending.append(row)
	except Exception:
		frappe.log_error(title="Keyless audit log failed", message=frappe.get_traceback())


def _header(name: str) -> str | None:
	try:
		return frappe.get_request_header(name)
	except Exception:
		return None


def _insert(row: dict) -> None:
	doc = frappe.get_doc(row)
	doc.flags.ignore_permissions = True
	doc.insert()


def _flush() -> None:
	"""after_response callback: the request's transaction is already committed or
	rolled back, so these rows go in a transaction of their own."""
	rows = getattr(frappe.local, "keyless_audit_pending", None) or []
	frappe.local.keyless_audit_pending = None
	if not rows:
		return
	try:
		for row in rows:
			_insert(row)
		frappe.db.commit()
	except Exception:
		frappe.db.rollback()
		frappe.log_error(title="Keyless audit log failed", message=frappe.get_traceback())
		frappe.db.commit()
