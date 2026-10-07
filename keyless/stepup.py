"""Recent re-authentication ("step-up") before sensitive account changes (audit M-3, D7).

Signing in marks the session; so does confirming with an existing passkey or a
fresh email code (keyless.api.stepup). Adding a passkey or regenerating backup
codes requires a mark younger than Keyless Settings' Step-up Window.
"""

from __future__ import annotations

import time

import frappe
from frappe import _

from keyless.settings import get_settings

CACHE_PREFIX = "keyless:stepup:"


class StepUpRequiredError(frappe.PermissionError):
	pass


def now_ts() -> float:
	return time.time()


def window_seconds() -> int:
	return max(1, int(get_settings().step_up_window_minutes or 5)) * 60


def _key() -> bytes | None:
	sid = getattr(frappe.session, "sid", None)
	if not sid or frappe.session.user == "Guest":
		return None
	# Raw Redis key, so no request-local cache can serve a stale mark.
	return frappe.cache.make_key(CACHE_PREFIX + sid)


def mark() -> None:
	if key := _key():
		frappe.cache.setex(key, window_seconds(), str(now_ts()))


def is_recent() -> bool:
	key = _key()
	at = frappe.cache.get(key) if key else None
	if not at:
		return False
	return 0 <= now_ts() - float(at) <= window_seconds()


def require() -> None:
	if not is_recent():
		frappe.throw(_("Confirm it's you before changing how you sign in."), StepUpRequiredError)


def on_session_creation(login_manager):
	"""Hook: a fresh sign-in counts as recent re-authentication."""
	mark()
