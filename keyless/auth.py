"""Request-level auth hook and session events.

`auth_hooks` run on every request *after* Frappe has tried cookie / API-key /
OAuth. Use this only for additive authenticators (e.g. a signed Keyless
assertion header). Session issuance for browser login always goes through
LoginManager.login_as — never frappe.set_user() from a guest POST without a
session cookie.
"""

from __future__ import annotations

import frappe

from keyless.audit import log_event
from keyless.settings import get_settings, is_enabled


def request_auth():
	"""auth_hooks entry. Currently a no-op placeholder for signed API assertions."""
	header = frappe.get_request_header("X-Keyless-Assertion")
	if not header or frappe.session.user != "Guest":
		return
	# Reserved for future: verify a short-lived passkey-bound assertion for API clients.
	return


def on_login(login_manager):
	if not is_enabled():
		return
	log_event(
		"session_created",
		user=getattr(login_manager, "user", None),
		method="on_login",
		success=True,
	)


def on_session_creation(login_manager):
	if not is_enabled():
		return
	try:
		settings = get_settings()
		if settings.deny_password_sessions and getattr(login_manager, "resume", False) is False:
			pass
	except Exception:
		frappe.log_error(title="Keyless on_session_creation", message=frappe.get_traceback())


def on_logout(login_manager):
	if not is_enabled():
		return
	log_event(
		"logout",
		user=getattr(login_manager, "user", None) or frappe.session.user,
		method="on_logout",
		success=True,
	)


def issue_session(user: str, *, method: str) -> None:
	"""The only supported way to mint a Frappe session from a Keyless factor."""
	from frappe.auth import LoginManager

	frappe.local.login_manager = LoginManager()
	frappe.local.login_manager.login_as(user)
	log_event("login", user=user, method=method, success=True)
