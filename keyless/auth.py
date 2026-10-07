"""Request-level auth hook and session events.

`auth_hooks` run on every request *after* Frappe has tried cookie / API-key /
OAuth. Use this only for additive authenticators (e.g. a signed Keyless
assertion header). Session issuance for browser login always goes through
LoginManager.login_as — never frappe.set_user() from a guest POST without a
session cookie.
"""

from __future__ import annotations

import frappe

from keyless import password_policy
from keyless.audit import log_event
from keyless.settings import get_settings, is_enabled


def request_auth():
	"""auth_hooks entry. Currently a no-op placeholder for signed API assertions."""
	header = frappe.get_request_header("X-Keyless-Assertion")
	if not header or frappe.session.user != "Guest":
		return
	# Reserved for future: verify a short-lived passkey-bound assertion for API clients.
	return


def before_login(login_manager):
	"""Runs inside LoginManager.login(), i.e. only for username/password logins,
	before the password is checked, so a blocked login looks the same whether
	or not the password was right (audit C-2)."""
	frappe.flags.keyless_password_login = True
	login_name = frappe.form_dict.get("usr")
	if frappe.form_dict.get("tmp_id"):
		# Second leg of Frappe's 2FA flow: credentials come from the cache.
		from frappe.twofactor import get_cached_user_pass

		login_name = get_cached_user_pass()[0]
	password_policy.enforce(login_name=login_name)


def on_login(login_manager):
	if not is_enabled():
		return
	if frappe.flags.get("keyless_password_login") and not frappe.flags.get("keyless_login"):
		# Authoritative check on the user Frappe actually authenticated.
		password_policy.enforce(user=login_manager.user)
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

	# Tells the on_login hook this session comes from a Keyless factor, not a password.
	frappe.flags.keyless_login = method
	try:
		frappe.local.login_manager = LoginManager()
		frappe.local.login_manager.login_as(user)
	finally:
		frappe.flags.keyless_login = None
	log_event("login", user=user, method=method, success=True)
