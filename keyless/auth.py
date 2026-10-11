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
from keyless.settings import is_enabled


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
	password_policy.enforce(login_name=password_login_name())


def password_login_name() -> str | None:
	"""The login name LoginManager.login() is about to check, chosen as Frappe chooses it.

	The second leg of Frappe's 2FA flow (`tmp_id`) takes the name and password
	from the cache, but only when both are there; otherwise Frappe falls back to
	the form's `usr` and `pwd` (LoginManager.authenticate, v15 and v16). A
	`tmp_id` with nothing cached used to make this check nobody while Frappe
	still checked the form's password (audit 2026-10-10, F-1).
	"""
	from frappe.twofactor import get_cached_user_pass

	user, pwd = get_cached_user_pass()
	if user and pwd:
		return user
	return frappe.form_dict.get("usr")


def on_login(login_manager):
	if not is_enabled():
		return
	if not frappe.flags.get("keyless_login"):
		if frappe.flags.get("keyless_password_login") or password_policy.is_password_login_request():
			# Authoritative check on the user Frappe actually authenticated. The
			# password is already verified here, so a refusal must look like a
			# wrong password, never like BLOCKED_MESSAGE (F-1). The second case
			# is Frappe 15 before keyless.compat patched login() in this process.
			password_policy.enforce_after_password_check(login_manager)
		else:
			password_policy.enforce_mailed_login(login_manager.user)
	log_event(
		"session_created",
		user=getattr(login_manager, "user", None),
		method="on_login",
		success=True,
	)


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

	password_policy.enforce_factor(user, method)
	# Tells the on_login hook this session comes from a Keyless factor, not a password.
	frappe.flags.keyless_login = method
	try:
		frappe.local.login_manager = LoginManager()
		frappe.local.login_manager.login_as(user)
	finally:
		frappe.flags.keyless_login = None
	log_event("login", user=user, method=method, success=True)
