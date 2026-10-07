"""Who may sign in with a password, and where that is enforced.

Frappe performs username/password login inside `LoginManager()` itself
(`cmd=login` on any path, or `/api/method/login`), before any whitelisted
method runs, so the policy is enforced from the `before_login` and
`on_login` hooks, which run on every password path (audit C-2).
"""

from __future__ import annotations

import frappe
from frappe import _

from keyless.audit import log_event
from keyless.settings import get_settings, is_enabled

# One message for every blocked attempt, whatever the password, so a block
# never confirms a correct password.
BLOCKED_MESSAGE = "Password login is disabled. Use a passkey or email code."


def resolve_login_name(login_name: str | None) -> str | None:
	"""The User a login name refers to, the way Frappe resolves it.

	Frappe accepts the user name and, when enabled in System Settings, a
	username or mobile number. Mirror that so the policy cannot be bypassed
	by typing a different identifier.
	"""
	login_name = (login_name or "").strip()
	if not login_name:
		return None
	from frappe.core.doctype.user.user import User

	found = User.find_by_credentials(login_name, "", validate_password=False)
	return found["name"] if found else None


def password_blocked(user: str | None, settings) -> bool:
	"""`user` is a resolved User name, or None when the login name matches nobody."""
	if user == "Administrator" and settings.allow_administrator_password:
		return False
	if settings.disable_password_login:
		return True
	if not user:
		return False
	flags = frappe.db.get_value("User", user, ["keyless_passwordless_only", "user_type"], as_dict=True) or {}
	if flags.get("keyless_passwordless_only"):
		return True
	if settings.require_passkey_for_system_users and flags.get("user_type") == "System User":
		return True
	return False


# Factors that prove only control of the mailbox. They are refused for System
# Users when require_passkey_for_system_users is on (D5), and for anyone
# Frappe 2FA applies to, since login_as() skips Frappe's 2FA step (D3).
EMAIL_FACTORS = ("email_otp", "magic_link")


def enforce_factor(user: str, method: str) -> None:
	"""Raise AuthenticationError if `user` may not sign in with Keyless factor `method`."""
	if method not in EMAIL_FACTORS or not is_enabled():
		return
	from frappe.twofactor import two_factor_is_enabled

	if (
		get_settings().require_passkey_for_system_users
		and frappe.db.get_value("User", user, "user_type") == "System User"
	):
		reason = "passkey_required"
	elif two_factor_is_enabled(user=user):
		reason = "frappe_2fa"
	else:
		return
	log_event("factor_blocked", user=user, method=method, success=False, detail=reason)
	frappe.throw(_("Sign in with a passkey."), frappe.AuthenticationError)


OAUTH_TOKEN_METHOD = "frappe.integrations.oauth2.get_token"


def block_oauth_password_grant() -> None:
	"""before_request hook. Frappe's OAuth2 provider accepts grant_type=password
	and checks the password with LoginManager.authenticate(), which runs no
	login hooks, so the policy is applied here (audit H-4b, D4)."""
	form = frappe.form_dict
	if form.get("grant_type") != "password":
		return
	request = getattr(frappe.local, "request", None)
	path = (getattr(request, "path", "") or "").rstrip("/")
	if not (path.endswith("/" + OAUTH_TOKEN_METHOD) or form.get("cmd") == OAUTH_TOKEN_METHOD):
		return
	enforce(login_name=form.get("username"), method="oauth_password")


def enforce(*, login_name: str | None = None, user: str | None = None, method: str = "password") -> None:
	"""Raise AuthenticationError if this password login is not allowed."""
	if not is_enabled():
		return
	if user is None:
		user = resolve_login_name(login_name)
	if not password_blocked(user, get_settings()):
		return
	log_event(
		"password_blocked",
		user=user or "Guest",
		method=method,
		success=False,
		detail=None if user else (login_name or "")[:140],
	)
	frappe.throw(_(BLOCKED_MESSAGE), frappe.AuthenticationError)
