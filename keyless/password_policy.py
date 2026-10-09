"""Who may sign in with a password, and where that is enforced.

Frappe performs username/password login inside `LoginManager()` itself
(`cmd=login` on any path, or `/api/method/login`), before any whitelisted
method runs, so the policy is enforced from the `before_login` and
`on_login` hooks, which run on every password path (audit C-2).

Frappe 15 has no `before_login` hook. There the policy runs from `on_login`,
after the password has been checked, and a blocked login is refused exactly
as a wrong password is, so the response still never confirms a password.
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


def password_blocked(user: str | None, settings, *, frappe_2fa_runs: bool = True) -> bool:
	"""`user` is a resolved User name, or None when the login name matches nobody.

	`frappe_2fa_runs` is False on paths that check the password without Frappe's
	2FA step, such as the OAuth2 password grant.
	"""
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
		# D9: a password is still allowed when Frappe 2FA will ask for a second factor.
		from frappe.twofactor import two_factor_is_enabled

		return not (frappe_2fa_runs and two_factor_is_enabled(user=user))
	return False


# Factors that prove only control of the mailbox. They are refused for System
# Users when require_passkey_for_system_users is on (D5), and for anyone
# Frappe 2FA applies to, since login_as() skips Frappe's 2FA step (D3).
EMAIL_FACTORS = ("email_otp", "magic_link")


def email_factor_refusal(user: str) -> str | None:
	"""Why `user` may not use email factors (a short reason), or None if they may."""
	from frappe.twofactor import two_factor_is_enabled

	if (
		get_settings().require_passkey_for_system_users
		and frappe.db.get_value("User", user, "user_type") == "System User"
	):
		return "passkey_required"
	if two_factor_is_enabled(user=user):
		return "frappe_2fa"
	return None


def enforce_factor(user: str, method: str) -> None:
	"""Raise AuthenticationError if `user` may not sign in with Keyless factor `method`."""
	if method not in EMAIL_FACTORS or not is_enabled():
		return
	reason = email_factor_refusal(user)
	if not reason:
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


# Frappe methods that create a session from a mailed secret: the password
# reset link (update_password with a key, also reached from an expired
# password) and Frappe's own "login with email link".
RESET_METHOD = "frappe.core.doctype.user.user.update_password"
EMAIL_LINK_METHOD = "frappe.www.login.login_via_key"
API_METHOD_PREFIXES = ("/api/method/", "/api/v1/method/", "/api/v2/method/")


def called_method() -> str:
	"""Dotted name of the whitelisted method this request calls, or ""."""
	request = getattr(frappe.local, "request", None)
	path = (getattr(request, "path", "") or "").rstrip("/")
	for prefix in API_METHOD_PREFIXES:
		if path.startswith(prefix):
			return path[len(prefix) :]
	return frappe.form_dict.get("cmd") or ""


def enforce_mailed_login(user: str) -> None:
	"""on_login check for sessions Frappe creates from a mailed secret.

	Frappe's email-link login proves only control of the mailbox, so it is
	held to the email-factor rules (D3, D5). A reset link signs the user in
	after setting a password, so it is held to the password rules, and to D5
	(System Users who need a passkey). It is not refused for Frappe 2FA users
	(D3): that would leave them no way to recover a forgotten password; the
	reset skipping Frappe 2FA is Frappe's own behaviour. Raising here stops
	login_as before the session exists, and the request (including the new
	password) is rolled back.
	"""
	method = called_method()
	if method not in (RESET_METHOD, EMAIL_LINK_METHOD) or not is_enabled():
		return
	settings = get_settings()
	reason = email_factor_refusal(user)
	if method == RESET_METHOD:
		if reason == "frappe_2fa":
			reason = None
		if not reason and password_blocked(user, settings, frappe_2fa_runs=False):
			reason = "password_blocked"
	if not reason:
		return
	log_event("factor_blocked", user=user, method=method.rsplit(".", 1)[-1], success=False, detail=reason)
	frappe.throw(_("Sign in with a passkey."), frappe.AuthenticationError)


def is_password_login_request() -> bool:
	"""True on the requests LoginManager() treats as a username/password login."""
	request = getattr(frappe.local, "request", None)
	return frappe.form_dict.get("cmd") == "login" or getattr(request, "path", None) == "/api/method/login"


def _blocked(*, login_name: str | None = None, user: str | None = None, method: str = "password") -> bool:
	"""True, after writing the audit entry, if this password login is not allowed."""
	if not is_enabled():
		return False
	if user is None:
		user = resolve_login_name(login_name)
	if not password_blocked(user, get_settings(), frappe_2fa_runs=method == "password"):
		return False
	log_event(
		"password_blocked",
		user=user or "Guest",
		method=method,
		success=False,
		detail=None if user else (login_name or "")[:140],
	)
	return True


def enforce(*, login_name: str | None = None, user: str | None = None, method: str = "password") -> None:
	"""Raise AuthenticationError if this password login is not allowed."""
	if _blocked(login_name=login_name, user=user, method=method):
		frappe.throw(_(BLOCKED_MESSAGE), frappe.AuthenticationError)


def enforce_after_password_check(login_manager) -> None:
	"""Frappe 15 path: the password is already verified when this runs.

	Answering with BLOCKED_MESSAGE here would tell a caller the password was
	right, so fail the login the way Frappe fails a wrong password. The audit
	log keeps the real reason.
	"""
	if _blocked(user=login_manager.user):
		login_manager.fail("Invalid login credentials", user=login_manager.user)
