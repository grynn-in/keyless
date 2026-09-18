"""Override frappe.handler `login` so password can be disabled site-wide.

Break-glass: Administrator may still use a password when
`allow_administrator_password` is set. Per-user `keyless_passwordless_only`
blocks passwords even if the site still allows them.
"""

from __future__ import annotations

import frappe
from frappe import _
from frappe.auth import LoginManager

from keyless.audit import log_event
from keyless.settings import get_settings, is_enabled


@frappe.whitelist(allow_guest=True)
def login():
	if not is_enabled():
		return _core_login()

	settings = get_settings()
	usr = (frappe.form_dict.get("usr") or "").strip()
	pwd = frappe.form_dict.get("pwd")

	if not pwd:
		return _core_login()

	if _password_blocked(usr, settings):
		log_event("password_blocked", user=usr or "Guest", method="login", success=False)
		frappe.local.response["message"] = _("Password login is disabled. Use a passkey or email code.")
		frappe.throw(_("Password login is disabled. Use a passkey or email code."), frappe.AuthenticationError)

	return _core_login()


def _password_blocked(usr: str, settings) -> bool:
	if usr == "Administrator" and settings.allow_administrator_password:
		return False
	if settings.disable_password_login:
		return True
	if usr and frappe.db.get_value("User", usr, "keyless_passwordless_only"):
		return True
	return False


def _core_login():
	frappe.local.login_manager = LoginManager()
	frappe.local.login_manager.login()
	login_as = getattr(frappe.local.login_manager, "user", None)
	if login_as and login_as != "Guest":
		log_event("login", user=login_as, method="password", success=True)
	return "Logged In"
