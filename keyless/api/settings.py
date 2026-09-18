from __future__ import annotations

import frappe

from keyless.settings import get_settings, is_enabled


@frappe.whitelist()
def can_show_app() -> bool:
	if frappe.session.user == "Guest":
		return False
	return "System Manager" in frappe.get_roles()


@frappe.whitelist(allow_guest=True)
def public_config() -> dict:
	"""Login-page config. No secrets. Safe for guests."""
	if not is_enabled():
		return {"enabled": False}
	s = get_settings()
	return {
		"enabled": True,
		"disable_password_login": bool(s.disable_password_login),
		"enable_passkeys": bool(s.enable_passkeys),
		"enable_magic_link": bool(s.enable_magic_link),
		"enable_email_otp": bool(s.enable_email_otp),
		"enable_backup_codes": bool(s.enable_backup_codes),
		"allow_passwordless_signup": bool(s.allow_passwordless_signup),
		"otp_length": int(s.otp_length or 6),
		"replace_standard_login": bool(s.replace_standard_login),
		"login_route": "/keyless/login",
	}
