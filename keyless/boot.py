"""Expose Keyless policy to Desk and the website login page via bootinfo."""

from __future__ import annotations

import frappe

from keyless.settings import get_settings, is_enabled


def extend_bootinfo(bootinfo):
	if not is_enabled():
		bootinfo["keyless"] = {"enabled": False}
		return
	settings = get_settings()
	bootinfo["keyless"] = {
		"enabled": True,
		"disable_password_login": bool(settings.disable_password_login),
		"enable_passkeys": bool(settings.enable_passkeys),
		"enable_magic_link": bool(settings.enable_magic_link),
		"enable_email_otp": bool(settings.enable_email_otp),
		"enable_backup_codes": bool(settings.enable_backup_codes),
		"replace_standard_login": bool(settings.replace_standard_login),
		"login_route": "/keyless/login",
		"rp_id": settings.rp_id or _default_rp_id(),
		"rp_name": settings.rp_name or (frappe.local.conf.get("app_name") or "Frappe"),
	}


def _default_rp_id() -> str:
	from urllib.parse import urlparse

	url = frappe.utils.get_url()
	return urlparse(url).hostname or "localhost"
