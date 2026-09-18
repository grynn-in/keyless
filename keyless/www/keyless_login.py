import frappe
from frappe import _
from frappe.utils import cint, get_url

from keyless.settings import get_settings, is_enabled

no_cache = 1


def get_context(context):
	context.no_header = True
	context.no_cache = 1
	context.title = _("Sign in")
	context.hide_login = True

	enabled = is_enabled()
	settings = get_settings() if enabled else None
	context.keyless_enabled = enabled
	context.enable_passkeys = bool(settings and settings.enable_passkeys)
	context.enable_magic_link = bool(settings and settings.enable_magic_link)
	context.enable_email_otp = bool(settings and settings.enable_email_otp)
	context.enable_backup_codes = bool(settings and settings.enable_backup_codes)
	context.disable_password = bool(settings and settings.disable_password_login)
	context.otp_length = cint(settings.otp_length) if settings else 6
	context.app_name = (
		frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	)
	context.logo = get_url("/assets/keyless/images/keyless-mark.svg")
	context.redirect_to = frappe.form_dict.get("redirect-to") or frappe.form_dict.get("redirect_to")
	return context
