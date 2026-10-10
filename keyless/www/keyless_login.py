"""Keyless sign-in page.

Mirrors Frappe's own `frappe/www/login.py` + `login.html` (v15 and v16) so the
page reuses Frappe's `login.bundle.css` and looks like the standard login page.
"""

from urllib.parse import quote

import frappe
from frappe import _
from frappe.apps import get_default_path
from frappe.core.doctype.navbar_settings.navbar_settings import get_app_logo
from frappe.utils import cint
from frappe.website.utils import get_home_page

from keyless.redirects import safe_redirect
from keyless.settings import get_settings, is_enabled

no_cache = 1


def frappe_major_version() -> int:
	return cint(str(frappe.__version__).split(".", 1)[0])


def get_context(context):
	frappe_major = frappe_major_version()
	# Same-site relative paths only; anything else falls back to the default (audit H-1).
	redirect_to = safe_redirect(frappe.form_dict.get("redirect-to") or frappe.form_dict.get("redirect_to"))

	# Same as Frappe's login page: a signed-in user is sent on, not shown the form.
	if frappe.session.user != "Guest":
		if not redirect_to:
			if frappe.session.data.user_type == "Website User":
				redirect_to = get_default_path() or get_home_page()
			else:
				redirect_to = get_default_path() or ("/desk" if frappe_major >= 16 else "/app")
		frappe.local.flags.redirect_location = redirect_to
		raise frappe.Redirect

	context.no_header = True
	context.no_cache = 1
	context.title = _("Login")
	context.hide_login = True
	context.frappe_major = frappe_major
	context.frappe_v16 = frappe_major >= 16
	# v15 styles the main button as .btn-primary; v16 as .btn-default.btn-login.
	context.primary_btn = "btn-default" if context.frappe_v16 else "btn-primary"
	context.back_links = [
		{"href": "#login", "label": _("Back to sign in") if context.frappe_v16 else _("Back to Login")}
	]

	enabled = is_enabled()
	settings = get_settings() if enabled else None
	context.keyless_enabled = enabled
	context.enable_passkeys = bool(settings and settings.enable_passkeys)
	context.enable_magic_link = bool(settings and settings.enable_magic_link)
	context.enable_email_otp = bool(settings and settings.enable_email_otp)
	context.enable_backup_codes = bool(settings and settings.enable_backup_codes)
	context.disable_password = bool(settings and settings.disable_password_login)
	context.allow_administrator_password = bool(settings and settings.allow_administrator_password)
	context.otp_length = cint(settings.otp_length) if settings else 6

	# The email form's submit button runs the first enabled email factor; the
	# rest render as Frappe's secondary "login option" buttons.
	context.primary_action = (
		"otp" if context.enable_email_otp else "link" if context.enable_magic_link else None
	)
	context.needs_email = bool(context.primary_action)
	context.has_options = bool(
		(context.enable_passkeys and context.primary_action)
		or (context.enable_magic_link and context.primary_action != "link")
		or not context.disable_password
	)

	context.app_name = (
		frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	)
	context.logo = get_app_logo()
	context.redirect_to = redirect_to
	context.password_login_url = "/login" + (f"?redirect-to={quote(redirect_to, safe='')}" if redirect_to else "")

	# Text links at the foot of the card, where Frappe shows "Sign up".
	context.footer_links = []
	if context.enable_backup_codes:
		context.footer_links.append({"href": "#recovery", "label": _("Use a recovery code")})
	if context.disable_password and context.allow_administrator_password:
		# Break-glass: the password policy still accepts Administrator's password.
		context.footer_links.append(
			{"href": context.password_login_url, "label": _("Administrator? Login with password")}
		)
	return context
