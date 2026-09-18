from __future__ import annotations

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import get_url
from frappe.utils.oauth import redirect_post_login

from keyless.api.common import (
	constant_time_delay,
	get_rate_limit,
	normalize_email,
	pretend_success_if_unknown,
	require_enabled,
)
from keyless.audit import log_event
from keyless.auth import issue_session
from keyless.tokens import consume_magic_key, random_token, store_magic_key


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=get_rate_limit, seconds=60 * 60)
def send_link(email: str, redirect_to: str | None = None):
	settings = require_enabled()
	if not settings.enable_magic_link:
		frappe.throw(_("Magic link login is disabled"))

	email = normalize_email(email)
	if not email or "@" not in email:
		frappe.throw(_("Enter a valid email address"))

	user = pretend_success_if_unknown(email)
	expiry_min = int(settings.magic_link_expiry_minutes or 10)

	if user:
		key = random_token(32)
		store_magic_key(key, email, expiry_min * 60)
		link = get_url(f"/api/method/keyless.api.magic_link.login_via_link?key={key}", allow_header_override=False)
		if redirect_to:
			link += f"&redirect_to={frappe.utils.quote(redirect_to)}"
		_send_link_mail(email, link, expiry_min)
		log_event("magic_link_sent", user=user, method="magic_link", success=True)
	else:
		constant_time_delay()
		if not settings.hide_user_enumeration:
			frappe.throw(_("No active user found"), frappe.DoesNotExistError)
		log_event("magic_link_sent", user=email, method="magic_link", success=False, detail="unknown")

	return {"ok": True, "expires_in": expiry_min * 60}


@frappe.whitelist(allow_guest=True, methods=["GET"])
@rate_limit(limit=get_rate_limit, seconds=60 * 60)
def login_via_link(key: str, redirect_to: str | None = None):
	settings = require_enabled()
	if not settings.enable_magic_link:
		frappe.throw(_("Magic link login is disabled"))

	email = consume_magic_key(key or "")
	user = pretend_success_if_unknown(email or "")
	if not email or not user:
		log_event("magic_link_failed", method="magic_link", success=False)
		frappe.respond_as_web_page(
			_("Not Permitted"),
			_("This sign-in link is invalid or has expired."),
			http_status_code=403,
			indicator_color="red",
		)
		return

	issue_session(user, method="magic_link")
	desk_user = frappe.db.get_value("User", user, "user_type") == "System User"
	redirect_post_login(desk_user=desk_user, redirect_to=redirect_to)


def _send_link_mail(email: str, link: str, minutes: int):
	app_name = frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	try:
		frappe.sendmail(
			recipients=email,
			subject=_("Sign in to {0}").format(app_name),
			template="keyless_magic_link",
			args={"link": link, "minutes": minutes, "app_name": app_name},
			now=True,
			with_container=True,
		)
	except frappe.OutgoingEmailError:
		frappe.log_error(title="Keyless magic link mail failed", message=frappe.get_traceback())
		frappe.throw(_("Could not send email. Try a passkey or contact your administrator."))
