from __future__ import annotations

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import escape_html, get_url
from frappe.utils.oauth import redirect_post_login

from keyless.api.common import (
	get_rate_limit,
	normalize_email,
	pretend_success_if_unknown,
	require_enabled,
)
from keyless.audit import log_event
from keyless.auth import issue_session
from keyless.redirects import safe_redirect
from keyless.tokens import consume_magic_link, peek_magic_link, random_token, store_magic_key


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
		# The target stays in Redis with the key, never in the emailed URL (audit H-2).
		store_magic_key(key, email, expiry_min * 60, redirect_to=safe_redirect(redirect_to))
		link = get_url(f"/api/method/keyless.api.magic_link.login_via_link?key={key}", allow_header_override=False)
		_send_link_mail(email, link, expiry_min)
		log_event("magic_link_sent", user=user, method="magic_link", success=True)
	else:
		if not settings.hide_user_enumeration:
			frappe.throw(_("No active user found"), frappe.DoesNotExistError)
		log_event("magic_link_sent", user=email, method="magic_link", success=False, detail="unknown")

	return {"ok": True, "expires_in": expiry_min * 60}


@frappe.whitelist(allow_guest=True, methods=["GET", "POST"])
@rate_limit(limit=get_rate_limit, seconds=60 * 60)
def login_via_link(key: str, redirect_to: str | None = None):
	"""GET (opening the emailed link) only shows a confirmation page; the POST from
	its button uses up the link and signs in. Mail scanners and link previews only
	send GETs, so they no longer burn links or sign anyone in (audit M-4, D8)."""
	settings = require_enabled()
	if not settings.enable_magic_link:
		frappe.throw(_("Magic link login is disabled"))

	if frappe.request.method != "POST":
		if not peek_magic_link(key or ""):
			return _invalid_link_page()
		return _confirmation_page(key, safe_redirect(redirect_to))

	payload = consume_magic_link(key or "") or {}
	email = payload.get("email")
	user = pretend_success_if_unknown(email or "")
	if not email or not user:
		log_event("magic_link_failed", method="magic_link", success=False)
		return _invalid_link_page()

	issue_session(user, method="magic_link")
	desk_user = frappe.db.get_value("User", user, "user_type") == "System User"
	# Links sent before this change carry redirect_to in the URL; accept it only if it is safe.
	target = safe_redirect(payload.get("redirect_to")) or safe_redirect(redirect_to)
	redirect_post_login(desk_user=desk_user, redirect_to=target)


def _invalid_link_page():
	frappe.respond_as_web_page(
		_("Not Permitted"),
		_("This sign-in link is invalid or has expired."),
		http_status_code=403,
		indicator_color="red",
	)


def _confirmation_page(key: str, redirect_to: str | None):
	app_name = frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	fields = {"key": key}
	if redirect_to:  # only from links sent before targets were stored with the key
		fields["redirect_to"] = redirect_to
	if csrf_token := frappe.session.data.get("csrf_token"):
		# A browser that is already signed in has a CSRF token and must send it.
		fields["csrf_token"] = csrf_token
	hidden = "".join(
		f'<input type="hidden" name="{escape_html(name)}" value="{escape_html(value)}">'
		for name, value in fields.items()
	)
	html = (
		f"<p>{escape_html(_('Continue to sign in to {0}.').format(app_name))}</p>"
		'<form method="post" action="/api/method/keyless.api.magic_link.login_via_link">'
		f'{hidden}<button type="submit" class="btn btn-primary btn-sm">{escape_html(_("Sign in"))}</button>'
		"</form>"
	)
	frappe.respond_as_web_page(_("Sign in"), html, indicator_color="blue", primary_action=None)


def _send_link_mail(email: str, link: str, minutes: int):
	app_name = frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	try:
		frappe.sendmail(
			recipients=email,
			subject=_("Sign in to {0}").format(app_name),
			template="keyless_magic_link",
			args={"link": link, "minutes": minutes, "app_name": app_name},
			# Queued, so known and unknown addresses do the same work (audit M-2).
			now=False,
			with_container=True,
		)
	except Exception:
		# Same response as for an unknown address; the failure is only logged.
		frappe.log_error(title="Keyless magic link mail failed", message=frappe.get_traceback())
