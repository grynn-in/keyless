from __future__ import annotations

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import add_to_date, escape_html, get_url, now_datetime
from frappe.utils.oauth import redirect_post_login

from keyless.api.common import (
	after_response,
	get_ip_rate_limit,
	limit_mail_requests,
	normalize_email,
	pretend_success_if_unknown,
	require_enabled,
)
from keyless.audit import log_event
from keyless.auth import issue_session
from keyless.redirects import safe_redirect
from keyless.tokens import compare, consume_magic_link, digest, peek_magic_link, random_token, store_magic_key


# A link only works in the browser that asked for it. send_link gives that browser a
# random ID in this cookie and stores a digest of it with the link; opening and
# confirming the link need the same ID. A page on another site can make a visitor's
# browser submit the confirmation form with a link the attacker asked for (signing
# the visitor into the attacker's account), but that browser has no matching ID, and
# SameSite=Lax keeps the cookie off cross-site form posts anyway (D8 follow-up).
BROWSER_COOKIE = "keyless_link_browser"


def _browser_id() -> str | None:
	request = getattr(frappe.local, "request", None)
	value = request.cookies.get(BROWSER_COOKIE) if request else None
	# Only IDs Keyless could have issued (random_token(32) is 43 URL-safe characters).
	if value and len(value) == 43 and value.replace("-", "").replace("_", "").isalnum():
		return value
	return None


def _bind_to_browser(expiry_min: int) -> str:
	"""This browser's ID (new if it has none), with the cookie kept for the link's life.
	One ID per browser, so every link it asked for keeps working."""
	browser = _browser_id() or random_token(32)
	cookie_manager = getattr(frappe.local, "cookie_manager", None)
	if cookie_manager:
		cookie_manager.set_cookie(
			BROWSER_COOKIE, browser, expires=add_to_date(now_datetime(), minutes=expiry_min), httponly=True
		)
	return browser


def _same_browser(payload: dict) -> bool:
	expected = payload.get("browser")
	if not expected:  # sent before links were bound to a browser
		return True
	browser = _browser_id()
	return bool(browser) and compare(browser, expected)


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=get_ip_rate_limit, seconds=60 * 60)
def send_link(email: str, redirect_to: str | None = None):
	settings = require_enabled()
	if not settings.enable_magic_link:
		frappe.throw(_("Magic link login is disabled"))

	email = normalize_email(email)
	if not email or "@" not in email:
		frappe.throw(_("Enter a valid email address"))

	limit_mail_requests(email, settings, "link")

	expiry_min = int(settings.magic_link_expiry_minutes or 10)
	if not settings.hide_user_enumeration and not pretend_success_if_unknown(email):
		frappe.throw(_("No active user found"), frappe.DoesNotExistError)
	target = safe_redirect(redirect_to)
	# Every request gets the cookie, whether or not the address has an account (M-2).
	browser = digest(_bind_to_browser(expiry_min))
	after_response(lambda: _deliver_link(email, expiry_min, target, browser))

	return {"ok": True, "expires_in": expiry_min * 60}


@frappe.whitelist(allow_guest=True, methods=["GET", "POST"])
@rate_limit(limit=get_ip_rate_limit, seconds=60 * 60)
def login_via_link(key: str, redirect_to: str | None = None):
	"""GET (opening the emailed link) only shows a confirmation page; the POST from
	its button uses up the link and signs in. Mail scanners and link previews only
	send GETs, so they no longer burn links or sign anyone in (audit M-4, D8)."""
	settings = require_enabled()
	if not settings.enable_magic_link:
		frappe.throw(_("Magic link login is disabled"))

	link = peek_magic_link(key or "")
	if not link:
		if frappe.request.method == "POST":
			log_event("magic_link_failed", method="magic_link", success=False)
		return _invalid_link_page()
	if not _same_browser(link):
		# The link stays valid, so its owner can still open it in the right browser.
		if frappe.request.method == "POST":
			log_event(
				"magic_link_failed", user=link.get("email"), method="magic_link", success=False, detail="other_browser"
			)
		return _other_browser_page()
	if frappe.request.method != "POST":
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


def _other_browser_page():
	frappe.respond_as_web_page(
		_("Open this link where you asked for it"),
		_(
			"For your security, a sign-in link only works in the browser it was requested from. "
			"Open it there, or request a new link or an email code in this browser."
		),
		http_status_code=403,
		indicator_color="orange",
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


def _deliver_link(email: str, expiry_min: int, redirect_to: str | None, browser: str | None = None) -> None:
	"""Create and mail a link if the address has an account; runs after the response."""
	user = pretend_success_if_unknown(email)
	if not user:
		log_event("magic_link_sent", user=email, method="magic_link", success=False, detail="unknown")
		return
	key = random_token(32)
	# The target stays in Redis with the key, never in the emailed URL (audit H-2).
	store_magic_key(key, email, expiry_min * 60, redirect_to=redirect_to, browser=browser)
	link = get_url(f"/api/method/keyless.api.magic_link.login_via_link?key={key}", allow_header_override=False)
	_send_link_mail(email, link, expiry_min)
	log_event("magic_link_sent", user=user, method="magic_link", success=True)


def _send_link_mail(email: str, link: str, minutes: int):
	app_name = frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	messages_before = len(frappe.local.message_log)
	try:
		frappe.sendmail(
			recipients=email,
			subject=_("Sign in to {0}").format(app_name),
			template="keyless_magic_link",
			args={"link": link, "minutes": minutes, "app_name": app_name},
			# Sent as soon as the transaction commits; the link is created after the
			# response, so this adds no timing difference (see _send_otp_mail).
			now=True,
			with_container=True,
		)
	except Exception:
		# Same response as for an unknown address; the failure is only logged.
		# frappe.throw() queues its message before raising, so drop it too, or
		# the error reaches the browser and shows the address exists (audit M-2).
		del frappe.local.message_log[messages_before:]
		frappe.log_error(title="Keyless magic link mail failed", message=frappe.get_traceback())
