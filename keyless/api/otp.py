from __future__ import annotations

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit

from keyless.api.common import (
	get_rate_limit,
	normalize_email,
	pretend_success_if_unknown,
	require_enabled,
)
from keyless.audit import log_event
from keyless.auth import issue_session
from keyless.tokens import count_hit, hit_count, random_otp, store_otp, verify_and_consume_otp

HOUR = 60 * 60
DAY = 24 * HOUR
# An account may make this many times max_otp_attempts wrong guesses per hour.
ACCOUNT_GUESS_FACTOR = 2


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=get_rate_limit, seconds=60 * 60)
def request_otp(email: str):
	"""Send a one-time email code. Always returns ok when enumeration is hidden."""
	settings = require_enabled()
	if not settings.enable_email_otp:
		frappe.throw(_("Email OTP is disabled"))

	email = normalize_email(email)
	if not email or "@" not in email:
		frappe.throw(_("Enter a valid email address"))

	# Per-account limits, independent of the client IP (which a client can spoof
	# via X-Forwarded-For behind a misconfigured proxy). Unknown addresses are
	# counted the same way, so the limits reveal nothing (audit M-1).
	if count_hit("otp-request-hour", email, HOUR) > int(settings.rate_limit_per_hour or 5):
		_too_many()
	if count_hit("otp-request-day", email, DAY) > int(settings.otp_daily_limit or 10):
		_too_many()

	user = pretend_success_if_unknown(email)
	expires = int(settings.otp_expiry_seconds or 300)
	length = int(settings.otp_length or 6)

	if user:
		otp = random_otp(length)
		store_otp(email, otp, expires)
		_send_otp_mail(email, otp, expires)
		log_event("otp_requested", user=user, method="email_otp", success=True)
	else:
		if not settings.hide_user_enumeration:
			frappe.throw(_("No active user found"), frappe.DoesNotExistError)
		log_event("otp_requested", user=email, method="email_otp", success=False, detail="unknown")

	return {"ok": True, "expires_in": expires, "length": length}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=get_rate_limit, seconds=60 * 60)
def verify_otp(email: str, otp: str):
	settings = require_enabled()
	if not settings.enable_email_otp:
		frappe.throw(_("Email OTP is disabled"))

	email = normalize_email(email)
	max_attempts = int(settings.max_otp_attempts or 5)
	# Wrong guesses per account per hour, across every code issued in that hour,
	# so requesting a new code does not buy more guesses (audit M-1).
	if hit_count("otp-fail-hour", email) >= max_attempts * ACCOUNT_GUESS_FACTOR:
		_too_many()
	user = pretend_success_if_unknown(email)
	if not user or not verify_and_consume_otp(email, otp or "", max_attempts):
		count_hit("otp-fail-hour", email, HOUR)
		log_event("otp_failed", user=email, method="email_otp", success=False)
		frappe.throw(_("Invalid or expired code"), frappe.AuthenticationError)

	issue_session(user, method="email_otp")
	return {"ok": True, "user": user, "home": _home_for(user)}


def _too_many():
	frappe.throw(_("Too many attempts. Try again later."), frappe.RateLimitExceededError)


def _send_otp_mail(email: str, otp: str, expires: int):
	app_name = frappe.get_website_settings("app_name") or frappe.get_system_settings("app_name") or _("Frappe")
	minutes = max(1, int(expires / 60))
	try:
		frappe.sendmail(
			recipients=email,
			subject=_("Your {0} sign-in code").format(app_name),
			template="keyless_otp",
			args={"otp": otp, "minutes": minutes, "app_name": app_name},
			# Queued, so known and unknown addresses do the same work (audit M-2).
			now=False,
			with_container=True,
		)
	except Exception:
		# Same response as for an unknown address; the failure is only logged.
		frappe.log_error(title="Keyless OTP mail failed", message=frappe.get_traceback())


def _home_for(user: str) -> str:
	if frappe.db.get_value("User", user, "user_type") == "System User":
		return "/app"
	return frappe.utils.get_url()
