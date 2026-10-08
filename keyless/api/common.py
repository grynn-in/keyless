from __future__ import annotations

from urllib.parse import urlsplit

import frappe
from frappe import _

from keyless.settings import get_settings, is_enabled
from keyless.user import resolve_enabled_user


def require_enabled():
	if not is_enabled():
		frappe.throw(_("Keyless is disabled"), frappe.AuthenticationError)
	return get_settings()


HOUR = 60 * 60
DAY = 24 * HOUR

# Per-IP limits only stop floods from one address. A whole office can share one IP
# behind NAT, so they sit well above what one person needs; the per-account limits
# below are what protect individual accounts (audit L-2).
IP_LIMIT_FACTOR = 20  # email and code endpoints: 100 per hour by default
PASSKEY_IP_LIMIT_FACTOR = 200  # passkey endpoints: every attempt needs a valid signature


def get_rate_limit() -> int:
	"""Rate Limit per Hour: requests per account per hour."""
	try:
		return int(get_settings().rate_limit_per_hour or 5)
	except Exception:
		return 5


def get_ip_rate_limit() -> int:
	return get_rate_limit() * IP_LIMIT_FACTOR


def get_passkey_ip_rate_limit() -> int:
	return get_rate_limit() * PASSKEY_IP_LIMIT_FACTOR


def too_many():
	frappe.throw(_("Too many attempts. Try again later."), frappe.RateLimitExceededError)


def limit_mail_requests(email: str, settings, kind: str) -> None:
	"""Per-account limits on codes or links mailed to `email`, whatever the client IP.
	Unknown addresses are counted the same way, so the limits reveal nothing (M-1)."""
	from keyless.tokens import count_hit

	if count_hit(f"{kind}-request-hour", email, HOUR) > int(settings.rate_limit_per_hour or 5):
		too_many()
	if count_hit(f"{kind}-request-day", email, DAY) > int(settings.otp_daily_limit or 10):
		too_many()


def normalize_email(email: str) -> str:
	return (email or "").strip().lower()


def pretend_success_if_unknown(email: str) -> str | None:
	"""Resolve an enabled user, or return None without leaking existence."""
	return resolve_enabled_user(email)


def site_origin() -> str:
	"""Origin of the configured site URL (site_config host_name, else the site name).

	Never derived from request headers, which the client controls (audit H-5).
	"""
	parts = urlsplit(frappe.utils.get_url(allow_header_override=False))
	return f"{parts.scheme}://{parts.netloc}"


def allowed_origins() -> list[str]:
	"""Origins a passkey ceremony may come from: the site origin plus the
	Allowed Origins setting (for example a bench port or an extra domain)."""
	origins = [site_origin()]
	for line in (get_settings().allowed_origins or "").splitlines():
		origin = line.strip().rstrip("/")
		if origin and origin not in origins:
			origins.append(origin)
	return origins


def rp_id() -> str:
	"""The configured RP ID, else the configured site's hostname. Never a request header."""
	settings = get_settings()
	if settings.rp_id:
		return settings.rp_id
	return urlsplit(site_origin()).hostname or "localhost"


def rp_name() -> str:
	settings = get_settings()
	return settings.rp_name or frappe.get_website_settings("app_name") or "Frappe"
