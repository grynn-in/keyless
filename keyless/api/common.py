from __future__ import annotations

import time
from urllib.parse import urlparse

import frappe
from frappe import _

from keyless.settings import get_settings, is_enabled
from keyless.user import resolve_enabled_user


def require_enabled():
	if not is_enabled():
		frappe.throw(_("Keyless is disabled"), frappe.AuthenticationError)
	return get_settings()


def get_rate_limit() -> int:
	try:
		return int(get_settings().rate_limit_per_hour or 5)
	except Exception:
		return 5


def normalize_email(email: str) -> str:
	return (email or "").strip().lower()


def pretend_success_if_unknown(email: str) -> str | None:
	"""Resolve an enabled user, or return None without leaking existence."""
	return resolve_enabled_user(email)


def constant_time_delay():
	# Cheap equalisation so missing users don't return faster than mail send.
	time.sleep(0.15)


def client_origin() -> str:
	"""Origin the authenticator signed. Prefer the browser Origin header.

	`frappe.utils.get_url()` follows site_config host_name and is often wrong
	on a local bench (port 8000 vs 8001, http vs https).
	"""
	origin = (frappe.get_request_header("Origin") or "").strip().rstrip("/")
	if origin and origin.lower() != "null":
		return origin
	request = getattr(frappe.local, "request", None)
	if request is not None and request.host:
		scheme = request.scheme or "http"
		return f"{scheme}://{request.host}".rstrip("/")
	return frappe.utils.get_url().rstrip("/")


def rp_id() -> str:
	settings = get_settings()
	if settings.rp_id:
		return settings.rp_id
	return urlparse(client_origin()).hostname or "localhost"


def rp_name() -> str:
	settings = get_settings()
	return settings.rp_name or frappe.get_website_settings("app_name") or "Frappe"
