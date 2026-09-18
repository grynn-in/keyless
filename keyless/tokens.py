"""Secret hashing, OTP generation, and Redis-backed challenge store.

Never persist a raw OTP, magic-link key, or WebAuthn challenge. Values live in
Redis (frappe.cache) with a TTL; only HMAC-SHA256 digests of one-time codes are
compared, using the site encryption_key as pepper.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

import frappe
from frappe.utils import cint, now_datetime


OTP_CACHE_PREFIX = "keyless:otp:"
MAGIC_CACHE_PREFIX = "keyless:magic:"
CHALLENGE_CACHE_PREFIX = "keyless:challenge:"
LOCK_CACHE_PREFIX = "keyless:lock:"


def _pepper() -> str:
	return str(frappe.local.conf.get("encryption_key") or frappe.local.conf.get("secret_key") or "")


def digest(value: str) -> str:
	"""HMAC-SHA256 hex digest, peppered with the site encryption key."""
	return hmac.new(_pepper().encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def compare(value: str, expected_digest: str) -> bool:
	if not expected_digest:
		return False
	return hmac.compare_digest(digest(value), expected_digest)


def random_otp(length: int = 6) -> str:
	length = max(4, min(cint(length) or 6, 8))
	# secrets.randbelow avoids modulo bias of random.randint
	return "".join(str(secrets.randbelow(10)) for _ in range(length))


def random_token(nbytes: int = 32) -> str:
	return secrets.token_urlsafe(nbytes)


def cache_set(prefix: str, key: str, payload: dict[str, Any], expires_in_sec: int) -> None:
	frappe.cache.set_value(f"{prefix}{key}", payload, expires_in_sec=expires_in_sec)


def cache_get(prefix: str, key: str) -> dict[str, Any] | None:
	value = frappe.cache.get_value(f"{prefix}{key}")
	return value if isinstance(value, dict) else None


def cache_delete(prefix: str, key: str) -> None:
	frappe.cache.delete_value(f"{prefix}{key}")


def store_otp(email: str, otp: str, expires_in_sec: int) -> None:
	cache_set(
		OTP_CACHE_PREFIX,
		email,
		{
			"digest": digest(otp),
			"attempts": 0,
			"created": str(now_datetime()),
		},
		expires_in_sec,
	)


def verify_and_consume_otp(email: str, otp: str, max_attempts: int = 5) -> bool:
	payload = cache_get(OTP_CACHE_PREFIX, email)
	if not payload:
		return False
	attempts = cint(payload.get("attempts")) + 1
	payload["attempts"] = attempts
	if attempts > max_attempts:
		cache_delete(OTP_CACHE_PREFIX, email)
		return False
	if not compare(otp.strip(), payload.get("digest") or ""):
		cache_set(OTP_CACHE_PREFIX, email, payload, expires_in_sec=300)
		return False
	cache_delete(OTP_CACHE_PREFIX, email)
	return True


def store_magic_key(key: str, email: str, expires_in_sec: int) -> None:
	# Key is unguessable; value is the bound email. Consume on first GET.
	cache_set(MAGIC_CACHE_PREFIX, key, {"email": email, "created": str(now_datetime())}, expires_in_sec)


def consume_magic_key(key: str) -> str | None:
	payload = cache_get(MAGIC_CACHE_PREFIX, key)
	cache_delete(MAGIC_CACHE_PREFIX, key)
	if not payload:
		return None
	return payload.get("email")


def store_challenge(challenge_id: str, payload: dict[str, Any], expires_in_sec: int = 300) -> None:
	cache_set(CHALLENGE_CACHE_PREFIX, challenge_id, payload, expires_in_sec)


def consume_challenge(challenge_id: str) -> dict[str, Any] | None:
	payload = cache_get(CHALLENGE_CACHE_PREFIX, challenge_id)
	cache_delete(CHALLENGE_CACHE_PREFIX, challenge_id)
	return payload
