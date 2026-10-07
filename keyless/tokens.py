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
ATTEMPTS_CACHE_PREFIX = "keyless:otp-attempts:"
RATE_CACHE_PREFIX = "keyless:rl:"


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


def _raw_key(name: str) -> bytes:
	return frappe.cache.make_key(name)


def store_otp(email: str, otp: str, expires_in_sec: int) -> None:
	cache_set(OTP_CACHE_PREFIX, email, {"digest": digest(otp), "created": str(now_datetime())}, expires_in_sec)
	# Attempts live in their own counter so they can be incremented atomically
	# (INCR) without rewriting the code, whose TTL must not change (audit M-1).
	frappe.cache.setex(_raw_key(ATTEMPTS_CACHE_PREFIX + email), expires_in_sec, 0)


def verify_and_consume_otp(email: str, otp: str, max_attempts: int = 5) -> bool:
	if not cache_get(OTP_CACHE_PREFIX, email):
		return False
	attempts_key = _raw_key(ATTEMPTS_CACHE_PREFIX + email)
	attempts = frappe.cache.incrby(attempts_key, 1)
	if attempts == 1 and frappe.cache.ttl(attempts_key) < 0:
		# Counter vanished (e.g. evicted) while the code lives: expire it with the code.
		frappe.cache.expire(attempts_key, max(1, frappe.cache.ttl(_raw_key(OTP_CACHE_PREFIX + email))))
	if attempts > max_attempts:
		# Delete the code but keep the counter, so requests already past the check
		# above keep counting instead of starting a fresh counter.
		frappe.cache.delete(_raw_key(OTP_CACHE_PREFIX + email))
		cache_delete(OTP_CACHE_PREFIX, email)
		return False
	if not compare(otp.strip(), (cache_get(OTP_CACHE_PREFIX, email) or {}).get("digest") or ""):
		return False
	# Only the request that actually deletes the code wins, so one code gives one session.
	return _delete_otp(email)


def _delete_otp(email: str) -> bool:
	deleted = frappe.cache.delete(_raw_key(OTP_CACHE_PREFIX + email))
	frappe.cache.delete(_raw_key(ATTEMPTS_CACHE_PREFIX + email))
	cache_delete(OTP_CACHE_PREFIX, email)
	return bool(deleted)


def count_hit(bucket: str, identity: str, window_sec: int) -> int:
	"""Atomically count one event for `identity` in a fixed window; return the count.

	Identities (e.g. email addresses) are stored as digests, never in clear.
	"""
	key = _raw_key(f"{RATE_CACHE_PREFIX}{bucket}:{digest(identity)}")
	count = frappe.cache.incrby(key, 1)
	if count == 1:
		frappe.cache.expire(key, window_sec)
	return count


def hit_count(bucket: str, identity: str) -> int:
	return cint(frappe.cache.get(_raw_key(f"{RATE_CACHE_PREFIX}{bucket}:{digest(identity)}")))


def store_magic_key(key: str, email: str, expires_in_sec: int, redirect_to: str | None = None) -> None:
	# Key is unguessable; value is the bound email and post-login target, kept
	# server-side so the emailed URL cannot be edited to point elsewhere.
	cache_set(
		MAGIC_CACHE_PREFIX,
		key,
		{"email": email, "redirect_to": redirect_to, "created": str(now_datetime())},
		expires_in_sec,
	)


def consume_magic_link(key: str) -> dict[str, Any] | None:
	"""Return and delete the stored payload ({"email", "redirect_to", ...})."""
	payload = cache_get(MAGIC_CACHE_PREFIX, key)
	cache_delete(MAGIC_CACHE_PREFIX, key)
	return payload or None


def consume_magic_key(key: str) -> str | None:
	payload = consume_magic_link(key)
	return payload.get("email") if payload else None


def store_challenge(challenge_id: str, payload: dict[str, Any], expires_in_sec: int = 300) -> None:
	cache_set(CHALLENGE_CACHE_PREFIX, challenge_id, payload, expires_in_sec)


def consume_challenge(challenge_id: str) -> dict[str, Any] | None:
	payload = cache_get(CHALLENGE_CACHE_PREFIX, challenge_id)
	cache_delete(CHALLENGE_CACHE_PREFIX, challenge_id)
	return payload
