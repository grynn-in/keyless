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
from frappe import _
from frappe.utils import cint, now_datetime
from frappe.utils.password import get_encryption_key


OTP_CACHE_PREFIX = "keyless:otp:"
MAGIC_CACHE_PREFIX = "keyless:magic:"
CHALLENGE_CACHE_PREFIX = "keyless:challenge:"
LOCK_CACHE_PREFIX = "keyless:lock:"
ATTEMPTS_CACHE_PREFIX = "keyless:otp-attempts:"
RATE_CACHE_PREFIX = "keyless:rl:"


def _pepper() -> str:
	"""The site's encryption_key, never secret_key or an empty pepper (audit I-1).
	A new site has none until something first encrypts a value; Frappe's own helper then
	creates and saves one, as it does for encrypted passwords.
	Rotating encryption_key invalidates every stored backup code."""
	key = get_encryption_key()
	if not key:
		frappe.throw(
			_("Keyless needs encryption_key in site_config.json before it can issue or check codes."),
			title=_("Keyless is not configured"),
		)
	return str(key)


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


def _rate_key(bucket: str, identity: str) -> bytes:
	return _raw_key(f"{RATE_CACHE_PREFIX}{bucket}:{digest(identity)}")


# Count and set the expiry in one atomic step. A counter found without an expiry
# (left by an older version that set it separately) gets one too.
_COUNT = (
	"local n = redis.call('incr', KEYS[1]) "
	"if redis.call('ttl', KEYS[1]) < 0 then redis.call('expire', KEYS[1], ARGV[1]) end "
	"return n"
)


def count_hit(bucket: str, identity: str, window_sec: int) -> int:
	"""Atomically count one event for `identity` in a fixed window; return the count.

	The expiry is set in the same step as the count, so a counter can never be left
	without one (which would lock the identity out for good).
	Identities (e.g. email addresses) are stored as digests, never in clear.
	"""
	return cint(frappe.cache.eval(_COUNT, 1, _rate_key(bucket, identity), int(window_sec)))


# Decrement only while the counter exists, so a give-back after the window ended
# cannot create a negative counter with no expiry.
_UNCOUNT = "if redis.call('exists', KEYS[1]) == 1 then return redis.call('decr', KEYS[1]) end return 0"


def uncount_hit(bucket: str, identity: str) -> None:
	"""Give back one event counted by count_hit (for an attempt that succeeded)."""
	frappe.cache.eval(_UNCOUNT, 1, _rate_key(bucket, identity))


def hit_count(bucket: str, identity: str) -> int:
	return cint(frappe.cache.get(_rate_key(bucket, identity)))


def store_magic_key(
	key: str, email: str, expires_in_sec: int, redirect_to: str | None = None, browser: str | None = None
) -> None:
	# Key is unguessable; value is the bound email and post-login target, kept
	# server-side so the emailed URL cannot be edited to point elsewhere, and the
	# digest of the requesting browser's ID (see keyless.api.magic_link).
	cache_set(
		MAGIC_CACHE_PREFIX,
		key,
		{"email": email, "redirect_to": redirect_to, "browser": browser, "created": str(now_datetime())},
		expires_in_sec,
	)


def peek_magic_link(key: str) -> dict[str, Any] | None:
	"""The stored payload of a still-valid magic-link key, without using it up."""
	return cache_get(MAGIC_CACHE_PREFIX, key) if key else None


def consume_magic_link(key: str) -> dict[str, Any] | None:
	"""Return and delete the stored payload ({"email", "redirect_to", ...})."""
	return _take(MAGIC_CACHE_PREFIX, key)


def _take(prefix: str, key: str) -> dict[str, Any] | None:
	"""Read and delete a one-shot value. Only the caller whose DELETE removed it gets
	it, so parallel requests cannot both use the same link or challenge."""
	payload = cache_get(prefix, key)
	deleted = frappe.cache.delete(_raw_key(f"{prefix}{key}"))
	cache_delete(prefix, key)
	return payload if payload and deleted else None


def consume_magic_key(key: str) -> str | None:
	payload = consume_magic_link(key)
	return payload.get("email") if payload else None


def store_challenge(challenge_id: str, payload: dict[str, Any], expires_in_sec: int = 300) -> None:
	cache_set(CHALLENGE_CACHE_PREFIX, challenge_id, payload, expires_in_sec)


def consume_challenge(challenge_id: str) -> dict[str, Any] | None:
	return _take(CHALLENGE_CACHE_PREFIX, challenge_id)
