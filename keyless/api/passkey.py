"""WebAuthn / passkey ceremonies.

Registration is authenticated (logged-in user). Authentication is guest-allowed
and uses discoverable credentials so the user does not have to type an email
first. Credential public keys live on User Passkey; challenges live in Redis.
"""

from __future__ import annotations

import hmac
import json

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit

from keyless import notify, stepup
from keyless.api.common import allowed_origins, get_passkey_ip_rate_limit, require_enabled, rp_id, rp_name
from keyless.audit import log_event
from keyless.auth import issue_session
from keyless.tokens import consume_challenge, random_token, store_challenge
from keyless.user import ensure_user_handle


def _uv_requirement(settings):
	from webauthn.helpers.structs import UserVerificationRequirement

	value = (settings.passkey_user_verification or "required").lower()
	mapping = {
		"required": UserVerificationRequirement.REQUIRED,
		"preferred": UserVerificationRequirement.PREFERRED,
		"discouraged": UserVerificationRequirement.DISCOURAGED,
	}
	return mapping.get(value, UserVerificationRequirement.REQUIRED)


def _handle_bytes(handle: str) -> bytes:
	"""The WebAuthn user.id we registered for a stored keyless_user_handle."""
	return bytes.fromhex(handle) if len(handle) == 32 else handle.encode("utf-8")


def _user_handle_matches(cred: dict, passkey) -> bool:
	"""The assertion's userHandle must be the registered handle of passkey.user.

	Passkeys are created as resident keys, so authenticators always return
	userHandle; a missing one is treated as a mismatch.
	"""
	from webauthn.helpers import base64url_to_bytes

	expected = frappe.db.get_value("User", passkey.user, "keyless_user_handle")
	if not expected or (passkey.user_handle and passkey.user_handle != expected):
		return False
	asserted = ((cred.get("response") or {}).get("userHandle") or "").strip()
	if not asserted:
		return False
	try:
		asserted_bytes = base64url_to_bytes(asserted)
	except Exception:
		return False
	return hmac.compare_digest(asserted_bytes, _handle_bytes(expected))


def _challenge_bytes(stored) -> bytes:
	"""py_webauthn compares against decoded clientDataJSON.challenge (bytes).

	We persist the same base64url string we sent the browser, then decode here.
	Passing the string through as expected_challenge always fails.
	"""
	from webauthn.helpers import base64url_to_bytes

	if isinstance(stored, (bytes, bytearray, memoryview)):
		return bytes(stored)
	if not stored:
		frappe.throw(_("Registration challenge expired"), frappe.AuthenticationError)
	return base64url_to_bytes(str(stored))


def _store_options_challenge(options, *, kind: str, user: str | None) -> tuple[str, dict]:
	from webauthn import options_to_json
	from webauthn.helpers import bytes_to_base64url

	payload = json.loads(options_to_json(options))
	# Persist the exact challenge string the client will round-trip, not a
	# second encoding of options.challenge that might differ in padding.
	challenge_b64 = payload.get("challenge") or bytes_to_base64url(options.challenge)
	challenge_id = random_token(16)
	store_challenge(
		challenge_id,
		{"type": kind, "user": user, "challenge": challenge_b64},
		expires_in_sec=300,
	)
	payload["challenge_id"] = challenge_id
	return challenge_id, payload


@frappe.whitelist()
def registration_options():
	"""Start passkey registration for the current user."""
	from webauthn import generate_registration_options
	from webauthn.helpers import base64url_to_bytes
	from webauthn.helpers.structs import (
		AttestationConveyancePreference,
		AuthenticatorSelectionCriteria,
		PublicKeyCredentialDescriptor,
		ResidentKeyRequirement,
	)

	settings = require_enabled()
	if not settings.enable_passkeys:
		frappe.throw(_("Passkeys are disabled"))
	if frappe.session.user == "Guest":
		frappe.throw(_("Sign in before registering a passkey"), frappe.PermissionError)
	stepup.require()

	user = frappe.session.user
	handle = ensure_user_handle(user)
	existing = frappe.get_all("User Passkey", filters={"user": user}, fields=["credential_id"])

	exclude = []
	for row in existing:
		try:
			exclude.append(PublicKeyCredentialDescriptor(id=base64url_to_bytes(row.credential_id)))
		except Exception:
			continue

	full_name = frappe.db.get_value("User", user, "full_name") or user
	options = generate_registration_options(
		rp_id=rp_id(),
		rp_name=rp_name(),
		user_name=user,
		user_id=_handle_bytes(handle),
		user_display_name=full_name,
		attestation=AttestationConveyancePreference.NONE,
		authenticator_selection=AuthenticatorSelectionCriteria(
			resident_key=ResidentKeyRequirement.REQUIRED,
			user_verification=_uv_requirement(settings),
		),
		exclude_credentials=exclude or None,
	)
	_challenge_id, payload = _store_options_challenge(options, kind="registration", user=user)
	return payload


@frappe.whitelist()
def verify_registration(credential: str | dict, challenge_id: str, friendly_name: str | None = None):
	from webauthn import verify_registration_response
	from webauthn.helpers import bytes_to_base64url
	from webauthn.helpers.exceptions import InvalidRegistrationResponse, WebAuthnException

	settings = require_enabled()
	if frappe.session.user == "Guest":
		frappe.throw(_("Sign in before registering a passkey"), frappe.PermissionError)
	stepup.require()

	challenge = consume_challenge(challenge_id)
	if not challenge or challenge.get("type") != "registration" or challenge.get("user") != frappe.session.user:
		frappe.throw(_("Registration challenge expired"), frappe.AuthenticationError)

	cred = json.loads(credential) if isinstance(credential, str) else credential
	try:
		verification = verify_registration_response(
			credential=cred,
			expected_challenge=_challenge_bytes(challenge["challenge"]),
			expected_origin=allowed_origins(),
			expected_rp_id=rp_id(),
			require_user_verification=settings.passkey_user_verification == "required",
		)
	except (InvalidRegistrationResponse, WebAuthnException) as e:
		log_event(
			"passkey_register_failed",
			user=frappe.session.user,
			method="passkey",
			success=False,
			detail=str(e)[:140],
		)
		# The library's text stays in the audit log only (audit L-3).
		frappe.throw(_("Could not verify this passkey."), frappe.AuthenticationError)

	credential_id = bytes_to_base64url(verification.credential_id)
	if frappe.db.exists("User Passkey", {"credential_id": credential_id}):
		frappe.throw(_("This passkey is already registered"))

	doc = frappe.get_doc(
		{
			"doctype": "User Passkey",
			"user": frappe.session.user,
			"credential_id": credential_id,
			"public_key": bytes_to_base64url(verification.credential_public_key),
			"sign_count": verification.sign_count,
			"aaguid": str(verification.aaguid) if verification.aaguid else None,
			# device_type is the WebAuthn authenticator attachment, reported by the
			# browser on the credential. py_webauthn's credential_device_type
			# (single_device / multi_device) is a different property; whether the
			# credential syncs is already captured by backed_up.
			"device_type": _authenticator_attachment(cred),
			"backed_up": 1 if verification.credential_backed_up else 0,
			"friendly_name": (friendly_name or "").strip() or _default_name(cred),
			"user_handle": frappe.db.get_value("User", frappe.session.user, "keyless_user_handle"),
		}
	)
	doc.insert(ignore_permissions=True)
	log_event("passkey_registered", user=frappe.session.user, method="passkey", success=True)
	notify.sign_in_methods_changed(
		frappe.session.user, _('A passkey named "{0}" was added to your account.').format(doc.friendly_name)
	)
	return {"ok": True, "name": doc.name, "friendly_name": doc.friendly_name}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=get_passkey_ip_rate_limit, seconds=60 * 60)
def authentication_options():
	"""Start a passkey sign-in. Discoverable credentials only: the response never
	depends on who is signing in, so it cannot reveal which accounts have passkeys
	(audit M-2, D6)."""
	from webauthn import generate_authentication_options

	settings = require_enabled()
	if not settings.enable_passkeys:
		frappe.throw(_("Passkeys are disabled"))

	options = generate_authentication_options(rp_id=rp_id(), user_verification=_uv_requirement(settings))
	_challenge_id, payload = _store_options_challenge(options, kind="authentication", user=None)
	return payload


def verify_assertion(credential: str | dict, challenge: dict, settings):
	"""Verify a passkey assertion against a consumed challenge and return the
	User Passkey row (name, user). Used by sign-in and by step-up (audit M-3).
	If the challenge names a user, the passkey must belong to that user."""
	from webauthn import verify_authentication_response
	from webauthn.helpers import base64url_to_bytes
	from webauthn.helpers.exceptions import InvalidAuthenticationResponse, WebAuthnException

	cred = json.loads(credential) if isinstance(credential, str) else credential
	raw_id = cred.get("id") or cred.get("rawId")
	if not raw_id:
		frappe.throw(_("Invalid passkey response"))

	passkey = frappe.db.get_value(
		"User Passkey",
		{"credential_id": raw_id},
		["name", "user", "public_key", "sign_count", "user_handle"],
		as_dict=True,
	)
	if not passkey:
		log_event("passkey_failed", method="passkey", success=False, detail="unknown_credential")
		frappe.throw(_("Unknown passkey"), frappe.AuthenticationError)

	if challenge.get("user") and challenge["user"] != passkey.user:
		frappe.throw(_("Passkey does not match this account"), frappe.AuthenticationError)

	if not _user_handle_matches(cred, passkey):
		log_event("passkey_failed", method="passkey", success=False, detail="user_handle_mismatch")
		frappe.throw(_("Passkey does not match this account"), frappe.AuthenticationError)

	try:
		verification = verify_authentication_response(
			credential=cred,
			expected_challenge=_challenge_bytes(challenge["challenge"]),
			expected_origin=allowed_origins(),
			expected_rp_id=rp_id(),
			credential_public_key=base64url_to_bytes(passkey.public_key),
			credential_current_sign_count=int(passkey.sign_count or 0),
			require_user_verification=settings.passkey_user_verification == "required",
		)
	except (InvalidAuthenticationResponse, WebAuthnException) as e:
		log_event("passkey_failed", method="passkey", success=False, detail=str(e)[:140])
		# The library's text stays in the audit log only (audit L-3).
		frappe.throw(_("Could not verify this passkey."), frappe.AuthenticationError)

	# Refuse disabled users before recording anything about the assertion (audit I-1).
	if not frappe.db.get_value("User", passkey.user, "enabled"):
		log_event("passkey_failed", user=passkey.user, method="passkey", success=False, detail="user_disabled")
		frappe.throw(_("User is disabled"), frappe.AuthenticationError)

	frappe.db.set_value(
		"User Passkey",
		passkey.name,
		{
			"sign_count": verification.new_sign_count,
			"last_used": frappe.utils.now_datetime(),
		},
		update_modified=False,
	)
	return passkey


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=get_passkey_ip_rate_limit, seconds=60 * 60)
def verify_authentication(credential: str | dict, challenge_id: str):
	settings = require_enabled()
	if not settings.enable_passkeys:
		frappe.throw(_("Passkeys are disabled"))

	challenge = consume_challenge(challenge_id)
	if not challenge or challenge.get("type") != "authentication":
		log_event("passkey_failed", method="passkey", success=False, detail="no_challenge")
		frappe.throw(_("Sign-in challenge expired"), frappe.AuthenticationError)

	passkey = verify_assertion(credential, challenge, settings)
	issue_session(passkey.user, method="passkey")
	home = "/app" if frappe.db.get_value("User", passkey.user, "user_type") == "System User" else "/"
	return {"ok": True, "user": passkey.user, "home": home}


@frappe.whitelist()
def list_passkeys():
	if frappe.session.user == "Guest":
		frappe.throw(_("Not permitted"), frappe.PermissionError)
	return frappe.get_all(
		"User Passkey",
		filters={"user": frappe.session.user},
		fields=["name", "friendly_name", "device_type", "backed_up", "last_used", "creation"],
		order_by="creation desc",
	)


@frappe.whitelist()
def revoke_passkey(name: str):
	doc = frappe.get_doc("User Passkey", name)
	if doc.user != frappe.session.user and "System Manager" not in frappe.get_roles():
		frappe.throw(_("Not permitted"), frappe.PermissionError)
	user = doc.user
	# Ownership is checked above; the doctype grants no role to end users (C-1).
	doc.delete(ignore_permissions=True)
	log_event("passkey_revoked", user=user, method="passkey", success=True, detail=name)
	notify.sign_in_methods_changed(
		user, _('The passkey named "{0}" was removed from your account.').format(doc.friendly_name or name)
	)
	return {"ok": True}


AUTHENTICATOR_ATTACHMENTS = ("platform", "cross-platform")


def _authenticator_attachment(cred) -> str | None:
	"""Return the credential's authenticatorAttachment, or None when absent.

	Browsers may omit it (older engines) or send an unexpected value. We store
	nothing rather than guess, so an empty Device Type means "not reported".
	"""
	if not isinstance(cred, dict):
		return None
	value = cred.get("authenticatorAttachment")
	return value if value in AUTHENTICATOR_ATTACHMENTS else None


def _default_name(cred) -> str:
	kind = _authenticator_attachment(cred) or "passkey"
	return f"{kind} · {frappe.utils.pretty_date(frappe.utils.now_datetime())}"
