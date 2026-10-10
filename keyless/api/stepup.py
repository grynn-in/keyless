"""Step-up: confirm it's you before adding a passkey or regenerating backup codes
(audit M-3, D7). A fresh sign-in also counts; see keyless.stepup."""

from __future__ import annotations

import frappe
from frappe import _

from keyless import stepup
from keyless.api import passkey as passkey_api
from keyless.api.common import HOUR, limit_mail_requests, require_enabled, take_attempt
from keyless.api.otp import _send_otp_mail
from keyless.audit import log_event
from keyless.password_policy import email_factor_refusal
from keyless.tokens import random_otp, store_otp, verify_and_consume_otp

# Step-up email codes live apart from sign-in codes so neither can stand in for the other.
OTP_KEY_PREFIX = "stepup:"


def _user() -> str:
	if frappe.session.user == "Guest":
		frappe.throw(_("Sign in first"), frappe.PermissionError)
	return frappe.session.user


def _methods(settings, user: str) -> list[str]:
	methods = []
	if settings.enable_passkeys and frappe.db.exists("User Passkey", {"user": user}):
		methods.append("passkey")
	if settings.enable_email_otp and not email_factor_refusal(user):
		methods.append("email")
	return methods


@frappe.whitelist()
def status():
	"""Whether the session re-authenticated recently, and how it can if not."""
	settings = require_enabled()
	user = _user()
	return {
		"recent": stepup.is_recent(),
		"methods": _methods(settings, user),
		"window_minutes": stepup.window_seconds() // 60,
	}


@frappe.whitelist(methods=["POST"])
def passkey_options():
	from webauthn import generate_authentication_options
	from webauthn.helpers import base64url_to_bytes
	from webauthn.helpers.structs import PublicKeyCredentialDescriptor

	settings = require_enabled()
	user = _user()
	if "passkey" not in _methods(settings, user):
		frappe.throw(_("You have no passkey to confirm with"), frappe.PermissionError)
	credentials = frappe.get_all("User Passkey", filters={"user": user}, pluck="credential_id")
	options = generate_authentication_options(
		rp_id=passkey_api.rp_id(),
		user_verification=passkey_api._uv_requirement(settings),
		allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c)) for c in credentials],
	)
	_challenge_id, payload = passkey_api._store_options_challenge(options, kind="stepup", user=user)
	return payload


@frappe.whitelist(methods=["POST"])
def verify_passkey(credential: str | dict, challenge_id: str):
	settings = require_enabled()
	user = _user()
	challenge = passkey_api.consume_challenge(challenge_id)
	if not challenge or challenge.get("type") != "stepup" or challenge.get("user") != user:
		frappe.throw(_("Confirmation expired. Try again."), frappe.AuthenticationError)
	# The challenge names the session user, so a passkey of another account fails here.
	passkey_api.verify_assertion(credential, challenge, settings)
	stepup.mark()
	log_event("step_up", user=user, method="passkey", success=True)
	return {"ok": True}


@frappe.whitelist(methods=["POST"])
def request_email_code():
	settings = require_enabled()
	user = _user()
	if "email" not in _methods(settings, user):
		frappe.throw(_("Confirm with a passkey instead"), frappe.PermissionError)
	# The same hourly and daily limits as sign-in codes.
	limit_mail_requests(user, settings, "stepup")
	expires = int(settings.otp_expiry_seconds or 300)
	code = random_otp(int(settings.otp_length or 6))
	store_otp(OTP_KEY_PREFIX + user, code, expires)
	_send_otp_mail(frappe.db.get_value("User", user, "email"), code, expires)
	return {"ok": True, "expires_in": expires}


@frappe.whitelist(methods=["POST"])
def verify_email_code(otp: str):
	settings = require_enabled()
	user = _user()
	max_attempts = int(settings.max_otp_attempts or 5)
	# Only the signed-in user can use this up, so per account, not per IP.
	give_back = take_attempt("stepup-guess-hour", user, max_attempts * 2, HOUR, per_ip=False)
	if not verify_and_consume_otp(OTP_KEY_PREFIX + user, otp or "", max_attempts):
		log_event("step_up_failed", user=user, method="email_otp", success=False)
		frappe.throw(_("Invalid or expired code"), frappe.AuthenticationError)
	give_back()
	stepup.mark()
	log_event("step_up", user=user, method="email_otp", success=True)
	return {"ok": True}
