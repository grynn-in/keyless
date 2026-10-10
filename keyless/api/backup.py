from __future__ import annotations

import secrets

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit

from keyless import notify, stepup
from keyless.api.common import HOUR, get_ip_rate_limit, normalize_email, require_enabled, take_attempt
from keyless.audit import log_event
from keyless.auth import issue_session
from keyless.tokens import compare, digest
from keyless.user import resolve_enabled_user

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODES_PER_USER = 10
# Recovery-code guesses per account and client IP per hour; ten times this from all
# IPs together. Codes have 50 bits of entropy, so the backstop costs no security.
BACKUP_FAILURES_PER_HOUR = 10
# Compared against when there is no real code, so every redemption does the same work.
_DUMMY_HASH = "0" * 64


def _generate_code() -> str:
	return "".join(ALPHABET[secrets.randbelow(len(ALPHABET))] for _ in range(10))


@frappe.whitelist()
def generate_codes():
	"""Rotate backup codes for the current user. Returns plaintext once."""
	settings = require_enabled()
	if not settings.enable_backup_codes:
		frappe.throw(_("Backup codes are disabled"))
	if frappe.session.user == "Guest":
		frappe.throw(_("Not permitted"), frappe.PermissionError)
	stepup.require()

	user = frappe.session.user
	frappe.db.delete("Keyless Backup Code", {"user": user})
	plain = []
	for _i in range(CODES_PER_USER):
		code = _generate_code()
		plain.append(code)
		frappe.get_doc(
			{
				"doctype": "Keyless Backup Code",
				"user": user,
				"code_hash": digest(code),
			}
		).insert(ignore_permissions=True)
	log_event("backup_codes_generated", user=user, method="backup", success=True)
	notify.sign_in_methods_changed(
		user, _("New backup codes were generated for your account. The old codes no longer work.")
	)
	return {"ok": True, "codes": plain}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=get_ip_rate_limit, seconds=HOUR)
def redeem(email: str, code: str):
	settings = require_enabled()
	if not settings.enable_backup_codes:
		frappe.throw(_("Backup codes are disabled"))

	email = normalize_email(email)
	give_back = take_attempt("backup-guess-hour", email, BACKUP_FAILURES_PER_HOUR, HOUR)
	user = resolve_enabled_user(email)
	# Same work whether the account exists, has codes left, or not: one query and
	# exactly CODES_PER_USER hash checks, with no early exit (audit M-2).
	rows = frappe.get_all(
		"Keyless Backup Code",
		filters={"user": user or "", "used": 0},
		fields=["name", "code_hash"],
		limit=CODES_PER_USER,
	)
	hashes = [row.code_hash for row in rows] + [_DUMMY_HASH] * (CODES_PER_USER - len(rows))
	normalized = (code or "").strip().upper()
	match = None
	for i, expected in enumerate(hashes):
		if compare(normalized, expected) and i < len(rows) and match is None:
			match = rows[i]
	if not match:
		log_event("backup_failed", user=user or "Guest", method="backup", success=False)
		frappe.throw(_("Invalid recovery code"), frappe.AuthenticationError)

	# Lock the row and re-check it is unused, so parallel requests with the same
	# code wait for each other and only the first one signs in (audit L-1).
	if not frappe.db.get_value("Keyless Backup Code", {"name": match.name, "used": 0}, "name", for_update=True):
		log_event("backup_failed", user=user, method="backup", success=False, detail="already_used")
		frappe.throw(_("Invalid recovery code"), frappe.AuthenticationError)
	give_back()
	frappe.db.set_value(
		"Keyless Backup Code",
		match.name,
		{"used": 1, "used_on": frappe.utils.now_datetime()},
	)
	issue_session(user, method="backup_code")
	return {"ok": True, "user": user, "home": "/app"}
