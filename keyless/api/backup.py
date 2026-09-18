from __future__ import annotations

import secrets

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit

from keyless.api.common import get_rate_limit, normalize_email, require_enabled
from keyless.audit import log_event
from keyless.auth import issue_session
from keyless.tokens import compare, digest
from keyless.user import resolve_enabled_user

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _generate_code() -> str:
	return "".join(ALPHABET[secrets.randbelow(len(ALPHABET))] for _ in range(10))


@frappe.whitelist()
def generate_codes():
	"""Rotate backup codes for the current user. Returns plaintext once."""
	settings = require_enabled()
	if not settings.enable_backup_codes:
		frappe.throw(_("Backup codes are disabled"))
	if frappe.session.user == "Guest":
		frappe.throw(frappe.PermissionError)

	user = frappe.session.user
	frappe.db.delete("Keyless Backup Code", {"user": user})
	plain = []
	for _ in range(10):
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
	return {"ok": True, "codes": plain}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=get_rate_limit, seconds=60 * 60)
def redeem(email: str, code: str):
	settings = require_enabled()
	if not settings.enable_backup_codes:
		frappe.throw(_("Backup codes are disabled"))

	email = normalize_email(email)
	user = resolve_enabled_user(email)
	if not user:
		frappe.throw(_("Invalid recovery code"), frappe.AuthenticationError)

	rows = frappe.get_all(
		"Keyless Backup Code",
		filters={"user": user, "used": 0},
		fields=["name", "code_hash"],
	)
	match = None
	normalized = (code or "").strip().upper()
	for row in rows:
		if compare(normalized, row.code_hash):
			match = row
			break
	if not match:
		log_event("backup_failed", user=email, method="backup", success=False)
		frappe.throw(_("Invalid recovery code"), frappe.AuthenticationError)

	frappe.db.set_value(
		"Keyless Backup Code",
		match.name,
		{"used": 1, "used_on": frappe.utils.now_datetime()},
	)
	issue_session(user, method="backup_code")
	return {"ok": True, "user": user, "home": "/app"}
