"""Install, migrate, uninstall. Create the settings single and User custom fields."""

from __future__ import annotations

import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields


CUSTOM_FIELDS = {
	"User": [
		{
			"fieldname": "keyless_section",
			"label": "Keyless",
			"fieldtype": "Section Break",
			"insert_after": "new_password",
			"collapsible": 1,
		},
		{
			"fieldname": "keyless_user_handle",
			"label": "WebAuthn User Handle",
			"fieldtype": "Data",
			"read_only": 1,
			"unique": 1,
			"no_copy": 1,
			"insert_after": "keyless_section",
			"description": "Stable WebAuthn user.id. Generated on first passkey registration.",
		},
		{
			"fieldname": "keyless_passwordless_only",
			"label": "Passwordless Only",
			"fieldtype": "Check",
			"insert_after": "keyless_user_handle",
			"description": "Block password login for this user even if site-wide passwords remain enabled.",
		},
	]
}


def after_install():
	create_custom_fields(CUSTOM_FIELDS, ignore_validate=True)
	_ensure_settings()
	frappe.clear_cache()


def after_migrate():
	create_custom_fields(CUSTOM_FIELDS, ignore_validate=True)
	_ensure_settings()


def before_uninstall():
	for fieldname in ("keyless_passwordless_only", "keyless_user_handle", "keyless_section"):
		name = frappe.db.get_value("Custom Field", {"dt": "User", "fieldname": fieldname})
		if name:
			frappe.delete_doc("Custom Field", name, force=True, ignore_permissions=True)


def _ensure_settings():
	if frappe.db.exists("Keyless Settings", "Keyless Settings"):
		return
	doc = frappe.new_doc("Keyless Settings")
	doc.enabled = 1
	doc.enable_passkeys = 1
	doc.enable_magic_link = 1
	doc.enable_email_otp = 1
	doc.enable_backup_codes = 1
	doc.hide_user_enumeration = 1
	doc.allow_administrator_password = 1
	doc.otp_length = 6
	doc.otp_expiry_seconds = 300
	doc.magic_link_expiry_minutes = 10
	doc.max_otp_attempts = 5
	doc.rate_limit_per_hour = 5
	doc.passkey_user_verification = "required"
	doc.audit_retention_days = 90
	doc.flags.ignore_permissions = True
	doc.insert()
