"""Install, migrate, uninstall. Create the User custom fields.

Keyless Settings defaults come from keyless_settings.json. A fresh install
leaves Keyless and every factor off until an administrator opts in (audit H-3).
"""

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
	frappe.clear_cache()


def after_migrate():
	create_custom_fields(CUSTOM_FIELDS, ignore_validate=True)


def before_uninstall():
	for fieldname in ("keyless_passwordless_only", "keyless_user_handle", "keyless_section"):
		name = frappe.db.get_value("Custom Field", {"dt": "User", "fieldname": fieldname})
		if name:
			frappe.delete_doc("Custom Field", name, force=True, ignore_permissions=True)

