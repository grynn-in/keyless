import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

from keyless.install import CUSTOM_FIELDS
from keyless.security import report_self_cleared_passwordless_only


def execute():
	# Audit 2026-10-10, F-3: the Keyless fields on User become permlevel 1
	# (System Manager only), so users can no longer clear Passwordless Only on
	# their own record. after_migrate applies CUSTOM_FIELDS as well; doing it
	# here makes the upgrade explicit. Then report, without changing anything,
	# users who cleared the flag themselves before the fix.
	create_custom_fields(CUSTOM_FIELDS, ignore_validate=True)
	frappe.clear_cache(doctype="User")
	report_self_cleared_passwordless_only()
