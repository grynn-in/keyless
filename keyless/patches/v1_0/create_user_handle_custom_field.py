import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

from keyless.install import CUSTOM_FIELDS


def execute():
	create_custom_fields(CUSTOM_FIELDS, ignore_validate=True)
	frappe.clear_cache()
