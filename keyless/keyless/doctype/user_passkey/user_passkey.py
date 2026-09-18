from __future__ import annotations

import frappe
from frappe.model.document import Document


class UserPasskey(Document):
	# begin: auto-generated types
	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		aaguid: DF.Data | None
		backed_up: DF.Check
		credential_id: DF.Data
		device_type: DF.Literal["platform", "cross-platform"]
		friendly_name: DF.Data | None
		last_used: DF.Datetime | None
		public_key: DF.LongText
		sign_count: DF.Int
		transports: DF.SmallText | None
		user: DF.Link
		user_handle: DF.Data | None
	# end: auto-generated types

	def before_insert(self):
		if not self.user:
			self.user = frappe.session.user
		if self.user != frappe.session.user and "System Manager" not in frappe.get_roles():
			frappe.throw(frappe.PermissionError)

	def on_trash(self):
		if self.user != frappe.session.user and "System Manager" not in frappe.get_roles():
			frappe.throw(frappe.PermissionError)
