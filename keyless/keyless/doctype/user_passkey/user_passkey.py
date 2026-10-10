from __future__ import annotations

import frappe
from frappe import _
from frappe.model.document import Document

# Binding between a credential and its owner. Changing any of these after
# insert would let a row be re-pointed at another account (audit C-1).
LOCKED_FIELDS = ("user", "credential_id", "public_key", "user_handle")


class UserPasskey(Document):
	# begin: auto-generated types
	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		aaguid: DF.Data | None
		backed_up: DF.Check
		credential_id: DF.Data
		device_type: DF.Literal["", "platform", "cross-platform"]
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
			frappe.throw(_("Not permitted"), frappe.PermissionError)

	def validate(self):
		if self.is_new():
			return
		stored = frappe.db.get_value("User Passkey", self.name, LOCKED_FIELDS, as_dict=True)
		if not stored:
			return
		changed = [f for f in LOCKED_FIELDS if (self.get(f) or None) != (stored.get(f) or None)]
		if changed:
			frappe.throw(
				_("Cannot change {0} of a registered passkey").format(", ".join(changed)),
				frappe.ValidationError,
			)

	def on_trash(self):
		if self.user != frappe.session.user and "System Manager" not in frappe.get_roles():
			frappe.throw(_("Not permitted"), frappe.PermissionError)
