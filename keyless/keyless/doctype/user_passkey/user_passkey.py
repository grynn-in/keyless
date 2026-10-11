from __future__ import annotations

import frappe
from frappe import _
from frappe.model.document import Document

from keyless import notify
from keyless.audit import log_event

# Binding between a credential and its owner. Changing any of these after
# insert would let a row be re-pointed at another account (audit C-1).
LOCKED_FIELDS = ("user", "credential_id", "public_key", "user_handle")

# keyless.api.passkey.verify_registration sets this document flag to the user
# whose WebAuthn registration it has just verified. Only server code can set
# it: Frappe ignores a "flags" key in a request body or an import file.
REGISTERED_FLAG = "keyless_registered_user"


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
		# A passkey row is a credential that signs its user in. It may only come
		# from a verified registration by that user, not from Desk, REST or Data
		# Import, where a System Manager could add a key they hold to any
		# account, Administrator included, and sign in as its owner (audit
		# 2026-10-10, F-2).
		if not self.user or self.flags.get(REGISTERED_FLAG) != self.user:
			frappe.throw(_("Passkeys can only be added by registering them."), frappe.PermissionError)
		if self.user == "Administrator" and frappe.session.user != "Administrator":
			frappe.throw(_("Not permitted"), frappe.PermissionError)
		expected = frappe.db.get_value("User", self.user, "keyless_user_handle")
		if not expected or self.user_handle != expected:
			frappe.throw(_("The passkey's user handle does not match its user."), frappe.ValidationError)

	def after_insert(self):
		# Here rather than in the API, so that every passkey added is logged
		# and notified, whichever code path adds it.
		log_event("passkey_registered", user=self.user, method="passkey", success=True, detail=self._by(self.name))
		notify.sign_in_methods_changed(
			self.user, _('A passkey named "{0}" was added to your account.').format(self.friendly_name)
		)

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

	def after_delete(self):
		# Also covers a System Manager deleting from Desk or REST, which used to
		# remove a passkey without a word to its owner. Deleting a user removes
		# their passkeys without hooks, so no mail goes to a deleted account.
		log_event("passkey_revoked", user=self.user, method="passkey", success=True, detail=self._by(self.name))
		notify.sign_in_methods_changed(
			self.user,
			_('The passkey named "{0}" was removed from your account.').format(self.friendly_name or self.name),
		)

	def _by(self, detail: str) -> str:
		"""`detail`, plus who did it when that is not the passkey's owner."""
		actor = frappe.session.user
		return detail if actor == self.user else f"{detail} by {actor}"
