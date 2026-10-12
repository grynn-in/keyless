# Keyless Backup Code
from __future__ import annotations

import frappe
from frappe import _
from frappe.model.document import Document

from keyless import notify
from keyless.audit import log_event

# keyless.api.backup.generate_codes sets this document flag to the user it is
# generating codes for. Only server code can set it: Frappe ignores a "flags"
# key in a request body or an import file.
GENERATED_FLAG = "keyless_generated_for"

# Hash scheme of rows this version writes. 1: HMAC of the code alone (Keyless
# 2.0.0 and earlier). 2: HMAC of the code and the user's WebAuthn handle, so
# a row moved to another user no longer matches (audit 2026-10-12, G-1).
HASH_VERSION = 2

# Binding between a code and its owner. Changing any of these after insert
# would let a code sign in someone else, or be used again.
LOCKED_FIELDS = ("user", "code_hash", "hash_version", "owner")


class KeylessBackupCode(Document):
	# begin: auto-generated types
	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		code_hash: DF.Data
		hash_version: DF.Int
		used: DF.Check
		used_on: DF.Datetime | None
		user: DF.Link
	# end: auto-generated types

	def before_insert(self):
		# A backup code signs its user in and bypasses passkey and 2FA rules.
		# It may only come from that user's own generate_codes, not from Desk,
		# REST, Data Import or a script, where a System Manager could add a
		# code they know to any account, Administrator included (audit
		# 2026-10-12, G-1; the same rule as User Passkey, F-2).
		if not self.user or self.flags.get(GENERATED_FLAG) != self.user:
			frappe.throw(_("Backup codes can only be added by generating them."), frappe.PermissionError)
		if self.user == "Administrator" and frappe.session.user != "Administrator":
			frappe.throw(_("Not permitted"), frappe.PermissionError)
		self.hash_version = HASH_VERSION
		self.used = 0
		self.used_on = None

	def validate(self):
		if self.is_new():
			return
		stored = frappe.db.get_value(
			"Keyless Backup Code", self.name, (*LOCKED_FIELDS, "used", "used_on"), as_dict=True
		)
		if not stored:
			return
		changed = [f for f in LOCKED_FIELDS if (self.get(f) or None) != (stored.get(f) or None)]
		if stored.used and (not self.used or str(self.used_on or "") != str(stored.used_on or "")):
			changed.append("used")
		if changed:
			frappe.throw(
				_("Cannot change {0} of a backup code").format(", ".join(changed)),
				frappe.ValidationError,
			)

	def after_delete(self):
		# generate_codes and deleting a user remove rows without hooks, so this
		# covers a System Manager deleting codes from Desk or REST, which used
		# to be silent.
		actor = frappe.session.user
		detail = self.name if actor == self.user else f"{self.name} by {actor}"
		log_event("backup_code_deleted", user=self.user, method="backup", success=True, detail=detail)
		notify.sign_in_methods_changed(
			self.user,
			_("A backup code was deleted from your account.")
			if actor == self.user
			else _("A backup code was deleted from your account by {0}.").format(actor),
		)
