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
		# Every field of a code binds it to its user or records its use, so an
		# existing row is never saved again: not by Desk, REST, a script or a
		# role given write with a Custom DocPerm. Redeeming marks a code used
		# with frappe.db.set_value, which does not run this check. A legitimate
		# unused row is therefore never re-saved, and redeem relies on that for
		# rows stored before G-1 (audit 2026-10-12, G-1).
		if not self.is_new():
			frappe.throw(
				_("Backup codes cannot be changed. Generate new ones instead."),
				frappe.ValidationError,
			)

	def after_delete(self):
		# generate_codes and deleting a user remove rows without hooks, so this
		# covers a System Manager deleting codes from Desk or REST, which used
		# to be silent. Every row is logged; the user gets one email per request.
		actor = frappe.session.user
		detail = self.name if actor == self.user else f"{self.name} by {actor}"
		log_event("backup_code_deleted", user=self.user, method="backup", success=True, detail=detail)
		_notify_once(self.user, actor)


def _notify_once(user: str, actor: str) -> None:
	"""Email `user` about a deleted backup code once per request or job.

	Desk's bulk delete removes up to ten rows in one request and commits after
	each, so the mail is queued in the transaction of the first deletion (and
	rolled back with it) and later deletions for the same user are skipped.
	"""
	notified = getattr(frappe.local, "keyless_backup_code_deleted_notified", None)
	if notified is None:
		notified = frappe.local.keyless_backup_code_deleted_notified = set()
	if user in notified:
		return
	notified.add(user)
	# If this transaction is rolled back, the queued mail goes with it: let a
	# later deletion in the same request send it.
	frappe.db.after_rollback.add(lambda: notified.discard(user))
	notify.sign_in_methods_changed(
		user,
		_("Backup codes were deleted from your account.")
		if actor == user
		else _("Backup codes were deleted from your account by {0}.").format(actor),
	)
