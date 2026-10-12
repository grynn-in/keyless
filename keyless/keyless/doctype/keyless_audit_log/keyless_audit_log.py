import frappe
from frappe import _
from frappe.model.document import Document


class KeylessAuditLog(Document):
	"""A sign-in audit entry. Entries are evidence: once written, nobody may change
	them, and only Administrator may delete them (audit 2026-10-12, G-8).

	The permissions in the DocType only grant System Manager read, report and
	export, but a System Manager can grant themselves more in Role Permissions
	Manager, and Administrator has every permission. So the record enforces it.
	The retention job (keyless.tasks.purge_old_audit_logs) deletes with
	frappe.db.delete and does not pass through here."""

	def validate(self):
		if not self.is_new():
			frappe.throw(_("Audit log entries cannot be changed."), frappe.PermissionError)

	def on_trash(self):
		# Frappe keeps a Deleted Document copy of what Administrator deletes.
		if frappe.session.user != "Administrator":
			frappe.throw(_("Only Administrator can delete audit log entries."), frappe.PermissionError)
