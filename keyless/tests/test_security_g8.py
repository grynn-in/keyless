"""G-8 (audit of 12 October 2026): Keyless Audit Log rows are evidence. A System
Manager must not be able to delete them, even after granting themselves the
permission, and nobody may change a row once it is written. Administrator can
still delete rows, and the retention job still purges old ones."""

from __future__ import annotations

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import add_days, now_datetime, set_request

from keyless.tasks import purge_old_audit_logs
from keyless.tests.security_utils import (
	api_auth_header,
	delete_user,
	http,
	keyless_settings,
	make_user,
	new_client,
)

MANAGER = "kl-g8-manager@example.com"
SUBJECT = "kl-g8-subject@example.com"


def audit_row(**fields) -> str:
	doc = frappe.get_doc(
		{
			"doctype": "Keyless Audit Log",
			"event": "login",
			"user": SUBJECT,
			"method": "passkey",
			"success": 1,
			"detail": "kl-g8",
			"event_on": now_datetime(),
			**fields,
		}
	)
	doc.insert(ignore_permissions=True)
	frappe.db.commit()
	return doc.name


class TestAuditLogIsImmutable(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(MANAGER, user_type="System User", roles=("System Manager",))
		cls.headers = api_auth_header(MANAGER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(MANAGER)
		super().tearDownClass()

	def setUp(self):
		frappe.set_user("Administrator")
		self.addCleanup(self.remove_rows)
		self.name = audit_row()

	def remove_rows(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()
		frappe.db.delete("Keyless Audit Log", {"user": SUBJECT})
		frappe.db.delete("Deleted Document", {"deleted_doctype": "Keyless Audit Log", "deleted_name": self.name})
		frappe.db.commit()

	# Deleting

	def test_system_manager_cannot_delete_via_rest(self):
		response = http(
			new_client(), "delete", f"/api/resource/Keyless Audit Log/{self.name}", headers=self.headers
		)
		frappe.db.rollback()
		self.assertEqual(response.status_code, 403, response.get_data(as_text=True)[:300])
		self.assertTrue(frappe.db.exists("Keyless Audit Log", self.name))

	def test_system_manager_cannot_delete_from_desk(self):
		frappe.set_user(MANAGER)
		with self.assertRaises(frappe.PermissionError):
			frappe.delete_doc("Keyless Audit Log", self.name)
		frappe.set_user("Administrator")
		frappe.db.rollback()
		self.assertTrue(frappe.db.exists("Keyless Audit Log", self.name))

	def test_system_manager_cannot_delete_even_with_permission_granted(self):
		# A System Manager can grant any role "delete" in Role Permissions Manager;
		# the record itself must still refuse.
		frappe.set_user(MANAGER)
		with self.assertRaises(frappe.PermissionError):
			frappe.delete_doc("Keyless Audit Log", self.name, ignore_permissions=True)
		frappe.set_user("Administrator")
		frappe.db.rollback()
		self.assertTrue(frappe.db.exists("Keyless Audit Log", self.name))

	def test_administrator_can_delete(self):
		frappe.delete_doc("Keyless Audit Log", self.name)
		frappe.db.commit()
		self.assertFalse(frappe.db.exists("Keyless Audit Log", self.name))
		# Frappe keeps a copy of what was deleted, and who deleted it.
		self.assertTrue(
			frappe.db.exists(
				"Deleted Document",
				{"deleted_doctype": "Keyless Audit Log", "deleted_name": self.name, "owner": "Administrator"},
			)
		)

	# Editing

	def test_system_manager_cannot_edit_via_rest(self):
		response = http(
			new_client(),
			"put",
			f"/api/resource/Keyless Audit Log/{self.name}",
			json={"detail": "changed", "success": 0},
			headers=self.headers,
		)
		frappe.db.rollback()
		self.assertEqual(response.status_code, 403, response.get_data(as_text=True)[:300])
		self.assertEqual(frappe.db.get_value("Keyless Audit Log", self.name, "detail"), "kl-g8")

	def test_nobody_can_edit_a_row(self):
		for user in (MANAGER, "Administrator"):
			with self.subTest(user=user):
				frappe.set_user(user)
				doc = frappe.get_doc("Keyless Audit Log", self.name)
				doc.detail = "changed"
				doc.user = "someone-else@example.com"
				with self.assertRaises(frappe.PermissionError):
					doc.save(ignore_permissions=True)
				frappe.set_user("Administrator")
				frappe.db.rollback()
				self.assertEqual(frappe.db.get_value("Keyless Audit Log", self.name, "detail"), "kl-g8")

	def test_administrator_cannot_edit_with_set_value(self):
		from frappe.client import set_value

		with self.assertRaises(frappe.PermissionError):
			set_value("Keyless Audit Log", self.name, {"detail": "changed"})
		frappe.db.rollback()
		self.assertEqual(frappe.db.get_value("Keyless Audit Log", self.name, "detail"), "kl-g8")

	# Legitimate paths

	def test_events_are_still_logged(self):
		from keyless.audit import log_event

		# A request with no after_response: the row goes into this transaction.
		set_request(method="POST", path="/api/method/ping")
		log_event("logout", user=SUBJECT, success=True, detail="kl-g8-new")
		frappe.db.commit()
		self.assertTrue(frappe.db.exists("Keyless Audit Log", {"user": SUBJECT, "detail": "kl-g8-new"}))

	def test_retention_job_still_purges_old_rows(self):
		old = audit_row(event_on=add_days(now_datetime(), -40), detail="kl-g8-old")
		with keyless_settings(audit_retention_days=30):
			purge_old_audit_logs()
		self.assertFalse(frappe.db.exists("Keyless Audit Log", old))
		self.assertTrue(frappe.db.exists("Keyless Audit Log", self.name))
