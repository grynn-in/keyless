"""L-1: one backup code, redeemed by many requests at once, gives one session."""

from __future__ import annotations

import threading
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from keyless.api import backup
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits
from keyless.tokens import digest

USER = "kl-l1-user@example.com"
CODE = "ABCDEFGH23"


class TestBackupCodeRace(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(USER)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		frappe.db.delete("Keyless Backup Code", {"user": USER})
		frappe.get_doc({"doctype": "Keyless Backup Code", "user": USER, "code_hash": digest(CODE)}).insert(
			ignore_permissions=True
		)
		frappe.db.commit()

	def test_parallel_redemptions_give_one_session(self):
		site = frappe.local.site
		sessions = []
		lock = threading.Lock()
		start = threading.Barrier(6)

		def record(user, method):
			with lock:
				sessions.append(user)

		def redeem():
			frappe.init(site=site)
			frappe.connect()
			try:
				start.wait()
				try:
					backup.redeem(USER, CODE)
				except frappe.AuthenticationError:
					pass
				frappe.db.commit()  # as at the end of a request
			finally:
				frappe.destroy()

		with (
			keyless_settings(enabled=1, enable_backup_codes=1),
			patch.object(backup, "issue_session", side_effect=record),
		):
			threads = [threading.Thread(target=redeem) for _ in range(6)]
			for t in threads:
				t.start()
			for t in threads:
				t.join()
		self.assertEqual(sessions, [USER])
		self.assertEqual(frappe.db.get_value("Keyless Backup Code", {"user": USER}, "used"), 1)
