"""F-3 (audit of 10 October 2026): users must not be able to turn off Passwordless
Only, or change their WebAuthn handle, on their own User record. Changes made by
a System Manager are logged and notified."""

from __future__ import annotations

import json
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless.install import CUSTOM_FIELDS
from keyless.security import find_self_cleared_passwordless_only
from keyless.tests.security_utils import api_auth_header, delete_user, http, make_user, new_client

USER = "kl-f3-user@example.com"
MANAGER = "kl-f3-manager@example.com"
FIELDS = ("keyless_section", "keyless_user_handle", "keyless_passwordless_only")


class PasswordlessOnlyCase(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER)
		cls.user_headers = api_auth_header(USER)
		make_user(MANAGER, user_type="System User", roles=("System Manager",))
		cls.manager_headers = api_auth_header(MANAGER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		frappe.db.delete("Keyless Audit Log", {"user": USER})
		delete_user(USER)
		delete_user(MANAGER)
		super().tearDownClass()

	def setUp(self):
		# A fresh request with no after_response, so audit rows go straight into
		# this transaction rather than to a callback left by an earlier test.
		set_request(method="POST", path="/api/method/ping")
		self.set_flag(1)
		self.addCleanup(self.set_flag, 0)
		self.addCleanup(frappe.set_user, "Administrator")
		self.handle = frappe.db.get_value("User", USER, "keyless_user_handle")

	def set_flag(self, value: int):
		frappe.db.rollback()
		frappe.db.set_value("User", USER, "keyless_passwordless_only", value)
		frappe.db.commit()
		frappe.clear_cache(user=USER)

	def flag(self):
		frappe.db.rollback()
		return frappe.db.get_value("User", USER, "keyless_passwordless_only")


class TestUserCannotChangeOwnFields(PasswordlessOnlyCase):
	def test_fields_are_system_manager_only(self):
		meta = frappe.get_meta("User")
		for fieldname in FIELDS:
			with self.subTest(field=fieldname):
				self.assertEqual(meta.get_field(fieldname).permlevel, 1)
		# New installs get the same definitions as upgraded sites.
		self.assertEqual({df["fieldname"]: df.get("permlevel") for df in CUSTOM_FIELDS["User"]}, dict.fromkeys(FIELDS, 1))

	def test_user_cannot_clear_flag_or_change_handle_via_rest(self):
		requests = {
			"PUT /api/resource": ("put", f"/api/resource/User/{USER}", {"keyless_passwordless_only": 0, "keyless_user_handle": "0" * 32}),
			"frappe.client.set_value": (
				"post",
				"/api/method/frappe.client.set_value",
				{"doctype": "User", "name": USER, "fieldname": "keyless_passwordless_only", "value": 0},
			),
		}
		for label, (method, path, body) in requests.items():
			with self.subTest(request=label):
				http(new_client(), method, path, json=body, headers=self.user_headers)
				self.assertEqual(self.flag(), 1)
				self.assertEqual(frappe.db.get_value("User", USER, "keyless_user_handle"), self.handle)

	def test_server_code_saving_as_the_user_cannot_clear_flag(self):
		frappe.set_user(USER)
		doc = frappe.get_doc("User", USER)
		doc.keyless_passwordless_only = 0
		doc.flags.ignore_permissions = True
		with self.assertRaises(frappe.PermissionError):
			doc.save()
		self.assertEqual(self.flag(), 1)


class TestSystemManagerChanges(PasswordlessOnlyCase):
	def put_flag(self, value: int):
		with patch("frappe.sendmail") as sendmail:
			response = http(
				new_client(),
				"put",
				f"/api/resource/User/{USER}",
				json={"keyless_passwordless_only": value},
				headers=self.manager_headers,
			)
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		return [c.kwargs for c in sendmail.call_args_list if USER in str(c.kwargs.get("recipients"))]

	def test_system_manager_can_turn_it_off_and_on_and_the_user_is_told(self):
		for value, detail, words in ((0, "off", "turned off"), (1, "on", "turned on")):
			with self.subTest(value=value):
				mails = self.put_flag(value)
				self.assertEqual(self.flag(), value)
				audit = {"user": USER, "event": "passwordless_only_changed", "detail": f"{detail} by {MANAGER}"}
				self.assertTrue(frappe.db.exists("Keyless Audit Log", audit))
				self.assertTrue(mails, "the user was not notified")
				self.assertIn(words, mails[-1].get("message") or "")


class TestReportOfEarlierChanges(PasswordlessOnlyCase):
	def version(self, owner: str, change: list) -> str:
		doc = frappe.get_doc(
			{"doctype": "Version", "ref_doctype": "User", "docname": USER, "data": json.dumps({"changed": [change]})}
		).insert(ignore_permissions=True)
		frappe.db.set_value("Version", doc.name, "owner", owner, update_modified=False)
		return doc.name

	def test_report_finds_only_self_made_clears(self):
		self.addCleanup(frappe.db.rollback)
		self_cleared = self.version(USER, ["keyless_passwordless_only", 1, 0])
		by_manager = self.version(MANAGER, ["keyless_passwordless_only", 1, 0])
		self_set = self.version(USER, ["keyless_passwordless_only", 0, 1])
		found = {row.version for row in find_self_cleared_passwordless_only()}
		self.assertIn(self_cleared, found)
		self.assertNotIn(by_manager, found)
		self.assertNotIn(self_set, found)
