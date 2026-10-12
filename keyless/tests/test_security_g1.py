"""G-1 (audit of 12 October 2026): a backup code may only come from the user's
own generate_codes, cannot be moved to another account afterwards, and only
signs in the user it was generated for. A System Manager must not be able to
create a code for another user, Administrator included, or re-point one of
their own codes at them."""

from __future__ import annotations

from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import now, set_request

from keyless.api import backup
from keyless.tests.security_utils import (
	api_auth_header,
	delete_user,
	http,
	keyless_settings,
	make_user,
	new_client,
	reset_rate_limits,
)
from keyless.tokens import digest

MANAGER = "kl-g1-manager@example.com"
TARGET = "kl-g1-target@example.com"
DOCTYPE = "Keyless Backup Code"
# Set by keyless.api.backup.generate_codes on each row it inserts.
GENERATED_FLAG = "keyless_generated_for"
KNOWN_CODE = "KNWN234567"


def generate_for(user: str) -> list[str]:
	"""Run generate_codes as `user`, as their own Desk session would, with step-up
	and the notice email out of the way. Returns the plaintext codes."""
	frappe.set_user(user)
	try:
		with patch("keyless.stepup.require"), patch("keyless.notify.sign_in_methods_changed"):
			return backup.generate_codes()["codes"]
	finally:
		frappe.set_user("Administrator")


def redeem(email: str, code: str) -> list[str]:
	"""Call the guest redeem endpoint. Returns the users it would have signed in."""
	set_request(method="POST", path="/api/method/keyless.api.backup.redeem")
	frappe.local.request_ip = "127.0.0.1"
	frappe.local.form_dict = frappe._dict(cmd="keyless.api.backup.redeem")
	signed_in = []
	with patch.object(backup, "issue_session", side_effect=lambda user, method: signed_in.append(user)):
		try:
			backup.redeem(email, code)
		except frappe.AuthenticationError:
			pass
	return signed_in


def insert_legacy_row(user: str, code: str, owner: str) -> str:
	"""A row as Keyless 2.0.0 stored it: the hash covers the code only, and the
	row's creator is whoever inserted it (the user, for generate_codes)."""
	name = frappe.generate_hash(length=10)
	stamp = now()
	frappe.db.sql(
		"""insert into `tabKeyless Backup Code`
			(name, user, code_hash, used, owner, modified_by, creation, modified)
		values (%s, %s, %s, 0, %s, %s, %s, %s)""",
		(name, user, digest(code), owner, owner, stamp, stamp),
	)
	return name


class TestBackupCodesOnlyFromGeneration(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(MANAGER, user_type="System User", roles=("System Manager",))
		make_user(TARGET)
		cls.headers = api_auth_header(MANAGER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		frappe.db.delete("Keyless Audit Log", {"user": ("in", (MANAGER, TARGET))})
		delete_user(MANAGER)
		delete_user(TARGET)
		frappe.db.commit()
		super().tearDownClass()

	def setUp(self):
		# A fresh request with no after_response, so audit rows go straight into
		# this transaction rather than to a callback left by an earlier test.
		set_request(method="POST", path="/api/method/ping")
		reset_rate_limits()
		self.admin_rows = frappe.get_all(DOCTYPE, filters={"user": "Administrator"}, fields=["*"])
		self.addCleanup(frappe.set_user, "Administrator")
		self.addCleanup(self.remove_rows)
		self.settings = keyless_settings(enabled=1, enable_backup_codes=1)
		self.settings.__enter__()
		self.addCleanup(self.settings.__exit__, None, None, None)

	def remove_rows(self):
		frappe.db.rollback()
		frappe.db.delete(DOCTYPE, {"user": ("in", (MANAGER, TARGET, "Administrator"))})
		frappe.db.delete(DOCTYPE, {"owner": ("in", (MANAGER, TARGET))})
		for row in self.admin_rows:
			# Put back Administrator's own codes exactly as they were.
			columns = ", ".join(f"`{column}`" for column in row)
			values = ", ".join(["%s"] * len(row))
			frappe.db.sql(f"insert into `tabKeyless Backup Code` ({columns}) values ({values})", list(row.values()))
		frappe.db.commit()
		reset_rate_limits()

	def own_row(self, user=MANAGER) -> tuple[str, str]:
		"""Generate codes for `user` and keep one: (row name, plaintext)."""
		with patch.object(backup, "_generate_code", return_value=KNOWN_CODE):
			generate_for(user)
		names = frappe.get_all(DOCTYPE, {"user": user}, pluck="name")
		frappe.db.delete(DOCTYPE, {"name": ("in", names[1:])})
		return names[0], KNOWN_CODE

	# --- creating rows ---------------------------------------------------------

	def test_system_manager_cannot_create_via_rest(self):
		name, code = self.own_row()
		code_hash = frappe.db.get_value(DOCTYPE, name, "code_hash")
		frappe.db.commit()
		for user in (TARGET, "Administrator"):
			with self.subTest(user=user):
				fields = {"doctype": DOCTYPE, "user": user, "code_hash": code_hash}
				response = http(new_client(), "post", f"/api/resource/{DOCTYPE}", json=fields, headers=self.headers)
				frappe.db.rollback()
				self.assertEqual(response.status_code, 403, response.get_data(as_text=True)[:300])
				self.assertFalse(frappe.db.exists(DOCTYPE, {"user": user, "code_hash": code_hash}))
				self.assertEqual(redeem(user, code), [])

	def test_server_code_cannot_insert_without_generation(self):
		# Even Administrator with ignore_permissions, as Desk, Data Import or a
		# script would.
		for user in (TARGET, "Administrator"):
			with self.subTest(user=user):
				doc = frappe.get_doc({"doctype": DOCTYPE, "user": user, "code_hash": digest("ABCDEFGHJK")})
				with self.assertRaises(frappe.PermissionError):
					doc.insert(ignore_permissions=True)

	def test_generation_mark_must_name_the_rows_user(self):
		doc = frappe.get_doc({"doctype": DOCTYPE, "user": TARGET, "code_hash": "a" * 64})
		doc.flags[GENERATED_FLAG] = MANAGER
		with self.assertRaises(frappe.PermissionError):
			doc.insert(ignore_permissions=True)

	def test_only_administrator_may_add_an_administrator_code(self):
		frappe.set_user(MANAGER)
		doc = frappe.get_doc({"doctype": DOCTYPE, "user": "Administrator", "code_hash": "a" * 64})
		doc.flags[GENERATED_FLAG] = "Administrator"
		with self.assertRaises(frappe.PermissionError):
			doc.insert(ignore_permissions=True)

	# --- changing rows ---------------------------------------------------------

	def test_system_manager_cannot_repoint_or_reset_via_rest(self):
		name, _code = self.own_row()
		frappe.db.set_value(DOCTYPE, name, {"used": 1})
		frappe.db.commit()
		before = frappe.db.get_value(DOCTYPE, name, ["user", "code_hash", "used"], as_dict=True)
		changes = (("user", TARGET), ("user", "Administrator"), ("code_hash", "b" * 64), ("used", 0))
		for field, value in changes:
			with self.subTest(path="set_value", field=field, value=value):
				response = http(
					new_client(),
					"post",
					"/api/method/frappe.client.set_value",
					json={"doctype": DOCTYPE, "name": name, "fieldname": field, "value": value},
					headers=self.headers,
				)
				frappe.db.rollback()
				self.assertNotEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
				self.assertEqual(frappe.db.get_value(DOCTYPE, name, ["user", "code_hash", "used"], as_dict=True), before)
			with self.subTest(path="resource", field=field, value=value):
				response = http(
					new_client(), "put", f"/api/resource/{DOCTYPE}/{name}", json={field: value}, headers=self.headers
				)
				frappe.db.rollback()
				self.assertNotEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
				self.assertEqual(frappe.db.get_value(DOCTYPE, name, ["user", "code_hash", "used"], as_dict=True), before)

	def test_server_code_cannot_change_a_code(self):
		name, _code = self.own_row()
		frappe.db.set_value(DOCTYPE, name, {"used": 1})
		for field, value in (("user", TARGET), ("user", "Administrator"), ("code_hash", "b" * 64), ("used", 0)):
			with self.subTest(field=field, value=value):
				doc = frappe.get_doc(DOCTYPE, name)
				doc.set(field, value)
				with self.assertRaises(frappe.ValidationError):
					doc.save(ignore_permissions=True)

	# --- redeeming -------------------------------------------------------------

	def test_own_codes_still_work_once(self):
		codes = generate_for(TARGET)
		self.assertEqual(redeem(TARGET, codes[0]), [TARGET])
		self.assertEqual(redeem(TARGET, codes[0]), [])
		self.assertEqual(redeem(TARGET, codes[1]), [TARGET])

	def test_administrator_own_codes_work(self):
		codes = generate_for("Administrator")
		self.assertEqual(redeem("Administrator", codes[0]), ["Administrator"])

	def test_code_moved_in_the_database_does_not_sign_in_its_new_user(self):
		# As if the row had been re-pointed before this fix, or by SQL.
		name, code = self.own_row()
		for user in (TARGET, "Administrator"):
			with self.subTest(user=user):
				frappe.db.set_value(DOCTYPE, name, "user", user, update_modified=False)
				self.assertEqual(redeem(user, code), [])
		frappe.db.set_value(DOCTYPE, name, "user", MANAGER, update_modified=False)
		self.assertEqual(redeem(MANAGER, code), [MANAGER])

	def test_legacy_code_keeps_working_for_its_user(self):
		# Upgrade path: rows generated before this fix are not regenerated.
		insert_legacy_row(TARGET, "LEGACY2345", owner=TARGET)
		self.assertEqual(redeem(TARGET, "LEGACY2345"), [TARGET])
		self.assertEqual(redeem(TARGET, "LEGACY2345"), [])

	def test_legacy_code_created_for_someone_else_does_not_sign_in(self):
		# A row a System Manager created for, or re-pointed at, another user
		# before this fix: its creator is not its user.
		for user in (TARGET, "Administrator"):
			with self.subTest(user=user):
				insert_legacy_row(user, "MOVED23456", owner=MANAGER)
				self.assertEqual(redeem(user, "MOVED23456"), [])

	def test_migrate_reports_legacy_codes_created_for_someone_else(self):
		from keyless.security import find_unbound_backup_codes

		moved = insert_legacy_row(TARGET, "MOVED23456", owner=MANAGER)
		own = insert_legacy_row(TARGET, "LEGACY2345", owner=TARGET)
		found = {row.name for row in find_unbound_backup_codes()}
		self.assertIn(moved, found)
		self.assertNotIn(own, found)

	# --- deleting rows ---------------------------------------------------------

	def test_delete_by_system_manager_is_logged_and_notified(self):
		generate_for(TARGET)
		name = frappe.get_all(DOCTYPE, {"user": TARGET}, pluck="name")[0]
		frappe.db.commit()
		with patch("frappe.sendmail") as sendmail:
			response = http(new_client(), "delete", f"/api/resource/{DOCTYPE}/{name}", headers=self.headers)
		self.assertIn(response.status_code, (200, 202), response.get_data(as_text=True)[:300])
		frappe.db.rollback()
		self.assertFalse(frappe.db.exists(DOCTYPE, name))
		self.assertTrue(
			frappe.db.exists(
				"Keyless Audit Log", {"user": TARGET, "event": "backup_code_deleted", "detail": f"{name} by {MANAGER}"}
			)
		)
		recipients = [str(call.kwargs.get("recipients")) for call in sendmail.call_args_list]
		self.assertTrue(any(TARGET in r for r in recipients), recipients)

