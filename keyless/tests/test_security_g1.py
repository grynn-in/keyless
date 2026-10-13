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


def insert_legacy_row(user: str, code: str, owner: str, modified_by: str | None = None, used: int = 0) -> str:
	"""A row as Keyless 2.0.0 stored it: the hash covers the code only, and the
	row's creator and last editor are whoever inserted it (the user, for
	generate_codes). Redeeming sets `used` with frappe.db.set_value, which makes
	the last editor Guest."""
	name = frappe.generate_hash(length=10)
	stamp = now()
	frappe.db.sql(
		"""insert into `tabKeyless Backup Code`
			(name, user, code_hash, used, owner, modified_by, creation, modified)
		values (%s, %s, %s, %s, %s, %s, %s, %s)""",
		(name, user, digest(code), used, owner, modified_by or owner, stamp, stamp),
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
		# Generating codes for Administrator gives it a WebAuthn handle and audit
		# entries; tearDownClass removes what this class added.
		cls.started = now()
		cls.admin_handle = frappe.db.get_value("User", "Administrator", "keyless_user_handle")
		frappe.db.commit()

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		frappe.db.delete("Keyless Audit Log", {"user": ("in", (MANAGER, TARGET))})
		frappe.db.delete("Keyless Audit Log", {"user": "Administrator", "creation": (">=", cls.started)})
		if not cls.admin_handle:
			frappe.db.set_value("User", "Administrator", "keyless_user_handle", None, update_modified=False)
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

	def test_system_manager_cannot_move_a_code_with_its_creator_via_rest(self):
		# Moving the user and the creator in one request would make the row look
		# as if generate_codes had made it for the new user.
		name, code = self.own_row()
		frappe.db.commit()
		fields = ["user", "owner", "modified_by", "code_hash"]
		before = frappe.db.get_value(DOCTYPE, name, fields, as_dict=True)
		for user in (TARGET, "Administrator"):
			moved = {"user": user, "owner": user}
			with self.subTest(path="set_value", user=user):
				response = http(
					new_client(),
					"post",
					"/api/method/frappe.client.set_value",
					json={"doctype": DOCTYPE, "name": name, "fieldname": moved},
					headers=self.headers,
				)
				frappe.db.rollback()
				self.assertNotEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
				self.assertEqual(frappe.db.get_value(DOCTYPE, name, fields, as_dict=True), before)
			with self.subTest(path="resource", user=user):
				response = http(
					new_client(), "put", f"/api/resource/{DOCTYPE}/{name}", json=moved, headers=self.headers
				)
				frappe.db.rollback()
				self.assertNotEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
				self.assertEqual(frappe.db.get_value(DOCTYPE, name, fields, as_dict=True), before)
			self.assertEqual(redeem(user, code), [])

	def test_server_code_cannot_change_a_code(self):
		# Desk, a script, or a role given write with a Custom DocPerm. Redeeming
		# marks a code used with frappe.db.set_value, which skips the controller.
		changes = (
			("user", TARGET),
			("user", "Administrator"),
			("owner", TARGET),
			("code_hash", "b" * 64),
			("hash_version", 1),
			("used", 0),
			("used", 1),
			("used_on", "2026-01-01 00:00:00"),
		)
		for used in (0, 1):
			name, _code = self.own_row()
			if used:
				frappe.db.set_value(DOCTYPE, name, {"used": 1, "used_on": now()})
			fields = ["user", "owner", "code_hash", "hash_version", "used", "used_on"]
			before = frappe.db.get_value(DOCTYPE, name, fields, as_dict=True)
			for field, value in changes:
				with self.subTest(used=used, field=field, value=value):
					doc = frappe.get_doc(DOCTYPE, name)
					doc.set(field, value)
					if doc.get(field) == before.get(field):
						continue
					with self.assertRaises(frappe.ValidationError):
						doc.save(ignore_permissions=True)
					self.assertEqual(frappe.db.get_value(DOCTYPE, name, fields, as_dict=True), before)
			frappe.db.delete(DOCTYPE, {"name": name})

	def test_server_code_cannot_burn_an_unused_code(self):
		# Marking a code used through the document would silently take it away
		# from its user.
		name, code = self.own_row()
		doc = frappe.get_doc(DOCTYPE, name)
		doc.used = 1
		with self.assertRaises(frappe.ValidationError):
			doc.save(ignore_permissions=True)
		self.assertEqual(redeem(MANAGER, code), [MANAGER])

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

	def test_legacy_code_moved_with_its_creator_does_not_sign_in(self):
		# Before G-1 a System Manager could set `user` and `owner` together with
		# frappe.client.set_value or PUT /api/resource. The save made them the
		# row's last editor; generate_codes rows are never saved again.
		for user in (TARGET, "Administrator"):
			with self.subTest(user=user):
				insert_legacy_row(user, "MOVED23456", owner=user, modified_by=MANAGER)
				self.assertEqual(redeem(user, "MOVED23456"), [])

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
		moved_with_owner = insert_legacy_row(TARGET, "MOVED34567", owner=TARGET, modified_by=MANAGER)
		own = insert_legacy_row(TARGET, "LEGACY2345", owner=TARGET)
		# Redeemed: frappe.db.set_value made Guest its last editor.
		own_used = insert_legacy_row(TARGET, "LEGACY3456", owner=TARGET, modified_by="Guest", used=1)
		found = {row.name for row in find_unbound_backup_codes()}
		self.assertIn(moved, found)
		self.assertIn(moved_with_owner, found)
		self.assertNotIn(own, found)
		self.assertNotIn(own_used, found)

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

	def test_bulk_delete_sends_one_email_per_user(self):
		# Desk's list view deletes up to ten rows in one request and commits
		# after each. Every row is logged; each user gets one email.
		generate_for(TARGET)
		generate_for(MANAGER)
		names = frappe.get_all(DOCTYPE, {"user": TARGET}, pluck="name")[:3]
		names += frappe.get_all(DOCTYPE, {"user": MANAGER}, pluck="name")[:2]
		frappe.db.commit()
		with patch("frappe.sendmail") as sendmail:
			response = http(
				new_client(),
				"post",
				"/api/method/frappe.desk.reportview.delete_items",
				data={"doctype": DOCTYPE, "items": frappe.as_json(names)},
				headers=self.headers,
			)
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		frappe.db.rollback()
		self.assertFalse(frappe.db.exists(DOCTYPE, {"name": ("in", names)}))
		logged = frappe.get_all(
			"Keyless Audit Log", {"event": "backup_code_deleted", "user": ("in", (MANAGER, TARGET))}, pluck="detail"
		)
		for name in names[:3]:
			self.assertIn(f"{name} by {MANAGER}", logged)
		for name in names[3:]:
			self.assertIn(name, logged)
		recipients = [str(call.kwargs.get("recipients")) for call in sendmail.call_args_list]
		self.assertEqual(sum(TARGET in r for r in recipients), 1, recipients)
		self.assertEqual(sum(MANAGER in r for r in recipients), 1, recipients)
