"""G-4 (audit of 12 October 2026): removing a passkey needs a recent
re-authentication (step-up), as adding one does. A stolen session outside the
step-up window must not be able to strip the owner's passkeys, whether through
keyless.api.passkey.revoke_passkey or by deleting the User Passkey record
(Desk, /api/resource, frappe.client.delete)."""

from __future__ import annotations

import secrets
from unittest.mock import patch

import frappe
from webauthn.helpers import bytes_to_base64url

from keyless import stepup
from keyless.api import passkey
from keyless.tests.security_utils import (
	PASSWORD,
	delete_user,
	http,
	insert_passkey,
	keyless_settings,
	make_user,
	new_client,
)
from keyless.tests.test_security_m3 import OTHER, USER, StepUpCase, clear_step_up

MANAGER = "kl-g4-manager@example.com"


class TestRevokeNeedsStepUp(StepUpCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		make_user(MANAGER, user_type="System User", roles=("System Manager",))

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		frappe.db.delete("Keyless Audit Log", {"user": ("in", (USER, OTHER))})
		frappe.db.commit()
		delete_user(MANAGER)
		super().tearDownClass()

	def own_passkeys(self, user=USER):
		"""Two passkeys for `user`, registered in a fresh session."""
		self.sign_in(user)
		keep = self.register("Keep")["name"]
		target = self.register("Target")["name"]
		return keep, target

	def revoke(self, name):
		self.request("keyless.api.passkey.revoke_passkey")
		return passkey.revoke_passkey(name)

	def test_revoke_refused_without_recent_auth(self):
		_keep, target = self.own_passkeys()
		clear_step_up()
		self.mail.reset_mock()
		with self.assertRaises(stepup.StepUpRequiredError) as ctx:
			self.revoke(target)
		# The same refusal as adding a passkey, so the Desk step-up flow recognises it.
		self.assertIn("Confirm it's you", str(ctx.exception))
		self.assertTrue(frappe.db.exists("User Passkey", target))
		self.assertFalse(self.mails_to(USER), "no 'passkey removed' email for a refused removal")

	def test_revoke_refused_after_window_expires(self):
		_keep, target = self.own_passkeys()
		later = stepup.now_ts() + 6 * 60
		with keyless_settings(step_up_window_minutes=5), patch.object(stepup, "now_ts", return_value=later):
			with self.assertRaises(stepup.StepUpRequiredError):
				self.revoke(target)
		self.assertTrue(frappe.db.exists("User Passkey", target))

	def test_revoke_works_after_fresh_sign_in(self):
		keep, target = self.own_passkeys()
		self.assertTrue(self.revoke(target)["ok"])
		self.assertFalse(frappe.db.exists("User Passkey", target))
		self.assertTrue(frappe.db.exists("User Passkey", keep))

	def test_revoke_works_after_step_up_by_email_code(self):
		from keyless.api import stepup as api

		_keep, target = self.own_passkeys()
		clear_step_up()
		self.request("keyless.api.stepup.request_email_code")
		api.request_email_code()
		code = self.mails_to(USER)[-1].kwargs["args"]["otp"]
		self.request("keyless.api.stepup.verify_email_code")
		api.verify_email_code(code)
		self.assertTrue(self.revoke(target)["ok"])
		self.assertFalse(frappe.db.exists("User Passkey", target))

	def test_manager_revoking_through_the_api_needs_step_up_too(self):
		_keep, target = self.own_passkeys(OTHER)
		self.sign_in(MANAGER)
		clear_step_up()
		with self.assertRaises(stepup.StepUpRequiredError):
			self.revoke(target)
		self.assertTrue(frappe.db.exists("User Passkey", target))

	def test_manager_delete_from_desk_is_unaffected(self):
		# Desk and REST delete the record directly; that path is logged and the
		# owner emailed (F-2), and stays available without step-up.
		_keep, target = self.own_passkeys(OTHER)
		self.sign_in(MANAGER)
		clear_step_up()
		# Only mails sent by the deletion count, not the earlier "added" ones.
		self.mail.reset_mock()
		frappe.delete_doc("User Passkey", target)
		self.assertFalse(frappe.db.exists("User Passkey", target))
		self.assertTrue(removed_mails(self.mails_to(OTHER)), "owner not told about the removal")


def removed_mails(calls):
	return [c for c in calls if "was removed from your account" in str(c.kwargs.get("message"))]


DELETE_PATHS = ("DELETE /api/resource", "frappe.client.delete")


class TestDeleteOwnPasskeyRecordNeedsStepUp(StepUpCase):
	"""Deleting one's own User Passkey record (Desk Delete, DELETE /api/resource,
	frappe.client.delete) needs step-up too. Otherwise a stolen Administrator or
	System Manager session could remove that administrator's own passkeys that way."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		make_user(MANAGER, user_type="System User", roles=("System Manager",))

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		frappe.db.delete("Keyless Audit Log", {"user": ("in", (MANAGER, OTHER))})
		frappe.db.commit()
		delete_user(MANAGER)
		super().tearDownClass()

	def setUp(self):
		super().setUp()
		# MANAGER signs in with a password here, so do not insist on a passkey.
		password_ok = keyless_settings(require_passkey_for_system_users=0)
		password_ok.__enter__()
		self.addCleanup(password_ok.__exit__, None, None, None)
		self.addCleanup(self.remove_manager_passkeys)
		self.remove_manager_passkeys()

	def remove_manager_passkeys(self):
		frappe.db.rollback()
		frappe.db.delete("User Passkey", {"user": MANAGER})
		frappe.db.commit()

	def passkey_for(self, user):
		doc = insert_passkey(
			{
				"user": user,
				"credential_id": bytes_to_base64url(secrets.token_bytes(16)),
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
				"friendly_name": "kl-g4",
			}
		)
		frappe.db.commit()
		return doc.name

	def manager_session(self, fresh: bool):
		"""A signed-in browser session for MANAGER. Not fresh: the step-up window
		has passed, as for a session stolen some time after sign-in."""
		client = new_client()
		response = http(client, "post", "/api/method/login", data={"usr": MANAGER, "pwd": PASSWORD})
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		if not fresh:
			clear_step_up()
		return client

	@staticmethod
	def delete_requests(name):
		"""The record-deletion paths, by label: (client method, path, keyword arguments)."""
		return {
			"DELETE /api/resource": ("delete", f"/api/resource/User Passkey/{name}", {}),
			"frappe.client.delete": (
				"post",
				"/api/method/frappe.client.delete",
				{"json": {"doctype": "User Passkey", "name": name}},
			),
		}

	def test_own_passkey_delete_refused_without_recent_auth(self):
		for label in DELETE_PATHS:
			with self.subTest(request=label):
				name = self.passkey_for(MANAGER)
				client = self.manager_session(fresh=False)
				self.mail.reset_mock()
				method, path, kwargs = self.delete_requests(name)[label]
				response = http(client, method, path, **kwargs)
				frappe.db.rollback()
				self.assertEqual(response.status_code, 403, response.get_data(as_text=True)[:300])
				self.assertIn("Confirm it", response.get_data(as_text=True))
				self.assertTrue(frappe.db.exists("User Passkey", name))
				self.assertFalse(removed_mails(self.mails_to(MANAGER)))

	def test_own_passkey_delete_works_after_fresh_sign_in(self):
		for label in DELETE_PATHS:
			with self.subTest(request=label):
				name = self.passkey_for(MANAGER)
				client = self.manager_session(fresh=True)
				self.mail.reset_mock()
				method, path, kwargs = self.delete_requests(name)[label]
				response = http(client, method, path, **kwargs)
				frappe.db.rollback()
				self.assertIn(response.status_code, (200, 202), response.get_data(as_text=True)[:300])
				self.assertFalse(frappe.db.exists("User Passkey", name))
				self.assertTrue(removed_mails(self.mails_to(MANAGER)), "owner not told about the removal")

	def test_manager_deleting_someone_elses_passkey_needs_no_step_up(self):
		# An administrator removing a user's credential, for example from a lost
		# device. Logged and the owner emailed (F-2).
		name = self.passkey_for(OTHER)
		client = self.manager_session(fresh=False)
		self.mail.reset_mock()
		response = http(client, "delete", f"/api/resource/User Passkey/{name}")
		frappe.db.rollback()
		self.assertIn(response.status_code, (200, 202), response.get_data(as_text=True)[:300])
		self.assertFalse(frappe.db.exists("User Passkey", name))
		self.assertTrue(removed_mails(self.mails_to(OTHER)), "owner not told about the removal")

	def test_own_passkey_delete_in_desk_bulk_job_refused(self):
		# Desk's bulk Delete of more than 10 rows runs as a background job as
		# the same user, with no request; it must not skip the check.
		name = self.passkey_for(MANAGER)
		frappe.set_user(MANAGER)
		frappe.local.request = None
		frappe.local.job = frappe._dict(name="kl-g4-bulk-delete")
		self.addCleanup(setattr, frappe.local, "job", None)
		with self.assertRaises(stepup.StepUpRequiredError):
			frappe.delete_doc("User Passkey", name)
		frappe.db.rollback()
		self.assertTrue(frappe.db.exists("User Passkey", name))

	def test_server_code_without_a_session_is_unaffected(self):
		# bench console, patches, migrate: no request, no job, no step-up to ask for.
		name = self.passkey_for(MANAGER)
		frappe.set_user(MANAGER)
		frappe.local.request = None
		frappe.local.job = None
		frappe.delete_doc("User Passkey", name)
		self.assertFalse(frappe.db.exists("User Passkey", name))

