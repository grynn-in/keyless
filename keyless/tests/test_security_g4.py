"""G-4 (audit of 12 October 2026): removing a passkey through keyless.api.passkey.revoke_passkey
needs a recent re-authentication (step-up), as adding one does. A stolen session
outside the step-up window must not be able to strip the owner's passkeys."""

from __future__ import annotations

from unittest.mock import patch

import frappe

from keyless import stepup
from keyless.api import passkey
from keyless.tests.security_utils import delete_user, keyless_settings, make_user
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
		frappe.delete_doc("User Passkey", target)
		self.assertFalse(frappe.db.exists("User Passkey", target))
		self.assertTrue(self.mails_to(OTHER), "owner not told about the removal")

