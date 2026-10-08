"""M-3: recent re-authentication before adding a passkey or rotating backup codes,
and an email to the user whenever passkeys or backup codes change."""

from __future__ import annotations

import re
import secrets
from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.auth import CookieManager, LoginManager
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request
from webauthn.helpers import bytes_to_base64url

from keyless.api import backup, passkey
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits

USER = "kl-m3-user@example.com"
OTHER = "kl-m3-other@example.com"
ON = {
	"enabled": 1,
	"enable_passkeys": 1,
	"enable_email_otp": 1,
	"enable_backup_codes": 1,
	"rp_id": "",
	"allowed_origins": "",
}


def clear_step_up():
	frappe.cache.delete_keys("keyless:stepup:")


def fake_registration(**kwargs):
	return SimpleNamespace(
		credential_id=secrets.token_bytes(16),
		credential_public_key=secrets.token_bytes(32),
		sign_count=0,
		aaguid=None,
		credential_backed_up=False,
	)


class StepUpCase(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER)
		make_user(OTHER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(USER)
		delete_user(OTHER)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		# Start each test without rows left by earlier tests or runs.
		for dt in ("User Passkey", "Keyless Backup Code"):
			frappe.db.delete(dt, {"user": ("in", (USER, OTHER))})
		frappe.db.commit()
		self.mail = patch("frappe.sendmail").start()
		self.addCleanup(patch.stopall)
		self.addCleanup(frappe.db.rollback)
		self.addCleanup(frappe.set_user, "Administrator")
		self.settings = keyless_settings(**ON)
		self.settings.__enter__()
		self.addCleanup(self.settings.__exit__, None, None, None)

	def sign_in(self, user=USER):
		"""A fresh session for `user`, as after any sign-in."""
		# Not /api/method/login: LoginManager() would then attempt a password login.
		set_request(method="POST", path="/api/method/keyless.api.otp.verify_otp")
		frappe.local.request_ip = "127.0.0.1"
		frappe.local.form_dict = frappe._dict()
		frappe.local.cookie_manager = CookieManager()
		frappe.local.login_manager = LoginManager()
		frappe.local.login_manager.login_as(user)
		self.assertEqual(frappe.session.user, user)

	def request(self, cmd):
		set_request(method="POST", path=f"/api/method/{cmd}")
		frappe.local.request_ip = "127.0.0.1"
		frappe.local.form_dict = frappe._dict(cmd=cmd)

	def register(self, name="Laptop"):
		self.request("keyless.api.passkey.verify_registration")
		cred = {"id": "x", "rawId": "x", "type": "public-key", "response": {}}
		with (
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "registration", "user": frappe.session.user, "challenge": "Y2hhbGxlbmdl"},
			),
			patch("webauthn.verify_registration_response", side_effect=fake_registration),
		):
			return passkey.verify_registration(cred, "cid", friendly_name=name)

	def mails_to(self, user):
		return [c for c in self.mail.call_args_list if user in str(c.kwargs.get("recipients"))]


class TestStepUpRequired(StepUpCase):
	def test_registration_refused_without_recent_auth(self):
		self.sign_in()
		clear_step_up()
		self.request("keyless.api.passkey.registration_options")
		with self.assertRaises(frappe.PermissionError):
			passkey.registration_options()
		with self.assertRaises(frappe.PermissionError):
			self.register()
		self.assertFalse(frappe.db.exists("User Passkey", {"user": USER}))

	def test_backup_rotation_refused_without_recent_auth(self):
		self.sign_in()
		frappe.get_doc({"doctype": "Keyless Backup Code", "user": USER, "code_hash": "a" * 64}).insert(
			ignore_permissions=True
		)
		clear_step_up()
		self.request("keyless.api.backup.generate_codes")
		with self.assertRaises(frappe.PermissionError):
			backup.generate_codes()
		self.assertEqual(frappe.db.count("Keyless Backup Code", {"user": USER}), 1)

	def test_fresh_sign_in_counts_as_recent(self):
		self.sign_in()
		self.request("keyless.api.passkey.registration_options")
		self.assertIn("challenge", passkey.registration_options())
		self.assertTrue(self.register()["ok"])
		self.request("keyless.api.backup.generate_codes")
		self.assertEqual(len(backup.generate_codes()["codes"]), 10)

	def test_recent_auth_expires_after_window(self):
		from keyless import stepup

		self.sign_in()
		with keyless_settings(step_up_window_minutes=5):
			with patch.object(stepup, "now_ts", return_value=stepup.now_ts() + 6 * 60):
				self.request("keyless.api.backup.generate_codes")
				with self.assertRaises(frappe.PermissionError):
					backup.generate_codes()
			with patch.object(stepup, "now_ts", return_value=stepup.now_ts() + 4 * 60):
				self.assertTrue(backup.generate_codes()["ok"])


class TestStepUpByEmailCode(StepUpCase):
	def test_email_code_restores_access(self):
		from keyless.api import stepup as api

		self.sign_in()
		clear_step_up()
		self.request("keyless.api.stepup.request_email_code")
		api.request_email_code()
		sent = self.mails_to(USER)[-1].kwargs["args"]["otp"]
		self.request("keyless.api.stepup.verify_email_code")
		with self.assertRaises(frappe.AuthenticationError):
			api.verify_email_code("000000" if sent != "000000" else "111111")
		api.verify_email_code(sent)
		self.request("keyless.api.backup.generate_codes")
		self.assertTrue(backup.generate_codes()["ok"])

	def test_email_code_not_offered_when_email_factors_are_refused(self):
		from keyless.api import stepup as api

		self.sign_in()
		clear_step_up()
		with keyless_settings(enable_email_otp=0):
			self.request("keyless.api.stepup.status")
			self.assertNotIn("email", api.status()["methods"])
			self.request("keyless.api.stepup.request_email_code")
			with self.assertRaises(frappe.PermissionError):
				api.request_email_code()


class TestStepUpByPasskey(StepUpCase):
	def _passkey_for(self, user):
		credential_id = bytes_to_base64url(secrets.token_bytes(16))
		handle = frappe.db.get_value("User", user, "keyless_user_handle")
		frappe.get_doc(
			{
				"doctype": "User Passkey",
				"user": user,
				"credential_id": credential_id,
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
				"user_handle": handle,
			}
		).insert(ignore_permissions=True)
		return credential_id, handle

	def _assert_with(self, credential_id, handle):
		from keyless.api import stepup as api

		self.request("keyless.api.stepup.passkey_options")
		options = api.passkey_options()
		cred = {
			"id": credential_id,
			"rawId": credential_id,
			"type": "public-key",
			"response": {"userHandle": bytes_to_base64url(passkey._handle_bytes(handle))},
		}
		self.request("keyless.api.stepup.verify_passkey")
		with (
			patch.object(passkey, "allowed_origins", return_value=["http://localhost"]),
			patch("webauthn.verify_authentication_response", return_value=SimpleNamespace(new_sign_count=1)),
		):
			return api.verify_passkey(cred, options["challenge_id"])

	def test_own_passkey_restores_access(self):
		credential_id, handle = self._passkey_for(USER)
		self.sign_in()
		clear_step_up()
		self._assert_with(credential_id, handle)
		self.request("keyless.api.backup.generate_codes")
		self.assertTrue(backup.generate_codes()["ok"])

	def test_someone_elses_passkey_does_not(self):
		self._passkey_for(USER)  # so step-up by passkey is offered at all
		credential_id, handle = self._passkey_for(OTHER)
		self.sign_in()
		clear_step_up()
		with self.assertRaises(frappe.AuthenticationError):
			self._assert_with(credential_id, handle)
		self.request("keyless.api.backup.generate_codes")
		with self.assertRaises(frappe.PermissionError):
			backup.generate_codes()


class TestNotifications(StepUpCase):
	def _last_notice(self):
		mails = self.mails_to(USER)
		self.assertTrue(mails, "no notification queued")
		kwargs = mails[-1].kwargs
		self.assertFalse(kwargs.get("now"), "notification must be queued, not sent inline")
		return kwargs.get("message") or ""

	def test_passkey_added_lists_active_passkeys(self):
		self.sign_in()
		self.register("Old phone")
		self.register('<b>New</b> laptop')
		message = self._last_notice()
		self.assertIn("Old phone", message)
		self.assertIn("&lt;b&gt;New&lt;/b&gt; laptop", message)
		self.assertNotIn("<b>New</b>", message)

	def test_passkey_removed(self):
		self.sign_in()
		name = self.register("Keep")["name"]
		other = self.register("Remove me")["name"]
		self.mail.reset_mock()
		self.request("keyless.api.passkey.revoke_passkey")
		passkey.revoke_passkey(other)
		message = self._last_notice()
		self.assertIn("Keep", message)
		self.assertIn("removed", message)
		# The first paragraph names the removed passkey; the list after it must not.
		self.assertNotIn("Remove me", re.sub(r"(?s)^<p>.*?</p>", "", message, count=1))
		self.assertTrue(frappe.db.exists("User Passkey", name))

	def test_backup_codes_regenerated(self):
		self.sign_in()
		self.register("Phone")
		self.mail.reset_mock()
		self.request("keyless.api.backup.generate_codes")
		backup.generate_codes()
		self.assertIn("Phone", self._last_notice())


class TestBackupCodesDisabledMessage(StepUpCase):
	def test_disabled_message_is_shown(self):
		self.sign_in()
		with keyless_settings(enable_backup_codes=0):
			self.request("keyless.api.backup.generate_codes")
			with self.assertRaisesRegex(frappe.ValidationError, "Backup codes are disabled"):
				backup.generate_codes()


class TestStepUpWindowSetting(FrappeTestCase):
	def tearDown(self):
		frappe.db.rollback()

	def test_upgraded_site_without_value_gets_default(self):
		doc = frappe.get_single("Keyless Settings")
		doc.step_up_window_minutes = 0
		doc.validate()
		self.assertEqual(doc.step_up_window_minutes, 5)

	def test_negative_window_refused(self):
		doc = frappe.get_single("Keyless Settings")
		doc.step_up_window_minutes = -1
		with self.assertRaises(frappe.ValidationError):
			doc.validate()
