"""Findings from the code and security reviews of PR #7."""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import frappe
from frappe.auth import LoginManager
from frappe.tests.utils import FrappeTestCase
from frappe.utils import CallbackManager, add_days, set_request, today

from keyless.api import common, otp, passkey
from keyless.tests.security_utils import (
	PASSWORD,
	delete_user,
	http,
	keyless_settings,
	logged_in_user,
	make_user,
	new_client,
	reset_rate_limits,
)

USER = "kl-review-user@example.com"
NEW_PASSWORD = "Kl-Review-New-Pass-5518!"
POLICY = {"enabled": 1, "disable_password_login": 0, "allow_administrator_password": 1}
BLOCK_SITE = {**POLICY, "disable_password_login": 1, "enable_passkeys": 1}
REQUIRE_PASSKEY = {**POLICY, "require_passkey_for_system_users": 1, "enable_passkeys": 1}


def api_login(client, pwd):
	return http(client, "post", "/api/method/login", data={"usr": USER, "pwd": pwd})


class ReviewCase(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER, user_type="System User", roles=("System Manager",))

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(USER)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		frappe.set_user("Administrator")
		from frappe.utils.password import update_password

		update_password(USER, PASSWORD)
		frappe.db.set_value("User", USER, {"keyless_passwordless_only": 0, "last_password_reset_date": today()})
		frappe.db.commit()

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.set_value("User", USER, "keyless_passwordless_only", 0)
		frappe.db.commit()

	def set_passwordless_only(self):
		frappe.db.set_value("User", USER, "keyless_passwordless_only", 1)
		frappe.db.commit()
		frappe.clear_cache(user=USER)


class TestBeforeLoginOnFrappe15(ReviewCase):
	def test_login_runs_before_login(self):
		source = inspect.getsource(LoginManager.login)
		patched = getattr(LoginManager.login, "_keyless_before_login", False)
		self.assertTrue(patched or 'run_trigger("before_login")' in source)

	def test_expired_password_gets_no_reset_link_when_blocked(self):
		# The expired-password branch answers a right password with a live reset
		# link before on_login runs; before_login must refuse first.
		original = frappe.db.get_single_value("System Settings", "force_user_to_reset_password")
		frappe.db.set_single_value("System Settings", "force_user_to_reset_password", 1)
		frappe.db.set_value("User", USER, "last_password_reset_date", add_days(today(), -30))
		frappe.db.commit()
		self.set_passwordless_only()
		try:
			with keyless_settings(**POLICY):
				right = api_login(new_client(), PASSWORD)
				wrong = api_login(new_client(), PASSWORD + "-wrong")
		finally:
			frappe.db.set_single_value("System Settings", "force_user_to_reset_password", original or 0)
			frappe.db.commit()
		body = right.get_data(as_text=True)
		self.assertNotIn("update-password", body)
		self.assertNotIn("Password Reset", body)
		self.assertEqual(right.status_code, wrong.status_code)
		self.assertEqual((right.json or {}).get("message"), (wrong.json or {}).get("message"))

	def test_on_login_fallback_still_blocks_without_the_backport(self):
		login = LoginManager.login
		unpatched = getattr(login, "__wrapped__", login) if getattr(login, "_keyless_before_login", False) else login
		self.set_passwordless_only()
		with keyless_settings(**POLICY), patch.object(LoginManager, "login", unpatched):
			client = new_client()
			api_login(client, PASSWORD)
		self.assertEqual(logged_in_user(client), "Guest")


class TestMailedSecretLogins(ReviewCase):
	def reset_key(self) -> str:
		link = frappe.get_doc("User", USER)._reset_password(send_email=False)
		frappe.db.commit()
		return parse_qs(urlsplit(link).query)["key"][0]

	def redeem(self, key):
		client = new_client()
		response = http(
			client,
			"post",
			"/api/method/frappe.core.doctype.user.user.update_password",
			data={"new_password": NEW_PASSWORD, "key": key},
		)
		return client, response

	def test_reset_link_gives_no_session_when_passwords_are_blocked(self):
		for label, settings in (("site-wide", BLOCK_SITE), ("per-user", POLICY)):
			with self.subTest(policy=label):
				if label == "per-user":
					self.set_passwordless_only()
				with keyless_settings(**settings):
					client, response = self.redeem(self.reset_key())
				self.assertEqual(logged_in_user(client), "Guest", response.get_data(as_text=True)[:300])

	def test_reset_link_gives_no_session_to_system_user_needing_a_passkey(self):
		with keyless_settings(**REQUIRE_PASSKEY):
			client, response = self.redeem(self.reset_key())
		self.assertEqual(logged_in_user(client), "Guest", response.get_data(as_text=True)[:300])

	def test_reset_link_still_signs_in_when_policy_allows(self):
		with keyless_settings(**POLICY):
			client, response = self.redeem(self.reset_key())
		self.assertEqual(logged_in_user(client), USER, response.get_data(as_text=True)[:300])


class TestStepUpUserHandle(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		self.handle = frappe.db.get_value("User", "Administrator", "keyless_user_handle")
		if not self.handle:
			self.skipTest("Administrator has no WebAuthn user handle")
		self.key = SimpleNamespace(user="Administrator", user_handle=self.handle)

	def test_missing_handle_refused_for_sign_in(self):
		cred = {"response": {}}
		self.assertFalse(passkey._user_handle_matches(cred, self.key))

	def test_missing_handle_accepted_for_step_up(self):
		cred = {"response": {}}
		self.assertTrue(passkey._user_handle_matches(cred, self.key, required=False))

	def test_wrong_handle_refused_for_step_up(self):
		cred = {"response": {"userHandle": "AAAA"}}
		self.assertFalse(passkey._user_handle_matches(cred, self.key, required=False))


class TestMailWorkAfterResponse(ReviewCase):
	def test_code_is_created_only_after_the_response(self):
		set_request(method="POST", path="/api/method/keyless.api.otp.request_otp")
		frappe.local.request.after_response = callbacks = CallbackManager()
		frappe.local.request_ip = "127.0.0.1"
		frappe.local.form_dict = frappe._dict(cmd="keyless.api.otp.request_otp", email=USER)
		settings = {**POLICY, "enable_email_otp": 1, "hide_user_enumeration": 1, "require_passkey_for_system_users": 0}
		with keyless_settings(**settings), patch("frappe.sendmail") as sendmail:
			for email in (USER, "kl-review-nobody@example.com"):
				self.assertEqual(otp.request_otp(email)["ok"], True)
			sendmail.assert_not_called()
			callbacks.run()
			self.assertEqual(sendmail.call_count, 1)
			self.assertEqual(sendmail.call_args.kwargs["recipients"], USER)


class TestPasskeyOriginWarning(FrappeTestCase):
	def test_warns_when_no_origin_is_https(self):
		with patch.object(common, "site_origin", return_value="http://erp.example.com"):
			self.assertIn("http://erp.example.com", common.passkey_origin_warning(""))
			self.assertIsNone(common.passkey_origin_warning("https://erp.example.com"))
		with patch.object(common, "site_origin", return_value="https://erp.example.com"):
			self.assertIsNone(common.passkey_origin_warning(""))

	def test_local_development_is_not_warned(self):
		with patch.object(common, "site_origin", return_value="http://localhost:8000"):
			self.assertIsNone(common.passkey_origin_warning(""))
