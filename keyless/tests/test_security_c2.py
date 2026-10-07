"""C-2: "Disable Password Login" must hold on every Frappe login path."""

from __future__ import annotations

import frappe
from frappe.auth import CookieManager
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless.auth import issue_session
from keyless.tests.security_utils import (
	PASSWORD,
	delete_user,
	http,
	keyless_settings,
	logged_in_user,
	make_user,
	new_client,
)

USER = "kl-c2-user@example.com"
ADMIN_PASSWORD_KEY = "admin_password"

BLOCK_SITE = {"enabled": 1, "disable_password_login": 1, "allow_administrator_password": 1}
BLOCK_PER_USER = {"enabled": 1, "disable_password_login": 0, "allow_administrator_password": 1}
POLICY_OFF = {"enabled": 1, "disable_password_login": 0, "allow_administrator_password": 1}


def ping_login(client, usr, pwd):
	return http(client, "post", "/api/method/ping", data={"cmd": "login", "usr": usr, "pwd": pwd})


def api_login(client, usr, pwd):
	return http(client, "post", "/api/method/login", data={"usr": usr, "pwd": pwd})


LOGIN_PATHS = {"cmd=login on /api/method/ping": ping_login, "/api/method/login": api_login}


class PasswordPolicyCase(FrappeTestCase):
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

	def set_passwordless_only(self, value: int):
		frappe.db.set_value("User", USER, "keyless_passwordless_only", value)
		frappe.db.commit()
		frappe.clear_cache(user=USER)

	def tearDown(self):
		self.set_passwordless_only(0)
		frappe.set_user("Administrator")

	def assert_no_session(self, login, usr=USER, pwd=PASSWORD):
		client = new_client()
		response = login(client, usr, pwd)
		self.assertEqual(logged_in_user(client), "Guest", response.get_data(as_text=True)[:300])
		return response


class TestPasswordLoginBlocked(PasswordPolicyCase):
	def test_site_wide_block_on_every_path(self):
		with keyless_settings(**BLOCK_SITE):
			for label, login in LOGIN_PATHS.items():
				with self.subTest(path=label):
					self.assert_no_session(login)

	def test_per_user_block_on_every_path(self):
		self.set_passwordless_only(1)
		with keyless_settings(**BLOCK_PER_USER):
			for label, login in LOGIN_PATHS.items():
				with self.subTest(path=label):
					self.assert_no_session(login)

	def test_blocked_correct_and_wrong_password_are_indistinguishable(self):
		for label, policy in (("site-wide", BLOCK_SITE), ("per-user", BLOCK_PER_USER)):
			self.set_passwordless_only(1 if label == "per-user" else 0)
			with keyless_settings(**policy):
				for path, login in LOGIN_PATHS.items():
					with self.subTest(policy=label, path=path):
						right = self.assert_no_session(login, pwd=PASSWORD)
						wrong = self.assert_no_session(login, pwd=PASSWORD + "-wrong")
						self.assertEqual(right.status_code, wrong.status_code)
						self.assertEqual((right.json or {}).get("message"), (wrong.json or {}).get("message"))

	def test_password_login_works_when_policy_off(self):
		with keyless_settings(**POLICY_OFF):
			for label, login in LOGIN_PATHS.items():
				with self.subTest(path=label):
					client = new_client()
					login(client, USER, PASSWORD)
					self.assertEqual(logged_in_user(client), USER)


class TestAdministratorBreakGlass(PasswordPolicyCase):
	def setUp(self):
		self.admin_password = frappe.conf.get(ADMIN_PASSWORD_KEY)
		if not self.admin_password:
			self.skipTest("site_config has no admin_password; cannot exercise break-glass")

	def test_break_glass_allowed_when_enabled(self):
		with keyless_settings(**BLOCK_SITE):
			client = new_client()
			api_login(client, "Administrator", self.admin_password)
			self.assertEqual(logged_in_user(client), "Administrator")

	def test_break_glass_blocked_when_disabled(self):
		with keyless_settings(**{**BLOCK_SITE, "allow_administrator_password": 0}):
			for label, login in LOGIN_PATHS.items():
				with self.subTest(path=label):
					self.assert_no_session(login, usr="Administrator", pwd=self.admin_password)


class TestKeylessFactorsStillWork(PasswordPolicyCase):
	"""issue_session is the Keyless path; it must not be caught by the password block."""

	def test_issue_session_for_each_factor_under_block(self):
		self.set_passwordless_only(1)
		with keyless_settings(**BLOCK_SITE):
			for method in ("passkey", "email_otp", "magic_link", "backup_code"):
				with self.subTest(method=method):
					set_request(path="/api/method/keyless.api.otp.verify_otp", method="POST")
					frappe.local.cookie_manager = CookieManager()
					issue_session(USER, method=method)
					self.assertEqual(frappe.session.user, USER)
					self.assertFalse(frappe.flags.get("keyless_login"), "flag must not leak past issue_session")
