"""H-4: password-policy gaps (login-name variants, OAuth2 password grant,
require_passkey_for_system_users, Administrator matching, dead settings)."""

from __future__ import annotations

import json
import re
from pathlib import Path

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

SYS_USER = "kl-h4-sys@example.com"
WEB_USER = "kl-h4-web@example.com"
USERNAME = "klh4sys"
MOBILE = "9990001234"

BLOCK_PER_USER = {"enabled": 1, "disable_password_login": 0, "allow_administrator_password": 1}
BLOCK_SITE = {"enabled": 1, "disable_password_login": 1, "allow_administrator_password": 1}
REQUIRE_PASSKEY = {
	"enabled": 1,
	"disable_password_login": 0,
	"allow_administrator_password": 1,
	"require_passkey_for_system_users": 1,
}


def api_login(client, usr, pwd):
	return http(client, "post", "/api/method/login", data={"usr": usr, "pwd": pwd})


def _system_settings(**values):
	for key, value in values.items():
		frappe.db.set_single_value("System Settings", key, value)
	frappe.db.commit()
	frappe.clear_cache()


class H4Case(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(
			SYS_USER,
			user_type="System User",
			roles=("System Manager",),
			username=USERNAME,
			mobile_no=MOBILE,
		)
		make_user(WEB_USER)
		cls.saved_system = {
			key: frappe.db.get_single_value("System Settings", key)
			for key in ("allow_login_using_user_name", "allow_login_using_mobile_number")
		}

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		_system_settings(**cls.saved_system)
		delete_user(SYS_USER)
		delete_user(WEB_USER)
		super().tearDownClass()

	def tearDown(self):
		frappe.db.set_value("User", SYS_USER, "keyless_passwordless_only", 0)
		frappe.db.commit()
		frappe.set_user("Administrator")


class TestLoginNameVariants(H4Case):
	"""H-4a: the per-user block must follow the resolved user, not the typed name."""

	def test_passwordless_only_user_blocked_by_username_and_mobile(self):
		_system_settings(allow_login_using_user_name=1, allow_login_using_mobile_number=1)
		frappe.db.set_value("User", SYS_USER, "keyless_passwordless_only", 1)
		frappe.db.commit()
		with keyless_settings(**BLOCK_PER_USER):
			for login_name in (USERNAME, MOBILE, SYS_USER.upper()):
				with self.subTest(login_name=login_name):
					client = new_client()
					api_login(client, login_name, PASSWORD)
					self.assertEqual(logged_in_user(client), "Guest")

	def test_username_login_still_works_without_block(self):
		_system_settings(allow_login_using_user_name=1)
		with keyless_settings(**BLOCK_PER_USER):
			client = new_client()
			api_login(client, USERNAME, PASSWORD)
			self.assertEqual(logged_in_user(client), SYS_USER)


class TestOAuthPasswordGrant(H4Case):
	"""H-4b / D4: the OAuth2 password grant is blocked when passwords are disabled."""

	def setUp(self):
		client = frappe.get_doc(
			{
				"doctype": "OAuth Client",
				"app_name": "kl-h4-oauth",
				"scopes": "all openid",
				"default_redirect_uri": "http://localhost/cb",
				"redirect_uris": "http://localhost/cb",
				"skip_authorization": 1,
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()
		self.client_id = client.name
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		frappe.db.delete("OAuth Bearer Token", {"client": self.client_id})
		frappe.delete_doc("OAuth Client", self.client_id, force=True, ignore_permissions=True)
		frappe.db.commit()

	def _password_grant(self, username, password):
		return http(
			new_client(),
			"post",
			"/api/method/frappe.integrations.oauth2.get_token",
			data={
				"grant_type": "password",
				"username": username,
				"password": password,
				"client_id": self.client_id,
				"scope": "all",
			},
		)

	def test_password_grant_refused_when_password_disabled(self):
		with keyless_settings(**BLOCK_SITE):
			response = self._password_grant(SYS_USER, PASSWORD)
		self.assertNotIn("access_token", response.get_data(as_text=True))
		self.assertGreaterEqual(response.status_code, 400)
		self.assertFalse(frappe.db.exists("OAuth Bearer Token", {"client": self.client_id}))

	def test_password_grant_refused_on_every_route(self):
		data = {
			"grant_type": "password",
			"username": SYS_USER,
			"password": PASSWORD,
			"client_id": self.client_id,
			"scope": "all",
		}
		routes = {
			"/api/v1/method/frappe.integrations.oauth2.get_token": data,
			"/api/v2/method/frappe.integrations.oauth2.get_token": data,
			"/": {**data, "cmd": "frappe.integrations.oauth2.get_token"},
		}
		with keyless_settings(**BLOCK_SITE):
			for path, form in routes.items():
				with self.subTest(path=path):
					response = http(new_client(), "post", path, data=form)
					self.assertNotIn("access_token", response.get_data(as_text=True))
		self.assertFalse(frappe.db.exists("OAuth Bearer Token", {"client": self.client_id}))

	def test_password_grant_refused_for_passwordless_only_user(self):
		frappe.db.set_value("User", SYS_USER, "keyless_passwordless_only", 1)
		frappe.db.commit()
		with keyless_settings(**BLOCK_PER_USER):
			response = self._password_grant(SYS_USER, PASSWORD)
		self.assertNotIn("access_token", response.get_data(as_text=True))

	def test_password_grant_works_when_policy_off(self):
		with keyless_settings(**BLOCK_PER_USER):
			response = self._password_grant(SYS_USER, PASSWORD)
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		self.assertIn("access_token", response.json)


class TestRequirePasskeyForSystemUsers(H4Case):
	"""H-4c / D5: System Users may not sign in with email OTP or magic link."""

	def _issue(self, user, method):
		set_request(path="/api/method/keyless.api.otp.verify_otp", method="POST")
		frappe.local.cookie_manager = CookieManager()
		issue_session(user, method=method)
		return frappe.session.user

	def test_email_factors_refused_for_system_user(self):
		with keyless_settings(**REQUIRE_PASSKEY):
			for method in ("email_otp", "magic_link"):
				with self.subTest(method=method):
					with self.assertRaises(frappe.AuthenticationError):
						self._issue(SYS_USER, method)
					self.assertNotEqual(frappe.session.user, SYS_USER)

	def test_passkey_and_backup_code_allowed_for_system_user(self):
		with keyless_settings(**REQUIRE_PASSKEY):
			for method in ("passkey", "backup_code"):
				with self.subTest(method=method):
					self.assertEqual(self._issue(SYS_USER, method), SYS_USER)

	def test_website_user_unaffected(self):
		with keyless_settings(**REQUIRE_PASSKEY):
			self.assertEqual(self._issue(WEB_USER, "email_otp"), WEB_USER)

	def test_password_refused_for_system_user(self):
		with keyless_settings(**REQUIRE_PASSKEY):
			client = new_client()
			api_login(client, SYS_USER, PASSWORD)
			self.assertEqual(logged_in_user(client), "Guest")

	def test_password_allowed_for_website_user(self):
		with keyless_settings(**REQUIRE_PASSKEY):
			client = new_client()
			api_login(client, WEB_USER, PASSWORD)
			self.assertEqual(logged_in_user(client), WEB_USER)

	def test_setting_off_allows_email_factors(self):
		with keyless_settings(**{**REQUIRE_PASSKEY, "require_passkey_for_system_users": 0}):
			self.assertEqual(self._issue(SYS_USER, "email_otp"), SYS_USER)


class TestAdministratorMatching(H4Case):
	"""H-4d: the Administrator exception follows the resolved user, not the typed string."""

	def setUp(self):
		self.admin_password = frappe.conf.get("admin_password")
		if not self.admin_password:
			self.skipTest("site_config has no admin_password")

	def test_exception_applies_to_any_spelling(self):
		with keyless_settings(**BLOCK_SITE):
			for typed in ("Administrator", "administrator", "ADMINISTRATOR"):
				with self.subTest(typed=typed):
					client = new_client()
					api_login(client, typed, self.admin_password)
					self.assertEqual(logged_in_user(client), "Administrator")

	def test_block_applies_to_any_spelling(self):
		with keyless_settings(**{**BLOCK_SITE, "allow_administrator_password": 0}):
			for typed in ("Administrator", "administrator", "ADMINISTRATOR"):
				with self.subTest(typed=typed):
					client = new_client()
					api_login(client, typed, self.admin_password)
					self.assertEqual(logged_in_user(client), "Guest")


class TestNoDeadSettings(FrappeTestCase):
	"""H-4c: every Keyless Settings field is read somewhere in the app."""

	LAYOUT = {"Section Break", "Column Break", "Tab Break", "HTML", "Heading"}

	def test_every_setting_is_read(self):
		app = Path(frappe.get_app_path("keyless"))
		meta = json.loads((app / "keyless/doctype/keyless_settings/keyless_settings.json").read_text())
		# Type stubs and install defaults only write or describe fields; they are not reads.
		not_reads = {"keyless_settings.py", "install.py"}
		sources = "\n".join(
			p.read_text()
			for p in app.rglob("*")
			if p.suffix in {".py", ".js", ".html"}
			and "tests" not in p.parts
			and p.name not in not_reads
			and p.is_file()
		)
		unread = [
			f["fieldname"]
			for f in meta["fields"]
			if f["fieldtype"] not in self.LAYOUT and not re.search(rf"\b{f['fieldname']}\b", sources)
		]
		self.assertEqual(unread, [])

	def test_no_reads_of_missing_settings(self):
		app = Path(frappe.get_app_path("keyless"))
		self.assertNotIn("deny_password_sessions", (app / "auth.py").read_text())
