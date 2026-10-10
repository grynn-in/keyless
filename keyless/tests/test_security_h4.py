"""H-4: password-policy gaps (login-name variants, OAuth2 password grant,
require_passkey_for_system_users, Administrator matching, dead settings)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import frappe
import frappe.twofactor
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
		from frappe.oauth import OAuthWebRequestValidator

		if not OAuthWebRequestValidator().validate_grant_type(None, "password", None, None):
			# Frappe 15.121+ dropped the password grant; nothing for Keyless to allow.
			self.skipTest("this Frappe version does not support the OAuth password grant")
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


TFA_USER = "kl-h4-2fa@example.com"
TFA_ROLE = "Keyless H4 2FA Role"


def _wait_for_fresh_totp_window(margin: int = 5) -> None:
	"""Frappe verifies TOTP codes with no tolerance window, so a code made in the last
	seconds of a 30 s step can expire before the request lands. Start a new step."""
	import time

	remaining = 30 - (time.time() % 30)
	if remaining < margin:
		time.sleep(remaining + 0.1)


class TestSystemUserPasswordWithFrappe2FA(FrappeTestCase):
	"""D9-C: with passkeys required for System Users, a System User may still use a
	password if Frappe 2FA applies to them, because Frappe then asks for the second
	factor. The OAuth password grant skips 2FA, so it stays refused."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		if not frappe.db.exists("Role", TFA_ROLE):
			frappe.get_doc({"doctype": "Role", "role_name": TFA_ROLE, "two_factor_auth": 1}).insert()
		make_user(TFA_USER, user_type="System User", roles=(TFA_ROLE,))
		# Authenticator app already set up, so Frappe does not email a setup QR code.
		frappe.twofactor.set_default(TFA_USER + "_otplogin", 1)
		frappe.db.commit()
		cls.saved_system = {
			key: frappe.db.get_single_value("System Settings", key)
			for key in ("enable_two_factor_auth", "two_factor_method")
		}
		_system_settings(enable_two_factor_auth=1, two_factor_method="OTP App")

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		_system_settings(**cls.saved_system)
		frappe.twofactor.clear_default(TFA_USER + "_otplogin")
		frappe.twofactor.clear_default(TFA_USER + "_otpsecret")
		delete_user(TFA_USER)
		frappe.delete_doc("Role", TFA_ROLE, force=True, ignore_permissions=True)
		frappe.db.commit()
		super().tearDownClass()

	def test_password_goes_to_frappe_2fa_and_then_signs_in(self):
		import pyotp

		with keyless_settings(**REQUIRE_PASSKEY):
			client = new_client()
			first = api_login(client, TFA_USER, PASSWORD)
			body = first.json or {}
			self.assertEqual(first.status_code, 200, first.get_data(as_text=True)[:300])
			self.assertIn("tmp_id", body, "Frappe should ask for the second factor")
			self.assertEqual(logged_in_user(client), "Guest", "no session before the second factor")

			secret = frappe.safe_decode(frappe.cache.get(body["tmp_id"] + "_otp_secret"))
			_wait_for_fresh_totp_window()
			http(
				client,
				"post",
				"/api/method/login",
				data={"tmp_id": body["tmp_id"], "otp": pyotp.TOTP(secret).now()},
			)
			self.assertEqual(logged_in_user(client), TFA_USER)

	def test_wrong_second_factor_gives_no_session(self):
		with keyless_settings(**REQUIRE_PASSKEY):
			client = new_client()
			body = api_login(client, TFA_USER, PASSWORD).json or {}
			http(client, "post", "/api/method/login", data={"tmp_id": body.get("tmp_id"), "otp": "000000"})
			self.assertEqual(logged_in_user(client), "Guest")

	def test_oauth_password_grant_still_refused(self):
		oauth = frappe.get_doc(
			{
				"doctype": "OAuth Client",
				"app_name": "kl-h4-2fa-oauth",
				"scopes": "all openid",
				"default_redirect_uri": "http://localhost/cb",
				"redirect_uris": "http://localhost/cb",
				"skip_authorization": 1,
			}
		).insert(ignore_permissions=True)
		frappe.db.commit()
		try:
			with keyless_settings(**REQUIRE_PASSKEY):
				response = http(
					new_client(),
					"post",
					"/api/method/frappe.integrations.oauth2.get_token",
					data={
						"grant_type": "password",
						"username": TFA_USER,
						"password": PASSWORD,
						"client_id": oauth.name,
						"scope": "all",
					},
				)
			self.assertNotIn("access_token", response.get_data(as_text=True))
		finally:
			frappe.db.delete("OAuth Bearer Token", {"client": oauth.name})
			frappe.delete_doc("OAuth Client", oauth.name, force=True, ignore_permissions=True)
			frappe.db.commit()
