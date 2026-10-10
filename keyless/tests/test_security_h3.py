"""H-3: email factors bypass Frappe 2FA; every factor was on by default."""

from __future__ import annotations

import frappe
from frappe.auth import CookieManager
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless import install
from keyless.auth import issue_session
from keyless.settings import get_settings, is_enabled
from keyless.tests.security_utils import delete_user, keyless_settings, make_user

TFA_USER = "kl-h3-2fa@example.com"
PLAIN_USER = "kl-h3-plain@example.com"
TFA_ROLE = "Keyless H3 2FA Role"
FACTORS = ("enable_passkeys", "enable_magic_link", "enable_email_otp", "enable_backup_codes")
ALL_ON = {"enabled": 1, **{f: 1 for f in FACTORS}}


class TestInstallDefaults(FrappeTestCase):
	"""D2: a fresh install leaves Keyless fully disabled."""

	def tearDown(self):
		frappe.db.rollback()
		frappe.clear_document_cache("Keyless Settings", "Keyless Settings")

	def _fresh_install(self):
		frappe.db.delete("Singles", {"doctype": "Keyless Settings"})
		frappe.clear_document_cache("Keyless Settings", "Keyless Settings")
		install.after_install()
		frappe.clear_document_cache("Keyless Settings", "Keyless Settings")
		return get_settings()

	def test_fresh_install_is_fully_disabled(self):
		settings = self._fresh_install()
		self.assertFalse(is_enabled())
		self.assertEqual(settings.enabled, 0)
		for field in FACTORS:
			with self.subTest(field=field):
				self.assertEqual(settings.get(field), 0)

	def test_field_defaults_match(self):
		doc = frappe.new_doc("Keyless Settings")
		self.assertEqual(doc.enabled, 0)
		for field in FACTORS:
			with self.subTest(field=field):
				self.assertEqual(doc.get(field), 0)

	def test_existing_settings_survive_migrate(self):
		frappe.db.set_single_value("Keyless Settings", {"enabled": 1, "enable_email_otp": 1})
		install.after_migrate()
		frappe.clear_document_cache("Keyless Settings", "Keyless Settings")
		self.assertEqual(get_settings().enabled, 1)
		self.assertEqual(get_settings().enable_email_otp, 1)


class TestFrappe2FA(FrappeTestCase):
	"""D3: email OTP and magic link are refused for users Frappe 2FA applies to."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		if not frappe.db.exists("Role", TFA_ROLE):
			frappe.get_doc({"doctype": "Role", "role_name": TFA_ROLE, "two_factor_auth": 1}).insert()
		make_user(TFA_USER, roles=(TFA_ROLE,))
		make_user(PLAIN_USER)
		cls.saved_2fa = frappe.db.get_single_value("System Settings", "enable_two_factor_auth")
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 1)
		frappe.db.commit()

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", cls.saved_2fa)
		delete_user(TFA_USER)
		delete_user(PLAIN_USER)
		frappe.delete_doc("Role", TFA_ROLE, force=True, ignore_permissions=True)
		frappe.db.commit()
		super().tearDownClass()

	def tearDown(self):
		frappe.set_user("Administrator")

	def _issue(self, user, method):
		set_request(path="/api/method/keyless.api.otp.verify_otp", method="POST")
		frappe.local.cookie_manager = CookieManager()
		issue_session(user, method=method)
		return frappe.session.user

	def test_email_factors_refused_for_2fa_user(self):
		with keyless_settings(**ALL_ON):
			for method in ("email_otp", "magic_link"):
				with self.subTest(method=method):
					with self.assertRaises(frappe.AuthenticationError):
						self._issue(TFA_USER, method)
					self.assertNotEqual(frappe.session.user, TFA_USER)

	def test_passkey_allowed_for_2fa_user(self):
		with keyless_settings(**ALL_ON):
			self.assertEqual(self._issue(TFA_USER, "passkey"), TFA_USER)

	def test_email_factors_work_for_user_without_2fa(self):
		with keyless_settings(**ALL_ON):
			for method in ("email_otp", "magic_link"):
				with self.subTest(method=method):
					self.assertEqual(self._issue(PLAIN_USER, method), PLAIN_USER)
