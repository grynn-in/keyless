"""Context flags behind /keyless/login and the /login "Login with Passkey" option."""

from __future__ import annotations

from contextlib import contextmanager

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request
from frappe.website.serve import get_response_content

from keyless.api.settings import public_config
from keyless.www import keyless_login

FACTORS = (
	"enabled",
	"enable_passkeys",
	"enable_email_otp",
	"enable_magic_link",
	"enable_backup_codes",
	"disable_password_login",
	"allow_administrator_password",
)


class TestKeylessLoginPage(FrappeTestCase):
	def setUp(self):
		self.settings = frappe.get_single("Keyless Settings")
		self.saved = {f: self.settings.get(f) for f in FACTORS}
		frappe.set_user("Guest")
		frappe.local.form_dict = frappe._dict()

	def tearDown(self):
		frappe.set_user("Administrator")
		self._apply(**self.saved)

	def _apply(self, **values):
		for key, value in values.items():
			frappe.db.set_single_value("Keyless Settings", key, value)
		frappe.clear_document_cache("Keyless Settings", "Keyless Settings")

	@contextmanager
	def policy(self, **values):
		base = {f: 0 for f in FACTORS}
		base["enabled"] = 1
		base.update(values)
		self._apply(**base)
		yield

	def context(self):
		return keyless_login.get_context(frappe._dict())

	def test_email_otp_is_primary_and_others_are_options(self):
		with self.policy(enable_email_otp=1, enable_magic_link=1, enable_passkeys=1):
			ctx = self.context()
		self.assertEqual(ctx.primary_action, "otp")
		self.assertTrue(ctx.needs_email)
		self.assertTrue(ctx.has_options)
		self.assertEqual(ctx.primary_btn, "btn-default" if ctx.frappe_v16 else "btn-primary")

	def test_passkey_only_hides_email_field(self):
		with self.policy(enable_passkeys=1, disable_password_login=1):
			ctx = self.context()
		self.assertIsNone(ctx.primary_action)
		self.assertFalse(ctx.needs_email)
		self.assertFalse(ctx.has_options)

	def test_password_link_only_when_password_allowed(self):
		with self.policy(enable_email_otp=1):
			ctx = self.context()
		self.assertFalse(ctx.disable_password)
		self.assertTrue(ctx.has_options)
		self.assertEqual(ctx.password_login_url, "/login")
		self.assertEqual(ctx.footer_links, [])

	def test_break_glass_link_when_password_disabled(self):
		with self.policy(enable_email_otp=1, disable_password_login=1, allow_administrator_password=1):
			ctx = self.context()
		self.assertEqual([link["href"] for link in ctx.footer_links], ["/login"])

	def test_recovery_link_when_backup_codes_enabled(self):
		with self.policy(enable_email_otp=1, enable_backup_codes=1, disable_password_login=1):
			ctx = self.context()
		self.assertEqual([link["href"] for link in ctx.footer_links], ["#recovery"])

	def test_page_renders_frappe_login_structure(self):
		with self.policy(enable_email_otp=1, enable_passkeys=1, enable_backup_codes=1):
			set_request(method="GET", path="/keyless/login")
			html = get_response_content("/keyless/login")
		for marker in (
			"for-login",
			"login-content page-card",
			"page-card-head",
			"page-card-actions",
			"btn-login-option",
			'id="keyless-email"',
			'id="keyless-otp-form"',
			'id="keyless-backup-form"',
			'id="keyless-passkey"',
		):
			self.assertIn(marker, html)

	def test_redirect_to_is_kept_on_password_link(self):
		set_request(method="GET", path="/keyless/login?redirect-to=/app/todo")
		frappe.local.form_dict = frappe._dict({"redirect-to": "/app/todo"})
		with self.policy(enable_email_otp=1):
			ctx = self.context()
		self.assertTrue(ctx.redirect_to.endswith("/app/todo"))
		self.assertTrue(ctx.password_login_url.startswith("/login?redirect-to="))

	def test_public_config_drives_standard_login_option(self):
		with self.policy(enable_magic_link=1):
			config = public_config()
		self.assertTrue(config["enabled"])
		self.assertFalse(config["enable_passkeys"])
		self.assertTrue(config["enable_magic_link"])
		self.assertEqual(config["login_route"], "/keyless/login")

	def test_public_config_when_disabled(self):
		with self.policy(enabled=0):
			self.assertEqual(public_config(), {"enabled": False})
