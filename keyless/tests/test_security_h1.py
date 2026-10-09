"""H-1: reflected XSS on /keyless/login and unvalidated redirect targets."""

from __future__ import annotations

from unittest.mock import patch
from urllib.parse import quote

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request
from frappe.website.serve import get_response_content

from keyless.tests.security_utils import http, keyless_settings, new_client
from keyless.www import keyless_login

PAYLOAD = '/x"><script>alert(1)</script>'
ENABLED = {"enabled": 1, "enable_email_otp": 1, "enable_passkeys": 1}
HOSTILE_TARGETS = (
	"//evil.com",
	"https://evil.com",
	"http://evil.com/app",
	"/\\evil.com",
	"\\\\evil.com",
	"/\t/evil.com",
	"javascript:alert(1)",
	"evil.com",
	" //evil.com",
)


class TestLoginPageXSS(FrappeTestCase):
	def test_redirect_payload_is_not_reflected_unescaped(self):
		with keyless_settings(**ENABLED):
			response = http(new_client(), "get", f"/keyless/login?redirect-to={quote(PAYLOAD, safe='')}")
		html = response.get_data(as_text=True)
		self.assertEqual(response.status_code, 200, html[:300])
		self.assertNotIn("<script>alert(1)</script>", html)
		self.assertNotIn('"><script', html)

	def test_logo_and_app_name_are_escaped(self):
		hostile = 'Acme"><img src=x onerror=alert(2)>'
		original = frappe.db.get_single_value("Website Settings", "app_name")
		frappe.db.set_single_value("Website Settings", "app_name", hostile)
		try:
			with (
				keyless_settings(**ENABLED),
				patch.object(keyless_login, "get_app_logo", return_value='/logo.png"><svg onload=alert(3)>'),
			):
				set_request(method="GET", path="/keyless/login")
				frappe.local.form_dict = frappe._dict()
				frappe.set_user("Guest")
				html = get_response_content("/keyless/login")
		finally:
			frappe.set_user("Administrator")
			# keyless_settings() commits, which also commits the hostile app_name,
			# so a rollback alone would leave it on the site.
			frappe.db.set_single_value("Website Settings", "app_name", original)
			frappe.db.commit()
		self.assertNotIn("<img src=x onerror=alert(2)>", html)
		self.assertNotIn("<svg onload=alert(3)>", html)
		self.assertIn("&lt;img src=x onerror=alert(2)&gt;", html)


class TestRedirectValidation(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Guest")
		self.addCleanup(frappe.set_user, "Administrator")

	def _context(self, target):
		set_request(method="GET", path="/keyless/login")
		frappe.local.form_dict = frappe._dict({"redirect-to": target})
		with keyless_settings(**ENABLED):
			return keyless_login.get_context(frappe._dict())

	def test_hostile_targets_fall_back_to_default(self):
		for target in HOSTILE_TARGETS:
			with self.subTest(target=target):
				ctx = self._context(target)
				self.assertIsNone(ctx.redirect_to)
				self.assertEqual(ctx.password_login_url, "/login")

	def test_valid_relative_path_is_kept(self):
		ctx = self._context("/app/foo?x=1#y")
		self.assertEqual(ctx.redirect_to, "/app/foo?x=1#y")
		self.assertEqual(ctx.password_login_url, "/login?redirect-to=%2Fapp%2Ffoo%3Fx%3D1%23y")

	def test_helper(self):
		from keyless.redirects import safe_redirect

		for target in HOSTILE_TARGETS + (None, "", "app/foo"):
			with self.subTest(target=target):
				self.assertIsNone(safe_redirect(target))
		for target in ("/", "/app/foo", "/me?tab=1"):
			with self.subTest(target=target):
				self.assertEqual(safe_redirect(target), target)
