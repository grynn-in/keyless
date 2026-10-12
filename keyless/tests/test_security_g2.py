"""G-2: open redirect after sign-in through dot segments in `redirect-to`.

A browser collapses "." and ".." path segments (also when written as %2e), so
"/.//evil.com" is read as "//evil.com": another host. The server must refuse
any target whose normalised path starts with "//".
"""

from __future__ import annotations

from urllib.parse import quote

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless.redirects import safe_redirect
from keyless.tests.security_utils import http, keyless_settings, new_client
from keyless.www import keyless_login

ENABLED = {"enabled": 1, "enable_email_otp": 1, "enable_passkeys": 1}
# Each one keeps the site origin when parsed, but its path normalises to "//evil.com".
DOT_SEGMENT_TARGETS = (
	"/.//evil.com",
	"/..//evil.com",
	"/a/..//evil.com",
	"/a/b/../..//evil.com",
	"/%2e//evil.com",
	"/%2E%2E//evil.com",
	"/.%2e//evil.com",
	"/%2e/%2fevil.com",
	"/%2F%2Fevil.com",
	"/%2f/evil.com",
	"/.//evil.com/app?x=1#y",
)
# Same-site paths that must keep working.
SAFE_TARGETS = (
	"/",
	"/app/foo?x=1#y",
	"/me?tab=1",
	"/./evil.com",
	"/app/../app/todo",
	"/app/sales-invoice/INV%2F2026%2F001",
)


class TestDotSegmentRedirect(FrappeTestCase):
	def test_dot_segment_targets_are_refused(self):
		for target in DOT_SEGMENT_TARGETS:
			with self.subTest(target=target):
				self.assertIsNone(safe_redirect(target))

	def test_same_site_paths_are_kept(self):
		for target in SAFE_TARGETS:
			with self.subTest(target=target):
				self.assertEqual(safe_redirect(target), target)


class TestLoginPageDotSegmentRedirect(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Guest")
		self.addCleanup(frappe.set_user, "Administrator")

	def test_page_context_drops_dot_segment_target(self):
		for target in DOT_SEGMENT_TARGETS:
			with self.subTest(target=target):
				set_request(method="GET", path="/keyless/login")
				frappe.local.form_dict = frappe._dict({"redirect-to": target})
				with keyless_settings(**ENABLED):
					ctx = keyless_login.get_context(frappe._dict())
				self.assertIsNone(ctx.redirect_to)
				self.assertEqual(ctx.password_login_url, "/login")

	def test_rendered_page_has_no_redirect_target(self):
		with keyless_settings(**ENABLED):
			response = http(new_client(), "get", f"/keyless/login?redirect-to={quote('/.//evil.com', safe='')}")
		html = response.get_data(as_text=True)
		self.assertEqual(response.status_code, 200, html[:300])
		self.assertNotIn("data-redirect-to", html)

	def test_rendered_page_keeps_a_same_site_target(self):
		with keyless_settings(**ENABLED):
			response = http(new_client(), "get", f"/keyless/login?redirect-to={quote('/app/todo', safe='')}")
		html = response.get_data(as_text=True)
		self.assertEqual(response.status_code, 200, html[:300])
		self.assertIn('data-redirect-to="/app/todo"', html)
