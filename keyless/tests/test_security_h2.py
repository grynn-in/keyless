"""H-2: open redirect after magic-link login."""

from __future__ import annotations

from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import frappe
from frappe.auth import CookieManager
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request

from keyless.api import magic_link
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits
from keyless.tokens import store_magic_key

USER = "kl-h2-user@example.com"
LINK_ON = {"enabled": 1, "enable_magic_link": 1}


class TestMagicLinkRedirect(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER)

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(USER)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.local.response = frappe._dict()

	def _send(self, redirect_to):
		sent = {}
		with (
			keyless_settings(**LINK_ON),
			patch.object(magic_link, "_send_link_mail", side_effect=lambda e, link, m: sent.update(link=link)),
			patch.object(magic_link, "log_event"),
		):
			set_request(method="POST", path="/api/method/keyless.api.magic_link.send_link")
			frappe.local.request_ip = "127.0.0.1"
			magic_link.send_link(USER, redirect_to=redirect_to)
		return sent["link"]

	def _follow(self, **params):
		with keyless_settings(**LINK_ON), patch.object(magic_link, "log_event"):
			set_request(method="GET", path="/api/method/keyless.api.magic_link.login_via_link")
			frappe.local.request_ip = "127.0.0.1"
			frappe.local.cookie_manager = CookieManager()
			frappe.local.response = frappe._dict()
			magic_link.login_via_link(**params)
		return frappe.local.response.get("location") or ""

	@staticmethod
	def _params(link):
		return {k: v[0] for k, v in parse_qs(urlsplit(link).query).items()}

	def _assert_same_site(self, location):
		parts = urlsplit(location)
		self.assertIn(parts.netloc, ("", urlsplit(frappe.utils.get_url()).netloc), location)
		self.assertNotIn("evil", location)

	def test_external_redirect_is_not_carried_in_emailed_link(self):
		for target in ("https://evil.com/x", "//evil.com", "/\\evil.com"):
			with self.subTest(target=target):
				link = self._send(target)
				self.assertNotIn("evil", link)

	def test_tampered_redirect_on_follow_goes_to_default(self):
		for target in ("https://evil.com/x", "//evil.com", "/\\evil.com"):
			with self.subTest(target=target):
				key = frappe.generate_hash(length=32)
				store_magic_key(key, USER, 600)
				location = self._follow(key=key, redirect_to=target)
				self._assert_same_site(location)
				self.assertEqual(frappe.session.user, USER)

	def test_valid_relative_redirect_round_trips(self):
		link = self._send("/app/todo")
		location = self._follow(**self._params(link))
		self.assertTrue(location.endswith("/app/todo"), location)
		self._assert_same_site(location)
