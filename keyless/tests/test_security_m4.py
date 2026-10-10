"""M-4: opening a magic link (GET) must not sign in or use up the link; only the
confirmation POST does (D8, option C: GET->POST now, browser binding later)."""

from __future__ import annotations

import re

import frappe
from frappe.tests.utils import FrappeTestCase

from keyless.tests.security_utils import (
	delete_user,
	http,
	keyless_settings,
	logged_in_user,
	make_user,
	new_client,
	reset_rate_limits,
)
from keyless.tokens import MAGIC_CACHE_PREFIX, store_magic_key


def link_exists(key: str) -> bool:
	# Raw Redis: the request runs on another thread, so this process's local cache is stale.
	return frappe.cache.get(frappe.cache.make_key(MAGIC_CACHE_PREFIX + key)) is not None

USER = "kl-m4-user@example.com"
LINK_ON = {"enabled": 1, "enable_magic_link": 1, "rate_limit_per_hour": 50}
PATH = "/api/method/keyless.api.magic_link.login_via_link"


class TestMagicLinkConfirmation(FrappeTestCase):
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
		self.key = frappe.generate_hash(length=32)
		store_magic_key(self.key, USER, 600, redirect_to="/app/todo")
		self.settings = keyless_settings(**LINK_ON)
		self.settings.__enter__()
		self.addCleanup(self.settings.__exit__, None, None, None)

	def test_get_shows_confirmation_without_signing_in(self):
		client = new_client()
		response = http(client, "get", f"{PATH}?key={self.key}")
		html = response.get_data(as_text=True)
		self.assertEqual(response.status_code, 200, html[:300])
		self.assertRegex(html, r'(?is)<form[^>]+method="post"')
		self.assertIn(f'value="{self.key}"', html)
		self.assertEqual(logged_in_user(client), "Guest")
		self.assertTrue(link_exists(self.key), "GET must not use up the link")

	def test_repeated_gets_do_not_burn_the_link(self):
		for _ in range(3):  # e.g. a mail scanner, a preview, then the person
			http(new_client(), "get", f"{PATH}?key={self.key}")
		self.assertTrue(link_exists(self.key))

	def test_post_signs_in_once(self):
		client = new_client()
		response = http(client, "post", PATH, data={"key": self.key})
		self.assertIn(response.status_code, (301, 302, 303), response.get_data(as_text=True)[:300])
		self.assertTrue(response.headers["Location"].endswith("/app/todo"))
		self.assertEqual(logged_in_user(client), USER)

		again = new_client()
		http(again, "post", PATH, data={"key": self.key})
		self.assertEqual(logged_in_user(again), "Guest")

	def test_confirmation_works_for_a_signed_in_visitor(self):
		"""A browser that already has a session (and so a CSRF token) can still confirm."""
		client = new_client()
		other = frappe.generate_hash(length=32)
		store_magic_key(other, USER, 600)
		http(client, "post", PATH, data={"key": other})
		self.assertEqual(logged_in_user(client), USER)

		page = http(client, "get", f"{PATH}?key={self.key}").get_data(as_text=True)
		form = dict(re.findall(r'name="([^"]+)" value="([^"]*)"', page))
		self.assertEqual(form.get("key"), self.key)
		response = http(client, "post", PATH, data=form)
		self.assertIn(response.status_code, (301, 302, 303), response.get_data(as_text=True)[:300])

	def test_invalid_key_on_get_says_so_without_a_form(self):
		html = http(new_client(), "get", f"{PATH}?key=not-a-real-key").get_data(as_text=True)
		self.assertIn("invalid or has expired", html)
		self.assertNotRegex(html, r'(?is)<form[^>]+method="post"')


class TestOneShotUnderConcurrency(FrappeTestCase):
	def test_parallel_consumes_yield_one_payload(self):
		import threading

		from keyless.tokens import consume_magic_link

		key = frappe.generate_hash(length=32)
		store_magic_key(key, USER, 600)
		site = frappe.local.site
		results = []
		start = threading.Barrier(8)

		def take():
			frappe.init(site=site)
			frappe.connect()
			try:
				start.wait()
				results.append(consume_magic_link(key))
			finally:
				frappe.destroy()

		threads = [threading.Thread(target=take) for _ in range(8)]
		for t in threads:
			t.start()
		for t in threads:
			t.join()
		self.assertEqual(len([r for r in results if r]), 1)
