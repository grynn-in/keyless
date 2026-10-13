"""G-3 (audit 2026-10-12): the magic-link browser cookie must live for the link's
life whatever the site's time zone.

The cookie's expiry used to be a naive date-time in the site's time zone, which the
browser reads as UTC. West of UTC the cookie arrived already expired, so magic links
never worked; east of UTC it outlived the link by hours."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from keyless.api import magic_link
from keyless.tests.security_utils import (
	delete_user,
	http,
	keyless_settings,
	logged_in_user,
	make_user,
	new_client,
	reset_rate_limits,
)

USER = "kl-g3-user@example.com"
EXPIRY_MIN = 10
LINK_ON = {
	"enabled": 1,
	"enable_magic_link": 1,
	"rate_limit_per_hour": 50,
	"magic_link_expiry_minutes": EXPIRY_MIN,
}
SEND = "/api/method/keyless.api.magic_link.send_link"
LOGIN = "/api/method/keyless.api.magic_link.login_via_link"
ZONES = ("America/New_York", "UTC", "Asia/Kolkata")


def _set_time_zone(zone: str) -> None:
	frappe.db.set_single_value("System Settings", "time_zone", zone)
	frappe.db.commit()
	frappe.clear_document_cache("System Settings", "System Settings")
	frappe.clear_cache(doctype="System Settings")
	frappe.local.system_settings = None


def _browser_cookie_header(response) -> str:
	return next(h for h in response.headers.getlist("Set-Cookie") if h.startswith(magic_link.BROWSER_COOKIE + "="))


def _lifetime_seconds(header: str, sent_at: datetime) -> float:
	"""How long a browser keeps the cookie: Max-Age wins over Expires (RFC 6265 5.3)."""
	max_age = re.search(r"(?i);\s*Max-Age=(-?\d+)", header)
	if max_age:
		return float(max_age.group(1))
	expires = re.search(r"(?i);\s*Expires=([^;]+)", header)
	if not expires:
		return float("inf")  # a session cookie
	return (parsedate_to_datetime(expires.group(1)) - sent_at).total_seconds()


class TestBrowserCookieLifetime(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER)
		cls.saved_zone = frappe.db.get_single_value("System Settings", "time_zone")

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		_set_time_zone(cls.saved_zone)
		delete_user(USER)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		self.settings = keyless_settings(**LINK_ON)
		self.settings.__enter__()
		self.addCleanup(self.settings.__exit__, None, None, None)
		self.addCleanup(_set_time_zone, self.saved_zone)

	def _send(self, client, sent: dict | None = None):
		def capture(email, link, minutes):
			if sent is not None:
				sent["link"] = link

		with patch.object(magic_link, "_send_link_mail", side_effect=capture):
			sent_at = datetime.now(timezone.utc)
			response = http(client, "post", SEND, data={"email": USER})
		self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
		return response, sent_at

	def test_cookie_lives_for_the_link_in_every_time_zone(self):
		for zone in ZONES:
			with self.subTest(zone=zone):
				_set_time_zone(zone)
				response, sent_at = self._send(new_client())
				header = _browser_cookie_header(response)
				lifetime = _lifetime_seconds(header, sent_at)
				self.assertAlmostEqual(lifetime, EXPIRY_MIN * 60, delta=60, msg=header)

				# Expires (for old browsers) must agree with Max-Age, in UTC.
				expires = re.search(r"(?i);\s*Expires=([^;]+)", header)
				self.assertIsNotNone(expires, header)
				left = (parsedate_to_datetime(expires.group(1)) - sent_at).total_seconds()
				self.assertAlmostEqual(left, EXPIRY_MIN * 60, delta=60, msg=header)

	def test_magic_link_round_trip_west_of_utc(self):
		"""Request a link and confirm it in the same browser on a site set to New York.
		The test client keeps cookies a browser would already have dropped, so drop
		the cookie here if its header says it has expired."""
		_set_time_zone("America/New_York")
		client = new_client()
		sent = {}
		response, sent_at = self._send(client, sent)
		if _lifetime_seconds(_browser_cookie_header(response), sent_at) <= 0:
			client.delete_cookie(magic_link.BROWSER_COOKIE)

		key = re.search(r"key=([\w-]+)", sent["link"]).group(1)
		page = http(client, "get", f"{LOGIN}?key={key}")
		self.assertEqual(page.status_code, 200, page.get_data(as_text=True)[:300])
		response = http(client, "post", LOGIN, data={"key": key})
		self.assertIn(response.status_code, (301, 302, 303), response.get_data(as_text=True)[:300])
		self.assertEqual(logged_in_user(client), USER)
