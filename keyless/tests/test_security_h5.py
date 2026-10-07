"""H-5: WebAuthn expected origin and RP ID must come from configuration, not request headers."""

from __future__ import annotations

import json
import secrets
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import get_url, set_request
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse

from keyless.api import passkey
from keyless.tests.security_utils import keyless_settings, reset_rate_limits

EVIL = "https://evil.example"
EXTRA = "https://extra.example"
PASSKEYS_ON = {"enabled": 1, "enable_passkeys": 1, "rp_id": "", "allowed_origins": ""}


def site_origin() -> str:
	parts = urlsplit(get_url(allow_header_override=False))
	return f"{parts.scheme}://{parts.netloc}"


def _origin_ok(claimed, expected):
	expected = [expected] if isinstance(expected, str) else list(expected)
	return claimed in expected


def fake_verify_registration(*, credential, expected_origin, **kwargs):
	if not _origin_ok(credential["_origin"], expected_origin):
		raise InvalidRegistrationResponse("Unexpected client data origin")
	return SimpleNamespace(
		credential_id=secrets.token_bytes(16),
		credential_public_key=secrets.token_bytes(32),
		sign_count=0,
		aaguid=None,
		credential_backed_up=False,
	)


def fake_verify_authentication(*, credential, expected_origin, **kwargs):
	if not _origin_ok(credential["_origin"], expected_origin):
		raise InvalidAuthenticationResponse("Unexpected client data origin")
	return SimpleNamespace(new_sign_count=1)


class OriginCase(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		reset_rate_limits()
		self.addCleanup(frappe.db.rollback)

	def request(self, origin: str, host: str | None = None, path="/api/method/keyless.api.passkey.x"):
		headers = {"Origin": origin}
		if host:
			headers["Host"] = host
		set_request(method="POST", path=path, headers=headers)
		frappe.local.request_ip = "127.0.0.1"


class TestRegistrationOrigin(OriginCase):
	def _register(self, origin, **settings):
		self.request(origin)
		cred = {"id": "x", "rawId": "x", "type": "public-key", "response": {}, "_origin": origin}
		with (
			keyless_settings(**{**PASSKEYS_ON, **settings}),
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "registration", "user": "Administrator", "challenge": "Y2hhbGxlbmdl"},
			),
			patch("webauthn.verify_registration_response", side_effect=fake_verify_registration),
			patch.object(passkey, "log_event"),
		):
			return passkey.verify_registration(cred, "cid")

	def test_foreign_origin_rejected_even_when_header_matches(self):
		with self.assertRaises(frappe.AuthenticationError):
			self._register(EVIL)

	def test_site_origin_accepted(self):
		self.assertTrue(self._register(site_origin())["ok"])

	def test_allow_listed_origin_accepted(self):
		self.assertTrue(self._register(EXTRA, allowed_origins=f"{EXTRA}\n")["ok"])


class TestAuthenticationOrigin(OriginCase):
	def setUp(self):
		super().setUp()
		handle = frappe.db.get_value("User", "Administrator", "keyless_user_handle")
		if not handle:
			from keyless.user import ensure_user_handle

			handle = ensure_user_handle("Administrator")
		self.handle = handle
		self.credential_id = bytes_to_base64url(secrets.token_bytes(16))
		frappe.get_doc(
			{
				"doctype": "User Passkey",
				"user": "Administrator",
				"credential_id": self.credential_id,
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
				"user_handle": handle,
			}
		).insert(ignore_permissions=True)

	def _authenticate(self, origin, **settings):
		self.request(origin)
		cred = {
			"id": self.credential_id,
			"rawId": self.credential_id,
			"type": "public-key",
			"response": {"userHandle": bytes_to_base64url(passkey._handle_bytes(self.handle))},
			"_origin": origin,
		}
		with (
			keyless_settings(**{**PASSKEYS_ON, **settings}),
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "authentication", "user": None, "challenge": "Y2hhbGxlbmdl"},
			),
			patch("webauthn.verify_authentication_response", side_effect=fake_verify_authentication),
			patch.object(passkey, "log_event"),
			patch.object(passkey, "issue_session") as issue,
		):
			result = passkey.verify_authentication(json.dumps(cred), "cid")
		return result, issue

	def test_foreign_origin_rejected_even_when_header_matches(self):
		with self.assertRaises(frappe.AuthenticationError):
			self._authenticate(EVIL)

	def test_site_origin_accepted(self):
		_result, issue = self._authenticate(site_origin())
		issue.assert_called_once()

	def test_allow_listed_origin_accepted(self):
		_result, issue = self._authenticate(EXTRA, allowed_origins=EXTRA)
		issue.assert_called_once()


class TestRelyingPartyId(OriginCase):
	def _options_rp_id(self, **settings):
		self.request(EVIL, host="evil.example", path="/api/method/keyless.api.passkey.registration_options")
		with keyless_settings(**{**PASSKEYS_ON, **settings}):
			return passkey.registration_options()["rp"]["id"]

	def test_spoofed_host_does_not_change_rp_id(self):
		self.assertEqual(self._options_rp_id(), urlsplit(site_origin()).hostname)

	def test_configured_rp_id_wins(self):
		self.assertEqual(self._options_rp_id(rp_id="example.org"), "example.org")


class TestAllowedOriginsSetting(FrappeTestCase):
	def tearDown(self):
		frappe.db.rollback()

	def test_origins_are_normalised(self):
		doc = frappe.get_single("Keyless Settings")
		doc.allowed_origins = " https://ERP.example.com:8001/ \n\nhttp://localhost:8000"
		doc.validate()
		self.assertEqual(doc.allowed_origins, "https://erp.example.com:8001\nhttp://localhost:8000")

	def test_malformed_origins_are_refused(self):
		for value in ("erp.example.com", "https://erp.example.com/path", "ftp://erp.example.com", "https://"):
			with self.subTest(value=value):
				doc = frappe.get_single("Keyless Settings")
				doc.allowed_origins = value
				with self.assertRaises(frappe.ValidationError):
					doc.validate()
