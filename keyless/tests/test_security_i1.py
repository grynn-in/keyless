"""I-1: hardening notes."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import set_request
from webauthn.helpers import bytes_to_base64url

from keyless import tokens
from keyless.api import passkey
from keyless.tests.security_utils import delete_user, keyless_settings, make_user, reset_rate_limits

USER = "kl-i1-user@example.com"
ON = {"enabled": 1, "enable_passkeys": 1, "rp_id": "", "allowed_origins": ""}


class TestPepper(FrappeTestCase):
	def test_missing_encryption_key_is_created_not_replaced(self):
		# A new site has no encryption_key until something first encrypts a value.
		# Keyless must create one (as Frappe does), never fall back to secret_key.
		conf = frappe.local.conf
		saved = conf.pop("encryption_key", None)
		try:
			with (
				patch.dict(conf, {"secret_key": "not-a-pepper"}),
				patch("frappe.installer.update_site_config") as save,
			):
				value = tokens.digest("123456")
				created = conf.get("encryption_key")
			self.assertTrue(created)
			save.assert_called_once_with("encryption_key", created)
			self.assertNotEqual(value, hmac.new(b"not-a-pepper", b"123456", hashlib.sha256).hexdigest())
			self.assertEqual(value, hmac.new(created.encode(), b"123456", hashlib.sha256).hexdigest())
		finally:
			conf.pop("encryption_key", None)
			if saved is not None:
				conf["encryption_key"] = saved

	def test_empty_encryption_key_fails_closed(self):
		with patch.object(tokens, "get_encryption_key", return_value=""):
			with self.assertRaisesRegex(frappe.ValidationError, "encryption_key"):
				tokens.digest("123456")

	def test_digest_uses_encryption_key(self):
		self.assertEqual(len(tokens.digest("123456")), 64)


class PasskeySignIn(FrappeTestCase):
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
		self.addCleanup(frappe.db.rollback)
		self.credential_id = bytes_to_base64url(secrets.token_bytes(16))
		self.handle = frappe.db.get_value("User", USER, "keyless_user_handle")
		self.passkey = frappe.get_doc(
			{
				"doctype": "User Passkey",
				"user": USER,
				"credential_id": self.credential_id,
				"public_key": bytes_to_base64url(secrets.token_bytes(32)),
				"user_handle": self.handle,
			}
		).insert(ignore_permissions=True)

	def _request(self, cmd):
		set_request(method="POST", path=f"/api/method/{cmd}")
		frappe.local.request_ip = "127.0.0.1"
		frappe.local.form_dict = frappe._dict(cmd=cmd)

	def _credential(self):
		return json.dumps(
			{
				"id": self.credential_id,
				"rawId": self.credential_id,
				"type": "public-key",
				"response": {"userHandle": bytes_to_base64url(passkey._handle_bytes(self.handle))},
			}
		)

	def _sign_in(self, challenge_id):
		self._request("keyless.api.passkey.verify_authentication")
		return passkey.verify_authentication(self._credential(), challenge_id)


class TestDisabledUser(PasskeySignIn):
	def test_disabled_user_is_refused_before_sign_count_is_stored(self):
		frappe.db.set_value("User", USER, "enabled", 0)
		with (
			keyless_settings(**ON),
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "authentication", "user": None, "challenge": "Y2hhbGxlbmdl"},
			),
			patch("webauthn.verify_authentication_response", return_value=SimpleNamespace(new_sign_count=7)),
			patch.object(passkey, "issue_session") as issue,
		):
			with self.assertRaises(frappe.AuthenticationError):
				self._sign_in("cid")
		issue.assert_not_called()
		row = frappe.db.get_value("User Passkey", self.passkey.name, ["sign_count", "last_used"], as_dict=True)
		self.assertEqual(row.sign_count, 0)
		self.assertIsNone(row.last_used)


class TestReplayedChallenge(PasskeySignIn):
	def test_challenge_cannot_be_used_twice(self):
		with (
			keyless_settings(**ON),
			patch("webauthn.verify_authentication_response", return_value=SimpleNamespace(new_sign_count=1)),
			patch.object(passkey, "issue_session") as issue,
		):
			self._request("keyless.api.passkey.authentication_options")
			challenge_id = passkey.authentication_options()["challenge_id"]
			self._sign_in(challenge_id)
			with self.assertRaises(frappe.AuthenticationError):
				self._sign_in(challenge_id)
		self.assertEqual(issue.call_count, 1)


class TestNoOpCodeRemoved(FrappeTestCase):
	def test_no_placeholder_jobs_or_methods(self):
		app = Path(frappe.get_app_path("keyless"))
		self.assertNotIn("purge_expired_challenges", (app / "tasks.py").read_text())
		self.assertNotIn("purge_expired_challenges", (app / "hooks.py").read_text())
		settings = (app / "keyless/doctype/keyless_settings/keyless_settings.py").read_text()
		self.assertNotIn("_sync_login_redirect", settings)
