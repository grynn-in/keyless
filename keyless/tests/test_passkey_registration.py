from __future__ import annotations

import json
import secrets
from types import SimpleNamespace
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from keyless.api import passkey

USER = "Administrator"


def _verification(device_type="multi_device", backed_up=True):
	"""Stand-in for py_webauthn's VerifiedRegistration."""
	return SimpleNamespace(
		credential_id=secrets.token_bytes(16),
		credential_public_key=secrets.token_bytes(32),
		sign_count=0,
		aaguid=None,
		credential_device_type=device_type,
		credential_backed_up=backed_up,
	)


def _credential(attachment=None):
	cred = {"id": "x", "rawId": "x", "type": "public-key", "response": {}}
	if attachment is not None:
		cred["authenticatorAttachment"] = attachment
	return cred


class TestPasskeyRegistrationDeviceType(FrappeTestCase):
	def setUp(self):
		frappe.set_user(USER)
		self.patches = [
			patch.object(passkey, "require_enabled", return_value=frappe._dict(passkey_user_verification="required")),
			patch.object(
				passkey,
				"consume_challenge",
				return_value={"type": "registration", "user": USER, "challenge": "Y2hhbGxlbmdl"},
			),
			patch.object(passkey, "allowed_origins", return_value=["http://localhost"]),
			patch.object(passkey, "rp_id", return_value="localhost"),
			patch.object(passkey, "log_event"),
		]
		for p in self.patches:
			p.start()

	def tearDown(self):
		for p in self.patches:
			p.stop()
		frappe.db.rollback()

	def _register(self, credential, verification):
		with patch("webauthn.verify_registration_response", return_value=verification):
			result = passkey.verify_registration(credential, "challenge-id")
		return frappe.get_doc("User Passkey", result["name"])

	def test_attachment_is_stored_for_dict_and_str_credentials(self):
		cases = [
			("platform", "platform"),
			("cross-platform", "cross-platform"),
			(None, None),
			("multi_device", None),
		]
		for as_str in (False, True):
			for attachment, expected in cases:
				with self.subTest(as_str=as_str, attachment=attachment):
					cred = _credential(attachment)
					doc = self._register(json.dumps(cred) if as_str else cred, _verification())
					self.assertEqual(doc.device_type or None, expected)
					self.assertEqual(doc.backed_up, 1)

	def test_multi_device_verification_never_reaches_device_type(self):
		for attachment in ("platform", "cross-platform", None):
			with self.subTest(attachment=attachment):
				doc = self._register(_credential(attachment), _verification("multi_device", True))
				self.assertNotIn(doc.device_type, ("multi_device", "single_device"))
				self.assertNotIn("multi_device", doc.friendly_name)

	def test_single_device_not_backed_up(self):
		doc = self._register(_credential("cross-platform"), _verification("single_device", False))
		self.assertEqual(doc.device_type, "cross-platform")
		self.assertEqual(doc.backed_up, 0)
