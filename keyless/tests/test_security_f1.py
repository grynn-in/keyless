"""F-1 (audit of 10 October 2026): a `tmp_id` with nothing cached must not let a
password login skip the policy check, and no refusal may confirm a password."""

from __future__ import annotations

import json
import secrets
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from keyless import auth, password_policy
from keyless.tests.security_utils import (
	PASSWORD,
	delete_user,
	http,
	keyless_settings,
	logged_in_user,
	make_user,
	new_client,
	reset_rate_limits,
)

USER = "kl-f1-user@example.com"
PER_USER = {"enabled": 1, "disable_password_login": 0, "allow_administrator_password": 1}
REQUIRE_PASSKEY = {**PER_USER, "require_passkey_for_system_users": 1}


def shown_messages(response) -> list[str]:
	"""The texts Frappe shows the user, without per-response IDs."""
	raw = (response.json or {}).get("_server_messages")
	return [json.loads(m).get("message") for m in json.loads(raw)] if raw else []


def login(client, pwd, **extra):
	return http(client, "post", "/api/method/login", data={"usr": USER, "pwd": pwd, **extra})


class TestJunkTmpId(FrappeTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")
		make_user(USER, user_type="System User", roles=("System Manager",))

	@classmethod
	def tearDownClass(cls):
		frappe.set_user("Administrator")
		delete_user(USER)
		super().tearDownClass()

	def setUp(self):
		reset_rate_limits()
		self.addCleanup(self.set_passwordless_only, 0)

	def set_passwordless_only(self, value: int):
		frappe.db.set_value("User", USER, "keyless_passwordless_only", value)
		frappe.db.commit()
		frappe.clear_cache(user=USER)

	def assert_same_refusal(self, **extra):
		"""Right and wrong password get the same answer and neither gets a session."""
		answers = []
		for pwd in (PASSWORD, PASSWORD + "-wrong"):
			client = new_client()
			response = login(client, pwd, **extra)
			self.assertEqual(logged_in_user(client), "Guest", response.get_data(as_text=True)[:300])
			answers.append(response)
		right, wrong = answers
		self.assertEqual(right.status_code, wrong.status_code)
		self.assertEqual((right.json or {}).get("message"), (wrong.json or {}).get("message"))
		self.assertEqual(shown_messages(right), shown_messages(wrong))
		return right

	def test_junk_tmp_id_is_refused_like_a_wrong_password(self):
		cases = {"passwordless only": (PER_USER, 1), "passkey required for System Users": (REQUIRE_PASSKEY, 0)}
		for label, (settings, passwordless_only) in cases.items():
			with self.subTest(rule=label), keyless_settings(**settings):
				self.set_passwordless_only(passwordless_only)
				response = self.assert_same_refusal(tmp_id=secrets.token_hex(8))
				self.assertEqual(response.status_code, 401)
				self.assertIn(password_policy.BLOCKED_MESSAGE, response.get_data(as_text=True))

	def test_junk_tmp_id_still_signs_in_when_allowed(self):
		# The fix follows Frappe's choice of user; it does not refuse every tmp_id.
		with keyless_settings(**PER_USER):
			client = new_client()
			login(client, PASSWORD, tmp_id=secrets.token_hex(8))
			self.assertEqual(logged_in_user(client), USER)

	def test_login_name_follows_frappe(self):
		tmp_id = secrets.token_hex(8)
		frappe.local.form_dict = frappe._dict(usr=USER, tmp_id=tmp_id)
		self.assertEqual(auth.password_login_name(), USER, "nothing cached: Frappe uses the form")
		frappe.cache.set(tmp_id + "_usr", "Administrator")
		self.addCleanup(frappe.cache.delete, tmp_id + "_usr", tmp_id + "_pwd")
		self.assertEqual(auth.password_login_name(), USER, "half cached: Frappe uses the form")
		frappe.cache.set(tmp_id + "_pwd", "x")
		self.assertEqual(auth.password_login_name(), "Administrator", "both cached: Frappe uses the cache")

	def test_on_login_refuses_like_a_wrong_password(self):
		# If before_login ever misses a blocked user, on_login runs after the
		# password check. Its refusal must not differ from a wrong password.
		self.set_passwordless_only(1)
		with keyless_settings(**PER_USER), patch.object(password_policy, "resolve_login_name", return_value=None):
			response = self.assert_same_refusal()
		self.assertEqual(response.status_code, 401)
		self.assertEqual(response.json.get("message"), "Invalid login credentials")
		self.assertNotIn(password_policy.BLOCKED_MESSAGE, response.get_data(as_text=True))
