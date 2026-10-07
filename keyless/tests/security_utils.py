"""Shared fixtures for the security regression tests (test_security_*.py).

Requests go through the real WSGI app (`frappe.app.application`) via
werkzeug's test client, on a separate thread with its own DB connection, so
fixtures must be committed and cleaned up explicitly.
"""

from __future__ import annotations

from contextlib import contextmanager
from threading import Thread
from unittest.mock import patch

import frappe
from frappe.utils import get_test_client

PASSWORD = "Kl-Test-Pass-9271!"


def http(client, method: str, path: str, **kwargs):
	"""Run one request against the site on a worker thread and return the response."""
	site = frappe.local.site
	result = {}

	def run():
		with patch("frappe.app.get_site_name", return_value=site):
			result["response"] = getattr(client, method)(path, **kwargs)

	thread = Thread(target=run)
	thread.start()
	thread.join()
	return result["response"]


def new_client():
	return get_test_client()


def logged_in_user(client) -> str:
	"""The user the client's cookies resolve to ("Guest" when there is no usable session)."""
	response = http(client, "get", "/api/method/frappe.auth.get_logged_user")
	if response.status_code != 200:
		return "Guest"
	return (response.json or {}).get("message") or "Guest"


def make_user(email: str, *, user_type: str = "Website User", roles=(), **fields) -> str:
	if frappe.db.exists("User", email):
		delete_user(email)
	doc = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": email.split("@")[0],
			"user_type": user_type,
			"send_welcome_email": 0,
			"new_password": PASSWORD,
			**fields,
		}
	)
	doc.flags.ignore_password_policy = True
	doc.insert(ignore_permissions=True)
	if roles:
		doc.add_roles(*roles)
	frappe.db.commit()
	return doc.name


def api_auth_header(user: str) -> dict:
	"""Token auth for `user`, independent of any login policy."""
	from frappe.core.doctype.user.user import generate_keys

	secret = generate_keys(user)["api_secret"]
	key = frappe.db.get_value("User", user, "api_key")
	frappe.db.commit()
	return {"Authorization": f"token {key}:{secret}"}


def delete_user(email: str) -> None:
	for dt in ("User Passkey", "Keyless Backup Code"):
		frappe.db.delete(dt, {"user": email})
	frappe.delete_doc("User", email, force=True, ignore_permissions=True)
	frappe.db.commit()


@contextmanager
def keyless_settings(**values):
	"""Temporarily set Keyless Settings fields (committed, so worker threads see them)."""
	saved = {key: frappe.db.get_single_value("Keyless Settings", key) for key in values}
	_set_settings(values)
	try:
		yield
	finally:
		_set_settings(saved)


def _set_settings(values: dict) -> None:
	for key, value in values.items():
		frappe.db.set_single_value("Keyless Settings", key, value)
	frappe.db.commit()
	frappe.clear_document_cache("Keyless Settings", "Keyless Settings")
	frappe.clear_cache(doctype="Keyless Settings")


def reset_rate_limits() -> None:
	"""Clear Frappe's @rate_limit counters and Keyless's own per-account counters and
	codes, so tests do not trip each other's limits."""
	for prefix in ("rl:", "keyless:rl:", "keyless:otp"):
		frappe.cache.delete_keys(prefix)
