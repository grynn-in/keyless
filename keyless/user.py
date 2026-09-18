"""User lifecycle: stable WebAuthn user handles, cleanup, unusable passwords."""

from __future__ import annotations

import secrets

import frappe
from frappe.utils import random_string


def ensure_user_handle(user: str | None = None) -> str:
	"""WebAuthn user.id must be stable even if the Frappe user is renamed."""
	name = user or frappe.session.user
	handle = frappe.db.get_value("User", name, "keyless_user_handle")
	if handle:
		return handle
	handle = secrets.token_hex(16)
	frappe.db.set_value("User", name, "keyless_user_handle", handle, update_modified=False)
	return handle


def after_user_insert(doc, method=None):
	if not doc.keyless_user_handle:
		doc.db_set("keyless_user_handle", secrets.token_hex(16), update_modified=False)


def on_user_update(doc, method=None):
	if not doc.keyless_user_handle:
		doc.db_set("keyless_user_handle", secrets.token_hex(16), update_modified=False)


def on_user_trash(doc, method=None):
	for dt in ("User Passkey", "Keyless Backup Code"):
		frappe.db.delete(dt, {"user": doc.name})


def set_unusable_password(user: str) -> None:
	"""Frappe User.password is NOT NULL. Give passwordless accounts a secret they never learn."""
	from frappe.utils.password import update_password

	update_password(user, random_string(40))


def resolve_enabled_user(email: str) -> str | None:
	"""Return the User name for an enabled account, or None. Does not throw."""
	if not email:
		return None
	email = email.strip().lower()
	name = frappe.db.get_value("User", {"name": email, "enabled": 1}, "name")
	if name:
		return name
	return frappe.db.get_value("User", {"email": email, "enabled": 1}, "name")
