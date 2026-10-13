"""User lifecycle: stable WebAuthn user handles, who may change Passwordless Only,
cleanup, unusable passwords."""

from __future__ import annotations

import secrets

import frappe
from frappe import _
from frappe.utils import random_string

from keyless import notify
from keyless.audit import log_event


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


def validate_user(doc, method=None):
	"""Only a System Manager may turn Passwordless Only off (audit 2026-10-10, F-3).

	The field is permlevel 1, so Frappe already puts back the stored value when
	anyone else saves the form or calls the REST API. This also covers server
	code that saves a User with ignore_permissions. Turning it on is not
	refused here: it only takes a way of signing in away.
	"""
	before = doc.get_doc_before_save()
	if not before or not before.get("keyless_passwordless_only") or doc.get("keyless_passwordless_only"):
		return
	if "System Manager" in frappe.get_roles():
		return
	log_event("passwordless_only_changed", user=doc.name, method="user", success=False, detail=_by(doc, "off refused"))
	frappe.throw(_("Only a System Manager can turn off Passwordless Only."), frappe.PermissionError)


def on_user_update(doc, method=None):
	if not doc.keyless_user_handle:
		doc.db_set("keyless_user_handle", secrets.token_hex(16), update_modified=False)
	_passwordless_only_changed(doc)


def _passwordless_only_changed(doc) -> None:
	"""Log a change to Passwordless Only and tell the user (F-3). New users are
	not notified; changes made with frappe.db.set_value run no hooks."""
	before = doc.get_doc_before_save()
	if not before or bool(before.get("keyless_passwordless_only")) == bool(doc.get("keyless_passwordless_only")):
		return
	on = bool(doc.get("keyless_passwordless_only"))
	log_event("passwordless_only_changed", user=doc.name, method="user", success=True, detail=_by(doc, "on" if on else "off"))
	notify.sign_in_methods_changed(
		doc.name,
		_("Passwordless Only was turned on for your account: you can no longer sign in with a password.")
		if on
		else _("Passwordless Only was turned off for your account: signing in with a password may work again."),
	)


def _by(doc, detail: str) -> str:
	"""`detail`, plus who did it when that is not the user themselves."""
	actor = frappe.session.user
	return detail if actor == doc.name else f"{detail} by {actor}"


def on_user_trash(doc, method=None):
	for dt in ("User Passkey", "Keyless Backup Code"):
		frappe.db.delete(dt, {"user": doc.name})


def set_unusable_password(user: str) -> None:
	"""Frappe User.password is NOT NULL. Give passwordless accounts a secret they never learn."""
	from frappe.utils.password import update_password

	update_password(user, random_string(40))


def resolve_enabled_user(email: str) -> str | None:
	"""Return the User name for an enabled account, or None. Does not throw.

	Both lookups always run, so an address with an account and one without take
	the same work: the sign-in request handlers call this before they answer (F-4).
	"""
	if not email:
		return None
	email = email.strip().lower()
	by_name = frappe.db.get_value("User", {"name": email, "enabled": 1}, "name")
	by_email = frappe.db.get_value("User", {"email": email, "enabled": 1}, "name")
	return by_name or by_email
