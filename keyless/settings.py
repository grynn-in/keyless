"""Cached accessor for the Keyless Settings single."""

from __future__ import annotations

from typing import TYPE_CHECKING

import frappe

if TYPE_CHECKING:
	from keyless.keyless.doctype.keyless_settings.keyless_settings import KeylessSettings


def get_settings() -> KeylessSettings:
	return frappe.get_cached_doc("Keyless Settings")


def is_enabled() -> bool:
	try:
		return bool(get_settings().enabled)
	except Exception:
		return False
