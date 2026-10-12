from __future__ import annotations

from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils import cint

# Allowed range for each numeric setting (audit 2026-10-10, F-9). Every default in
# keyless_settings.json is inside its range. A blank value (stored as 0) means the
# default; the app already reads it that way, and validate writes the default in.
SETTING_BOUNDS = {
	# Codes shorter than 6 digits can be guessed; the login page and random_otp stop at 8.
	"otp_length": (6, 8),
	"otp_expiry_seconds": (60, 3600),
	"max_otp_attempts": (1, 10),
	"rate_limit_per_hour": (1, 100),
	"otp_daily_limit": (1, 1000),
	"magic_link_expiry_minutes": (2, 60),
	"step_up_window_minutes": (1, 60),
	# A short or negative value lets the daily purge empty the audit log (review of #25).
	"audit_retention_days": (30, 3650),
}

# Settings where a stored value of 0 or less becomes the default rather than the
# floor. For limits the floor is the strict side; for retention it is the side
# that deletes the most, so a mistaken value must not be read as "keep 30 days".
NOT_POSITIVE_MEANS_DEFAULT = {"audit_retention_days"}


def setting_default(fieldname: str) -> int:
	return cint(frappe.get_meta("Keyless Settings").get_field(fieldname).default)


def bounded_value(fieldname: str, stored) -> int:
	"""The value in force for a stored setting: blank or zero is the default, and
	anything else outside SETTING_BOUNDS is the nearest bound, except that 0 or
	less is the default for NOT_POSITIVE_MEANS_DEFAULT."""
	low, high = SETTING_BOUNDS[fieldname]
	value = cint(stored)
	if not value or (value < 0 and fieldname in NOT_POSITIVE_MEANS_DEFAULT):
		return setting_default(fieldname)
	return min(max(value, low), high)


def audit_retention_days() -> int:
	"""Retention the purge uses. Applies the bounds to the stored value too, so a
	value written without validate (SQL, set_single_value, a site not yet
	migrated) cannot empty the log."""
	return bounded_value(
		"audit_retention_days", frappe.db.get_single_value("Keyless Settings", "audit_retention_days")
	)


def log_retention_change(old, new, by: str, method: str) -> None:
	"""Shortening retention deletes audit entries, so every change is itself audited."""
	from keyless.audit import log_event

	log_event(
		"audit_retention_changed",
		user=frappe.session.user,
		method=method,
		success=True,
		detail=f"{old} -> {new} by {by}",
	)


def clamp_stored_settings() -> tuple[list[str], list[str]]:
	"""Bring stored numeric settings inside SETTING_BOUNDS without running validate.

	Returns (out_of_range, filled): one line per value moved into range, and the
	names of blank values given their default. A blank value is not out of range:
	the app already read it as the default, so filling it changes nothing."""
	out_of_range, filled = [], []
	for fieldname, (low, high) in SETTING_BOUNDS.items():
		stored = frappe.db.get_single_value("Keyless Settings", fieldname)
		value = cint(stored)
		new = bounded_value(fieldname, stored)
		if value == new:
			continue
		frappe.db.set_single_value("Keyless Settings", fieldname, new)
		if value:
			out_of_range.append(f"{fieldname}: {stored!r} -> {new} (allowed {low} to {high})")
		else:
			filled.append(fieldname)
		if fieldname == "audit_retention_days":
			log_retention_change(value, new, by="migrate", method="migrate")
	if out_of_range or filled:
		frappe.clear_document_cache("Keyless Settings", "Keyless Settings")
	return out_of_range, filled


class KeylessSettings(Document):
	# begin: auto-generated types
	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		allow_administrator_password: DF.Check
		allowed_origins: DF.SmallText | None
		audit_retention_days: DF.Int
		disable_password_login: DF.Check
		enable_backup_codes: DF.Check
		enable_email_otp: DF.Check
		enable_magic_link: DF.Check
		enable_passkeys: DF.Check
		enabled: DF.Check
		hide_user_enumeration: DF.Check
		magic_link_expiry_minutes: DF.Int
		max_otp_attempts: DF.Int
		otp_daily_limit: DF.Int
		otp_expiry_seconds: DF.Int
		otp_length: DF.Int
		passkey_user_verification: DF.Literal["required", "preferred", "discouraged"]
		rate_limit_per_hour: DF.Int
		replace_standard_login: DF.Check
		require_passkey_for_system_users: DF.Check
		rp_id: DF.Data | None
		rp_name: DF.Data | None
		step_up_window_minutes: DF.Int
	# end: auto-generated types

	def validate(self):
		self._check_bounds()
		if self.rp_id:
			host = self.rp_id.strip().lower()
			if "://" in host:
				host = urlparse(host).hostname or host
			if ":" in host:
				frappe.throw(_("RP ID must be a hostname without port"))
			self.rp_id = host
		if self.allowed_origins:
			self.allowed_origins = "\n".join(self._clean_origins(self.allowed_origins))
		if self.enabled and self.enable_passkeys:
			from keyless.api.common import passkey_origin_warning

			warning = passkey_origin_warning(self.allowed_origins or "")
			if warning:
				frappe.msgprint(warning, title=_("Check passkey origins"), indicator="orange")
		if self.disable_password_login and not (
			self.enable_passkeys or self.enable_magic_link or self.enable_email_otp
		):
			frappe.throw(_("Enable at least one passwordless factor before disabling passwords"))

	def _check_bounds(self):
		meta = frappe.get_meta("Keyless Settings")
		for fieldname, (low, high) in SETTING_BOUNDS.items():
			value = cint(self.get(fieldname))
			if not value:
				# Blank, or a site upgraded from before the setting existed.
				self.set(fieldname, setting_default(fieldname))
			elif not low <= value <= high:
				frappe.throw(
					_("{0} must be between {1} and {2}").format(_(meta.get_label(fieldname)), low, high)
				)

	@staticmethod
	def _clean_origins(value: str) -> list[str]:
		origins = []
		for line in value.splitlines():
			line = line.strip().rstrip("/")
			if not line:
				continue
			parts = urlparse(line)
			if parts.scheme not in ("http", "https") or not parts.hostname or parts.path or parts.query:
				frappe.throw(_("Allowed origin must look like https://host[:port]: {0}").format(line))
			origins.append(f"{parts.scheme}://{parts.netloc.lower()}")
		return origins

	def on_update(self):
		before = self.get_doc_before_save()
		old = cint(before.get("audit_retention_days")) if before else 0
		new = cint(self.audit_retention_days)
		if old != new:
			log_retention_change(old, new, by=frappe.session.user, method="settings")
		frappe.cache.delete_value("keyless:settings")
		frappe.clear_cache()
