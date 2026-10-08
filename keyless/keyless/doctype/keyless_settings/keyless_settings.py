from __future__ import annotations

from urllib.parse import urlparse

import frappe
from frappe import _
from frappe.model.document import Document


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
		if self.otp_length and not (4 <= int(self.otp_length) <= 8):
			frappe.throw(_("OTP length must be between 4 and 8"))
		if self.otp_expiry_seconds and int(self.otp_expiry_seconds) < 60:
			frappe.throw(_("OTP expiry must be at least 60 seconds"))
		if not self.step_up_window_minutes:
			# Sites upgraded from before this setting load it as 0.
			self.step_up_window_minutes = 5
		elif int(self.step_up_window_minutes) < 1:
			frappe.throw(_("Step-up window must be at least 1 minute"))
		if self.magic_link_expiry_minutes and int(self.magic_link_expiry_minutes) < 2:
			frappe.throw(_("Magic link expiry must be at least 2 minutes"))
		if self.rp_id:
			host = self.rp_id.strip().lower()
			if "://" in host:
				host = urlparse(host).hostname or host
			if ":" in host:
				frappe.throw(_("RP ID must be a hostname without port"))
			self.rp_id = host
		if self.allowed_origins:
			self.allowed_origins = "\n".join(self._clean_origins(self.allowed_origins))
		if self.disable_password_login and not (
			self.enable_passkeys or self.enable_magic_link or self.enable_email_otp
		):
			frappe.throw(_("Enable at least one passwordless factor before disabling passwords"))

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
		frappe.cache.delete_value("keyless:settings")
		frappe.clear_cache()
