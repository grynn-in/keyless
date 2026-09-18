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
		allow_passwordless_signup: DF.Check
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
		otp_expiry_seconds: DF.Int
		otp_length: DF.Int
		passkey_user_verification: DF.Literal["required", "preferred", "discouraged"]
		rate_limit_per_hour: DF.Int
		replace_standard_login: DF.Check
		require_passkey_for_system_users: DF.Check
		rp_id: DF.Data | None
		rp_name: DF.Data | None
	# end: auto-generated types

	def validate(self):
		if self.otp_length and not (4 <= int(self.otp_length) <= 8):
			frappe.throw(_("OTP length must be between 4 and 8"))
		if self.otp_expiry_seconds and int(self.otp_expiry_seconds) < 60:
			frappe.throw(_("OTP expiry must be at least 60 seconds"))
		if self.magic_link_expiry_minutes and int(self.magic_link_expiry_minutes) < 2:
			frappe.throw(_("Magic link expiry must be at least 2 minutes"))
		if self.rp_id:
			host = self.rp_id.strip().lower()
			if "://" in host:
				host = urlparse(host).hostname or host
			if ":" in host:
				frappe.throw(_("RP ID must be a hostname without port"))
			self.rp_id = host
		if self.disable_password_login and not (
			self.enable_passkeys or self.enable_magic_link or self.enable_email_otp
		):
			frappe.throw(_("Enable at least one passwordless factor before disabling passwords"))
		if self.replace_standard_login:
			self._sync_login_redirect()

	def on_update(self):
		frappe.cache.delete_value("keyless:settings")
		frappe.clear_cache()

	def _sync_login_redirect(self):
		"""Keep a Website Route Redirect so /login lands on the Keyless page."""
		exists = frappe.db.exists("Website Route Redirect", {"source": "/login"})
		if exists:
			return
		# Website Route Redirect is optional; login.js also hard-redirects when boot says so.
		return
