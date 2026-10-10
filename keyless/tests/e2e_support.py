"""Server-side helpers for the browser suite in e2e/ (run through `bench execute`).

Only for throwaway test sites: every helper refuses to run unless the site has
`allow_tests` set.
"""

from __future__ import annotations

import email
from urllib.parse import urlsplit
from email import policy

import frappe
from frappe.installer import update_site_config

USERS = ("e2e-passkey@example.com", "e2e-nopasskey@example.com")


def _origin(url: str | None) -> str:
	if not url:
		return ""
	parts = urlsplit(url)
	return f"{parts.scheme}://{parts.netloc}"


def _require_test_site():
	if not frappe.conf.get("allow_tests"):
		frappe.throw("The Keyless browser suite only runs on sites with allow_tests set.")


def setup(url: str | None = None) -> list[str]:
	"""Reset the site to a known state for one run of the suite. Returns the test users.

	`url` is where the suite reaches the site. It becomes host_name, so emailed links
	and the passkey origin (which come from configuration, never request headers)
	match it, port included.
	"""
	_require_test_site()
	frappe.set_user("Administrator")

	# Mail is queued but never sent; the suite reads codes and links from the queue.
	update_site_config("mute_emails", 1)
	if url:
		update_site_config("host_name", url.rstrip("/"))

	settings = frappe.get_single("Keyless Settings")
	settings.update(
		dict(
			enabled=1,
			enable_passkeys=1,
			enable_magic_link=1,
			enable_email_otp=1,
			enable_backup_codes=1,
			disable_password_login=0,
			require_passkey_for_system_users=0,
			hide_user_enumeration=1,
			rate_limit_per_hour=50,
			otp_daily_limit=50,
			rp_id="",
			# Also accept the suite's origin for passkeys: a running server may not have
			# reread site_config yet, and settings take effect at once.
			allowed_origins=_origin(url),
			step_up_window_minutes=5,
		)
	)
	settings.save(ignore_permissions=True)

	for user in USERS:
		for doctype in ("User Passkey", "Keyless Backup Code"):
			frappe.db.delete(doctype, {"user": user})
		if not frappe.db.exists("User", user):
			doc = frappe.get_doc(
				{
					"doctype": "User",
					"email": user,
					"first_name": user.split("@")[0],
					"send_welcome_email": 0,
					"user_type": "System User",
				}
			).insert(ignore_permissions=True)
			doc.add_roles("System Manager")
		queued = frappe.get_all("Email Queue Recipient", filters={"recipient": user}, pluck="parent")
		frappe.db.delete("Email Queue", {"name": ("in", queued or [""])})

	# A new site has not run Frappe's setup wizard; Desk would show it instead of forms.
	if not frappe.db.get_single_value("System Settings", "setup_complete"):
		frappe.db.set_single_value(
			"System Settings", {"time_zone": "UTC", "currency": "USD", "setup_complete": 1}
		)
		frappe.db.set_value("Installed Application", {"app_name": "frappe"}, "is_setup_complete", 1)

	frappe.cache.delete_keys("rl:")
	frappe.cache.delete_keys("keyless:")
	frappe.db.commit()
	return list(USERS)


def last_mail(recipient: str) -> dict:
	"""{"text": ...} of the newest queued mail to `recipient` ("" when there is none).

	A dict, not a bare string: `bench execute` prints strings raw but other values as JSON.
	"""
	_require_test_site()
	rows = frappe.db.sql(
		"""select q.message from `tabEmail Queue` q
		join `tabEmail Queue Recipient` r on r.parent = q.name
		where r.recipient = %s order by q.creation desc limit 1""",
		recipient,
	)
	if not rows:
		return {"text": ""}
	message = email.message_from_string(rows[0][0], policy=policy.default)
	return {
		"text": "\n".join(
			part.get_content()
			for part in message.walk()
			if part.get_content_type() in ("text/plain", "text/html")
		)
	}


def recent_errors(limit: int = 5) -> list[str]:
	"""Titles of the newest Error Log entries, to explain a step that failed."""
	_require_test_site()
	return frappe.get_all("Error Log", fields=["method"], order_by="creation desc", limit=limit, pluck="method")


def clear_step_up() -> bool:
	"""Expire every session's recent re-authentication, as if the window had passed."""
	_require_test_site()
	frappe.cache.delete_keys("keyless:stepup:")
	return True


def count(doctype: str, user: str) -> int:
	_require_test_site()
	filters = {"user": user}
	if doctype == "Keyless Backup Code":
		filters["used"] = 0
	return frappe.db.count(doctype, filters)
