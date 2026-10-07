"""Security notices to the account owner (audit M-3)."""

from __future__ import annotations

import frappe
from frappe import _
from frappe.utils import escape_html


def sign_in_methods_changed(user: str, event: str) -> None:
	"""Queue an email telling `user` what changed, listing their active passkeys.

	`event` is plain text and is escaped here. A mail failure is only logged.
	"""
	email = frappe.db.get_value("User", user, "email")
	if not email:
		return
	passkeys = frappe.get_all(
		"User Passkey",
		filters={"user": user},
		fields=["friendly_name", "creation"],
		order_by="creation asc",
	)
	items = "".join(
		f"<li>{escape_html(row.friendly_name or _('Unnamed passkey'))}"
		f" ({escape_html(frappe.utils.format_datetime(row.creation))})</li>"
		for row in passkeys
	) or f"<li>{escape_html(_('None'))}</li>"
	message = (
		f"<p>{escape_html(event)}</p>"
		f"<p>{escape_html(_('Passkeys on your account now:'))}</p><ul>{items}</ul>"
		f"<p>{escape_html(_('If this was not you, sign in and remove anything you do not recognise, or contact your administrator.'))}</p>"
	)
	try:
		frappe.sendmail(
			recipients=[email],
			subject=_("Your sign-in methods changed"),
			message=message,
			now=False,
		)
	except Exception:
		frappe.log_error(title="Keyless security notice failed", message=frappe.get_traceback())
