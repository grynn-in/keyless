"""Security maintenance helpers.

Run on demand with:
	bench --site <site> execute keyless.security.report_repointed_passkeys
"""

from __future__ import annotations

import frappe


def find_repointed_passkeys() -> list[dict]:
	"""User Passkey rows that may have been re-pointed at another account (audit C-1).

	Flags rows whose creator is not the bound user, or whose stored user handle
	is not the bound user's WebAuthn handle. A System Manager creating a row on
	someone's behalf also matches the first check, so review rather than delete.
	"""
	rows = frappe.db.sql(
		"""
		select p.name, p.user, p.owner, p.user_handle, u.keyless_user_handle as expected_handle
		from `tabUser Passkey` p
		left join `tabUser` u on u.name = p.user
		where p.owner != p.user
			or ifnull(p.user_handle, '') != ifnull(u.keyless_user_handle, '')
		order by p.creation
		""",
		as_dict=True,
	)
	for row in rows:
		reasons = []
		if row.owner != row.user:
			reasons.append("owner differs from user")
		if (row.user_handle or "") != (row.expected_handle or ""):
			reasons.append("user handle differs from the user's handle")
		row["reasons"] = reasons
	return rows


def report_repointed_passkeys() -> list[dict]:
	"""Print and log suspicious rows. Reports only; never modifies or deletes."""
	rows = find_repointed_passkeys()
	if not rows:
		print("Keyless: no suspicious User Passkey rows found.")
		return rows
	lines = [f"{r.name}: user={r.user} owner={r.owner} ({'; '.join(r.reasons)})" for r in rows]
	message = "Review these User Passkey rows (audit C-1):\n" + "\n".join(lines)
	print(f"Keyless: {len(rows)} suspicious User Passkey row(s).\n{message}")
	frappe.log_error(title="Keyless: review User Passkey ownership", message=message)
	return rows
