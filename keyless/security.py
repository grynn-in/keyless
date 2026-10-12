"""Security maintenance helpers.

Run on demand with:
	bench --site <site> execute keyless.security.report_repointed_passkeys
	bench --site <site> execute keyless.security.report_self_cleared_passwordless_only
	bench --site <site> execute keyless.security.report_unbound_backup_codes
"""

from __future__ import annotations

import frappe


def find_repointed_passkeys() -> list[dict]:
	"""User Passkey rows that may have been re-pointed at another account (audit C-1),
	or added to it by someone else (audit 2026-10-10, F-2).

	Flags rows whose creator is not the bound user, or whose stored user handle
	is not the bound user's WebAuthn handle. Before F-2 a System Manager could
	create a row for any user from Desk or REST; such rows match the first
	check. Since F-2 only the user's own registration can create a row, so a
	new match needs looking into. Review rather than delete.
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
	message = "Review these User Passkey rows (audit C-1, F-2):\n" + "\n".join(lines)
	print(f"Keyless: {len(rows)} suspicious User Passkey row(s).\n{message}")
	frappe.log_error(title="Keyless: review User Passkey ownership", message=message)
	return rows


def find_self_cleared_passwordless_only() -> list[dict]:
	"""Users who turned off their own Passwordless Only (audit 2026-10-10, F-3).

	Read from the User record's Version history: changes of
	keyless_passwordless_only from on to off saved by the user themselves.
	Changes made with frappe.db.set_value leave no Version and are not found.
	"""
	rows = frappe.get_all(
		"Version",
		filters={"ref_doctype": "User", "data": ("like", "%keyless_passwordless_only%")},
		fields=["name", "docname", "owner", "creation", "data"],
		order_by="creation",
	)
	found = []
	for row in rows:
		if row.owner != row.docname:
			continue
		try:
			changed = frappe.parse_json(row.data).get("changed") or []
		except Exception:
			continue
		for change in changed:
			if len(change) == 3 and change[0] == "keyless_passwordless_only" and change[1] and not change[2]:
				found.append(
					frappe._dict(
						version=row.name,
						user=row.docname,
						changed_on=row.creation,
						still_off=not frappe.db.get_value("User", row.docname, "keyless_passwordless_only"),
					)
				)
	return found


def report_self_cleared_passwordless_only() -> list[dict]:
	"""Print and log users who cleared their own Passwordless Only. Reports only."""
	rows = find_self_cleared_passwordless_only()
	if not rows:
		print("Keyless: no user turned off their own Passwordless Only.")
		return rows
	lines = [
		f"{r.user} on {r.changed_on} (Version {r.version}){'; still off' if r.still_off else ''}" for r in rows
	]
	message = "These users turned off their own Passwordless Only (audit 2026-10-10, F-3):\n" + "\n".join(lines)
	print(f"Keyless: {len(rows)} self-made Passwordless Only change(s).\n{message}")
	frappe.log_error(title="Keyless: review Passwordless Only changes", message=message)
	return rows



def find_unbound_backup_codes() -> list[dict]:
	"""Backup codes stored before audit 2026-10-12 G-1 whose creator is not their user.

	generate_codes always ran as the user it made codes for, so a version-1 row
	created by anyone else was added from Desk, REST or a script, or was moved
	from another account with frappe.client.set_value. Since G-1 these rows no
	longer sign anyone in. Used rows are listed too: they may show past misuse.
	"""
	return frappe.db.sql(
		"""
		select name, user, owner, used, used_on, creation
		from `tabKeyless Backup Code`
		where ifnull(hash_version, 0) < 2 and owner != user
		order by creation
		""",
		as_dict=True,
	)


def report_unbound_backup_codes() -> list[dict]:
	"""Print and log the rows above. Reports only; never modifies or deletes."""
	rows = find_unbound_backup_codes()
	if not rows:
		print("Keyless: no backup code was created by someone other than its user.")
		return rows
	lines = [
		f"{r.name}: user={r.user} owner={r.owner}" + (f" (used {r.used_on})" if r.used else "") for r in rows
	]
	message = (
		"These backup codes were created by someone other than their user, or moved to them, before "
		"audit 2026-10-12 G-1. They no longer sign anyone in. Check the Keyless Audit Log for "
		"backup_code sign-ins by these users:\n" + "\n".join(lines)
	)
	print(f"Keyless: {len(rows)} backup code(s) not created by their user.\n{message}")
	frappe.log_error(title="Keyless: review Keyless Backup Code ownership", message=message)
	return rows
