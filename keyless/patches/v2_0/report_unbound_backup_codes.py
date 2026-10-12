from keyless.security import report_unbound_backup_codes


def execute():
	# Report only (audit 2026-10-12, G-1): never modifies or deletes backup codes.
	# Codes generated before the fix keep working for their own user; rows listed
	# here no longer sign anyone in.
	report_unbound_backup_codes()
