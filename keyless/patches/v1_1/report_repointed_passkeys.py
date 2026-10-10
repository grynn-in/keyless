from keyless.security import report_repointed_passkeys


def execute():
	# Report only (audit C-1): never modifies or deletes passkeys.
	report_repointed_passkeys()
