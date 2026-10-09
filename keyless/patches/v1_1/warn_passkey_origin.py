import frappe

from keyless.api.common import passkey_origin_warning
from keyless.settings import get_settings


def execute():
	# Report only: the upgrade makes passkey origins come from configuration
	# (audit H-5), so a site behind a TLS proxy may need host_name set.
	settings = get_settings()
	if not (settings.enabled and settings.enable_passkeys):
		return
	warning = passkey_origin_warning()
	if warning:
		print("Keyless: " + warning)
		frappe.log_error(title="Keyless: check passkey origins", message=warning)
