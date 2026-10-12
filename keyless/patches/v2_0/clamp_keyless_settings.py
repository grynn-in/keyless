import frappe

from keyless.keyless.doctype.keyless_settings.keyless_settings import clamp_stored_settings


def execute():
	# Audit 2026-10-10, F-9: Keyless Settings now refuses numbers outside fixed
	# bounds. Bring stored values inside them so the settings can still be saved,
	# and say what changed. Never stop the migrate over this.
	try:
		changes = clamp_stored_settings()
	except Exception:
		print("Keyless: could not check Keyless Settings bounds; see the Error Log")
		frappe.log_error(title="Keyless: settings bounds patch failed", message=frappe.get_traceback())
		return
	if changes:
		message = "Keyless Settings had values out of range. They were changed to:\n" + "\n".join(changes)
		print("Keyless: " + message)
		frappe.log_error(title="Keyless: settings out of range", message=message)
