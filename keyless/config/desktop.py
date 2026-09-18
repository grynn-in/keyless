from frappe import _


def get_data():
	return [
		{
			"module_name": "Keyless",
			"type": "module",
			"label": _("Keyless"),
			"color": "#8aa88a",
			"icon": "octicon octicon-key",
			"description": _("Passwordless accounts"),
		}
	]
