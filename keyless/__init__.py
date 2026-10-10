__version__ = "1.0.1"

try:
	from keyless.compat import backport_before_login

	backport_before_login()
except ImportError:
	# Frappe is not importable (for example while pip builds the package).
	pass
