__version__ = "2.0.0"

try:
	from keyless.compat import backport_before_login

	backport_before_login()
except ImportError:
	# Frappe is not importable (for example while pip builds the package).
	pass
