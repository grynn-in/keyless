"""Frappe 15 compatibility.

Frappe 16 runs the `before_login` trigger as the first step of
`LoginManager.login()`, before the password is checked. Frappe 15 has no such
trigger, so without it the password policy could only run from `on_login`,
after the password check: a blocked login then showed whether the password
was right (through Frappe 2FA or the login-attempt counter), and an expired
password got a reset link before `on_login` ever ran (code review of #7).

`backport_before_login` adds that one call to Frappe 15. It runs when the
`keyless` package is imported, which every Keyless hook does, so it is in
place from a worker's first request that touches Keyless onward. The
`on_login` check stays as the fallback for anything earlier.
"""

from __future__ import annotations

import inspect
from functools import wraps

MARKER = "_keyless_before_login"


def backport_before_login() -> bool:
	"""Make Frappe 15's LoginManager.login() run before_login first. Returns
	True if login() runs the trigger afterwards (patched or native)."""
	from frappe.auth import LoginManager

	if getattr(LoginManager.login, MARKER, False):
		return True
	try:
		source = inspect.getsource(LoginManager.login)
	except (OSError, TypeError):
		return False
	if 'run_trigger("before_login")' in source:
		return True

	original = LoginManager.login

	@wraps(original)
	def login(self):
		self.run_trigger("before_login")
		return original(self)

	setattr(login, MARKER, True)
	LoginManager.login = login
	return True
