"""G-6 (audit of 12 October 2026): py_webauthn decodes attacker-supplied CBOR at
passkey sign-in and registration, and only asks for cbor2 >= 5.6.5. cbor2 before
5.9.0 recurses without limit on deeply nested input (CVE-2026-26209), so Keyless
must declare the floor itself and the installed cbor2 must meet it.

cbor2 6 is a rewrite with breaking changes. py_webauthn 2.x was built on cbor2 5
but does not cap it, so Keyless's declared range stops below 6."""

from __future__ import annotations

import os
import re
from importlib.metadata import version

import frappe
from frappe.tests.utils import FrappeTestCase
from packaging.requirements import Requirement
from packaging.version import Version

CBOR2_FLOOR = Version("5.9.0")
CBOR2_CEILING = Version("6")
LAST_VULNERABLE = "5.8.0"


def app_root() -> str:
	return os.path.dirname(frappe.get_app_path("keyless"))


def declared(path: str) -> list[Requirement]:
	"""Requirements from pyproject.toml's dependencies list, or requirements.txt."""
	with open(os.path.join(app_root(), path)) as f:
		text = f.read()
	if path == "pyproject.toml":
		block = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M).group(1)
		lines = re.findall(r"\"([^\"]+)\"", block)
	else:
		lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
	return [Requirement(line) for line in lines]


class TestDependencyFloors(FrappeTestCase):
	def test_cbor2_floor_is_declared(self):
		for path in ("pyproject.toml", "requirements.txt"):
			with self.subTest(path=path):
				cbor2 = [r for r in declared(path) if r.name.lower() == "cbor2"]
				self.assertEqual(len(cbor2), 1, f"{path} does not declare cbor2")
				self.assertNotIn(LAST_VULNERABLE, cbor2[0].specifier)
				self.assertIn(str(CBOR2_FLOOR), cbor2[0].specifier)

	def test_cbor2_ceiling_is_declared(self):
		for path in ("pyproject.toml", "requirements.txt"):
			with self.subTest(path=path):
				(cbor2,) = [r for r in declared(path) if r.name.lower() == "cbor2"]
				self.assertIn("5.99.99", cbor2.specifier)
				for v in ("6.0.0", "6.0.0rc1", "6.1.2"):
					self.assertFalse(cbor2.specifier.contains(v, prereleases=True), f"{path} allows cbor2 {v}")

	def test_installed_cbor2_meets_the_floor(self):
		self.assertGreaterEqual(Version(version("cbor2")), CBOR2_FLOOR)

	def test_installed_cbor2_is_below_6(self):
		self.assertLess(Version(version("cbor2")), CBOR2_CEILING)

	def test_webauthn_constraint_unchanged(self):
		# The floor is added alongside py_webauthn, not instead of it.
		for path in ("pyproject.toml", "requirements.txt"):
			with self.subTest(path=path):
				names = {r.name.lower(): r for r in declared(path)}
				self.assertIn("webauthn", names)
				self.assertIn("2.7.1", names["webauthn"].specifier)
