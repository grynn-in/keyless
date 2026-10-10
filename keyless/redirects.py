"""Post-login redirect targets (audit H-1, H-2)."""

from __future__ import annotations

from urllib.parse import urlsplit


def safe_redirect(target: str | None) -> str | None:
	"""Return `target` if it is a same-site relative path, else None.

	Only paths that start with exactly one "/" are accepted. Anything a browser
	could read as another host is refused: "//host", "/\\host", backslashes
	(browsers treat them as "/"), schemes such as "https:" or "javascript:", and
	control characters (browsers drop tabs and newlines, so "/\\t/host" becomes
	"//host").
	"""
	if not target or not isinstance(target, str):
		return None
	if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in target) or "\\" in target:
		return None
	if not target.startswith("/") or target.startswith("//"):
		return None
	parts = urlsplit(target)
	if parts.scheme or parts.netloc:
		return None
	return target
