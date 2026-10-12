"""Post-login redirect targets (audit H-1, H-2, G-2)."""

from __future__ import annotations

from urllib.parse import unquote, urlsplit


def _normalised_path(path: str) -> str:
	"""Return `path` as a browser resolves it: percent-decoded, "." and ".." removed.

	Browsers treat "%2e" as "." and collapse dot segments, so "/.//host" and
	"/%2e//host" both become "//host". Decoding "%2f" as well covers servers or
	proxies that decode it before routing.
	"""
	segments = unquote(path).split("/")
	out: list[str] = []
	for segment in segments[1:]:
		if segment == ".":
			continue
		if segment == "..":
			if out:
				out.pop()
			continue
		out.append(segment)
	return "/" + "/".join(out)


def safe_redirect(target: str | None) -> str | None:
	"""Return `target` if it is a same-site relative path, else None.

	Only paths that start with exactly one "/" are accepted. Anything a browser
	could read as another host is refused: "//host", "/\\host", backslashes
	(browsers treat them as "/"), schemes such as "https:" or "javascript:",
	control characters (browsers drop tabs and newlines, so "/\\t/host" becomes
	"//host"), and paths whose dot segments or encoded slashes resolve to
	"//host", such as "/.//host" or "/%2e//host" (audit G-2).
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
	if _normalised_path(parts.path).startswith("//"):
		return None
	return target
