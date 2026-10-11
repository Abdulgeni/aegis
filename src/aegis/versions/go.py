"""Go module version matching: semver with a ``v`` prefix.

Go pseudo-versions (``v0.0.0-20210101000000-abcdef123456``) are ordered as semver
pre-releases of their base version, which matches Go's own ordering rules. Go also
allows ``v1`` and ``v1.2`` as shorthand for ``v1.0.0`` / ``v1.2.0``; those are padded
before parsing.
"""

from __future__ import annotations

from semver import Version


def _strip_prefix(version: str) -> str:
    """Remove a leading ``v`` if present (Go module versions always carry one)."""
    text = version.strip()
    return text[1:] if text.startswith("v") else text


def _pad(text: str) -> str:
    """Pad ``1`` to ``1.0.0`` and ``1.2`` to ``1.2.0``; preserve pre-release and build."""
    core_pre, sep, build = text.partition("+")
    build_part = f"+{build}" if sep else ""
    core, sep2, pre = core_pre.partition("-")
    pre_part = f"-{pre}" if sep2 else ""
    parts = core.split(".")
    if len(parts) == 1:
        parts.extend(["0", "0"])
    elif len(parts) == 2:
        parts.append("0")
    return ".".join(parts) + pre_part + build_part


class GoVersionMatcher:
    """semver ordering over Go module versions with the ``v`` prefix stripped."""

    ecosystem_name = "Go"

    def parse(self, version: str) -> Version | None:
        """Parse a Go module version. Returns ``None`` for invalid input."""
        try:
            return Version.parse(_pad(_strip_prefix(version)))
        except ValueError:
            return None

    def compare(self, left: Version, right: Version) -> int:
        """-1 / 0 / 1 ordering per semver.org (which Go uses for module versions)."""
        if left < right:
            return -1
        if left > right:
            return 1
        return 0