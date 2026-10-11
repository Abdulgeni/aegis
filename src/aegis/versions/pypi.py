"""PEP 440 version matching via ``packaging``."""

from __future__ import annotations

from packaging.version import InvalidVersion, Version


class PypiVersionMatcher:
    """Full PEP 440 semantics, including epochs, pre-releases, and post-releases.

    Delegates entirely to ``packaging.version.Version``; no ordering is hand-rolled.
    """

    ecosystem_name = "PyPI"

    def parse(self, version: str) -> Version | None:
        """Parse a PEP 440 version, or ``None`` if invalid."""
        try:
            return Version(version.strip())
        except InvalidVersion:
            return None

    def compare(self, left: Version, right: Version) -> int:
        """-1 / 0 / 1 ordering per PEP 440."""
        if left < right:
            return -1
        if left > right:
            return 1
        return 0
