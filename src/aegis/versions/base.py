"""VersionMatcher protocol."""

from __future__ import annotations

from typing import Protocol, TypeVar

P = TypeVar("P")


class VersionMatcher(Protocol[P]):
    """Per-ecosystem version ordering.

    ``parse`` returns an opaque, matcher-specific comparable, or ``None`` if the
    version cannot be parsed. ``compare`` orders two values produced by the same
    matcher and returns -1, 0, or 1.
    """

    ecosystem_name: str

    def parse(self, version: str) -> P | None:
        """Parse a version string into a comparable value, or ``None`` if invalid."""
        ...

    def compare(self, left: P, right: P) -> int:
        """Return -1 if left < right, 0 if equal, 1 if left > right."""
        ...
