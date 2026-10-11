"""Version parsing and constraint/range evaluation."""

from __future__ import annotations

from typing import Any

from aegis.core.enums import Ecosystem
from aegis.versions.base import VersionMatcher
from aegis.versions.go import GoVersionMatcher
from aegis.versions.npm import NpmVersionMatcher
from aegis.versions.pypi import PypiVersionMatcher

_MATCHERS: dict[Ecosystem, VersionMatcher[Any]] = {
    Ecosystem.PYPI: PypiVersionMatcher(),
    Ecosystem.NPM: NpmVersionMatcher(),
    Ecosystem.GO: GoVersionMatcher(),
}


def matcher_for(ecosystem: Ecosystem) -> VersionMatcher[Any]:
    """The VersionMatcher for an ecosystem. Matchers are stateless and shared."""
    return _MATCHERS[ecosystem]


__all__ = ["VersionMatcher", "matcher_for"]
