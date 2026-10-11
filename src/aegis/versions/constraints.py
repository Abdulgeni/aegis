"""Evaluate manifest constraint strings for remediation ranking (used in Step 6).

Two jobs share the same entry point:

* PyPI constraints are PEP 440 specifier sets, delegated to ``packaging``.
* npm constraints use the range grammar in ``versions/npm.py``.

Return value is tri-state: ``True`` (satisfied), ``False`` (not satisfied), ``None``
(unverifiable - malformed constraint or version). ``None`` results must be surfaced as a
warning, not silently treated as a pass or a fail.
"""

from __future__ import annotations

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from semver import Version as SemverVersion

from aegis.core.enums import Ecosystem
from aegis.versions.npm import _pad as npm_pad
from aegis.versions.npm import accepts as npm_accepts


def constraint_accepts(ecosystem: Ecosystem, constraint: str, version: str) -> bool | None:
    """Does ``version`` satisfy ``constraint``? ``None`` if unverifiable."""
    if ecosystem is Ecosystem.PYPI:
        return _pypi_accepts(constraint, version)
    if ecosystem is Ecosystem.NPM:
        return _npm_accepts(constraint, version)
    return None


def _pypi_accepts(constraint: str, version: str) -> bool | None:
    try:
        specifiers = SpecifierSet(constraint)
    except InvalidSpecifier:
        return None
    try:
        candidate = Version(version)
    except InvalidVersion:
        return None
    return candidate in specifiers


def _npm_accepts(constraint: str, version: str) -> bool | None:
    try:
        parsed = SemverVersion.parse(npm_pad(version))
    except ValueError:
        return None
    return npm_accepts(constraint, parsed)