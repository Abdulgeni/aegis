from __future__ import annotations

import pytest

from aegis.core.enums import Ecosystem
from aegis.versions.constraints import constraint_accepts

PYPI = Ecosystem.PYPI
NPM = Ecosystem.NPM


@pytest.mark.parametrize(
    ("constraint", "version", "expected"),
    [
        (">=1.0,<2.0", "1.5.0", True),
        (">=1.0,<2.0", "2.0.0", False),
        ("~=1.4.2", "1.4.5", True),
        ("~=1.4.2", "1.5.0", False),
        ("==1.4.*", "1.4.7", True),
        ("==1.4.*", "1.5.0", False),
        ("!=1.5.0", "1.5.0", False),
        ("!=1.5.0", "1.5.1", True),
        ("==1.0rc1", "1.0rc1", True),
        ("==1.0rc1", "1.0", False),
        ("", "1.0.0", True),
    ],
)
def test_pypi_constraints(constraint: str, version: str, expected: bool) -> None:
    assert constraint_accepts(PYPI, constraint, version) is expected


@pytest.mark.parametrize(
    ("constraint", "version", "expected"),
    [
        ("^1.2.3", "1.5.0", True),
        ("^1.2.3", "2.0.0", False),
        ("^0.2.3", "0.2.9", True),
        ("^0.2.3", "0.3.0", False),
        ("~1.2.3", "1.2.9", True),
        ("~1.2.3", "1.3.0", False),
        ("1.x", "1.9.9", True),
        ("1.x", "2.0.0", False),
        (">=1.0.0 <2.0.0", "1.5.0", True),
        (">=1.0.0 <2.0.0", "2.5.0", False),
        ("^1.0.0 || ^2.0.0", "1.5.0", True),
        ("^1.0.0 || ^2.0.0", "2.5.0", True),
        ("^1.0.0 || ^2.0.0", "3.0.0", False),
    ],
)
def test_npm_constraints(constraint: str, version: str, expected: bool) -> None:
    assert constraint_accepts(NPM, constraint, version) is expected


def test_bare_version_is_not_a_valid_pypi_constraint() -> None:
    # PEP 440 constraints require an operator (==, >=, ~=, ...). A bare version string
    # like "1.0rc1" is not a valid SpecifierSet, so this returns None (unverifiable).
    # Poetry manifests with `flask = "1.0rc1"` are handled by the parser's exact_pin
    # helper, which produces a `version` value, not a constraint string.
    assert constraint_accepts(PYPI, "1.0rc1", "1.0rc1") is None


def test_unverifiable_returns_none() -> None:
    assert constraint_accepts(PYPI, "not a specifier", "1.0.0") is None
    assert constraint_accepts(PYPI, ">=1.0", "bad version") is None
    assert constraint_accepts(NPM, "not a range", "1.0.0") is None
    assert constraint_accepts(Ecosystem.GO, ">=1.0", "v1.0.0") is None


def test_npm_constraint_with_partial_version_input() -> None:
    assert constraint_accepts(NPM, "^1.0.0", "1.2") is True