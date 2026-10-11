from __future__ import annotations

import pytest

from aegis.versions.pypi import PypiVersionMatcher

MATCHER = PypiVersionMatcher()


@pytest.mark.parametrize(
    "version",
    ["1.0", "1.0.0", "1.0rc1", "1.0.post1", "1!1.0", "2.0.0.dev5", "1.0.0+local"],
)
def test_parse_valid(version: str) -> None:
    assert MATCHER.parse(version) is not None


@pytest.mark.parametrize("version", ["", "not-a-version", "1.0.0-"])
def test_parse_invalid(version: str) -> None:
    assert MATCHER.parse(version) is None


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0", "1.0.1", -1),
        ("1.0.1", "1.0", 1),
        ("1.0", "1.0", 0),
        ("1.0rc1", "1.0", -1),
        ("1.0.0a1", "1.0.0", -1),
        ("1.0.post1", "1.0", 1),
        ("1!1.0", "999.0", 1),
        ("0!1.0", "1.0", 0),
    ],
)
def test_compare(left: str, right: str, expected: int) -> None:
    a, b = MATCHER.parse(left), MATCHER.parse(right)
    assert a is not None and b is not None
    assert MATCHER.compare(a, b) == expected