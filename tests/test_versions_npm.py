from __future__ import annotations

import pytest

from aegis.versions.npm import NpmVersionMatcher, accepts, parse_range

MATCHER = NpmVersionMatcher()


def _v(text: str):  # type: ignore[no-untyped-def]
    parsed = MATCHER.parse(text)
    assert parsed is not None, text
    return parsed


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0.0", "1.0.1", -1),
        ("1.0.1", "1.0.0", 1),
        ("1.0.0", "1.0.0", 0),
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-alpha", "1.0.0-alpha.1", -1),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
        ("1.0.0-alpha.beta", "1.0.0-beta", -1),
        ("1.0.0-beta.2", "1.0.0-beta.11", -1),
        ("1.0.0-beta.11", "1.0.0-rc.1", -1),
        ("1.0.0+build.1", "1.0.0+build.2", 0),
        ("1.0", "1.0.0", 0),
        ("1", "1.0.0", 0),
    ],
)
def test_compare(left: str, right: str, expected: int) -> None:
    assert MATCHER.compare(_v(left), _v(right)) == expected


@pytest.mark.parametrize("bad", ["", "x", "1.2.3.4", "1.2.3-", "1.2.3-alpha..1"])
def test_parse_invalid(bad: str) -> None:
    assert MATCHER.parse(bad) is None


@pytest.mark.parametrize(
    ("range_str", "version", "expected"),
    [
        ("1.2.3", "1.2.3", True),
        ("1.2.3", "1.2.4", False),
        ("=1.2.3", "1.2.3", True),
        (">=1.2.3", "1.2.3", True),
        (">1.2.3", "1.2.3", False),
        ("<=1.2.3", "1.2.3", True),
        ("<1.2.3", "1.2.3", False),
        ("^1.2.3", "1.2.3", True),
        ("^1.2.3", "1.9.0", True),
        ("^1.2.3", "2.0.0", False),
        ("^1.2.3", "1.2.2", False),
        ("^0.2.3", "0.2.3", True),
        ("^0.2.3", "0.2.9", True),
        ("^0.2.3", "0.3.0", False),
        ("^0.0.3", "0.0.3", True),
        ("^0.0.3", "0.0.4", False),
        ("^1.2", "1.5.0", True),
        ("^1.2", "2.0.0", False),
        ("^0.0", "0.0.9", True),
        ("^0.0", "0.1.0", False),
        ("^0", "0.5.0", True),
        ("^0", "1.0.0", False),
        ("~1.2.3", "1.2.3", True),
        ("~1.2.3", "1.2.99", True),
        ("~1.2.3", "1.3.0", False),
        ("~1.2", "1.2.99", True),
        ("~1.2", "1.3.0", False),
        ("~1", "1.9.9", True),
        ("~1", "2.0.0", False),
        ("1.x", "1.5.0", True),
        ("1.x", "2.0.0", False),
        ("1.2.x", "1.2.9", True),
        ("1.2.x", "1.3.0", False),
        ("1.*", "1.5.0", True),
        ("1", "1.5.0", True),
        ("1", "2.0.0", False),
        ("1.2", "1.2.5", True),
        ("1.2", "1.3.0", False),
        ("1.2.3 - 2.3.4", "1.2.2", False),
        ("1.2.3 - 2.3.4", "1.2.3", True),
        ("1.2.3 - 2.3.4", "2.3.4", True),
        ("1.2.3 - 2.3.4", "2.3.5", False),
        (">=1.2.3 <2.0.0", "1.5.0", True),
        (">=1.2.3 <2.0.0", "2.0.0", False),
        ("^1.0.0 || ^2.0.0", "1.5.0", True),
        ("^1.0.0 || ^2.0.0", "2.5.0", True),
        ("^1.0.0 || ^2.0.0", "3.0.0", False),
        ("*", "9.9.9", True),
        ("", "9.9.9", True),
    ],
)
def test_range_accepts(range_str: str, version: str, expected: bool) -> None:
    assert accepts(range_str, _v(version)) is expected


def test_unparseable_range_returns_none() -> None:
    assert accepts("not a range", _v("1.0.0")) is None
    assert parse_range(">=1.2.3 || ~foo") is None


def test_empty_alternative_accepts_anything() -> None:
    alternatives = parse_range("*")
    assert alternatives == [[]]
