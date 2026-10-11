from __future__ import annotations

import pytest

from aegis.versions.go import GoVersionMatcher

MATCHER = GoVersionMatcher()


def _v(text: str):  # type: ignore[no-untyped-def]
    parsed = MATCHER.parse(text)
    assert parsed is not None, text
    return parsed


@pytest.mark.parametrize(
    ("version", "expected_ok"),
    [
        ("v1.2.3", True),
        ("1.2.3", True),
        ("v0.0.0-20210101000000-abcdef123456", True),
        ("v2.0.0+incompatible", True),
        ("v1.2", True),
        ("", False),
        ("not-a-version", False),
    ],
)
def test_parse(version: str, expected_ok: bool) -> None:
    parsed = MATCHER.parse(version)
    assert (parsed is not None) is expected_ok


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("v1.2.3", "v1.3.0", -1),
        ("v1.3.0", "v1.2.3", 1),
        ("v1.2.3", "v1.2.3", 0),
        ("v1.2.3", "1.2.3", 0),
        ("v0.0.0-20210101000000-abcdef123456", "v0.0.0", -1),
        ("v0.0.0-20210101000000-abcdef123456", "v0.0.0-20220101000000-abcdef123456", -1),
        ("v2.0.0+incompatible", "v2.0.0", 0),
    ],
)
def test_compare(left: str, right: str, expected: int) -> None:
    assert MATCHER.compare(_v(left), _v(right)) == expected
