from __future__ import annotations

import pytest

from aegis.parsers._common import exact_pin, npm_exact, parent_links


@pytest.mark.parametrize(
    ("constraint", "expected"),
    [
        ("==1.2.3", "1.2.3"),
        ("===1.2.3", "1.2.3"),
        ("1.2.3", "1.2.3"),
        ("==1.0.post1", "1.0.post1"),
        ("1!2.0", "1!2.0"),
        (">=1.0,==1.2.0", "1.2.0"),
        ("==1.2.*", None),
        (">=1,<2", None),
        ("~=1.4.2", None),
        ("!=1.5.0", None),
        ("^1.2", None),
        ("*", None),
        ("", None),
    ],
)
def test_exact_pin(constraint: str, expected: str | None) -> None:
    assert exact_pin(constraint) == expected


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("1.2.3", "1.2.3"),
        ("=1.2.3", "1.2.3"),
        ("v1.2.3", "1.2.3"),
        ("1.2.3-beta.1+b5", "1.2.3-beta.1"),
        ("^1.2.3", None),
        ("1.2", None),
        ("1.x", None),
        ("*", None),
        (">=1.0.0", None),
        ("1.2.3 - 2.0.0", None),
        ("git+https://example.com/x.git", None),
        ("latest", None),
    ],
)
def test_npm_exact(spec: str, expected: str | None) -> None:
    assert npm_exact(spec) == expected


def test_parent_links_prefers_bfs_then_falls_back() -> None:
    edges = {"r": ["a", "b"], "a": ["c"], "b": ["c", "d"], "x": ["y"]}
    assert parent_links(edges, ["r"]) == {"a": "r", "b": "r", "c": "a", "d": "b", "y": "x"}


def test_parent_links_without_roots_uses_smallest_parent() -> None:
    assert parent_links({"p": ["q"], "q": ["r"], "z": ["r"]}, []) == {"q": "p", "r": "q"}


def test_parent_links_ignores_self_loops() -> None:
    assert parent_links({"a": ["a"]}, []) == {}
