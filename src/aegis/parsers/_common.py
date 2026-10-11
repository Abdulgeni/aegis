"""Helpers shared by parsers."""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from aegis.core.enums import Ecosystem, NoticeCode, NoticeLevel
from aegis.core.models import Notice, ParseResult
from aegis.core.names import normalize_name

_NPM_EXACT = re.compile(r"^[=v]?\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:\+[0-9A-Za-z.-]+)?$")


def info(code: NoticeCode, message: str, path: str | None) -> Notice:
    """Build an INFO notice."""
    return Notice(level=NoticeLevel.INFO, code=code, message=message, path=path)


def warn(code: NoticeCode, message: str, path: str | None) -> Notice:
    """Build a WARNING notice."""
    return Notice(level=NoticeLevel.WARNING, code=code, message=message, path=path)


def failed(path: str, reason: str) -> ParseResult:
    """A whole-file parse failure: no dependencies and one PARSE_FAILED warning."""
    return ParseResult(notices=(warn(NoticeCode.PARSE_FAILED, reason, path),))


def partial_parse(path: str, skipped: Sequence[str]) -> Notice:
    """Warn that some entries were skipped (lists up to five)."""
    shown = ", ".join(skipped[:5]) + (", ..." if len(skipped) > 5 else "")
    message = f"skipped unparseable entries ({len(skipped)}): {shown}"
    return warn(NoticeCode.PARTIAL_PARSE, message, path)


def as_table(value: object) -> dict[str, Any]:
    """`value` if it is a mapping, else an empty dict (for untrusted TOML/JSON)."""
    return value if isinstance(value, dict) else {}


def as_strings(value: object) -> list[str]:
    """The string items of `value` if it is a list, else an empty list."""
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def load_json_object(content: str) -> dict[str, Any] | None:
    """Parse a JSON object; None for invalid JSON, non-objects, or absurd nesting."""
    try:
        data = json.loads(content)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _is_version(text: str) -> bool:
    try:
        Version(text)
    except InvalidVersion:
        return False
    return True


def exact_pin(constraint: str) -> str | None:
    """The exact version a PEP 440 or Poetry constraint pins, else None.

    A bare version (Poetry style) or an `==`/`===` clause without wildcard pins.
    """
    text = constraint.strip()
    if not text or "*" in text:
        return None
    if _is_version(text):
        return text
    try:
        specifiers = SpecifierSet(text)
    except InvalidSpecifier:
        return None
    for spec in specifiers:
        if spec.operator in ("==", "===") and not spec.version.endswith(".*"):
            return spec.version
    return None


def npm_exact(spec: str) -> str | None:
    """The exact version of an npm spec like `1.2.3`, `=1.2.3` or `v1.2.3`, else None.

    Build metadata is dropped, since it does not affect version precedence.
    """
    match = _NPM_EXACT.match(spec.strip())
    return match.group(1) if match else None


def parse_requirement_string(text: str) -> tuple[str, str | None] | None:
    """Parse a PEP 508 string into (normalized PyPI name, exact pin or None)."""
    try:
        requirement = Requirement(text)
    except InvalidRequirement:
        return None
    pin = exact_pin(str(requirement.specifier)) if requirement.specifier else None
    return normalize_name(Ecosystem.PYPI, requirement.name), pin


def parent_links(edges: Mapping[str, Sequence[str]], roots: Iterable[str]) -> dict[str, str]:
    """Map each child node to a parent node.

    Parents come from a breadth-first search from `roots` (a shortest path, ties broken by
    sorted order). Nodes the search does not reach fall back to the lexicographically
    smallest node listing them as a child. Roots themselves get no parent.
    """
    parents: dict[str, str] = {}
    seen = set(roots)
    queue = deque(sorted(seen))
    while queue:
        node = queue.popleft()
        for child in sorted(edges.get(node, ())):
            if child not in seen:
                seen.add(child)
                parents[child] = node
                queue.append(child)
    for node in sorted(edges):
        for child in edges[node]:
            if child != node and child not in seen:
                parents.setdefault(child, node)
    return parents
