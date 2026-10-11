"""Per-ecosystem package name normalization, applied before lookup and dedup."""

from __future__ import annotations

import re

from aegis.core.enums import Ecosystem

_PEP503_SEPARATORS = re.compile(r"[-_.]+")


def normalize_name(ecosystem: Ecosystem, name: str) -> str:
    """Normalize a package name.

    PyPI follows PEP 503. npm names and Go module paths are case-sensitive and kept as-is
    (surrounding whitespace is stripped).
    """
    stripped = name.strip()
    if ecosystem is Ecosystem.PYPI:
        return _PEP503_SEPARATORS.sub("-", stripped).lower()
    return stripped
