"""npm semver version and range evaluation.

Version parsing and ordering use the ``semver`` package (semver.org semantics, correctly
handling pre-release identifier comparison and build-metadata ignorance). Range grammar
(caret, tilde, wildcards, hyphen ranges, ``||``) has no Python equivalent, so it is
translated locally into a list of comparators; the comparisons themselves use
``semver.Version``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from semver import Version

_PARTIAL = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?$")
_WILDCARD = re.compile(r"^[xX*]$")


def _pad(text: str) -> str:
    """Pad ``1`` to ``1.0.0`` and ``1.2`` to ``1.2.0``; preserve pre-release and build."""
    text = text.strip()
    core_pre, sep, build = text.partition("+")
    build_part = f"+{build}" if sep else ""
    core, sep2, pre = core_pre.partition("-")
    pre_part = f"-{pre}" if sep2 else ""
    parts = core.split(".")
    if len(parts) == 1:
        parts.extend(["0", "0"])
    elif len(parts) == 2:
        parts.append("0")
    return ".".join(parts) + pre_part + build_part


class NpmVersionMatcher:
    """npm semver ordering, delegating comparison to the ``semver`` package."""

    ecosystem_name = "npm"

    def parse(self, version: str) -> Version | None:
        """Parse an npm version. Partial versions like ``1.2`` are padded to ``1.2.0``."""
        try:
            return Version.parse(_pad(version))
        except ValueError:
            return None

    def compare(self, left: Version, right: Version) -> int:
        """-1 / 0 / 1 ordering per semver.org."""
        if left < right:
            return -1
        if left > right:
            return 1
        return 0


# ---- range grammar -----------------------------------------------------------


@dataclass(frozen=True)
class Comparator:
    """One comparison in an npm range: version <op> bound, with op in ``< <= > >= =``."""

    op: str
    version: Version

    def holds(self, candidate: Version) -> bool:
        """Whether ``candidate`` satisfies this comparison."""
        if self.op == "<":
            return candidate < self.version
        if self.op == "<=":
            return candidate <= self.version
        if self.op == ">":
            return candidate > self.version
        if self.op == ">=":
            return candidate >= self.version
        return candidate == self.version  # "="


def parse_range(range_str: str) -> list[list[Comparator]] | None:
    """Parse an npm range into OR alternatives of AND comparators.

    Returns ``None`` if any token is unparseable. An empty alternative (``[]``) means
    "accept everything".
    """
    alternatives: list[list[Comparator]] = []
    for raw_alt in range_str.split("||"):
        alt = raw_alt.strip()
        if not alt or alt == "*":
            alternatives.append([])
            continue
        if " - " in alt:
            low_text, _, high_text = alt.partition(" - ")
            low = _parse_full(low_text.strip())
            high = _parse_full(high_text.strip())
            if low is None or high is None:
                return None
            alternatives.append([Comparator(">=", low), Comparator("<=", high)])
            continue
        comparators: list[Comparator] = []
        for piece in alt.split():
            expanded = _expand_token(piece)
            if expanded is None:
                return None
            comparators.extend(expanded)
        alternatives.append(comparators)
    return alternatives


def accepts(range_str: str, candidate: Version) -> bool | None:
    """Whether ``candidate`` satisfies ``range_str``; ``None`` if the range is unparseable."""
    alternatives = parse_range(range_str)
    if alternatives is None:
        return None
    return any(all(c.holds(candidate) for c in alt) for alt in alternatives)


def _parse_full(text: str) -> Version | None:
    """Parse a version that must have all three numeric components."""
    try:
        return Version.parse(_pad(text))
    except ValueError:
        return None


def _parse_parts(text: str) -> tuple[int, int | None, int | None] | None:
    """Parse ``1`` / ``1.2`` / ``1.2.3`` into a tuple, or ``None`` if malformed."""
    match = _PARTIAL.match(text)
    if match is None:
        return None
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else None
    patch = int(match.group(3)) if match.group(3) is not None else None
    return major, minor, patch


def _expand_token(text: str) -> list[Comparator] | None:
    """Expand one whitespace-free npm range token into comparators."""
    text = text.strip()
    if not text or text == "*":
        return []
    for op in (">=", "<=", ">", "<"):
        if text.startswith(op):
            version = _parse_full(text[len(op) :])
            return None if version is None else [Comparator(op, version)]
    if text.startswith("="):
        return _exact(text[1:])
    if text.startswith("^"):
        return _caret(text[1:])
    if text.startswith("~"):
        return _tilde(text[1:])
    return _wildcard_or_exact(text)


def _exact(text: str) -> list[Comparator] | None:
    version = _parse_full(text)
    return None if version is None else [Comparator("=", version)]


def _caret(text: str) -> list[Comparator] | None:
    """Caret expansion.

    ``^1.2.3`` -> ``>=1.2.3 <2.0.0``; ``^0.2.3`` -> ``>=0.2.3 <0.3.0``;
    ``^0.0.3`` -> ``>=0.0.3 <0.0.4``; ``^1.2`` -> ``>=1.2.0 <2.0.0``;
    ``^0.0`` -> ``>=0.0.0 <0.1.0``; ``^0`` -> ``>=0.0.0 <1.0.0``.
    """
    parts = _parse_parts(text)
    if parts is None:
        return None
    major, minor, patch = parts
    if minor is None:
        lower = Version(major, 0, 0)
        upper = Version(major + 1, 0, 0)
    elif patch is None:
        lower = Version(major, minor, 0)
        upper = Version(0, minor + 1, 0) if major == 0 else Version(major + 1, 0, 0)
    elif major > 0:
        lower = Version(major, minor, patch)
        upper = Version(major + 1, 0, 0)
    elif minor > 0:
        lower = Version(major, minor, patch)
        upper = Version(0, minor + 1, 0)
    else:
        lower = Version(0, 0, patch)
        upper = Version(0, 0, patch + 1)
    return [Comparator(">=", lower), Comparator("<", upper)]


def _tilde(text: str) -> list[Comparator] | None:
    """Tilde expansion.

    ``~1.2.3`` -> ``>=1.2.3 <1.3.0``; ``~1.2`` -> ``>=1.2.0 <1.3.0``;
    ``~1`` -> ``>=1.0.0 <2.0.0``.
    """
    parts = _parse_parts(text)
    if parts is None:
        return None
    major, minor, patch = parts
    if minor is None:
        lower = Version(major, 0, 0)
        upper = Version(major + 1, 0, 0)
    else:
        lower = Version(major, minor, patch if patch is not None else 0)
        upper = Version(major, minor + 1, 0)
    return [Comparator(">=", lower), Comparator("<", upper)]


def _wildcard_or_exact(text: str) -> list[Comparator] | None:
    """Wildcard, partial wildcard, or exact.

    ``1.2.3`` -> exact; ``1.2`` -> ``>=1.2.0 <1.3.0``; ``1`` -> ``>=1.0.0 <2.0.0``;
    ``1.2.x`` and ``1.2.*`` -> same as ``1.2``; ``1.x`` and ``1.*`` -> same as ``1``.
    """
    pieces = text.split(".")
    wildcard_at: int | None = None
    for index, piece in enumerate(pieces):
        if _WILDCARD.match(piece):
            wildcard_at = index
            break
    if wildcard_at is None and len(pieces) < 3:
        wildcard_at = len(pieces)
    if wildcard_at is not None:
        numeric = pieces[:wildcard_at]
        if not all(p.isdigit() for p in numeric):
            return None
        parts = _parse_parts(".".join(numeric) if numeric else "0")
        if parts is None:
            return None
        major, minor, _patch = parts
        if wildcard_at == 0:
            return []
        if wildcard_at == 1:
            lower = Version(major, 0, 0)
            upper = Version(major + 1, 0, 0)
        else:
            lower = Version(major, minor if minor is not None else 0, 0)
            upper = Version(major, (minor or 0) + 1, 0)
        return [Comparator(">=", lower), Comparator("<", upper)]
    version = _parse_full(text)
    return None if version is None else [Comparator("=", version)]