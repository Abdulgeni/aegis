"""Compute the minimum safe fixed version for one finding.

Gathers ``fixed`` events from every applicable range of a vuln. If any applicable range
has no ``fixed`` event, the finding is marked ``NO_FIX``. Otherwise the maximum ``fixed``
value across applicable ranges is the candidate; it is then re-verified against the whole
vuln's affected ranges (a higher fix may land in a later vulnerable window). If the
candidate is still affected, we try the next higher candidate; if none works, the finding
is ``UNRESOLVED``.

Ecosystem-specific distance computation lives in ``_distance``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from packaging.version import InvalidVersion
from packaging.version import Version as PyVersion
from semver import Version as SemverVersion

from aegis.core.enums import Ecosystem
from aegis.core.models import (
    Dependency,
    FixStatus,
    Remediation,
    UpgradeDistance,
)
from aegis.core.names import normalize_name
from aegis.osv.models import Affected, VulnRecord
from aegis.remediation.commands import suggest_command
from aegis.versions import matcher_for
from aegis.versions.osv_ranges import RangeVerdict, evaluate


def fix_for(
    record: VulnRecord,
    ecosystem: Ecosystem,
    name: str,
    current: str,
    direct: bool | None,
    group: Sequence[Dependency],
) -> Remediation:
    """Compute remediation guidance for one finding."""
    applicable = [entry for entry in record.affected if _matches(entry, ecosystem, name)]
    if not applicable:
        return Remediation(status=FixStatus.NO_FIX)

    candidates = _fixed_candidates(applicable)
    if candidates is None:
        return Remediation(status=FixStatus.NO_FIX)

    ordered = _sorted_candidates(candidates, ecosystem)
    for candidate in ordered:
        if not _still_affected(record, ecosystem, name, candidate):
            return _remediation(record, ecosystem, name, current, candidate, direct, group)
    return Remediation(status=FixStatus.UNRESOLVED, fixed_version=ordered[-1] if ordered else None)


def _fixed_candidates(applicable: list[Affected]) -> list[str] | None:
    """Union of ``fixed`` events across applicable ranges; ``None`` if any range lacks one."""
    candidates: list[str] = []
    for entry in applicable:
        found_any = False
        for range_ in entry.ranges:
            events = range_.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, Mapping):
                    continue
                value = event.get("fixed")
                if isinstance(value, str) and value:
                    candidates.append(value)
                    found_any = True
        if entry.ranges and not found_any:
            return None
    if not candidates:
        return None
    return list(dict.fromkeys(candidates))  # dedupe, preserve order


def _sorted_candidates(candidates: list[str], ecosystem: Ecosystem) -> list[str]:
    """Sort candidates ascending by ecosystem-specific version ordering."""
    matcher = matcher_for(ecosystem)
    parseable: list[tuple[Any, str]] = []
    unparseable: list[str] = []
    for value in candidates:
        parsed = matcher.parse(value)
        if parsed is None:
            unparseable.append(value)
        else:
            parseable.append((parsed, value))
    parseable.sort(key=lambda pair: pair[0])
    return [value for _, value in parseable] + sorted(unparseable)


def _still_affected(record: VulnRecord, ecosystem: Ecosystem, name: str, candidate: str) -> bool:
    """Whether ``candidate`` is still in any applicable vulnerable range."""
    matcher = matcher_for(ecosystem)
    for entry in record.affected:
        if not _matches(entry, ecosystem, name):
            continue
        if entry.versions and candidate in entry.versions:
            return True
        if entry.ranges:
            verdict = evaluate(candidate, list(entry.ranges), matcher)
            if verdict is RangeVerdict.AFFECTED:
                return True
    return False


def _matches(entry: Affected, ecosystem: Ecosystem, name: str) -> bool:
    entry_eco = Ecosystem.parse(entry.package.ecosystem)
    if entry_eco is not ecosystem:
        return False
    return normalize_name(ecosystem, entry.package.name) == name


def _remediation(
    record: VulnRecord,
    ecosystem: Ecosystem,
    name: str,
    current: str,
    fixed: str,
    direct: bool | None,
    group: Sequence[Dependency],
) -> Remediation:
    distance = _distance(ecosystem, current, fixed)
    safe_upgrade = distance in (UpgradeDistance.PATCH, UpgradeDistance.MINOR)
    path = _dependency_path(group)
    command, alternatives = suggest_command(ecosystem, name, fixed, direct, group)
    return Remediation(
        fixed_version=fixed,
        status=FixStatus.AVAILABLE,
        distance=distance,
        safe_upgrade=safe_upgrade,
        command=command,
        alternatives=alternatives,
        path=path,
    )


def _dependency_path(group: Sequence[Dependency]) -> tuple[str, ...]:
    """Shortest resolved_from chain from a direct ancestor down to this dependency."""
    parents: dict[str, str | None] = {}
    for dep in group:
        key = f"{dep.name}@{dep.version}" if dep.version else dep.name
        parents.setdefault(key, dep.resolved_from)
    chain: list[str] = []
    first = group[0]
    start = f"{first.name}@{first.version}" if first.version else first.name
    seen: set[str] = set()
    current: str | None = start
    while current is not None and current not in seen:
        seen.add(current)
        chain.append(current)
        current = parents.get(current)
    chain.reverse()
    return tuple(chain)


def _distance(ecosystem: Ecosystem, current: str, fixed: str) -> UpgradeDistance | None:
    """patch / minor / major from current to fixed. ``None`` if either is unparseable."""
    if ecosystem is Ecosystem.PYPI:
        return _distance_pypi(current, fixed)
    if ecosystem in (Ecosystem.NPM, Ecosystem.GO):
        return _distance_semver(current, fixed)
    return None


def _distance_pypi(current: str, fixed: str) -> UpgradeDistance | None:
    try:
        a = PyVersion(current)
        b = PyVersion(fixed)
    except InvalidVersion:
        return None
    if a >= b:
        return UpgradeDistance.PATCH
    if a.release[:1] != b.release[:1]:
        return UpgradeDistance.MAJOR
    if a.release[:2] != b.release[:2]:
        return UpgradeDistance.MINOR
    return UpgradeDistance.PATCH


def _distance_semver(current: str, fixed: str) -> UpgradeDistance | None:
    try:
        a = SemverVersion.parse(_pad(current))
        b = SemverVersion.parse(_pad(fixed))
    except ValueError:
        return None
    if a.major != b.major:
        return UpgradeDistance.MAJOR
    if a.major == 0:
        # 0.x: a minor bump is treated as major-equivalent for "safe_upgrade".
        if a.minor != b.minor:
            return UpgradeDistance.MAJOR
        return UpgradeDistance.PATCH
    if a.minor != b.minor:
        return UpgradeDistance.MINOR
    return UpgradeDistance.PATCH


def _pad(text: str) -> str:
    """Pad ``1`` / ``1.2`` to three components so semver can parse them."""
    body, sep, rest = text.partition("+")
    core, sep2, pre = body.partition("-")
    parts = core.split(".")
    while len(parts) < 3:
        parts.append("0")
    rebuilt = ".".join(parts)
    if sep2:
        rebuilt += f"-{pre}"
    if sep:
        rebuilt += f"+{rest}"
    return rebuilt


__all__ = ["fix_for"]
