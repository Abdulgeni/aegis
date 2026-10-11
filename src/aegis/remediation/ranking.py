"""Composite sort key for findings.

Ordering (most important first):

1. Severity: CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN.
2. Direct before transitive (``direct=True`` first, then ``None``, then ``False``).
3. Smaller upgrade jump first (patch < minor < major).
4. Package name.
5. Vuln ID.
"""

from __future__ import annotations

from aegis.core.models import Finding, UpgradeDistance

_DISTANCE_ORDER: dict[UpgradeDistance | None, int] = {
    UpgradeDistance.PATCH: 0,
    UpgradeDistance.MINOR: 1,
    UpgradeDistance.MAJOR: 2,
    None: 3,  # unknown / no fix yet: sorted last
}
_DIRECT_ORDER: dict[bool | None, int] = {True: 0, None: 1, False: 2}


def sort_key(finding: Finding) -> tuple[int, int, int, str, str]:
    """Stable, total ordering key for the composite rank."""
    return (
        -finding.severity.rank,
        _DIRECT_ORDER.get(finding.direct, 2),
        _DISTANCE_ORDER.get(finding.remediation.distance, 3),
        finding.package,
        finding.vuln_id,
    )


def rank(findings: list[Finding]) -> list[Finding]:
    """Return ``findings`` sorted by the composite key."""
    return sorted(findings, key=sort_key)
