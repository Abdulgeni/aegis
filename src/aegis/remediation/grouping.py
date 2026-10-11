"""Group-fixable detection.

Findings in the same ecosystem and lockfile whose fixes are all satisfied by one
``package manager upgrade`` command are tagged with the same ``group_id``. We do not
merge them into one finding; the reporter uses the tag to display them together.
"""

from __future__ import annotations

import hashlib

from aegis.core.models import Finding, FixStatus

_GROUP_PREFIX = "G"


def assign_groups(findings: list[Finding]) -> list[Finding]:
    """Return ``findings`` with ``group_id`` set where a group of ≥2 exists."""
    buckets: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        if finding.remediation.status is not FixStatus.AVAILABLE:
            continue
        primary_source = finding.sources[0] if finding.sources else ""
        key = (finding.ecosystem.value, primary_source)
        buckets.setdefault(key, []).append(finding)

    groups: dict[tuple[str, str], str] = {}
    counter = 1
    for key in sorted(buckets):
        members = buckets[key]
        if len(members) < 2:
            continue
        digest = hashlib.sha256(f"{key[0]}|{key[1]}".encode()).hexdigest()[:8]
        groups[key] = f"{_GROUP_PREFIX}{counter:03d}-{digest}"
        counter += 1

    out: list[Finding] = []
    for finding in findings:
        if finding.remediation.status is not FixStatus.AVAILABLE:
            out.append(finding)
            continue
        primary_source = finding.sources[0] if finding.sources else ""
        key = (finding.ecosystem.value, primary_source)
        group_id = groups.get(key)
        out.append(finding.model_copy(update={"group_id": group_id}) if group_id else finding)
    return out
