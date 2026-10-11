"""Turn (Dependency, VulnRecord) pairs into Findings.

Applicability rules (per spec):

* A vuln applies if the dependency's version falls in any matching-package
  ``affected[].ranges`` (evaluated with the ecosystem's VersionMatcher), OR appears in
  ``affected[].versions``. Package name AND ecosystem must both match.
* An affected entry with neither ranges nor versions is treated as affecting all
  versions of that package (some OSV records list only the package).
* ``UNVERIFIABLE`` range results still produce a finding with ``unverified=True``; the
  finding is never silently dropped or silently trusted.
* Severity comes from the CVSS vector when present and scorable; otherwise from the GHSA
  text label (``MODERATE`` normalized to ``MEDIUM``); otherwise ``UNKNOWN``.
* ``vuln_id`` is the lexicographically smallest CVE alias, or the OSV id if there is no
  CVE. All aliases (including the OSV id) are kept, sorted, in ``aliases``.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from aegis.core.enums import Ecosystem, NoticeCode, Severity
from aegis.core.models import Dependency, Finding, Notice
from aegis.core.names import normalize_name
from aegis.osv.cvss import score_vector
from aegis.osv.models import Affected, OsvSeverity, VulnRecord
from aegis.parsers._common import warn
from aegis.remediation.fixes import fix_for
from aegis.versions import matcher_for
from aegis.versions.osv_ranges import RangeVerdict, evaluate, evaluate_exact_match

LookupKey = tuple[str, str, str]
RecordsByKey = Mapping[LookupKey, list[VulnRecord]]


def build_findings(
    dependencies: list[Dependency], records: RecordsByKey
) -> tuple[list[Finding], list[Notice]]:
    """Return ``(findings, notices)`` for a full scan."""
    by_key = _aggregate_dependencies(dependencies)
    notices: list[Notice] = []
    findings: list[Finding] = []
    for key, dep_group in by_key.items():
        for record in records.get(key, []):
            finding, record_notices = _evaluate(record, dep_group)
            notices.extend(record_notices)
            if finding is not None:
                findings.append(finding)
    return _dedupe(findings), notices


def _aggregate_dependencies(
    dependencies: list[Dependency],
) -> dict[LookupKey, list[Dependency]]:
    """Group dependencies by ``(ecosystem, name, version)``, keeping source metadata."""
    groups: dict[LookupKey, list[Dependency]] = {}
    for dep in dependencies:
        if dep.version is None:
            continue
        key = (dep.ecosystem.value, dep.name, dep.version)
        groups.setdefault(key, []).append(dep)
    return groups


def _evaluate(record: VulnRecord, group: list[Dependency]) -> tuple[Finding | None, list[Notice]]:
    first = group[0]
    ecosystem = first.ecosystem
    version = first.version
    if version is None:  # unreachable given aggregation, guarded for mypy
        return None, []

    applicable, unverified = _applicability(record, ecosystem, first.name, version)
    if not applicable and not unverified:
        return None, []

    notices = []
    if unverified:
        notices.append(
            warn(
                NoticeCode.UNVERIFIED_RANGE,
                f"{record.id}: some ranges could not be evaluated for "
                f"{ecosystem.value}:{first.name}@{version}; the finding is marked unverified",
                first.source,
            )
        )

    severity, cvss_score, cvss_vector = _severity(record)
    direct = _is_direct(group)
    remediation = fix_for(record, ecosystem, first.name, version, direct, group)
    sources = tuple(sorted({d.source for d in group}))
    line = min((d.line for d in group if d.line is not None), default=None)

    return (
        Finding(
            vuln_id=_display_id(record),
            aliases=_aliases(record),
            package=first.name,
            version=version,
            ecosystem=ecosystem,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            summary=record.summary or _first_line(record.details),
            introduced_version=_introduced(record),
            direct=direct,
            sources=sources,
            line=line,
            remediation=remediation,
            unverified=unverified,
            published=_parse_timestamp(record.published),
            references=tuple(ref.url for ref in record.references if ref.url),
        ),
        notices,
    )


def _applicability(
    record: VulnRecord, ecosystem: Ecosystem, name: str, version: str
) -> tuple[bool, bool]:
    """``(applies, unverified)`` across every affected entry matching this package.

    An entry with neither ranges nor versions is treated as affecting all versions.
    """
    matcher = matcher_for(ecosystem)
    applies = False
    unverified = False
    matched_any = False
    for entry in record.affected:
        if not _matches(entry, ecosystem, name):
            continue
        matched_any = True
        if not entry.ranges and not entry.versions:
            applies = True
            continue
        if entry.ranges:
            range_verdict = evaluate(version, list(entry.ranges), matcher)
            if range_verdict is RangeVerdict.AFFECTED:
                applies = True
            elif range_verdict is RangeVerdict.UNVERIFIABLE:
                unverified = True
        if entry.versions:
            exact_verdict = evaluate_exact_match(version, list(entry.versions), matcher)
            if exact_verdict is RangeVerdict.AFFECTED:
                applies = True
            elif exact_verdict is RangeVerdict.UNVERIFIABLE:
                unverified = True
    if not matched_any:
        return False, False
    return applies, unverified


def _matches(entry: Affected, ecosystem: Ecosystem, name: str) -> bool:
    entry_eco = Ecosystem.parse(entry.package.ecosystem)
    if entry_eco is not ecosystem:
        return False
    return normalize_name(ecosystem, entry.package.name) == name


def _severity(record: VulnRecord) -> tuple[Severity, float | None, str | None]:
    """Pick severity from CVSS if scorable, else from the GHSA text label."""
    _vector, vector_string = _first_cvss_vector(record.severity)
    if vector_string is not None:
        scored = score_vector(vector_string)
        if scored.score is not None:
            return scored.severity_band, scored.score, vector_string
    label = _ghsa_label(record.database_specific, record.severity)
    return label, None, vector_string


def _first_cvss_vector(severities: tuple[OsvSeverity, ...]) -> tuple[object, str | None]:
    """The first severity entry whose ``score`` looks like a CVSS vector."""
    for entry in severities:
        if entry.score.upper().startswith("CVSS:"):
            return entry, entry.score
    return None, None


def _ghsa_label(
    database_specific: Mapping[str, object], severities: tuple[OsvSeverity, ...]
) -> Severity:
    """GHSA text severity from ``database_specific.severity`` or a non-CVSS severity entry."""
    raw = database_specific.get("severity")
    if isinstance(raw, str):
        parsed = Severity.from_label(raw)
        if parsed is not None and parsed is not Severity.UNKNOWN:
            return parsed
    for entry in severities:
        if not entry.score.upper().startswith("CVSS:"):
            parsed = Severity.from_label(entry.score)
            if parsed is not None and parsed is not Severity.UNKNOWN:
                return parsed
    return Severity.UNKNOWN


def _display_id(record: VulnRecord) -> str:
    cves = record.cve_aliases
    return cves[0] if cves else record.id


def _aliases(record: VulnRecord) -> tuple[str, ...]:
    found = {record.id, *record.aliases, *record.cve_aliases}
    found.discard("")
    return tuple(sorted(found))


def _introduced(record: VulnRecord) -> str | None:
    """The lowest ``introduced`` value across all ranges of the record, or ``None``."""
    candidates: list[str] = []
    for entry in record.affected:
        for range_ in entry.ranges:
            events = range_.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, Mapping):
                    value = event.get("introduced")
                    if isinstance(value, str) and value != "0":
                        candidates.append(value)
    return min(candidates) if candidates else None


def _is_direct(group: list[Dependency]) -> bool | None:
    """A dependency is direct if any of its declaring entries say so. All-None -> None."""
    seen = [dep.direct for dep in group]
    if any(flag is True for flag in seen):
        return True
    if all(flag is None for flag in seen):
        return None
    return False


def _first_line(text: str) -> str:
    return text.strip().split("\n", 1)[0] if text else ""


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (vuln_id, ecosystem, package, version); sources are merged."""
    merged: dict[tuple[str, str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.vuln_id, finding.ecosystem.value, finding.package, finding.version)
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        combined_sources = tuple(sorted(set(existing.sources) | set(finding.sources)))
        merged[key] = existing.model_copy(update={"sources": combined_sources})
    return list(merged.values())
