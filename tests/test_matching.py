from __future__ import annotations

from typing import Any

from aegis.core.enums import Ecosystem, NoticeCode, Severity
from aegis.core.models import Dependency, FixStatus
from aegis.matching import build_findings
from aegis.osv.models import parse_vuln


def _dep(
    name: str = "requests",
    version: str | None = "2.31.0",
    ecosystem: Ecosystem = Ecosystem.PYPI,
    direct: bool | None = True,
    source: str = "poetry.lock",
    resolved_from: str | None = None,
) -> Dependency:
    return Dependency(
        name=name,
        version=version,
        ecosystem=ecosystem,
        direct=direct,
        source=source,
        resolved_from=resolved_from,
    )


def _osv(
    vuln_id: str = "GHSA-xxxx",
    package_name: str = "requests",
    ecosystem: str = "PyPI",
    aliases: list[str] | None = None,
    summary: str = "test",
    ranges: list[dict[str, Any]] | None = None,
    versions: list[str] | None = None,
    severity: list[dict[str, str]] | None = None,
    database_specific: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": vuln_id,
        "aliases": aliases or [],
        "summary": summary,
        "details": "Detail text.\nSecond line.",
        "severity": severity or [],
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": package_name},
                "ranges": ranges or [],
                "versions": versions or [],
            }
        ],
        "database_specific": database_specific or {},
        "references": [{"type": "ADVISORY", "url": "https://example.com/a"}],
    }


def _records(
    payload: dict[str, Any], name: str = "requests", version: str = "2.31.0"
) -> dict[tuple[str, str, str], list[Any]]:
    """Build a records dict keyed by (ecosystem.value, normalized name, version)."""
    record = parse_vuln(payload)
    assert record is not None
    return {("PyPI", name, version): [record]}


def test_applies_on_range_match() -> None:
    record = _osv(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}])
    findings, notices = build_findings([_dep()], _records(record))
    assert len(findings) == 1
    assert findings[0].vuln_id == "GHSA-xxxx"
    assert findings[0].remediation.fixed_version == "3.0.0"
    assert findings[0].remediation.status is FixStatus.AVAILABLE
    assert notices == []


def test_does_not_apply_when_outside_range() -> None:
    record = _osv(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}])
    findings, _ = build_findings([_dep()], _records(record))
    assert findings == []


def test_applies_on_exact_versions_list() -> None:
    record = _osv(versions=["2.31.0"])
    findings, _ = build_findings([_dep()], _records(record))
    assert len(findings) == 1


def test_applies_when_entry_has_no_ranges_or_versions() -> None:
    # An entry listing only the package affects all versions.
    record = _osv()
    findings, _ = build_findings([_dep()], _records(record))
    assert len(findings) == 1


def test_ecosystem_mismatch_means_no_finding() -> None:
    record = _osv(ecosystem="npm")
    findings, _ = build_findings([_dep()], _records(record))
    assert findings == []


def test_package_name_mismatch_means_no_finding() -> None:
    record = _osv(package_name="urllib3")
    findings, _ = build_findings([_dep()], _records(record))
    assert findings == []


def test_pep503_normalization_of_pypi_names() -> None:
    record = _osv(package_name="Django_REST.framework")
    findings, _ = build_findings(
        [_dep(name="django-rest-framework")],
        _records(record, name="django-rest-framework"),
    )
    assert len(findings) == 1


def test_cvss_vector_determines_severity_and_score() -> None:
    record = _osv(
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    )
    findings, _ = build_findings([_dep()], _records(record))
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].cvss_score == 9.8
    assert findings[0].cvss_vector is not None


def test_ghsa_label_is_fallback_when_no_cvss() -> None:
    record = _osv(database_specific={"severity": "MODERATE"})
    findings, _ = build_findings([_dep()], _records(record))
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].cvss_score is None


def test_ghsa_label_severity_list_fallback() -> None:
    record = _osv(severity=[{"type": "GHSA", "score": "HIGH"}])
    findings, _ = build_findings([_dep()], _records(record))
    assert findings[0].severity is Severity.HIGH


def test_cvss_v4_falls_back_to_ghsa_label() -> None:
    record = _osv(
        severity=[
            {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}
        ],
        database_specific={"severity": "HIGH"},
    )
    findings, _ = build_findings([_dep()], _records(record))
    assert findings[0].severity is Severity.HIGH
    assert findings[0].cvss_score is None


def test_smallest_cve_alias_becomes_vuln_id() -> None:
    record = _osv(vuln_id="GHSA-xxxx", aliases=["CVE-2024-9999", "CVE-2024-0001"])
    findings, _ = build_findings([_dep()], _records(record))
    assert findings[0].vuln_id == "CVE-2024-0001"
    assert "CVE-2024-9999" in findings[0].aliases
    assert "GHSA-xxxx" in findings[0].aliases


def test_unverifiable_range_marks_finding_unverified() -> None:
    record = _osv(ranges=[{"type": "GIT", "events": [{"introduced": "abc"}]}])
    findings, notices = build_findings([_dep()], _records(record))
    assert len(findings) == 1
    assert findings[0].unverified is True
    assert any(n.code is NoticeCode.UNVERIFIED_RANGE for n in notices)


def test_dedup_across_sources() -> None:
    record = _osv(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}])
    dep_a = _dep(source="poetry.lock")
    dep_b = _dep(source="requirements.txt")
    findings, _ = build_findings([dep_a, dep_b], _records(record))
    assert len(findings) == 1
    assert set(findings[0].sources) == {"poetry.lock", "requirements.txt"}


def test_direct_flag_aggregation() -> None:
    record = _osv(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}])
    dep_direct = _dep(direct=True, source="a")
    dep_unknown = _dep(direct=None, source="b")
    findings, _ = build_findings([dep_direct, dep_unknown], _records(record))
    assert findings[0].direct is True


def test_unknown_direct_when_all_unknown() -> None:
    record = _osv(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}])
    findings, _ = build_findings([_dep(direct=None)], _records(record))
    assert findings[0].direct is None


def test_introduced_version_extracted() -> None:
    record = _osv(
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "3.0.0"}]}]
    )
    findings, _ = build_findings([_dep()], _records(record))
    assert findings[0].introduced_version == "1.0.0"


def test_no_fix_available_when_range_has_no_fixed_event() -> None:
    record = _osv(ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}])
    findings, _ = build_findings([_dep()], _records(record))
    assert findings[0].remediation.status is FixStatus.NO_FIX
    assert findings[0].remediation.fixed_version is None
