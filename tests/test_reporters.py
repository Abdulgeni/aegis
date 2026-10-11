from __future__ import annotations

import json

import pytest

from aegis.core.enums import Ecosystem, NoticeCode, NoticeLevel, Severity
from aegis.core.errors import ConfigError
from aegis.core.models import (
    AuditReport,
    Finding,
    FixStatus,
    Notice,
    Remediation,
    UpgradeDistance,
)
from aegis.reporters import OUTPUT_FORMATS, get_reporter
from aegis.reporters.json_report import JsonReporter
from aegis.reporters.markdown import MarkdownReporter
from aegis.reporters.sarif import SarifReporter
from aegis.reporters.table import TableReporter


def _finding(
    vuln_id: str = "CVE-2024-1234",
    package: str = "requests",
    version: str = "2.31.0",
    severity: Severity = Severity.HIGH,
    direct: bool | None = True,
    fixed: str | None = "2.32.0",
    status: FixStatus = FixStatus.AVAILABLE,
    distance: UpgradeDistance | None = UpgradeDistance.MINOR,
    command: str | None = 'pip install "requests>=2.32.0"',
    cvss: float | None = 7.5,
    summary: str = "An issue in requests.",
    unverified: bool = False,
    sources: tuple[str, ...] = ("poetry.lock",),
    line: int | None = 42,
    aliases: tuple[str, ...] = ("GHSA-aaaa",),
    ecosystem: Ecosystem = Ecosystem.PYPI,
) -> Finding:
    return Finding(
        vuln_id=vuln_id,
        aliases=aliases,
        package=package,
        version=version,
        ecosystem=ecosystem,
        severity=severity,
        cvss_score=cvss,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        summary=summary,
        direct=direct,
        sources=sources,
        line=line,
        remediation=Remediation(
            status=status,
            fixed_version=fixed,
            distance=distance,
            safe_upgrade=distance in (UpgradeDistance.PATCH, UpgradeDistance.MINOR),
            command=command,
            alternatives=(),
            path=("requests@2.31.0",) if direct else (),
        ),
        unverified=unverified,
    )


def _report(
    findings: list[Finding] | None = None,
    notices: list[Notice] | None = None,
    root: str = "/repo",
) -> AuditReport:
    return AuditReport(
        root=root,
        findings=tuple(findings or []),
        notices=tuple(notices or []),
        ecosystem_counts={"PyPI": 3, "npm": 2},
    )


class TestFactory:
    def test_each_format_has_a_reporter(self) -> None:
        assert isinstance(get_reporter("table", color=False), TableReporter)
        assert isinstance(get_reporter("json"), JsonReporter)
        assert isinstance(get_reporter("sarif"), SarifReporter)
        assert isinstance(get_reporter("markdown"), MarkdownReporter)

    def test_unknown_format_raises(self) -> None:
        with pytest.raises(ConfigError, match="unknown output format"):
            get_reporter("xml")

    def test_supported_formats_are_documented(self) -> None:
        assert set(OUTPUT_FORMATS) == {"table", "json", "sarif", "markdown"}


class TestDeterminism:
    @pytest.mark.parametrize("fmt", ["json", "sarif", "markdown"])
    def test_render_is_byte_identical_for_identical_input(self, fmt: str) -> None:
        report = _report([_finding(), _finding(vuln_id="CVE-2023-0001", package="urllib3")])
        reporter = get_reporter(fmt)
        assert reporter.render(report) == reporter.render(report)

    def test_table_is_byte_identical(self) -> None:
        report = _report([_finding()])
        reporter = TableReporter(color=False, width=140)
        assert reporter.render(report) == reporter.render(report)


class TestTable:
    def test_columns_and_row(self) -> None:
        out = TableReporter(color=False, width=140).render(
            _report([_finding(severity=Severity.CRITICAL)])
        )
        assert "Aegis: /repo" in out
        assert "CRITICAL" in out
        assert "CVE-2024-1234" in out
        assert "requests" in out
        assert "2.32.0" in out

    def test_empty_report(self) -> None:
        out = TableReporter(color=False, width=140).render(_report())
        assert "No vulnerabilities found." in out

    def test_notices_rendered(self) -> None:
        notice = Notice(
            level=NoticeLevel.WARNING,
            code=NoticeCode.UNVERIFIED_RANGE,
            message="something unverified",
            path="poetry.lock",
        )
        out = TableReporter(color=False, width=140).render(_report(notices=[notice]))
        assert "[WARNING]" in out and "something unverified" in out

    def test_color_off_no_ansi(self) -> None:
        out = TableReporter(color=False, width=140).render(_report([_finding()]))
        assert "\x1b[" not in out

    def test_color_on_emits_ansi(self) -> None:
        out = TableReporter(color=True, width=140).render(
            _report([_finding(severity=Severity.CRITICAL)])
        )
        assert "\x1b[" in out


class TestJson:
    def test_shape_and_schema_version(self) -> None:
        out = JsonReporter().render(_report([_finding()]))
        data = json.loads(out)
        assert data["schema_version"] == 1
        assert data["tool"]["name"] == "aegis"
        assert data["root"] == "/repo"
        assert data["summary"]["total"] == 1
        assert data["summary"]["by_severity"]["HIGH"] == 1
        assert data["summary"]["ecosystem_counts"] == {"PyPI": 3, "npm": 2}
        assert len(data["findings"]) == 1

    def test_finding_fields(self) -> None:
        out = JsonReporter().render(_report([_finding()]))
        finding = json.loads(out)["findings"][0]
        assert finding["vuln_id"] == "CVE-2024-1234"
        assert finding["severity"] == "HIGH"
        assert finding["package"] == "requests"
        assert finding["remediation"]["fixed_version"] == "2.32.0"
        assert finding["remediation"]["distance"] == "minor"
        assert finding["aliases"] == ["GHSA-aaaa"]

    def test_notices_are_serialised(self) -> None:
        notice = Notice(
            level=NoticeLevel.INFO,
            code=NoticeCode.LOCK_PREFERRED,
            message="preferring lock",
            path="poetry.lock",
        )
        out = JsonReporter().render(_report(notices=[notice]))
        notices = json.loads(out)["notices"]
        assert notices[0]["code"] == "lock-preferred"
        assert notices[0]["path"] == "poetry.lock"


class TestSarif:
    def test_top_level_shape(self) -> None:
        doc = json.loads(SarifReporter().render(_report([_finding()])))
        assert doc["version"] == "2.1.0"
        assert "sarif-2.1.0" in doc["$schema"]
        assert len(doc["runs"]) == 1

    def test_driver_and_rule_structure(self) -> None:
        doc = json.loads(SarifReporter().render(_report([_finding()])))
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "aegis"
        assert len(driver["rules"]) == 1
        rule = driver["rules"][0]
        assert rule["id"] == "CVE-2024-1234"
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["properties"]["security-severity"] == "7.5"
        assert "supply-chain" in rule["properties"]["tags"]

    def test_security_severity_falls_back_to_band(self) -> None:
        doc = json.loads(
            SarifReporter().render(_report([_finding(cvss=None, severity=Severity.MEDIUM)]))
        )
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "5.5"

    def test_rule_severity_uses_highest_rank_not_string_order(self) -> None:
        # Two findings for the same vuln ID, one CRITICAL, one LOW.
        # Even though "CRITICAL" < "LOW" lexically, CRITICAL must win.
        a = _finding(vuln_id="CVE-2024-0001", package="alpha", severity=Severity.LOW)
        b = _finding(vuln_id="CVE-2024-0001", package="beta", severity=Severity.CRITICAL)
        doc = json.loads(SarifReporter().render(_report([a, b])))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_result_shape(self) -> None:
        doc = json.loads(SarifReporter().render(_report([_finding()])))
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "CVE-2024-1234"
        assert result["ruleIndex"] == 0
        assert result["level"] == "error"
        assert "CVE-2024-1234" in result["message"]["text"]
        physical = result["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "poetry.lock"
        assert physical["region"]["startLine"] == 42

    def test_fingerprint_stable_across_line_changes(self) -> None:
        a = json.loads(SarifReporter().render(_report([_finding(line=10)])))
        b = json.loads(SarifReporter().render(_report([_finding(line=9999)])))
        fa = a["runs"][0]["results"][0]["partialFingerprints"]["aegis/v1"]
        fb = b["runs"][0]["results"][0]["partialFingerprints"]["aegis/v1"]
        assert fa == fb

    def test_fingerprint_differs_for_different_vulns(self) -> None:
        a = json.loads(SarifReporter().render(_report([_finding(vuln_id="CVE-2024-0001")])))
        b = json.loads(SarifReporter().render(_report([_finding(vuln_id="CVE-2024-0002")])))
        fa = a["runs"][0]["results"][0]["partialFingerprints"]["aegis/v1"]
        fb = b["runs"][0]["results"][0]["partialFingerprints"]["aegis/v1"]
        assert fa != fb

    def test_two_findings_same_vuln_share_rule(self) -> None:
        a = _finding(vuln_id="CVE-2024-0001", package="alpha")
        b = _finding(vuln_id="CVE-2024-0001", package="beta")
        doc = json.loads(SarifReporter().render(_report([a, b])))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        results = doc["runs"][0]["results"]
        assert len(results) == 2
        assert all(r["ruleIndex"] == 0 for r in results)

    def test_unknown_line_defaults_to_one(self) -> None:
        doc = json.loads(SarifReporter().render(_report([_finding(line=None)])))
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 1

    def test_no_source_uses_placeholder(self) -> None:
        doc = json.loads(SarifReporter().render(_report([_finding(sources=())])))
        uri = (
            doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
        )
        assert uri == "unknown"

    def test_invocation_carries_notices(self) -> None:
        notice = Notice(
            level=NoticeLevel.WARNING,
            code=NoticeCode.UNVERIFIED_RANGE,
            message="unverified",
            path="poetry.lock",
        )
        doc = json.loads(SarifReporter().render(_report(notices=[notice])))
        invocation = doc["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
        assert invocation["toolExecutionNotifications"][0]["message"]["text"].startswith(
            "[unverified-range]"
        )

    def test_unverified_flag_in_result_properties(self) -> None:
        doc = json.loads(SarifReporter().render(_report([_finding(unverified=True)])))
        props = doc["runs"][0]["results"][0]["properties"]
        assert props["unverified"] is True


class TestMarkdown:
    def test_executive_summary_first(self) -> None:
        out = MarkdownReporter().render(_report([_finding()]))
        assert out.startswith("# Aegis dependency audit")
        exec_pos = out.index("## Executive summary")
        findings_pos = out.index("## Findings")
        assert exec_pos < findings_pos

    def test_findings_grouped_by_severity(self) -> None:
        findings = [
            _finding(vuln_id="CVE-2024-0001", severity=Severity.HIGH),
            _finding(vuln_id="CVE-2024-0002", severity=Severity.MEDIUM, package="urllib3"),
        ]
        out = MarkdownReporter().render(_report(findings))
        high_pos = out.index("### High")
        medium_pos = out.index("### Medium")
        assert high_pos < medium_pos

    def test_remediation_block_present(self) -> None:
        out = MarkdownReporter().render(_report([_finding()]))
        assert "**Remediation:**" in out
        assert "pip install" in out

    def test_unverified_warning(self) -> None:
        out = MarkdownReporter().render(_report([_finding(unverified=True)]))
        assert "Verification could not be completed" in out

    def test_notices_section(self) -> None:
        notice = Notice(
            level=NoticeLevel.WARNING,
            code=NoticeCode.UNVERIFIED_RANGE,
            message="something unverified",
            path="poetry.lock",
        )
        out = MarkdownReporter().render(_report(notices=[notice]))
        assert "## Notices" in out
        assert "unverified-range" in out

    def test_truncation_when_over_budget(self) -> None:
        findings = [
            _finding(vuln_id=f"CVE-2024-{i:04d}", package=f"pkg{i}", severity=Severity.LOW)
            for i in range(50)
        ]
        out = MarkdownReporter(max_chars=4000).render(_report(findings))
        assert "lower-ranked finding(s) omitted" in out

    def test_empty_report_still_renders(self) -> None:
        out = MarkdownReporter().render(_report())
        assert "No vulnerabilities found." in out
        assert out.endswith("\n")
