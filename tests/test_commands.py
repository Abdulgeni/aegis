from __future__ import annotations

import io
from datetime import date
from pathlib import Path

import pytest

from aegis.commands import (
    ScanOptions,
    run_ignore,
    run_list_ignores,
    run_scan,
)
from aegis.core.config import AegisConfig
from aegis.core.enums import Ecosystem, NoticeCode, NoticeLevel, Severity
from aegis.core.errors import InputError
from aegis.core.models import (
    AuditReport,
    Finding,
    FixStatus,
    Notice,
    Remediation,
)


class FakeAuditor:
    """Returns a canned AuditReport. Compatible with the commands.Auditor protocol."""

    def __init__(self, report: AuditReport) -> None:
        self._report = report
        self.calls: list[Path] = []

    def audit(self, root: Path) -> AuditReport:
        self.calls.append(root)
        return self._report


def _finding(
    vuln_id: str = "CVE-2024-1234",
    severity: Severity = Severity.HIGH,
    package: str = "requests",
) -> Finding:
    return Finding(
        vuln_id=vuln_id,
        aliases=(),
        package=package,
        version="1.0.0",
        ecosystem=Ecosystem.PYPI,
        severity=severity,
        direct=True,
        sources=("poetry.lock",),
        remediation=Remediation(status=FixStatus.NO_FIX),
    )


def _report(
    findings: list[Finding] | None = None,
    notices: list[Notice] | None = None,
) -> AuditReport:
    return AuditReport(
        root="repo",
        findings=tuple(findings or []),
        notices=tuple(notices or []),
        ecosystem_counts={"PyPI": 1},
    )


def _factory(report: AuditReport):
    holder: dict[str, object] = {}

    def _build(config: AegisConfig, root: Path, no_cache: bool, only_direct: bool) -> FakeAuditor:
        holder["config"] = config
        holder["root"] = root
        holder["no_cache"] = no_cache
        holder["only_direct"] = only_direct
        auditor = FakeAuditor(report)
        holder["auditor"] = auditor
        return auditor  # type: ignore[return-value]

    return _build, holder


def _run(options: ScanOptions, report: AuditReport) -> tuple[int, str, str, dict]:
    factory, holder = _factory(report)
    out, err = io.StringIO(), io.StringIO()
    code = run_scan(
        options,
        env={},
        stdout=out,
        stderr=err,
        auditor_factory=factory,  # type: ignore[arg-type]
    )
    return code, out.getvalue(), err.getvalue(), holder


def test_scan_clean_exit_zero(tmp_path: Path) -> None:
    code, out, _, holder = _run(ScanOptions(path=tmp_path), _report())
    assert code == 0
    assert "No vulnerabilities found" in out
    assert holder["root"] == tmp_path.resolve()


def test_scan_findings_exit_one(tmp_path: Path) -> None:
    code, out, _, _ = _run(ScanOptions(path=tmp_path), _report([_finding()]))
    assert code == 1
    assert "CVE-2024-1234" in out


def test_scan_fail_on_threshold(tmp_path: Path) -> None:
    code, _, _, _ = _run(
        ScanOptions(path=tmp_path, fail_on=Severity.CRITICAL), _report([_finding()])
    )
    assert code == 0


def test_scan_output_json(tmp_path: Path) -> None:
    code, out, _, _ = _run(
        ScanOptions(path=tmp_path, output="json"), _report([_finding()])
    )
    assert code == 1
    assert out.lstrip().startswith("{")


def test_scan_output_file(tmp_path: Path) -> None:
    target = tmp_path / "out.json"
    code, out, err, _ = _run(
        ScanOptions(path=tmp_path, output="json", out=target), _report([_finding()])
    )
    assert code == 1
    assert out == ""
    assert "report written" in err
    assert target.read_text(encoding="utf-8").lstrip().startswith("{")


def test_scan_strict_incomplete_exits_two(tmp_path: Path) -> None:
    notice = Notice(level=NoticeLevel.WARNING, code=NoticeCode.OSV_PARTIAL_RESULTS, message="x")
    code, _, err, _ = _run(
        ScanOptions(path=tmp_path, strict=True), _report(notices=[notice])
    )
    assert code == 2
    assert "--strict" in err


def test_scan_nonexistent_path_raises(tmp_path: Path) -> None:
    with pytest.raises(InputError):
        run_scan(ScanOptions(path=tmp_path / "missing"))


def test_scan_applies_ignores(tmp_path: Path) -> None:
    cfg = tmp_path / ".aegis.yaml"
    cfg.write_text("ignore:\n  - id: CVE-2024-1234\n", encoding="utf-8")
    code, out, _, _ = _run(
        ScanOptions(path=tmp_path, config_path=cfg), _report([_finding()])
    )
    assert code == 0
    assert "No vulnerabilities found" in out


def test_scan_only_direct_flag_forwarded(tmp_path: Path) -> None:
    _, _, _, holder = _run(ScanOptions(path=tmp_path, only_direct=True), _report())
    assert holder["only_direct"] is True


def test_scan_no_cache_flag_forwarded(tmp_path: Path) -> None:
    _, _, _, holder = _run(ScanOptions(path=tmp_path, no_cache=True), _report())
    assert holder["no_cache"] is True


def test_scan_ecosystem_filter_overrides_config(tmp_path: Path) -> None:
    cfg = tmp_path / ".aegis.yaml"
    cfg.write_text("ecosystem:\n  exclude: [Go]\n", encoding="utf-8")
    _, _, _, holder = _run(
        ScanOptions(path=tmp_path, config_path=cfg, ecosystem=Ecosystem.PYPI), _report()
    )
    config: AegisConfig = holder["config"]  # type: ignore[assignment]
    assert config.enabled_ecosystems() == {Ecosystem.PYPI}


def test_run_ignore_writes_file(tmp_path: Path) -> None:
    cfg = tmp_path / ".aegis.yaml"
    err = io.StringIO()
    code = run_ignore("CVE-2024-1234", reason="test", config_path=cfg, stderr=err)
    assert code == 0
    assert cfg.exists()
    assert "CVE-2024-1234" in cfg.read_text(encoding="utf-8")


def test_run_ignore_invalid_until_returns_two(tmp_path: Path) -> None:
    cfg = tmp_path / ".aegis.yaml"
    code = run_ignore("CVE-1", until="2026-13-01", config_path=cfg, stderr=io.StringIO())
    assert code == 2


def test_run_list_ignores_no_config(tmp_path: Path) -> None:
    out = io.StringIO()
    code = run_list_ignores(config_path=tmp_path / "missing.yaml", stdout=out)
    assert code == 0
    assert "no config file" in out.getvalue()


def test_run_list_ignores_no_rules(tmp_path: Path) -> None:
    cfg = tmp_path / ".aegis.yaml"
    cfg.write_text("fail_on: high\n", encoding="utf-8")
    out = io.StringIO()
    code = run_list_ignores(config_path=cfg, stdout=out)
    assert code == 0
    assert "no ignore rules" in out.getvalue()


def test_run_list_ignores_active_and_expired(tmp_path: Path) -> None:
    cfg = tmp_path / ".aegis.yaml"
    cfg.write_text(
        "ignore:\n"
        "  - id: CVE-1\n"
        "    reason: keep\n"
        "  - id: CVE-2\n"
        "    until: 2020-01-01\n",
        encoding="utf-8",
    )
    out = io.StringIO()
    run_list_ignores(config_path=cfg, stdout=out, today=date(2026, 6, 15))
    text = out.getvalue()
    assert "Active:" in text and "CVE-1" in text
    assert "Expired:" in text and "CVE-2" in text
