"""JSON reporter: schema-versioned, deterministic (sorted keys, no timestamps)."""

from __future__ import annotations

import json

from aegis import __version__
from aegis.core.models import AuditReport, Finding
from aegis.reporters.base import SCHEMA_VERSION, Reporter, counts_by_severity, sort_findings


class JsonReporter(Reporter):
    """Emits the full report as JSON. Key order is fixed by the model, not sorted."""

    def __init__(self, indent: int | None = 2) -> None:
        self._indent = indent

    def render(self, report: AuditReport) -> str:
        findings = sort_findings(report.findings)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "aegis", "version": __version__},
            "root": report.root,
            "summary": {
                "total": len(findings),
                "by_severity": {
                    sev.value: count for sev, count in counts_by_severity(findings).items()
                },
                "ecosystem_counts": dict(sorted(report.ecosystem_counts.items())),
            },
            "findings": [_finding_dict(finding) for finding in findings],
            "notices": [
                {
                    "level": notice.level.value,
                    "code": notice.code.value,
                    "message": notice.message,
                    "path": notice.path,
                }
                for notice in report.notices
            ],
        }
        return json.dumps(payload, indent=self._indent, ensure_ascii=False) + "\n"


def _finding_dict(finding: Finding) -> dict[str, object]:
    return {
        "vuln_id": finding.vuln_id,
        "aliases": list(finding.aliases),
        "package": finding.package,
        "version": finding.version,
        "ecosystem": finding.ecosystem.value,
        "severity": finding.severity.value,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "summary": finding.summary,
        "introduced_version": finding.introduced_version,
        "direct": finding.direct,
        "sources": list(finding.sources),
        "line": finding.line,
        "unverified": finding.unverified,
        "group_id": finding.group_id,
        "published": finding.published.isoformat() if finding.published else None,
        "references": list(finding.references),
        "remediation": {
            "status": finding.remediation.status.value,
            "fixed_version": finding.remediation.fixed_version,
            "distance": finding.remediation.distance.value
            if finding.remediation.distance
            else None,
            "safe_upgrade": finding.remediation.safe_upgrade,
            "command": finding.remediation.command,
            "alternatives": list(finding.remediation.alternatives),
            "path": list(finding.remediation.path),
        },
    }
