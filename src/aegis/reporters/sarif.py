"""SARIF 2.1.0 reporter for GitHub Code Scanning.

One ``rule`` per vulnerability ID; one ``result`` per finding. The rule's
``security-severity`` property uses the CVSS score of the highest-severity finding for
that rule, falling back to the qualitative band. ``partialFingerprints`` are keyed on
``vuln_id|ecosystem|package|version`` so they are stable across line-number changes.

Locations use the finding's primary source (first sorted) and its recorded line, or line
1 when the line is unknown.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from aegis import __version__
from aegis.core.enums import Severity
from aegis.core.models import AuditReport, Finding, Notice
from aegis.reporters.base import Reporter, sort_findings

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_FINGERPRINT_KEY = "aegis/v1"

_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "note",
}

_SECURITY_SEVERITY_BANDS: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.UNKNOWN: "0.0",
}


class SarifReporter(Reporter):
    """Renders a valid SARIF 2.1.0 document."""

    def render(self, report: AuditReport) -> str:
        findings = sort_findings(report.findings)
        rules, index = _build_rules(findings)
        run = {
            "tool": {
                "driver": {
                    "name": "aegis",
                    "version": __version__,
                    "informationUri": "https://github.com/Abdulgeni/aegis",
                    "rules": rules,
                }
            },
            "results": [_result(finding, index[finding.vuln_id]) for finding in findings],
            "invocations": [_invocation(report)],
        }
        document = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
        return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _build_rules(findings: list[Finding]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """One rule per vuln ID; rules follow first appearance in the ranked findings.

    The rule's severity is the highest-ranked severity among its findings (compared by
    ``Severity.rank``, not string ordering) and its ``security-severity`` is the highest
    CVSS score among its findings, or the qualitative band if no score is available.
    """
    index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    worst: dict[str, Severity] = {}
    best_score: dict[str, float] = {}
    for finding in findings:
        if finding.vuln_id not in index:
            index[finding.vuln_id] = len(rules)
            rules.append(_rule_stub(finding))
        current = worst.get(finding.vuln_id)
        if current is None or finding.severity.rank > current.rank:
            worst[finding.vuln_id] = finding.severity
        if finding.cvss_score is not None:
            best_score[finding.vuln_id] = max(
                best_score.get(finding.vuln_id, 0.0), finding.cvss_score
            )
    for rule in rules:
        rule_id = rule["id"]
        severity = worst.get(rule_id, Severity.UNKNOWN)
        rule["defaultConfiguration"] = {"level": _LEVELS[severity]}
        rule["properties"]["security-severity"] = _security_severity(
            severity, best_score.get(rule_id)
        )
    return rules, index


def _rule_stub(finding: Finding) -> dict[str, Any]:
    help_uri = finding.references[0] if finding.references else ""
    short = finding.summary or f"Vulnerability in {finding.package}"
    stub: dict[str, Any] = {
        "id": finding.vuln_id,
        "name": finding.vuln_id,
        "shortDescription": {"text": _clip(short, 200)},
        "fullDescription": {"text": _clip(short, 1000)},
        "properties": {
            "tags": ["security", "supply-chain", finding.ecosystem.value],
            "precision": "high" if not finding.unverified else "medium",
        },
    }
    if help_uri:
        stub["helpUri"] = help_uri
    if finding.aliases:
        stub["properties"]["aliases"] = list(finding.aliases)
    return stub


def _security_severity(severity: Severity, cvss_score: float | None) -> str:
    if cvss_score is not None and 0.0 < cvss_score <= 10.0:
        return f"{cvss_score:.1f}"
    return _SECURITY_SEVERITY_BANDS[severity]


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    source = finding.sources[0] if finding.sources else "unknown"
    line = finding.line if finding.line and finding.line >= 1 else 1
    message = _message(finding)
    return {
        "ruleId": finding.vuln_id,
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source},
                    "region": {"startLine": line},
                },
                "logicalLocations": [
                    {"name": finding.package, "kind": "package"},
                ],
            }
        ],
        "partialFingerprints": {
            _FINGERPRINT_KEY: _fingerprint(finding),
        },
        "properties": {
            "package": finding.package,
            "installedVersion": finding.version,
            "fixedVersion": finding.remediation.fixed_version,
            "ecosystem": finding.ecosystem.value,
            "direct": finding.direct,
            "unverified": finding.unverified,
        },
    }


def _message(finding: Finding) -> str:
    parts = [
        f"{finding.package} {finding.version} is affected by {finding.vuln_id}.",
        finding.summary.strip() or "",
    ]
    if finding.remediation.fixed_version:
        parts.append(f"Fixed in {finding.remediation.fixed_version}.")
    if finding.remediation.command:
        parts.append(f"Suggested fix: {finding.remediation.command}")
    if finding.unverified:
        parts.append("Note: verification could not be completed for this range.")
    return " ".join(p for p in parts if p)


def _fingerprint(finding: Finding) -> str:
    material = "|".join(
        [finding.vuln_id, finding.ecosystem.value, finding.package, finding.version]
    )
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def _invocation(report: AuditReport) -> dict[str, Any]:
    notifications = [
        {"level": "warning", "message": {"text": _notice_text(notice)}}
        for notice in report.notices
    ]
    return {
        "executionSuccessful": not any(n.level.value == "error" for n in report.notices),
        "toolExecutionNotifications": notifications,
    }


def _notice_text(notice: Notice) -> str:
    if notice.path:
        return f"[{notice.code.value}] {notice.path}: {notice.message}"
    return f"[{notice.code.value}] {notice.message}"


def _clip(text: str, limit: int) -> str:
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1].rstrip() + "\u2026"
