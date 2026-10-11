"""Markdown reporter: a ticket-ready document, executive summary first.

Findings are grouped by severity (most severe first). The document is size-budgeted for a
GitHub PR comment (~65_536 chars); when over budget, the lowest-ranked findings are
dropped until it fits, with a truncation note. Notices always survive.
"""

from __future__ import annotations

from aegis.core.models import AuditReport, Finding
from aegis.reporters.base import (
    SEVERITY_LABELS,
    Reporter,
    counts_by_severity,
    sort_findings,
    unique_ordered,
)

MAX_CHARS = 60_000
_RESERVE_FOR_TAIL = 800  # leaves room for notices + trailing sections


class MarkdownReporter(Reporter):
    """Renders an AuditReport as a Markdown document."""

    def __init__(self, max_chars: int = MAX_CHARS) -> None:
        self._max = max_chars

    def render(self, report: AuditReport) -> str:
        findings = sort_findings(report.findings)
        header = _header(report, findings)
        notice_section = _notices(report)
        budget = self._max - len(header) - len(notice_section) - _RESERVE_FOR_TAIL
        body, dropped = _findings_section(findings, budget)
        truncation = _truncation_note(dropped) if dropped else ""
        return _join(header, body, truncation, notice_section)


def _header(report: AuditReport, findings: list[Finding]) -> str:
    counts = counts_by_severity(findings)
    lines = [
        "# Aegis dependency audit",
        "",
        "## Executive summary",
        "",
        f"Scanned `{report.root}`.",
        "",
        f"- Dependencies checked: **{sum(report.ecosystem_counts.values())}**",
        f"- Findings: **{len(findings)}**",
        f"- Unique advisories: **{len(unique_ordered(f.vuln_id for f in findings))}**",
        "",
    ]
    if findings:
        lines += ["| Severity | Count |", "|---|---|"]
        for severity, count in counts.items():
            if count:
                lines.append(f"| {SEVERITY_LABELS[severity]} | {count} |")
    else:
        lines.append("**No vulnerabilities found.**")
    lines.append("")
    return "\n".join(lines)


def _findings_section(findings: list[Finding], budget: int) -> tuple[str, int]:
    if not findings:
        return "", 0
    blocks: list[str] = ["## Findings", ""]
    used = sum(len(b) + 1 for b in blocks)
    current: str | None = None
    shown = 0
    for finding in findings:
        label = SEVERITY_LABELS[finding.severity]
        if label != current:
            blocks.append(f"### {label}")
            blocks.append("")
            current = label
        block = _finding_block(finding)
        if used + len(block) > budget:
            break
        blocks.append(block)
        used += len(block) + 1
        shown += 1
    return "\n".join(blocks), len(findings) - shown


def _finding_block(finding: Finding) -> str:
    lines = [
        f"#### `{finding.vuln_id}` - {finding.package} {finding.version}",
        "",
        f"- Ecosystem: `{finding.ecosystem.value}`",
        f"- Current: `{finding.version}`",
        f"- Fixed: `{finding.remediation.fixed_version or 'not available'}`",
        f"- Direct dependency: {_direct_label(finding.direct)}",
        f"- Sources: {', '.join(f'`{s}`' for s in finding.sources) or '-'}",
    ]
    severity_line = f"- Severity: **{finding.severity.value}**"
    if finding.cvss_score is not None:
        severity_line += f" (CVSS {finding.cvss_score:.1f})"
    lines.append(severity_line)
    if finding.aliases:
        lines.append(f"- Aliases: {', '.join(finding.aliases)}")
    if finding.unverified:
        lines.append("- **Verification could not be completed for this range.**")
    lines.append("")
    if finding.summary:
        lines += [_clip(finding.summary, 400), ""]
    if finding.remediation.command:
        lines += ["**Remediation:**", "", f"```\n{finding.remediation.command}\n```", ""]
        if finding.remediation.alternatives:
            for alt in finding.remediation.alternatives:
                lines += [f"Alternative: `{alt}`"]
            lines.append("")
    if finding.references:
        lines.append("References:")
        lines += [f"- {url}" for url in finding.references]
        lines.append("")
    return "\n".join(lines)


def _truncation_note(dropped: int) -> str:
    return f"_{dropped} lower-ranked finding(s) omitted to fit the size budget._\n"


def _notices(report: AuditReport) -> str:
    if not report.notices:
        return ""
    lines = ["## Notices", ""]
    for notice in report.notices:
        where = f"`{notice.path}`: " if notice.path else ""
        lines.append(
            f"- **{notice.level.value.upper()}** [{notice.code.value}] {where}{notice.message}"
        )
    lines.append("")
    return "\n".join(lines)


def _join(*sections: str) -> str:
    kept = [s for s in sections if s]
    return "\n".join(kept).rstrip() + "\n"


def _direct_label(direct: bool | None) -> str:
    if direct is True:
        return "yes"
    if direct is False:
        return "no"
    return "unknown"


def _clip(text: str, limit: int) -> str:
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1].rstrip() + "\u2026"
