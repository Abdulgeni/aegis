"""Rich table reporter: severity-colored rows sorted by composite rank.

Honors ``NO_COLOR`` and non-TTY output (styles are silently stripped by rich). The
``color`` constructor argument overrides auto-detection; tests pass ``False`` to get
deterministic plain text.
"""

from __future__ import annotations

import io
import shutil

from rich.console import Console
from rich.table import Table as RichTable
from rich.text import Text

from aegis.core.models import AuditReport, Finding
from aegis.reporters.base import (
    SEVERITY_STYLES,
    Reporter,
    counts_by_severity,
    sort_findings,
    unique_ordered,
    wants_color,
)

_LEVEL_STYLES = {"info": "dim", "warning": "yellow", "error": "bold red"}
_FIX_STATUS_LABELS = {
    "available": "available",
    "no_fix": "no-fix",
    "unresolved": "unresolved",
}


class TableReporter(Reporter):
    """Renders an AuditReport as a terminal-friendly table."""

    def __init__(self, *, color: bool | None = None, width: int | None = None) -> None:
        self._color = color
        self._width = width

    def render(self, report: AuditReport) -> str:
        color = wants_color(self._color)
        width = self._width or max(shutil.get_terminal_size((120, 24)).columns, 120)
        buffer = io.StringIO()
        console = Console(
            file=buffer,
            force_terminal=color,
            color_system="standard" if color else None,
            width=width,
            highlight=False,
            legacy_windows=False,
        )
        console.print(self._header(report))
        console.print()
        findings = sort_findings(report.findings)
        if findings:
            console.print(self._table(findings))
            console.print(self._summary(findings))
        else:
            console.print(Text("No vulnerabilities found.", style="green"))
        if report.notices:
            console.print()
            console.print(Text("Notices:", style="bold"))
            for notice in report.notices:
                console.print(
                    Text(
                        f"  [{notice.level.value.upper()}] {notice.message}",
                        style=_LEVEL_STYLES.get(notice.level.value, "dim"),
                    )
                )
        return buffer.getvalue()

    @staticmethod
    def _header(report: AuditReport) -> Text:
        return Text(
            f"Aegis: {report.root} - {len(report.findings)} finding(s)",
            style="bold",
        )

    @staticmethod
    def _table(findings: list[Finding]) -> RichTable:
        table = RichTable(show_lines=False, header_style="bold", expand=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Vuln ID", no_wrap=True)
        table.add_column("Package", no_wrap=True)
        table.add_column("Current", no_wrap=True)
        table.add_column("Fixed", no_wrap=True)
        table.add_column("Direct", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Summary", overflow="fold", ratio=2)
        for finding in findings:
            table.add_row(
                Text(finding.severity.value, style=SEVERITY_STYLES[finding.severity]),
                Text(finding.vuln_id),
                Text(f"{finding.package} [{finding.ecosystem.value}]"),
                Text(finding.version),
                Text(finding.remediation.fixed_version or "-"),
                Text(_direct_label(finding.direct)),
                Text(_FIX_STATUS_LABELS.get(finding.remediation.status.value, "-")),
                Text(_short(finding.summary)),
            )
        return table

    @staticmethod
    def _summary(findings: list[Finding]) -> Text:
        counts = counts_by_severity(findings)
        parts = [f"{n} {sev.value}" for sev, n in counts.items() if n]
        rules = len(unique_ordered(f.vuln_id for f in findings))
        return Text(
            f"Total: {len(findings)} finding(s) across {rules} unique advisory(ies) "
            f"({', '.join(parts)})",
            style="bold",
        )


def _direct_label(direct: bool | None) -> str:
    if direct is True:
        return "yes"
    if direct is False:
        return "no"
    return "?"


def _short(text: str, limit: int = 100) -> str:
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1].rstrip() + "\u2026"
