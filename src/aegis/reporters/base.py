"""Reporter protocol and shared helpers."""

from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping

from aegis.core.enums import Severity
from aegis.core.models import AuditReport, Finding
from aegis.remediation.ranking import rank

SCHEMA_VERSION = 1

SEVERITY_STYLES: Mapping[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "dim",
}

SEVERITY_LABELS: Mapping[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.UNKNOWN: "Unknown",
}


class Reporter(ABC):
    """Turns an AuditReport into a string. Implementations must be deterministic."""

    @abstractmethod
    def render(self, report: AuditReport) -> str:
        """Return the full report text. Must not include timestamps."""


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Composite-rank ordering from Step 6, so every reporter agrees on order."""
    return rank(list(findings))


def counts_by_severity(findings: Iterable[Finding]) -> dict[Severity, int]:
    """Zero-filled counts for every severity, most severe first."""
    counts = {severity: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity] += 1
    return {severity: counts[severity] for severity in Severity}


def wants_color(explicit: bool | None) -> bool:
    """Resolve color: ``None`` means "auto-detect from stdout and NO_COLOR"."""
    if explicit is not None:
        return explicit
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def unique_ordered(values: Iterable[str]) -> list[str]:
    """Deduplicate while preserving order (used for rule IDs in SARIF)."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out
