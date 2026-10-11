"""Reporters: AuditReport -> text (table, JSON, SARIF, Markdown)."""

from __future__ import annotations

from aegis.core.errors import ConfigError
from aegis.reporters.base import Reporter
from aegis.reporters.json_report import JsonReporter
from aegis.reporters.markdown import MarkdownReporter
from aegis.reporters.sarif import SarifReporter
from aegis.reporters.table import TableReporter

OUTPUT_FORMATS = ("table", "json", "sarif", "markdown")


def get_reporter(name: str, *, color: bool | None = None, width: int | None = None) -> Reporter:
    """Return the reporter for ``name``. ``color``/``width`` only affect the table."""
    if name == "table":
        return TableReporter(color=color, width=width)
    if name == "json":
        return JsonReporter()
    if name == "sarif":
        return SarifReporter()
    if name == "markdown":
        return MarkdownReporter()
    raise ConfigError(f"unknown output format {name!r}; choose one of {list(OUTPUT_FORMATS)}")


__all__ = [
    "OUTPUT_FORMATS",
    "JsonReporter",
    "MarkdownReporter",
    "Reporter",
    "SarifReporter",
    "TableReporter",
    "get_reporter",
]
