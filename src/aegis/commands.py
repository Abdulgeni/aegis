"""Command logic (framework-free, so it is unit-testable). ``cli.py`` is the typer shell.

All commands return an exit code. Streams (``stdout``/``stderr``) and the environment
(``env``) are injectable for testing. Exception classes come from ``core.errors`` and map
to exit code 2 at the CLI boundary.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, TextIO

from aegis.auditor import Auditor, _merge_notices
from aegis.core.config import CONFIG_FILENAME, AegisConfig, find_config, load_config
from aegis.core.enums import Ecosystem, NoticeCode, Severity
from aegis.core.errors import ConfigError, InputError
from aegis.core.ignores import active_and_expired, apply_ignores
from aegis.core.models import AuditReport, Dependency, Finding, Notice
from aegis.ignore_editor import add_ignore, parse_until
from aegis.matching import build_findings
from aegis.osv.client import OsvClient
from aegis.osv.models import VulnRecord, parse_vuln
from aegis.reporters import get_reporter
from aegis.scanners import build_auditor_for_config

AuditorFactory = Callable[[AegisConfig, Path, bool, bool], Auditor]


@dataclass(frozen=True)
class ScanOptions:
    """Parsed ``aegis scan`` options. ``None`` means "not given on the CLI"."""

    path: Path
    ecosystem: Ecosystem | None = None
    only_direct: bool = False
    fail_on: Severity | None = None
    output: str | None = None
    out: Path | None = None
    config_path: Path | None = None
    no_cache: bool = False
    strict: bool = False


# ---------------------------------------------------------------- scan --------


def run_scan(
    options: ScanOptions,
    *,
    env: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    auditor_factory: AuditorFactory | None = None,
    today: date | None = None,
) -> int:
    """Execute ``aegis scan`` and return the exit code."""
    environ = os.environ if env is None else env
    out_stream = stdout or sys.stdout
    err_stream = stderr or sys.stderr
    root = _resolve_root(options.path)

    config = _load_scan_config(options, root)
    auditor = (auditor_factory or _default_auditor_factory)(
        config, root, options.no_cache, options.only_direct
    )
    report = auditor.audit(root)

    outcome = apply_ignores(report.findings, config.ignore, today=today)
    threshold = config.severity_threshold
    kept = [f for f in outcome.kept if f.severity.rank >= threshold.rank]
    final_report = report.model_copy(
        update={
            "findings": tuple(kept),
            "notices": _merge_notices(report.notices, outcome.notices),
        }
    )

    fmt = options.output or "table"
    rendered = get_reporter(fmt, color=_wants_color(fmt, out_stream, environ)).render(final_report)
    _emit(rendered, options.out, out_stream, err_stream)

    if options.strict and _has_incomplete_results(final_report):
        print("aegis: incomplete results (--strict)", file=err_stream)
        return 2

    fail_on = options.fail_on if options.fail_on is not None else config.fail_on
    if fail_on is not None and any(f.severity.rank >= fail_on.rank for f in kept):
        return 1
    return 0


def _load_scan_config(options: ScanOptions, root: Path) -> AegisConfig:
    """Load config and apply CLI overrides for ecosystem filter and fail-on."""
    path = options.config_path if options.config_path else find_config(root)
    config = load_config(path) if path else AegisConfig()
    if options.ecosystem is not None:
        config = config.model_copy(
            update={
                "ecosystem": config.ecosystem.model_copy(
                    update={"include": [options.ecosystem], "exclude": []}
                )
            }
        )
    if options.fail_on is not None:
        config = config.model_copy(update={"fail_on": options.fail_on})
    return config


def _resolve_root(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise InputError(f"scan path does not exist or cannot be resolved: {path}") from exc


def _default_auditor_factory(
    config: AegisConfig, root: Path, no_cache: bool, only_direct: bool
) -> Auditor:
    """Production wiring: real discoverer, resolver, OSV lookup. ``root`` is unused here."""
    del root
    return build_auditor_for_config(config, no_cache=no_cache, only_direct=only_direct)


def _wants_color(fmt: str, stream: TextIO, env: Mapping[str, str]) -> bool | None:
    if fmt != "table":
        return None
    if not getattr(stream, "isatty", lambda: False)():
        return False
    return "NO_COLOR" not in env


def _emit(text: str, out: Path | None, stdout: TextIO, stderr: TextIO) -> None:
    if out is None:
        stdout.write(text)
        stdout.flush()
        return
    try:
        out.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot write {out}: {exc.strerror or exc}") from exc
    print(f"report written to {out}", file=stderr)


def _has_incomplete_results(report: AuditReport) -> bool:
    codes = {NoticeCode.OSV_PARTIAL_RESULTS.value, NoticeCode.OSV_REQUEST_FAILED.value}
    return any(n.code.value in codes for n in report.notices)


# ---------------------------------------------------------------- audit -------


def run_audit(
    package: str,
    version: str,
    *,
    ecosystem: Ecosystem = Ecosystem.PYPI,
    env: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Execute ``aegis audit <package>==<version>`` and return the exit code."""
    out_stream = stdout or sys.stdout
    del env  # reserved for future per-call config; currently unused
    client = OsvClient()
    try:
        dep = Dependency(
            name=package,
            version=version,
            ecosystem=ecosystem,
            direct=True,
            source="<command line>",
        )
        records, notices = asyncio.run(_lookup_one(client, dep))
    finally:
        _close_client(client)
    findings, _ = build_findings([dep], records)
    report = AuditReport(
        root=f"{ecosystem.value}:{package}=={version}",
        findings=tuple(findings),
        notices=tuple(notices),
        ecosystem_counts={ecosystem.value: 1},
    )
    out_stream.write(get_reporter("table", color=False).render(report))
    out_stream.flush()
    return 1 if findings else 0


async def _lookup_one(
    client: OsvClient, dep: Dependency
) -> tuple[dict[tuple[str, str, str], list[VulnRecord]], list[Notice]]:
    """Run an in-process OSV lookup for a single dependency."""
    from aegis.osv.lookup import OsvLookup

    return await OsvLookup(client).lookup([dep])


def _close_client(client: OsvClient) -> None:
    with contextlib.suppress(Exception):
        asyncio.run(client.close())


# ---------------------------------------------------------------- explain -----


def run_explain(
    vuln_id: str,
    *,
    env: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Execute ``aegis explain <VULN-ID>`` and return the exit code."""
    del env
    out_stream = stdout or sys.stdout
    err_stream = stderr or sys.stderr
    client = OsvClient()
    try:
        payload = asyncio.run(_fetch(client, vuln_id))
    finally:
        _close_client(client)
    record = parse_vuln(payload) if payload else None
    if record is None:
        print(f"vuln {vuln_id} not found", file=err_stream)
        return 2
    out_stream.write(_render_explain(record))
    out_stream.flush()
    return 0


async def _fetch(client: OsvClient, vuln_id: str) -> dict[str, Any]:
    with contextlib.suppress(Exception):
        return await client.fetch_vuln(vuln_id)
    return {}


def _render_explain(record: VulnRecord) -> str:
    lines = [f"# {record.id}", "", record.summary or "(no summary)", ""]
    if record.aliases:
        lines.append(f"Aliases: {', '.join(record.aliases)}")
    for severity in record.severity:
        lines.append(f"Severity vector: {severity.type} = {severity.score}")
    for affected in record.affected:
        lines.append(f"Affected: {affected.package.ecosystem} / {affected.package.name}")
        for range_ in affected.ranges:
            events = range_.get("events", [])
            lines.append(f"  Range ({range_.get('type')}): {events}")
        if affected.versions:
            lines.append(f"  Exact versions: {', '.join(affected.versions)}")
    if record.references:
        lines.append("")
        lines.append("References:")
        for ref in record.references:
            lines.append(f"  {ref.url}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- ignore ------


def run_ignore(
    vuln_id: str,
    *,
    package: str | None = None,
    reason: str | None = None,
    until: str | None = None,
    config_path: Path | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Execute ``aegis ignore <VULN-ID>`` and return the exit code."""
    from aegis.core.config import IgnoreRule

    err_stream = stderr or sys.stderr
    try:
        rule = IgnoreRule(id=vuln_id, package=package, reason=reason, until=parse_until(until))
    except ConfigError as exc:
        print(f"error: {exc}", file=err_stream)
        return 2
    try:
        path = add_ignore(config_path, rule)
    except ConfigError as exc:
        print(f"error: {exc}", file=err_stream)
        return 2
    print(f"ignore rule written to {path}", file=err_stream)
    return 0


def run_list_ignores(
    *,
    config_path: Path | None = None,
    stdout: TextIO | None = None,
    today: date | None = None,
) -> int:
    """Execute ``aegis list-ignores`` and return the exit code."""
    out_stream = stdout or sys.stdout
    path = config_path or find_config(Path.cwd()) or (Path.cwd() / CONFIG_FILENAME)
    if not path.exists():
        out_stream.write(f"no config file at {path}\n")
        return 0
    config = load_config(path)
    if not config.ignore:
        out_stream.write("no ignore rules\n")
        return 0
    active, expired = active_and_expired(config.ignore, today=today)
    if active:
        out_stream.write("Active:\n")
        for rule in active:
            out_stream.write(f"  {_format_rule(rule)}\n")
    if expired:
        out_stream.write("Expired:\n")
        for rule in expired:
            out_stream.write(f"  {_format_rule(rule)} (EXPIRED)\n")
    return 0


def _format_rule(rule: Any) -> str:
    bits = [rule.id]
    if rule.package:
        bits.append(f"package={rule.package}")
    if rule.until:
        bits.append(f"until={rule.until.isoformat()}")
    if rule.reason:
        bits.append(f'"{rule.reason}"')
    return " ".join(bits)


__all__ = [
    "AuditorFactory",
    "Finding",
    "Notice",
    "ScanOptions",
    "run_audit",
    "run_explain",
    "run_ignore",
    "run_list_ignores",
    "run_scan",
]
