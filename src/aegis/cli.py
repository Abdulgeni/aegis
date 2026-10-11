"""Aegis command-line interface. Thin Typer shell around ``commands.py``.

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or tool error.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from aegis import __version__, commands
from aegis.core.enums import Ecosystem, Severity
from aegis.core.errors import AegisError

app = typer.Typer(
    name="aegis",
    help="Dependency vulnerability scanner for lock files, powered by OSV.dev.",
    add_completion=False,
)


class OutputFormat(StrEnum):
    table = "table"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


class EcosystemChoice(StrEnum):
    pypi = "pypi"
    npm = "npm"
    go = "go"


_PATH = Annotated[
    Path,
    typer.Argument(
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
        help="File or directory to scan.",
    ),
]

_CONFIG_OPT = Annotated[
    Path | None,
    typer.Option("--config", exists=True, dir_okay=False, readable=True, help="YAML config file."),
]


def _fail(exc: AegisError) -> typer.Exit:
    typer.echo(f"error: {exc}", err=True)
    return typer.Exit(exc.exit_code)


def _parse_ecosystem(choice: EcosystemChoice | None) -> Ecosystem | None:
    if choice is None:
        return None
    return {
        EcosystemChoice.pypi: Ecosystem.PYPI,
        EcosystemChoice.npm: Ecosystem.NPM,
        EcosystemChoice.go: Ecosystem.GO,
    }[choice]


def _parse_severity(choice: str | None) -> Severity | None:
    if choice is None:
        return None
    parsed = Severity.from_label(choice)
    if parsed is None or parsed is Severity.UNKNOWN:
        raise typer.BadParameter(f"unknown severity: {choice!r}")
    return parsed


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", help="Show version and exit."),
    ] = False,
) -> None:
    """Aegis dependency auditor."""
    if version:
        typer.echo(f"aegis {__version__}")
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


@app.command()
def scan(
    path: _PATH = Path("."),
    output: Annotated[
        OutputFormat | None,
        typer.Option("--output", "-o", help="Report format (default: table)."),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Write the report to this file instead of stdout."),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit 1 if any finding is at or above this severity."),
    ] = None,
    ecosystem: Annotated[
        EcosystemChoice | None,
        typer.Option("--ecosystem", help="Restrict scanning to one ecosystem."),
    ] = None,
    only_direct: Annotated[
        bool, typer.Option("--only-direct", help="Scan direct dependencies only.")
    ] = False,
    config: _CONFIG_OPT = None,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Skip OSV cache reads and writes.")
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit 2 on incomplete results (partial OSV failures)."),
    ] = False,
) -> None:
    """Scan a project for vulnerable dependencies."""
    options = commands.ScanOptions(
        path=path,
        ecosystem=_parse_ecosystem(ecosystem),
        only_direct=only_direct,
        fail_on=_parse_severity(fail_on),
        output=output.value if output else None,
        out=out,
        config_path=config,
        no_cache=no_cache,
        strict=strict,
    )
    try:
        code = commands.run_scan(options)
    except AegisError as exc:
        raise _fail(exc) from exc
    raise typer.Exit(code)


@app.command()
def audit(
    spec: Annotated[
        str,
        typer.Argument(
            help="Package and version, e.g. 'requests==2.31.0' (PyPI) or 'axios@1.6.0' (npm)."
        ),
    ],
    ecosystem: Annotated[
        EcosystemChoice,
        typer.Option("--ecosystem", help="Ecosystem to use (default: pypi)."),
    ] = EcosystemChoice.pypi,
) -> None:
    """Audit a single package at a specific version."""
    parsed = _parse_spec(spec, ecosystem)
    if parsed is None:
        typer.echo(
            f"error: cannot parse {spec!r}; expected name==version or name@version", err=True
        )
        raise typer.Exit(2)
    name, version = parsed
    try:
        code = commands.run_audit(
            name, version, ecosystem=_parse_ecosystem(ecosystem) or Ecosystem.PYPI
        )
    except AegisError as exc:
        raise _fail(exc) from exc
    raise typer.Exit(code)


@app.command()
def explain(
    vuln_id: Annotated[str, typer.Argument(help="Vulnerability ID, e.g. CVE-2024-1234.")],
) -> None:
    """Show full details for one vulnerability."""
    try:
        code = commands.run_explain(vuln_id)
    except AegisError as exc:
        raise _fail(exc) from exc
    raise typer.Exit(code)


@app.command()
def ignore(
    vuln_id: Annotated[str, typer.Argument(help="Vulnerability ID to ignore.")],
    package: Annotated[
        str | None, typer.Option("--package", help="Restrict the ignore to one package name.")
    ] = None,
    reason: Annotated[
        str | None, typer.Option("--reason", help="Justification shown in list-ignores.")
    ] = None,
    until: Annotated[
        str | None,
        typer.Option("--until", help="Expiry date, YYYY-MM-DD."),
    ] = None,
    config: _CONFIG_OPT = None,
) -> None:
    """Add an ignore rule to ``.aegis.yaml``."""
    code = commands.run_ignore(
        vuln_id, package=package, reason=reason, until=until, config_path=config
    )
    raise typer.Exit(code)


@app.command("list-ignores")
def list_ignores(config: _CONFIG_OPT = None) -> None:
    """Show ignore rules with their state (active or expired)."""
    code = commands.run_list_ignores(config_path=config)
    raise typer.Exit(code)


def _parse_spec(spec: str, ecosystem: EcosystemChoice) -> tuple[str, str] | None:
    separator = "@" if ecosystem == EcosystemChoice.npm else "=="
    if separator not in spec:
        return None
    name, _, version = spec.partition(separator)
    name = name.strip()
    version = version.strip()
    if not name or not version:
        return None
    return name, version
