"""Parser for pyproject.toml (PEP 621, PEP 735 groups, and Poetry)."""

from __future__ import annotations

import tomllib
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any

from aegis.core.enums import Ecosystem, NoticeCode
from aegis.core.models import Dependency, ManifestFile, ParseResult
from aegis.core.names import normalize_name
from aegis.parsers._common import (
    as_strings,
    as_table,
    exact_pin,
    failed,
    info,
    parse_requirement_string,
    partial_parse,
)


class PyprojectParser:
    """Reads declared dependencies; every one is direct. Extras are out of scope (INFO)."""

    def supports(self, manifest: ManifestFile) -> bool:
        """True for files named pyproject.toml."""
        return PurePosixPath(manifest.rel_path).name == "pyproject.toml"

    def parse(self, manifest: ManifestFile, content: str) -> ParseResult:
        """Parse pyproject text. Invalid TOML gives a PARSE_FAILED warning."""
        try:
            data = tomllib.loads(content)
        except tomllib.TOMLDecodeError as exc:
            return failed(manifest.rel_path, f"invalid TOML: {exc}")

        project = as_table(data.get("project"))
        poetry = as_table(as_table(data.get("tool")).get("poetry"))
        requirement_strings = as_strings(project.get("dependencies"))
        for group in as_table(data.get("dependency-groups")).values():
            requirement_strings.extend(as_strings(group))

        declared: list[tuple[str, str | None]] = []
        skipped: list[str] = []
        for text in requirement_strings:
            parsed = parse_requirement_string(text)
            if parsed is None:
                skipped.append(text)
            else:
                declared.append(parsed)
        declared.extend(_poetry_entries(poetry))

        dependencies = tuple(
            Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.PYPI,
                direct=True,
                source=manifest.rel_path,
            )
            for name, version in declared
        )
        notices = []
        if skipped:
            notices.append(partial_parse(manifest.rel_path, skipped))
        if as_table(project.get("optional-dependencies")) or as_table(poetry.get("extras")):
            notices.append(
                info(
                    NoticeCode.OUT_OF_SCOPE_DEPENDENCIES,
                    "optional-dependencies / extras are out of scope in v1 and were not checked",
                    manifest.rel_path,
                )
            )
        return ParseResult(dependencies=dependencies, notices=tuple(notices))


def _poetry_entries(poetry: dict[str, Any]) -> Iterator[tuple[str, str | None]]:
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables.extend(
        as_table(group).get("dependencies") for group in as_table(poetry.get("group")).values()
    )
    for table in tables:
        for name, spec in as_table(table).items():
            if name.lower() != "python":
                yield normalize_name(Ecosystem.PYPI, name), _poetry_pin(spec)


def _poetry_pin(spec: object) -> str | None:
    if isinstance(spec, str):
        return exact_pin(spec)
    if isinstance(spec, dict) and isinstance(spec.get("version"), str):
        return exact_pin(spec["version"])
    return None  # git/path dependencies and multiple-constraint lists
