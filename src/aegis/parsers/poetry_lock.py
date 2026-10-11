"""Parser for poetry.lock."""

from __future__ import annotations

import tomllib
from pathlib import PurePosixPath

from aegis.core.enums import Ecosystem
from aegis.core.models import Dependency, ManifestFile, ParseResult
from aegis.core.names import normalize_name
from aegis.parsers._common import as_table, failed, parent_links


class PoetryLockParser:
    """Reads `[[package]]` entries.

    The lock does not say which packages are direct, so `direct` is None here; the resolver
    derives it from a sibling manifest. `resolved_from` is the smallest-named dependent,
    since the lock has no roots to search from.
    """

    def supports(self, manifest: ManifestFile) -> bool:
        """True for files named poetry.lock."""
        return PurePosixPath(manifest.rel_path).name == "poetry.lock"

    def parse(self, manifest: ManifestFile, content: str) -> ParseResult:
        """Parse lock text. Invalid TOML gives a PARSE_FAILED warning."""
        try:
            data = tomllib.loads(content)
        except tomllib.TOMLDecodeError as exc:
            return failed(manifest.rel_path, f"invalid TOML: {exc}")

        raw = data.get("package")
        packages = raw if isinstance(raw, list) else []
        name_lines = _name_lines(content)
        if len(name_lines) != len(packages):
            name_lines = []

        entries: list[tuple[str, str | None, int | None]] = []
        versions: dict[str, str | None] = {}
        edges: dict[str, list[str]] = {}
        for index, package in enumerate(packages):
            if not isinstance(package, dict) or not isinstance(package.get("name"), str):
                continue
            name = normalize_name(Ecosystem.PYPI, package["name"])
            version = package.get("version")
            version = version if isinstance(version, str) and version else None
            entries.append((name, version, name_lines[index] if name_lines else None))
            versions.setdefault(name, version)
            edges.setdefault(name, []).extend(
                normalize_name(Ecosystem.PYPI, dep) for dep in as_table(package.get("dependencies"))
            )
        edges = {n: [c for c in children if c in versions] for n, children in edges.items()}
        parents = parent_links(edges, roots=())

        dependencies = tuple(
            Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.PYPI,
                direct=None,
                source=manifest.rel_path,
                resolved_from=_label(parents.get(name), versions),
                line=line,
            )
            for name, version, line in entries
        )
        return ParseResult(dependencies=dependencies)


def _label(name: str | None, versions: dict[str, str | None]) -> str | None:
    if name is None:
        return None
    version = versions.get(name)
    return f"{name}@{version}" if version else name


def _name_lines(content: str) -> list[int]:
    """Line number of the `name = ...` entry following each `[[package]]` header."""
    lines: list[int] = []
    expecting = False
    for number, text in enumerate(content.splitlines(), start=1):
        stripped = text.strip()
        if stripped == "[[package]]":
            expecting = True
        elif expecting and stripped.startswith("name"):
            lines.append(number)
            expecting = False
    return lines
