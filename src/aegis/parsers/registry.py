"""Pluggable parser registry."""

from __future__ import annotations

from collections.abc import Iterable

from aegis.core.models import ManifestFile
from aegis.core.protocols import Parser
from aegis.parsers.go_mod import GoModParser
from aegis.parsers.package_json import PackageJsonParser
from aegis.parsers.package_lock import PackageLockParser
from aegis.parsers.poetry_lock import PoetryLockParser
from aegis.parsers.pyproject import PyprojectParser
from aegis.parsers.requirements_txt import RequirementsTxtParser


class ParserRegistry:
    """Finds the first registered parser that supports a file."""

    def __init__(self, parsers: Iterable[Parser] = ()) -> None:
        self._parsers: list[Parser] = list(parsers)

    def register(self, parser: Parser) -> None:
        """Add a parser; earlier registrations win ties."""
        self._parsers.append(parser)

    def parser_for(self, manifest: ManifestFile) -> Parser | None:
        """The parser for `manifest`, or None if the format has no parser yet."""
        return next((p for p in self._parsers if p.supports(manifest)), None)


def default_registry() -> ParserRegistry:
    """Registry with every v1 parser. Pipfile.lock, yarn.lock, pnpm-lock.yaml and go.sum have none."""
    return ParserRegistry(
        [
            RequirementsTxtParser(),
            PyprojectParser(),
            PoetryLockParser(),
            PackageJsonParser(),
            PackageLockParser(),
            GoModParser(),
        ]
    )
