"""Stage protocols for dependency injection. Each step adds the protocol for its stage."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from aegis.core.models import (
    Dependency,
    DiscoveryResult,
    ManifestFile,
    Notice,
    ParseResult,
    ResolutionResult,
)
from aegis.osv.models import VulnRecord


class Discoverer(Protocol):
    """Finds manifest and lock files under a path."""

    def discover(self, target: Path) -> DiscoveryResult: ...


class Parser(Protocol):
    """Parses the text of one supported file format. Must not raise on bad input."""

    def supports(self, manifest: ManifestFile) -> bool: ...

    def parse(self, manifest: ManifestFile, content: str) -> ParseResult: ...


class Resolver(Protocol):
    """Parses discovered files and picks the dependencies to look up."""

    def resolve(self, discovery: DiscoveryResult) -> ResolutionResult: ...


class VulnerabilityLookup(Protocol):
    """Looks up OSV vuln records for a set of dependencies.

    Returns a mapping ``(ecosystem, name, version) -> list[VulnRecord]`` for the
    dependencies that were successfully checked, plus notices for any that were not.
    """

    async def lookup(
        self, dependencies: list[Dependency]
    ) -> tuple[dict[tuple[str, str, str], list[VulnRecord]], list[Notice]]: ...
