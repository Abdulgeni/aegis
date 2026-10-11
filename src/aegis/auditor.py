"""Audit pipeline orchestrator: discovery -> resolution -> lookup -> matching -> report.

All stages are injected as protocols. The sync ``audit`` method wraps an async lookup
via ``asyncio.run``; callers with an already-running loop should use ``audit_async``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aegis.core.enums import Ecosystem
from aegis.core.models import AuditReport, Dependency, Notice
from aegis.core.protocols import Discoverer, Resolver
from aegis.matching import build_findings
from aegis.osv.lookup import LookupKey
from aegis.osv.models import VulnRecord
from aegis.remediation.grouping import assign_groups


class AsyncLookup(Protocol):
    """The OSV lookup interface, injected here so tests can fake it."""

    async def lookup(
        self, dependencies: list[Dependency]
    ) -> tuple[dict[LookupKey, list[VulnRecord]], list[Notice]]: ...


@dataclass(frozen=True)
class Auditor:
    """Runs the full audit pipeline for one root directory."""

    discoverer: Discoverer
    resolver: Resolver
    lookup: AsyncLookup
    only_direct: bool = False

    def audit(self, root: Path) -> AuditReport:
        """Sync wrapper around ``audit_async`` for CLI use."""
        return asyncio.run(self.audit_async(root))

    async def audit_async(self, root: Path) -> AuditReport:
        """Run every stage and assemble the final AuditReport."""
        discovery = self.discoverer.discover(root)
        resolution = self.resolver.resolve(discovery)
        dependencies = list(resolution.dependencies)
        if self.only_direct:
            dependencies = [d for d in dependencies if d.direct is True]
        records, lookup_notices = await self.lookup.lookup(dependencies)
        findings, match_notices = build_findings(dependencies, records)
        grouped = assign_groups(findings)
        notices = _merge_notices(
            discovery.notices,
            resolution.notices,
            lookup_notices,
            match_notices,
        )
        return AuditReport(
            root=str(discovery.root),
            findings=tuple(grouped),
            notices=notices,
            ecosystem_counts=_count_by_ecosystem(dependencies),
        )


def _merge_notices(*groups: Sequence[Notice]) -> tuple[Notice, ...]:
    """Preserve order, then sort by (path, code, message) for stable output."""
    seen: set[tuple[str, str, str]] = set()
    merged: list[Notice] = []
    for group in groups:
        for notice in group:
            key = (notice.path or "", notice.code.value, notice.message)
            if key in seen:
                continue
            seen.add(key)
            merged.append(notice)
    merged.sort(key=lambda n: (n.path or "", n.code.value, n.message))
    return tuple(merged)


def _count_by_ecosystem(dependencies: Sequence[Dependency]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dep in dependencies:
        key = dep.ecosystem.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def filter_ecosystems(
    dependencies: Sequence[Dependency], ecosystem: Ecosystem | None
) -> list[Dependency]:
    """Return only dependencies of ``ecosystem`` (or all, if ``None``)."""
    if ecosystem is None:
        return list(dependencies)
    return [d for d in dependencies if d.ecosystem is ecosystem]
