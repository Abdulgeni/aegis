"""Resolution stage: parse discovered files and choose the authoritative dependency source.

Rules, per (directory, ecosystem):
- If a usable lock exists, only lock dependencies are scanned. Sibling manifests are used
  solely to tell direct from transitive dependencies and never produce the
  "unpinned manifest" warning.
- Otherwise the manifests are the sole source and each one with unpinned entries gets one
  UNPINNED_MANIFEST warning.
A lock is usable if it has a parser and parsed without PARSE_FAILED.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

from aegis.core.enums import Ecosystem, ManifestKind, NoticeCode
from aegis.core.models import (
    Dependency,
    DiscoveryResult,
    ManifestFile,
    Notice,
    ResolutionResult,
)
from aegis.parsers._common import warn
from aegis.parsers.registry import ParserRegistry, default_registry


@dataclass(frozen=True)
class _Parsed:
    manifest: ManifestFile
    dependencies: tuple[Dependency, ...]
    usable: bool


class DependencyResolver:
    """Parses every discovered file and returns the dependencies to look up."""

    def __init__(self, registry: ParserRegistry | None = None) -> None:
        self._registry = registry if registry is not None else default_registry()

    def resolve(self, discovery: DiscoveryResult) -> ResolutionResult:
        """Parse, select sources per project, dedup within files, and sort deterministically."""
        notices: list[Notice] = []
        parsed = [
            item
            for manifest in discovery.manifests
            if (item := self._parse_file(manifest, notices)) is not None
        ]
        groups: dict[tuple[str, Ecosystem], list[_Parsed]] = defaultdict(list)
        for item in parsed:
            directory = PurePosixPath(item.manifest.rel_path).parent.as_posix()
            groups[(directory, item.manifest.ecosystem)].append(item)

        dependencies: list[Dependency] = []
        for key in sorted(groups, key=lambda k: (k[0], k[1].value)):
            members = groups[key]
            locks = [m for m in members if m.manifest.kind is ManifestKind.LOCK and m.usable]
            manifests = [m for m in members if m.manifest.kind is ManifestKind.MANIFEST]
            if locks:
                dependencies.extend(_from_locks(locks, manifests, notices))
            else:
                dependencies.extend(_from_manifests(manifests, notices))
        return ResolutionResult(
            dependencies=tuple(_dedupe(dependencies)),
            notices=tuple(sorted(notices, key=lambda n: (n.path or "", n.code.value, n.message))),
        )

    def _parse_file(self, manifest: ManifestFile, notices: list[Notice]) -> _Parsed | None:
        rel = manifest.rel_path
        parser = self._registry.parser_for(manifest)
        if parser is None:
            notices.append(
                warn(NoticeCode.PARSER_NOT_IMPLEMENTED, "discovered, parser not yet implemented", rel)
            )
            return None
        try:
            content = manifest.path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            notices.append(warn(NoticeCode.FILE_UNREADABLE, f"skipped: {exc.strerror}", rel))
            return None
        except UnicodeDecodeError:
            notices.append(warn(NoticeCode.PARSE_FAILED, "file is not valid UTF-8", rel))
            return None
        try:
            result = parser.parse(manifest, content)
        except Exception as exc:  # parsers see untrusted input; a bug must not abort the run
            notices.append(warn(NoticeCode.PARSE_FAILED, f"parser error: {type(exc).__name__}", rel))
            return None
        notices.extend(result.notices)
        usable = all(n.code is not NoticeCode.PARSE_FAILED for n in result.notices)
        return _Parsed(manifest, result.dependencies, usable)


def _from_locks(
    locks: list[_Parsed], manifests: list[_Parsed], notices: list[Notice]
) -> list[Dependency]:
    declared = {dep.name for item in manifests for dep in item.dependencies}
    declared_known = any(item.usable for item in manifests)
    result: list[Dependency] = []
    for lock in locks:
        resolved = [_with_direct(dep, declared, declared_known) for dep in lock.dependencies]
        if any(dep.direct is None for dep in resolved):
            notices.append(
                warn(
                    NoticeCode.DIRECT_UNKNOWN,
                    "direct vs transitive could not be determined (no usable sibling manifest); "
                    "treated as unknown and ranked after known-direct dependencies",
                    lock.manifest.rel_path,
                )
            )
        result.extend(resolved)
    return result


def _with_direct(dep: Dependency, declared: set[str], known: bool) -> Dependency:
    if dep.direct is None and known:
        dep = dep.model_copy(update={"direct": dep.name in declared})
    if dep.direct is True and dep.resolved_from is not None:
        dep = dep.model_copy(update={"resolved_from": None})
    return dep


def _from_manifests(manifests: list[_Parsed], notices: list[Notice]) -> list[Dependency]:
    result: list[Dependency] = []
    for item in manifests:
        total = len(item.dependencies)
        unpinned = sum(1 for dep in item.dependencies if dep.version is None)
        if unpinned:
            message = (
                "unpinned manifest, no exact versions to check"
                if unpinned == total
                else f"{unpinned} of {total} dependencies are unpinned; only exact pins are checked"
            )
            notices.append(warn(NoticeCode.UNPINNED_MANIFEST, message, item.manifest.rel_path))
        result.extend(item.dependencies)
    return result


def _dedupe(dependencies: Iterable[Dependency]) -> list[Dependency]:
    """Collapse duplicates within one source file, preferring a direct=True copy."""
    chosen: dict[tuple[str, Ecosystem, str, str | None], Dependency] = {}
    for dep in dependencies:
        key = (dep.source, dep.ecosystem, dep.name, dep.version)
        current = chosen.get(key)
        if current is None or (dep.direct is True and current.direct is not True):
            chosen[key] = dep
    return sorted(
        chosen.values(), key=lambda d: (d.ecosystem.value, d.source, d.name, d.version or "")
    )
