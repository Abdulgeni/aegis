"""Parser for package-lock.json (lockfileVersion 2 and 3)."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from pathlib import PurePosixPath
from typing import Any, NamedTuple

from aegis.core.enums import Ecosystem, NoticeCode
from aegis.core.models import Dependency, ManifestFile, Notice, ParseResult
from aegis.core.names import normalize_name
from aegis.parsers._common import as_table, failed, info, load_json_object, parent_links

_DECLARING_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_EDGE_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
_KEY_LINE = re.compile(r'^\s*"([^"]+)"\s*:\s*\{')

Entries = Mapping[str, Mapping[str, Any]]


class _Node(NamedTuple):
    name: str
    version: str | None
    direct: bool | None
    line: int | None


class PackageLockParser:
    """Reads the `packages` map.

    `direct` is true for top-level installs declared by the root project or a workspace
    member. `resolved_from` is the parent on a shortest path from a direct dependency.
    Workspace members, links, and entries without a version get `version=None`.
    """

    def supports(self, manifest: ManifestFile) -> bool:
        """True for files named package-lock.json."""
        return PurePosixPath(manifest.rel_path).name == "package-lock.json"

    def parse(self, manifest: ManifestFile, content: str) -> ParseResult:
        """Parse lock text. Invalid JSON or lockfileVersion 1 gives a PARSE_FAILED warning."""
        data = load_json_object(content)
        if data is None:
            return failed(manifest.rel_path, "invalid JSON or not a JSON object")
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return failed(
                manifest.rel_path,
                "no 'packages' section; only npm 7+ lock files (lockfileVersion 2 or 3) are supported",
            )
        entries: dict[str, dict[str, Any]] = {
            key: value
            for key, value in packages.items()
            if isinstance(key, str) and isinstance(value, dict)
        }
        nodes = _build_nodes(entries, _line_index(content))
        roots = [key for key, node in nodes.items() if node.direct or not _is_installed(key)]
        parents = parent_links(_build_edges(entries, nodes), roots)

        dependencies = tuple(
            Dependency(
                name=node.name,
                version=node.version,
                ecosystem=Ecosystem.NPM,
                direct=node.direct,
                source=manifest.rel_path,
                resolved_from=_label(nodes, parents.get(key)) if not node.direct else None,
                line=node.line,
            )
            for key, node in sorted(nodes.items())
        )
        unversioned = sum(1 for dep in dependencies if dep.version is None)
        notices: tuple[Notice, ...] = ()
        if unversioned:
            notices = (
                info(
                    NoticeCode.UNVERSIONED_PACKAGES,
                    f"{unversioned} workspace or local package(s) have no version and will not be checked",
                    manifest.rel_path,
                ),
            )
        return ParseResult(dependencies=dependencies, notices=notices)


def _is_installed(key: str) -> bool:
    return key.startswith("node_modules/") or "/node_modules/" in key


def _declared_names(entries: Entries) -> set[str]:
    """Names declared by the root project and workspace members (non-installed entries)."""
    names: set[str] = set()
    for key, entry in entries.items():
        if not _is_installed(key):
            for field in _DECLARING_FIELDS:
                names.update(as_table(entry.get(field)))
    return names


def _build_nodes(entries: Entries, lines: Mapping[str, int]) -> dict[str, _Node]:
    declared = _declared_names(entries)
    has_root = "" in entries
    nodes: dict[str, _Node] = {}
    for key in sorted(entries):
        if key == "":
            continue
        entry = entries[key]
        installed = _is_installed(key)
        key_name = key.rsplit("node_modules/", 1)[1] if installed else key.rsplit("/", 1)[-1]
        raw_name = entry.get("name")
        real_name = raw_name if isinstance(raw_name, str) and raw_name else key_name
        raw_version = entry.get("version")
        has_version = isinstance(raw_version, str) and bool(raw_version) and not entry.get("link")
        version: str | None = raw_version if installed and has_version else None
        direct: bool | None
        if not installed:
            direct = True
        elif not has_root:
            direct = None
        else:
            direct = key == f"node_modules/{key_name}" and key_name in declared
        nodes[key] = _Node(normalize_name(Ecosystem.NPM, real_name), version, direct, lines.get(key))
    return nodes


def _ancestors(key: str) -> Iterator[str]:
    """Directories searched (nearest first) when resolving a dependency of `key`."""
    base = key
    while True:
        yield base
        index = base.rfind("node_modules/")
        if index <= 0:
            break
        base = base[:index].rstrip("/")
    yield ""


def _resolve_key(key: str, name: str, entries: Entries) -> str | None:
    """Node-style resolution: the nearest `node_modules/<name>` walking up from `key`."""
    for base in _ancestors(key):
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in entries:
            return candidate
    return None


def _build_edges(entries: Entries, nodes: Mapping[str, _Node]) -> dict[str, list[str]]:
    edges: dict[str, list[str]] = {}
    for key in nodes:
        children: set[str] = set()
        for field in _EDGE_FIELDS:
            for name in as_table(entries[key].get(field)):
                target = _resolve_key(key, name, entries)
                if target is not None and target != key and target in nodes:
                    children.add(target)
        if children:
            edges[key] = sorted(children)
    return edges


def _label(nodes: Mapping[str, _Node], key: str | None) -> str | None:
    if key is None:
        return None
    node = nodes[key]
    return f"{node.name}@{node.version}" if node.version else node.name


def _line_index(content: str) -> dict[str, int]:
    """Line number of each `"key": {` in the file (first occurrence wins)."""
    lines: dict[str, int] = {}
    for number, text in enumerate(content.splitlines(), start=1):
        match = _KEY_LINE.match(text)
        if match:
            lines.setdefault(match.group(1), number)
    return lines