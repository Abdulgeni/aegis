"""Core data models shared by every pipeline stage."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.enums import Ecosystem, ManifestKind, NoticeCode, NoticeLevel


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ManifestFile(_Frozen):
    """A discovered manifest or lock file."""

    path: Path  # absolute location on disk
    rel_path: str  # POSIX path relative to the scan root; used in all reports
    ecosystem: Ecosystem
    kind: ManifestKind


class Dependency(_Frozen):
    """One normalized dependency declaration."""

    name: str  # normalized per ecosystem (see core.names)
    version: str | None  # None for unpinned manifest entries and local packages
    ecosystem: Ecosystem
    direct: bool | None  # None means unknown; ranked the same as transitive
    source: str  # rel_path of the declaring file
    resolved_from: str | None = None  # parent as "name@version" if transitive
    line: int | None = Field(default=None, ge=1)  # 1-based line in source, if tracked


class Notice(_Frozen):
    """An INFO or WARNING that is not a vulnerability finding."""

    level: NoticeLevel
    code: NoticeCode
    message: str
    path: str | None = None  # rel_path the notice refers to, if any


class DiscoveryResult(_Frozen):
    """Output of the discovery stage."""

    root: Path
    manifests: tuple[ManifestFile, ...] = ()
    notices: tuple[Notice, ...] = ()


class ParseResult(_Frozen):
    """Output of parsing one file."""

    dependencies: tuple[Dependency, ...] = ()
    notices: tuple[Notice, ...] = ()


class ResolutionResult(_Frozen):
    """Output of the resolution stage: the dependencies to look up."""

    dependencies: tuple[Dependency, ...] = ()
    notices: tuple[Notice, ...] = ()
