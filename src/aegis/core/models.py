"""Core data models shared by every pipeline stage."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.enums import Ecosystem, ManifestKind, NoticeCode, NoticeLevel, Severity


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


class FixStatus(StrEnum):
    """Whether a safe upgrade path exists for a finding."""

    AVAILABLE = "available"  # a safe fixed version was computed
    NO_FIX = "no_fix"  # the vulnerable range has no 'fixed' event
    UNRESOLVED = "unresolved"  # candidates exist but every one lands in another window


class UpgradeDistance(StrEnum):
    """How large an upgrade the fix requires (patch < minor < major)."""

    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


class Remediation(_Frozen):
    """Concrete upgrade guidance for one finding."""

    fixed_version: str | None = None
    status: FixStatus = FixStatus.NO_FIX
    distance: UpgradeDistance | None = None
    safe_upgrade: bool = False  # True when not crossing a major boundary
    command: str | None = None  # primary suggested command
    alternatives: tuple[str, ...] = ()  # additional commands (overrides, constraints)
    path: tuple[str, ...] = ()  # resolved_from chain, direct first


class Finding(_Frozen):
    """One (dependency, vulnerability) pair that applies to the scanned project."""

    vuln_id: str  # primary display ID (smallest CVE alias, else OSV id)
    aliases: tuple[str, ...] = ()  # all known IDs, sorted
    package: str
    version: str
    ecosystem: Ecosystem
    severity: Severity
    cvss_score: float | None = None
    cvss_vector: str | None = None
    summary: str = ""
    introduced_version: str | None = None
    direct: bool | None
    sources: tuple[str, ...] = ()  # rel_paths that declared this dependency
    line: int | None = None
    remediation: Remediation = Field(default_factory=Remediation)
    unverified: bool = False  # True when range evaluation could not be completed
    group_id: str | None = None  # set by grouping when part of a group-fixable set
    published: datetime | None = None  # OSV published timestamp, if parseable
    references: tuple[str, ...] = ()


class AuditReport(_Frozen):
    """Aggregated output of a full audit run."""

    root: str
    findings: tuple[Finding, ...] = ()
    notices: tuple[Notice, ...] = ()
    ecosystem_counts: dict[str, int] = Field(default_factory=dict)
