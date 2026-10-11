"""Tolerant parsing of OSV vulnerability JSON.

Fields are extracted defensively: unknown fields are ignored, wrong-typed fields are
dropped, and no field is mandatory. The full raw JSON of any record we keep is preserved
in ``raw`` so later stages can dig deeper without re-fetching.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")


class OsvSeverity(_Frozen):
    """One ``severity[]`` entry: a CVSS vector string of a named type."""

    type: str
    score: str


class AffectedPackage(_Frozen):
    """The ``package`` sub-object of an ``affected`` entry."""

    ecosystem: str = ""
    name: str = ""
    purl: str = ""


class Affected(_Frozen):
    """One ``affected[]`` entry: a package plus ranges and exact versions."""

    package: AffectedPackage
    ranges: tuple[dict[str, Any], ...] = ()
    versions: tuple[str, ...] = ()
    database_specific: dict[str, Any] = Field(default_factory=dict)


class VulnReference(_Frozen):
    """One ``references[]`` entry."""

    type: str = ""
    url: str = ""


class VulnRecord(_Frozen):
    """A curated view of one OSV record. ``raw`` is the full JSON as returned by OSV."""

    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    severity: tuple[OsvSeverity, ...] = ()
    affected: tuple[Affected, ...] = ()
    references: tuple[VulnReference, ...] = ()
    published: str | None = None
    modified: str | None = None
    database_specific: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def cve_aliases(self) -> tuple[str, ...]:
        """CVE IDs from ``aliases`` and from ``id`` if it is itself a CVE, sorted."""
        found: set[str] = set()
        if self.id.startswith("CVE-"):
            found.add(self.id)
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                found.add(alias)
        return tuple(sorted(found))


def parse_vuln(payload: Mapping[str, Any]) -> VulnRecord | None:
    """Parse an OSV record payload, or ``None`` if it has no usable ``id``."""
    vuln_id = payload.get("id")
    if not isinstance(vuln_id, str) or not vuln_id:
        return None
    return VulnRecord(
        id=vuln_id,
        aliases=_strings(payload.get("aliases")),
        summary=_string(payload.get("summary")),
        details=_string(payload.get("details")),
        severity=_severities(payload.get("severity")),
        affected=_affected(payload.get("affected")),
        references=_references(payload.get("references")),
        published=_optional_string(payload.get("published")),
        modified=_optional_string(payload.get("modified")),
        database_specific=_dict(payload.get("database_specific")),
        raw=dict(payload),
    )


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _severities(value: Any) -> tuple[OsvSeverity, ...]:
    if not isinstance(value, list):
        return ()
    out: list[OsvSeverity] = []
    for item in value:
        if isinstance(item, Mapping):
            type_ = item.get("type")
            score = item.get("score")
            if isinstance(type_, str) and isinstance(score, str):
                out.append(OsvSeverity(type=type_, score=score))
    return tuple(out)


def _affected(value: Any) -> tuple[Affected, ...]:
    if not isinstance(value, list):
        return ()
    out: list[Affected] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        package = item.get("package")
        if not isinstance(package, Mapping):
            continue
        ranges = item.get("ranges")
        versions = item.get("versions")
        out.append(
            Affected(
                package=AffectedPackage(
                    ecosystem=_string(package.get("ecosystem")),
                    name=_string(package.get("name")),
                    purl=_string(package.get("purl")),
                ),
                ranges=tuple(
                    r for r in (ranges or []) if isinstance(r, Mapping)
                ),
                versions=tuple(v for v in (versions or []) if isinstance(v, str)),
                database_specific=_dict(item.get("database_specific")),
            )
        )
    return tuple(out)


def _references(value: Any) -> tuple[VulnReference, ...]:
    if not isinstance(value, list):
        return ()
    out: list[VulnReference] = []
    for item in value:
        if isinstance(item, Mapping):
            url = item.get("url")
            if isinstance(url, str) and url:
                out.append(VulnReference(type=_string(item.get("type")), url=url))
    return tuple(out)
