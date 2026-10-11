"""Shared vocabulary, defined once: ecosystems, severity bands, file kinds, notices."""

from __future__ import annotations

from enum import StrEnum


class Ecosystem(StrEnum):
    """OSV ecosystem names, used verbatim for lookup and reporting."""

    PYPI = "PyPI"
    NPM = "npm"
    GO = "Go"

    @classmethod
    def parse(cls, label: str) -> Ecosystem | None:
        """Case-insensitive lookup by value; None if unrecognized."""
        wanted = label.strip().casefold()
        return next((m for m in cls if m.value.casefold() == wanted), None)


class ManifestKind(StrEnum):
    """`manifest` holds unpinned constraints; `lock` holds resolved versions."""

    MANIFEST = "manifest"
    LOCK = "lock"


_SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEVERITY_ALIASES = {"MODERATE": "MEDIUM"}


class Severity(StrEnum):
    """Severity bands. Higher `rank` means more severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        """0 (UNKNOWN) to 4 (CRITICAL)."""
        return _SEVERITY_RANK[self.value]

    def at_least(self, other: Severity) -> bool:
        """True if this severity is at or above `other`."""
        return self.rank >= other.rank

    @classmethod
    def from_label(cls, label: str) -> Severity | None:
        """Parse a label case-insensitively; GHSA `MODERATE` becomes MEDIUM."""
        key = label.strip().upper()
        key = _SEVERITY_ALIASES.get(key, key)
        return cls(key) if key in _SEVERITY_RANK else None

    @classmethod
    def normalize(cls, label: str | None) -> Severity:
        """Like `from_label`, but missing or unrecognized labels become UNKNOWN."""
        parsed = cls.from_label(label) if label is not None else None
        return parsed or cls.UNKNOWN

    @classmethod
    def from_score(cls, score: float) -> Severity:
        """Map a CVSS base score to a band (9.0+ CRITICAL, 7.0+ HIGH, 4.0+ MEDIUM, >0 LOW)."""
        if not 0.0 < score <= 10.0:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW


class NoticeLevel(StrEnum):
    """Level of a non-vulnerability notice."""

    INFO = "info"
    WARNING = "warning"


class NoticeCode(StrEnum):
    """Stable machine-readable notice identifiers."""

    # discovery
    LOCK_PREFERRED = "lock-preferred"
    FILE_UNREADABLE = "file-unreadable"
    FILE_TOO_LARGE = "file-too-large"
    SYMLINK_OUTSIDE_ROOT = "symlink-outside-root"
    NO_MANIFESTS_FOUND = "no-manifests-found"
    # parsing and resolution
    PARSER_NOT_IMPLEMENTED = "parser-not-implemented"
    PARSE_FAILED = "parse-failed"
    PARTIAL_PARSE = "partial-parse"
    UNPINNED_MANIFEST = "unpinned-manifest"
    UNVERSIONED_PACKAGES = "unversioned-packages"
    OUT_OF_SCOPE_DEPENDENCIES = "out-of-scope-dependencies"
    DIRECT_UNKNOWN = "direct-unknown"
    # lookup
    OSV_REQUEST_FAILED = "osv-request-failed"
    OSV_PARTIAL_RESULTS = "osv-partial-results"
    CACHE_READ_FAILED = "cache-read-failed"
    CACHE_WRITE_FAILED = "cache-write-failed"
    CACHE_SCHEMA_RESET = "cache-schema-reset"
    NVD_REQUEST_FAILED = "nvd-request-failed"
    CVSS_UNSUPPORTED = "cvss-unsupported"
    # matching and remediation
    UNVERIFIED_RANGE = "unverified-range"
    NO_FIX_AVAILABLE = "no-fix-available"
    UNRESOLVED_FIX = "unresolved-fix"
    SEVERITY_OVERRIDDEN = "severity-overridden"
