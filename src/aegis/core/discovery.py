"""Manifest and lock file discovery.

Bad *files* never fail the run: unreadable, oversized, or escaping-symlink files become
warning notices and are skipped. Only an invalid scan target raises UsageError.
Symlinked directories are never followed. Output is sorted by relative path.
"""

from __future__ import annotations

import os
import stat
from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path, PurePath, PurePosixPath

from aegis.core.config import AegisConfig
from aegis.core.enums import Ecosystem, ManifestKind, NoticeCode, NoticeLevel
from aegis.core.errors import UsageError
from aegis.core.models import DiscoveryResult, ManifestFile, Notice

DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
SKIP_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", "target", "vendor"}
)

_EXACT_FILES: dict[str, tuple[Ecosystem, ManifestKind]] = {
    "pyproject.toml": (Ecosystem.PYPI, ManifestKind.MANIFEST),
    "poetry.lock": (Ecosystem.PYPI, ManifestKind.LOCK),
    "Pipfile.lock": (Ecosystem.PYPI, ManifestKind.LOCK),
    "package.json": (Ecosystem.NPM, ManifestKind.MANIFEST),
    "package-lock.json": (Ecosystem.NPM, ManifestKind.LOCK),
    "yarn.lock": (Ecosystem.NPM, ManifestKind.LOCK),
    "pnpm-lock.yaml": (Ecosystem.NPM, ManifestKind.LOCK),
    "go.mod": (Ecosystem.GO, ManifestKind.LOCK),
    "go.sum": (Ecosystem.GO, ManifestKind.LOCK),
}


def classify_file(path: PurePath) -> tuple[Ecosystem, ManifestKind] | None:
    """Return (ecosystem, kind) for a supported file name, else None."""
    exact = _EXACT_FILES.get(path.name)
    if exact is not None:
        return exact
    if path.name.endswith(".txt") and _is_requirements_file(path):
        return (Ecosystem.PYPI, ManifestKind.MANIFEST)
    return None


def _is_requirements_file(path: PurePath) -> bool:
    name = path.name
    return (
        name == "requirements.txt"
        or name.startswith("requirements-")
        or path.parent.name == "requirements"
    )


class FileDiscoverer:
    """Finds supported manifest and lock files under a file or directory."""

    def __init__(
        self,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        ecosystems: frozenset[Ecosystem] | None = None,
        include_dirs: Iterable[str] = (),
    ) -> None:
        self._max_file_bytes = max_file_bytes
        self._ecosystems = ecosystems if ecosystems is not None else frozenset(Ecosystem)
        self._skip_dirs = SKIP_DIRS - frozenset(include_dirs)

    @classmethod
    def from_config(cls, config: AegisConfig) -> FileDiscoverer:
        """Build a discoverer from the discovery and ecosystem config sections."""
        return cls(
            max_file_bytes=config.discovery.max_file_bytes,
            ecosystems=config.enabled_ecosystems(),
            include_dirs=config.discovery.include_dirs,
        )

    def discover(self, target: Path) -> DiscoveryResult:
        """Discover files under `target`. Raises UsageError for an invalid target."""
        resolved = _resolve_target(target)
        notices: list[Notice] = []
        candidates: Iterable[Path]
        if resolved.is_file():
            if classify_file(resolved) is None:
                raise UsageError(f"{target} is not a recognized manifest or lock file")
            root, candidates = resolved.parent, [resolved]
        else:
            root, candidates = resolved, self._walk(resolved, notices)

        found = [m for path in candidates if (m := self._admit(path, root, notices)) is not None]
        manifests = sorted(found, key=lambda m: m.rel_path)
        notices.extend(_lock_preference_notices(manifests))
        if not manifests:
            notices.append(
                Notice(
                    level=NoticeLevel.INFO,
                    code=NoticeCode.NO_MANIFESTS_FOUND,
                    message="no supported manifest or lock files found",
                )
            )
        return DiscoveryResult(
            root=root,
            manifests=tuple(manifests),
            notices=tuple(sorted(notices, key=_notice_key)),
        )

    def _walk(self, root: Path, notices: list[Notice]) -> Iterator[Path]:
        def on_error(exc: OSError) -> None:
            where = _rel(Path(exc.filename), root) if exc.filename else "."
            notices.append(_warn(NoticeCode.FILE_UNREADABLE, f"directory skipped: {exc.strerror}", where))

        for dirpath, dirnames, filenames in os.walk(root, onerror=on_error, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in self._skip_dirs)
            for name in sorted(filenames):
                yield Path(dirpath) / name

    def _admit(self, path: Path, root: Path, notices: list[Notice]) -> ManifestFile | None:
        rule = classify_file(path)
        if rule is None or rule[0] not in self._ecosystems:
            return None
        rel = _rel(path, root)
        if path.is_symlink() and _symlink_escapes(path, root):
            notices.append(
                _warn(
                    NoticeCode.SYMLINK_OUTSIDE_ROOT,
                    "skipped: symlink target is outside the scan root or cannot be resolved",
                    rel,
                )
            )
            return None
        try:
            info = path.stat()
        except OSError as exc:
            notices.append(_warn(NoticeCode.FILE_UNREADABLE, f"skipped: {exc.strerror}", rel))
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > self._max_file_bytes:
            message = f"skipped: {info.st_size} bytes exceeds the {self._max_file_bytes} byte limit"
            notices.append(_warn(NoticeCode.FILE_TOO_LARGE, message, rel))
            return None
        if not os.access(path, os.R_OK):
            notices.append(_warn(NoticeCode.FILE_UNREADABLE, "skipped: file is not readable", rel))
            return None
        return ManifestFile(path=path, rel_path=rel, ecosystem=rule[0], kind=rule[1])


def _resolve_target(target: Path) -> Path:
    try:
        return target.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UsageError(f"scan path does not exist or cannot be resolved: {target}") from exc


def _symlink_escapes(path: Path, root: Path) -> bool:
    try:
        return not path.resolve().is_relative_to(root)
    except (OSError, RuntimeError):
        return True


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _warn(code: NoticeCode, message: str, path: str | None) -> Notice:
    return Notice(level=NoticeLevel.WARNING, code=code, message=message, path=path)


def _notice_key(notice: Notice) -> tuple[str, str, str]:
    return (notice.path or "", notice.code.value, notice.message)


def _lock_preference_notices(manifests: Sequence[ManifestFile]) -> list[Notice]:
    """One INFO per (directory, ecosystem) that has both lock and manifest files."""
    groups: dict[tuple[str, Ecosystem], list[ManifestFile]] = defaultdict(list)
    for item in manifests:
        directory = PurePosixPath(item.rel_path).parent.as_posix()
        groups[(directory, item.ecosystem)].append(item)

    notices: list[Notice] = []
    for (_, ecosystem), members in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1].value)):
        locks = [m for m in members if m.kind is ManifestKind.LOCK]
        manifest_files = [m for m in members if m.kind is ManifestKind.MANIFEST]
        if not (locks and manifest_files):
            continue
        lock_names = ", ".join(PurePosixPath(m.rel_path).name for m in locks)
        manifest_names = ", ".join(PurePosixPath(m.rel_path).name for m in manifest_files)
        notices.append(
            Notice(
                level=NoticeLevel.INFO,
                code=NoticeCode.LOCK_PREFERRED,
                message=(
                    f"{ecosystem.value}: preferring {lock_names} over {manifest_names}; "
                    "manifests are used only to tell direct from transitive dependencies"
                ),
                path=locks[0].rel_path,
            )
        )
    return notices
