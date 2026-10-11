from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import pytest

from aegis.core.config import parse_config
from aegis.core.discovery import SKIP_DIRS, FileDiscoverer, classify_file
from aegis.core.enums import Ecosystem, ManifestKind, NoticeCode, NoticeLevel
from aegis.core.errors import UsageError

PYPI, NPM, GO = Ecosystem.PYPI, Ecosystem.NPM, Ecosystem.GO
MANIFEST, LOCK = ManifestKind.MANIFEST, ManifestKind.LOCK

SUPPORTED = {
    "requirements.txt": (PYPI, MANIFEST),
    "requirements-dev.txt": (PYPI, MANIFEST),
    "requirements/base.txt": (PYPI, MANIFEST),
    "pyproject.toml": (PYPI, MANIFEST),
    "poetry.lock": (PYPI, LOCK),
    "Pipfile.lock": (PYPI, LOCK),
    "web/package.json": (NPM, MANIFEST),
    "web/package-lock.json": (NPM, LOCK),
    "web/yarn.lock": (NPM, LOCK),
    "web/pnpm-lock.yaml": (NPM, LOCK),
    "svc/go.mod": (GO, LOCK),
    "svc/go.sum": (GO, LOCK),
}


@pytest.mark.parametrize(
    ("rel", "expected"), [*SUPPORTED.items(), ("a/b/requirements/dev.txt", (PYPI, MANIFEST))]
)
def test_classify_supported_files(rel: str, expected: tuple[Ecosystem, ManifestKind]) -> None:
    assert classify_file(PurePosixPath(rel)) == expected


@pytest.mark.parametrize(
    "rel",
    ["notes.txt", "requirements/README.md", "requirements.txt.bak", "my-requirements.txt", "Package.json"],
)
def test_classify_ignores_other_files(rel: str) -> None:
    assert classify_file(PurePosixPath(rel)) is None


def _populate(write: Callable[..., Path]) -> None:
    for rel in SUPPORTED:
        write(rel)
    for rel in ("notes.txt", "requirements/README.md", "web/tsconfig.json"):
        write(rel)


def test_discovers_all_formats_sorted_with_kinds(tmp_path: Path, write: Callable[..., Path]) -> None:
    _populate(write)
    result = FileDiscoverer().discover(tmp_path)
    assert [m.rel_path for m in result.manifests] == sorted(SUPPORTED)
    assert {m.rel_path: (m.ecosystem, m.kind) for m in result.manifests} == SUPPORTED
    assert result.root == tmp_path.resolve()
    assert all(m.path.is_absolute() for m in result.manifests)


def test_lock_preference_notices(tmp_path: Path, write: Callable[..., Path]) -> None:
    _populate(write)
    result = FileDiscoverer().discover(tmp_path)
    infos = [n for n in result.notices if n.code is NoticeCode.LOCK_PREFERRED]
    assert [n.level for n in infos] == [NoticeLevel.INFO, NoticeLevel.INFO]
    assert {n.path for n in infos} == {"Pipfile.lock", "web/package-lock.json"}
    assert any("poetry.lock" in n.message for n in infos)
    assert all(n.level is NoticeLevel.INFO for n in result.notices)
    assert "pyproject.toml" in [m.rel_path for m in result.manifests]


def test_no_lock_preference_without_both_kinds(tmp_path: Path, write: Callable[..., Path]) -> None:
    write("package.json")
    write("svc/go.mod")
    write("svc/go.sum")
    assert not FileDiscoverer().discover(tmp_path).notices


@pytest.mark.parametrize("skipped", sorted(SKIP_DIRS))
def test_skips_default_directories(tmp_path: Path, write: Callable[..., Path], skipped: str) -> None:
    write("package-lock.json")
    write(f"{skipped}/pkg/package-lock.json")
    result = FileDiscoverer().discover(tmp_path)
    assert [m.rel_path for m in result.manifests] == ["package-lock.json"]


def test_include_dirs_reenables_vendor(tmp_path: Path, write: Callable[..., Path]) -> None:
    write("vendor/dep/go.mod")
    write("node_modules/x/package.json")
    result = FileDiscoverer(include_dirs=["vendor"]).discover(tmp_path)
    assert [m.rel_path for m in result.manifests] == ["vendor/dep/go.mod"]


def test_scan_root_named_like_a_skipped_dir_is_scanned(
    tmp_path: Path, write: Callable[..., Path]
) -> None:
    write("build/package-lock.json")
    result = FileDiscoverer().discover(tmp_path / "build")
    assert [m.rel_path for m in result.manifests] == ["package-lock.json"]


def test_explicit_file_is_not_subject_to_directory_skipping(
    tmp_path: Path, write: Callable[..., Path]
) -> None:
    target = write("node_modules/p/package.json")
    result = FileDiscoverer().discover(target)
    assert [m.rel_path for m in result.manifests] == ["package.json"]
    assert result.root == target.parent.resolve()


def test_unrecognized_explicit_file_is_a_usage_error(write: Callable[..., Path]) -> None:
    with pytest.raises(UsageError, match="not a recognized"):
        FileDiscoverer().discover(write("notes.txt"))


def test_missing_target_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="does not exist"):
        FileDiscoverer().discover(tmp_path / "missing")


def test_empty_directory_reports_no_manifests(tmp_path: Path) -> None:
    result = FileDiscoverer().discover(tmp_path)
    assert result.manifests == ()
    assert [n.code for n in result.notices] == [NoticeCode.NO_MANIFESTS_FOUND]
    assert result.notices[0].level is NoticeLevel.INFO


def test_oversized_file_is_a_warning_not_an_error(
    tmp_path: Path, write: Callable[..., Path]
) -> None:
    write("package-lock.json", "x" * 20)
    result = FileDiscoverer(max_file_bytes=10).discover(tmp_path)
    assert result.manifests == ()
    too_large = [n for n in result.notices if n.code is NoticeCode.FILE_TOO_LARGE]
    assert too_large[0].level is NoticeLevel.WARNING
    assert too_large[0].path == "package-lock.json"


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="permission bits are not enforced here",
)
def test_unreadable_file_is_a_warning(tmp_path: Path, write: Callable[..., Path]) -> None:
    target = write("package-lock.json")
    target.chmod(0)
    try:
        result = FileDiscoverer().discover(tmp_path)
    finally:
        target.chmod(0o644)
    assert result.manifests == ()
    assert any(n.code is NoticeCode.FILE_UNREADABLE for n in result.notices)


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def test_symlink_escaping_root_is_skipped_with_warning(
    tmp_path: Path, write: Callable[..., Path]
) -> None:
    outside = write("outside/package-lock.json", "{}")
    root = tmp_path / "scan"
    _symlink(root / "package-lock.json", outside)
    result = FileDiscoverer().discover(root)
    assert result.manifests == ()
    escaped = [n for n in result.notices if n.code is NoticeCode.SYMLINK_OUTSIDE_ROOT]
    assert escaped[0].path == "package-lock.json"
    assert escaped[0].level is NoticeLevel.WARNING


def test_symlink_inside_root_is_allowed(tmp_path: Path, write: Callable[..., Path]) -> None:
    real = write("scan/real/package-lock.json", "{}")
    _symlink(tmp_path / "scan" / "package-lock.json", real)
    result = FileDiscoverer().discover(tmp_path / "scan")
    assert [m.rel_path for m in result.manifests] == ["package-lock.json", "real/package-lock.json"]


def test_symlinked_directories_are_not_followed(tmp_path: Path, write: Callable[..., Path]) -> None:
    write("scan/real/package-lock.json", "{}")
    _symlink(tmp_path / "scan" / "link", tmp_path / "scan" / "real")
    result = FileDiscoverer().discover(tmp_path / "scan")
    assert [m.rel_path for m in result.manifests] == ["real/package-lock.json"]


def test_ecosystem_filter(tmp_path: Path, write: Callable[..., Path]) -> None:
    _populate(write)
    result = FileDiscoverer(ecosystems=frozenset({NPM})).discover(tmp_path)
    assert {m.ecosystem for m in result.manifests} == {NPM}


def test_from_config_applies_limits_and_ecosystems(
    tmp_path: Path, write: Callable[..., Path]
) -> None:
    write("go.mod", "x" * 5)
    write("package-lock.json", "x" * 50)
    config = parse_config(
        "ecosystem:\n  exclude: [Go]\ndiscovery:\n  max_file_size_mb: 0.00002\n"
    )
    result = FileDiscoverer.from_config(config).discover(tmp_path)
    assert result.manifests == ()
    assert [n.code for n in result.notices if n.level is NoticeLevel.WARNING] == [
        NoticeCode.FILE_TOO_LARGE
    ]


def test_output_is_deterministic(tmp_path: Path, write: Callable[..., Path]) -> None:
    _populate(write)
    discoverer = FileDiscoverer()
    assert discoverer.discover(tmp_path) == discoverer.discover(tmp_path)
