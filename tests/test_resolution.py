from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from aegis.core.discovery import FileDiscoverer
from aegis.core.enums import NoticeCode, NoticeLevel
from aegis.core.models import ManifestFile, ParseResult
from aegis.parsers.registry import ParserRegistry, default_registry
from aegis.resolution import DependencyResolver

Writer = Callable[..., Path]

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.31.0"

[package.dependencies]
urllib3 = ">=1.21.1,<3"

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "flask"
version = "3.0.0"
"""


def _resolve(root: Path, registry: ParserRegistry | None = None):  # type: ignore[no-untyped-def]
    return DependencyResolver(registry).resolve(FileDiscoverer().discover(root))


def _codes(result) -> list[NoticeCode]:  # type: ignore[no-untyped-def]
    return [n.code for n in result.notices]


def test_registry_lookup(make_manifest: Callable[[str], ManifestFile]) -> None:
    registry = default_registry()
    name = lambda rel: type(registry.parser_for(make_manifest(rel))).__name__  # noqa: E731
    assert name("poetry.lock") == "PoetryLockParser"
    assert name("requirements/dev.txt") == "RequirementsTxtParser"
    assert name("go.mod") == "GoModParser"
    for rel in ("yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "go.sum"):
        assert registry.parser_for(make_manifest(rel)) is None


def test_lock_wins_and_manifest_supplies_direct_flags(tmp_path: Path, write: Writer) -> None:
    write("pyproject.toml", '[project]\nname = "app"\ndependencies = ["requests>=2", "flask"]\n')
    write("poetry.lock", POETRY_LOCK)
    result = _resolve(tmp_path)
    by_name = {d.name: d for d in result.dependencies}
    assert set(by_name) == {"requests", "urllib3", "flask"}
    assert all(d.source == "poetry.lock" for d in result.dependencies)
    assert by_name["requests"].direct is True and by_name["flask"].direct is True
    assert by_name["urllib3"].direct is False
    assert by_name["urllib3"].resolved_from == "requests@2.31.0"
    assert by_name["requests"].resolved_from is None
    assert result.notices == ()


def test_lock_without_manifest_has_unknown_direct(tmp_path: Path, write: Writer) -> None:
    write("poetry.lock", POETRY_LOCK)
    result = _resolve(tmp_path)
    assert all(d.direct is None for d in result.dependencies)
    (notice,) = result.notices
    assert notice.code is NoticeCode.DIRECT_UNKNOWN
    assert notice.level is NoticeLevel.WARNING
    assert notice.path == "poetry.lock"


def test_manifest_only_warns_unpinned(tmp_path: Path, write: Writer) -> None:
    write("pyproject.toml", '[project]\ndependencies = ["requests>=2"]\n')
    result = _resolve(tmp_path)
    assert [(d.name, d.version) for d in result.dependencies] == [("requests", None)]
    (notice,) = result.notices
    assert notice.code is NoticeCode.UNPINNED_MANIFEST
    assert notice.message == "unpinned manifest, no exact versions to check"


def test_partially_pinned_requirements(tmp_path: Path, write: Writer) -> None:
    write("requirements.txt", "requests==2.31.0\nflask\n")
    result = _resolve(tmp_path)
    assert [(d.name, d.version) for d in result.dependencies] == [
        ("flask", None),
        ("requests", "2.31.0"),
    ]
    (notice,) = result.notices
    assert "1 of 2" in notice.message


def test_unimplemented_lock_leaves_manifest_as_sole_source(tmp_path: Path, write: Writer) -> None:
    write("package.json", json.dumps({"dependencies": {"axios": "^1.0.0"}}))
    write("yarn.lock", "# yarn lockfile v1\n")
    result = _resolve(tmp_path)
    assert set(_codes(result)) == {NoticeCode.PARSER_NOT_IMPLEMENTED, NoticeCode.UNPINNED_MANIFEST}
    not_implemented = next(n for n in result.notices if n.code is NoticeCode.PARSER_NOT_IMPLEMENTED)
    assert not_implemented.path == "yarn.lock"
    assert not_implemented.message == "discovered, parser not yet implemented"


def test_corrupt_lock_falls_back_to_manifest(tmp_path: Path, write: Writer) -> None:
    write("pyproject.toml", '[project]\ndependencies = ["requests>=2"]\n')
    write("poetry.lock", "[[package]\n")
    result = _resolve(tmp_path)
    assert set(_codes(result)) == {NoticeCode.PARSE_FAILED, NoticeCode.UNPINNED_MANIFEST}
    assert [d.source for d in result.dependencies] == ["pyproject.toml"]


def test_go_mod_is_a_lock_and_go_sum_is_reported(tmp_path: Path, write: Writer) -> None:
    write("go.mod", "module x\n\nrequire github.com/a/b v1.2.3\n")
    write("go.sum", "github.com/a/b v1.2.3 h1:abc=\n")
    result = _resolve(tmp_path)
    assert [(d.name, d.version, d.direct) for d in result.dependencies] == [
        ("github.com/a/b", "v1.2.3", True)
    ]
    (notice,) = result.notices
    assert notice.code is NoticeCode.PARSER_NOT_IMPLEMENTED and notice.path == "go.sum"


def test_duplicates_collapse_within_a_file(tmp_path: Path, write: Writer) -> None:
    write(
        "package-lock.json",
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"a": "1", "b": "1"}},
                    "node_modules/a": {"version": "1.0.0", "dependencies": {"x": "1"}},
                    "node_modules/a/node_modules/x": {"version": "1.0.0"},
                    "node_modules/b": {"version": "1.0.0", "dependencies": {"x": "1"}},
                    "node_modules/b/node_modules/x": {"version": "1.0.0"},
                }
            }
        ),
    )
    result = _resolve(tmp_path)
    assert [(d.name, d.version) for d in result.dependencies] == [
        ("a", "1.0.0"),
        ("b", "1.0.0"),
        ("x", "1.0.0"),
    ]


class _Exploding:
    def supports(self, manifest: ManifestFile) -> bool:
        return True

    def parse(self, manifest: ManifestFile, content: str) -> ParseResult:
        raise ValueError("boom")


def test_parser_crash_becomes_a_warning(tmp_path: Path, write: Writer) -> None:
    write("package.json", "{}")
    result = _resolve(tmp_path, ParserRegistry([_Exploding()]))
    assert result.dependencies == ()
    (notice,) = result.notices
    assert notice.code is NoticeCode.PARSE_FAILED
    assert notice.message == "parser error: ValueError"


def test_non_utf8_file_is_a_warning(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_bytes(b"\xff\xfe\x00bad")
    result = _resolve(tmp_path)
    assert _codes(result) == [NoticeCode.PARSE_FAILED]


def test_resolution_is_deterministic(tmp_path: Path, write: Writer) -> None:
    write("pyproject.toml", '[project]\ndependencies = ["requests", "flask"]\n')
    write("poetry.lock", POETRY_LOCK)
    write("web/package.json", json.dumps({"dependencies": {"axios": "1.6.0"}}))
    write("go.mod", "module x\n\nrequire github.com/a/b v1.2.3\n")
    assert _resolve(tmp_path) == _resolve(tmp_path)
