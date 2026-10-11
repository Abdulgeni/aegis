from __future__ import annotations

import json
from collections.abc import Callable

from aegis.core.enums import NoticeCode, NoticeLevel
from aegis.core.models import ManifestFile
from aegis.parsers.go_mod import GoModParser
from aegis.parsers.package_json import PackageJsonParser
from aegis.parsers.package_lock import PackageLockParser

Factory = Callable[[str], ManifestFile]

PACKAGE_JSON = json.dumps(
    {
        "dependencies": {"axios": "1.6.0", "lodash": "^4.17.0", "left": "=2.0.0-beta.1+build.5", "g": "git+https://x"},
        "devDependencies": {"jest": "v29.0.0", "weird": 5},
        "peerDependencies": {"react": ">=17"},
        "optionalDependencies": {"fsevents": "2.3.2"},
    }
)


def test_package_json_pins_and_scope(make_manifest: Factory) -> None:
    result = PackageJsonParser().parse(make_manifest("package.json"), PACKAGE_JSON)
    assert {d.name: d.version for d in result.dependencies} == {
        "axios": "1.6.0",
        "lodash": None,
        "left": "2.0.0-beta.1",
        "g": None,
        "jest": "29.0.0",
    }
    assert all(d.direct is True for d in result.dependencies)
    assert {n.code for n in result.notices} == {
        NoticeCode.PARTIAL_PARSE,
        NoticeCode.OUT_OF_SCOPE_DEPENDENCIES,
    }


def test_package_json_invalid(make_manifest: Factory) -> None:
    for text in ("{not json", "[]", "[" * 100_000):
        result = PackageJsonParser().parse(make_manifest("package.json"), text)
        assert result.dependencies == ()
        assert [n.code for n in result.notices] == [NoticeCode.PARSE_FAILED]


PACKAGE_LOCK = """\
{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"a": "^1", "b": "^1"}, "devDependencies": {"d": "^1"}},
    "node_modules/@scope/pkg": {"version": "3.0.0"},
    "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^2", "shared": "^1"}},
    "node_modules/a/node_modules/c": {"version": "2.0.0", "dependencies": {"e": "^1"}},
    "node_modules/b": {"version": "1.1.0", "dependencies": {"shared": "^1"}},
    "node_modules/c": {"version": "1.5.0"},
    "node_modules/d": {"version": "1.0.0", "dev": true},
    "node_modules/e": {"version": "1.0.0"},
    "node_modules/local": {"resolved": "packages/local", "link": true},
    "node_modules/shared": {"version": "1.2.3"},
    "packages/local": {"version": ""}
  }
}
"""


def test_package_lock_direct_parents_and_local_packages(make_manifest: Factory) -> None:
    result = PackageLockParser().parse(make_manifest("package-lock.json"), PACKAGE_LOCK)
    by_id = {(d.name, d.version): d for d in result.dependencies}

    for key in (("a", "1.0.0"), ("b", "1.1.0"), ("d", "1.0.0")):
        assert by_id[key].direct is True and by_id[key].resolved_from is None
    assert by_id[("c", "2.0.0")].direct is False
    assert by_id[("c", "2.0.0")].resolved_from == "a@1.0.0"
    assert by_id[("c", "1.5.0")].direct is False
    assert by_id[("c", "1.5.0")].resolved_from is None
    assert by_id[("e", "1.0.0")].resolved_from == "c@2.0.0"
    assert by_id[("shared", "1.2.3")].resolved_from == "a@1.0.0"
    assert by_id[("@scope/pkg", "3.0.0")].direct is False

    local = [d for d in result.dependencies if d.name == "local"]
    assert len(local) == 2 and all(d.version is None for d in local)
    (notice,) = result.notices
    assert notice.code is NoticeCode.UNVERSIONED_PACKAGES
    assert notice.level is NoticeLevel.INFO
    assert "2" in notice.message


def test_package_lock_line_numbers(make_manifest: Factory) -> None:
    result = PackageLockParser().parse(make_manifest("package-lock.json"), PACKAGE_LOCK)
    lines = PACKAGE_LOCK.splitlines()
    expected = next(i for i, text in enumerate(lines, 1) if text.strip().startswith('"node_modules/a":'))
    a = next(d for d in result.dependencies if d.name == "a")
    assert a.line == expected


def test_package_lock_without_root_entry_has_unknown_direct(make_manifest: Factory) -> None:
    text = json.dumps({"packages": {"node_modules/a": {"version": "1.0.0"}}})
    (dep,) = PackageLockParser().parse(make_manifest("package-lock.json"), text).dependencies
    assert dep.direct is None


def test_package_lock_alias_uses_real_name(make_manifest: Factory) -> None:
    text = json.dumps(
        {
            "packages": {
                "": {"dependencies": {"foo": "npm:bar@1"}},
                "node_modules/foo": {"name": "bar", "version": "1.0.0"},
            }
        }
    )
    (dep,) = PackageLockParser().parse(make_manifest("package-lock.json"), text).dependencies
    assert (dep.name, dep.version, dep.direct) == ("bar", "1.0.0", True)


def test_package_lock_rejects_v1_and_garbage(make_manifest: Factory) -> None:
    for text in ('{"lockfileVersion": 1, "dependencies": {}}', "not json", "[]"):
        result = PackageLockParser().parse(make_manifest("package-lock.json"), text)
        assert result.dependencies == ()
        assert [n.code for n in result.notices] == [NoticeCode.PARSE_FAILED]


GO_MOD = """\
module example.com/app

go 1.21

require github.com/a/b v1.2.3
require (
\tgithub.com/c/d v0.1.0 // indirect
\tgolang.org/x/text v0.3.7 // indirect; pinned by x
\tgithub.com/e/f v1.0.0-20210101000000-abcdef123456
\tgithub.com/bad/entry
)

replace github.com/a/b => ../b

exclude (
\tgithub.com/x/y v1.0.0
)
"""


def test_go_mod_requires_indirect_and_pseudo_versions(make_manifest: Factory) -> None:
    result = GoModParser().parse(make_manifest("go.mod"), GO_MOD)
    lines = GO_MOD.splitlines()
    by_name = {d.name: d for d in result.dependencies}
    assert {n: (d.version, d.direct) for n, d in by_name.items()} == {
        "github.com/a/b": ("v1.2.3", True),
        "github.com/c/d": ("v0.1.0", False),
        "golang.org/x/text": ("v0.3.7", False),
        "github.com/e/f": ("v1.0.0-20210101000000-abcdef123456", True),
    }
    assert by_name["github.com/a/b"].line == lines.index("require github.com/a/b v1.2.3") + 1
    assert {n.code for n in result.notices} == {
        NoticeCode.PARTIAL_PARSE,
        NoticeCode.OUT_OF_SCOPE_DEPENDENCIES,
    }


def test_go_mod_without_requires(make_manifest: Factory) -> None:
    result = GoModParser().parse(make_manifest("go.mod"), "module x\n\ngo 1.21\n")
    assert result.dependencies == () and result.notices == ()
