from __future__ import annotations

from collections.abc import Callable

from aegis.core.enums import NoticeCode, NoticeLevel
from aegis.core.models import ManifestFile
from aegis.parsers.poetry_lock import PoetryLockParser
from aegis.parsers.pyproject import PyprojectParser
from aegis.parsers.requirements_txt import RequirementsTxtParser

Factory = Callable[[str], ManifestFile]

REQUIREMENTS = """\
# comment
requests==2.31.0  # inline comment
Django_REST.framework>=3.0,<4
flask[async]==2.0.1 ; python_version >= "3.8"
urllib3==1.26.*
numpy==1.26.0 \\
    --hash=sha256:aaa \\
    --hash=sha256:bbb
pkg @ https://example.com/pkg.tar.gz
-r base.txt
-e .
--index-url https://example.com/simple
git+https://github.com/a/b.git#egg=b
"""

EXPECTED_REQUIREMENTS = {
    "requests": ("2.31.0", 2),
    "django-rest-framework": (None, 3),
    "flask": ("2.0.1", 4),
    "urllib3": (None, 5),
    "numpy": ("1.26.0", 6),
    "pkg": (None, 9),
}


def test_requirements_pins_lines_and_skips(make_manifest: Factory) -> None:
    result = RequirementsTxtParser().parse(make_manifest("requirements.txt"), REQUIREMENTS)
    assert {d.name: (d.version, d.line) for d in result.dependencies} == EXPECTED_REQUIREMENTS
    assert all(d.direct is True and d.source == "requirements.txt" for d in result.dependencies)
    (notice,) = result.notices
    assert notice.code is NoticeCode.PARTIAL_PARSE
    assert notice.level is NoticeLevel.WARNING
    assert "line 13" in notice.message


def test_requirements_handles_crlf(make_manifest: Factory) -> None:
    text = REQUIREMENTS.replace("\n", "\r\n")
    result = RequirementsTxtParser().parse(make_manifest("requirements.txt"), text)
    assert {d.name: (d.version, d.line) for d in result.dependencies} == EXPECTED_REQUIREMENTS


def test_requirements_supports(make_manifest: Factory) -> None:
    parser = RequirementsTxtParser()
    assert parser.supports(make_manifest("requirements/base.txt"))
    assert parser.supports(make_manifest("requirements-dev.txt"))
    assert not parser.supports(make_manifest("pyproject.toml"))


PYPROJECT = """\
[project]
name = "app"
dependencies = ["Requests==2.31.0", "click>=8", "bad dep !!"]

[project.optional-dependencies]
dev = ["pytest"]

[dependency-groups]
test = ["coverage==7.0", {include-group = "other"}]

[tool.poetry.dependencies]
python = "^3.11"
flask = "2.0.1"
django = {version = "^4.0", optional = true}
rich = {version = "==13.0.0"}
gitdep = {git = "https://example.com/x.git"}

[tool.poetry.group.dev.dependencies]
pytest = "^8"
"""


def test_pyproject_reads_pep621_groups_and_poetry(make_manifest: Factory) -> None:
    result = PyprojectParser().parse(make_manifest("pyproject.toml"), PYPROJECT)
    assert {d.name: d.version for d in result.dependencies} == {
        "requests": "2.31.0",
        "click": None,
        "coverage": "7.0",
        "flask": "2.0.1",
        "django": None,
        "rich": "13.0.0",
        "gitdep": None,
        "pytest": None,
    }
    assert all(d.direct is True and d.line is None for d in result.dependencies)
    assert {n.code for n in result.notices} == {
        NoticeCode.PARTIAL_PARSE,
        NoticeCode.OUT_OF_SCOPE_DEPENDENCIES,
    }
    out_of_scope = next(n for n in result.notices if n.code is NoticeCode.OUT_OF_SCOPE_DEPENDENCIES)
    assert out_of_scope.level is NoticeLevel.INFO


def test_pyproject_invalid_toml_is_a_warning(make_manifest: Factory) -> None:
    result = PyprojectParser().parse(make_manifest("pyproject.toml"), "[project\n")
    assert result.dependencies == ()
    assert [n.code for n in result.notices] == [NoticeCode.PARSE_FAILED]


def test_pyproject_tolerates_wrong_types(make_manifest: Factory) -> None:
    text = 'project = "nope"\n[tool]\npoetry = 3\n'
    result = PyprojectParser().parse(make_manifest("pyproject.toml"), text)
    assert result.dependencies == () and result.notices == ()


POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP"

[package.dependencies]
urllib3 = ">=1.21.1,<3"
Charset_Normalizer = ">=2,<4"

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "charset-normalizer"
version = "3.3.2"

[metadata]
lock-version = "2.0"
"""


def test_poetry_lock_packages_lines_and_parents(make_manifest: Factory) -> None:
    result = PoetryLockParser().parse(make_manifest("poetry.lock"), POETRY_LOCK)
    by_name = {d.name: d for d in result.dependencies}
    assert {n: d.version for n, d in by_name.items()} == {
        "requests": "2.31.0",
        "urllib3": "2.0.7",
        "charset-normalizer": "3.3.2",
    }
    assert all(d.direct is None for d in result.dependencies)
    assert by_name["requests"].resolved_from is None
    assert by_name["urllib3"].resolved_from == "requests@2.31.0"
    assert by_name["charset-normalizer"].resolved_from == "requests@2.31.0"
    lines = POETRY_LOCK.splitlines()
    assert by_name["urllib3"].line == lines.index('name = "urllib3"') + 1
    assert result.notices == ()


def test_poetry_lock_invalid_toml_and_empty(make_manifest: Factory) -> None:
    bad = PoetryLockParser().parse(make_manifest("poetry.lock"), "[[package]\n")
    assert [n.code for n in bad.notices] == [NoticeCode.PARSE_FAILED]
    empty = PoetryLockParser().parse(make_manifest("poetry.lock"), "[metadata]\n")
    assert empty.dependencies == () and empty.notices == ()
