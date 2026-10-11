from __future__ import annotations

import math

import pytest

from aegis.core.enums import Ecosystem, Severity
from aegis.core.names import normalize_name


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("High", Severity.HIGH),
        ("MODERATE", Severity.MEDIUM),
        (" moderate ", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("unknown", Severity.UNKNOWN),
        ("urgent", None),
    ],
)
def test_severity_from_label(label: str, expected: Severity | None) -> None:
    assert Severity.from_label(label) is expected


def test_severity_normalize_falls_back_to_unknown() -> None:
    assert Severity.normalize(None) is Severity.UNKNOWN
    assert Severity.normalize("nonsense") is Severity.UNKNOWN
    assert Severity.normalize("moderate") is Severity.MEDIUM


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.UNKNOWN),
        (10.1, Severity.UNKNOWN),
        (-1.0, Severity.UNKNOWN),
        (math.nan, Severity.UNKNOWN),
    ],
)
def test_severity_from_score_bands(score: float, expected: Severity) -> None:
    assert Severity.from_score(score) is expected


def test_severity_ordering() -> None:
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert Severity.HIGH.at_least(Severity.HIGH)
    assert not Severity.LOW.at_least(Severity.MEDIUM)
    assert Severity.UNKNOWN.rank < Severity.LOW.rank


def test_ecosystem_parse_is_case_insensitive() -> None:
    assert Ecosystem.parse("pypi") is Ecosystem.PYPI
    assert Ecosystem.parse("NPM") is Ecosystem.NPM
    assert Ecosystem.parse("go") is Ecosystem.GO
    assert Ecosystem.parse("rust") is None


def test_pypi_names_follow_pep503() -> None:
    assert normalize_name(Ecosystem.PYPI, "Django_REST.framework") == "django-rest-framework"
    assert normalize_name(Ecosystem.PYPI, "a--b__c..d") == "a-b-c-d"


def test_npm_and_go_names_are_preserved() -> None:
    assert normalize_name(Ecosystem.NPM, " @Scope/Pkg ") == "@Scope/Pkg"
    assert normalize_name(Ecosystem.GO, "github.com/Foo/Bar") == "github.com/Foo/Bar"
