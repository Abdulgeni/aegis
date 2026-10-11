from __future__ import annotations

from typing import Any

from aegis.core.enums import Ecosystem
from aegis.versions import matcher_for
from aegis.versions.osv_ranges import RangeVerdict, evaluate, evaluate_exact_match

PYPI = matcher_for(Ecosystem.PYPI)
NPM = matcher_for(Ecosystem.NPM)
GO = matcher_for(Ecosystem.GO)


def _range(kind: str, *events: dict[str, str]) -> dict[str, Any]:
    return {"type": kind, "events": list(events)}


def _intro(v: str) -> dict[str, str]:
    return {"introduced": v}


def _fix(v: str) -> dict[str, str]:
    return {"fixed": v}


def _last(v: str) -> dict[str, str]:
    return {"last_affected": v}


def _limit(v: str) -> dict[str, str]:
    return {"limit": v}


class TestSingleInterval:
    def test_introduced_zero_fixed_exclusive(self) -> None:
        ranges = [_range("ECOSYSTEM", _intro("0"), _fix("2.0.0"))]
        assert evaluate("1.5.0", ranges, PYPI) is RangeVerdict.AFFECTED
        assert evaluate("2.0.0", ranges, PYPI) is RangeVerdict.NOT_AFFECTED
        assert evaluate("2.0.1", ranges, PYPI) is RangeVerdict.NOT_AFFECTED

    def test_introduced_specific(self) -> None:
        ranges = [_range("SEMVER", _intro("1.0.0"), _fix("2.0.0"))]
        assert evaluate("0.9.9", ranges, NPM) is RangeVerdict.NOT_AFFECTED
        assert evaluate("1.0.0", ranges, NPM) is RangeVerdict.AFFECTED
        assert evaluate("1.9.9", ranges, NPM) is RangeVerdict.AFFECTED
        assert evaluate("2.0.0", ranges, NPM) is RangeVerdict.NOT_AFFECTED

    def test_last_affected_inclusive(self) -> None:
        ranges = [_range("ECOSYSTEM", _intro("1.0.0"), _last("2.0.0"))]
        assert evaluate("2.0.0", ranges, PYPI) is RangeVerdict.AFFECTED
        assert evaluate("2.0.1", ranges, PYPI) is RangeVerdict.NOT_AFFECTED

    def test_limit_treated_as_exclusive_upper_bound(self) -> None:
        ranges = [_range("ECOSYSTEM", _intro("1.0.0"), _limit("2.0.0"))]
        assert evaluate("2.0.0", ranges, PYPI) is RangeVerdict.NOT_AFFECTED
        assert evaluate("1.9.9", ranges, PYPI) is RangeVerdict.AFFECTED

    def test_open_ended_interval(self) -> None:
        ranges = [_range("ECOSYSTEM", _intro("1.0.0"))]
        assert evaluate("0.9.9", ranges, PYPI) is RangeVerdict.NOT_AFFECTED
        assert evaluate("1.0.0", ranges, PYPI) is RangeVerdict.AFFECTED
        assert evaluate("99.0.0", ranges, PYPI) is RangeVerdict.AFFECTED


class TestMultipleIntervals:
    def test_two_windows(self) -> None:
        ranges = [
            _range("ECOSYSTEM", _intro("1.0.0"), _fix("1.5.0"), _intro("2.0.0"), _fix("2.5.0")),
        ]
        assert evaluate("0.9.0", ranges, PYPI) is RangeVerdict.NOT_AFFECTED
        assert evaluate("1.0.0", ranges, PYPI) is RangeVerdict.AFFECTED
        assert evaluate("1.4.9", ranges, PYPI) is RangeVerdict.AFFECTED
        assert evaluate("1.5.0", ranges, PYPI) is RangeVerdict.NOT_AFFECTED
        assert evaluate("1.9.0", ranges, PYPI) is RangeVerdict.NOT_AFFECTED
        assert evaluate("2.0.0", ranges, PYPI) is RangeVerdict.AFFECTED
        assert evaluate("2.4.9", ranges, PYPI) is RangeVerdict.AFFECTED
        assert evaluate("2.5.0", ranges, PYPI) is RangeVerdict.NOT_AFFECTED

    def test_multiple_ranges_any_match_wins(self) -> None:
        ranges = [
            _range("SEMVER", _intro("1.0.0"), _fix("2.0.0")),
            _range("SEMVER", _intro("3.0.0"), _fix("4.0.0")),
        ]
        assert evaluate("1.5.0", ranges, NPM) is RangeVerdict.AFFECTED
        assert evaluate("3.5.0", ranges, NPM) is RangeVerdict.AFFECTED
        assert evaluate("2.5.0", ranges, NPM) is RangeVerdict.NOT_AFFECTED


class TestUnverifiable:
    def test_unparseable_version(self) -> None:
        ranges = [_range("ECOSYSTEM", _intro("0"), _fix("2.0.0"))]
        assert evaluate("not-a-version", ranges, PYPI) is RangeVerdict.UNVERIFIABLE

    def test_unparseable_bound(self) -> None:
        ranges = [_range("ECOSYSTEM", _intro("0"), _fix("not-a-version"))]
        assert evaluate("1.0.0", ranges, PYPI) is RangeVerdict.UNVERIFIABLE

    def test_git_range_only_is_unverifiable(self) -> None:
        ranges = [{"type": "GIT", "events": [_intro("abc"), _fix("def")]}]
        assert evaluate("1.0.0", ranges, PYPI) is RangeVerdict.UNVERIFIABLE

    def test_git_range_with_semver_range(self) -> None:
        ranges = [
            {"type": "GIT", "events": [_intro("abc"), _fix("def")]},
            _range("SEMVER", _intro("1.0.0"), _fix("2.0.0")),
        ]
        assert evaluate("1.5.0", ranges, NPM) is RangeVerdict.AFFECTED
        assert evaluate("2.5.0", ranges, NPM) is RangeVerdict.UNVERIFIABLE

    def test_unknown_range_type_is_unverifiable(self) -> None:
        ranges = [{"type": "WEIRD", "events": [_intro("1.0.0"), _fix("2.0.0")]}]
        assert evaluate("1.5.0", ranges, PYPI) is RangeVerdict.UNVERIFIABLE

    def test_missing_events_is_unverifiable(self) -> None:
        assert evaluate("1.0.0", [{"type": "SEMVER"}], PYPI) is RangeVerdict.UNVERIFIABLE


class TestGoRanges:
    def test_go_pseudo_version_in_range(self) -> None:
        ranges = [_range("SEMVER", _intro("0.0.0-0"), _fix("0.1.0"))]
        assert evaluate("v0.0.0-20210101000000-abcdef123456", ranges, GO) is RangeVerdict.AFFECTED
        assert evaluate("v0.1.0", ranges, GO) is RangeVerdict.NOT_AFFECTED
        assert evaluate("v0.0.0", ranges, GO) is RangeVerdict.AFFECTED


class TestExactVersions:
    def test_exact_match_list(self) -> None:
        assert evaluate_exact_match("1.0.0", ["1.0.0", "1.0.1"], PYPI) is RangeVerdict.AFFECTED
        assert evaluate_exact_match("2.0.0", ["1.0.0", "1.0.1"], PYPI) is RangeVerdict.NOT_AFFECTED

    def test_unparseable_in_list(self) -> None:
        assert evaluate_exact_match("1.0.0", ["not-a-version"], PYPI) is RangeVerdict.UNVERIFIABLE

    def test_unparseable_candidate(self) -> None:
        assert evaluate_exact_match("bad", ["1.0.0"], PYPI) is RangeVerdict.UNVERIFIABLE
