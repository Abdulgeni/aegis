"""Evaluate OSV affected ranges.

An OSV range is an event list. Events build up vulnerable intervals as follows:

* ``introduced`` opens a vulnerable interval at that version (inclusive). The literal
  value ``"0"`` means "the beginning of time" and is treated as unbounded-below.
* ``fixed`` closes the interval; that version and anything higher are NOT in the
  interval (exclusive upper bound).
* ``last_affected`` closes the interval; that version IS in the interval (inclusive).
* ``limit`` is treated as an exclusive upper bound, the same as ``fixed``.

Multiple intro/close pairs in one range describe multiple vulnerable windows. Ranges of
type ``GIT`` are recorded and skipped (they use commit hashes, not versions). A range
whose events cannot be parsed, or a candidate version that cannot be parsed, yields
``UNVERIFIABLE`` for that range - never a silent "safe" answer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any

from aegis.versions.base import VersionMatcher


class RangeVerdict(StrEnum):
    """Three-state result of evaluating a version against OSV ranges."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNVERIFIABLE = "unverifiable"


def evaluate(
    version: str,
    ranges: Sequence[Mapping[str, Any]],
    matcher: VersionMatcher[Any],
) -> RangeVerdict:
    """Whether ``version`` falls into any of the OSV ``ranges``.

    Combines per-range verdicts: any ``AFFECTED`` wins; all ``NOT_AFFECTED`` gives
    ``NOT_AFFECTED``; any other mix gives ``UNVERIFIABLE``.
    """
    parsed = matcher.parse(version)
    if parsed is None:
        return RangeVerdict.UNVERIFIABLE
    saw_unverifiable = False
    for range_ in ranges:
        verdict = _evaluate_range(parsed, range_, matcher)
        if verdict is RangeVerdict.AFFECTED:
            return RangeVerdict.AFFECTED
        if verdict is RangeVerdict.UNVERIFIABLE:
            saw_unverifiable = True
    return RangeVerdict.UNVERIFIABLE if saw_unverifiable else RangeVerdict.NOT_AFFECTED


def evaluate_exact_match(
    version: str,
    versions: Sequence[str],
    matcher: VersionMatcher[Any],
) -> RangeVerdict:
    """Whether ``version`` appears in the OSV ``affected[].versions`` exact-match list."""
    parsed = matcher.parse(version)
    if parsed is None:
        return RangeVerdict.UNVERIFIABLE
    unparseable = False
    for item in versions:
        other = matcher.parse(item)
        if other is None:
            unparseable = True
            continue
        if matcher.compare(parsed, other) == 0:
            return RangeVerdict.AFFECTED
    return RangeVerdict.UNVERIFIABLE if unparseable else RangeVerdict.NOT_AFFECTED


class _Sentinel:
    """Sentinel marker for parse failures and unbounded intervals."""


_PARSE_ERROR = _Sentinel()
_UNBOUNDED = _Sentinel()


def _evaluate_range(
    parsed: Any,
    range_: Mapping[str, Any],
    matcher: VersionMatcher[Any],
) -> RangeVerdict:
    range_type = range_.get("type")
    if range_type == "GIT":
        return RangeVerdict.UNVERIFIABLE
    if range_type not in ("SEMVER", "ECOSYSTEM"):
        return RangeVerdict.UNVERIFIABLE
    events = range_.get("events")
    if not isinstance(events, list):
        return RangeVerdict.UNVERIFIABLE
    lower: Any = None
    for event in events:
        if not isinstance(event, Mapping):
            return RangeVerdict.UNVERIFIABLE
        if "introduced" in event:
            lower = _parse_lower(event["introduced"], matcher)
            if lower is _PARSE_ERROR:
                return RangeVerdict.UNVERIFIABLE
        elif "fixed" in event:
            verdict = _check_close(parsed, lower, event["fixed"], matcher, upper_inclusive=False)
            if verdict is not RangeVerdict.NOT_AFFECTED:
                return verdict
            lower = None
        elif "last_affected" in event:
            verdict = _check_close(
                parsed, lower, event["last_affected"], matcher, upper_inclusive=True
            )
            if verdict is not RangeVerdict.NOT_AFFECTED:
                return verdict
            lower = None
        elif "limit" in event:
            verdict = _check_close(parsed, lower, event["limit"], matcher, upper_inclusive=False)
            if verdict is not RangeVerdict.NOT_AFFECTED:
                return verdict
            lower = None
        else:
            return RangeVerdict.UNVERIFIABLE
    if (
        lower is not None
        and lower is not _UNBOUNDED
        and matcher.compare(parsed, lower) >= 0
    ):
        return RangeVerdict.AFFECTED
    return RangeVerdict.NOT_AFFECTED


def _parse_lower(value: Any, matcher: VersionMatcher[Any]) -> Any:
    """Parse an ``introduced`` value; return ``_UNBOUNDED`` for ``"0"`` or ``_PARSE_ERROR``."""
    if value == "0":
        return _UNBOUNDED
    if not isinstance(value, str):
        return _PARSE_ERROR
    parsed = matcher.parse(value)
    return _PARSE_ERROR if parsed is None else parsed


def _check_close(
    parsed: Any,
    lower: Any,
    raw_upper: Any,
    matcher: VersionMatcher[Any],
    *,
    upper_inclusive: bool,
) -> RangeVerdict:
    """Whether ``parsed`` is in the interval opened by ``lower`` and closed at ``raw_upper``."""
    if lower is _PARSE_ERROR:
        return RangeVerdict.UNVERIFIABLE
    if not isinstance(raw_upper, str):
        return RangeVerdict.UNVERIFIABLE
    upper = matcher.parse(raw_upper)
    if upper is None:
        return RangeVerdict.UNVERIFIABLE
    below = True if lower is _UNBOUNDED else matcher.compare(parsed, lower) >= 0
    if not below:
        return RangeVerdict.NOT_AFFECTED
    cmp = matcher.compare(parsed, upper)
    if upper_inclusive:
        return RangeVerdict.AFFECTED if cmp <= 0 else RangeVerdict.NOT_AFFECTED
    return RangeVerdict.AFFECTED if cmp < 0 else RangeVerdict.NOT_AFFECTED