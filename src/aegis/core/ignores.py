"""Ignore rule matching and application.

An ``IgnoreRule`` suppresses a finding when its ``id`` equals the finding's
``vuln_id`` or appears in the finding's ``aliases``. An optional ``package`` further
restricts the match to one package name (normalized per ecosystem).

``until`` is a ``date``. A rule with ``until`` in the past stops suppressing its findings
and is reported as expired. A rule that matches no findings is reported as unused.
Both cases produce INFO or WARNING notices so the user knows their suppression list is
not doing what they think it is.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date

from aegis.core.config import IgnoreRule
from aegis.core.enums import NoticeCode
from aegis.core.models import Finding, Notice
from aegis.core.names import normalize_name
from aegis.parsers._common import info, warn


@dataclass(frozen=True)
class IgnoreOutcome:
    """Result of applying ignore rules: findings to keep, plus audit notices."""

    kept: tuple[Finding, ...]
    suppressed: tuple[Finding, ...]
    notices: tuple[Notice, ...]


def apply_ignores(
    findings: Sequence[Finding],
    rules: Sequence[IgnoreRule],
    *,
    today: date | None = None,
) -> IgnoreOutcome:
    """Apply ignore rules to a list of findings.

    Args:
        findings: Ranked or unranked findings, unmodified.
        rules: Rules from the config file.
        today: Override for the current date (for deterministic tests).
    """
    today = today or date.today()
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    used_rule_ids: set[int] = set()
    notices: list[Notice] = []

    for finding in findings:
        matched = _first_matching_rule(finding, rules, today)
        if matched is None:
            kept.append(finding)
            continue
        suppressed.append(finding)
        used_rule_ids.add(id(matched))

    for rule in rules:
        if id(rule) in used_rule_ids:
            continue
        if rule.until is not None and rule.until < today:
            notices.append(
                warn(
                    NoticeCode.SEVERITY_OVERRIDDEN,
                    f"ignore rule for {rule.id!r} expired on {rule.until.isoformat()} "
                    "and no longer suppresses anything",
                    None,
                )
            )
        else:
            notices.append(
                info(
                    NoticeCode.SEVERITY_OVERRIDDEN,
                    f"ignore rule for {rule.id!r} matched no findings",
                    None,
                )
            )

    return IgnoreOutcome(
        kept=tuple(kept),
        suppressed=tuple(suppressed),
        notices=tuple(notices),
    )


def _first_matching_rule(
    finding: Finding, rules: Sequence[IgnoreRule], today: date
) -> IgnoreRule | None:
    for rule in rules:
        if not _matches(finding, rule, today):
            continue
        return rule
    return None


def _matches(finding: Finding, rule: IgnoreRule, today: date) -> bool:
    if rule.until is not None and rule.until < today:
        return False
    if rule.id not in {finding.vuln_id, *finding.aliases}:
        return False
    if rule.package is None:
        return True
    return normalize_name(finding.ecosystem, rule.package) == finding.package


def active_and_expired(
    rules: Sequence[IgnoreRule], today: date | None = None
) -> tuple[list[IgnoreRule], list[IgnoreRule]]:
    """Split rules into (active, expired) based on ``until``."""
    today = today or date.today()
    active = [r for r in rules if r.until is None or r.until >= today]
    expired = [r for r in rules if r.until is not None and r.until < today]
    return active, expired


def iter_rule_ids(rules: Iterable[IgnoreRule]) -> list[str]:
    """Stable sorted list of rule IDs, used by the CLI for display."""
    return sorted({rule.id for rule in rules})
