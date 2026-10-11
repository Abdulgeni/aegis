from __future__ import annotations

from datetime import date

from aegis.core.config import IgnoreRule
from aegis.core.enums import Ecosystem, NoticeCode, Severity
from aegis.core.ignores import active_and_expired, apply_ignores
from aegis.core.models import Finding, FixStatus, Remediation


def _finding(
    vuln_id: str = "CVE-2024-1234",
    package: str = "requests",
    aliases: tuple[str, ...] = ("GHSA-aaaa",),
    ecosystem: Ecosystem = Ecosystem.PYPI,
) -> Finding:
    return Finding(
        vuln_id=vuln_id,
        aliases=aliases,
        package=package,
        version="1.0.0",
        ecosystem=ecosystem,
        severity=Severity.HIGH,
        direct=True,
        remediation=Remediation(status=FixStatus.NO_FIX),
    )


TODAY = date(2026, 6, 15)


def _rule(id_: str = "CVE-2024-1234", **kwargs: object) -> IgnoreRule:
    return IgnoreRule(id=id_, **kwargs)  # type: ignore[arg-type]


def test_no_rules_keeps_all() -> None:
    findings = [_finding()]
    outcome = apply_ignores(findings, [], today=TODAY)
    assert outcome.kept == tuple(findings)
    assert outcome.suppressed == ()
    assert outcome.notices == ()


def test_rule_matches_vuln_id() -> None:
    outcome = apply_ignores([_finding()], [_rule()], today=TODAY)
    assert outcome.kept == ()
    assert len(outcome.suppressed) == 1


def test_rule_matches_alias() -> None:
    outcome = apply_ignores([_finding()], [_rule("GHSA-aaaa")], today=TODAY)
    assert outcome.kept == ()
    assert len(outcome.suppressed) == 1


def test_rule_does_not_match_unrelated_id() -> None:
    outcome = apply_ignores([_finding()], [_rule("CVE-9999-0000")], today=TODAY)
    assert len(outcome.kept) == 1
    assert any(n.code is NoticeCode.SEVERITY_OVERRIDDEN for n in outcome.notices)


def test_package_filter_restricts_match() -> None:
    rule = _rule(package="urllib3")
    outcome = apply_ignores([_finding(package="requests")], [rule], today=TODAY)
    assert len(outcome.kept) == 1


def test_package_filter_matches_same_name() -> None:
    rule = _rule(package="requests")
    outcome = apply_ignores([_finding(package="requests")], [rule], today=TODAY)
    assert outcome.kept == ()


def test_expired_rule_does_not_suppress() -> None:
    rule = _rule(until=date(2026, 1, 1))
    outcome = apply_ignores([_finding()], [rule], today=TODAY)
    assert len(outcome.kept) == 1
    assert any(
        n.code is NoticeCode.SEVERITY_OVERRIDDEN and "expired" in n.message
        for n in outcome.notices
    )


def test_unused_rule_emits_info() -> None:
    rule = _rule("CVE-9999-0000")
    outcome = apply_ignores([_finding()], [rule], today=TODAY)
    matching = [n for n in outcome.notices if "matched no findings" in n.message]
    assert len(matching) == 1


class TestActiveAndExpired:
    def test_split(self) -> None:
        rules = [
            _rule("CVE-1"),
            _rule("CVE-2", until=date(2026, 1, 1)),
            _rule("CVE-3", until=date(2027, 1, 1)),
        ]
        active, expired = active_and_expired(rules, today=TODAY)
        assert [r.id for r in active] == ["CVE-1", "CVE-3"]
        assert [r.id for r in expired] == ["CVE-2"]
