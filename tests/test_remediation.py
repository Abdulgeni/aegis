from __future__ import annotations

from typing import Any

from aegis.core.enums import Ecosystem
from aegis.core.models import Dependency, Finding, FixStatus, Remediation, Severity, UpgradeDistance
from aegis.osv.models import parse_vuln
from aegis.remediation.commands import suggest_command
from aegis.remediation.fixes import fix_for
from aegis.remediation.grouping import assign_groups
from aegis.remediation.ranking import rank


def _dep(
    name: str = "requests",
    version: str = "2.31.0",
    direct: bool | None = True,
    source: str = "poetry.lock",
    resolved_from: str | None = None,
) -> Dependency:
    return Dependency(
        name=name,
        version=version,
        ecosystem=Ecosystem.PYPI,
        direct=direct,
        source=source,
        resolved_from=resolved_from,
    )


def _record(events: list[dict[str, str]]) -> Any:
    payload = {
        "id": "GHSA-xxxx",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
    }
    parsed = parse_vuln(payload)
    assert parsed is not None
    return parsed


def test_patch_fix_is_safe_upgrade() -> None:
    record = _record([{"introduced": "0"}, {"fixed": "2.31.5"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", True, [_dep()])
    assert remediation.status is FixStatus.AVAILABLE
    assert remediation.fixed_version == "2.31.5"
    assert remediation.safe_upgrade is True
    assert remediation.distance is UpgradeDistance.PATCH


def test_major_fix_is_not_safe_upgrade() -> None:
    record = _record([{"introduced": "0"}, {"fixed": "3.0.0"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", True, [_dep()])
    assert remediation.status is FixStatus.AVAILABLE
    assert remediation.fixed_version == "3.0.0"
    assert remediation.safe_upgrade is False
    assert remediation.distance is UpgradeDistance.MAJOR


def test_no_fix_when_range_has_no_fixed_event() -> None:
    record = _record([{"introduced": "0"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", True, [_dep()])
    assert remediation.status is FixStatus.NO_FIX


def test_patch_distance() -> None:
    record = _record([{"introduced": "0"}, {"fixed": "2.31.5"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", True, [_dep()])
    assert remediation.distance is UpgradeDistance.PATCH
    assert remediation.safe_upgrade is True


def test_minor_distance() -> None:
    record = _record([{"introduced": "0"}, {"fixed": "2.40.0"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", True, [_dep()])
    assert remediation.distance is UpgradeDistance.MINOR
    assert remediation.safe_upgrade is True


def test_major_distance_is_not_safe() -> None:
    record = _record([{"introduced": "0"}, {"fixed": "3.0.0"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", True, [_dep()])
    assert remediation.distance is UpgradeDistance.MAJOR
    assert remediation.safe_upgrade is False


def test_npm_zero_x_minor_bump_is_major_equivalent() -> None:
    payload = {
        "id": "GHSA-yyyy",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.5.0"}]}],
            }
        ],
    }
    record = parse_vuln(payload)
    assert record is not None
    remediation = fix_for(
        record,
        Ecosystem.NPM,
        "left-pad",
        "0.4.0",
        True,
        [
            Dependency(
                name="left-pad",
                version="0.4.0",
                ecosystem=Ecosystem.NPM,
                direct=True,
                source="package-lock.json",
            )
        ],
    )
    assert remediation.distance is UpgradeDistance.MAJOR
    assert remediation.safe_upgrade is False


def test_pypi_command_is_suggested() -> None:
    record = _record([{"introduced": "0"}, {"fixed": "3.0.0"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", True, [_dep()])
    assert remediation.command is not None
    assert "pip install" in remediation.command
    assert "requests>=3.0.0" in remediation.command


def test_transitive_command_uses_parent() -> None:
    parent = _dep(source="poetry.lock")
    child = Dependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        direct=False,
        source="poetry.lock",
        resolved_from="some-parent@1.0.0",
    )
    record = _record([{"introduced": "0"}, {"fixed": "3.0.0"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", False, [child, parent])
    assert remediation.command is not None
    assert "some-parent" in remediation.command
    assert any("constraints" in alt for alt in remediation.alternatives)


def test_path_is_set_for_transitive_chain() -> None:
    a = Dependency(
        name="a", version="1.0", ecosystem=Ecosystem.PYPI, direct=True, source="lock"
    )
    b = Dependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        direct=False,
        source="lock",
        resolved_from="a@1.0",
    )
    record = _record([{"introduced": "0"}, {"fixed": "3.0.0"}])
    remediation = fix_for(record, Ecosystem.PYPI, "requests", "2.31.0", False, [b, a])
    assert remediation.path == ("a@1.0", "requests@2.31.0")


def test_npm_command_syntax() -> None:
    command, _ = suggest_command(Ecosystem.NPM, "axios", "1.6.0", True, [])
    assert command == "npm install axios@^1.6.0"


def test_go_command_syntax() -> None:
    command, _ = suggest_command(Ecosystem.GO, "github.com/x/y", "1.2.3", True, [])
    assert command is not None
    assert command.startswith("go get github.com/x/y@v")


class TestRanking:
    def _finding(
        self,
        severity_rank: int,
        direct: bool | None,
        distance: UpgradeDistance | None,
        name: str = "pkg",
        vuln_id: str = "CVE-1",
    ) -> Finding:
        severity = [
            Severity.UNKNOWN,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ][severity_rank]
        return Finding(
            vuln_id=vuln_id,
            package=name,
            version="1.0.0",
            ecosystem=Ecosystem.PYPI,
            severity=severity,
            direct=direct,
            remediation=Remediation(status=FixStatus.AVAILABLE, distance=distance),
        )

    def test_severity_dominates(self) -> None:
        a = self._finding(4, False, UpgradeDistance.MAJOR)
        b = self._finding(0, True, UpgradeDistance.PATCH)
        assert rank([b, a]) == [a, b]

    def test_direct_before_transitive_at_same_severity(self) -> None:
        a = self._finding(4, True, UpgradeDistance.MAJOR)
        b = self._finding(4, False, UpgradeDistance.PATCH)
        assert rank([b, a]) == [a, b]

    def test_smaller_distance_first_at_same_severity_and_directness(self) -> None:
        a = self._finding(4, True, UpgradeDistance.PATCH)
        b = self._finding(4, True, UpgradeDistance.MAJOR)
        assert rank([b, a]) == [a, b]

    def test_total_tiebreak_by_name_then_id(self) -> None:
        a = self._finding(4, True, UpgradeDistance.PATCH, name="aaa")
        b = self._finding(4, True, UpgradeDistance.PATCH, name="bbb")
        assert rank([b, a]) == [a, b]


class TestGrouping:
    def _finding(self, name: str, source: str) -> Finding:
        return Finding(
            vuln_id="CVE-1",
            package=name,
            version="1.0.0",
            ecosystem=Ecosystem.PYPI,
            severity=Severity.HIGH,
            direct=True,
            sources=(source,),
            remediation=Remediation(status=FixStatus.AVAILABLE, fixed_version="2.0.0"),
        )

    def test_two_findings_same_source_get_same_group(self) -> None:
        a = self._finding("a", "lock")
        b = self._finding("b", "lock")
        grouped = assign_groups([a, b])
        assert grouped[0].group_id is not None
        assert grouped[0].group_id == grouped[1].group_id

    def test_single_finding_no_group(self) -> None:
        a = self._finding("a", "lock")
        assert assign_groups([a])[0].group_id is None

    def test_no_fix_findings_not_grouped(self) -> None:
        a = Finding(
            vuln_id="CVE-1",
            package="a",
            version="1.0.0",
            ecosystem=Ecosystem.PYPI,
            severity=Severity.HIGH,
            direct=True,
            sources=("lock",),
            remediation=Remediation(status=FixStatus.NO_FIX),
        )
        b = self._finding("b", "lock")
        grouped = assign_groups([a, b])
        assert grouped[0].group_id is None
        assert grouped[1].group_id is None
