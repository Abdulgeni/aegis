from __future__ import annotations

from aegis.osv.models import parse_vuln


def _base(**extra: object) -> dict[str, object]:
    data: dict[str, object] = {"id": "GHSA-xxxx-yyyy-zzzz"}
    data.update(extra)
    return data


def test_minimal_record() -> None:
    record = parse_vuln(_base())
    assert record is not None
    assert record.id == "GHSA-xxxx-yyyy-zzzz"
    assert record.aliases == ()
    assert record.severity == ()
    assert record.affected == ()


def test_missing_id_is_unusable() -> None:
    assert parse_vuln({"summary": "x"}) is None
    assert parse_vuln({"id": ""}) is None
    assert parse_vuln({"id": 42}) is None


def test_cve_aliases_include_id_and_aliases() -> None:
    record = parse_vuln(_base(aliases=["CVE-2024-1234", "OSV-2024-1", "CVE-2023-0001"]))
    assert record is not None
    assert record.cve_aliases == ("CVE-2023-0001", "CVE-2024-1234")


def test_cve_as_id_is_used() -> None:
    record = parse_vuln({"id": "CVE-2024-9999"})
    assert record is not None
    assert record.cve_aliases == ("CVE-2024-9999",)


def test_severity_list_is_tolerant() -> None:
    record = parse_vuln(
        _base(
            severity=[
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"},
                {"type": "CVSS_V4"},  # missing score
                "not-a-dict",
                {"type": "CVSS_V3", "score": "bad vector"},  # wrong type ignored upstream
            ]
        )
    )
    assert record is not None
    assert [s.type for s in record.severity] == ["CVSS_V3", "CVSS_V3"]


def test_affected_is_parsed_when_well_formed() -> None:
    record = parse_vuln(
        _base(
            affected=[
                {
                    "package": {"ecosystem": "PyPI", "name": "requests", "purl": "pkg:pypi/requests"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    "versions": ["1.0.0", "1.0.1"],
                },
                "not-a-mapping",
                {"package": "wrong-type"},
            ]
        )
    )
    assert record is not None
    assert len(record.affected) == 1
    entry = record.affected[0]
    assert entry.package.ecosystem == "PyPI"
    assert entry.package.name == "requests"
    assert entry.versions == ("1.0.0", "1.0.1")
    assert entry.ranges[0]["type"] == "ECOSYSTEM"


def test_references_require_a_url() -> None:
    record = parse_vuln(
        _base(
            references=[
                {"type": "ADVISORY", "url": "https://example.com/1"},
                {"type": "WEB"},
                "not-a-mapping",
            ]
        )
    )
    assert record is not None
    assert [r.url for r in record.references] == ["https://example.com/1"]


def test_raw_payload_is_preserved() -> None:
    payload = _base(summary="test summary", unknown_field=[1, 2, 3])
    record = parse_vuln(payload)
    assert record is not None
    assert record.raw["unknown_field"] == [1, 2, 3]
    assert record.summary == "test summary"
