from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aegis.core.enums import Ecosystem, NoticeCode
from aegis.core.models import Dependency
from aegis.osv.cache import OsvCache, query_key
from aegis.osv.client import BatchHit, OsvError, Query
from aegis.osv.lookup import OsvLookup


class FakeClient:
    """Fake OSV client: canned batch results and per-ID records; records failures by key."""

    def __init__(
        self,
        batch: dict[tuple[str, str, str], tuple[str, ...]] | None = None,
        records: dict[str, dict[str, Any]] | None = None,
        fail_batch: Exception | None = None,
        fail_ids: set[str] | None = None,
    ) -> None:
        self.batch = batch or {}
        self.records = records or {}
        self.fail_batch = fail_batch
        self.fail_ids = fail_ids or set()
        self.batch_calls: list[list[Query]] = []
        self.fetch_calls: list[str] = []

    async def query_batch(self, queries: list[Query]) -> list[BatchHit]:
        self.batch_calls.append(list(queries))
        if self.fail_batch is not None:
            raise self.fail_batch
        return [
            BatchHit(
                query=q,
                vuln_ids=self.batch.get((q.ecosystem, q.name, q.version), ()),
            )
            for q in queries
        ]

    async def fetch_vuln(self, vuln_id: str) -> dict[str, Any]:
        self.fetch_calls.append(vuln_id)
        if vuln_id in self.fail_ids:
            raise OsvError(f"cannot fetch {vuln_id}")
        return self.records.get(vuln_id, {"id": vuln_id})


def _dep(name: str, version: str | None, ecosystem: Ecosystem = Ecosystem.PYPI) -> Dependency:
    return Dependency(
        name=name,
        version=version,
        ecosystem=ecosystem,
        direct=True,
        source="lockfile",
    )


async def test_lookup_batches_and_fetches_records() -> None:
    client = FakeClient(
        batch={
            ("PyPI", "a", "1.0"): ("CVE-1", "CVE-2"),
            ("PyPI", "b", "2.0"): ("CVE-2",),
            ("PyPI", "c", "3.0"): (),
        },
        records={
            "CVE-1": {"id": "CVE-1", "summary": "one"},
            "CVE-2": {"id": "CVE-2", "summary": "two"},
        },
    )
    lookup = OsvLookup(client)
    records, notices = await lookup.lookup([_dep("a", "1.0"), _dep("b", "2.0"), _dep("c", "3.0")])
    assert len(client.batch_calls) == 1
    # CVE-2 is fetched only once despite appearing for both a and b
    assert sorted(client.fetch_calls) == ["CVE-1", "CVE-2"]
    assert [r.id for r in records[("PyPI", "a", "1.0")]] == ["CVE-1", "CVE-2"]
    assert [r.id for r in records[("PyPI", "b", "2.0")]] == ["CVE-2"]
    assert records[("PyPI", "c", "3.0")] == []
    assert notices == []


async def test_unversioned_dependencies_are_skipped() -> None:
    client = FakeClient()
    lookup = OsvLookup(client)
    records, notices = await lookup.lookup([_dep("a", None)])
    assert records == {}
    assert client.batch_calls == []
    assert notices == []


async def test_duplicate_queries_are_deduplicated() -> None:
    client = FakeClient(batch={("PyPI", "a", "1.0"): ("CVE-1",)}, records={"CVE-1": {"id": "CVE-1"}})
    lookup = OsvLookup(client)
    await lookup.lookup([_dep("a", "1.0"), _dep("a", "1.0"), _dep("a", "1.0")])
    assert len(client.batch_calls[0]) == 1


async def test_batch_failure_is_a_warning_and_returns_empty() -> None:
    client = FakeClient(fail_batch=OsvError("down"))
    lookup = OsvLookup(client)
    records, notices = await lookup.lookup([_dep("a", "1.0")])
    assert records == {}
    assert any(n.code is NoticeCode.OSV_REQUEST_FAILED for n in notices)
    assert any(n.code is NoticeCode.OSV_PARTIAL_RESULTS for n in notices)


async def test_record_fetch_failure_excludes_only_that_id() -> None:
    client = FakeClient(
        batch={("PyPI", "a", "1.0"): ("CVE-1", "CVE-2")},
        records={"CVE-1": {"id": "CVE-1"}},
        fail_ids={"CVE-2"},
    )
    lookup = OsvLookup(client)
    records, notices = await lookup.lookup([_dep("a", "1.0")])
    assert [r.id for r in records[("PyPI", "a", "1.0")]] == ["CVE-1"]
    assert any(n.code is NoticeCode.OSV_REQUEST_FAILED for n in notices)
    assert any(n.code is NoticeCode.OSV_PARTIAL_RESULTS for n in notices)


async def test_cache_avoids_client_calls(tmp_path: Path) -> None:
    client = FakeClient(
        batch={("PyPI", "a", "1.0"): ("CVE-1",)},
        records={"CVE-1": {"id": "CVE-1", "summary": "one"}},
    )
    cache = OsvCache(tmp_path / "c.db")
    lookup = OsvLookup(client, cache)
    first, _ = await lookup.lookup([_dep("a", "1.0")])
    assert len(client.batch_calls) == 1 and len(client.fetch_calls) == 1

    second_client = FakeClient()
    lookup2 = OsvLookup(second_client, cache)
    second, notices = await lookup2.lookup([_dep("a", "1.0")])
    assert second_client.batch_calls == [] and second_client.fetch_calls == []
    assert first[("PyPI", "a", "1.0")][0].id == second[("PyPI", "a", "1.0")][0].id
    assert notices == []


async def test_cache_miss_writes_then_hits(tmp_path: Path) -> None:
    client = FakeClient(
        batch={("PyPI", "a", "1.0"): ("CVE-1",)},
        records={"CVE-1": {"id": "CVE-1"}},
    )
    cache = OsvCache(tmp_path / "c.db")
    lookup = OsvLookup(client, cache)
    await lookup.lookup([_dep("a", "1.0")])
    assert cache.get_query(query_key("PyPI", "a", "1.0")) == ["CVE-1"]
    assert cache.get_record("CVE-1") == {"id": "CVE-1"}
