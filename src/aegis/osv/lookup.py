"""Orchestrator: dependencies -> vuln records, with caching and partial-failure notices."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from aegis.core.enums import NoticeCode
from aegis.core.models import Dependency, Notice
from aegis.osv.cache import OsvCache, query_key
from aegis.osv.client import BatchHit, OsvClient, OsvError, Query
from aegis.osv.models import VulnRecord, parse_vuln
from aegis.parsers._common import info, warn

LookupKey = tuple[str, str, str]


class _Client(Protocol):
    async def query_batch(self, queries: Sequence[Query]) -> list[BatchHit]: ...
    async def fetch_vuln(self, vuln_id: str) -> dict[str, object]: ...


class OsvLookup:
    """Looks up OSV records for a set of dependencies, using the cache where possible.

    Cache misses trigger a single batch call for all uncached ``(ecosystem, name, version)``
    pairs. Full records are fetched once per unique vuln ID. Any failure becomes a warning
    and the affected dependencies are excluded from the return value.
    """

    def __init__(self, client: _Client, cache: OsvCache | None = None) -> None:
        self._client = client
        self._cache = cache

    async def lookup(
        self, dependencies: list[Dependency]
    ) -> tuple[dict[LookupKey, list[VulnRecord]], list[Notice]]:
        """Return ``(records_by_key, notices)``. ``records_by_key`` may be partial."""
        notices: list[Notice] = []
        indexed: list[tuple[LookupKey, str]] = []  # (key, dependency-source) in first-seen order
        seen: dict[LookupKey, None] = {}
        for dep in dependencies:
            if dep.version is None:
                continue
            key = (dep.ecosystem.value, dep.name, dep.version)
            if key in seen:
                continue
            seen[key] = None
            indexed.append((key, dep.source))

        ids_by_key: dict[LookupKey, list[str]] = {}
        missing: list[LookupKey] = []
        if self._cache is not None:
            for key, _ in indexed:
                cached = self._cache.get_query(query_key(*key))
                if cached is None:
                    missing.append(key)
                else:
                    ids_by_key[key] = cached
        else:
            missing = [key for key, _ in indexed]

        if missing:
            fetched_ids, fetch_notices = await self._batch_fetch(missing)
            notices.extend(fetch_notices)
            ids_by_key.update(fetched_ids)

        records_by_id, record_notices = await self._fetch_records(
            sorted({vuln_id for ids in ids_by_key.values() for vuln_id in ids})
        )
        notices.extend(record_notices)

        result: dict[LookupKey, list[VulnRecord]] = {}
        for key, ids in ids_by_key.items():
            kept = [records_by_id[i] for i in ids if i in records_by_id]
            result[key] = kept

        if notices:
            notices.insert(
                0,
                info(
                    NoticeCode.OSV_PARTIAL_RESULTS,
                    "some dependencies could not be fully checked; see the notices above",
                    None,
                ),
            )
        return result, notices

    async def _batch_fetch(
        self, keys: list[LookupKey]
    ) -> tuple[dict[LookupKey, list[str]], list[Notice]]:
        notices: list[Notice] = []
        queries = [Query(ecosystem=k[0], name=k[1], version=k[2]) for k in keys]
        try:
            hits = await self._client.query_batch(queries)
        except OsvError as exc:
            notices.append(
                warn(
                    NoticeCode.OSV_REQUEST_FAILED,
                    f"batch query failed ({exc}); {len(keys)} dependencies not checked",
                    None,
                )
            )
            return {}, notices
        by_query = {_query_tuple(hit.query): hit for hit in hits}
        out: dict[LookupKey, list[str]] = {}
        for key in keys:
            hit = by_query.get(key)
            ids = list(hit.vuln_ids) if hit is not None else []
            out[key] = ids
            if self._cache is not None:
                self._cache.put_query(query_key(*key), ids)
        return out, notices

    async def _fetch_records(
        self, vuln_ids: list[str]
    ) -> tuple[dict[str, VulnRecord], list[Notice]]:
        notices: list[Notice] = []
        records: dict[str, VulnRecord] = {}
        unresolved: list[str] = []
        if self._cache is not None:
            for vuln_id in vuln_ids:
                cached = self._cache.get_record(vuln_id)
                if cached is None:
                    unresolved.append(vuln_id)
                else:
                    parsed = parse_vuln(cached)
                    if parsed is None:
                        unresolved.append(vuln_id)
                    else:
                        records[vuln_id] = parsed
        else:
            unresolved = list(vuln_ids)

        for vuln_id in unresolved:
            try:
                payload = await self._client.fetch_vuln(vuln_id)
            except OsvError as exc:
                notices.append(
                    warn(
                        NoticeCode.OSV_REQUEST_FAILED,
                        f"fetch of {vuln_id} failed ({exc})",
                        None,
                    )
                )
                continue
            parsed = parse_vuln(payload)
            if parsed is None:
                notices.append(
                    warn(
                        NoticeCode.OSV_REQUEST_FAILED,
                        f"OSV record {vuln_id} is not usable (missing id)",
                        None,
                    )
                )
                continue
            records[vuln_id] = parsed
            if self._cache is not None:
                self._cache.put_record(vuln_id, dict(payload))
        return records, notices


def _query_tuple(query: Query) -> LookupKey:
    return (query.ecosystem, query.name, query.version)


__all__ = ["OsvClient", "OsvLookup"]
