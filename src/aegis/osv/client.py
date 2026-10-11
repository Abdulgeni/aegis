"""Async OSV HTTP client.

Uses ``httpx.AsyncClient`` but the session is injectable, so tests use a fake. The client
exposes two operations:

* ``query_batch(queries)`` - POST /v1/querybatch, chunked at ``BATCH_CHUNK`` queries per
  request. Returns a flat list of results in the input order.
* ``fetch_vuln(vuln_id)`` - GET /v1/vulns/{id}, returns the raw JSON dict.

Both operations retry on 429/5xx and on transient network errors, honour ``Retry-After``,
respect a shared concurrency semaphore, and raise ``OsvError`` on final failure.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

DEFAULT_BASE_URL = "https://api.osv.dev"
BATCH_CHUNK = 1000
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class OsvError(Exception):
    """A failed OSV request. ``status_code`` is set when the server responded."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HttpSession(Protocol):
    """The slice of ``httpx.AsyncClient`` the client uses; faked in tests."""

    async def post(self, url: str, **kwargs: Any) -> httpx.Response: ...
    async def get(self, url: str, **kwargs: Any) -> httpx.Response: ...
    async def aclose(self) -> None: ...


@dataclass(frozen=True)
class Query:
    """One query to the OSV batch endpoint."""

    ecosystem: str
    name: str
    version: str

    def to_json(self) -> dict[str, Any]:
        """The OSV ``query`` object shape."""
        return {"package": {"ecosystem": self.ecosystem, "name": self.name}, "version": self.version}


@dataclass(frozen=True)
class BatchHit:
    """One result row from a batch call, in input order."""

    query: Query
    vuln_ids: tuple[str, ...]


class OsvClient:
    """Async OSV client with retry, backoff, and bounded concurrency.

    Args:
        session: An httpx-compatible async session. If ``None``, one is created.
        base_url: Override for tests or self-hosted OSV mirrors.
        max_concurrency: Max concurrent in-flight HTTP requests.
        timeout_s: Per-request timeout.
        max_retries: Retries after the first attempt on retryable failures.
        backoff_base: First backoff delay in seconds; doubles each retry.
        backoff_max: Cap on backoff delay.
        sleep: Injected sleep callable for tests; defaults to ``asyncio.sleep`` at
            construction time so monkeypatching ``asyncio.sleep`` works as expected.
        rand: Injected RNG for deterministic backoff in tests.
    """

    def __init__(
        self,
        *,
        session: HttpSession | None = None,
        base_url: str = DEFAULT_BASE_URL,
        max_concurrency: int = 4,
        timeout_s: float = 30.0,
        max_retries: int = 5,
        backoff_base: float = 1.0,
        backoff_max: float = 30.0,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        rand: Callable[[], float] | None = None,
    ) -> None:
        self._session = session or httpx.AsyncClient(timeout=timeout_s)
        self._base_url = base_url.rstrip("/")
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._sleep = sleep if sleep is not None else asyncio.sleep
        self._rand = rand if rand is not None else random.random

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        await self._session.aclose()

    async def query_batch(self, queries: Sequence[Query]) -> list[BatchHit]:
        """Query a batch of packages, chunked if the input exceeds ``BATCH_CHUNK``.

        Chunks are processed concurrently (bounded by the semaphore); results are
        re-ordered into the input order.
        """
        indexed: list[tuple[int, Query]] = list(enumerate(queries))
        chunks = [
            indexed[i : i + BATCH_CHUNK] for i in range(0, len(indexed), BATCH_CHUNK)
        ]
        chunk_results = await asyncio.gather(
            *(self._query_chunk(chunk) for chunk in chunks)
        )
        flat: list[BatchHit] = [hit for chunk in chunk_results for hit in chunk]
        flat.sort(key=lambda hit: _order_of(hit.query, indexed))
        return flat

    async def _query_chunk(self, chunk: list[tuple[int, Query]]) -> list[BatchHit]:
        if not chunk:
            return []
        body = {"queries": [query.to_json() for _, query in chunk]}
        url = f"{self._base_url}/v1/querybatch"
        payload = await self._request("POST", url, json=body)
        results = payload.get("results")
        if not isinstance(results, list):
            raise OsvError("OSV batch response did not contain a 'results' list")
        hits: list[BatchHit] = []
        for entry, (_, query) in zip(results, chunk, strict=False):
            ids: list[str] = []
            if isinstance(entry, dict):
                vulns = entry.get("vulns")
                if isinstance(vulns, list):
                    ids = [
                        v["id"]
                        for v in vulns
                        if isinstance(v, dict) and isinstance(v.get("id"), str)
                    ]
            hits.append(BatchHit(query=query, vuln_ids=tuple(ids)))
        return hits

    async def fetch_vuln(self, vuln_id: str) -> dict[str, Any]:
        """Fetch one full OSV record by ID."""
        url = f"{self._base_url}/v1/vulns/{vuln_id}"
        return await self._request("GET", url)

    async def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        last_error = "no attempt made"
        for attempt in range(self._max_retries + 1):
            async with self._semaphore:
                try:
                    if method == "POST":
                        response = await self._session.post(url, **kwargs)
                    else:
                        response = await self._session.get(url, **kwargs)
                except (httpx.RequestError, httpx.TimeoutException) as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    delay = self._backoff(attempt, None)
                else:
                    if response.status_code == 200:
                        try:
                            return _as_dict(response.json())
                        except (ValueError, TypeError) as exc:
                            raise OsvError(f"invalid JSON from OSV: {exc}") from exc
                    if response.status_code in _RETRYABLE_STATUS:
                        last_error = f"HTTP {response.status_code}"
                        delay = self._backoff(attempt, response.headers.get("Retry-After"))
                    else:
                        raise OsvError(
                            f"OSV request to {url} failed with HTTP {response.status_code}",
                            status_code=response.status_code,
                        )
            if attempt == self._max_retries:
                break
            await self._sleep(delay)
        raise OsvError(
            f"OSV request to {url} failed after {self._max_retries + 1} attempts ({last_error})"
        )

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        ceiling = min(self._backoff_max, self._backoff_base * float(2**attempt))
        delay = ceiling * (0.5 + 0.5 * self._rand())
        if retry_after:
            with contextlib.suppress(ValueError):
                delay = max(delay, min(float(retry_after), self._backoff_max))
        return delay


def _as_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OsvError("OSV returned a JSON value that is not an object")
    return value


def _order_of(query: Query, indexed: list[tuple[int, Query]]) -> int:
    for index, candidate in indexed:
        if candidate == query:
            return index
    return len(indexed)