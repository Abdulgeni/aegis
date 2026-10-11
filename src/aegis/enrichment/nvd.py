"""Optional NVD enrichment: fill in a CVSS score for CVEs that OSV did not score.

Off by default. Called only when the config enables it and an API key is present. Same
shape as the OSV client: injectable session, async, retry/backoff on 429/5xx.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

import httpx

DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class NvdError(Exception):
    """A failed NVD request. ``status_code`` is set when the server responded."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HttpSession(Protocol):
    async def get(self, url: str, **kwargs: Any) -> httpx.Response: ...
    async def aclose(self) -> None: ...


class NvdClient:
    """Minimal NVD client: one CVE lookup by ID, returning the CVSS base score if any."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        session: HttpSession | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = 30.0,
        max_retries: int = 3,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        rand: Callable[[], float] | None = None,
    ) -> None:
        self._api_key = api_key
        self._session = session or httpx.AsyncClient(timeout=timeout_s)
        self._base_url = base_url
        self._max_retries = max_retries
        self._sleep = sleep if sleep is not None else asyncio.sleep
        self._rand = rand if rand is not None else random.random

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        await self._session.aclose()

    async def cvss_score(self, cve_id: str) -> float | None:
        """Return the CVSS base score for a CVE, or ``None`` if unavailable."""
        headers = {"apiKey": self._api_key} if self._api_key else {}
        params = {"cveId": cve_id}
        payload = await self._request(headers=headers, params=params)
        vulns = payload.get("vulnerabilities")
        if not isinstance(vulns, list) or not vulns:
            return None
        first = vulns[0]
        if not isinstance(first, dict):
            return None
        cve = first.get("cve")
        if not isinstance(cve, dict):
            return None
        return _pick_score(cve.get("metrics"))

    async def _request(self, **kwargs: Any) -> dict[str, Any]:
        last_error = "no attempt made"
        for attempt in range(self._max_retries + 1):
            try:
                response = await self._session.get(self._base_url, **kwargs)
            except (httpx.RequestError, httpx.TimeoutException) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                delay = self._backoff(attempt, None)
            else:
                if response.status_code == 200:
                    try:
                        data = response.json()
                    except (ValueError, TypeError) as exc:
                        raise NvdError(f"invalid JSON from NVD: {exc}") from exc
                    if not isinstance(data, dict):
                        raise NvdError("NVD response is not a JSON object")
                    return data
                if response.status_code in _RETRYABLE_STATUS:
                    last_error = f"HTTP {response.status_code}"
                    delay = self._backoff(attempt, response.headers.get("Retry-After"))
                else:
                    raise NvdError(
                        f"NVD request failed with HTTP {response.status_code}",
                        status_code=response.status_code,
                    )
            if attempt == self._max_retries:
                break
            await self._sleep(delay)
        raise NvdError(
            f"NVD request failed after {self._max_retries + 1} attempts ({last_error})"
        )

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        delay = min(30.0, 1.0 * float(2**attempt)) * (0.5 + 0.5 * self._rand())
        if retry_after:
            with contextlib.suppress(ValueError):
                delay = max(delay, min(float(retry_after), 30.0))
        return delay


_METRIC_KEYS = (
    ("cvssMetricV31",),
    ("cvssMetricV30",),
    ("cvssMetricV2",),
)


def _pick_score(metrics: Any) -> float | None:
    if not isinstance(metrics, dict):
        return None
    for (key,) in _METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        first = entries[0]
        if not isinstance(first, dict):
            continue
        data = first.get("cvssData")
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        if isinstance(score, (int, float)):
            return float(score)
    return None