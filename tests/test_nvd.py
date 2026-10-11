from __future__ import annotations

import pytest

from aegis.enrichment.nvd import NvdClient, NvdError


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: object = None, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self) -> object:
        return self._payload


class FakeSession:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    async def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    async def aclose(self) -> None:
        return None


def _cve_with_score(score: float, metric_key: str = "cvssMetricV31") -> dict[str, object]:
    return {
        "vulnerabilities": [
            {"cve": {"id": "CVE-1", "metrics": {metric_key: [{"cvssData": {"baseScore": score}}]}}}
        ]
    }


async def test_cvss_score_v31() -> None:
    session = FakeSession([FakeResponse(200, _cve_with_score(9.8))])
    client = NvdClient(session=session)
    assert await client.cvss_score("CVE-1") == 9.8
    assert session.calls[0]["params"] == {"cveId": "CVE-1"}
    assert session.calls[0]["headers"] == {}


async def test_api_key_is_sent_as_header() -> None:
    session = FakeSession([FakeResponse(200, _cve_with_score(7.5))])
    client = NvdClient(api_key="secret", session=session)
    await client.cvss_score("CVE-1")
    assert session.calls[0]["headers"] == {"apiKey": "secret"}


async def test_v30_fallback_metric() -> None:
    session = FakeSession([FakeResponse(200, _cve_with_score(5.0, "cvssMetricV30"))])
    client = NvdClient(session=session)
    assert await client.cvss_score("CVE-1") == 5.0


async def test_no_vulnerabilities_returns_none() -> None:
    session = FakeSession([FakeResponse(200, {"vulnerabilities": []})])
    client = NvdClient(session=session)
    assert await client.cvss_score("CVE-1") is None


async def test_non_retryable_status_raises() -> None:
    session = FakeSession([FakeResponse(404)])
    client = NvdClient(session=session, max_retries=0)
    with pytest.raises(NvdError, match="HTTP 404"):
        await client.cvss_score("CVE-1")
