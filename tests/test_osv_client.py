from __future__ import annotations

import httpx
import pytest

from aegis.osv.client import BatchHit, OsvClient, OsvError, Query


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: object = None, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self) -> object:
        if self._payload is _INVALID:
            raise ValueError("bad json")
        return self._payload


_INVALID = object()


class FakeSession:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    async def post(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append({"method": "POST", "url": url, **kwargs})
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    async def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append({"method": "GET", "url": url, **kwargs})
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    async def aclose(self) -> None:
        return None


@pytest.fixture
def fast_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    delays: list[float] = []

    async def _sleep(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr("aegis.osv.client.asyncio.sleep", _sleep)
    return delays


async def test_query_batch_parses_ids_in_order(fast_sleep: list[float]) -> None:
    payload = {
        "results": [
            {"vulns": [{"id": "CVE-1"}, {"id": "CVE-2"}]},
            {"vulns": [{"id": "CVE-3"}]},
            {},
        ]
    }
    session = FakeSession([FakeResponse(200, payload)])
    client = OsvClient(session=session, base_url="https://test")
    hits = await client.query_batch(
        [
            Query(ecosystem="PyPI", name="a", version="1.0"),
            Query(ecosystem="PyPI", name="b", version="2.0"),
            Query(ecosystem="PyPI", name="c", version="3.0"),
        ]
    )
    assert [h.vuln_ids for h in hits] == [("CVE-1", "CVE-2"), ("CVE-3",), ()]
    assert all(isinstance(h, BatchHit) for h in hits)
    body = session.calls[0]["json"]
    assert isinstance(body, dict)
    assert [q["package"]["name"] for q in body["queries"]] == ["a", "b", "c"]


async def test_fetch_vuln_returns_dict(fast_sleep: list[float]) -> None:
    session = FakeSession([FakeResponse(200, {"id": "CVE-1", "summary": "x"})])
    client = OsvClient(session=session, base_url="https://test")
    data = await client.fetch_vuln("CVE-1")
    assert data["id"] == "CVE-1"
    assert session.calls[0]["url"] == "https://test/v1/vulns/CVE-1"


async def test_retryable_status_retries_with_backoff(fast_sleep: list[float]) -> None:
    session = FakeSession(
        [FakeResponse(429, headers={"Retry-After": "2"}), FakeResponse(200, {"ok": True})]
    )
    client = OsvClient(session=session, base_url="https://test", rand=lambda: 0.5)
    data = await client.fetch_vuln("X")
    assert data == {"ok": True}
    assert len(session.calls) == 2
    assert fast_sleep == [2.0]


async def test_non_retryable_status_raises_osv_error(fast_sleep: list[float]) -> None:
    session = FakeSession([FakeResponse(404, payload=None)])
    client = OsvClient(session=session, base_url="https://test")
    with pytest.raises(OsvError) as info:
        await client.fetch_vuln("missing")
    assert info.value.status_code == 404


async def test_network_error_retried_then_gives_up(fast_sleep: list[float]) -> None:
    session = FakeSession([httpx.ConnectError("down"), httpx.ConnectError("down")])
    client = OsvClient(session=session, base_url="https://test", max_retries=1)
    with pytest.raises(OsvError, match="failed after 2 attempts"):
        await client.fetch_vuln("X")


async def test_invalid_json_raises(fast_sleep: list[float]) -> None:
    session = FakeSession([FakeResponse(200, payload=_INVALID)])
    client = OsvClient(session=session, base_url="https://test")
    with pytest.raises(OsvError, match="invalid JSON"):
        await client.fetch_vuln("X")


async def test_non_object_json_raises(fast_sleep: list[float]) -> None:
    session = FakeSession([FakeResponse(200, payload=[1, 2])])
    client = OsvClient(session=session, base_url="https://test")
    with pytest.raises(OsvError, match="not an object"):
        await client.fetch_vuln("X")


async def test_batch_missing_results_is_an_error(fast_sleep: list[float]) -> None:
    session = FakeSession([FakeResponse(200, {"other": 1})])
    client = OsvClient(session=session, base_url="https://test")
    with pytest.raises(OsvError, match="results"):
        await client.query_batch([Query(ecosystem="PyPI", name="a", version="1")])
