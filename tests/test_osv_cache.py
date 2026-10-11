from __future__ import annotations

from pathlib import Path

from aegis.core.enums import NoticeCode
from aegis.osv.cache import SCHEMA_VERSION, OsvCache, query_key


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_query_cache_roundtrip(tmp_path: Path) -> None:
    clock = _Clock()
    with OsvCache(tmp_path / "c.db", ttl_seconds=100, clock=clock) as cache:
        key = query_key("PyPI", "requests", "2.31.0")
        assert cache.get_query(key) is None
        cache.put_query(key, ["CVE-1", "CVE-2"])
        assert cache.get_query(key) == ["CVE-1", "CVE-2"]


def test_query_cache_expires(tmp_path: Path) -> None:
    clock = _Clock()
    with OsvCache(tmp_path / "c.db", ttl_seconds=10, clock=clock) as cache:
        key = query_key("PyPI", "x", "1.0")
        cache.put_query(key, ["CVE-1"])
        clock.now += 9
        assert cache.get_query(key) == ["CVE-1"]
        clock.now += 2
        assert cache.get_query(key) is None


def test_record_cache_roundtrip(tmp_path: Path) -> None:
    with OsvCache(tmp_path / "c.db") as cache:
        payload = {"id": "CVE-2024-1234", "summary": "x", "nested": {"a": 1}}
        cache.put_record("CVE-2024-1234", payload)
        assert cache.get_record("CVE-2024-1234") == payload


def test_missing_keys_return_none(tmp_path: Path) -> None:
    with OsvCache(tmp_path / "c.db") as cache:
        assert cache.get_query("nope") is None
        assert cache.get_record("nope") is None


def test_corrupt_payload_is_a_miss(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "c.db"
    with OsvCache(path) as cache:
        key = query_key("PyPI", "x", "1.0")
        cache.put_query(key, ["CVE-1"])
    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE query_cache SET payload = 'not json'")
    conn.commit()
    conn.close()
    with OsvCache(path) as cache2:
        assert cache2.get_query(key) is None


def test_schema_version_mismatch_drops_and_notices(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "c.db"
    with OsvCache(path) as cache:
        cache.put_query(query_key("PyPI", "x", "1.0"), ["CVE-1"])
    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE schema_version SET v = ?", (SCHEMA_VERSION + 1,))
    conn.commit()
    conn.close()
    with OsvCache(path) as cache2:
        assert any(n.code is NoticeCode.CACHE_SCHEMA_RESET for n in cache2.notices)
        # Old keys were dropped
        assert cache2.get_query(query_key("PyPI", "x", "1.0")) is None


def test_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "c.db"
    with OsvCache(path) as first:
        first.put_query("k", ["v"])
    with OsvCache(path) as second:
        assert second.get_query("k") == ["v"]
