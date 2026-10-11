"""Two-tier SQLite cache for OSV lookups.

Tier 1: ``(ecosystem|name|version) -> [vuln_ids]``. Tier 2: ``vuln_id -> full record``.
Both with TTL. A ``schema_version`` table records the schema; a mismatch causes a rebuild.

All cache operations are best-effort: a corrupt row is treated as a miss and deleted, and
a write failure is logged as a Notice but never aborts the run.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aegis.core.enums import NoticeCode
from aegis.core.models import Notice
from aegis.parsers._common import info, warn

SCHEMA_VERSION = 1


def query_key(ecosystem: str, name: str, version: str) -> str:
    """Stable cache key for one (ecosystem, name, version) tuple."""
    return hashlib.sha256(f"{ecosystem}\0{name}\0{version}".encode()).hexdigest()


class OsvCache:
    """SQLite-backed cache. Thread-safe via a single lock; every connection runs WAL."""

    def __init__(
        self,
        path: Path | str,
        ttl_seconds: float = 86400.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = str(path)
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._notices: list[Notice] = []
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._setup()

    @property
    def notices(self) -> list[Notice]:
        """Notices accumulated during cache operations (best-effort failures)."""
        return list(self._notices)

    def _setup(self) -> None:
        try:
            with self._lock, self._conn:
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)"
                )
                row = self._conn.execute("SELECT v FROM schema_version").fetchone()
                if row is None:
                    self._conn.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION,))
                    row = (SCHEMA_VERSION,)
                if row[0] != SCHEMA_VERSION:
                    self._conn.execute("DROP TABLE IF EXISTS query_cache")
                    self._conn.execute("DROP TABLE IF EXISTS record_cache")
                    self._conn.execute("DELETE FROM schema_version")
                    self._conn.execute(
                        "INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION,)
                    )
                    self._notices.append(
                        info(
                            NoticeCode.CACHE_SCHEMA_RESET,
                            f"cache schema upgraded from {row[0]} to {SCHEMA_VERSION}; "
                            "existing entries were dropped",
                            None,
                        )
                    )
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS query_cache ("
                    "key TEXT PRIMARY KEY, payload TEXT NOT NULL, fetched_at REAL NOT NULL)"
                )
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS record_cache ("
                    "vuln_id TEXT PRIMARY KEY, payload TEXT NOT NULL, fetched_at REAL NOT NULL)"
                )
        except sqlite3.Error as exc:
            self._notices.append(
                warn(NoticeCode.CACHE_WRITE_FAILED, f"cache setup failed: {exc}", None)
            )

    # -- query tier -----------------------------------------------------------

    def get_query(self, key: str) -> list[str] | None:
        """Return the cached list of vuln IDs, or ``None`` on miss/expired/corrupt."""
        return self._get("query_cache", "key", key, list)

    def put_query(self, key: str, vuln_ids: list[str]) -> None:
        """Store the vuln IDs for a query key."""
        self._put("query_cache", "key", key, vuln_ids)

    # -- record tier ----------------------------------------------------------

    def get_record(self, vuln_id: str) -> dict[str, Any] | None:
        """Return the cached record payload, or ``None`` on miss/expired/corrupt."""
        return self._get("record_cache", "vuln_id", vuln_id, dict)

    def put_record(self, vuln_id: str, payload: dict[str, Any]) -> None:
        """Store a record payload by ID."""
        self._put("record_cache", "vuln_id", vuln_id, payload)

    # -- shared ---------------------------------------------------------------

    def _get(self, table: str, key_column: str, key: str, expected: type) -> Any | None:
        try:
            with self._lock:
                row = self._conn.execute(
                    f"SELECT payload, fetched_at FROM {table} WHERE {key_column} = ?",  # noqa: S608
                    (key,),
                ).fetchone()
                if row is None:
                    return None
                payload, fetched_at = row
                if self._clock() - fetched_at > self._ttl:
                    self._conn.execute(
                        f"DELETE FROM {table} WHERE {key_column} = ?",  # noqa: S608
                        (key,),
                    )
                    self._conn.commit()
                    return None
                try:
                    value = json.loads(payload)
                except (ValueError, TypeError):
                    self._conn.execute(
                        f"DELETE FROM {table} WHERE {key_column} = ?",  # noqa: S608
                        (key,),
                    )
                    self._conn.commit()
                    return None
                return value if isinstance(value, expected) else None
        except sqlite3.Error as exc:
            self._notices.append(
                warn(NoticeCode.CACHE_READ_FAILED, f"cache read failed: {exc}", None)
            )
            return None

    def _put(self, table: str, key_column: str, key: str, payload: Any) -> None:
        try:
            serialised = json.dumps(payload)
            with self._lock, self._conn:
                self._conn.execute(
                    f"INSERT OR REPLACE INTO {table} ({key_column}, payload, fetched_at) "  # noqa: S608
                    "VALUES (?, ?, ?)",
                    (key, serialised, self._clock()),
                )
        except (sqlite3.Error, TypeError, ValueError) as exc:
            self._notices.append(
                warn(NoticeCode.CACHE_WRITE_FAILED, f"cache write failed: {exc}", None)
            )

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> OsvCache:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
