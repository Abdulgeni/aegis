"""Production wiring for the auditor: real discoverer, resolver, and OSV lookup."""

from __future__ import annotations

from pathlib import Path

from aegis.auditor import Auditor
from aegis.core.config import AegisConfig, resolve_cache_dir
from aegis.core.discovery import FileDiscoverer
from aegis.osv.cache import OsvCache
from aegis.osv.client import OsvClient
from aegis.osv.lookup import OsvLookup
from aegis.resolution import DependencyResolver


def build_auditor_for_config(
    config: AegisConfig,
    *,
    no_cache: bool,
    only_direct: bool,
    cache_dir: Path | None = None,
) -> Auditor:
    """Wire a real Auditor from a config. Cache dir defaults to the platform location."""
    discoverer = FileDiscoverer.from_config(config)
    resolver = DependencyResolver()
    cache: OsvCache | None = None
    if not no_cache:
        try:
            path = (cache_dir or resolve_cache_dir(config, {})) / "osv.db"
            cache = OsvCache(path)
        except Exception:
            cache = None
    client = OsvClient()
    lookup = OsvLookup(client, cache)
    return Auditor(
        discoverer=discoverer,
        resolver=resolver,
        lookup=lookup,
        only_direct=only_direct,
    )


__all__ = ["build_auditor_for_config"]
