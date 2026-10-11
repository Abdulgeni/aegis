from __future__ import annotations

from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest

import aegis.core.config as config_module
from aegis.core.config import (
    AegisConfig,
    find_config,
    load_config,
    parse_config,
    resolve_cache_dir,
    resolve_nvd_api_key,
)
from aegis.core.enums import Ecosystem, Severity
from aegis.core.errors import ConfigError

SPEC_YAML = """
severity_threshold: low
fail_on: high
ignore:
  - id: CVE-2024-1234
    package: requests
    reason: "Mitigated by network ACL, tracked in SEC-42"
    until: 2026-12-31
  - id: GHSA-xxxx-yyyy-zzzz
    reason: "Not exploitable in our usage"
ecosystem:
  include: [PyPI, npm]
  exclude: [Go]
cache:
  directory: null
  ttl_hours: 24
network:
  timeout_s: 30
  max_concurrency: 4
  nvd_enrichment: false
"""


def test_spec_example_parses() -> None:
    config = parse_config(SPEC_YAML)
    assert config.fail_on is Severity.HIGH
    assert config.ignore[0].until == date(2026, 12, 31)
    assert config.ignore[0].package == "requests"
    assert config.ignore[1].package is None
    assert config.enabled_ecosystems() == {Ecosystem.PYPI, Ecosystem.NPM}
    assert config.cache.directory is None


def test_empty_file_gives_defaults() -> None:
    assert parse_config("") == AegisConfig()
    assert AegisConfig().enabled_ecosystems() == set(Ecosystem)


def test_ecosystem_names_are_case_insensitive() -> None:
    config = parse_config("ecosystem:\n  include: [pypi, NPM]\n")
    assert config.enabled_ecosystems() == {Ecosystem.PYPI, Ecosystem.NPM}


def test_severity_accepts_moderate_alias() -> None:
    assert parse_config("fail_on: moderate\n").fail_on is Severity.MEDIUM


@pytest.mark.parametrize(
    "text",
    [
        "bogus: 1\n",
        "fail_on: urgent\n",
        "fail_on: unknown\n",
        "ecosystem:\n  include: [Rust]\n",
        "cache:\n  ttl_hours: 0\n",
        "network:\n  max_concurrency: 0\n",
        "ignore:\n  - package: x\n",
        "ignore:\n  - id: X\n    extra: 1\n",
        "discovery:\n  include_dirs: [a/b]\n",
    ],
)
def test_invalid_config_is_rejected(text: str) -> None:
    with pytest.raises(ConfigError):
        parse_config(text)


def test_unknown_key_error_names_the_key() -> None:
    with pytest.raises(ConfigError, match="bogus"):
        parse_config("bogus: 1\n")


def test_structural_problems_are_config_errors() -> None:
    with pytest.raises(ConfigError, match="mapping"):
        parse_config("- a\n- b\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        parse_config("a: [\n")


def test_yaml_aliases_are_rejected() -> None:
    with pytest.raises(ConfigError, match="aliases"):
        parse_config("a: &x [1]\nb: *x\n")


def test_load_config_enforces_size_cap(
    write: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(".aegis.yaml", "fail_on: low\n")
    monkeypatch.setattr(config_module, "MAX_CONFIG_BYTES", 5)
    with pytest.raises(ConfigError, match="larger"):
        load_config(path)


def test_load_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.yaml")


def test_load_config_reads_file(write: Callable[..., Path]) -> None:
    assert load_config(write(".aegis.yaml", "fail_on: low\n")).fail_on is Severity.LOW


def test_find_config_in_start_directory(tmp_path: Path, write: Callable[..., Path]) -> None:
    cfg = write(".aegis.yaml")
    assert find_config(tmp_path) == cfg.resolve()


def test_find_config_walks_upward_from_a_file(tmp_path: Path, write: Callable[..., Path]) -> None:
    cfg = write(".aegis.yaml")
    lock = write("proj/sub/package-lock.json")
    assert find_config(lock) == cfg.resolve()


def test_find_config_stops_at_git_directory(tmp_path: Path, write: Callable[..., Path]) -> None:
    write(".aegis.yaml")
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    write("repo/src/x.txt")
    assert find_config(tmp_path / "repo" / "src") is None


def test_find_config_stops_at_git_file(tmp_path: Path, write: Callable[..., Path]) -> None:
    write(".aegis.yaml")
    write("sub/.git", "gitdir: ../.git/modules/sub")
    write("sub/src/x.txt")
    assert find_config(tmp_path / "sub" / "src") is None


def test_find_config_prefers_config_next_to_git(tmp_path: Path, write: Callable[..., Path]) -> None:
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    cfg = write("repo/.aegis.yaml")
    assert find_config(tmp_path / "repo" / "pkg") == cfg.resolve()


def test_cache_dir_config_beats_env() -> None:
    config = parse_config("cache:\n  directory: /c/cfg\n")
    assert resolve_cache_dir(config, {"AEGIS_CACHE_DIR": "/c/env"}) == Path("/c/cfg")


def test_cache_dir_env_beats_default() -> None:
    assert resolve_cache_dir(AegisConfig(), {"AEGIS_CACHE_DIR": "/c/env"}) == Path("/c/env")


def test_cache_dir_default_and_blank_env() -> None:
    home = Path("/home/u")
    assert resolve_cache_dir(AegisConfig(), {}, home=home) == home / ".cache" / "aegis"
    assert resolve_cache_dir(AegisConfig(), {"AEGIS_CACHE_DIR": ""}, home=home) == (
        home / ".cache" / "aegis"
    )


def test_cache_dir_windows_uses_local_app_data() -> None:
    env = {"LOCALAPPDATA": "C:/Users/u/AppData/Local"}
    assert resolve_cache_dir(AegisConfig(), env, os_name="nt") == Path(env["LOCALAPPDATA"]) / "aegis"


def test_nvd_key_is_env_only_and_blank_safe() -> None:
    assert resolve_nvd_api_key({"NVD_API_KEY": "  k  "}) == "k"
    assert resolve_nvd_api_key({"NVD_API_KEY": "  "}) is None
    assert resolve_nvd_api_key({}) is None
    with pytest.raises(ConfigError):
        parse_config("nvd_api_key: secret\n")
