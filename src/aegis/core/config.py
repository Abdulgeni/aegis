"""`.aegis.yaml` configuration: strict schema, safe loading, and env-derived settings.

Precedence is CLI flags > config file > environment > defaults. The environment
participates only for two settings: AEGIS_CACHE_DIR (a path) and NVD_API_KEY (a secret,
never read from the file). Environment variables never set any other config key.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError, field_validator

from aegis.core.enums import Ecosystem, Severity
from aegis.core.errors import ConfigError

CONFIG_FILENAME = ".aegis.yaml"
MAX_CONFIG_BYTES = 1_000_000


def _parse_severity(value: object) -> object:
    if isinstance(value, str):
        parsed = Severity.from_label(value)
        if parsed is None or parsed is Severity.UNKNOWN:
            raise ValueError(f"{value!r} is not a severity; use critical, high, medium or low")
        return parsed
    return value


def _parse_ecosystem(value: object) -> object:
    if isinstance(value, str):
        parsed = Ecosystem.parse(value)
        if parsed is None:
            raise ValueError(f"{value!r} is not an ecosystem; use PyPI, npm or Go")
        return parsed
    return value


ConfiguredSeverity = Annotated[Severity, BeforeValidator(_parse_severity)]
ConfiguredEcosystem = Annotated[Ecosystem, BeforeValidator(_parse_ecosystem)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IgnoreRule(_Strict):
    """Suppress a vulnerability (matched against any alias), optionally per package."""

    id: str = Field(min_length=1)
    package: str | None = None
    reason: str | None = None
    until: date | None = None


class EcosystemConfig(_Strict):
    """Which ecosystems are scanned. Defaults to all."""

    include: list[ConfiguredEcosystem] = Field(default_factory=lambda: list(Ecosystem))
    exclude: list[ConfiguredEcosystem] = Field(default_factory=list)


class CacheConfig(_Strict):
    """Cache location (null means AEGIS_CACHE_DIR or the platform default) and TTL."""

    directory: Path | None = None
    ttl_hours: int = Field(default=24, ge=1)


class NetworkConfig(_Strict):
    """Network politeness and optional NVD enrichment."""

    timeout_s: float = Field(default=30.0, gt=0)
    max_concurrency: int = Field(default=4, ge=1)
    nvd_enrichment: bool = False


class DiscoveryConfig(_Strict):
    """Discovery limits. `include_dirs` re-enables normally skipped directory names."""

    max_file_size_mb: float = Field(default=10.0, gt=0)
    include_dirs: list[str] = Field(default_factory=list)

    @field_validator("include_dirs")
    @classmethod
    def _bare_names(cls, value: list[str]) -> list[str]:
        for name in value:
            if not name or "/" in name or "\\" in name:
                raise ValueError(f"{name!r} must be a bare directory name")
        return value

    @property
    def max_file_bytes(self) -> int:
        """The size cap in bytes."""
        return int(self.max_file_size_mb * 1024 * 1024)


class AegisConfig(_Strict):
    """The full `.aegis.yaml` schema."""

    severity_threshold: ConfiguredSeverity = Severity.LOW
    fail_on: ConfiguredSeverity = Severity.HIGH
    ignore: list[IgnoreRule] = Field(default_factory=list)
    ecosystem: EcosystemConfig = Field(default_factory=EcosystemConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)

    def enabled_ecosystems(self) -> frozenset[Ecosystem]:
        """Ecosystems in `include` minus those in `exclude`."""
        return frozenset(self.ecosystem.include) - frozenset(self.ecosystem.exclude)


def find_config(start: Path) -> Path | None:
    """Search upward from `start` for `.aegis.yaml`.

    In each directory the config file is checked first, then a `.git` entry (file or
    directory) stops the walk. A `.git` anywhere above the scan path therefore ends the
    search, even if it belongs to a parent repository.
    """
    here = start.resolve()
    if here.is_file():
        here = here.parent
    for directory in (here, *here.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if (directory / ".git").exists():
            return None
    return None


def load_config(path: Path) -> AegisConfig:
    """Read and validate a config file. Raises ConfigError on any problem."""
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path}: config file is larger than {MAX_CONFIG_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: cannot read config file: {exc}") from exc
    return parse_config(text, source=str(path))


def parse_config(text: str, *, source: str = "<string>") -> AegisConfig:
    """Parse config text with `yaml.safe_load` and validate it. Empty text gives defaults."""
    try:
        _reject_aliases(text, source)
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: invalid YAML: {exc}") from exc
    if raw is None:
        return AegisConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"{source}: top level must be a mapping")
    try:
        return AegisConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{source}: {_format_errors(exc)}") from exc


def _reject_aliases(text: str, source: str) -> None:
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            raise ConfigError(f"{source}: YAML anchors and aliases are not supported")


def _format_errors(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)


def resolve_cache_dir(
    config: AegisConfig,
    env: Mapping[str, str],
    *,
    os_name: str = os.name,
    home: Path | None = None,
) -> Path:
    """Cache directory: config file, else AEGIS_CACHE_DIR, else the platform default."""
    if config.cache.directory is not None:
        return config.cache.directory.expanduser()
    override = env.get("AEGIS_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    if os_name == "nt":
        local_app_data = env.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "aegis"
    return (home or Path.home()) / ".cache" / "aegis"


def resolve_nvd_api_key(env: Mapping[str, str]) -> str | None:
    """The NVD API key from NVD_API_KEY, or None if unset or blank. Env-only by design."""
    key = env.get("NVD_API_KEY", "").strip()
    return key or None
