"""Edit ``.aegis.yaml`` to add an ignore rule.

Uses ``ruamel.yaml`` round-trip when available so existing comments and formatting
survive. When it is not installed, appends a fenced ignore section only if the file has
no existing ``ignore:`` block; otherwise refuses with a clear error so the user's hand-
written config is never silently clobbered.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from aegis.core.config import CONFIG_FILENAME, IgnoreRule
from aegis.core.errors import ConfigError

_BEGIN_MARKER = "# --- aegis ignore rules (managed by `aegis ignore`) ---"
_END_MARKER = "# --- end aegis ignore rules ---"


def add_ignore(config_path: Path | None, rule: IgnoreRule) -> Path:
    """Add ``rule`` to the config file, creating one if needed. Returns the path written."""
    path = config_path or Path.cwd() / CONFIG_FILENAME
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if _has_ruamel():
        _add_with_ruamel(path, rule)
    else:
        _add_with_text(path, text, rule)
    return path


def _has_ruamel() -> bool:
    try:
        import ruamel.yaml  # noqa: F401
    except ImportError:
        return False
    return True


def _add_with_ruamel(path: Path, rule: IgnoreRule) -> None:
    from ruamel.yaml import YAML

    yaml = YAML()
    yaml.preserve_quotes = True
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.load(handle) or {}
    else:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    existing = data.get("ignore")
    if not isinstance(existing, list):
        existing = []
        data["ignore"] = existing
    existing.append(_rule_to_dict(rule))
    with path.open("w", encoding="utf-8") as handle:
        yaml.dump(data, handle)


def _add_with_text(path: Path, text: str, rule: IgnoreRule) -> None:
    if "ignore:" in text:
        raise ConfigError(
            f"{path} already contains an 'ignore:' section and ruamel.yaml is not installed. "
            "Install 'aegis-audit[edit]' or add the rule by hand."
        )
    block = _render_block(rule)
    if text and not text.endswith("\n"):
        text += "\n"
    path.write_text(text + block, encoding="utf-8")


def _render_block(rule: IgnoreRule) -> str:
    lines = ["", _BEGIN_MARKER, "ignore:"]
    lines.append(f"  - id: {rule.id}")
    if rule.package is not None:
        lines.append(f"    package: {rule.package}")
    if rule.reason is not None:
        lines.append(f'    reason: "{rule.reason}"')
    if rule.until is not None:
        lines.append(f"    until: {rule.until.isoformat()}")
    lines.append(_END_MARKER)
    return "\n".join(lines) + "\n"


def _rule_to_dict(rule: IgnoreRule) -> dict[str, object]:
    data: dict[str, object] = {"id": rule.id}
    if rule.package is not None:
        data["package"] = rule.package
    if rule.reason is not None:
        data["reason"] = rule.reason
    if rule.until is not None:
        data["until"] = rule.until
    return data


def parse_until(text: str | None) -> date | None:
    """Parse ``YYYY-MM-DD`` or return ``None`` for ``None``/empty."""
    if text is None or not text.strip():
        return None
    try:
        return date.fromisoformat(text.strip())
    except ValueError as exc:
        raise ConfigError(f"--until must be YYYY-MM-DD, got {text!r}") from exc
