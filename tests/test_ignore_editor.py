from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

import aegis.ignore_editor as editor
from aegis.core.config import IgnoreRule
from aegis.core.errors import ConfigError
from aegis.ignore_editor import add_ignore, parse_until


def test_parse_until_valid() -> None:
    assert parse_until("2026-12-31") == date(2026, 12, 31)


def test_parse_until_empty() -> None:
    assert parse_until(None) is None
    assert parse_until("") is None
    assert parse_until("   ") is None


def test_parse_until_invalid() -> None:
    with pytest.raises(ConfigError, match="--until must be YYYY-MM-DD"):
        parse_until("31-12-2026")


@pytest.fixture
def no_ruamel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(editor, "_has_ruamel", lambda: False)


def test_add_ignore_creates_file_no_ruamel(tmp_path: Path, no_ruamel: None) -> None:
    config = tmp_path / ".aegis.yaml"
    rule = IgnoreRule(id="CVE-2024-1234", reason="tracked", until=date(2026, 12, 31))
    path = add_ignore(config, rule)
    assert path == config
    text = config.read_text(encoding="utf-8")
    assert "ignore:" in text
    assert "CVE-2024-1234" in text
    assert "tracked" in text
    assert "2026-12-31" in text


def test_add_ignore_appends_to_existing_file(tmp_path: Path, no_ruamel: None) -> None:
    config = tmp_path / ".aegis.yaml"
    config.write_text("fail_on: high\n", encoding="utf-8")
    add_ignore(config, IgnoreRule(id="CVE-2024-0001"))
    text = config.read_text(encoding="utf-8")
    assert "fail_on: high" in text
    assert "CVE-2024-0001" in text


def test_add_ignore_refuses_when_ignore_block_exists(tmp_path: Path, no_ruamel: None) -> None:
    config = tmp_path / ".aegis.yaml"
    config.write_text("ignore:\n  - id: CVE-1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="already contains an 'ignore:' section"):
        add_ignore(config, IgnoreRule(id="CVE-2"))


def test_add_ignore_preserves_comments_with_ruamel(tmp_path: Path) -> None:
    pytest.importorskip("ruamel.yaml")
    config = tmp_path / ".aegis.yaml"
    config.write_text("# my top comment\nfail_on: high\n", encoding="utf-8")
    add_ignore(config, IgnoreRule(id="CVE-2024-9999"))
    text = config.read_text(encoding="utf-8")
    assert "my top comment" in text
    assert "CVE-2024-9999" in text
