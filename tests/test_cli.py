from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from aegis import cli
from aegis.cli import app
from aegis.commands import ScanOptions

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _plain(text: str) -> str:
    """Strip ANSI escapes and collapse whitespace for robust option checks.

    Rich wraps long option names on narrow terminals; forcing COLUMNS=200 in each
    invoke keeps them on one line, and stripping ANSI guards against the CI's
    colour-capable terminal detection.
    """
    return " ".join(_ANSI.sub("", text).split())


def _invoke(*args: str):  # type: ignore[no-untyped-def]
    # COLUMNS=200 keeps long option names from wrapping.
    return runner.invoke(app, list(args), env={"COLUMNS": "200", "LINES": "50"})


def test_version() -> None:
    result = _invoke("--version")
    assert result.exit_code == 0
    assert result.output.startswith("aegis ")


def test_scan_help_lists_options() -> None:
    result = _invoke("scan", "--help")
    assert result.exit_code == 0
    plain = _plain(result.output)
    for needle in (
        "--output",
        "--fail-on",
        "--ecosystem",
        "--only-direct",
        "--strict",
        "--no-cache",
    ):
        assert needle in plain, f"{needle!r} missing from scan help"


def test_scan_nonexistent_path_exits_two(tmp_path: Path) -> None:
    result = _invoke("scan", str(tmp_path / "missing"))
    assert result.exit_code == 2


def test_scan_invalid_severity_exits_two(tmp_path: Path) -> None:
    result = _invoke("scan", str(tmp_path), "--fail-on", "super-bad")
    assert result.exit_code == 2


def test_scan_invalid_ecosystem_exits_two(tmp_path: Path) -> None:
    result = _invoke("scan", str(tmp_path), "--ecosystem", "rust")
    assert result.exit_code == 2


def test_scan_calls_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run(options: ScanOptions) -> int:
        captured["options"] = options
        return 0

    monkeypatch.setattr(cli.commands, "run_scan", fake_run)
    result = _invoke("scan", str(tmp_path), "--fail-on", "high")
    assert result.exit_code == 0
    options: ScanOptions = captured["options"]  # type: ignore[assignment]
    assert options.path == tmp_path
    assert options.fail_on is not None
    assert options.fail_on.value == "HIGH"


def test_scan_forwards_only_direct(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run(options: ScanOptions) -> int:
        captured["options"] = options
        return 0

    monkeypatch.setattr(cli.commands, "run_scan", fake_run)
    _invoke("scan", str(tmp_path), "--only-direct", "--strict", "--no-cache")
    options: ScanOptions = captured["options"]  # type: ignore[assignment]
    assert options.only_direct is True
    assert options.strict is True
    assert options.no_cache is True


def test_ignore_command_writes_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / ".aegis.yaml"
    monkeypatch.chdir(tmp_path)
    result = _invoke("ignore", "CVE-2024-1234", "--reason", "tracked")
    assert result.exit_code == 0
    assert cfg.exists()
    assert "CVE-2024-1234" in cfg.read_text(encoding="utf-8")


def test_list_ignores_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = _invoke("list-ignores")
    assert result.exit_code == 0
    assert "no config file" in result.output or "no ignore rules" in result.output


def test_list_ignores_with_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".aegis.yaml").write_text(
        "ignore:\n  - id: CVE-2024-1234\n    reason: test\n", encoding="utf-8"
    )
    result = _invoke("list-ignores")
    assert result.exit_code == 0
    assert "CVE-2024-1234" in result.output


def test_audit_bad_spec_exits_two() -> None:
    result = _invoke("audit", "no-separator-here")
    assert result.exit_code == 2
