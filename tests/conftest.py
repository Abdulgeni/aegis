from __future__ import annotations

from collections.abc import Callable
from pathlib import Path, PurePosixPath

import pytest

from aegis.core.discovery import classify_file
from aegis.core.models import ManifestFile


@pytest.fixture
def write(tmp_path: Path) -> Callable[..., Path]:
    """Create a file (and parent dirs) under tmp_path and return its path."""

    def _write(rel: str, text: str = "") -> Path:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    return _write


@pytest.fixture
def make_manifest() -> Callable[[str], ManifestFile]:
    """Build a ManifestFile for parser tests; ecosystem and kind come from the file name."""

    def _make(rel: str) -> ManifestFile:
        rule = classify_file(PurePosixPath(rel))
        assert rule is not None, rel
        return ManifestFile(
            path=Path("/virtual") / rel, rel_path=rel, ecosystem=rule[0], kind=rule[1]
        )

    return _make
