"""Parser for pip requirements files (requirements.txt and friends)."""

from __future__ import annotations

import re
from collections.abc import Iterator

from aegis.core.enums import Ecosystem
from aegis.core.models import Dependency, ManifestFile, ParseResult
from aegis.parsers._common import parse_requirement_string, partial_parse

_COMMENT = re.compile(r"(^|\s)#.*$")
_HASH_OPTION = re.compile(r"\s--hash=\S+")


class RequirementsTxtParser:
    """Extracts requirement lines; `==` pins become versions, anything else is unpinned.

    Option lines (-r, -c, -e, --index-url, ...) are skipped. Environment markers are not
    evaluated, so a marker-guarded requirement is conservatively included.
    """

    def supports(self, manifest: ManifestFile) -> bool:
        """True for PyPI `.txt` files (discovery only yields requirements files)."""
        return manifest.ecosystem is Ecosystem.PYPI and manifest.rel_path.endswith(".txt")

    def parse(self, manifest: ManifestFile, content: str) -> ParseResult:
        """Parse requirements text. Bad lines become one PARTIAL_PARSE warning."""
        dependencies: list[Dependency] = []
        skipped: list[str] = []
        for number, text in _logical_lines(content):
            if not text or text.startswith("-"):
                continue
            parsed = parse_requirement_string(text)
            if parsed is None:
                skipped.append(f"line {number}")
                continue
            name, version = parsed
            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    direct=True,
                    source=manifest.rel_path,
                    line=number,
                )
            )
        notices = (partial_parse(manifest.rel_path, skipped),) if skipped else ()
        return ParseResult(dependencies=tuple(dependencies), notices=notices)


def _logical_lines(content: str) -> Iterator[tuple[int, str]]:
    """Yield (first physical line number, cleaned text), joining backslash continuations."""
    pieces: list[str] = []
    start = 1
    for number, raw in enumerate(content.splitlines(), start=1):
        if not pieces:
            start = number
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            pieces.append(stripped[:-1])
            continue
        pieces.append(raw)
        yield start, _clean("".join(pieces))
        pieces = []
    if pieces:
        yield start, _clean("".join(pieces))


def _clean(text: str) -> str:
    return _HASH_OPTION.sub("", _COMMENT.sub("", text)).strip()
