"""Parser for go.mod."""

from __future__ import annotations

from pathlib import PurePosixPath

from aegis.core.enums import Ecosystem, NoticeCode
from aegis.core.models import Dependency, ManifestFile, ParseResult
from aegis.core.names import normalize_name
from aegis.parsers._common import info, partial_parse


class GoModParser:
    """Reads `require` directives (single-line and block form).

    Versions are kept raw, including the `v` prefix and pseudo-versions. `// indirect`
    gives `direct=False`. `replace` directives are not applied (INFO).
    """

    def supports(self, manifest: ManifestFile) -> bool:
        """True for files named go.mod."""
        return PurePosixPath(manifest.rel_path).name == "go.mod"

    def parse(self, manifest: ManifestFile, content: str) -> ParseResult:
        """Parse go.mod text. Malformed require lines become one PARTIAL_PARSE warning."""
        dependencies: list[Dependency] = []
        skipped: list[str] = []
        saw_replace = False
        block: str | None = None
        for number, raw in enumerate(content.splitlines(), start=1):
            code, _, comment = raw.partition("//")
            code, comment = code.strip(), comment.strip()
            if block is not None:
                if code == ")":
                    block = None
                elif block == "require" and code:
                    self._collect(code, comment, number, manifest, dependencies, skipped)
                elif block == "replace" and code:
                    saw_replace = True
                continue
            parts = code.split(None, 1)
            if not parts:
                continue
            directive, rest = parts[0], (parts[1].strip() if len(parts) > 1 else "")
            if rest == "(":
                block = directive
                saw_replace = saw_replace or directive == "replace"
            elif directive == "require" and rest:
                self._collect(rest, comment, number, manifest, dependencies, skipped)
            elif directive == "replace":
                saw_replace = True

        notices = []
        if skipped:
            notices.append(partial_parse(manifest.rel_path, skipped))
        if saw_replace:
            notices.append(
                info(
                    NoticeCode.OUT_OF_SCOPE_DEPENDENCIES,
                    "replace directives are not applied; replaced modules may differ from those checked",
                    manifest.rel_path,
                )
            )
        return ParseResult(dependencies=tuple(dependencies), notices=tuple(notices))

    @staticmethod
    def _collect(
        entry: str,
        comment: str,
        number: int,
        manifest: ManifestFile,
        dependencies: list[Dependency],
        skipped: list[str],
    ) -> None:
        tokens = entry.split()
        if len(tokens) != 2 or not tokens[1].startswith("v"):
            skipped.append(f"line {number}")
            return
        dependencies.append(
            Dependency(
                name=normalize_name(Ecosystem.GO, tokens[0].strip("\"`")),
                version=tokens[1],
                ecosystem=Ecosystem.GO,
                direct=not comment.startswith("indirect"),
                source=manifest.rel_path,
                line=number,
            )
        )
