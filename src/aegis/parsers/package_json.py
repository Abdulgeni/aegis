"""Parser for package.json."""

from __future__ import annotations

from pathlib import PurePosixPath

from aegis.core.enums import Ecosystem, NoticeCode
from aegis.core.models import Dependency, ManifestFile, ParseResult
from aegis.core.names import normalize_name
from aegis.parsers._common import as_table, failed, info, load_json_object, npm_exact, partial_parse

_IN_SCOPE = ("dependencies", "devDependencies")
_OUT_OF_SCOPE = ("peerDependencies", "optionalDependencies")


class PackageJsonParser:
    """Reads `dependencies` and `devDependencies`; all are direct.

    Only exact versions (`1.2.3`, `=1.2.3`, `v1.2.3`) are pinned; ranges, tags, URLs and
    aliases give `version=None`. Peer and optional dependencies are out of scope (INFO).
    """

    def supports(self, manifest: ManifestFile) -> bool:
        """True for files named package.json."""
        return PurePosixPath(manifest.rel_path).name == "package.json"

    def parse(self, manifest: ManifestFile, content: str) -> ParseResult:
        """Parse package.json text. Invalid JSON gives a PARSE_FAILED warning."""
        data = load_json_object(content)
        if data is None:
            return failed(manifest.rel_path, "invalid JSON or not a JSON object")

        dependencies: list[Dependency] = []
        skipped: list[str] = []
        for section in _IN_SCOPE:
            for name, spec in as_table(data.get(section)).items():
                if not isinstance(spec, str):
                    skipped.append(name)
                    continue
                dependencies.append(
                    Dependency(
                        name=normalize_name(Ecosystem.NPM, name),
                        version=npm_exact(spec),
                        ecosystem=Ecosystem.NPM,
                        direct=True,
                        source=manifest.rel_path,
                    )
                )
        notices = []
        if skipped:
            notices.append(partial_parse(manifest.rel_path, skipped))
        if any(as_table(data.get(section)) for section in _OUT_OF_SCOPE):
            notices.append(
                info(
                    NoticeCode.OUT_OF_SCOPE_DEPENDENCIES,
                    "peerDependencies / optionalDependencies are out of scope in v1 and were not checked",
                    manifest.rel_path,
                )
            )
        return ParseResult(dependencies=tuple(dependencies), notices=tuple(notices))
