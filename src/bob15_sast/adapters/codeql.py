"""CodeQL database creation and SARIF analysis adapter.

No repository-supplied build command is accepted.  Languages that need a
compiled database use CodeQL's build-mode ``none`` where supported; projects
requiring a real build must be handled in a separately sandboxed build stage.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from bob15_sast.adapters.base import ScanExecution, ScannerAdapter, prepare_scan_paths
from bob15_sast.safe_exec import SafeCommandRunner

_LANGUAGE_ALIASES = {
    "javascript": "javascript-typescript",
    "typescript": "javascript-typescript",
    "java": "java-kotlin",
}
_SUPPORTED_LANGUAGES = {
    "csharp",
    "java-kotlin",
    "javascript-typescript",
    "python",
    "ruby",
}
_NO_BUILD_MODE_LANGUAGES = {
    "csharp",
    "java-kotlin",
    "javascript-typescript",
    "python",
    "ruby",
}
_QUERY_PACK_LANGUAGES = {
    "csharp": "csharp",
    "java-kotlin": "java",
    "javascript-typescript": "javascript",
    "python": "python",
    "ruby": "ruby",
}


def _contains_kotlin_source(target: Path) -> bool:
    """Return whether a file or tree contains Kotlin source.

    CodeQL's no-build extraction is intentionally used by this adapter so
    repository-controlled build scripts are never executed.  That mode does
    not extract Kotlin, so silently analyzing only the Java portion would
    produce a dangerously incomplete result.
    """

    if target.is_file():
        return target.suffix.casefold() in {".kt", ".kts"}
    for _root, _directories, filenames in os.walk(target, followlinks=False):
        if any(
            filename.casefold().endswith((".kt", ".kts"))
            for filename in filenames
        ):
            return True
    return False


class CodeQLAdapter(ScannerAdapter):
    name = "codeql"

    def __init__(
        self,
        *,
        language: str,
        database_path: Path,
        queries: Sequence[str | Path] | None = None,
        runner: SafeCommandRunner | None = None,
        timeout_seconds: float = 1_800.0,
        overwrite_database: bool = False,
    ) -> None:
        normalized_language = _LANGUAGE_ALIASES.get(language, language)
        if normalized_language not in _SUPPORTED_LANGUAGES:
            raise ValueError(
                f"unsupported or build-required CodeQL language: {language!r}"
            )
        self.language = normalized_language
        self.database_path = database_path.expanduser().resolve()
        self.queries = tuple(str(query) for query in (queries or ()))
        self.runner = runner or SafeCommandRunner()
        self.timeout_seconds = timeout_seconds
        self.overwrite_database = overwrite_database

    def _default_query_suite(self) -> str:
        pack_language = _QUERY_PACK_LANGUAGES[self.language]
        return (
            f"codeql/{pack_language}-queries:codeql-suites/"
            f"{pack_language}-security-and-quality.qls"
        )

    def scan(self, target: Path, output_path: Path) -> ScanExecution:
        target, output_path = prepare_scan_paths(target, output_path)
        if self.language == "java-kotlin" and _contains_kotlin_source(target):
            raise ValueError(
                "CodeQL --build-mode=none is Java-only and does not extract Kotlin; "
                "the target contains .kt or .kts source files. Analyze it in a separately "
                "sandboxed build stage instead."
            )
        if self.database_path == target or target in self.database_path.parents:
            raise ValueError("the CodeQL database must be outside the target tree")
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        create_argv = [
            "codeql",
            "database",
            "create",
            str(self.database_path),
            f"--language={self.language}",
            f"--source-root={target}",
        ]
        if self.language in _NO_BUILD_MODE_LANGUAGES:
            create_argv.append("--build-mode=none")
        if self.overwrite_database:
            create_argv.append("--overwrite")

        create_result = self.runner.run(
            create_argv,
            timeout_seconds=self.timeout_seconds,
            forbidden_executable_roots=(target,),
        )
        if not create_result.succeeded:
            return ScanExecution(self.name, output_path, (create_result,))

        analyze_argv = [
            "codeql",
            "database",
            "analyze",
            str(self.database_path),
            *(self.queries or (self._default_query_suite(),)),
            "--format=sarifv2.1.0",
            f"--output={output_path}",
            "--threads=0",
        ]
        analyze_result = self.runner.run(
            analyze_argv,
            timeout_seconds=self.timeout_seconds,
            forbidden_executable_roots=(target,),
        )
        return ScanExecution(
            self.name, output_path, (create_result, analyze_result)
        )
