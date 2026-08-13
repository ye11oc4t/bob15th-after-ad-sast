"""Semgrep CE SARIF adapter."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from bob15_sast.adapters.base import ScanExecution, ScannerAdapter, prepare_scan_paths
from bob15_sast.safe_exec import SafeCommandRunner


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"

    def __init__(
        self,
        *,
        configs: Sequence[str | Path] = ("rules/semgrep",),
        runner: SafeCommandRunner | None = None,
        timeout_seconds: float = 300.0,
    ) -> None:
        if not configs:
            raise ValueError("at least one Semgrep config is required")
        self.configs = tuple(str(config) for config in configs)
        self.runner = runner or SafeCommandRunner()
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _resolve_local_config(config: str) -> Path:
        """Resolve a Semgrep config without permitting registry or URL selectors."""

        if "\x00" in config:
            raise ValueError("Semgrep config paths must not contain NUL bytes")
        if "://" in config:
            raise ValueError("Semgrep configs must be local paths, not URLs")

        path = Path(config).expanduser()
        try:
            resolved = path.resolve(strict=True)
        except FileNotFoundError as error:
            raise FileNotFoundError(f"Semgrep config does not exist: {path}") from error
        if not (resolved.is_file() or resolved.is_dir()):
            raise ValueError(f"Semgrep config must be a file or directory: {resolved}")

        required_access = os.R_OK | (os.X_OK if resolved.is_dir() else 0)
        if not os.access(resolved, required_access):
            raise PermissionError(f"Semgrep config is not readable: {resolved}")
        return resolved

    def scan(self, target: Path, output_path: Path) -> ScanExecution:
        target, output_path = prepare_scan_paths(target, output_path)
        configs = tuple(self._resolve_local_config(config) for config in self.configs)
        argv: list[str] = ["semgrep", "scan"]
        for config in configs:
            argv.extend(("--config", str(config)))
        argv.extend(
            (
                "--sarif",
                "--output",
                str(output_path),
                "--metrics=off",
                "--disable-version-check",
                str(target),
            )
        )
        result = self.runner.run(
            argv,
            timeout_seconds=self.timeout_seconds,
            forbidden_executable_roots=(target,),
        )
        return ScanExecution(self.name, output_path, (result,))
