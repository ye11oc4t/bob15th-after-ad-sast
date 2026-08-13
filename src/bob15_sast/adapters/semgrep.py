"""Semgrep CE SARIF adapter."""

from __future__ import annotations

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

    def scan(self, target: Path, output_path: Path) -> ScanExecution:
        target, output_path = prepare_scan_paths(target, output_path)
        argv: list[str] = ["semgrep", "scan"]
        for config in self.configs:
            argv.extend(("--config", config))
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
        result = self.runner.run(argv, timeout_seconds=self.timeout_seconds)
        return ScanExecution(self.name, output_path, (result,))
