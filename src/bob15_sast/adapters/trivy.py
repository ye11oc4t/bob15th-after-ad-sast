"""Trivy filesystem SARIF adapter."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from bob15_sast.adapters.base import ScanExecution, ScannerAdapter, prepare_scan_paths
from bob15_sast.safe_exec import SafeCommandRunner

_ALLOWED_SCANNERS = frozenset({"vuln", "misconfig", "secret", "license"})


class TrivyAdapter(ScannerAdapter):
    name = "trivy"

    def __init__(
        self,
        *,
        scanners: Sequence[str] = ("vuln", "misconfig"),
        runner: SafeCommandRunner | None = None,
        timeout_seconds: float = 600.0,
        offline: bool = True,
    ) -> None:
        if not scanners or not set(scanners) <= _ALLOWED_SCANNERS:
            raise ValueError(
                f"scanners must be selected from {sorted(_ALLOWED_SCANNERS)}"
            )
        self.scanners = tuple(dict.fromkeys(scanners))
        self.runner = runner or SafeCommandRunner()
        self.timeout_seconds = timeout_seconds
        self.offline = offline

    def scan(self, target: Path, output_path: Path) -> ScanExecution:
        target, output_path = prepare_scan_paths(target, output_path)
        argv = [
            "trivy",
            "fs",
            "--format",
            "sarif",
            "--output",
            str(output_path),
            "--scanners",
            ",".join(self.scanners),
            "--skip-dirs",
            ".git",
            "--quiet",
        ]
        if self.offline:
            argv.extend(("--offline-scan", "--skip-db-update", "--skip-java-db-update"))
        argv.append(str(target))
        result = self.runner.run(argv, timeout_seconds=self.timeout_seconds)
        return ScanExecution(self.name, output_path, (result,))
