"""Trivy filesystem SARIF adapter."""

from __future__ import annotations

import os
import tempfile
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
        cache_dir: str | Path | None = None,
    ) -> None:
        if not scanners or not set(scanners) <= _ALLOWED_SCANNERS:
            raise ValueError(
                f"scanners must be selected from {sorted(_ALLOWED_SCANNERS)}"
            )
        self.scanners = tuple(dict.fromkeys(scanners))
        self.runner = runner or SafeCommandRunner()
        self.timeout_seconds = timeout_seconds
        self.offline = offline
        self.cache_dir = None if cache_dir is None else Path(cache_dir)

    def _resolve_cache_dir(self, target: Path) -> Path | None:
        if self.cache_dir is None:
            return None
        try:
            cache_dir = self.cache_dir.expanduser().resolve(strict=True)
        except FileNotFoundError as error:
            raise FileNotFoundError(
                f"Trivy cache directory does not exist: {self.cache_dir}"
            ) from error
        if not cache_dir.is_dir():
            raise NotADirectoryError(cache_dir)
        if cache_dir == target or target in cache_dir.parents:
            raise ValueError("Trivy cache directory must be outside the untrusted target")
        if not os.access(cache_dir, os.R_OK | os.W_OK | os.X_OK):
            raise PermissionError(f"Trivy cache directory is not accessible: {cache_dir}")
        return cache_dir

    def scan(self, target: Path, output_path: Path) -> ScanExecution:
        target, output_path = prepare_scan_paths(target, output_path)
        cache_dir = self._resolve_cache_dir(target)

        # Trivy otherwise discovers trivy.yaml and .trivyignore from its working
        # directory.  Use private, known-empty policy files outside the target so
        # an untrusted repository cannot alter scanner behavior or suppress results.
        with tempfile.TemporaryDirectory(
            prefix=".bob15-trivy-policy-", dir=output_path.parent
        ) as policy_name:
            policy_dir = Path(policy_name)
            config_path = policy_dir / "trivy.yaml"
            ignore_path = policy_dir / ".trivyignore"
            config_path.write_text("{}\n", encoding="utf-8")
            ignore_path.write_text("", encoding="utf-8")
            config_path.chmod(0o600)
            ignore_path.chmod(0o600)

            argv = [
                "trivy",
                "--config",
                str(config_path),
            ]
            if cache_dir is not None:
                argv.extend(("--cache-dir", str(cache_dir)))
            argv.extend(
                (
                    "fs",
                    "--ignorefile",
                    str(ignore_path),
                    "--format",
                    "sarif",
                    "--output",
                    str(output_path),
                    "--scanners",
                    ",".join(self.scanners),
                    "--skip-dirs",
                    ".git",
                    "--quiet",
                )
            )
            if self.offline:
                argv.extend(
                    (
                        "--offline-scan",
                        "--skip-db-update",
                        "--skip-java-db-update",
                        "--skip-check-update",
                        "--skip-version-check",
                        "--disable-telemetry",
                    )
                )
            argv.append(str(target))
            result = self.runner.run(
                argv,
                timeout_seconds=self.timeout_seconds,
                cwd=policy_dir,
                forbidden_executable_roots=(target,),
            )
        return ScanExecution(self.name, output_path, (result,))
