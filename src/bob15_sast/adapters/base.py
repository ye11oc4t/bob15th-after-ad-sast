"""Shared scanner adapter contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from bob15_sast.safe_exec import CommandResult


@dataclass(frozen=True, slots=True)
class ScanExecution:
    """Scanner process results and the SARIF path it was asked to create."""

    scanner: str
    output_path: Path
    commands: tuple[CommandResult, ...]

    @property
    def succeeded(self) -> bool:
        return bool(self.commands) and all(command.succeeded for command in self.commands)

    @property
    def result(self) -> CommandResult:
        """Return the final command result for simple one-command consumers."""

        if not self.commands:
            raise RuntimeError("the adapter did not execute a command")
        return self.commands[-1]


class ScannerAdapter(ABC):
    """Interface implemented by SARIF-producing local scanners."""

    name: str

    @abstractmethod
    def scan(self, target: Path, output_path: Path) -> ScanExecution:
        """Scan ``target`` and request SARIF at ``output_path``."""

        raise NotImplementedError


def prepare_scan_paths(target: Path, output_path: Path) -> tuple[Path, Path]:
    resolved_target = target.expanduser().resolve()
    if not resolved_target.exists():
        raise FileNotFoundError(resolved_target)

    resolved_output = output_path.expanduser().resolve()
    if resolved_output == resolved_target or resolved_target in resolved_output.parents:
        raise ValueError("scanner output must be outside the untrusted target tree")
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    return resolved_target, resolved_output
