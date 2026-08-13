"""SARIF-producing scanner adapters."""

from bob15_sast.adapters.base import ScanExecution, ScannerAdapter
from bob15_sast.adapters.codeql import CodeQLAdapter
from bob15_sast.adapters.semgrep import SemgrepAdapter
from bob15_sast.adapters.trivy import TrivyAdapter

__all__ = [
    "CodeQLAdapter",
    "ScanExecution",
    "ScannerAdapter",
    "SemgrepAdapter",
    "TrivyAdapter",
]
