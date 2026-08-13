"""Canonical data models shared by the scanner adapters.

The project deliberately keeps the normalized model smaller than SARIF.  Scanner
specific data is retained in ``properties``, while the fields used for triage and
root-cause grouping have a stable, typed representation.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from enum import StrEnum
from typing import Any
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_CWE_RE = re.compile(r"(?i)(?<![A-Z0-9])CWE(?:[-_/ ]?)(\d{1,5})(?!\d)")


class Severity(StrEnum):
    """Scanner-independent severity values."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return {
            Severity.UNKNOWN: 0,
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }[self]


def normalize_cwe(value: str | int | None) -> str | None:
    """Return a canonical ``CWE-N`` identifier, or ``None`` when unavailable."""

    if value is None:
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if value >= 0 else None
    match = _CWE_RE.search(str(value))
    if not match:
        return None
    return f"CWE-{int(match.group(1))}"


def normalize_path(path: str) -> str:
    """Normalize a SARIF artifact path without depending on the host platform."""

    cleaned = unquote(str(path)).replace("\\", "/").strip()
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    # Preserve an absolute-path marker here.  The SARIF adapter removes build
    # roots before constructing a Location.
    is_absolute = cleaned.startswith("/")
    cleaned = posixpath.normpath(cleaned or ".")
    if cleaned == ".":
        return "<unknown>"
    if not is_absolute:
        cleaned = cleaned.lstrip("/")
    return cleaned


class Location(BaseModel):
    """A source location normalized to a repository-relative POSIX path."""

    model_config = ConfigDict(extra="forbid")

    path: str
    line: int = Field(default=1, ge=0)
    column: int | None = Field(default=None, ge=0)
    end_line: int | None = Field(default=None, ge=0)
    end_column: int | None = Field(default=None, ge=0)
    snippet: str | None = None
    original_uri: str | None = None

    @field_validator("path")
    @classmethod
    def _normalize_path(cls, value: str) -> str:
        return normalize_path(value)


class TraceStep(BaseModel):
    """One location in a SARIF thread flow."""

    model_config = ConfigDict(extra="allow")

    location: Location
    message: str | None = None
    execution_order: int | None = Field(default=None, ge=0)
    nesting_level: int | None = Field(default=None, ge=0)
    kinds: list[str] = Field(default_factory=list)


class CodeFlow(BaseModel):
    """A flattened SARIF thread flow from source to sink."""

    model_config = ConfigDict(extra="allow")

    steps: list[TraceStep] = Field(default_factory=list)
    message: str | None = None

    @property
    def sink(self) -> Location | None:
        return self.steps[-1].location if self.steps else None


def root_cause_fingerprint(
    service: str,
    cwes: str | list[str] | tuple[str, ...] | set[str] | None,
    sink_path: str,
    sink_line: int,
) -> str:
    """Build a stable fingerprint from the root-cause identity fields.

    The hash intentionally excludes scanner name, rule ID, message text and
    severity.  Those values commonly differ between Semgrep, CodeQL and Trivy
    even when they describe the same vulnerable sink.
    """

    raw_cwes = [cwes] if isinstance(cwes, str) else list(cwes or [])
    canonical_cwes = sorted(
        {canonical for raw in raw_cwes if (canonical := normalize_cwe(raw))}
    )
    material = {
        "service": service.strip().casefold(),
        "cwe": canonical_cwes or ["CWE-UNKNOWN"],
        "sink": normalize_path(sink_path),
        "line": int(sink_line),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class Finding(BaseModel):
    """A normalized result emitted by one static-analysis tool."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    service: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    rule_name: str | None = None
    message: str = ""
    severity: Severity = Severity.UNKNOWN
    cwes: list[str] = Field(default_factory=list)
    locations: list[Location] = Field(default_factory=list)
    code_flows: list[CodeFlow] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str | None = None

    @field_validator("cwes", mode="before")
    @classmethod
    def _canonicalize_cwes(cls, value: Any) -> list[str]:
        if value is None:
            return []
        values = [value] if isinstance(value, (str, int)) else list(value)
        return sorted(
            {canonical for item in values if (canonical := normalize_cwe(item))}
        )

    @model_validator(mode="after")
    def _set_fingerprint(self) -> Finding:
        if not self.fingerprint:
            sink = self.sink
            self.fingerprint = root_cause_fingerprint(
                self.service,
                self.cwes,
                sink.path if sink else "<unknown>",
                sink.line if sink else 0,
            )
        return self

    @property
    def sink(self) -> Location | None:
        """Return the code-flow sink, falling back to the primary location."""

        for flow in self.code_flows:
            if flow.sink is not None:
                return flow.sink
        return self.locations[0] if self.locations else None

    @property
    def primary_location(self) -> Location | None:
        return self.locations[0] if self.locations else self.sink

    @property
    def primary_cwe(self) -> str | None:
        return self.cwes[0] if self.cwes else None

    # Compatibility aliases make integrations less dependent on pluralization.
    @property
    def cwe(self) -> str | None:
        return self.primary_cwe

    @property
    def codeflows(self) -> list[CodeFlow]:
        return self.code_flows


class FindingGroup(BaseModel):
    """Findings from one or more tools that share a root cause."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    service: str
    cwes: list[str] = Field(default_factory=list)
    sink: Location | None = None
    severity: Severity = Severity.UNKNOWN
    tools: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def is_cross_tool(self) -> bool:
        return len(self.tools) > 1

    @property
    def rule_ids(self) -> list[str]:
        return sorted({finding.rule_id for finding in self.findings})


__all__ = [
    "CodeFlow",
    "Finding",
    "FindingGroup",
    "Location",
    "Severity",
    "TraceStep",
    "normalize_cwe",
    "normalize_path",
    "root_cause_fingerprint",
]
