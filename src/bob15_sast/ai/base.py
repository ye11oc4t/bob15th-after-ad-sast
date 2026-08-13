"""Typed contracts for evidence-bound AI triage.

AI output is a review hypothesis, never a vulnerability confirmation.  The
schema intentionally has no ``confirmed`` state and requires evidence IDs so
that every assessment remains traceable to locally stored evidence.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Disposition = Literal[
    "likely_vulnerability",
    "needs_review",
    "likely_false_positive",
    "insufficient_evidence",
]
Reachability = Literal["reachable", "blocked", "unknown", "not_applicable"]
EvidenceKind = Literal[
    "scanner",
    "source",
    "dataflow",
    "configuration",
    "runtime",
    "patch",
    "test",
    "other",
]

_NEGATED_CONFIRMATION = re.compile(
    r"\b(?:not|never)\s+(?:an?\s+)?confirmed\b|"
    r"\b(?:is|was|has|have)\s+not\s+(?:been\s+)?confirmed\b|"
    r"\b(?:cannot|can\s+not|can't)\s+be\s+confirmed\b|"
    r"\bunconfirmed\b|"
    r"(?:미확정|확정\s*아님|확정되지\s*않\w*|확정할\s*수\s*없\w*)",
    re.IGNORECASE,
)
_AUTHORITATIVE_CLAIM = re.compile(
    r"\b(?:is|was|has\s+been|have\s+been|now|definitively|definitely|"
    r"conclusively)\s+confirmed\b|"
    r"\bconfirmed\s+(?:vulnerability|finding|issue)\b|"
    r"\b(?:proven|verified)\s+(?:vulnerability|finding|issue)\b|"
    r"(?:취약점|문제|항목)(?:으로)?\s*확정|"
    r"확정(?:됨|되었\w*|입니다|이다)|"
    r"검증\s*완료(?:됨|되었\w*|입니다)?",
    re.IGNORECASE,
)


class EvidenceReference(BaseModel):
    """Small, redacted evidence fragment supplied to a triage provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(min_length=1, max_length=200)
    kind: EvidenceKind
    content: str = Field(min_length=1, max_length=24_000)
    location: str | None

    @field_validator("evidence_id", "content")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence fields may not be blank")
        return value


class TriageRequest(BaseModel):
    """Scanner finding plus the bounded evidence needed to review it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1, max_length=200)
    scanner: str = Field(min_length=1, max_length=100)
    rule_id: str = Field(min_length=1, max_length=300)
    message: str = Field(min_length=1, max_length=8_000)
    reported_severity: str
    evidence: list[EvidenceReference] = Field(min_length=1, max_length=40)
    metadata: dict[str, Any]

    @field_validator("finding_id", "scanner", "rule_id", "message")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("triage request fields may not be blank")
        return value

    @model_validator(mode="after")
    def evidence_ids_are_unique(self) -> TriageRequest:
        ids = [item.evidence_id for item in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence IDs must be unique within a request")
        return self

    @property
    def evidence_ids(self) -> frozenset[str]:
        return frozenset(item.evidence_id for item in self.evidence)


class TriageAssessment(BaseModel):
    """Structured, non-authoritative triage hypothesis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=300)
    disposition: Disposition
    summary: str = Field(min_length=1, max_length=4_000)
    root_cause_hypothesis: str = Field(min_length=1, max_length=4_000)
    cwe: str | None
    reachability: Reachability
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(min_length=1, max_length=40)
    missing_evidence: list[str] = Field(max_length=20)
    recommended_actions: list[str] = Field(min_length=1, max_length=20)
    requires_human_confirmation: Literal[True]

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_are_nonblank_and_unique(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if any(not value for value in normalized):
            raise ValueError("at least one non-blank evidence ID is required")
        if len(normalized) != len(set(normalized)):
            raise ValueError("assessment evidence IDs must be unique")
        return normalized

    @model_validator(mode="after")
    def forbid_confirmation_claims(self) -> TriageAssessment:
        # A finding can only become confirmed in the human-controlled workflow.
        # Keeping this word out of generated prose makes that boundary explicit.
        prose = " ".join(
            (
                self.title,
                self.summary,
                self.root_cause_hypothesis,
                *self.missing_evidence,
                *self.recommended_actions,
            )
        )
        # Explicit uncertainty such as "not confirmed" is desirable. Remove
        # those phrases before checking for an affirmative authority claim.
        claims_only = _NEGATED_CONFIRMATION.sub("", prose)
        if _AUTHORITATIVE_CLAIM.search(claims_only):
            raise ValueError("AI triage may not claim that a finding is confirmed")
        return self


@runtime_checkable
class TriageProvider(Protocol):
    """Provider interface used by the orchestration layer."""

    def triage(self, request: TriageRequest) -> TriageAssessment:
        """Return an evidence-bound review hypothesis."""

        ...
