"""Deterministic offline AI provider for tests and demos."""

from __future__ import annotations

import hashlib

from bob15_sast.ai.base import Disposition, TriageAssessment, TriageRequest


class MockTriageProvider:
    """Produce stable hypotheses without network or model dependencies."""

    def triage(self, request: TriageRequest) -> TriageAssessment:
        serialized = request.model_dump_json(exclude_none=False)
        bucket = int(hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:8], 16)
        severity = request.reported_severity.casefold()
        disposition: Disposition = (
            "likely_vulnerability"
            if severity in {"critical", "high", "error"}
            else "needs_review"
        )
        confidence = round(0.55 + (bucket % 16) / 100, 2)
        evidence_ids = [item.evidence_id for item in request.evidence]
        return TriageAssessment(
            finding_id=request.finding_id,
            title=f"Review hypothesis for {request.rule_id}",
            disposition=disposition,
            summary=(
                f"The {request.scanner} finding is supported by the referenced "
                "artifacts but still requires local validation."
            ),
            root_cause_hypothesis=(
                "A scanner-reported unsafe data or configuration pattern may be "
                "present along the referenced path."
            ),
            cwe=None,
            reachability="unknown",
            confidence=confidence,
            evidence_ids=evidence_ids,
            missing_evidence=["A guard-aware source-to-sink or runtime check"],
            recommended_actions=[
                "Review the referenced code and execute an isolated regression test"
            ],
            requires_human_confirmation=True,
        )
