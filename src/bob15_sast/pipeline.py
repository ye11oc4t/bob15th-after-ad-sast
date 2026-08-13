"""Orchestrate SARIF normalization, evidence collection, triage, and reporting."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ai import EvidenceReference, TriageAssessment, TriageProvider, TriageRequest
from .evidence import evidence_id, source_excerpt, write_bundle
from .grouping import group_findings
from .jsonio import write_json
from .models import Finding, FindingGroup
from .redaction import redact, redact_text
from .report import render_markdown
from .sarif import load_sarif

_SAFE_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Paths and counts produced by one immutable pipeline run directory."""

    run_id: str
    run_directory: Path
    finding_count: int
    group_count: int
    assessment_count: int
    report_path: Path


def _new_run_id(now: datetime | None = None) -> str:
    moment = now or datetime.now(UTC)
    return moment.strftime("%Y%m%dT%H%M%S.%fZ")


def _validate_run_id(run_id: str) -> str:
    if _SAFE_RUN_ID.fullmatch(run_id) is None:
        raise ValueError(
            "run_id must start with an alphanumeric character and contain only "
            "letters, numbers, dot, underscore, or dash"
        )
    return run_id


def load_findings(
    sarif_paths: Sequence[Path],
    *,
    service: str,
    repo_root: Path | None = None,
) -> list[Finding]:
    """Load one or more SARIF files into a deterministic finding list."""

    if not sarif_paths:
        raise ValueError("at least one SARIF path is required")
    findings: list[Finding] = []
    for path in sarif_paths:
        findings.extend(load_sarif(path, service=service, repo_root=repo_root))
    return sorted(
        findings,
        key=lambda item: (
            item.service.casefold(),
            item.sink.path if item.sink else "<unknown>",
            item.sink.line if item.sink else 0,
            item.tool.casefold(),
            item.rule_id,
        ),
    )


def _group_payload(group: FindingGroup) -> dict[str, Any]:
    location = _public_location(group.sink)
    return {
        "id": group.fingerprint,
        "fingerprint": group.fingerprint,
        "service": redact_text(group.service),
        "tools": [redact_text(tool) for tool in group.tools],
        "rule_ids": [redact_text(rule_id) for rule_id in group.rule_ids],
        "severity": group.severity.value,
        "cwes": group.cwes,
        "location": location,
        "status": "candidate",
        "requires_human_confirmation": True,
        "findings": [public_finding(finding) for finding in group.findings],
    }


def _public_location(location: Any) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        "path": redact_text(location.path),
        "line": location.line,
        "column": location.column,
        "end_line": location.end_line,
        "end_column": location.end_column,
    }


def public_finding(finding: Finding) -> dict[str, Any]:
    """Serialize only fields needed for review; omit raw SARIF snippets/properties."""

    return {
        "fingerprint": finding.fingerprint,
        "service": redact_text(finding.service),
        "tool": redact_text(finding.tool),
        "rule_id": redact_text(finding.rule_id),
        "severity": finding.severity.value,
        "cwes": finding.cwes,
        "locations": [
            location
            for item in finding.locations
            if (location := _public_location(item)) is not None
        ],
        "code_flows": [
            {
                "steps": [
                    {
                        "location": _public_location(step.location),
                        "execution_order": step.execution_order,
                        "kinds": step.kinds[:10],
                    }
                    for step in flow.steps[:20]
                ]
            }
            for flow in finding.code_flows[:5]
        ],
    }


def _scanner_evidence(group: FindingGroup) -> EvidenceReference:
    location = group.sink
    where = (
        f"{location.path}:{location.line}" if location is not None else "<unknown>:0"
    )
    content = redact_text(
        "\n".join(
            (
                f"Tools: {', '.join(group.tools)}",
                f"Rules: {', '.join(group.rule_ids)}",
                f"Severity: {group.severity.value}",
                f"CWE: {', '.join(group.cwes) or 'unknown'}",
                f"Sink: {where}",
            )
        )
    )
    return EvidenceReference(
        evidence_id=evidence_id("scanner", content),
        kind="scanner",
        content=content,
        location=where,
    )


def _dataflow_evidence(group: FindingGroup) -> EvidenceReference | None:
    for finding in group.findings:
        for flow in finding.code_flows:
            if not flow.steps:
                continue
            selected = flow.steps[:20]
            content = redact_text(
                "\n".join(
                    f"{index}. {step.location.path}:{step.location.line}"
                    for index, step in enumerate(selected, start=1)
                )
            )[:24_000]
            return EvidenceReference(
                evidence_id=evidence_id("dataflow", content),
                kind="dataflow",
                content=content,
                location=(
                    f"{selected[-1].location.path}:{selected[-1].location.line}"
                ),
            )
    return None


def _source_evidence(
    group: FindingGroup,
    source_root: Path | None,
) -> EvidenceReference | None:
    if source_root is None or group.sink is None:
        return None
    try:
        excerpt, first, last = source_excerpt(
            source_root,
            group.sink.path,
            group.sink.line,
        )
    except (OSError, ValueError):
        return None
    location = f"{group.sink.path}:{first}-{last}"
    content = excerpt[:24_000]
    return EvidenceReference(
        evidence_id=evidence_id("source", f"{location}\0{content}"),
        kind="source",
        content=content,
        location=location,
    )


def build_triage_request(
    group: FindingGroup,
    *,
    source_root: Path | None = None,
) -> TriageRequest:
    """Create a bounded, redacted request that cites only collected evidence."""

    evidence = [_scanner_evidence(group)]
    dataflow = _dataflow_evidence(group)
    source = _source_evidence(group, source_root)
    if dataflow is not None:
        evidence.append(dataflow)
    if source is not None:
        evidence.append(source)

    message = (
        "Scanner candidate requires review. Raw scanner messages are intentionally "
        "excluded from remote triage."
    )
    return TriageRequest(
        finding_id=group.fingerprint,
        scanner=", ".join(group.tools)[:100] or "unknown",
        rule_id=", ".join(group.rule_ids)[:300] or "unknown-rule",
        message=message,
        reported_severity=group.severity.value,
        evidence=evidence,
        metadata=redact(
            {
                "service": group.service,
                "cwes": group.cwes,
                "cross_tool": group.is_cross_tool,
                "raw_finding_count": group.count,
            }
        ),
    )


def _report_assessment(assessment: TriageAssessment) -> dict[str, Any]:
    return {
        "disposition": assessment.disposition,
        "confidence": assessment.confidence,
        "root_cause_hypothesis": assessment.root_cause_hypothesis,
        "evidence_ids": assessment.evidence_ids,
        "requires_human_confirmation": True,
    }


def run_pipeline(
    sarif_paths: Sequence[Path],
    *,
    service: str,
    output_root: Path,
    source_root: Path | None = None,
    repo_root: Path | None = None,
    provider: TriageProvider | None = None,
    include_source_evidence: bool = False,
    run_id: str | None = None,
    generated_at: datetime | None = None,
) -> PipelineResult:
    """Run the local evidence pipeline without executing target source code."""

    if not service.strip():
        raise ValueError("service must not be blank")
    selected_run_id = _validate_run_id(run_id or _new_run_id(generated_at))
    run_directory = output_root.expanduser().resolve() / selected_run_id
    run_directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    try:
        run_directory.chmod(0o700)
    except OSError:  # pragma: no cover - permissions differ on Windows
        pass

    findings = load_findings(sarif_paths, service=service, repo_root=repo_root)
    groups = group_findings(findings)
    write_json(
        run_directory / "normalized-findings.json",
        [public_finding(finding) for finding in findings],
    )
    write_json(
        run_directory / "root-cause-groups.json",
        [_group_payload(group) for group in groups],
    )

    assessments: dict[str, dict[str, Any]] = {}
    for group in groups:
        request = build_triage_request(
            group,
            source_root=source_root if include_source_evidence else None,
        )
        evidence_manifest = [item.model_dump(mode="json") for item in request.evidence]
        bundle = write_bundle(
            run_directory / "evidence-bundles",
            _group_payload(group),
            evidence_manifest,
        )
        if provider is None:
            continue
        write_json(bundle / "triage-request.json", redact(request.model_dump(mode="json")))
        assessment = provider.triage(request)
        if assessment.finding_id != request.finding_id:
            raise ValueError("triage response finding ID does not match the request")
        unknown_evidence = set(assessment.evidence_ids) - request.evidence_ids
        if unknown_evidence:
            raise ValueError(
                f"triage response cited unknown evidence IDs: {sorted(unknown_evidence)}"
            )
        clean_assessment = redact(assessment.model_dump(mode="json"))
        write_json(bundle / "triage-assessment.json", clean_assessment)
        assessments[group.fingerprint] = clean_assessment

    write_json(run_directory / "triage-assessments.json", assessments)
    report_path = run_directory / "report.md"
    report_path.write_text(
        render_markdown(
            run_id=selected_run_id,
            groups=groups,
            assessments={
                fingerprint: _report_assessment(
                    TriageAssessment.model_validate(assessment)
                )
                for fingerprint, assessment in assessments.items()
            },
            generated_at=generated_at,
        ),
        encoding="utf-8",
    )
    try:
        report_path.chmod(0o600)
    except OSError:  # pragma: no cover - permissions differ on Windows
        pass
    write_json(
        run_directory / "run.json",
        {
            "run_id": selected_run_id,
            "service": redact_text(service),
            "inputs": [redact_text(path.name) for path in sarif_paths],
            "finding_count": len(findings),
            "root_cause_group_count": len(groups),
            "assessment_count": len(assessments),
            "triage_provider": type(provider).__name__ if provider else "disabled",
            "human_review_status": "pending_review",
        },
    )
    return PipelineResult(
        run_id=selected_run_id,
        run_directory=run_directory,
        finding_count=len(findings),
        group_count=len(groups),
        assessment_count=len(assessments),
        report_path=report_path,
    )
