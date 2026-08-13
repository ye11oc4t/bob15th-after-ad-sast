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
_NON_SOURCE_PATHS = {"<unknown>", "<unsafe-path>", "<external-path>"}
DEFAULT_MAX_AI_GROUPS = 20
DEFAULT_MAX_FINDINGS = 5_000
DEFAULT_MAX_GROUPS = 500

_MAX_FINGERPRINT_CHARS = 200
_MAX_SERVICE_CHARS = 500
_MAX_TOOL_CHARS = 500
_MAX_RULE_ID_CHARS = 1_000
_MAX_CWE_CHARS = 32
_MAX_GROUP_TOOLS = 32
_MAX_GROUP_RULE_IDS = 128
_MAX_GROUP_CWES = 128
_MAX_PUBLIC_LOCATIONS = 20


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


def _bounded_text(value: object, max_chars: int) -> str:
    """Redact a scalar before bounding its public representation."""

    return redact_text(str(value)[: max_chars * 4])[:max_chars]


def _bounded_values(
    values: Sequence[object],
    *,
    max_items: int,
    max_chars: int,
) -> list[str]:
    return [_bounded_text(value, max_chars) for value in values[:max_items]]


def _bounded_join(
    values: Sequence[object],
    *,
    max_chars: int,
    max_items: int,
    item_chars: int,
) -> str:
    """Join untrusted descriptors without first constructing an unbounded scalar."""

    parts: list[str] = []
    used = 0
    for value in values[:max_items]:
        separator = ", " if parts else ""
        remaining = max_chars - used - len(separator)
        if remaining <= 0:
            break
        part = _bounded_text(value, min(item_chars, remaining))
        if not part:
            continue
        if separator:
            parts.append(separator)
        parts.append(part)
        used += len(separator) + len(part)
    return "".join(parts)


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
    status = "candidate"
    if group.findings and all(_is_suppressed(item) for item in group.findings):
        status = "suppressed_candidate"
    elif group.findings and all(_baseline_state(item) == "absent" for item in group.findings):
        status = "baseline_absent"
    return {
        "id": _bounded_text(group.fingerprint, _MAX_FINGERPRINT_CHARS),
        "fingerprint": _bounded_text(group.fingerprint, _MAX_FINGERPRINT_CHARS),
        "service": _bounded_text(group.service, _MAX_SERVICE_CHARS),
        "tools": _bounded_values(
            group.tools,
            max_items=_MAX_GROUP_TOOLS,
            max_chars=_MAX_TOOL_CHARS,
        ),
        "rule_ids": _bounded_values(
            group.rule_ids,
            max_items=_MAX_GROUP_RULE_IDS,
            max_chars=_MAX_RULE_ID_CHARS,
        ),
        "severity": group.severity.value,
        "cwes": _bounded_values(
            group.cwes,
            max_items=_MAX_GROUP_CWES,
            max_chars=_MAX_CWE_CHARS,
        ),
        "location": location,
        "status": status,
        "requires_human_confirmation": True,
        "findings": [public_finding(finding) for finding in group.findings],
    }


def _public_location(location: Any) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        "path": redact_text(location.path)[:2_000],
        "line": location.line,
        "column": location.column,
        "end_line": location.end_line,
        "end_column": location.end_column,
    }


def _is_suppressed(finding: Finding) -> bool:
    return finding.properties.get("sarif_has_accepted_suppression") is True


def _baseline_state(finding: Finding) -> str | None:
    value = finding.properties.get("sarif_baseline_state")
    normalized = str(value).casefold() if value is not None else None
    return normalized if normalized in {"new", "unchanged", "updated", "absent"} else None


def public_finding(finding: Finding) -> dict[str, Any]:
    """Serialize only fields needed for review; omit raw SARIF snippets/properties."""

    return {
        "fingerprint": _bounded_text(finding.fingerprint or "unknown", _MAX_FINGERPRINT_CHARS),
        "service": _bounded_text(finding.service, _MAX_SERVICE_CHARS),
        "tool": _bounded_text(finding.tool, _MAX_TOOL_CHARS),
        "rule_id": _bounded_text(finding.rule_id, _MAX_RULE_ID_CHARS),
        "severity": finding.severity.value,
        "cwes": _bounded_values(
            finding.cwes,
            max_items=_MAX_GROUP_CWES,
            max_chars=_MAX_CWE_CHARS,
        ),
        "suppressed": _is_suppressed(finding),
        "baseline_state": _baseline_state(finding),
        "locations": [
            location
            for item in finding.locations[:_MAX_PUBLIC_LOCATIONS]
            if (location := _public_location(item)) is not None
        ],
        "code_flows": [
            {
                "steps": [
                    {
                        "location": _public_location(step.location),
                        "execution_order": step.execution_order,
                        "kinds": [redact_text(str(kind))[:200] for kind in step.kinds[:10]],
                    }
                    for step in flow.steps[:20]
                ]
            }
            for flow in finding.code_flows[:5]
        ],
    }


def _scanner_evidence(group: FindingGroup) -> EvidenceReference:
    location = group.sink
    where = redact_text(
        f"{location.path}:{location.line}" if location is not None else "<unknown>:0"
    )[:2_000]
    content = redact_text(
        "\n".join(
            (
                "Tools: "
                + _bounded_join(
                    group.tools,
                    max_chars=2_000,
                    max_items=_MAX_GROUP_TOOLS,
                    item_chars=_MAX_TOOL_CHARS,
                ),
                "Rules: "
                + _bounded_join(
                    group.rule_ids,
                    max_chars=4_000,
                    max_items=_MAX_GROUP_RULE_IDS,
                    item_chars=_MAX_RULE_ID_CHARS,
                ),
                f"Severity: {group.severity.value}",
                "CWE: "
                + (
                    _bounded_join(
                        group.cwes,
                        max_chars=1_000,
                        max_items=_MAX_GROUP_CWES,
                        item_chars=_MAX_CWE_CHARS,
                    )
                    or "unknown"
                ),
                f"Sink: {where}",
            )
        )
    )[:24_000]
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
                location=redact_text(f"{selected[-1].location.path}:{selected[-1].location.line}")[
                    :2_000
                ],
            )
    return None


def _source_evidence(
    group: FindingGroup,
    source_root: Path | None,
) -> EvidenceReference | None:
    if source_root is None or group.sink is None or group.sink.path in _NON_SOURCE_PATHS:
        return None
    try:
        excerpt, first, last = source_excerpt(
            source_root,
            group.sink.path,
            group.sink.line,
        )
    except (OSError, ValueError):
        return None
    location = redact_text(f"{group.sink.path}:{first}-{last}")[:2_000]
    content = excerpt[:24_000]
    if not content.strip():
        return None
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
        finding_id=_bounded_text(group.fingerprint, _MAX_FINGERPRINT_CHARS),
        scanner=(
            _bounded_join(
                group.tools,
                max_chars=100,
                max_items=_MAX_GROUP_TOOLS,
                item_chars=_MAX_TOOL_CHARS,
            )
            or "unknown"
        ),
        rule_id=(
            _bounded_join(
                group.rule_ids,
                max_chars=300,
                max_items=_MAX_GROUP_RULE_IDS,
                item_chars=_MAX_RULE_ID_CHARS,
            )
            or "unknown-rule"
        ),
        message=message,
        reported_severity=group.severity.value,
        evidence=evidence,
        metadata=redact(
            {
                "service": _bounded_text(group.service, _MAX_SERVICE_CHARS),
                "cwes": _bounded_values(
                    group.cwes,
                    max_items=_MAX_GROUP_CWES,
                    max_chars=_MAX_CWE_CHARS,
                ),
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
    max_ai_groups: int = DEFAULT_MAX_AI_GROUPS,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    max_groups: int = DEFAULT_MAX_GROUPS,
    run_id: str | None = None,
    generated_at: datetime | None = None,
) -> PipelineResult:
    """Run the local evidence pipeline without executing target source code."""

    if not service.strip():
        raise ValueError("service must not be blank")
    if max_ai_groups < 0:
        raise ValueError("max_ai_groups must be zero or greater")
    if max_findings < 0:
        raise ValueError("max_findings must be zero or greater")
    if max_groups < 0:
        raise ValueError("max_groups must be zero or greater")
    resolved_output_root = output_root.expanduser().resolve()
    if source_root is not None:
        resolved_source_root = source_root.expanduser().resolve()
        if resolved_output_root == resolved_source_root or resolved_output_root.is_relative_to(
            resolved_source_root
        ):
            raise ValueError("output_root must be outside the untrusted source tree")
    selected_run_id = _validate_run_id(run_id or _new_run_id(generated_at))
    findings = load_findings(sarif_paths, service=service, repo_root=repo_root)
    if len(findings) > max_findings:
        raise ValueError(
            f"pipeline loaded {len(findings)} findings, exceeding max_findings={max_findings}"
        )
    groups = group_findings(findings)
    if len(groups) > max_groups:
        raise ValueError(
            f"pipeline produced {len(groups)} groups, exceeding max_groups={max_groups}"
        )
    if provider is not None and len(groups) > max_ai_groups:
        raise ValueError(
            f"AI triage requires {len(groups)} calls, exceeding max_ai_groups="
            f"{max_ai_groups}; increase the limit explicitly after reviewing cost"
        )
    run_directory = resolved_output_root / selected_run_id
    run_directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    try:
        run_directory.chmod(0o700)
    except OSError:  # pragma: no cover - permissions differ on Windows
        pass
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
                fingerprint: _report_assessment(TriageAssessment.model_validate(assessment))
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
            "service": _bounded_text(service, _MAX_SERVICE_CHARS),
            "inputs": [redact_text(path.name) for path in sarif_paths],
            "finding_count": len(findings),
            "root_cause_group_count": len(groups),
            "assessment_count": len(assessments),
            "max_ai_groups": max_ai_groups,
            "limits": {
                "max_findings": max_findings,
                "max_groups": max_groups,
                "max_ai_groups": max_ai_groups,
            },
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
