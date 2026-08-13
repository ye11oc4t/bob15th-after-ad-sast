"""Deterministic Markdown reporting for normalized findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .models import FindingGroup, Severity
from .redaction import redact_text


def _cell(value: object) -> str:
    text = redact_text(str(value)).replace("\\", "\\\\").replace("\n", " ")
    text = text.replace("`", "ˋ").replace("<", "&lt;").replace(">", "&gt;")
    for character in ("!", "[", "]", "|", "*"):
        text = text.replace(character, f"\\{character}")
    return text


def _score(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def render_markdown(
    *,
    run_id: str,
    groups: Sequence[FindingGroup],
    assessments: Mapping[str, Mapping[str, Any]] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render one report without claiming that AI hypotheses are confirmed."""
    assessments = assessments or {}
    generated_at = generated_at or datetime.now(UTC)
    severities = Counter(group.severity.value for group in groups)
    services = Counter(group.service for group in groups)
    raw_count = sum(group.count for group in groups)
    cross_tool = sum(group.is_cross_tool for group in groups)

    lines = [
        "# AI-assisted SAST report",
        "",
        f"- Run: `{_cell(run_id)}`",
        f"- Generated: `{generated_at.isoformat()}`",
        f"- Raw scanner findings: **{raw_count}**",
        f"- Root-cause groups: **{len(groups)}**",
        f"- Cross-tool groups: **{cross_tool}**",
        "",
        "> AI verdicts in this report are triage hypotheses. Only a human reviewer "
        "can mark a finding as confirmed or patched.",
        "",
        "## Summary",
        "",
        "### By severity",
        "",
        "| Severity | Groups |",
        "|---|---:|",
    ]
    for severity in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
        Severity.UNKNOWN,
    ):
        lines.append(f"| {severity.value} | {severities[severity.value]} |")
    lines.extend(["", "### By service", "", "| Service | Groups |", "|---|---:|"])
    for service, count in sorted(services.items()):
        lines.append(f"| {_cell(service)} | {count} |")

    lines.extend(
        [
            "",
            "## Root-cause groups",
            "",
            "| Fingerprint | Service | CWE | Severity | Tools | Raw | AI verdict | Confidence |",
            "|---|---|---|---|---|---:|---|---:|",
        ]
    )
    for group in sorted(
        groups,
        key=lambda item: (-item.severity.rank, item.service, item.fingerprint),
    ):
        assessment = assessments.get(group.fingerprint, {})
        verdict = assessment.get("disposition", assessment.get("verdict", "not_run"))
        confidence = assessment.get("confidence")
        numeric_confidence = float(confidence) if isinstance(confidence, (float, int)) else None
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{_cell(group.fingerprint[:19])}…`",
                    _cell(group.service),
                    _cell(", ".join(group.cwes) or "unknown"),
                    group.severity.value,
                    _cell(", ".join(group.tools)),
                    str(group.count),
                    _cell(verdict),
                    _score(numeric_confidence),
                ]
            )
            + " |"
        )

    lines.extend(["", "## Review queue", ""])
    for index, group in enumerate(
        sorted(groups, key=lambda item: (-item.severity.rank, item.fingerprint)), start=1
    ):
        assessment = assessments.get(group.fingerprint, {})
        location = group.sink
        location_text = (
            f"{_cell(location.path)}:{location.line}" if location else "<unknown>:0"
        )
        verdict = assessment.get("disposition", assessment.get("verdict", "not_run"))
        lines.extend(
            [
                f"### {index}. `{_cell(group.fingerprint)}`",
                "",
                f"- Service: `{_cell(group.service)}`",
                f"- Rules: `{_cell(', '.join(group.rule_ids))}`",
                f"- Location: `{location_text}`",
                f"- AI verdict: `{_cell(verdict)}`",
                "- Human status: `pending_review`",
                "",
            ]
        )
        root_cause = assessment.get(
            "root_cause_hypothesis", assessment.get("root_cause")
        )
        if isinstance(root_cause, str) and root_cause:
            lines.extend(["AI-proposed root cause:", "", f"> {_cell(root_cause)}", ""])
        evidence_ids = assessment.get("evidence_ids")
        if isinstance(evidence_ids, list):
            lines.append(f"Evidence: `{_cell(', '.join(map(str, evidence_ids)))}`")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"
