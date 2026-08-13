"""Deterministic Markdown reporting for normalized findings."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .models import FindingGroup, Severity
from .redaction import redact_text

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _cell(value: object, *, max_chars: int = 500) -> str:
    raw = str(value)
    text = _CONTROL_CHARACTERS.sub(" ", redact_text(raw[: max_chars * 4]))[:max_chars]
    text = text.replace("\\", "\\\\")
    text = text.replace("`", "ˋ").replace("<", "&lt;").replace(">", "&gt;")
    for character in ("!", "[", "]", "|", "*"):
        text = text.replace(character, f"\\{character}")
    return text


def _bounded_join(
    values: Sequence[object],
    *,
    max_chars: int,
    max_items: int,
    item_chars: int,
) -> str:
    """Join descriptors incrementally so one group cannot inflate the report."""

    parts: list[str] = []
    used = 0
    for value in values[:max_items]:
        separator = ", " if parts else ""
        remaining = max_chars - used - len(separator)
        if remaining <= 0:
            break
        limit = min(item_chars, remaining)
        part = redact_text(str(value)[: limit * 4])[:limit]
        if not part:
            continue
        if separator:
            parts.append(separator)
        parts.append(part)
        used += len(separator) + len(part)
    return "".join(parts)


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
    services = Counter(_cell(group.service, max_chars=500) for group in groups)
    raw_count = sum(group.count for group in groups)
    cross_tool = sum(group.is_cross_tool for group in groups)

    lines = [
        "# AI-assisted SAST report",
        "",
        f"- Run: `{_cell(run_id, max_chars=128)}`",
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
        lines.append(f"| {service} | {count} |")

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
                    f"`{_cell(group.fingerprint[:19], max_chars=19)}…`",
                    _cell(group.service, max_chars=500),
                    _cell(
                        _bounded_join(
                            group.cwes,
                            max_chars=1_000,
                            max_items=128,
                            item_chars=32,
                        )
                        or "unknown",
                        max_chars=1_000,
                    ),
                    group.severity.value,
                    _cell(
                        _bounded_join(
                            group.tools,
                            max_chars=1_000,
                            max_items=32,
                            item_chars=500,
                        ),
                        max_chars=1_000,
                    ),
                    str(group.count),
                    _cell(verdict, max_chars=200),
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
            f"{_cell(location.path, max_chars=2_000)}:{location.line}"
            if location
            else "<unknown>:0"
        )
        verdict = assessment.get("disposition", assessment.get("verdict", "not_run"))
        lines.extend(
            [
                f"### {index}. `{_cell(group.fingerprint, max_chars=200)}`",
                "",
                f"- Service: `{_cell(group.service, max_chars=500)}`",
                "- Rules: `"
                + _cell(
                    _bounded_join(
                        group.rule_ids,
                        max_chars=2_000,
                        max_items=128,
                        item_chars=1_000,
                    ),
                    max_chars=2_000,
                )
                + "`",
                f"- Location: `{location_text}`",
                f"- AI verdict: `{_cell(verdict, max_chars=200)}`",
                "- Human status: `pending_review`",
                "",
            ]
        )
        root_cause = assessment.get("root_cause_hypothesis", assessment.get("root_cause"))
        if isinstance(root_cause, str) and root_cause:
            lines.extend(
                [
                    "AI-proposed root cause:",
                    "",
                    f"> {_cell(root_cause, max_chars=4_000)}",
                    "",
                ]
            )
        evidence_ids = assessment.get("evidence_ids")
        if isinstance(evidence_ids, list):
            lines.append(
                "Evidence: `"
                + _cell(
                    _bounded_join(
                        evidence_ids,
                        max_chars=2_000,
                        max_items=40,
                        item_chars=200,
                    ),
                    max_chars=2_000,
                )
                + "`"
            )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"
