"""Conservative, deterministic grouping for normalized scanner findings."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable

from .models import Finding, FindingGroup, Severity, root_cause_fingerprint

_NON_CONCRETE_PATHS = {"<unknown>", "<unsafe-path>", "<external-path>"}
_MAX_IDENTITY_CHARS = 2_000


def _identity_text(value: str) -> str:
    """Bound attacker-controlled fingerprint material without losing identity."""

    if len(value) <= _MAX_IDENTITY_CHARS:
        return value
    digest = hashlib.sha256(value.encode()).hexdigest()
    return f"{value[:_MAX_IDENTITY_CHARS]}#sha256:{digest}"


def _location_key(finding: Finding) -> tuple[str, str, int] | None:
    sink = finding.sink
    if sink is None or sink.path in _NON_CONCRETE_PATHS:
        return None
    return finding.service.strip().casefold(), sink.path, sink.line


def are_duplicates(left: Finding, right: Finding) -> bool:
    """Return whether two tools plausibly identify the same sink and CWE.

    Findings without a concrete location or CWE remain separate. Results from
    the same tool remain separate unless their rule IDs are identical, which
    avoids collapsing unrelated dependency records that share a manifest line.
    """

    left_location = _location_key(left)
    if left_location is None or left_location != _location_key(right):
        return False
    left_cwes, right_cwes = set(left.cwes), set(right.cwes)
    if not left_cwes or not right_cwes or not (left_cwes & right_cwes):
        return False
    if left.tool.casefold() == right.tool.casefold():
        return left.rule_id == right.rule_id
    return True


def _finding_sort_key(finding: Finding) -> tuple[str, str, int, str, str, str]:
    location = _location_key(finding)
    service, path, line = location or (
        finding.service.strip().casefold(),
        "<unknown>",
        0,
    )
    return service, path, line, finding.primary_cwe or "", finding.tool, finding.rule_id


def _standalone_fingerprint(finding: Finding) -> str:
    """Create a unique stable ID when location/CWE grouping is unsafe."""

    material = [
        finding.fingerprint or "",
        _identity_text(finding.service.casefold()),
        _identity_text(finding.tool.casefold()),
        _identity_text(finding.rule_id),
        _identity_text(finding.message),
    ]
    encoded = json.dumps(material, ensure_ascii=False, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _group_fingerprint(
    first: Finding,
    grouped_findings: list[Finding],
    common_cwes: set[str],
) -> str:
    sink = first.sink
    if sink is None or not common_cwes:
        return _standalone_fingerprint(first)
    base = root_cause_fingerprint(
        first.service,
        sorted(common_cwes),
        sink.path,
        sink.line,
    )
    # Cross-tool corroboration keeps the scanner-neutral root-cause ID. A
    # same-tool group needs its rule as a discriminator because incompatible
    # rules may legitimately share a file, line, and CWE.
    tools = {finding.tool.casefold() for finding in grouped_findings}
    if len(tools) > 1:
        return base
    rules = json.dumps(
        sorted({_identity_text(finding.rule_id) for finding in grouped_findings}),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(f"{base}\0{rules}".encode()).hexdigest()


def _compatible_with_group(finding: Finding, members: list[Finding]) -> bool:
    """Require pairwise compatibility to prevent transitive CWE bridges."""

    return all(are_duplicates(finding, member) for member in members)


def _make_group(grouped_findings: list[Finding]) -> FindingGroup:
    grouped_findings.sort(key=_finding_sort_key)
    first = grouped_findings[0]
    sink = first.sink
    all_cwes = sorted({cwe for finding in grouped_findings for cwe in finding.cwes})
    common_cwes = set(grouped_findings[0].cwes)
    for finding in grouped_findings[1:]:
        common_cwes &= set(finding.cwes)
    fingerprint = _group_fingerprint(first, grouped_findings, common_cwes)
    severity = max(
        (finding.severity for finding in grouped_findings),
        key=lambda value: value.rank,
        default=Severity.UNKNOWN,
    )
    return FindingGroup(
        fingerprint=fingerprint,
        service=first.service,
        cwes=all_cwes,
        sink=sink,
        severity=severity,
        tools=sorted({finding.tool for finding in grouped_findings}),
        findings=grouped_findings,
    )


def _disambiguate_colliding_fingerprints(groups: list[FindingGroup]) -> None:
    collisions: dict[str, list[FindingGroup]] = defaultdict(list)
    for group in groups:
        collisions[group.fingerprint].append(group)
    for fingerprint, members in collisions.items():
        if len(members) < 2:
            continue
        for group in members:
            signature = json.dumps(
                sorted(
                    [_identity_text(item.tool.casefold()), _identity_text(item.rule_id)]
                    for item in group.findings
                ),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            group.fingerprint = "sha256:" + hashlib.sha256(
                json.dumps(
                    [fingerprint, signature],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()


def group_findings(findings: Iterable[Finding]) -> list[FindingGroup]:
    """Group only pairwise-compatible findings at the same concrete location."""

    buckets: dict[tuple[str, str, int] | None, list[Finding]] = defaultdict(list)
    for finding in sorted(findings, key=_finding_sort_key):
        buckets[_location_key(finding)].append(finding)

    grouped: list[list[Finding]] = []
    for location, candidates in buckets.items():
        if location is None:
            standalone: dict[str, list[Finding]] = defaultdict(list)
            for finding in candidates:
                standalone[_standalone_fingerprint(finding)].append(finding)
            grouped.extend(standalone.values())
            continue
        local_groups: list[list[Finding]] = []
        for finding in candidates:
            target = next(
                (
                    members
                    for members in local_groups
                    if _compatible_with_group(finding, members)
                ),
                None,
            )
            if target is None:
                local_groups.append([finding])
            else:
                target.append(finding)
        grouped.extend(local_groups)

    groups = [_make_group(members) for members in grouped]
    _disambiguate_colliding_fingerprints(groups)
    return sorted(
        groups,
        key=lambda group: (
            group.service.casefold(),
            group.sink.path if group.sink else "<unknown>",
            group.sink.line if group.sink else 0,
            group.fingerprint,
        ),
    )


def group_by_root_cause(findings: Iterable[Finding]) -> list[FindingGroup]:
    """Readable alias for :func:`group_findings`."""

    return group_findings(findings)


def cross_tool_groups(findings: Iterable[Finding]) -> list[FindingGroup]:
    """Return only groups corroborated by at least two scanners."""

    return [group for group in group_findings(findings) if group.is_cross_tool]


__all__ = [
    "are_duplicates",
    "cross_tool_groups",
    "group_by_root_cause",
    "group_findings",
]
