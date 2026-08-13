"""SARIF 2.1 normalization for Semgrep, CodeQL and Trivy output.

The three scanners all emit valid SARIF but use different fields for severity,
CWE metadata and data-flow traces.  This module accepts that variation and emits
the small canonical model in :mod:`bob15_sast.models`.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, TextIO
from urllib.parse import unquote, urljoin, urlparse

from .models import CodeFlow, Finding, Location, Severity, TraceStep, normalize_cwe

_SEVERITY_WORDS = re.compile(
    r"(?i)(?:^|[^a-z])(critical|high|medium|moderate|low|info(?:rmational)?|unknown)(?:$|[^a-z])"
)

# These limits are intentionally generous for normal scanner output while still
# bounding work when a malformed or untrusted SARIF file is ingested.  Limits are
# rejected explicitly instead of silently dropping security findings.
MAX_SARIF_BYTES = 50 * 1024 * 1024
MAX_RUNS = 1_000
MAX_RULES = 100_000
MAX_RESULTS = 10_000
MAX_CODE_FLOWS = 10_000
MAX_THREAD_FLOWS_PER_CODE_FLOW = 1_000
MAX_TRACE_STEPS = 10_000
MAX_LOCATIONS_PER_RESULT = 10_000
MAX_RESULT_LOCATIONS = 20_000
MAX_SUPPRESSIONS_PER_RESULT = 10_000
MAX_URI_BASE_DEPTH = 64
MAX_METADATA_NODES = 2_000_000

_UNSAFE_PATH = "<unsafe-path>"
_EXTERNAL_PATH = "<external-path>"
_MAX_URI_DECODE_PASSES = 8
_EMPTY_RULE: Mapping[str, Any] = {}


class SarifParseError(ValueError):
    """Raised when an input cannot be interpreted as a SARIF document."""


@dataclass
class _ParseBudget:
    results: int = 0
    code_flows: int = 0
    trace_steps: int = 0
    result_locations: int = 0
    metadata_nodes: int = 0

    def consume(self, field: str, amount: int, limit: int) -> None:
        updated = getattr(self, field) + amount
        if updated > limit:
            label = field.replace("_", " ")
            raise SarifParseError(f"SARIF exceeds the {label} limit ({limit})")
        setattr(self, field, updated)


def _message_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        for key in ("text", "markdown", "id"):
            if value.get(key) is not None:
                return str(value[key])
    return "" if value is None else str(value)


def _walk_strings(value: Any, *, budget: _ParseBudget | None = None) -> Iterable[str]:
    """Yield strings from JSON-like metadata without recursive traversal."""

    active_budget = budget or _ParseBudget()
    stack = [value]
    visited_containers: set[int] = set()
    while stack:
        child = stack.pop()
        active_budget.consume("metadata_nodes", 1, MAX_METADATA_NODES)
        if isinstance(child, str):
            yield child
            continue
        if isinstance(child, Mapping):
            identity = id(child)
            if identity in visited_containers:
                continue
            visited_containers.add(identity)
            stack.extend(child.values())
        elif isinstance(child, (list, tuple, set, frozenset)):
            identity = id(child)
            if identity in visited_containers:
                continue
            visited_containers.add(identity)
            stack.extend(child)


def extract_cwes(
    *values: Any,
    _budget: _ParseBudget | None = None,
) -> list[str]:
    """Extract and canonicalize CWE identifiers from arbitrary SARIF metadata."""

    budget = _budget or _ParseBudget()
    found: set[str] = set()
    for value in values:
        for text in _walk_strings(value, budget=budget):
            # A string can contain more than one identifier, so scan each match
            # rather than relying on normalize_cwe's first-match behavior.
            for match in re.finditer(
                r"(?i)(?<![A-Z0-9])CWE(?:[-_/ ]?)(\d{1,5})(?!\d)", text
            ):
                canonical = normalize_cwe(f"CWE-{match.group(1)}")
                if canonical:
                    found.add(canonical)
    return sorted(found, key=lambda cwe: int(cwe.split("-", 1)[1]))


def _severity_from_number(value: Any) -> Severity | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= score <= 10:
        return None
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _severity_from_text(value: Any) -> Severity | None:
    if value is None:
        return None
    numeric = _severity_from_number(value)
    if numeric is not None:
        return numeric
    match = _SEVERITY_WORDS.search(str(value).strip())
    if not match:
        return None
    name = match.group(1).casefold()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
        "unknown": Severity.UNKNOWN,
    }[name]


def _mapping_value(mapping: Mapping[str, Any], dotted_key: str) -> Any:
    # SARIF producers use both the literal ``problem.severity`` key and nested
    # objects.  Supporting both keeps the adapter scanner-neutral.
    if dotted_key in mapping:
        return mapping[dotted_key]
    cursor: Any = mapping
    for part in dotted_key.split("."):
        if not isinstance(cursor, Mapping) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


_NUMERIC_SEVERITY_KEYS = (
    "security-severity",
    "security_severity",
    "cvss",
    "cvssScore",
)
_TEXT_SEVERITY_KEYS = ("severity", "impact", "problem.severity")


def _level_severity(value: Any) -> Severity:
    return {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "note": Severity.LOW,
        "none": Severity.INFO,
    }.get(str(value).casefold(), Severity.UNKNOWN)


def _first_property_severity(
    properties: Mapping[str, Any],
    keys: tuple[str, ...],
    *,
    numeric: bool,
) -> Severity | None:
    converter = _severity_from_number if numeric else _severity_from_text
    for key in keys:
        severity = converter(_mapping_value(properties, key))
        if severity is not None:
            return severity
    return None


@dataclass(frozen=True)
class _RuleMetadata:
    cwes: tuple[str, ...]
    properties: dict[str, Any]
    numeric_severity: Severity | None
    text_severity: Severity | None
    tag_severity: Severity | None
    default_level_severity: Severity


def _build_rule_metadata(
    descriptor: Mapping[str, Any], budget: _ParseBudget
) -> _RuleMetadata:
    raw_properties = descriptor.get("properties") or {}
    rule_properties = (
        dict(raw_properties) if isinstance(raw_properties, Mapping) else {}
    )
    tag_severity = None
    for tag in _walk_strings(rule_properties.get("tags", []), budget=budget):
        candidate = _severity_from_text(tag)
        if candidate is not None and candidate is not Severity.UNKNOWN:
            tag_severity = candidate
            break

    default_configuration = descriptor.get("defaultConfiguration") or {}
    default_level = (
        default_configuration.get("level")
        if isinstance(default_configuration, Mapping)
        else None
    )
    return _RuleMetadata(
        cwes=tuple(
            extract_cwes(
                rule_properties,
                descriptor.get("help"),
                descriptor.get("shortDescription"),
                descriptor.get("fullDescription"),
                _budget=budget,
            )
        ),
        properties=rule_properties,
        numeric_severity=_first_property_severity(
            rule_properties, _NUMERIC_SEVERITY_KEYS, numeric=True
        ),
        text_severity=_first_property_severity(
            rule_properties, _TEXT_SEVERITY_KEYS, numeric=False
        ),
        tag_severity=tag_severity,
        default_level_severity=_level_severity(default_level),
    )


def _normalize_result_severity(
    result: Mapping[str, Any],
    rule_metadata: _RuleMetadata,
) -> Severity:
    raw_result_properties = result.get("properties") or {}
    result_properties = (
        raw_result_properties if isinstance(raw_result_properties, Mapping) else {}
    )

    # Preserve the precedence of the public normalizer: numeric scanner metadata
    # wins over textual impact, and result metadata wins within each category.
    result_numeric = _first_property_severity(
        result_properties, _NUMERIC_SEVERITY_KEYS, numeric=True
    )
    if result_numeric is not None:
        return result_numeric
    if rule_metadata.numeric_severity is not None:
        return rule_metadata.numeric_severity

    result_text = _first_property_severity(
        result_properties, _TEXT_SEVERITY_KEYS, numeric=False
    )
    if result_text is not None:
        return result_text
    if rule_metadata.text_severity is not None:
        return rule_metadata.text_severity
    if rule_metadata.tag_severity is not None:
        return rule_metadata.tag_severity

    if result.get("level") is not None:
        return _level_severity(result.get("level"))
    return rule_metadata.default_level_severity


def normalize_severity(
    result: Mapping[str, Any], rule: Mapping[str, Any] | None = None
) -> Severity:
    """Normalize SARIF and scanner-specific severity metadata."""

    budget = _ParseBudget()
    metadata = _build_rule_metadata(rule or {}, budget)
    return _normalize_result_severity(result, metadata)


def _base_uri(base_id: str | None, bases: Mapping[str, Any]) -> str | None:
    """Resolve a URI base chain iteratively, rejecting cycles and excess depth."""

    if not base_id:
        return None
    current = str(base_id)
    seen: set[str] = set()
    chain: list[str] = []
    for _ in range(MAX_URI_BASE_DEPTH):
        if current in seen or current not in bases:
            return None
        seen.add(current)
        entry = bases[current]
        if not isinstance(entry, Mapping):
            return None
        uri = str(entry.get("uri") or "")
        if _contains_parent_segment(uri):
            return _UNSAFE_PATH
        chain.append(uri)
        parent = entry.get("uriBaseId")
        if not parent:
            break
        current = str(parent)
    else:
        return None

    resolved = ""
    for uri in reversed(chain):
        resolved = urljoin(resolved.rstrip("/") + "/", uri) if resolved else uri
    return resolved


def _artifact_location_with_identity(
    artifact_location: Mapping[str, Any],
    run: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    """Return an artifact location with a concrete URI identity, if available."""

    uri = artifact_location.get("uri")
    if isinstance(uri, str) and uri.strip():
        return artifact_location

    if isinstance(artifact_location.get("index"), int) and not isinstance(
        artifact_location.get("index"), bool
    ):
        artifacts = run.get("artifacts") or []
        index = artifact_location["index"]
        if isinstance(artifacts, list) and 0 <= index < len(artifacts):
            artifact = artifacts[index]
            if isinstance(artifact, Mapping):
                stored_location = artifact.get("location") or {}
                if isinstance(stored_location, Mapping):
                    stored_uri = stored_location.get("uri")
                    if isinstance(stored_uri, str) and stored_uri.strip():
                        # Explicit base/index values on the physical location win,
                        # while the artifact-table URI supplies its identity.
                        resolved = {**stored_location, **artifact_location}
                        resolved["uri"] = stored_uri
                        return resolved
    return None


def _resolve_artifact_uri(
    artifact_location: Mapping[str, Any],
    run: Mapping[str, Any],
) -> str | None:
    resolved_location = _artifact_location_with_identity(artifact_location, run)
    if resolved_location is None:
        return None
    uri = str(resolved_location["uri"])
    if _contains_parent_segment(uri):
        return _UNSAFE_PATH
    bases = run.get("originalUriBaseIds") or {}
    if isinstance(bases, Mapping):
        base = _base_uri(resolved_location.get("uriBaseId"), bases)
        if base == _UNSAFE_PATH:
            return _UNSAFE_PATH
        if base:
            return urljoin(base.rstrip("/") + "/", uri)
    return uri


def _contains_parent_segment(uri: str) -> bool:
    raw = _decode_uri(str(uri)).replace("\\", "/")
    if raw == _UNSAFE_PATH:
        return True
    return ".." in PurePosixPath(urlparse(raw).path or raw).parts


def _decode_uri(value: str) -> str:
    """Decode nested percent escapes with a strict work bound."""

    decoded = value
    for _ in range(_MAX_URI_DECODE_PASSES):
        next_value = unquote(decoded)
        if next_value == decoded:
            return decoded
        decoded = next_value
    return decoded if unquote(decoded) == decoded else _UNSAFE_PATH


def normalize_artifact_path(
    uri: str,
    *,
    service: str,
    repo_root: str | os.PathLike[str] | None = None,
) -> str:
    """Turn an artifact URI into a stable service-relative POSIX path."""

    raw = _decode_uri(str(uri)).replace("\\", "/")
    if raw == _UNSAFE_PATH:
        return _UNSAFE_PATH
    parsed = urlparse(raw)
    if parsed.scheme == "file":
        raw = parsed.path
        if parsed.netloc and parsed.netloc not in ("", "localhost"):
            raw = f"/{parsed.netloc}{raw}"
    elif parsed.scheme and len(parsed.scheme) > 1:
        # Non-file schemes are rare in scan results.  Path is still the stable
        # portion; host/query/fragment must not influence a root-cause ID.
        raw = parsed.path or raw

    raw = raw.replace("\\", "/")
    if "\x00" in raw:
        return _UNSAFE_PATH
    root = str(repo_root).replace("\\", "/").rstrip("/") if repo_root else None
    if root and (raw == root or raw.startswith(root + "/")):
        raw = raw[len(root) :].lstrip("/")

    was_absolute = raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) is not None
    raw_parts = PurePosixPath(raw).parts
    if ".." in raw_parts:
        return _UNSAFE_PATH
    parts = [part for part in raw_parts if part not in ("/", ".")]
    service_key = service.casefold()
    # SARIF created inside a container often contains an ephemeral absolute
    # prefix.  Strip through the service root when it can be identified.  For a
    # relative path, only strip a leading service directory. Looking deeper can
    # incorrectly remove a legitimate package/directory named after a service.
    service_indexes = (
        [i for i, part in enumerate(parts) if part.casefold() == service_key]
        if was_absolute
        else ([0] if parts and parts[0].casefold() == service_key else [])
    )
    if service_indexes:
        parts = parts[service_indexes[-1] + 1 :]
    elif was_absolute:
        return _EXTERNAL_PATH

    return "/".join(parts) or "<unknown>"


def _safe_nonnegative_int(value: Any, *, default: int | None = None) -> int | None:
    """Return a non-negative integer without accepting booleans or fractions."""

    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value if value >= 0 else default
    if isinstance(value, str):
        stripped = value.strip()
        # The bound also avoids Python's large-integer conversion guard becoming
        # an input-dependent exception.
        if stripped.isdigit() and len(stripped) <= 18:
            try:
                return int(stripped)
            except ValueError:
                return default
    return default


def _safe_line_number(value: Any) -> int:
    parsed = _safe_nonnegative_int(value)
    return parsed if parsed is not None else 1


def _array(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _parse_location(
    location: Mapping[str, Any],
    *,
    run: Mapping[str, Any],
    service: str,
    repo_root: str | os.PathLike[str] | None,
) -> Location | None:
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, Mapping):
        return None
    region = physical.get("region") or {}
    if not isinstance(region, Mapping):
        region = {}
    original_uri = _resolve_artifact_uri(artifact, run)
    if original_uri is None:
        return None
    normalized_path = normalize_artifact_path(
        original_uri, service=service, repo_root=repo_root
    )
    public_uri = (
        normalized_path
        if normalized_path in {_EXTERNAL_PATH, _UNSAFE_PATH}
        else original_uri
    )
    snippet = region.get("snippet")
    return Location(
        path=normalized_path,
        line=_safe_line_number(region.get("startLine")),
        column=_safe_nonnegative_int(region.get("startColumn")),
        end_line=_safe_nonnegative_int(region.get("endLine")),
        end_column=_safe_nonnegative_int(region.get("endColumn")),
        snippet=_message_text(snippet) or None,
        original_uri=public_uri,
    )


def _parse_code_flows(
    result: Mapping[str, Any],
    *,
    run: Mapping[str, Any],
    service: str,
    repo_root: str | os.PathLike[str] | None,
    budget: _ParseBudget,
) -> list[CodeFlow]:
    normalized: list[CodeFlow] = []
    raw_code_flows = _array(result.get("codeFlows"))
    budget.consume("code_flows", len(raw_code_flows), MAX_CODE_FLOWS)
    for code_flow in raw_code_flows:
        if not isinstance(code_flow, Mapping):
            continue
        flow_message = _message_text(code_flow.get("message")) or None
        thread_flows = _array(code_flow.get("threadFlows"))
        if len(thread_flows) > MAX_THREAD_FLOWS_PER_CODE_FLOW:
            raise SarifParseError(
                "SARIF exceeds the thread flows per code flow limit "
                f"({MAX_THREAD_FLOWS_PER_CODE_FLOW})"
            )
        for thread_flow in thread_flows:
            if not isinstance(thread_flow, Mapping):
                continue
            steps: list[TraceStep] = []
            raw_steps = _array(thread_flow.get("locations"))
            budget.consume("trace_steps", len(raw_steps), MAX_TRACE_STEPS)
            for item in raw_steps:
                if not isinstance(item, Mapping):
                    continue
                sarif_location = item.get("location") or {}
                if not isinstance(sarif_location, Mapping):
                    continue
                parsed = _parse_location(
                    sarif_location,
                    run=run,
                    service=service,
                    repo_root=repo_root,
                )
                if parsed is None:
                    continue
                raw_kinds = item.get("kinds") or []
                kinds = [raw_kinds] if isinstance(raw_kinds, str) else _array(raw_kinds)
                steps.append(
                    TraceStep(
                        location=parsed,
                        message=_message_text(sarif_location.get("message")) or None,
                        execution_order=_safe_nonnegative_int(item.get("executionOrder")),
                        nesting_level=_safe_nonnegative_int(item.get("nestingLevel")),
                        kinds=[str(kind) for kind in kinds],
                    )
                )
            if steps:
                normalized.append(
                    CodeFlow(
                        steps=steps,
                        message=_message_text(thread_flow.get("message"))
                        or flow_message,
                    )
                )
    return normalized


def _rules_for_run(
    run: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], list[Mapping[str, Any]]]:
    tool = run.get("tool") or {}
    components: list[Mapping[str, Any]] = []
    if isinstance(tool, Mapping):
        driver = tool.get("driver") or {}
        if isinstance(driver, Mapping):
            components.append(driver)
        components.extend(
            component
            for component in tool.get("extensions") or []
            if isinstance(component, Mapping)
        )
    indexed: list[Mapping[str, Any]] = []
    by_id: dict[str, Mapping[str, Any]] = {}
    for component in components:
        descriptors = _array(component.get("rules"))
        if len(indexed) + len(descriptors) > MAX_RULES:
            raise SarifParseError(f"SARIF exceeds the rules limit ({MAX_RULES})")
        for descriptor in descriptors:
            if not isinstance(descriptor, Mapping):
                continue
            indexed.append(descriptor)
            if descriptor.get("id") is not None:
                by_id[str(descriptor["id"])] = descriptor
    return by_id, indexed


def _rule_for_result(
    result: Mapping[str, Any],
    by_id: Mapping[str, Mapping[str, Any]],
    indexed: list[Mapping[str, Any]],
) -> Mapping[str, Any]:
    rule_id = result.get("ruleId")
    if rule_id is not None and str(rule_id) in by_id:
        return by_id[str(rule_id)]
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(indexed):
        return indexed[index]
    embedded = result.get("rule")
    return embedded if isinstance(embedded, Mapping) else _EMPTY_RULE


def _add_result_state_properties(
    result: Mapping[str, Any], properties: dict[str, Any]
) -> None:
    """Expose SARIF lifecycle state without hiding auditable results."""

    raw_suppressions = result.get("suppressions")
    suppressions = _array(raw_suppressions)
    if len(suppressions) > MAX_SUPPRESSIONS_PER_RESULT:
        raise SarifParseError(
            "SARIF exceeds the suppressions per result limit "
            f"({MAX_SUPPRESSIONS_PER_RESULT})"
        )
    if raw_suppressions is not None:
        properties["sarif_suppressions"] = raw_suppressions
    has_accepted_suppression = any(
        isinstance(suppression, Mapping)
        and str(suppression.get("status") or "").casefold() == "accepted"
        for suppression in suppressions
    )
    properties["sarif_has_accepted_suppression"] = has_accepted_suppression

    raw_baseline_state = result.get("baselineState")
    baseline_state = str(raw_baseline_state or "").casefold()
    valid_baseline_states = {"new", "unchanged", "updated", "absent"}
    if raw_baseline_state is not None:
        properties["sarif_baseline_state_raw"] = raw_baseline_state
        properties["sarif_baseline_state"] = (
            baseline_state if baseline_state in valid_baseline_states else "unknown"
        )
    properties["sarif_is_active"] = (
        baseline_state != "absent" and not has_accepted_suppression
    )


def parse_sarif(
    document: Mapping[str, Any],
    *,
    service: str,
    repo_root: str | os.PathLike[str] | None = None,
) -> list[Finding]:
    """Normalize every result in a decoded SARIF document."""

    if not isinstance(document, Mapping):
        raise SarifParseError("SARIF root must be an object")
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise SarifParseError("SARIF root must contain a runs array")
    if len(runs) > MAX_RUNS:
        raise SarifParseError(f"SARIF exceeds the runs limit ({MAX_RUNS})")

    findings: list[Finding] = []
    budget = _ParseBudget()
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        tool = run.get("tool") or {}
        driver = tool.get("driver") or {} if isinstance(tool, Mapping) else {}
        tool_name = (
            str(driver.get("name") or "unknown")
            if isinstance(driver, Mapping)
            else "unknown"
        )
        by_id, indexed = _rules_for_run(run)
        rule_metadata_cache: dict[int, tuple[Mapping[str, Any], _RuleMetadata]] = {}

        raw_results = _array(run.get("results"))
        budget.consume("results", len(raw_results), MAX_RESULTS)
        for result in raw_results:
            if not isinstance(result, Mapping):
                continue
            # SARIF may contain baseline/pass records that are not findings.
            if str(result.get("kind") or "fail").casefold() in {
                "pass",
                "notapplicable",
            }:
                continue
            rule = _rule_for_result(result, by_id, indexed)
            cache_key = id(rule)
            cached = rule_metadata_cache.get(cache_key)
            if cached is None or cached[0] is not rule:
                rule_metadata = _build_rule_metadata(rule, budget)
                rule_metadata_cache[cache_key] = (rule, rule_metadata)
            else:
                rule_metadata = cached[1]
            rule_id = str(result.get("ruleId") or rule.get("id") or "unknown-rule")
            raw_locations = _array(result.get("locations"))
            if len(raw_locations) > MAX_LOCATIONS_PER_RESULT:
                raise SarifParseError(
                    "SARIF exceeds the locations per result limit "
                    f"({MAX_LOCATIONS_PER_RESULT})"
                )
            budget.consume(
                "result_locations",
                len(raw_locations),
                MAX_RESULT_LOCATIONS,
            )
            locations = [
                parsed
                for raw in raw_locations
                if isinstance(raw, Mapping)
                and (
                    parsed := _parse_location(
                        raw,
                        run=run,
                        service=service,
                        repo_root=repo_root,
                    )
                )
                is not None
            ]
            code_flows = _parse_code_flows(
                result,
                run=run,
                service=service,
                repo_root=repo_root,
                budget=budget,
            )
            result_props = result.get("properties") or {}
            result_cwes = extract_cwes(
                result_props,
                result.get("message"),
                _budget=budget,
            )
            cwes = sorted(
                {*rule_metadata.cwes, *result_cwes},
                key=lambda cwe: int(cwe.split("-", 1)[1]),
            )
            properties = dict(result_props) if isinstance(result_props, Mapping) else {}
            properties["sarif_rule_properties"] = rule_metadata.properties
            if result.get("partialFingerprints") is not None:
                properties["sarif_partial_fingerprints"] = result["partialFingerprints"]
            _add_result_state_properties(result, properties)

            findings.append(
                Finding(
                    service=service,
                    tool=tool_name,
                    rule_id=rule_id,
                    rule_name=str(rule.get("name")) if rule.get("name") else None,
                    message=_message_text(result.get("message")),
                    severity=_normalize_result_severity(result, rule_metadata),
                    cwes=cwes,
                    locations=locations,
                    code_flows=code_flows,
                    properties=properties,
                )
            )
    return findings


def normalize_sarif(
    document: Mapping[str, Any],
    service: str,
    repo_root: str | os.PathLike[str] | None = None,
) -> list[Finding]:
    """Positional-friendly alias for :func:`parse_sarif`."""

    return parse_sarif(document, service=service, repo_root=repo_root)


def load_sarif(
    source: str | os.PathLike[str] | TextIO | BinaryIO,
    *,
    service: str,
    repo_root: str | os.PathLike[str] | None = None,
) -> list[Finding]:
    """Decode and normalize SARIF from a path or an open file object."""

    try:
        if hasattr(source, "read"):
            raw_document = source.read(MAX_SARIF_BYTES + 1)
        else:
            path = Path(source)
            if path.stat().st_size > MAX_SARIF_BYTES:
                raise SarifParseError(
                    f"SARIF exceeds the input size limit ({MAX_SARIF_BYTES} bytes)"
                )
            with path.open("rb") as handle:
                raw_document = handle.read(MAX_SARIF_BYTES + 1)

        if not isinstance(raw_document, (str, bytes, bytearray)):
            raise TypeError("SARIF stream must return text or bytes")
        encoded_size = (
            len(raw_document.encode("utf-8"))
            if isinstance(raw_document, str)
            else len(raw_document)
        )
        if encoded_size > MAX_SARIF_BYTES:
            raise SarifParseError(
                f"SARIF exceeds the input size limit ({MAX_SARIF_BYTES} bytes)"
            )
        document = json.loads(raw_document)
    except SarifParseError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, TypeError) as exc:
        raise SarifParseError(f"unable to read SARIF: {exc}") from exc
    return parse_sarif(document, service=service, repo_root=repo_root)


__all__ = [
    "SarifParseError",
    "extract_cwes",
    "load_sarif",
    "normalize_artifact_path",
    "normalize_sarif",
    "normalize_severity",
    "parse_sarif",
]
