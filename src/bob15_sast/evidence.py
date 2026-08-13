"""Build minimal, private evidence bundles for human and model review."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from .jsonio import write_json
from .redaction import redact_text

_SAFE_EVIDENCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")
_SAFE_FINDING_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_MAX_COORDINATE = 2_147_483_647
_MAX_RAW_FINDINGS = 100
_MAX_LOCATIONS = 20
_MAX_CODE_FLOWS = 5
_MAX_FLOW_STEPS = 20
_MAX_EVIDENCE_ITEMS = 100


def evidence_id(kind: str, content: str) -> str:
    digest = hashlib.sha256(f"{kind}\0{content}".encode()).hexdigest()[:16]
    return f"EV-{digest}"


def safe_source_path(source_root: Path, repository_path: str) -> Path:
    """Resolve a repository-relative path and reject traversal or symlink escapes."""

    pure = PurePosixPath(repository_path.replace("\\", "/"))
    if not pure.parts:
        raise ValueError("source path must name a repository file")
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe repository path: {repository_path}")
    root = source_root.resolve()
    candidate = (root / Path(*pure.parts)).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError(f"path escapes source root: {repository_path}")
    return candidate


def _open_source_descriptor(source_root: Path, repository_path: str) -> int:
    """Open a source file without following repository-controlled symlinks."""

    path = safe_source_path(source_root, repository_path)
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if os.name != "posix" or not no_follow:
        return os.open(path, file_flags)

    pure = PurePosixPath(repository_path.replace("\\", "/"))
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_descriptor = os.open(source_root.resolve(), directory_flags)
    try:
        for component in pure.parts[:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return os.open(
            pure.parts[-1],
            file_flags | no_follow,
            dir_fd=directory_descriptor,
        )
    finally:
        os.close(directory_descriptor)


def source_excerpt(
    source_root: Path,
    repository_path: str,
    start_line: int,
    *,
    context: int = 12,
    max_bytes: int = 64_000,
) -> tuple[str, int, int]:
    descriptor = _open_source_descriptor(source_root, repository_path)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"source path is not a regular file: {repository_path}")
        if metadata.st_size > max_bytes:
            raise ValueError(
                f"source file exceeds {max_bytes} bytes: {repository_path}"
            )

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16_384))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise ValueError(
                f"source file exceeds {max_bytes} bytes: {repository_path}"
            )
    finally:
        os.close(descriptor)

    lines = raw.decode("utf-8", errors="replace").splitlines()
    first = max(1, start_line - context)
    last = min(len(lines), start_line + context)
    numbered = "\n".join(
        f"{number:>6}: {lines[number - 1]}" for number in range(first, last + 1)
    )
    return redact_text(numbered), first, last


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:  # pragma: no cover - permissions differ on Windows
        pass


def _private_file(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - permissions differ on Windows
        pass


def _markdown_fence(content: str) -> str:
    longest = max(
        (len(match.group(0)) for match in re.finditer(r"`+", content)),
        default=0,
    )
    return "`" * max(4, longest + 1)


def _bounded_redacted_string(value: Any, limit: int) -> str | None:
    """Return a bounded string without ever coercing a nested value to text."""

    if not isinstance(value, str):
        return None
    # Bound redaction work as well as the serialized result.  The multiplier lets
    # common token patterns that cross the final output boundary remain detectable.
    return redact_text(value[: limit * 4])[:limit]


def _bounded_string_list(value: Any, *, count: int, length: int) -> list[str]:
    return [
        cleaned
        for item in _bounded_list(value, count)
        if (cleaned := _bounded_redacted_string(item, length)) is not None
    ]


def _bounded_integer(value: Any) -> int | None:
    if type(value) is not int or not 0 <= value <= _MAX_COORDINATE:
        return None
    return value


def _validate_identifier(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"finding {field} must be a string")
    if _SAFE_FINDING_ID.fullmatch(value) is None:
        raise ValueError(
            f"finding {field} must be a path-safe identifier of at most 200 characters"
        )
    return value


def _allow_location(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    path = _bounded_redacted_string(value.get("path"), 2_000)
    if path is None:
        return None

    clean: dict[str, Any] = {"path": path}
    for key in ("line", "column", "end_line", "end_column"):
        if key not in value:
            continue
        coordinate = value[key]
        if coordinate is None:
            clean[key] = None
        elif (bounded := _bounded_integer(coordinate)) is not None:
            clean[key] = bounded
    return clean


def _bounded_list(value: Any, limit: int) -> list[Any]:
    if not isinstance(value, list):
        return []
    return value[:limit]


def _allow_raw_finding(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    clean: dict[str, Any] = {}
    if "fingerprint" in value:
        clean["fingerprint"] = _validate_identifier(
            value["fingerprint"], field="fingerprint"
        )
    for key, limit in (
        ("service", 500),
        ("tool", 500),
        ("rule_id", 1_000),
        ("severity", 100),
    ):
        if (text := _bounded_redacted_string(value.get(key), limit)) is not None:
            clean[key] = text
    clean["cwes"] = _bounded_string_list(
        value.get("cwes"), count=100, length=100
    )
    clean["locations"] = [
        location
        for item in _bounded_list(value.get("locations"), _MAX_LOCATIONS)
        if (location := _allow_location(item)) is not None
    ]
    flows: list[dict[str, Any]] = []
    for flow in _bounded_list(value.get("code_flows"), _MAX_CODE_FLOWS):
        if not isinstance(flow, dict):
            continue
        steps: list[dict[str, Any]] = []
        for step in _bounded_list(flow.get("steps"), _MAX_FLOW_STEPS):
            if not isinstance(step, dict):
                continue
            location = _allow_location(step.get("location"))
            if location is None:
                continue
            clean_step: dict[str, Any] = {
                "location": location,
                "kinds": _bounded_string_list(
                    step.get("kinds"), count=10, length=200
                ),
            }
            execution_order = step.get("execution_order")
            if execution_order is None:
                clean_step["execution_order"] = None
            elif (bounded := _bounded_integer(execution_order)) is not None:
                clean_step["execution_order"] = bounded
            steps.append(clean_step)
        flows.append({"steps": steps})
    clean["code_flows"] = flows
    if type(value.get("suppressed")) is bool:
        clean["suppressed"] = value["suppressed"]
    baseline_state = value.get("baseline_state")
    if baseline_state is None and "baseline_state" in value:
        clean["baseline_state"] = None
    elif (text := _bounded_redacted_string(baseline_state, 100)) is not None:
        clean["baseline_state"] = text
    return clean


def _allow_finding(value: dict[str, Any]) -> dict[str, Any]:
    """Keep only the documented public finding/group schema."""

    clean: dict[str, Any] = {}
    for key in ("id", "fingerprint"):
        if key in value:
            clean[key] = _validate_identifier(value[key], field=key)
    for key, limit in (
        ("service", 500),
        ("severity", 100),
        ("status", 100),
    ):
        if (text := _bounded_redacted_string(value.get(key), limit)) is not None:
            clean[key] = text
    clean["tools"] = _bounded_string_list(
        value.get("tools"), count=32, length=500
    )
    clean["rule_ids"] = _bounded_string_list(
        value.get("rule_ids"), count=256, length=1_000
    )
    clean["cwes"] = _bounded_string_list(
        value.get("cwes"), count=100, length=100
    )
    clean["location"] = _allow_location(value.get("location"))
    if type(value.get("requires_human_confirmation")) is bool:
        clean["requires_human_confirmation"] = value[
            "requires_human_confirmation"
        ]
    clean["findings"] = [
        finding
        for item in _bounded_list(value.get("findings"), _MAX_RAW_FINDINGS)
        if (finding := _allow_raw_finding(item)) is not None
    ]
    return clean


def _allow_evidence(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise TypeError("evidence entries must be objects")
    item_id = item.get("evidence_id", item.get("id"))
    if not isinstance(item_id, str) or _SAFE_EVIDENCE_ID.fullmatch(item_id) is None:
        raise ValueError("evidence id must be a safe single-line identifier")
    fields: dict[str, str] = {}
    for key, limit in (("kind", 100), ("location", 2_000), ("content", 24_000)):
        value = item.get(key)
        if not isinstance(value, str):
            raise TypeError(f"evidence {key} must be a string")
        fields[key] = redact_text(value[: limit * 4])[:limit]
    return {
        "evidence_id": item_id,
        **fields,
    }


def _finding_identifier(finding: dict[str, Any]) -> str:
    if "id" in finding:
        return _validate_identifier(finding["id"], field="id")
    if "fingerprint" in finding:
        return _validate_identifier(finding["fingerprint"], field="fingerprint")
    raise ValueError("finding requires a safe id or fingerprint")


def _bundle_directory_name(finding_id: str) -> str:
    slug = finding_id.replace(":", "-")[:180]
    digest = hashlib.sha256(finding_id.encode()).hexdigest()[:16]
    return f"{slug}-{digest}"


def write_bundle(
    output_root: Path,
    finding: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> Path:
    """Write one allowlisted finding and its already-collected evidence manifest."""

    if not isinstance(finding, dict):
        raise TypeError("finding must be an object")
    finding_id = _finding_identifier(finding)
    clean_finding = _allow_finding(finding)
    clean_evidence = [
        _allow_evidence(item)
        for item in _bounded_list(evidence, _MAX_EVIDENCE_ITEMS)
    ]
    safe_id = _bundle_directory_name(finding_id)
    bundle = output_root / safe_id
    _private_directory(output_root)
    _private_directory(bundle)

    finding_path = bundle / "finding.json"
    evidence_path = bundle / "evidence.json"
    write_json(finding_path, clean_finding)
    write_json(evidence_path, clean_evidence)
    _private_file(finding_path)
    _private_file(evidence_path)

    trace = [
        f"# Evidence trace: {finding_id}",
        "",
        "AI assessments are hypotheses until human review.",
        "",
    ]
    for item in clean_evidence:
        item_id = item["evidence_id"]
        content = item["content"]
        location = item["location"]
        location = location.replace("\r", " ").replace("\n", " ")
        fence = _markdown_fence(content)
        trace.extend(
            [
                f"## {item_id}",
                "",
                f"Location: `{location.replace('`', 'ˋ')}`",
                "",
                f"{fence}text",
                content,
                fence,
                "",
            ]
        )
    trace_path = bundle / "trace.md"
    trace_path.write_text("\n".join(trace), encoding="utf-8")
    _private_file(trace_path)
    return bundle


def build_bundle(
    output_root: Path,
    finding: dict[str, Any],
    *,
    source_root: Path | None = None,
) -> Path:
    """Compatibility helper that collects at most one redacted source excerpt."""

    evidence: list[dict[str, Any]] = []
    location = finding.get("location")
    if source_root is not None and isinstance(location, dict):
        repository_path = location.get("path")
        start_line = location.get("start_line", location.get("line"))
        if (
            isinstance(repository_path, str)
            and len(repository_path) <= 2_000
            and type(start_line) is int
            and 0 <= start_line <= _MAX_COORDINATE
        ):
            try:
                excerpt, first, last = source_excerpt(
                    source_root, repository_path, start_line
                )
            except (OSError, ValueError):
                pass
            else:
                content = excerpt[:24_000]
                location_text = f"{repository_path}:{first}-{last}"
                evidence.append(
                    {
                        "id": evidence_id("source", f"{location_text}\0{content}"),
                        "kind": "source",
                        "location": location_text,
                        "content": content,
                    }
                )
    return write_bundle(output_root, finding, evidence)


__all__ = [
    "build_bundle",
    "evidence_id",
    "safe_source_path",
    "source_excerpt",
    "write_bundle",
]
