"""Build minimal, private evidence bundles for human and model review."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .jsonio import write_json
from .redaction import redact, redact_text


def evidence_id(kind: str, content: str) -> str:
    digest = hashlib.sha256(f"{kind}\0{content}".encode()).hexdigest()[:16]
    return f"EV-{digest}"


def safe_source_path(source_root: Path, repository_path: str) -> Path:
    """Resolve a repository-relative path and reject traversal or symlink escapes."""

    pure = PurePosixPath(repository_path.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe repository path: {repository_path}")
    root = source_root.resolve()
    candidate = (root / Path(*pure.parts)).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError(f"path escapes source root: {repository_path}")
    return candidate


def source_excerpt(
    source_root: Path,
    repository_path: str,
    start_line: int,
    *,
    context: int = 12,
    max_bytes: int = 64_000,
) -> tuple[str, int, int]:
    path = safe_source_path(source_root, repository_path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"source file exceeds {max_bytes} bytes: {repository_path}")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
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


def write_bundle(
    output_root: Path,
    finding: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> Path:
    """Write one allowlisted finding and its already-collected evidence manifest."""

    finding_id = str(finding.get("id") or finding.get("fingerprint") or "unknown")
    safe_id = "".join(
        character
        for character in finding_id
        if character.isascii() and (character.isalnum() or character in "-_")
    )
    if not safe_id:
        raise ValueError("finding requires a safe id or fingerprint")
    bundle = output_root / safe_id
    _private_directory(output_root)
    _private_directory(bundle)

    finding_path = bundle / "finding.json"
    evidence_path = bundle / "evidence.json"
    write_json(finding_path, redact(finding))
    write_json(evidence_path, redact(evidence))
    _private_file(finding_path)
    _private_file(evidence_path)

    trace = [
        f"# Evidence trace: {safe_id}",
        "",
        "AI assessments are hypotheses until human review.",
        "",
    ]
    for item in evidence:
        item_id = item.get("id") or item.get("evidence_id")
        if not isinstance(item_id, str) or not item_id:
            raise ValueError("every evidence item requires an id")
        content = redact_text(str(item.get("content", "")))
        location = redact_text(str(item.get("location") or "<none>"))
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
        if isinstance(repository_path, str) and isinstance(start_line, int):
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
