"""Redaction for evidence sent to an external model or written to reports."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "<REDACTED>"

_SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|flag|passwd|password|secret|token)",
    re.IGNORECASE,
)
_TEXT_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b(api[_-]?key|authorization|cookie|credential|flag|passwd|password|secret|token)"
        r"(\s*[:=]\s*)([^\s,;]{4,})"
    ),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"(?i)\bflag\{[^}\r\n]{1,256}\}"),
    re.compile(r"\b(?:gh[opusr]|github_pat)_[A-Za-z0-9_]{20,255}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
        r"[^\s/@:]+:[^\s/@]+@"
    ),
    re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
    ),
)


def redact_text(value: str) -> str:
    """Remove common credentials and challenge flags while preserving context."""
    redacted = _TEXT_PATTERNS[0].sub(f"Bearer {REDACTED}", value)
    redacted = _TEXT_PATTERNS[1].sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", redacted
    )
    for pattern in _TEXT_PATTERNS[2:6]:
        redacted = pattern.sub(REDACTED, redacted)
    redacted = _TEXT_PATTERNS[6].sub(
        lambda match: match.group(0).split("://", 1)[0] + "://" + REDACTED + "@",
        redacted,
    )
    redacted = _TEXT_PATTERNS[7].sub(REDACTED, redacted)
    return redacted


def redact(value: Any) -> Any:
    """Recursively redact a JSON-compatible object without changing its shape."""
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _SENSITIVE_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [redact(item) for item in value]
    return value
