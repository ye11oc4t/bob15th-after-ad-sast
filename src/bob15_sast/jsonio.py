"""Small, deterministic JSON I/O helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    """Read an object-valued JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return data


def write_json(path: Path, value: Any) -> None:
    """Atomically write stable, human-readable JSON."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    parent = parent.resolve()
    destination = parent / path.name
    if destination.exists() and destination.is_symlink():
        raise ValueError(f"refusing to replace symlink output: {destination}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
