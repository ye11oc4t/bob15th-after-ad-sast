"""Safe counterpart to the synthetic command-injection fixture."""

from __future__ import annotations

import re
import subprocess


_SAFE_TARGET = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


def run_diagnostic(user_value: str) -> subprocess.CompletedProcess[str]:
    """Validate the value and avoid shell interpretation."""

    if _SAFE_TARGET.fullmatch(user_value) is None:
        raise ValueError("target contains unsupported characters")

    return subprocess.run(
        ["printf", "checking %s\\n", user_value],
        check=True,
        shell=False,
        text=True,
    )
