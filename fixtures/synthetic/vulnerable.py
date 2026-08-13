"""Intentionally vulnerable synthetic fixture.

This file is never production code and is not copied from a BoB challenge.
The functions are not called on import.
"""

from __future__ import annotations

import os


def run_diagnostic(user_value: str) -> int:
    """Demonstrate CWE-78 by passing untrusted text to a shell."""

    return os.system("printf 'checking %s\\n' " + user_value)
