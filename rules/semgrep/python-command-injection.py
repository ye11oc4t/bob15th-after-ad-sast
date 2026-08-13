"""Semgrep rule tests for bob15.python.command-injection."""

import os
import subprocess


def vulnerable_os_system() -> int:
    value = input("synthetic value: ")
    # ruleid: bob15.python.command-injection
    return os.system("printf '%s\\n' " + value)


def vulnerable_subprocess() -> subprocess.CompletedProcess[bytes]:
    value = input("synthetic value: ")
    # ruleid: bob15.python.command-injection
    return subprocess.run("printf '%s\\n' " + value, shell=True, check=False)


def safe_argument_vector() -> subprocess.CompletedProcess[str]:
    value = input("synthetic value: ")
    # ok: bob15.python.command-injection
    return subprocess.run(["printf", "%s\\n", value], shell=False, check=True, text=True)
