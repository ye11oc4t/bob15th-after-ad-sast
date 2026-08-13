from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from bob15_sast.adapters import TrivyAdapter
from bob15_sast.safe_exec import (
    DEFAULT_MAX_OUTPUT_BYTES,
    CommandTimedOutError,
    UnsafeCommandError,
    run_command,
)

PYTHON = str(Path(sys.executable).resolve())


def test_rejects_shell_command_strings() -> None:
    with pytest.raises(UnsafeCommandError, match="argument sequence"):
        run_command("semgrep --version")


def test_rejects_executable_outside_allowlist() -> None:
    with pytest.raises(UnsafeCommandError, match="not allowlisted"):
        run_command([PYTHON, "--version"])


def test_does_not_inherit_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BOB15_TEST_SECRET", "must-not-leak")
    result = run_command(
        [
            PYTHON,
            "-c",
            "import os; print(os.environ.get('BOB15_TEST_SECRET', 'absent'))",
        ],
        allowed_executables=(PYTHON,),
    )
    assert result.succeeded
    assert result.stdout.strip() == "absent"


@pytest.mark.parametrize("name", ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"])
def test_rejects_process_injection_environment(name: str) -> None:
    with pytest.raises(UnsafeCommandError, match="environment variable"):
        run_command(
            [PYTHON, "-c", "pass"],
            allowed_executables=(PYTHON,),
            environment={name: "/untrusted/value"},
        )


def test_arguments_are_not_interpreted_by_a_shell(tmp_path: Path) -> None:
    marker = tmp_path / "shell-was-used"
    shell_text = f"$(touch {marker})"
    result = run_command(
        [PYTHON, "-c", "import sys; print(sys.argv[1])", shell_text],
        allowed_executables=(PYTHON,),
    )
    assert result.stdout.strip() == shell_text
    assert not marker.exists()


def test_enforces_timeout() -> None:
    with pytest.raises(CommandTimedOutError):
        run_command(
            [PYTHON, "-c", "import time; time.sleep(5)"],
            allowed_executables=(PYTHON,),
            timeout_seconds=0.05,
        )


@pytest.mark.skipif(os.name != "posix", reason="uses a POSIX detached descendant")
def test_timeout_is_not_masked_when_descendant_keeps_pipe_open() -> None:
    started = time.monotonic()
    with pytest.raises(CommandTimedOutError):
        run_command(
            [
                PYTHON,
                "-c",
                (
                    "import subprocess,sys,time;"
                    "subprocess.Popen([sys.executable,'-c',"
                    "'import time;time.sleep(1)'],start_new_session=True);"
                    "time.sleep(5)"
                ),
            ],
            allowed_executables=(PYTHON,),
            timeout_seconds=0.05,
        )
    assert time.monotonic() - started < 0.8


def test_caps_and_drains_stdout_and_stderr() -> None:
    cap = 4_096
    result = run_command(
        [
            PYTHON,
            "-c",
            (
                "import sys;"
                "sys.stdout.buffer.write(b'o' * (2 * 1024 * 1024));"
                "sys.stderr.buffer.write(b'e' * (2 * 1024 * 1024))"
            ),
        ],
        allowed_executables=(PYTHON,),
        timeout_seconds=5,
        max_output_bytes=cap,
    )
    assert result.succeeded
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True
    assert len(result.stdout.encode("utf-8")) <= cap
    assert len(result.stderr.encode("utf-8")) <= cap
    assert result.stdout.endswith("...[scanner output truncated]")
    assert result.stderr.endswith("...[scanner output truncated]")


def test_default_capture_policy_is_one_mebibyte() -> None:
    assert DEFAULT_MAX_OUTPUT_BYTES == 1024 * 1024


def test_trivy_does_not_scan_secrets_by_default() -> None:
    assert "secret" not in TrivyAdapter().scanners


@pytest.mark.skipif(os.name == "nt", reason="POSIX path policy assertion")
def test_relative_executable_paths_are_rejected() -> None:
    with pytest.raises(UnsafeCommandError, match="relative executable"):
        run_command(["bin/semgrep", "--version"])


def test_rejects_scanner_executable_inside_untrusted_tree() -> None:
    with pytest.raises(UnsafeCommandError, match="inside an untrusted tree"):
        run_command(
            [PYTHON, "--version"],
            allowed_executables=(PYTHON,),
            forbidden_executable_roots=(Path(PYTHON).parent,),
        )
