"""Constrained subprocess execution for local security scanners.

The project scans untrusted repositories.  Scanner commands therefore use an
argument vector, a small executable allowlist, a deliberately sparse
environment, bounded output capture, and a hard timeout.  This module never
invokes a shell.  It is a process policy boundary, not a filesystem, network,
privilege, CPU, or memory sandbox; callers still need an isolation boundary.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess  # noqa: S404 - this module is the constrained subprocess boundary
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

DEFAULT_ALLOWED_EXECUTABLES = frozenset({"semgrep", "codeql", "trivy"})
DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
_INHERITED_ENVIRONMENT_KEYS = (
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
)
_FORBIDDEN_EXPLICIT_ENVIRONMENT_KEYS = frozenset(
    {
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GCONV_PATH",
        "IFS",
        "NODE_OPTIONS",
        "PATH",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
        "SHELLOPTS",
    }
)
_FORBIDDEN_EXPLICIT_ENVIRONMENT_PREFIXES = ("DYLD_", "LD_")


class UnsafeCommandError(ValueError):
    """Raised when a command does not satisfy the execution policy."""


class CommandTimedOutError(TimeoutError):
    """Raised after a scanner process group exceeds its deadline."""

    def __init__(self, argv: Sequence[str], timeout_seconds: float) -> None:
        self.argv = tuple(argv)
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"command exceeded the {timeout_seconds:g}s timeout: {self.argv[0]}"
        )


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Captured result of a policy-approved command."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0


@dataclass(slots=True)
class _CapturedStream:
    data: bytearray = field(default_factory=bytearray)
    truncated: bool = False


def _drain_stream(
    stream: IO[bytes],
    capture: _CapturedStream,
    max_output_bytes: int,
) -> None:
    """Drain a pipe to EOF while retaining at most the configured byte cap."""

    try:
        while chunk := stream.read(64 * 1024):
            remaining = max_output_bytes - len(capture.data)
            if remaining > 0:
                capture.data.extend(chunk[:remaining])
            if len(chunk) > remaining:
                capture.truncated = True
    except (OSError, ValueError):
        # The parent can close a pipe after a scanner exits while a descendant
        # still holds the write end.  The process result remains bounded.
        capture.truncated = True
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _render_capture(capture: _CapturedStream, max_output_bytes: int) -> str:
    payload = bytes(capture.data)
    if capture.truncated:
        notice = b"\n...[scanner output truncated]"
        if max_output_bytes >= len(notice):
            payload = payload[: max_output_bytes - len(notice)] + notice
    return payload.decode("utf-8", errors="replace")


def _join_capture_threads(
    streams: tuple[IO[bytes], IO[bytes]],
    threads: tuple[threading.Thread, threading.Thread],
    captures: tuple[_CapturedStream, _CapturedStream],
    *,
    strict: bool = True,
) -> None:
    """Finish pipe draining without waiting forever on an orphan descendant."""

    deadline = time.monotonic() + 0.25
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    for stream, thread in zip(streams, threads, strict=True):
        if thread.is_alive():
            try:
                stream.close()
            except OSError:
                pass
    if strict:
        deadline = time.monotonic() + 0.25
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
    alive = [thread.is_alive() for thread in threads]
    for capture, is_alive in zip(captures, alive, strict=True):
        if is_alive:
            capture.truncated = True
    if strict and any(alive):
        raise RuntimeError("scanner descendants left captured output pipes open")


def _clean_path(raw_path: str | None) -> str:
    """Keep absolute PATH entries only, excluding empty/current-dir entries."""

    candidates = (raw_path or os.defpath).split(os.pathsep)
    clean: list[str] = []
    for candidate in candidates:
        if not candidate or not os.path.isabs(candidate):
            continue
        normalized = os.path.normpath(candidate)
        if normalized not in clean:
            clean.append(normalized)
    return os.pathsep.join(clean) or os.defpath


def sanitized_environment(
    explicit: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build an environment without implicitly forwarding credentials.

    Only basic process/locale variables are inherited.  Callers may pass
    additional non-secret values explicitly; both names and values are checked
    for NUL bytes because they are handed directly to the operating system.
    """

    environment: dict[str, str] = {}
    for key in _INHERITED_ENVIRONMENT_KEYS:
        value = os.environ.get(key)
        if value is not None and "\x00" not in value:
            environment[key] = value
    environment["PATH"] = _clean_path(environment.get("PATH"))
    environment.setdefault("LANG", "C.UTF-8")
    environment["PYTHONIOENCODING"] = "utf-8"

    for key, value in (explicit or {}).items():
        if not key or "=" in key or "\x00" in key:
            raise UnsafeCommandError(f"invalid environment variable name: {key!r}")
        normalized_key = key.upper()
        if normalized_key in _FORBIDDEN_EXPLICIT_ENVIRONMENT_KEYS or any(
            normalized_key.startswith(prefix)
            for prefix in _FORBIDDEN_EXPLICIT_ENVIRONMENT_PREFIXES
        ):
            raise UnsafeCommandError(
                f"process-injection environment variable is not allowed: {key!r}"
            )
        if not isinstance(value, str) or "\x00" in value:
            raise UnsafeCommandError(f"invalid environment value for {key!r}")
        environment[key] = value
    environment["PATH"] = _clean_path(environment.get("PATH"))
    return environment


def _coerce_argv(argv: Sequence[str | os.PathLike[str]]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise UnsafeCommandError("commands must be an argument sequence, not a string")
    if not argv:
        raise UnsafeCommandError("empty commands are not allowed")

    coerced = tuple(os.fspath(argument) for argument in argv)
    if any(not argument or "\x00" in argument for argument in coerced):
        raise UnsafeCommandError("command arguments must be non-empty and NUL-free")
    return coerced


def _has_path_separator(value: str) -> bool:
    return os.sep in value or (os.altsep is not None and os.altsep in value)


def _resolve_executable(
    requested: str,
    allowed_executables: Iterable[str | os.PathLike[str]],
    environment: Mapping[str, str],
) -> str:
    """Resolve an executable and enforce name/path-aware allowlisting.

    A bare allowlist item such as ``semgrep`` only permits a bare command name
    resolved through the sanitized PATH.  An absolute command (useful for
    tests or pinned installations) must be explicitly allowlisted by its exact
    absolute path.  Deployments should prefer pinned absolute paths because a
    bare name trusts whichever binary is first in the inherited PATH.
    """

    allowed_names: set[str] = set()
    allowed_paths: set[Path] = set()
    for item in allowed_executables:
        value = os.fspath(item)
        if _has_path_separator(value):
            path = Path(value)
            if not path.is_absolute():
                raise UnsafeCommandError("allowlisted executable paths must be absolute")
            allowed_paths.add(path.resolve())
        else:
            allowed_names.add(value)

    if _has_path_separator(requested):
        path = Path(requested)
        if not path.is_absolute():
            raise UnsafeCommandError("relative executable paths are not allowed")
        resolved = path.resolve()
        if resolved not in allowed_paths:
            raise UnsafeCommandError(f"executable path is not allowlisted: {requested}")
    else:
        if requested not in allowed_names:
            raise UnsafeCommandError(f"executable is not allowlisted: {requested}")
        located = shutil.which(requested, path=environment.get("PATH"))
        if located is None:
            raise FileNotFoundError(f"allowlisted executable was not found: {requested}")
        resolved = Path(located).resolve()

    if not resolved.is_file():
        raise FileNotFoundError(f"executable does not exist: {resolved}")
    return str(resolved)


def run_command(
    argv: Sequence[str | os.PathLike[str]],
    *,
    allowed_executables: Iterable[str | os.PathLike[str]] = DEFAULT_ALLOWED_EXECUTABLES,
    timeout_seconds: float = 300.0,
    cwd: str | os.PathLike[str] | None = None,
    environment: Mapping[str, str] | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    forbidden_executable_roots: Iterable[str | os.PathLike[str]] = (),
) -> CommandResult:
    """Run one scanner command under the constrained execution policy."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be greater than zero")

    original_argv = _coerce_argv(argv)
    child_environment = sanitized_environment(environment)
    executable = _resolve_executable(
        original_argv[0], allowed_executables, child_environment
    )
    executable_path = Path(executable)
    for raw_root in forbidden_executable_roots:
        root = Path(raw_root).expanduser().resolve()
        if executable_path == root or executable_path.is_relative_to(root):
            raise UnsafeCommandError(
                f"scanner executable resolves inside an untrusted tree: {executable_path}"
            )
    execution_argv = (executable, *original_argv[1:])

    working_directory: str | None = None
    if cwd is not None:
        directory = Path(cwd).resolve()
        if not directory.is_dir():
            raise NotADirectoryError(directory)
        working_directory = str(directory)

    start_new_session = os.name == "posix"
    creationflags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if os.name == "nt"  # pragma: no cover - evaluated on Windows runners
        else 0
    )

    started = time.monotonic()
    process = subprocess.Popen(  # noqa: S603 - executable is explicitly allowlisted
        execution_argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        cwd=working_directory,
        env=child_environment,
        close_fds=True,
        start_new_session=start_new_session,
        creationflags=creationflags,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    streams = (process.stdout, process.stderr)
    stdout_capture = _CapturedStream()
    stderr_capture = _CapturedStream()
    threads = (
        threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout_capture, max_output_bytes),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_capture, max_output_bytes),
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:  # pragma: no cover - exercised on Windows runners
            process.kill()
        process.wait()
        _join_capture_threads(
            streams,
            threads,
            (stdout_capture, stderr_capture),
            strict=False,
        )
        raise CommandTimedOutError(original_argv, timeout_seconds) from error

    _join_capture_threads(
        streams,
        threads,
        (stdout_capture, stderr_capture),
    )
    assert process.returncode is not None
    return CommandResult(
        argv=original_argv,
        returncode=process.returncode,
        stdout=_render_capture(stdout_capture, max_output_bytes),
        stderr=_render_capture(stderr_capture, max_output_bytes),
        duration_seconds=time.monotonic() - started,
        stdout_truncated=stdout_capture.truncated,
        stderr_truncated=stderr_capture.truncated,
    )


class SafeCommandRunner:
    """Reusable runner with a fixed executable policy and default timeout."""

    def __init__(
        self,
        *,
        allowed_executables: Iterable[str | os.PathLike[str]] = DEFAULT_ALLOWED_EXECUTABLES,
        timeout_seconds: float = 300.0,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        self.allowed_executables = tuple(allowed_executables)
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def run(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        timeout_seconds: float | None = None,
        cwd: str | os.PathLike[str] | None = None,
        environment: Mapping[str, str] | None = None,
        max_output_bytes: int | None = None,
        forbidden_executable_roots: Iterable[str | os.PathLike[str]] = (),
    ) -> CommandResult:
        return run_command(
            argv,
            allowed_executables=self.allowed_executables,
            timeout_seconds=(
                self.timeout_seconds if timeout_seconds is None else timeout_seconds
            ),
            cwd=cwd,
            environment=environment,
            max_output_bytes=(
                self.max_output_bytes
                if max_output_bytes is None
                else max_output_bytes
            ),
            forbidden_executable_roots=forbidden_executable_roots,
        )
