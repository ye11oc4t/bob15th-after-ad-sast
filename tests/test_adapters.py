from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from bob15_sast.adapters import CodeQLAdapter, SemgrepAdapter, TrivyAdapter
from bob15_sast.safe_exec import CommandResult, SafeCommandRunner


class FakeRunner(SafeCommandRunner):
    """Record scanner argument vectors without starting a subprocess."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.working_directories: list[Path | None] = []
        self.policy_files: list[dict[str, str]] = []

    def run(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        timeout_seconds: float | None = None,
        cwd: str | os.PathLike[str] | None = None,
        environment: Mapping[str, str] | None = None,
        max_output_bytes: int | None = None,
        forbidden_executable_roots: Sequence[str | os.PathLike[str]] = (),
    ) -> CommandResult:
        del timeout_seconds, environment, max_output_bytes, forbidden_executable_roots
        call = tuple(os.fspath(argument) for argument in argv)
        self.calls.append(call)
        self.working_directories.append(
            None if cwd is None else Path(cwd).resolve()
        )
        captured: dict[str, str] = {}
        for flag in ("--config", "--ignorefile"):
            if flag in call:
                value = Path(call[call.index(flag) + 1])
                if value.is_file():
                    captured[flag] = value.read_text(encoding="utf-8")
        self.policy_files.append(captured)
        return CommandResult(call, 0, "", "", 0.0)


@pytest.mark.parametrize(
    ("language", "normalized"),
    [
        ("csharp", "csharp"),
        ("java-kotlin", "java-kotlin"),
        ("java", "java-kotlin"),
        ("javascript-typescript", "javascript-typescript"),
        ("javascript", "javascript-typescript"),
        ("typescript", "javascript-typescript"),
        ("python", "python"),
        ("ruby", "ruby"),
    ],
)
def test_codeql_all_accepted_languages_use_no_build_mode(
    tmp_path: Path,
    language: str,
    normalized: str,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    runner = FakeRunner()
    adapter = CodeQLAdapter(
        language=language,
        database_path=tmp_path / "database",
        runner=runner,
    )

    result = adapter.scan(target, tmp_path / "result.sarif")

    assert result.succeeded
    assert len(runner.calls) == 2
    create_argv = runner.calls[0]
    assert create_argv[:3] == ("codeql", "database", "create")
    assert f"--language={normalized}" in create_argv
    assert "--build-mode=none" in create_argv


def test_codeql_rejects_go_instead_of_running_a_repository_build(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported or build-required"):
        CodeQLAdapter(language="go", database_path=tmp_path / "database")


@pytest.mark.parametrize("extension", [".KT", ".kts"])
def test_codeql_no_build_mode_rejects_kotlin_sources(
    tmp_path: Path, extension: str
) -> None:
    target = tmp_path / "target"
    nested = target / "src" / "main" / "kotlin"
    nested.mkdir(parents=True)
    (nested / f"Example{extension}").write_text("fun main() = Unit\n", encoding="utf-8")
    runner = FakeRunner()
    adapter = CodeQLAdapter(
        language="java-kotlin",
        database_path=tmp_path / "database",
        runner=runner,
    )

    with pytest.raises(ValueError, match=r"Java-only.*\.kt or \.kts"):
        adapter.scan(target, tmp_path / "result.sarif")

    assert runner.calls == []


def test_semgrep_uses_safe_noninteractive_argv(tmp_path: Path) -> None:
    target = tmp_path / "target;still-one-argument"
    target.mkdir()
    config_dir = tmp_path / "local-rules"
    config_dir.mkdir()
    config_file = tmp_path / "local.yml"
    config_file.write_text("rules: []\n", encoding="utf-8")
    runner = FakeRunner()
    adapter = SemgrepAdapter(configs=(config_dir, config_file), runner=runner)

    adapter.scan(target, tmp_path / "semgrep.sarif")

    assert runner.calls == [
        (
            "semgrep",
            "scan",
            "--config",
            str(config_dir.resolve()),
            "--config",
            str(config_file.resolve()),
            "--sarif",
            "--output",
            str((tmp_path / "semgrep.sarif").resolve()),
            "--metrics=off",
            "--disable-version-check",
            str(target.resolve()),
        )
    ]


@pytest.mark.parametrize("config", ["p/default", "https://example.test/rules.yml"])
def test_semgrep_rejects_remote_or_registry_configs(
    tmp_path: Path, config: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    runner = FakeRunner()

    with pytest.raises((FileNotFoundError, ValueError)):
        SemgrepAdapter(configs=(config,), runner=runner).scan(
            target, tmp_path / "semgrep.sarif"
        )

    assert runner.calls == []


def test_semgrep_rejects_missing_local_config(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    runner = FakeRunner()

    with pytest.raises(FileNotFoundError, match="Semgrep config does not exist"):
        SemgrepAdapter(configs=(tmp_path / "missing.yml",), runner=runner).scan(
            target, tmp_path / "semgrep.sarif"
        )

    assert runner.calls == []


def test_trivy_offline_argv_disables_network_updates_and_telemetry(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    runner = FakeRunner()

    TrivyAdapter(runner=runner).scan(target, tmp_path / "trivy.sarif")

    argv = runner.calls[0]
    for flag in (
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
    ):
        assert flag in argv
    scanners = argv[argv.index("--scanners") + 1].split(",")
    assert scanners == ["vuln", "misconfig"]
    assert "secret" not in scanners


def test_trivy_uses_explicit_empty_policy_files_and_isolated_cwd(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "trivy.yaml").write_text("timeout: 1ns\n", encoding="utf-8")
    (target / ".trivyignore").write_text("CVE-ALL\n", encoding="utf-8")
    runner = FakeRunner()

    TrivyAdapter(runner=runner).scan(target, tmp_path / "results" / "trivy.sarif")

    argv = runner.calls[0]
    working_directory = runner.working_directories[0]
    assert working_directory is not None
    assert working_directory != target.resolve()
    assert target.resolve() not in working_directory.parents
    assert Path(argv[argv.index("--config") + 1]).parent == working_directory
    assert Path(argv[argv.index("--ignorefile") + 1]).parent == working_directory
    assert runner.policy_files[0] == {"--config": "{}\n", "--ignorefile": ""}
    assert str(target / "trivy.yaml") not in argv
    assert str(target / ".trivyignore") not in argv


def test_trivy_passes_only_an_explicit_external_cache_directory(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    runner = FakeRunner()

    TrivyAdapter(runner=runner, cache_dir=cache).scan(
        target, tmp_path / "trivy.sarif"
    )

    argv = runner.calls[0]
    assert argv[argv.index("--cache-dir") + 1] == str(cache.resolve())


def test_trivy_rejects_cache_directory_inside_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    cache = target / "cache"
    cache.mkdir(parents=True)
    runner = FakeRunner()

    with pytest.raises(ValueError, match="outside the untrusted target"):
        TrivyAdapter(runner=runner, cache_dir=cache).scan(
            target, tmp_path / "trivy.sarif"
        )

    assert runner.calls == []
