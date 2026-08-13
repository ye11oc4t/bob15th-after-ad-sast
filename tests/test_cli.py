from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import bob15_sast.cli as cli_module
from bob15_sast.cli import app

ROOT = Path(__file__).parents[1]
RUNNER = CliRunner()
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def test_doctor_succeeds_when_optional_tools_are_missing() -> None:
    result = RUNNER.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "default network behavior: no target access" in result.stdout


def test_ingest_emits_normalized_redacted_json() -> None:
    result = RUNNER.invoke(
        app,
        [
            "ingest",
            str(ROOT / "fixtures" / "sarif" / "sample.sarif"),
            "--service",
            "synthetic",
        ],
    )
    assert result.exit_code == 0
    assert '"rule_id": "bob15.python.command-injection"' in result.stdout
    assert '"fingerprint": "sha256:' in result.stdout


def test_demo_uses_synthetic_fixture_only(tmp_path: Path) -> None:
    result = RUNNER.invoke(app, ["demo", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "findings: 1" in result.stdout
    assert "AI hypotheses: 1" in result.stdout
    assert list(tmp_path.glob("*/report.md"))


def test_analyze_rejects_output_inside_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    result = RUNNER.invoke(
        app,
        ["analyze", str(target), "--output", str(target / "artifacts")],
    )
    assert result.exit_code != 0
    assert "outside the untrusted target tree" in result.output


def test_analyze_requires_external_cache_for_offline_trivy(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    result = RUNNER.invoke(app, ["analyze", str(target), "--scanner", "trivy"])
    assert result.exit_code != 0
    plain_output = ANSI_ESCAPE.sub("", result.output)
    assert "--trivy-cache-dir" in plain_output
    assert "required" in plain_output


def test_analyze_rejects_trivy_cache_inside_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    cache = target / "cache"
    cache.mkdir(parents=True)
    result = RUNNER.invoke(
        app,
        [
            "analyze",
            str(target),
            "--scanner",
            "trivy",
            "--trivy-cache-dir",
            str(cache),
        ],
    )
    assert result.exit_code != 0
    assert "outside the untrusted target tree" in result.output


def test_demo_exposes_ai_call_cap(tmp_path: Path) -> None:
    result = RUNNER.invoke(
        app,
        ["demo", "--output", str(tmp_path), "--max-ai-groups", "0"],
    )
    assert result.exit_code == 2
    assert "exceeding max_ai_groups=0" in result.output


@pytest.mark.parametrize(
    ("option", "message"),
    [
        ("--max-findings", "exceeding max_findings=0"),
        ("--max-groups", "exceeding max_groups=0"),
    ],
)
def test_demo_exposes_pipeline_work_caps(
    tmp_path: Path, option: str, message: str
) -> None:
    result = RUNNER.invoke(app, ["demo", "--output", str(tmp_path), option, "0"])
    assert result.exit_code == 2
    assert message in result.output


def test_analyze_rejects_platform_without_process_tree_kill(
    monkeypatch, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr(cli_module, "os", SimpleNamespace(name="nt"))
    result = RUNNER.invoke(app, ["analyze", str(target)])
    assert result.exit_code == 2
    assert "requires POSIX process-group termination" in result.output
