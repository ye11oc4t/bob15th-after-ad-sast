from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from bob15_sast.cli import app

ROOT = Path(__file__).parents[1]
RUNNER = CliRunner()


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
