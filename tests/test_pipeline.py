from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from bob15_sast.ai import MockTriageProvider
from bob15_sast.models import Finding, Location
from bob15_sast.pipeline import public_finding, run_pipeline

FIXTURE = Path(__file__).parents[1] / "fixtures" / "sarif" / "sample.sarif"
SOURCE_ROOT = Path(__file__).parents[1]


def test_pipeline_writes_redacted_review_artifacts(tmp_path: Path) -> None:
    result = run_pipeline(
        [FIXTURE],
        service="synthetic",
        output_root=tmp_path,
        source_root=SOURCE_ROOT,
        repo_root=SOURCE_ROOT,
        provider=MockTriageProvider(),
        run_id="test-run",
        generated_at=datetime(2026, 8, 13, tzinfo=UTC),
    )

    assert result.finding_count == 1
    assert result.group_count == 1
    assert result.assessment_count == 1
    assert result.report_path.is_file()
    assert (result.run_directory / "normalized-findings.json").is_file()
    assert (result.run_directory / "root-cause-groups.json").is_file()
    assert (result.run_directory / "triage-assessments.json").is_file()
    report = result.report_path.read_text(encoding="utf-8")
    assert "pending_review" in report
    assert "likely_vulnerability" in report

    bundles = list((result.run_directory / "evidence-bundles").iterdir())
    assert len(bundles) == 1
    assert (bundles[0] / "triage-request.json").is_file()
    assert (bundles[0] / "triage-assessment.json").is_file()


def test_pipeline_never_overwrites_existing_run(tmp_path: Path) -> None:
    kwargs = {
        "service": "synthetic",
        "output_root": tmp_path,
        "run_id": "same-run",
    }
    run_pipeline([FIXTURE], **kwargs)
    with pytest.raises(FileExistsError):
        run_pipeline([FIXTURE], **kwargs)


def test_pipeline_rejects_unsafe_run_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="run_id"):
        run_pipeline(
            [FIXTURE],
            service="synthetic",
            output_root=tmp_path,
            run_id="../escape",
        )


def test_public_finding_drops_raw_sarif_content() -> None:
    finding = Finding(
        service="demo-service",
        tool="scanner",
        rule_id="synthetic.rule",
        message="ghp_abcdefghijklmnopqrstuvwxyz123456",
        locations=[
            Location(
                path="src/app.py",
                line=1,
                snippet="postgresql://demo:p4ssword@example.invalid/db",
                original_uri="file:///private/work/src/app.py",
            )
        ],
        properties={"match": "ghp_abcdefghijklmnopqrstuvwxyz123456"},
    )
    serialized = public_finding(finding)
    rendered = str(serialized)
    assert "properties" not in serialized
    assert "message" not in serialized
    assert "snippet" not in rendered
    assert "original_uri" not in rendered
    assert "ghp_" not in rendered
    assert "p4ssword" not in rendered


@pytest.mark.skipif(__import__("os").name == "nt", reason="POSIX mode assertion")
def test_pipeline_artifacts_are_private(tmp_path: Path) -> None:
    result = run_pipeline(
        [FIXTURE],
        service="synthetic",
        output_root=tmp_path,
        provider=MockTriageProvider(),
        run_id="private-run",
    )
    assert result.run_directory.stat().st_mode & 0o077 == 0
    assert result.report_path.stat().st_mode & 0o077 == 0
    for path in result.run_directory.rglob("*"):
        if path.is_file():
            assert path.stat().st_mode & 0o077 == 0
