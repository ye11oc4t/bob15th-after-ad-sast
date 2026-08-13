from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bob15_sast.ai import MockTriageProvider
from bob15_sast.models import CodeFlow, Finding, FindingGroup, Location, TraceStep
from bob15_sast.pipeline import (
    _group_payload,
    build_triage_request,
    public_finding,
    run_pipeline,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "sarif" / "sample.sarif"
SOURCE_ROOT = Path(__file__).parents[1]


def _write_sarif_results(
    path: Path,
    *,
    count: int,
    distinct_locations: bool,
    long_descriptors: bool = False,
) -> None:
    suffix = "x" * 10_000 if long_descriptors else ""
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "scanner-" + suffix}},
                "results": [
                    {
                        "ruleId": "rule-" + suffix,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f"src/file-{index if distinct_locations else 0}.py"
                                    },
                                    "region": {"startLine": index + 1 if distinct_locations else 1},
                                }
                            }
                        ],
                    }
                    for index in range(count)
                ],
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")


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
    manifest = json.loads((result.run_directory / "run.json").read_text(encoding="utf-8"))
    assert manifest["limits"] == {
        "max_ai_groups": 20,
        "max_findings": 5_000,
        "max_groups": 500,
    }
    report = result.report_path.read_text(encoding="utf-8")
    assert "pending_review" in report
    assert "likely_vulnerability" in report

    bundles = list((result.run_directory / "evidence-bundles").iterdir())
    assert len(bundles) == 1
    assert (bundles[0] / "triage-request.json").is_file()
    assert (bundles[0] / "triage-assessment.json").is_file()


def test_pipeline_never_overwrites_existing_run(tmp_path: Path) -> None:
    run_pipeline(
        [FIXTURE],
        service="synthetic",
        output_root=tmp_path,
        run_id="same-run",
    )
    with pytest.raises(FileExistsError):
        run_pipeline(
            [FIXTURE],
            service="synthetic",
            output_root=tmp_path,
            run_id="same-run",
        )


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


def test_public_finding_redacts_trace_kinds() -> None:
    finding = Finding(
        service="demo",
        tool="scanner",
        rule_id="rule",
        code_flows=[
            CodeFlow(
                steps=[
                    TraceStep(
                        location=Location(path="app.py", line=1),
                        kinds=["token=super-sensitive-value"],
                    )
                ]
            )
        ],
    )
    assert "super-sensitive-value" not in str(public_finding(finding))


def test_public_finding_bounds_locations() -> None:
    finding = Finding(
        service="demo",
        tool="scanner",
        rule_id="rule",
        locations=[Location(path=f"src/{index}.py", line=1) for index in range(100)],
    )
    assert len(public_finding(finding)["locations"]) == 20


def test_public_finding_uses_only_accepted_suppression_state() -> None:
    accepted = Finding(
        service="demo",
        tool="scanner",
        rule_id="accepted",
        properties={"sarif_has_accepted_suppression": True},
    )
    under_review = Finding(
        service="demo",
        tool="scanner",
        rule_id="review",
        properties={
            "sarif_has_accepted_suppression": False,
            "sarif_suppressions": [{"status": "underReview"}],
        },
    )
    assert public_finding(accepted)["suppressed"] is True
    assert public_finding(under_review)["suppressed"] is False


def test_long_scanner_identifiers_are_bounded_for_triage() -> None:
    finding = Finding(
        service="demo",
        tool="scanner-" + "x" * 30_000,
        rule_id="rule-" + "y" * 30_000,
        cwes=["CWE-78"],
        locations=[Location(path="app.py", line=1)],
    )
    from bob15_sast.grouping import group_findings

    request = build_triage_request(group_findings([finding])[0])
    scanner_evidence = request.evidence[0]
    assert len(scanner_evidence.content) <= 24_000
    assert len(request.scanner) <= 100
    assert len(request.rule_id) <= 300


def test_long_shared_group_descriptors_are_bounded_in_payload_and_triage() -> None:
    long_tool = "scanner-" + "x" * 20_000
    long_rule = "rule-" + "y" * 20_000
    finding = Finding(
        service="service-" + "s" * 20_000,
        tool=long_tool,
        rule_id=long_rule,
        cwes=["CWE-78"],
        locations=[Location(path="app.py", line=1)],
    )
    group = FindingGroup(
        fingerprint=finding.fingerprint or "missing",
        service=finding.service,
        cwes=finding.cwes,
        sink=finding.sink,
        tools=[long_tool] * 32,
        findings=[finding],
    )

    payload = _group_payload(group)
    request = build_triage_request(group)

    assert len(payload["service"]) <= 500
    assert len(payload["tools"]) <= 32
    assert max(map(len, payload["tools"])) <= 500
    assert max(map(len, payload["rule_ids"])) <= 1_000
    assert len(request.scanner) <= 100
    assert len(request.rule_id) <= 300
    assert len(request.evidence[0].content) < 10_000


def test_ai_group_cap_fails_before_provider_calls(tmp_path: Path) -> None:
    class CountingProvider(MockTriageProvider):
        def __init__(self) -> None:
            self.calls = 0

        def triage(self, request):  # type: ignore[no-untyped-def]
            self.calls += 1
            return super().triage(request)

    provider = CountingProvider()
    with pytest.raises(ValueError, match="exceeding max_ai_groups=0"):
        run_pipeline(
            [FIXTURE],
            service="synthetic",
            output_root=tmp_path,
            provider=provider,
            max_ai_groups=0,
        )
    assert provider.calls == 0
    assert list(tmp_path.iterdir()) == []


def test_finding_cap_fails_before_output_write(tmp_path: Path) -> None:
    sarif = tmp_path / "same-group.sarif"
    output = tmp_path / "output"
    _write_sarif_results(sarif, count=3, distinct_locations=False)
    with pytest.raises(ValueError, match="exceeding max_findings=2"):
        run_pipeline(
            [sarif],
            service="synthetic",
            output_root=output,
            max_findings=2,
        )
    assert not output.exists()


def test_group_cap_fails_before_output_write(tmp_path: Path) -> None:
    sarif = tmp_path / "many-groups.sarif"
    output = tmp_path / "output"
    _write_sarif_results(
        sarif,
        count=3,
        distinct_locations=True,
        long_descriptors=True,
    )
    with pytest.raises(ValueError, match="exceeding max_groups=2"):
        run_pipeline(
            [sarif],
            service="synthetic",
            output_root=output,
            max_groups=2,
        )
    assert not output.exists()


def test_pipeline_rejects_negative_finding_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="max_findings must be zero or greater"):
        run_pipeline(
            [FIXTURE],
            service="synthetic",
            output_root=tmp_path,
            max_findings=-1,
        )
    assert list(tmp_path.iterdir()) == []


def test_pipeline_rejects_negative_group_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="max_groups must be zero or greater"):
        run_pipeline(
            [FIXTURE],
            service="synthetic",
            output_root=tmp_path,
            max_groups=-1,
        )
    assert list(tmp_path.iterdir()) == []


def test_pipeline_rejects_output_inside_source_tree(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="outside the untrusted source tree"):
        run_pipeline(
            [FIXTURE],
            service="synthetic",
            source_root=source,
            output_root=source / "artifacts",
        )


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
