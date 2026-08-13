from datetime import UTC, datetime

from bob15_sast.models import Finding, FindingGroup, Location, Severity
from bob15_sast.report import render_markdown


def test_report_does_not_claim_ai_confirmation() -> None:
    finding = Finding(
        service="demo-service",
        tool="Semgrep",
        rule_id="synthetic.command-injection",
        severity=Severity.HIGH,
        cwes=["CWE-78"],
        locations=[Location(path="app.py", line=4)],
    )
    group = FindingGroup(
        fingerprint=finding.fingerprint or "missing",
        service=finding.service,
        cwes=finding.cwes,
        sink=finding.sink,
        severity=finding.severity,
        tools=[finding.tool],
        findings=[finding],
    )
    report = render_markdown(
        run_id="test",
        groups=[group],
        assessments={
            group.fingerprint: {
                "verdict": "likely_true",
                "confidence": 0.8,
                "root_cause": "Untrusted input may reach a process API.",
                "evidence_ids": ["EV-test"],
            }
        },
        generated_at=datetime(2026, 8, 13, tzinfo=UTC),
    )
    assert "Only a human reviewer" in report
    assert "pending_review" in report
    assert "Human status: `confirmed`" not in report


def test_report_escapes_untrusted_markdown() -> None:
    finding = Finding(
        service="![remote](https://example.invalid/track)",
        tool="<img src=https://example.invalid/track>",
        rule_id="`break`",
        locations=[Location(path="[path](https://example.invalid)", line=1)],
    )
    group = FindingGroup(
        fingerprint=finding.fingerprint or "missing",
        service=finding.service,
        sink=finding.sink,
        tools=[finding.tool],
        findings=[finding],
    )
    report = render_markdown(run_id="safe", groups=[group])
    assert "![remote]" not in report
    assert "<img" not in report
    assert "`break`" not in report
