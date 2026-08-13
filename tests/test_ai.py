from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from bob15_sast.ai import (
    AIProviderResponseError,
    AIProviderUnavailable,
    EvidenceReference,
    MockTriageProvider,
    OpenAITriageProvider,
    TriageAssessment,
    TriageRequest,
)


def make_request() -> TriageRequest:
    return TriageRequest(
        finding_id="SYNTHETIC-001",
        scanner="semgrep",
        rule_id="java.lang.security.audit.command-injection",
        message="Request input may reach a process execution API",
        reported_severity="high",
        evidence=[
            EvidenceReference(
                evidence_id="EV-001",
                kind="dataflow",
                content="request parameter -> ProcessBuilder",
                location="src/example/Sample.java:42",
            )
        ],
        metadata={"service": "demo-service"},
    )


def make_assessment(**updates: object) -> TriageAssessment:
    values: dict[str, object] = {
        "finding_id": "SYNTHETIC-001",
        "title": "Possible unsafe process execution",
        "disposition": "needs_review",
        "summary": "The referenced flow requires isolated validation.",
        "root_cause_hypothesis": "Untrusted input may reach a process API.",
        "cwe": "CWE-78",
        "reachability": "unknown",
        "confidence": 0.72,
        "evidence_ids": ["EV-001"],
        "missing_evidence": ["Runtime reachability"],
        "recommended_actions": ["Run a non-destructive regression test"],
        "requires_human_confirmation": True,
    }
    values.update(updates)
    return TriageAssessment.model_validate(values)


def test_assessment_requires_evidence_ids() -> None:
    with pytest.raises(ValidationError):
        make_assessment(evidence_ids=[])


def test_assessment_cannot_claim_confirmation() -> None:
    with pytest.raises(ValidationError, match="may not claim"):
        make_assessment(summary="This issue is confirmed by the model.")


def test_assessment_allows_explicit_uncertainty() -> None:
    assessment = make_assessment(
        summary="This issue is not confirmed and requires human review."
    )
    assert assessment.requires_human_confirmation is True


def test_mock_provider_is_deterministic_and_non_authoritative() -> None:
    provider = MockTriageProvider()
    first = provider.triage(make_request())
    second = provider.triage(make_request())
    assert first == second
    assert first.evidence_ids == ["EV-001"]
    assert first.requires_human_confirmation is True
    assert first.disposition != "confirmed"


def test_openai_provider_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(AIProviderUnavailable, match="OPENAI_API_KEY"):
        OpenAITriageProvider()


def test_openai_provider_uses_responses_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BOB15_SAST_MODEL", raising=False)
    assessment = make_assessment()

    class FakeResponses:
        def __init__(self) -> None:
            self.kwargs: dict[str, object] | None = None

        def parse(self, **kwargs: object) -> SimpleNamespace:
            self.kwargs = kwargs
            return SimpleNamespace(output_parsed=assessment)

    responses = FakeResponses()
    client = SimpleNamespace(responses=responses)
    provider = OpenAITriageProvider(api_key="test-key", client=client)  # noqa: S106
    assert provider.triage(make_request()) == assessment
    assert responses.kwargs is not None
    assert responses.kwargs["text_format"] is TriageAssessment
    assert responses.kwargs["model"] == "gpt-5.6"
    assert responses.kwargs["store"] is False


def test_openai_provider_uses_model_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BOB15_SAST_MODEL", "gpt-test-model")
    assessment = make_assessment()

    class FakeResponses:
        def parse(self, **_: object) -> SimpleNamespace:
            return SimpleNamespace(output_parsed=assessment)

    provider = OpenAITriageProvider(
        api_key="test-key",  # noqa: S106
        client=SimpleNamespace(responses=FakeResponses()),
    )
    assert provider.model == "gpt-test-model"


def test_openai_provider_rejects_invented_evidence_ids() -> None:
    assessment = make_assessment(evidence_ids=["EV-INVENTED"])

    class FakeResponses:
        def parse(self, **_: object) -> SimpleNamespace:
            return SimpleNamespace(output_parsed=assessment)

    provider = OpenAITriageProvider(
        api_key="test-key",  # noqa: S106
        client=SimpleNamespace(responses=FakeResponses()),
    )
    with pytest.raises(AIProviderResponseError, match="unknown evidence"):
        provider.triage(make_request())


def test_openai_provider_redacts_request_again_before_sending() -> None:
    assessment = make_assessment()

    class FakeResponses:
        def __init__(self) -> None:
            self.sent = ""

        def parse(self, **kwargs: object) -> SimpleNamespace:
            self.sent = str(kwargs["input"])
            return SimpleNamespace(output_parsed=assessment)

    sensitive = TriageRequest(
        finding_id="SYNTHETIC-001",
        scanner="semgrep",
        rule_id="synthetic.rule",
        message="token=very-sensitive-value",
        reported_severity="high",
        evidence=[
            EvidenceReference(
                evidence_id="EV-001",
                kind="source",
                content="api_key=another-sensitive-value",
                location="fixtures/synthetic/example.py:1",
            )
        ],
        metadata={"authorization": "Bearer sensitive-bearer-value"},
    )
    responses = FakeResponses()
    provider = OpenAITriageProvider(
        api_key="test-key",  # noqa: S106
        client=SimpleNamespace(responses=responses),
    )
    provider.triage(sensitive)
    assert "very-sensitive-value" not in responses.sent
    assert "another-sensitive-value" not in responses.sent
    assert "sensitive-bearer-value" not in responses.sent
    assert "<REDACTED>" in responses.sent


def test_openai_provider_reports_incomplete_response() -> None:
    class FakeResponses:
        def parse(self, **_: object) -> SimpleNamespace:
            return SimpleNamespace(
                status="incomplete",
                incomplete_details=SimpleNamespace(reason="max_output_tokens"),
                output_parsed=None,
            )

    provider = OpenAITriageProvider(
        api_key="test-key",  # noqa: S106
        client=SimpleNamespace(responses=FakeResponses()),
    )
    with pytest.raises(AIProviderResponseError, match="incomplete.*max_output_tokens"):
        provider.triage(make_request())
