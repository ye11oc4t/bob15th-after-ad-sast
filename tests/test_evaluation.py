import pytest

from bob15_sast.evaluation import (
    EvaluationItem,
    EvaluationSet,
    PredictionLabel,
    TruthLabel,
    assert_no_split_leakage,
    calculate_metrics,
)


def _item(identifier: str, truth: TruthLabel, prediction: PredictionLabel) -> EvaluationItem:
    return EvaluationItem(
        root_cause_id=identifier,
        service="demo-service",
        truth=truth,
        prediction=prediction,
    )


def test_metrics_count_root_causes_and_abstentions() -> None:
    evaluation = EvaluationSet(
        split="blind-held-out",
        items=[
            _item("R1", TruthLabel.VULNERABLE, PredictionLabel.LIKELY_TRUE),
            _item("R2", TruthLabel.NOT_VULNERABLE, PredictionLabel.LIKELY_TRUE),
            _item("R3", TruthLabel.VULNERABLE, PredictionLabel.NEEDS_EVIDENCE),
        ],
    )
    result = calculate_metrics(evaluation)
    assert result.true_positive == 1
    assert result.false_positive == 1
    assert result.abstained == 1
    assert result.precision == 0.5


def test_duplicate_root_cause_is_rejected() -> None:
    with pytest.raises(ValueError, match="only once"):
        EvaluationSet(
            split="development",
            items=[
                _item("R1", TruthLabel.VULNERABLE, PredictionLabel.LIKELY_TRUE),
                _item("R1", TruthLabel.VULNERABLE, PredictionLabel.LIKELY_FALSE),
            ],
        )


def test_split_leakage_is_rejected() -> None:
    first = EvaluationSet(
        split="development",
        items=[_item("R1", TruthLabel.VULNERABLE, PredictionLabel.LIKELY_TRUE)],
    )
    second = EvaluationSet(
        split="blind-held-out",
        items=[_item("R1", TruthLabel.VULNERABLE, PredictionLabel.LIKELY_TRUE)],
    )
    with pytest.raises(ValueError, match="leakage"):
        assert_no_split_leakage(first, second)
