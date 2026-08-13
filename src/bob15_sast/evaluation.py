"""Leakage-aware, root-cause-level evaluation primitives."""

from __future__ import annotations

from collections import Counter
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TruthLabel(StrEnum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNVERIFIABLE = "unverifiable"


class PredictionLabel(StrEnum):
    LIKELY_TRUE = "likely_true"
    LIKELY_FALSE = "likely_false"
    NEEDS_EVIDENCE = "needs_evidence"


class EvaluationItem(BaseModel):
    """One independent root cause, never one raw scanner alert."""

    model_config = ConfigDict(extra="forbid")

    root_cause_id: str = Field(min_length=1)
    service: str = Field(min_length=1)
    truth: TruthLabel
    prediction: PredictionLabel


class Metrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    abstained: int
    evaluated: int
    precision: float | None
    recall: float | None
    f1: float | None
    by_service: dict[str, dict[str, int]]


class EvaluationSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    split: str = Field(pattern=r"^(development|blind-held-out|mutation)$")
    items: list[EvaluationItem]

    @model_validator(mode="after")
    def unique_root_causes(self) -> EvaluationSet:
        identifiers = [item.root_cause_id for item in self.items]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("each root cause may appear only once in an evaluation set")
        return self


def calculate_metrics(evaluation: EvaluationSet) -> Metrics:
    """Calculate metrics while excluding unverifiable truth from binary scores."""
    counts: Counter[str] = Counter()
    per_service: dict[str, Counter[str]] = {}

    for item in evaluation.items:
        service_counts = per_service.setdefault(item.service, Counter())
        if (
            item.truth is TruthLabel.UNVERIFIABLE
            or item.prediction is PredictionLabel.NEEDS_EVIDENCE
        ):
            counts["abstained"] += 1
            service_counts["abstained"] += 1
            continue
        if item.truth is TruthLabel.VULNERABLE:
            key = (
                "true_positive"
                if item.prediction is PredictionLabel.LIKELY_TRUE
                else "false_negative"
            )
        else:
            key = (
                "false_positive"
                if item.prediction is PredictionLabel.LIKELY_TRUE
                else "true_negative"
            )
        counts[key] += 1
        service_counts[key] += 1

    tp = counts["true_positive"]
    fp = counts["false_positive"]
    fn = counts["false_negative"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return Metrics(
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        true_negative=counts["true_negative"],
        abstained=counts["abstained"],
        evaluated=tp + fp + fn + counts["true_negative"],
        precision=precision,
        recall=recall,
        f1=f1,
        by_service={
            service: dict(service_counts)
            for service, service_counts in per_service.items()
        },
    )


def assert_no_split_leakage(development: EvaluationSet, held_out: EvaluationSet) -> None:
    """Reject an evaluation when a root cause appears in both splits."""
    development_ids = {item.root_cause_id for item in development.items}
    held_out_ids = {item.root_cause_id for item in held_out.items}
    overlap = sorted(development_ids & held_out_ids)
    if overlap:
        raise ValueError(f"root-cause leakage between splits: {', '.join(overlap)}")
