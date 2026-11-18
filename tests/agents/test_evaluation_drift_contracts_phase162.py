from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.evaluation_drift_contracts import (
    NO_EFFECTS,
    AssessmentOutcome,
    CanaryPlanStatus,
    CanaryProgressionPlan,
    CanaryStage,
    ConfidenceBand,
    Direction,
    DistributionBinding,
    DriftAssessment,
    EvaluationBaseline,
    EvaluationCohort,
    EvaluationDriftError,
    EvaluationMode,
    EvaluationPolicy,
    GateRole,
    IndependentGate,
    MetricDisposition,
    MetricName,
    MetricObservation,
    MetricThreshold,
    StratumSample,
    SubjectRole,
    assess_drift,
    build_canary_progression_plan,
    canonical_json,
    verify_assessment,
    verify_canary_plan,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "evaluation-drift-assessment-v1.schema.json"
FIXED_SHA = "sha256:" + "1" * 64
SOURCE_SHA = "sha256:" + "2" * 64


def _direction(metric: MetricName) -> Direction:
    if metric in {
        MetricName.FALSE_POSITIVE,
        MetricName.FALSE_NEGATIVE,
        MetricName.LATENCY,
        MetricName.COST,
    }:
        return Direction.LOWER_IS_BETTER
    return Direction.HIGHER_IS_BETTER


def _base_value(metric: MetricName) -> int:
    return 100_000 if _direction(metric) is Direction.LOWER_IS_BETTER else 900_000


def _cohort(
    *,
    samples: tuple[StratumSample, ...] | None = None,
    collected_at: str = "2026-09-19T00:00:00Z",
    expires_at: str = "2026-09-22T00:00:00Z",
) -> EvaluationCohort:
    distribution = DistributionBinding("eval-main", "2026.09.1", FIXED_SHA, ("api", "web"))
    return EvaluationCohort.create(
        distribution=distribution,
        samples=samples or (StratumSample("api", 500), StratumSample("web", 500)),
        collected_at=collected_at,
        expires_at=expires_at,
    )


def _observations(
    cohort: EvaluationCohort,
    role: SubjectRole,
    subject_id: str,
    subject_version: str,
    *,
    overrides: dict[MetricName, int] | None = None,
    observed_at: str = "2026-09-19T01:00:00Z",
    sample_count: int = 1_000,
    strata: tuple[str, ...] = ("api", "web"),
) -> tuple[MetricObservation, ...]:
    overrides = overrides or {}
    return tuple(
        MetricObservation.create(
            cohort_sha256=cohort.cohort_sha256,
            role=role,
            subject_id=subject_id,
            subject_version=subject_version,
            metric=metric,
            value_microunits=overrides.get(metric, _base_value(metric)),
            sample_count=sample_count,
            strata=strata,
            observed_at=observed_at,
            source_sha256=SOURCE_SHA,
        )
        for metric in sorted(MetricName, key=lambda item: item.value)
    )


def _baseline(cohort: EvaluationCohort) -> EvaluationBaseline:
    return EvaluationBaseline.create(
        cohort_sha256=cohort.cohort_sha256,
        control_id="control-model",
        control_version="5.6.1",
        distribution_artifact_sha256=cohort.distribution.artifact_sha256,
        observations=_observations(cohort, SubjectRole.CONTROL, "control-model", "5.6.1"),
        pinned_at="2026-09-19T02:00:00Z",
        expires_at="2026-09-22T00:00:00Z",
    )


def _policy(*, minimum_samples: int = 250) -> EvaluationPolicy:
    thresholds = []
    for metric in sorted(MetricName, key=lambda item: item.value):
        hard_limit = None
        if metric is MetricName.SAFETY:
            hard_limit = 850_000
        elif metric is MetricName.COST:
            hard_limit = 150_000
        thresholds.append(
            MetricThreshold(
                metric=metric,
                direction=_direction(metric),
                max_regression_microunits=20_000,
                minimum_samples=minimum_samples,
                hard_candidate_limit_microunits=hard_limit,
                critical=metric is MetricName.SAFETY,
            )
        )
    return EvaluationPolicy(
        policy_id="drift-policy",
        policy_version="1.0.0",
        thresholds=tuple(thresholds),
        required_strata=("api", "web"),
        max_evidence_age_seconds=172_800,
        min_total_samples=500,
        max_total_samples=5_000,
    )


def _assessment(
    *,
    mode: EvaluationMode = EvaluationMode.OFFLINE,
    overrides: dict[MetricName, int] | None = None,
    cohort: EvaluationCohort | None = None,
    observed_at: str = "2026-09-19T01:00:00Z",
    assessed_at: str = "2026-09-20T00:00:00Z",
    sample_count: int = 1_000,
    strata: tuple[str, ...] = ("api", "web"),
) -> DriftAssessment:
    cohort = cohort or _cohort()
    return assess_drift(
        baseline=_baseline(cohort),
        cohort=cohort,
        candidate_id="candidate-model",
        candidate_version="6.0.0",
        candidate_observations=_observations(
            cohort,
            SubjectRole.CANDIDATE,
            "candidate-model",
            "6.0.0",
            overrides=overrides,
            observed_at=observed_at,
            sample_count=sample_count,
            strata=strata,
        ),
        policy=_policy(),
        mode=mode,
        assessed_at=assessed_at,
    )


def _gates(*, same_reviewer: bool = False) -> tuple[IndependentGate, ...]:
    return (
        IndependentGate(
            GateRole.INDEPENDENT_CONTROL,
            "reviewer-control",
            "1.0",
            True,
            "2026-09-20T01:00:00Z",
            "sha256:" + "3" * 64,
        ),
        IndependentGate(
            GateRole.INDEPENDENT_ASSURANCE,
            "reviewer-control" if same_reviewer else "reviewer-assurance",
            "1.0",
            True,
            "2026-09-20T01:00:00Z",
            "sha256:" + "4" * 64,
        ),
    )


class EvaluationDriftContractsTests(unittest.TestCase):
    def test_content_addressed_round_trip_and_schema(self) -> None:
        assessment = _assessment()
        verify_assessment(assessment)
        rebuilt = DriftAssessment.from_dict(assessment.to_dict())
        self.assertEqual(rebuilt, assessment)
        self.assertEqual(assessment.outcome, AssessmentOutcome.PASS)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(assessment.to_dict())

    def test_tampering_is_rejected(self) -> None:
        raw = copy.deepcopy(_assessment().to_dict())
        raw["metric_results"][0]["candidate_value_microunits"] += 1
        with self.assertRaisesRegex(EvaluationDriftError, "identity"):
            DriftAssessment.from_dict(raw)

    def test_distribution_and_version_binding_mismatch_is_rejected(self) -> None:
        cohort = _cohort()
        baseline = _baseline(cohort)
        other = EvaluationCohort.create(
            distribution=DistributionBinding(
                "eval-main", "2026.09.2", "sha256:" + "9" * 64, ("api", "web")
            ),
            samples=(StratumSample("api", 500), StratumSample("web", 500)),
            collected_at="2026-09-19T00:00:00Z",
            expires_at="2026-09-22T00:00:00Z",
        )
        with self.assertRaisesRegex(EvaluationDriftError, "baseline and cohort"):
            assess_drift(
                baseline=baseline,
                cohort=other,
                candidate_id="candidate-model",
                candidate_version="6.0.0",
                candidate_observations=_observations(
                    other, SubjectRole.CANDIDATE, "candidate-model", "6.0.0"
                ),
                policy=_policy(),
                mode=EvaluationMode.OFFLINE,
                assessed_at="2026-09-20T00:00:00Z",
            )

    def test_missing_strata_stops_and_is_preserved(self) -> None:
        cohort = _cohort(samples=(StratumSample("api", 1_000),))
        assessment = _assessment(cohort=cohort, strata=("api",))
        self.assertEqual(assessment.outcome, AssessmentOutcome.STOPPED)
        self.assertIn("missing_required_strata", assessment.stop_reasons)
        self.assertIn("missing_observation_strata", assessment.stop_reasons)
        self.assertEqual(len(assessment.metric_results), 8)

    def test_threshold_edge_passes_and_one_microunit_over_regresses(self) -> None:
        edge = _assessment(overrides={MetricName.CORRECTNESS: 880_000})
        result = next(item for item in edge.metric_results if item.metric is MetricName.CORRECTNESS)
        self.assertEqual(result.disposition, MetricDisposition.PASS)
        over = _assessment(overrides={MetricName.CORRECTNESS: 879_999})
        result = next(item for item in over.metric_results if item.metric is MetricName.CORRECTNESS)
        self.assertEqual(over.outcome, AssessmentOutcome.REGRESSION)
        self.assertEqual(result.disposition, MetricDisposition.REGRESSION)

    def test_critical_safety_regression_stops(self) -> None:
        assessment = _assessment(overrides={MetricName.SAFETY: 849_999})
        self.assertEqual(assessment.outcome, AssessmentOutcome.STOPPED)
        self.assertIn("critical_safety_regression", assessment.stop_reasons)
        result = next(
            item for item in assessment.metric_results if item.metric is MetricName.SAFETY
        )
        self.assertEqual(result.disposition, MetricDisposition.CRITICAL_REGRESSION)

    def test_over_budget_stops(self) -> None:
        assessment = _assessment(overrides={MetricName.COST: 150_001})
        self.assertEqual(assessment.outcome, AssessmentOutcome.STOPPED)
        self.assertIn("over_budget", assessment.stop_reasons)

    def test_stale_evidence_stops(self) -> None:
        assessment = _assessment(
            observed_at="2026-09-19T01:00:00Z",
            assessed_at="2026-09-23T00:00:00Z",
        )
        self.assertEqual(assessment.outcome, AssessmentOutcome.STOPPED)
        self.assertIn("stale_evidence", assessment.stop_reasons)

    def test_sample_bounds_and_confidence_are_deterministic(self) -> None:
        cohort = _cohort(samples=(StratumSample("api", 2_501), StratumSample("web", 2_500)))
        assessment = _assessment(cohort=cohort, sample_count=250)
        self.assertIn("sample_limit_exceeded", assessment.stop_reasons)
        self.assertTrue(
            all(item.confidence is ConfidenceBand.MINIMUM for item in assessment.metric_results)
        )

    def test_shadow_mode_has_no_operational_decision_or_effects(self) -> None:
        assessment = _assessment(mode=EvaluationMode.SHADOW)
        self.assertFalse(assessment.operational_decision)
        self.assertFalse(assessment.to_dict()["operational_decision"])
        self.assertEqual(dict(assessment.effects), NO_EFFECTS)
        with self.assertRaises(TypeError):
            assessment.effects["network"] = "enabled"

    def test_canary_readiness_requires_both_independent_gates_and_rollback(self) -> None:
        assessment = _assessment(mode=EvaluationMode.CANARY_PLAN)
        plan = build_canary_progression_plan(
            assessment=assessment,
            stages=(CanaryStage(1, 100, 100), CanaryStage(2, 500, 500)),
            gates=_gates(),
            rollback_criteria=("Rollback on any safety regression",),
        )
        self.assertEqual(plan.status, CanaryPlanStatus.READY_FOR_SEPARATE_AUTHORIZATION)
        self.assertTrue(plan.to_dict()["planning_only"])
        self.assertEqual(dict(plan.effects), NO_EFFECTS)
        verify_canary_plan(plan)
        self.assertEqual(CanaryProgressionPlan.from_dict(plan.to_dict()), plan)

    def test_canary_failure_and_reviewer_separation_remain_blocked(self) -> None:
        assessment = _assessment(mode=EvaluationMode.CANARY_PLAN)
        plan = build_canary_progression_plan(
            assessment=assessment,
            stages=(CanaryStage(1, 100, 100),),
            gates=_gates(same_reviewer=True),
            rollback_criteria=("Rollback on any safety regression",),
        )
        self.assertEqual(plan.status, CanaryPlanStatus.BLOCKED)
        self.assertIn("reviewer_separation_failed", plan.blocked_reasons)

    def test_canary_nonpassing_assessment_and_missing_rollback_are_blocked(self) -> None:
        assessment = _assessment(
            mode=EvaluationMode.CANARY_PLAN,
            overrides={MetricName.CORRECTNESS: 879_999},
        )
        plan = build_canary_progression_plan(
            assessment=assessment,
            stages=(CanaryStage(1, 100, 100),),
            gates=_gates(),
            rollback_criteria=(),
        )
        self.assertEqual(plan.status, CanaryPlanStatus.BLOCKED)
        self.assertIn("assessment_not_passed", plan.blocked_reasons)
        self.assertIn("missing_rollback_criteria", plan.blocked_reasons)

    def test_secret_rejection(self) -> None:
        assessment = _assessment(mode=EvaluationMode.CANARY_PLAN)
        with self.assertRaisesRegex(EvaluationDriftError, "secret"):
            build_canary_progression_plan(
                assessment=assessment,
                stages=(CanaryStage(1, 100, 100),),
                gates=_gates(),
                rollback_criteria=("api_key=abcd1234",),
            )

    def test_canonical_json_is_stable_and_ascii(self) -> None:
        first = canonical_json({"z": "value", "a": [2, 1]})
        second = canonical_json({"a": [2, 1], "z": "value"})
        self.assertEqual(first, second)
        self.assertTrue(first.isascii())

    def test_no_runtime_effect_implementation_is_imported(self) -> None:
        source = (ROOT / "src" / "sunderkey" / "evaluation_drift_contracts.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "import requests",
            "import socket",
            "import subprocess",
            "urllib.request",
            "httpx",
            "openai",
        ):
            self.assertNotIn(forbidden, source.lower())


if __name__ == "__main__":
    unittest.main()
