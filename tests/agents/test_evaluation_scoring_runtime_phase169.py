from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.evaluation_program_contracts import (
    CORPUS_PARTITIONS,
    SCORECARD_MEASURES,
    SUBJECT_ROLES,
)
from sunderkey.evaluation_scoring_runtime import (
    METRIC_DEFINITIONS,
    METRIC_VALUE_FIELDS,
    NO_EFFECTS,
    BudgetObservation,
    ContaminationAttestation,
    ContaminationStatus,
    EvaluationCase,
    EvaluationScorecardReceipt,
    EvaluationScoringRuntimeError,
    ResultStatus,
    ScoredObservation,
    SubjectBinding,
    build_evaluation_scorecard_receipt,
    canonical_sha256,
    verify_evaluation_scorecard_receipt,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "evaluation-scorecard-receipt-v1.schema.json"


def _sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _metric_values(*, cost: int = 1_000) -> dict[str, int]:
    values = {name: 1 for name in METRIC_VALUE_FIELDS}
    values.update(
        {
            "completed_evaluation_runs": 1,
            "elapsed_milliseconds_to_first_verified_finding": 1_000,
            "evaluation_cost_micro_usd": cost,
            "unauthorized_target_actions": 0,
            "verified_attack_path_hops_milli": 3_000,
        }
    )
    return values


def _budget(*, cost: int = 1_000) -> BudgetObservation:
    return BudgetObservation(
        maximum_cost_microusd=10_000,
        maximum_latency_ms=10_000,
        maximum_requests=10,
        maximum_tokens=10_000,
        maximum_tool_calls=10,
        used_cost_microusd=cost,
        used_latency_ms=100,
        used_requests=1,
        used_tokens=100,
        used_tool_calls=1,
    )


def _inputs() -> dict[str, object]:
    cases: list[EvaluationCase] = []
    for partition_index, partition in enumerate(CORPUS_PARTITIONS):
        for run_index in range(1, 4):
            case_id = f"case-{partition_index:02d}-{run_index}"
            cases.append(
                EvaluationCase(
                    case_id=case_id,
                    case_sha256=_sha(case_id),
                    partition_type=partition,
                    repeat_group_id=f"repeat-{partition}",
                    run_index=run_index,
                )
            )
    subjects = tuple(
        SubjectBinding(
            role=role,
            subject_id=f"subject-{role}",
            subject_sha256=_sha(f"subject-{role}"),
            owner_identity_id=f"owner-{role}",
        )
        for role in SUBJECT_ROLES
    )
    attestations = tuple(
        ContaminationAttestation(
            partition_type=partition,
            status=ContaminationStatus.CLEAN,
            evidence_sha256=_sha(f"contamination-{partition}"),
            checker_identity_id="identity-contamination-checker",
            checked_at="2026-09-20T01:00:00Z",
        )
        for partition in CORPUS_PARTITIONS
    )
    observations: list[ScoredObservation] = []
    for case_index, case in enumerate(cases):
        for role_index, subject in enumerate(subjects):
            evaluator = "evaluator-a" if (case_index + role_index) % 2 == 0 else "evaluator-b"
            observations.append(
                ScoredObservation(
                    case_id=case.case_id,
                    case_sha256=case.case_sha256,
                    partition_type=case.partition_type,
                    subject_role=subject.role,
                    subject_id=subject.subject_id,
                    subject_sha256=subject.subject_sha256,
                    evaluator_identity_id=evaluator,
                    evidence_manifest_sha256=_sha(f"evidence-{case.case_id}-{subject.role}"),
                    result_status=ResultStatus.COMPLETED,
                    critical_failure_gate_ids=(),
                    budget=_budget(),
                    metric_values=_metric_values(),
                )
            )
    observations.sort(key=lambda item: (item.case_id, item.subject_role))
    return {
        "calculated_at": "2026-09-20T02:00:00Z",
        "contamination_attestations": attestations,
        "evaluation_cases": tuple(cases),
        "evaluation_program_contract_id": "EPC-0123456789ABCDEF0123456789ABCDEF",
        "evaluation_program_contract_sha256": _sha("program"),
        "evaluator_identity_ids": ("evaluator-a", "evaluator-b"),
        "minimum_cases_per_partition": 3,
        "minimum_repeated_runs": 3,
        "observations": tuple(observations),
        "regression_thresholds": {measure_id: 0 for measure_id in SCORECARD_MEASURES},
        "result_manifest_sha256": _sha("runner-result-manifest"),
        "scorecard_version": "1.0.0",
        "scoring_controller_identity_id": "identity-scoring-controller",
        "subjects": subjects,
    }


def _receipt(**changes: object) -> EvaluationScorecardReceipt:
    values = _inputs()
    values.update(changes)
    return build_evaluation_scorecard_receipt(**values)  # type: ignore[arg-type]


def _subject(raw: dict[str, object], role: str) -> dict[str, object]:
    result = raw["result"]
    assert isinstance(result, dict)
    scores = result["subject_scores"]
    assert isinstance(scores, list)
    return next(item for item in scores if item["role"] == role)


def _metric(score: dict[str, object], measure_id: str) -> dict[str, object]:
    metrics = score["metric_results"]
    assert isinstance(metrics, list)
    return next(item for item in metrics if item["measure_id"] == measure_id)


class EvaluationScoringRuntimeTests(unittest.TestCase):
    def test_boolean_or_float_schema_version_is_rejected_without_normalization(self) -> None:
        for replacement in (True, 1.0):
            changed = _receipt().to_dict()
            changed["schema_version"] = replacement
            for entry, raw in (("mapping", changed), ("json", json.dumps(changed))):
                with self.subTest(replacement=replacement, entry=entry):
                    with self.assertRaises(EvaluationScoringRuntimeError):
                        if entry == "mapping":
                            EvaluationScorecardReceipt.from_dict(raw)
                        else:
                            EvaluationScorecardReceipt.from_json(raw)

    def test_equal_boolean_or_float_calculations_are_rejected_on_import(self) -> None:
        original = _receipt()
        for field, replacement in (
            ("directional_delta", False),
            ("directional_delta", 0.0),
            ("minimum_denominator", True),
            ("minimum_denominator", 1.0),
        ):
            changed = original.to_dict()
            if field == "directional_delta":
                changed["result"]["comparisons"][0][field] = replacement
            else:
                _metric(_subject(changed, "candidate"), "ground_truth_recall")[field] = replacement
            encoded = json.dumps(changed)
            for entry, raw in (("mapping", changed), ("json", encoded)):
                with self.subTest(field=field, replacement=replacement, entry=entry):
                    with self.assertRaises(EvaluationScoringRuntimeError):
                        if entry == "mapping":
                            EvaluationScorecardReceipt.from_dict(raw)
                        else:
                            EvaluationScorecardReceipt.from_json(raw)
            with self.subTest(field=field, replacement=replacement, entry="typed_verify"):
                with self.assertRaises(EvaluationScoringRuntimeError):
                    verify_evaluation_scorecard_receipt(replace(original, document_json=encoded))

    def test_readdressed_boolean_calculation_is_not_a_valid_scorecard(self) -> None:
        changed = _receipt().to_dict()
        changed["result"]["comparisons"][0]["directional_delta"] = False
        body = copy.deepcopy(changed)
        body.pop("receipt_id")
        body.pop("receipt_sha256")
        changed["receipt_sha256"] = canonical_sha256(
            {"domain": "sunderkey.evaluation-scorecard-receipt.v1", "content": body}
        )
        changed["receipt_id"] = f"ESR-{changed['receipt_sha256'][7:39].upper()}"
        with self.assertRaises(EvaluationScoringRuntimeError):
            EvaluationScorecardReceipt.from_dict(changed)

    def test_complete_receipt_is_deterministic_schema_valid_and_non_promoting(self) -> None:
        receipt = _receipt()
        again = _receipt()
        self.assertEqual(receipt, again)
        verify_evaluation_scorecard_receipt(receipt)
        self.assertEqual(receipt, EvaluationScorecardReceipt.from_json(receipt.document_json))

        raw = receipt.to_dict()
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(raw)
        self.assertEqual(raw["effects"], dict(NO_EFFECTS))
        self.assertEqual(raw["result"]["evidence_status"], "complete")
        self.assertEqual(raw["result"]["candidate_disposition"], "scored_pass")
        self.assertEqual(raw["result"]["promotion_disposition"], "independent_review_required")
        self.assertEqual(raw["result"]["qualification_effect"], "none")
        self.assertEqual(raw["result"]["independent_review_location"], "outside_runtime")

    def test_exact_metric_formulas_and_budget_normalization(self) -> None:
        raw = _receipt().to_dict()
        candidate = _subject(raw, "candidate")
        self.assertEqual(
            _metric(candidate, "ground_truth_recall")["value"],
            10_000,
        )
        self.assertEqual(_metric(candidate, "attack_path_depth")["value"], 3_000)
        self.assertEqual(_metric(candidate, "time_to_first_verified_finding")["value"], 1_000)
        self.assertEqual(_metric(candidate, "cost_per_verified_finding")["value"], 1_000)
        self.assertEqual(
            candidate["budget_summary"],
            {
                "maximum_cost_microusd": 150_000,
                "normalized_cost_basis_points": 1_000,
                "used_cost_microusd": 15_000,
            },
        )
        self.assertTrue(
            all(
                metric["confidence_status"] == "sufficient"
                for metric in candidate["metric_results"]
            )
        )

    def test_directional_comparison_detects_candidate_cost_regression(self) -> None:
        inputs = _inputs()
        observations = []
        for item in inputs["observations"]:  # type: ignore[union-attr]
            if item.subject_role == "candidate":
                observations.append(
                    replace(
                        item,
                        budget=_budget(cost=2_000),
                        metric_values=_metric_values(cost=2_000),
                    )
                )
            else:
                observations.append(item)
        raw = _receipt(observations=tuple(observations)).to_dict()
        comparisons = raw["result"]["comparisons"]
        cost_comparisons = [
            item for item in comparisons if item["measure_id"] == "cost_per_verified_finding"
        ]
        self.assertTrue(all(item["directional_delta"] == -1_000 for item in cost_comparisons))
        self.assertTrue(all(item["status"] == "regression" for item in cost_comparisons))
        self.assertEqual(raw["result"]["candidate_disposition"], "regression")
        self.assertEqual(raw["result"]["promotion_disposition"], "blocked")

    def test_score_failure_is_distinct_from_incomplete_and_invalid_evidence(self) -> None:
        inputs = _inputs()
        observations = []
        for item in inputs["observations"]:  # type: ignore[union-attr]
            if item.subject_role == "candidate":
                values = dict(item.metric_values or {})
                values["reproduced_ground_truth_findings"] = 0
                observations.append(replace(item, metric_values=values))
            else:
                observations.append(item)
        failed = _receipt(observations=tuple(observations)).to_dict()
        self.assertEqual(failed["result"]["evidence_status"], "complete")
        self.assertEqual(failed["result"]["candidate_disposition"], "scored_fail")

        incomplete = _receipt(observations=tuple(observations[:-1])).to_dict()
        self.assertEqual(incomplete["result"]["evidence_status"], "insufficient")
        self.assertEqual(incomplete["result"]["candidate_disposition"], "insufficient_evidence")

        no_candidate = tuple(
            item
            for item in inputs["observations"]  # type: ignore[union-attr]
            if item.subject_role != "candidate"
        )
        absent = _receipt(observations=no_candidate).to_dict()
        self.assertEqual(absent["result"]["evidence_status"], "insufficient")
        self.assertEqual(_subject(absent, "candidate")["observation_count"], 0)
        self.assertEqual(_subject(absent, "candidate")["disposition"], "insufficient_evidence")

        attestations = list(inputs["contamination_attestations"])  # type: ignore[arg-type]
        attestations[1] = replace(attestations[1], status=ContaminationStatus.CONTAMINATED)
        invalid = _receipt(contamination_attestations=tuple(attestations)).to_dict()
        self.assertEqual(invalid["result"]["evidence_status"], "invalid")
        self.assertEqual(invalid["result"]["candidate_disposition"], "invalid_evidence")

    def test_failed_abstained_and_unknown_contamination_are_insufficient(self) -> None:
        inputs = _inputs()
        observations = list(inputs["observations"])  # type: ignore[arg-type]
        observations[0] = replace(
            observations[0],
            result_status=ResultStatus.ABSTAINED,
            metric_values=None,
        )
        attestations = list(inputs["contamination_attestations"])  # type: ignore[arg-type]
        attestations[0] = replace(attestations[0], status=ContaminationStatus.UNKNOWN)
        raw = _receipt(
            observations=tuple(observations),
            contamination_attestations=tuple(attestations),
        ).to_dict()
        self.assertEqual(raw["result"]["evidence_status"], "insufficient")
        self.assertTrue(raw["result"]["insufficiency_reason_codes"])
        score = _subject(raw, observations[0].subject_role)
        self.assertEqual(score["disposition"], "insufficient_evidence")
        self.assertTrue(
            any(item["confidence_status"] == "insufficient" for item in score["metric_results"])
        )

    def test_safety_failure_and_critical_metric_threshold_are_hard_stops(self) -> None:
        inputs = _inputs()
        observations = list(inputs["observations"])  # type: ignore[arg-type]
        candidate_index = next(
            index for index, item in enumerate(observations) if item.subject_role == "candidate"
        )
        observations[candidate_index] = replace(
            observations[candidate_index],
            result_status=ResultStatus.SAFETY_FAILURE,
            critical_failure_gate_ids=("qualification.gate.scope-authority",),
            metric_values=None,
        )
        safety = _receipt(observations=tuple(observations)).to_dict()
        self.assertEqual(safety["result"]["candidate_disposition"], "hard_failure")
        candidate = _subject(safety, "candidate")
        self.assertIn("qualification.gate.scope-authority", candidate["hard_failure_gate_ids"])

        observations = list(inputs["observations"])  # type: ignore[arg-type]
        for index, item in enumerate(observations):
            if item.subject_role == "candidate":
                values = dict(item.metric_values or {})
                values["verified_cleanup_obligations"] = 0
                observations[index] = replace(item, metric_values=values)
        cleanup = _receipt(observations=tuple(observations)).to_dict()
        self.assertEqual(cleanup["result"]["candidate_disposition"], "hard_failure")
        self.assertEqual(
            _metric(_subject(cleanup, "candidate"), "cleanup_completion")["outcome"],
            "hard_stop",
        )

    def test_budget_pairing_excess_and_cost_mismatch_are_invalid(self) -> None:
        inputs = _inputs()
        observations = list(inputs["observations"])  # type: ignore[arg-type]
        observations[0] = replace(
            observations[0],
            budget=replace(observations[0].budget, maximum_requests=1, used_requests=2),
        )
        raw = _receipt(observations=tuple(observations)).to_dict()
        self.assertEqual(raw["result"]["evidence_status"], "invalid")
        self.assertTrue(
            any(
                code.startswith("budget_exceeded:")
                for code in raw["result"]["invalid_reason_codes"]
            )
        )
        self.assertTrue(
            any(
                code.startswith("unpaired_budget:")
                for code in raw["result"]["invalid_reason_codes"]
            )
        )

        observations = list(inputs["observations"])  # type: ignore[arg-type]
        observations[0] = replace(
            observations[0], budget=replace(observations[0].budget, used_cost_microusd=999)
        )
        mismatch = _receipt(observations=tuple(observations)).to_dict()
        self.assertTrue(
            any(
                code.startswith("cost_observation_mismatch:")
                for code in mismatch["result"]["invalid_reason_codes"]
            )
        )

    def test_partition_sample_repeat_and_identity_separation_are_enforced(self) -> None:
        inputs = _inputs()
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "sample minimum"):
            _receipt(minimum_cases_per_partition=4)
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "comparison policy"):
            _receipt(minimum_repeated_runs=4)
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "identities must be separate"):
            _receipt(scoring_controller_identity_id="evaluator-a")

        subjects = list(inputs["subjects"])  # type: ignore[arg-type]
        subjects[0] = replace(subjects[0], owner_identity_id="evaluator-a")
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "identities must be separate"):
            _receipt(subjects=tuple(subjects))

    def test_subject_case_evaluator_and_metric_source_bindings_fail_closed(self) -> None:
        inputs = _inputs()
        observations = list(inputs["observations"])  # type: ignore[arg-type]
        observations[0] = replace(observations[0], case_sha256=_sha("wrong-case"))
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "crosses"):
            _receipt(observations=tuple(observations))

        observations = list(inputs["observations"])  # type: ignore[arg-type]
        observations[0] = replace(observations[0], evaluator_identity_id="unknown-evaluator")
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "not authorized"):
            _receipt(observations=tuple(observations))

        raw = inputs["observations"][0].to_dict()  # type: ignore[index,union-attr]
        raw["metric_values"].pop("verified_findings")
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "every exact metric"):
            ScoredObservation.from_dict(raw)

    def test_receipt_tampering_and_extra_fields_are_rejected(self) -> None:
        receipt = _receipt()
        raw = receipt.to_dict()
        raw["result"]["candidate_disposition"] = "scored_fail"
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "content or identity"):
            EvaluationScorecardReceipt.from_dict(raw)

        raw = receipt.to_dict()
        raw["unexpected"] = True
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "fields"):
            EvaluationScorecardReceipt.from_dict(raw)

        raw = receipt.to_dict()
        raw["receipt_sha256"] = _sha("tampered")
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "content or identity"):
            EvaluationScorecardReceipt.from_dict(raw)

    def test_content_identity_binds_all_inputs_and_metric_definitions(self) -> None:
        receipt = _receipt()
        raw = receipt.to_dict()
        self.assertEqual(
            raw["result"]["metric_definition_sha256"],
            canonical_sha256(list(METRIC_DEFINITIONS)),
        )
        changed = _receipt(calculated_at="2026-09-20T02:00:01Z")
        self.assertNotEqual(receipt.receipt_id, changed.receipt_id)
        self.assertNotEqual(receipt.receipt_sha256, changed.receipt_sha256)

    def test_parser_rejects_noncanonical_shapes_and_receipt_is_printable_ascii(self) -> None:
        raw = _receipt().to_dict()
        observation = copy.deepcopy(raw["observations"][0])
        observation["extra"] = "forbidden"
        with self.assertRaisesRegex(EvaluationScoringRuntimeError, "fields"):
            ScoredObservation.from_dict(observation)
        encoded = _receipt().document_json.encode("ascii")
        self.assertEqual(encoded.decode("ascii"), _receipt().document_json)

    def test_public_package_exports_scoring_boundary(self) -> None:
        self.assertIs(
            sunderkey.build_evaluation_scorecard_receipt,
            build_evaluation_scorecard_receipt,
        )
        self.assertIs(
            sunderkey.verify_evaluation_scorecard_receipt,
            verify_evaluation_scorecard_receipt,
        )
        self.assertIs(
            sunderkey.canonical_evaluation_scorecard_sha256,
            canonical_sha256,
        )


if __name__ == "__main__":
    unittest.main()
