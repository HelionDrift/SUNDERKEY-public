from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.evaluation_runner_contracts import (
    BINDING_KINDS,
    COMPARISON_ROLES,
    NO_EFFECTS,
    AggregateRunObservation,
    AggregateStatus,
    ArtifactBinding,
    Assessment,
    CaseAssignment,
    ComparisonInput,
    ComparisonObservationReference,
    CompletionStatus,
    ContaminationAttestation,
    EvaluationRunnerContractError,
    EvaluationRunPlan,
    EvidenceItem,
    EvidenceManifest,
    ExecutionResultEnvelope,
    IndependentReview,
    ReadinessStatus,
    ResultStatus,
    ReviewDecision,
    RunnerBudget,
    RunnerIdentities,
    UsageObservation,
    aggregate_results,
    assess_completion,
    assess_readiness,
    build_comparison_input,
    build_result_envelope,
    build_run_plan,
    canonical_sha256,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "src" / "sunderkey" / "evaluation_runner_contracts.py"
TEST_PATH = ROOT / "tests" / "agents" / "test_evaluation_runner_contracts_phase166.py"
SCHEMA_PATH = ROOT / "registry" / "schemas" / "evaluation-runner-contract-v1.schema.json"
DOC_PATH = ROOT / "docs" / "evaluation-runner-contracts.md"


def _sha(index: int) -> str:
    return "sha256:" + format(index % 16, "x") * 64


def _bindings() -> tuple[ArtifactBinding, ...]:
    return tuple(
        ArtifactBinding(kind, f"artifact-{kind}", "1.0.0", _sha(index))
        for index, kind in enumerate(BINDING_KINDS, start=1)
    )


def _identities() -> RunnerIdentities:
    return RunnerIdentities(
        "identity-candidate-owner",
        "identity-corpus-custodian",
        "identity-execution-controller",
        "identity-ground-truth-custodian",
        "identity-plan-author",
        ("identity-evaluator-a", "identity-evaluator-b"),
        ("identity-reviewer-a", "identity-reviewer-b"),
    )


def _assignments() -> tuple[CaseAssignment, ...]:
    return (
        CaseAssignment("assignment-a", "case-a", _sha(12), "identity-evaluator-a", "private"),
        CaseAssignment("assignment-b", "case-b", _sha(13), "identity-evaluator-b", "safety"),
        CaseAssignment("assignment-c", "case-c", _sha(14), "identity-evaluator-a", "regression"),
    )


def _plan(**overrides: object) -> EvaluationRunPlan:
    bindings = _bindings()
    values: dict[str, object] = {
        "plan_version": "1.0.0",
        "bindings": bindings,
        "budget": RunnerBudget(10_000, 10_000, 30, 30_000, 30),
        "identities": _identities(),
        "assignments": _assignments(),
        "contamination_attestation": ContaminationAttestation(
            bindings[0].sha256,
            bindings[6].sha256,
            "1.0.0",
            _sha(15),
            "2026-09-20T11:00:00Z",
            "clean",
        ),
        "idempotency_key": "run-key-1",
        "replay_epoch": 1,
    }
    values.update(overrides)
    return build_run_plan(**values)  # type: ignore[arg-type]


def _manifest(case_id: str, index: int) -> EvidenceManifest:
    return EvidenceManifest.build(
        (EvidenceItem(f"evidence-{case_id}", _sha(index), "application/json", 100),)
    )


def _result(
    plan: EvaluationRunPlan,
    case_id: str,
    index: int,
    *,
    status: ResultStatus = ResultStatus.COMPLETED,
    hard_failure_codes: tuple[str, ...] = (),
    usage: UsageObservation | None = None,
) -> ExecutionResultEnvelope:
    return build_result_envelope(
        plan=plan,
        case_id=case_id,
        idempotency_key=f"result-key-{case_id}",
        replay_nonce=f"nonce-{case_id}",
        status=status,
        hard_failure_codes=hard_failure_codes,
        usage=usage or UsageObservation(100, 200, 1, 1000, 1),
        evidence_manifest=_manifest(case_id, index),
        observed_at="2026-09-20T12:00:00Z",
    )


def _results(plan: EvaluationRunPlan) -> tuple[ExecutionResultEnvelope, ...]:
    return tuple(
        _result(plan, assignment.case_id, index)
        for index, assignment in enumerate(plan.assignments, start=1)
    )


def _reviews(observation: AggregateRunObservation) -> tuple[IndependentReview, ...]:
    return tuple(
        IndependentReview(
            observation.observation_id,
            observation.observation_sha256,
            reviewer,
            ReviewDecision.ACCEPTED,
            _sha(index + 8),
            "2026-09-20T13:00:00Z",
        )
        for index, reviewer in enumerate(("identity-reviewer-a", "identity-reviewer-b"), start=1)
    )


class EvaluationRunnerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = _plan()
        self.results = _results(self.plan)
        self.observation = aggregate_results(self.plan, self.results)

    def assert_schema(self, value: object) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_plan_is_deterministic_content_addressed_and_schema_valid(self) -> None:
        rebuilt = _plan(assignments=tuple(reversed(_assignments())))
        self.assertEqual(self.plan, rebuilt)
        self.assertEqual(self.plan, EvaluationRunPlan.from_json(self.plan.document_json))
        self.assertEqual(self.plan, parse_contract(self.plan.document_json))
        self.assert_schema(self.plan.to_dict())
        self.assertEqual(tuple(item.kind for item in self.plan.bindings), BINDING_KINDS)
        self.assertEqual(
            self.plan.fixed_membership_sha256,
            canonical_sha256([item.to_dict() for item in self.plan.assignments]),
        )

    def test_exact_binding_versions_and_hashes_are_mandatory(self) -> None:
        for moving in ("latest", "main", "head", "*"):
            with self.subTest(moving=moving), self.assertRaises(EvaluationRunnerContractError):
                ArtifactBinding("model", "model-a", moving, _sha(1))
        with self.assertRaises(EvaluationRunnerContractError):
            _plan(bindings=_bindings()[:-1])
        changed = list(_bindings())
        changed[-1] = replace(changed[-1], kind="candidate")
        with self.assertRaises(EvaluationRunnerContractError):
            _plan(bindings=changed)
        with self.assertRaises(EvaluationRunnerContractError):
            ArtifactBinding("model", "model-a", "1.0.0", "bad")

    def test_fixed_membership_and_assignment_boundaries_fail_closed(self) -> None:
        with self.assertRaises(EvaluationRunnerContractError):
            _plan(assignments=())
        duplicate_case = (*_assignments(), replace(_assignments()[0], assignment_id="assignment-z"))
        with self.assertRaises(EvaluationRunnerContractError):
            _plan(assignments=duplicate_case)
        outsider = replace(_assignments()[0], evaluator_id="identity-outsider")
        with self.assertRaises(EvaluationRunnerContractError):
            _plan(assignments=(outsider, *_assignments()[1:]))
        tampered = self.plan.to_dict()
        tampered["fixed_membership_sha256"] = _sha(9)
        with self.assertRaises(EvaluationRunnerContractError):
            EvaluationRunPlan.from_dict(tampered)

    def test_contamination_status_and_exact_candidate_corpus_context_are_required(self) -> None:
        bindings = _bindings()
        with self.assertRaises(EvaluationRunnerContractError):
            ContaminationAttestation(
                bindings[0].sha256,
                bindings[6].sha256,
                "1.0.0",
                _sha(15),
                "2026-09-20T11:00:00Z",
                "contaminated",
            )
        mismatched = ContaminationAttestation(
            _sha(15),
            bindings[6].sha256,
            "1.0.0",
            _sha(14),
            "2026-09-20T11:00:00Z",
            "clean",
        )
        with self.assertRaises(EvaluationRunnerContractError):
            _plan(contamination_attestation=mismatched)
        tampered = self.plan.to_dict()
        tampered["contamination_attestation"]["report_sha256"] = _sha(1)
        with self.assertRaises(EvaluationRunnerContractError):
            EvaluationRunPlan.from_dict(tampered)

    def test_identity_separation_and_reviewer_order_are_enforced(self) -> None:
        values = _identities().to_dict()
        values["execution_controller_id"] = values["candidate_owner_id"]
        with self.assertRaises(EvaluationRunnerContractError):
            RunnerIdentities.from_dict(values)
        values = _identities().to_dict()
        values["evaluator_ids"] = ["identity-evaluator-b", "identity-evaluator-a"]
        with self.assertRaises(EvaluationRunnerContractError):
            RunnerIdentities.from_dict(values)
        values = _identities().to_dict()
        values["reviewer_ids"] = ["identity-reviewer-b", "identity-reviewer-a"]
        with self.assertRaises(EvaluationRunnerContractError):
            RunnerIdentities.from_dict(values)
        values = _identities().to_dict()
        values["reviewer_ids"] = ["identity-reviewer-a"]
        with self.assertRaises(EvaluationRunnerContractError):
            RunnerIdentities.from_dict(values)

    def test_readiness_is_non_authorizing(self) -> None:
        assessment = assess_readiness(self.plan)
        self.assertEqual(assessment.status, ReadinessStatus.READY_FOR_SEPARATE_EXECUTION)
        self.assertEqual(assessment.reason_codes, ())
        self.assertEqual(assessment, parse_contract(json.dumps(assessment.to_dict())))
        self.assert_schema(assessment.to_dict())
        self.assertEqual(assessment.to_dict()["effects"], dict(NO_EFFECTS))

    def test_result_import_round_trip_and_exact_evidence_manifest(self) -> None:
        result = self.results[0]
        self.assertEqual(result, ExecutionResultEnvelope.from_dict(result.to_dict()))
        self.assertEqual(result, parse_contract(json.dumps(result.to_dict())))
        self.assert_schema(result.to_dict())
        changed = result.to_dict()
        changed["evidence_manifest"]["items"][0]["size_bytes"] = 101
        with self.assertRaises(EvaluationRunnerContractError):
            ExecutionResultEnvelope.from_dict(changed)

    def test_unknown_case_and_status_failure_mismatch_are_rejected(self) -> None:
        with self.assertRaises(EvaluationRunnerContractError):
            _result(self.plan, "case-unknown", 4)
        with self.assertRaises(EvaluationRunnerContractError):
            _result(
                self.plan,
                "case-a",
                4,
                status=ResultStatus.SAFETY_FAILURE,
                hard_failure_codes=(),
            )
        with self.assertRaises(EvaluationRunnerContractError):
            _result(
                self.plan,
                "case-a",
                4,
                status=ResultStatus.COMPLETED,
                hard_failure_codes=("unauthorized_action",),
            )

    def test_failed_and_abstained_cases_remain_in_denominator(self) -> None:
        results = list(self.results)
        results[0] = _result(self.plan, "case-a", 1, status=ResultStatus.FAILED)
        results[1] = _result(self.plan, "case-b", 2, status=ResultStatus.ABSTAINED)
        observation = aggregate_results(self.plan, results)
        self.assertEqual(sum(observation.status_counts.values()), len(self.plan.assignments))
        self.assertEqual(observation.status_counts["failed"], 1)
        self.assertEqual(observation.status_counts["abstained"], 1)
        self.assertEqual(observation.status, AggregateStatus.COMPLETE)

    def test_missing_posthoc_exclusion_and_duplicate_cases_are_rejected(self) -> None:
        with self.assertRaises(EvaluationRunnerContractError):
            aggregate_results(self.plan, self.results[:-1])
        with self.assertRaises(EvaluationRunnerContractError):
            aggregate_results(self.plan, (*self.results[:-1], self.results[0]))

    def test_idempotency_and_replay_protection_are_enforced(self) -> None:
        duplicate_key = build_result_envelope(
            plan=self.plan,
            case_id="case-b",
            idempotency_key=self.results[0].idempotency_key,
            replay_nonce="nonce-case-b",
            status=ResultStatus.COMPLETED,
            hard_failure_codes=(),
            usage=UsageObservation(100, 200, 1, 1000, 1),
            evidence_manifest=_manifest("case-b", 2),
            observed_at="2026-09-20T12:00:00Z",
        )
        with self.assertRaises(EvaluationRunnerContractError):
            aggregate_results(self.plan, (self.results[0], duplicate_key, self.results[2]))
        duplicate_nonce = build_result_envelope(
            plan=self.plan,
            case_id="case-b",
            idempotency_key="result-key-case-b",
            replay_nonce=self.results[0].replay_nonce,
            status=ResultStatus.COMPLETED,
            hard_failure_codes=(),
            usage=UsageObservation(100, 200, 1, 1000, 1),
            evidence_manifest=_manifest("case-b", 2),
            observed_at="2026-09-20T12:00:00Z",
        )
        with self.assertRaises(EvaluationRunnerContractError):
            aggregate_results(self.plan, (self.results[0], duplicate_nonce, self.results[2]))
        replayed_epoch = self.results[0].to_dict()
        replayed_epoch["replay_epoch"] = 2
        with self.assertRaises(EvaluationRunnerContractError):
            ExecutionResultEnvelope.from_dict(replayed_epoch)

    def test_cross_context_and_tampering_are_rejected(self) -> None:
        other = _plan(idempotency_key="run-key-2", replay_epoch=2)
        foreign = _result(other, "case-a", 1)
        with self.assertRaises(EvaluationRunnerContractError):
            aggregate_results(self.plan, (foreign, *self.results[1:]))
        changed = self.results[0].to_dict()
        changed["usage"]["tokens"] += 1
        with self.assertRaises(EvaluationRunnerContractError):
            ExecutionResultEnvelope.from_dict(changed)
        changed = self.plan.to_dict()
        changed["bindings"][0]["sha256"] = _sha(15)
        with self.assertRaises(EvaluationRunnerContractError):
            EvaluationRunPlan.from_dict(changed)

    def test_each_budget_dimension_has_a_hard_boundary(self) -> None:
        cases = (
            ("cost_microusd", UsageObservation(10_001, 1, 1, 1, 1)),
            ("latency_ms", UsageObservation(1, 10_001, 1, 1, 1)),
            ("requests", UsageObservation(1, 1, 31, 1, 1)),
            ("tokens", UsageObservation(1, 1, 1, 30_001, 1)),
            ("tool_calls", UsageObservation(1, 1, 1, 1, 31)),
        )
        for label, usage in cases:
            with self.subTest(label=label), self.assertRaises(EvaluationRunnerContractError):
                values = list(self.results)
                values[0] = _result(self.plan, "case-a", 1, usage=usage)
                aggregate_results(self.plan, values)

    def test_aggregate_is_deterministic_complete_and_schema_valid(self) -> None:
        reversed_result = aggregate_results(self.plan, tuple(reversed(self.results)))
        self.assertEqual(self.observation, reversed_result)
        self.assertEqual(
            self.observation,
            AggregateRunObservation.from_dict(self.observation.to_dict()),
        )
        self.assertEqual(
            self.observation,
            parse_contract(json.dumps(self.observation.to_dict())),
        )
        self.assert_schema(self.observation.to_dict())
        self.assertEqual(self.observation.status, AggregateStatus.COMPLETE)

    def test_hard_safety_failure_is_terminal_and_never_averaged_away(self) -> None:
        results = list(self.results)
        results[0] = _result(
            self.plan,
            "case-a",
            1,
            status=ResultStatus.SAFETY_FAILURE,
            hard_failure_codes=("unauthorized_target_action",),
        )
        observation = aggregate_results(self.plan, results)
        self.assertEqual(observation.status, AggregateStatus.COMPLETE_WITH_HARD_FAILURE)
        completion = assess_completion(self.plan, observation, _reviews(observation))
        self.assertEqual(completion.status, CompletionStatus.HARD_SAFETY_FAILURE)
        self.assertIn("hard_safety_failure", completion.reason_codes)

    def test_completion_requires_two_independent_bound_reviews(self) -> None:
        reviews = _reviews(self.observation)
        completion = assess_completion(self.plan, self.observation, reviews)
        self.assertEqual(completion.status, CompletionStatus.READY_FOR_COMPARISON)
        self.assertEqual(completion, Assessment.from_dict(completion.to_dict()))
        self.assert_schema(completion.to_dict())
        missing = assess_completion(self.plan, self.observation, reviews[:1])
        self.assertEqual(missing.status, CompletionStatus.INCOMPLETE)
        duplicate = assess_completion(self.plan, self.observation, (reviews[0], reviews[0]))
        self.assertEqual(duplicate.status, CompletionStatus.INCOMPLETE)
        rejected = replace(reviews[0], decision=ReviewDecision.REJECTED)
        denied = assess_completion(self.plan, self.observation, (rejected, reviews[1]))
        self.assertEqual(denied.status, CompletionStatus.REVIEW_REJECTED)

    def test_review_cross_context_and_unassigned_reviewer_fail_closed(self) -> None:
        reviews = list(_reviews(self.observation))
        reviews[0] = replace(reviews[0], observation_sha256=_sha(15))
        result = assess_completion(self.plan, self.observation, reviews)
        self.assertEqual(result.status, CompletionStatus.INCOMPLETE)
        reviews = list(_reviews(self.observation))
        reviews[0] = replace(reviews[0], reviewer_id="identity-outsider")
        result = assess_completion(self.plan, self.observation, reviews)
        self.assertEqual(result.status, CompletionStatus.INCOMPLETE)

    def test_comparison_input_requires_all_roles_and_exact_shared_context(self) -> None:
        references = tuple(
            ComparisonObservationReference(
                role,
                "1.0.0",
                f"observation-{role}",
                _sha(index),
                self.plan.fixed_membership_sha256,
                _bindings()[6].sha256,
                _bindings()[5].sha256,
                _bindings()[8].sha256,
                _bindings()[9].sha256,
                f"assessment-{role}",
                _sha(index + 8),
                CompletionStatus.READY_FOR_COMPARISON.value,
            )
            for index, role in enumerate(COMPARISON_ROLES, start=1)
        )
        comparison = build_comparison_input(references)
        self.assertEqual(comparison, ComparisonInput.from_dict(comparison.to_dict()))
        self.assertEqual(comparison, parse_contract(json.dumps(comparison.to_dict())))
        self.assert_schema(comparison.to_dict())
        with self.assertRaises(EvaluationRunnerContractError):
            build_comparison_input(references[:-1])
        changed = list(references)
        changed[-1] = replace(changed[-1], corpus_sha256=_sha(15))
        with self.assertRaises(EvaluationRunnerContractError):
            build_comparison_input(changed)
        with self.assertRaises(EvaluationRunnerContractError):
            replace(references[-1], completion_status="incomplete")

    def test_unknown_fields_noncanonical_effects_and_unknown_types_fail(self) -> None:
        changed = self.plan.to_dict()
        changed["unexpected"] = True
        with self.assertRaises(EvaluationRunnerContractError):
            EvaluationRunPlan.from_dict(changed)
        changed = self.plan.to_dict()
        changed["effects"]["network"] = "performed"
        with self.assertRaises(EvaluationRunnerContractError):
            EvaluationRunPlan.from_dict(changed)
        with self.assertRaises(EvaluationRunnerContractError):
            parse_contract('{"contract_type":"unknown"}')

    def test_schema_rejects_tampering_and_extra_fields(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for document in (
            self.plan.to_dict(),
            self.results[0].to_dict(),
            self.observation.to_dict(),
            assess_completion(self.plan, self.observation, _reviews(self.observation)).to_dict(),
        ):
            changed = copy.deepcopy(document)
            changed["unexpected"] = True
            self.assertTrue(list(validator.iter_errors(changed)))

    def test_files_have_no_markers_or_unicode_dashes(self) -> None:
        marker_terms = (
            "generated" + " by",
            "written" + " by ai",
            "written" + " by an ai",
            "as" + " an ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in (MODULE_PATH, TEST_PATH, SCHEMA_PATH, DOC_PATH):
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            self.assertFalse(any(term in lowered for term in marker_terms), path)
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)

    def test_no_effects_are_exact_and_runtime_clients_do_not_exist(self) -> None:
        self.assertEqual(set(NO_EFFECTS.values()), {"none"})
        for value in (
            self.plan,
            self.results[0],
            self.observation,
            assess_readiness(self.plan),
            assess_completion(self.plan, self.observation, _reviews(self.observation)),
        ):
            self.assertEqual(value.to_dict()["effects"], dict(NO_EFFECTS))
        source = MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
            "urllib.request",
            "openai.",
        ):
            self.assertNotIn(forbidden, source)

    def test_public_package_exports_runner_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.EvaluationRunPlan, EvaluationRunPlan)
        self.assertIs(sunderkey.build_evaluation_runner_plan, build_run_plan)
        self.assertIs(sunderkey.aggregate_evaluation_runner_results, aggregate_results)
        self.assertIs(sunderkey.parse_evaluation_runner_contract, parse_contract)


if __name__ == "__main__":
    unittest.main()
