from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

import sunderkey
from sunderkey.detection_validation_contracts import (
    NO_EFFECTS,
    ControlObjective,
    ControlValidationOutcome,
    CorrelationWindow,
    CoverageGap,
    DetectionValidationContract,
    DetectionValidationError,
    DetectorObservation,
    ExecutionEvidenceBinding,
    ExpectedDetection,
    IndependentValidationBinding,
    ReplaySafeValidationPlan,
    TelemetryObservationReference,
    build_replay_plan,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "detection-validation-contract-v1.schema.json"


def digest(character: str) -> str:
    return "sha256:" + character * 64


class DetectionValidationContractsPhase163Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.build_detection_replay_plan,
            build_replay_plan,
        )
        self.assertIs(
            sunderkey.DetectionValidationContract,
            DetectionValidationContract,
        )

    def binding(self) -> ExecutionEvidenceBinding:
        return ExecutionEvidenceBinding(
            assessment_id="assessment.163",
            execution_id="execution.163",
            executor_profile_id="profile.executor",
            action_tier="R1",
            scope_sha256=digest("1"),
            action_sha256=digest("2"),
            evidence_sha256=digest("3"),
            execution_started_at="2026-09-20T10:00:00Z",
            execution_completed_at="2026-09-20T10:00:10Z",
        )

    def validations(
        self, binding: ExecutionEvidenceBinding | None = None
    ) -> tuple[IndependentValidationBinding, ...]:
        source = binding or self.binding()
        common = {
            "decision": "accepted",
            "scope_sha256": source.scope_sha256,
            "action_sha256": source.action_sha256,
            "evidence_sha256": source.evidence_sha256,
            "reviewed_at": "2026-09-20T10:06:00Z",
        }
        return (
            IndependentValidationBinding(
                reviewer_profile_id="profile.control",
                reviewer_role="independent_control",
                review_sha256=digest("4"),
                **common,
            ),
            IndependentValidationBinding(
                reviewer_profile_id="profile.assurance",
                reviewer_role="independent_assurance",
                review_sha256=digest("5"),
                **common,
            ),
        )

    def contract(self, **changes: object) -> DetectionValidationContract:
        binding = changes.pop("binding", self.binding())
        objective = ControlObjective(
            objective_id="objective.alert",
            material_path_id="path.authz.1",
            control_id="control.app.waf",
            control_family="application",
            expected_effect="detect",
            control_config_sha256=digest("6"),
            required_domains=("application",),
            expectation_ids=("expectation.alert",),
        )
        expectation = ExpectedDetection(
            expectation_id="expectation.alert",
            objective_id=objective.objective_id,
            detector_id="detector.waf",
            telemetry_domain="application",
            accepted_observation_kinds=("alert",),
            maximum_latency_seconds=120,
            detector_config_sha256=digest("7"),
        )
        telemetry = TelemetryObservationReference(
            observation_id="observation.alert.1",
            source_system_id="source.siem",
            detector_id=expectation.detector_id,
            telemetry_domain="application",
            observation_kind="alert",
            observed_at="2026-09-20T10:00:20Z",
            retained_until="2026-10-20T10:00:20Z",
            artifact_sha256=digest("8"),
            custody_sha256=digest("9"),
            custody_status="durable_verified",
            scope_sha256=binding.scope_sha256,
            action_sha256=binding.action_sha256,
            evidence_sha256=binding.evidence_sha256,
        )
        detector = DetectorObservation(
            detector_observation_id="detector-observation.alert.1",
            expectation_id=expectation.expectation_id,
            detector_id=expectation.detector_id,
            observation_ids=(telemetry.observation_id,),
            disposition="true_positive",
            rationale_code="correlated_alert",
            evidence_sha256=binding.evidence_sha256,
            evaluated_at="2026-09-20T10:06:00Z",
        )
        outcome = ControlValidationOutcome(
            outcome_id="outcome.alert.1",
            objective_id=objective.objective_id,
            detector_observation_ids=(detector.detector_observation_id,),
            outcome_state="effective",
            false_positive_count=0,
            false_negative_count=0,
            evidence_sha256=binding.evidence_sha256,
        )
        values: dict[str, object] = {
            "binding": binding,
            "correlation_window": CorrelationWindow(
                opens_at="2026-09-20T09:59:50Z",
                closes_at="2026-09-20T10:05:00Z",
                maximum_lag_seconds=300,
            ),
            "objectives": (objective,),
            "expected_detections": (expectation,),
            "telemetry_observations": (telemetry,),
            "detector_observations": (detector,),
            "control_outcomes": (outcome,),
            "coverage_gaps": (),
            "independent_validations": self.validations(binding),
            "evaluated_at": "2026-09-20T10:06:00Z",
        }
        values.update(changes)
        return DetectionValidationContract(**values)

    def test_contract_and_replay_plan_round_trip_are_deterministic(self) -> None:
        first = self.contract()
        second = DetectionValidationContract.from_dict(first.to_dict())
        self.assertEqual(second, first)
        self.assertEqual(second.contract_sha256, first.contract_sha256)
        plan = build_replay_plan(first, control_change_sha256=digest("a"))
        rebuilt = ReplaySafeValidationPlan.from_dict(plan.to_dict())
        self.assertEqual(rebuilt, plan)
        self.assertEqual(rebuilt.requested_action_tier, "R0")
        self.assertEqual(rebuilt.to_dict()["effects"], dict(NO_EFFECTS))

    def test_schema_accepts_contract(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(self.contract().to_dict())

    def test_schema_rejects_unknown_fields(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        document = self.contract().to_dict()
        document["unexpected"] = True
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(document)

    def test_content_address_tamper_is_rejected(self) -> None:
        document = self.contract().to_dict()
        document["evaluated_at"] = "2026-09-20T10:07:00Z"
        with self.assertRaisesRegex(DetectionValidationError, "content address"):
            DetectionValidationContract.from_dict(document)

    def test_missing_and_unverified_custody_fail_closed(self) -> None:
        document = self.contract().to_dict()
        document["telemetry_observations"][0].pop("custody_sha256")
        with self.assertRaisesRegex(DetectionValidationError, "fields"):
            DetectionValidationContract.from_dict(document)
        document = self.contract().to_dict()
        document["telemetry_observations"][0]["custody_status"] = "best_effort"
        with self.assertRaisesRegex(DetectionValidationError, "durable_verified"):
            DetectionValidationContract.from_dict(document)

    def test_stale_and_out_of_window_telemetry_fail_closed(self) -> None:
        document = self.contract().to_dict()
        document["telemetry_observations"][0]["retained_until"] = "2026-09-20T10:05:30Z"
        with self.assertRaisesRegex(DetectionValidationError, "stale"):
            DetectionValidationContract.from_dict(document)
        document = self.contract().to_dict()
        document["telemetry_observations"][0]["observed_at"] = "2026-09-20T10:05:01Z"
        with self.assertRaisesRegex(DetectionValidationError, "outside"):
            DetectionValidationContract.from_dict(document)

    def test_late_detection_fails_closed(self) -> None:
        document = self.contract().to_dict()
        document["expected_detections"][0]["maximum_latency_seconds"] = 5
        with self.assertRaisesRegex(DetectionValidationError, "latency"):
            DetectionValidationContract.from_dict(document)

    def test_scope_action_and_evidence_hashes_are_exact(self) -> None:
        for field, replacement in (
            ("scope_sha256", digest("a")),
            ("action_sha256", digest("b")),
            ("evidence_sha256", digest("c")),
        ):
            with self.subTest(field=field):
                document = self.contract().to_dict()
                document["telemetry_observations"][0][field] = replacement
                with self.assertRaisesRegex(DetectionValidationError, "hashes"):
                    DetectionValidationContract.from_dict(document)

    def test_independent_review_hash_mismatch_fails_closed(self) -> None:
        document = self.contract().to_dict()
        document["independent_validations"][0]["action_sha256"] = digest("a")
        with self.assertRaisesRegex(DetectionValidationError, "hashes"):
            DetectionValidationContract.from_dict(document)

    def test_self_validation_and_role_aliasing_fail_closed(self) -> None:
        document = self.contract().to_dict()
        document["independent_validations"][0]["reviewer_profile_id"] = "profile.executor"
        with self.assertRaisesRegex(DetectionValidationError, "distinct"):
            DetectionValidationContract.from_dict(document)
        document = self.contract().to_dict()
        for validation in document["independent_validations"]:
            validation["reviewer_profile_id"] = "profile.shared"
        with self.assertRaisesRegex(DetectionValidationError, "distinct"):
            DetectionValidationContract.from_dict(document)

    def test_both_independent_roles_are_required(self) -> None:
        document = self.contract().to_dict()
        for validation in document["independent_validations"]:
            validation["reviewer_role"] = "independent_control"
        with self.assertRaisesRegex(DetectionValidationError, "duplicate|roles"):
            DetectionValidationContract.from_dict(document)

    def test_unapproved_live_action_claim_fails_closed(self) -> None:
        document = self.contract().to_dict()
        document["live_action_claimed"] = True
        with self.assertRaisesRegex(DetectionValidationError, "separate authorization"):
            DetectionValidationContract.from_dict(document)

    def test_approved_live_action_claim_is_evidence_only(self) -> None:
        contract = self.contract(
            live_action_claimed=True,
            live_action_authorization_sha256=digest("d"),
        )
        self.assertTrue(contract.live_action_claimed)
        self.assertEqual(contract.to_dict()["effects"], dict(NO_EFFECTS))

    def test_r0_evidence_cannot_claim_live_action(self) -> None:
        binding = ExecutionEvidenceBinding(**{**self.binding().to_dict(), "action_tier": "R0"})
        with self.assertRaisesRegex(DetectionValidationError, "R0"):
            self.contract(
                binding=binding,
                independent_validations=self.validations(binding),
                live_action_claimed=True,
                live_action_authorization_sha256=digest("d"),
            )

    def test_false_negative_requires_gap_and_derives_ineffective(self) -> None:
        base = self.contract()
        detector = DetectorObservation(
            detector_observation_id="detector-observation.alert.1",
            expectation_id="expectation.alert",
            detector_id="detector.waf",
            observation_ids=(),
            disposition="false_negative",
            rationale_code="alert_absent",
            evidence_sha256=base.binding.evidence_sha256,
            evaluated_at=base.evaluated_at,
        )
        outcome = ControlValidationOutcome(
            outcome_id="outcome.alert.1",
            objective_id="objective.alert",
            detector_observation_ids=(detector.detector_observation_id,),
            outcome_state="ineffective",
            false_positive_count=0,
            false_negative_count=1,
            evidence_sha256=base.binding.evidence_sha256,
        )
        gap = CoverageGap(
            gap_id="gap.alert.1",
            objective_id="objective.alert",
            expectation_id="expectation.alert",
            gap_kind="missing_detection",
            severity="high",
            reason_code="expected_alert_absent",
            evidence_sha256=base.binding.evidence_sha256,
        )
        contract = self.contract(
            telemetry_observations=(),
            detector_observations=(detector,),
            control_outcomes=(outcome,),
            coverage_gaps=(gap,),
        )
        self.assertEqual(contract.control_outcomes[0].outcome_state.value, "ineffective")
        with self.assertRaisesRegex(DetectionValidationError, "coverage gaps"):
            self.contract(
                telemetry_observations=(),
                detector_observations=(detector,),
                control_outcomes=(outcome,),
                coverage_gaps=(),
            )

    def test_contradictory_outcome_state_and_counts_fail_closed(self) -> None:
        for field, replacement in (
            ("outcome_state", "ineffective"),
            ("false_positive_count", 1),
            ("false_negative_count", 1),
        ):
            with self.subTest(field=field):
                document = self.contract().to_dict()
                document["control_outcomes"][0][field] = replacement
                with self.assertRaisesRegex(DetectionValidationError, "contradictory"):
                    DetectionValidationContract.from_dict(document)

    def test_observation_detector_domain_and_kind_must_match(self) -> None:
        mutations = (
            ("detector_id", "detector.other"),
            ("telemetry_domain", "network"),
            ("observation_kind", "event"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                document = self.contract().to_dict()
                document["telemetry_observations"][0][field] = replacement
                with self.assertRaises(DetectionValidationError):
                    DetectionValidationContract.from_dict(document)

    def test_objective_expected_effect_requires_matching_observation_kind(self) -> None:
        document = self.contract().to_dict()
        document["objectives"][0]["expected_effect"] = "prevent"
        with self.assertRaisesRegex(DetectionValidationError, "expected effect"):
            DetectionValidationContract.from_dict(document)

    def test_required_domains_must_be_exactly_mapped(self) -> None:
        document = self.contract().to_dict()
        document["objectives"][0]["required_domains"].append("network")
        with self.assertRaisesRegex(DetectionValidationError, "required domains"):
            DetectionValidationContract.from_dict(document)

    def test_review_and_detector_assessment_times_are_bounded(self) -> None:
        document = self.contract().to_dict()
        document["independent_validations"][0]["reviewed_at"] = "2026-09-20T10:04:59Z"
        with self.assertRaisesRegex(DetectionValidationError, "precedes"):
            DetectionValidationContract.from_dict(document)
        document = self.contract().to_dict()
        document["detector_observations"][0]["evaluated_at"] = "2026-09-20T10:04:59Z"
        with self.assertRaisesRegex(DetectionValidationError, "review interval"):
            DetectionValidationContract.from_dict(document)

    def test_effective_outcome_cannot_coexist_with_coverage_gap(self) -> None:
        base = self.contract()
        gap = CoverageGap(
            gap_id="gap.unverified.1",
            objective_id="objective.alert",
            expectation_id="expectation.alert",
            gap_kind="control_unverified",
            severity="medium",
            reason_code="control_evidence_missing",
            evidence_sha256=base.binding.evidence_sha256,
        )
        with self.assertRaisesRegex(DetectionValidationError, "effective"):
            self.contract(coverage_gaps=(gap,))

    def test_gap_kind_must_match_expected_effect(self) -> None:
        base = self.contract()
        detector = DetectorObservation(
            detector_observation_id="detector-observation.alert.1",
            expectation_id="expectation.alert",
            detector_id="detector.waf",
            observation_ids=(),
            disposition="false_negative",
            rationale_code="alert_absent",
            evidence_sha256=base.binding.evidence_sha256,
            evaluated_at=base.evaluated_at,
        )
        outcome = ControlValidationOutcome(
            outcome_id="outcome.alert.1",
            objective_id="objective.alert",
            detector_observation_ids=(detector.detector_observation_id,),
            outcome_state="ineffective",
            false_positive_count=0,
            false_negative_count=1,
            evidence_sha256=base.binding.evidence_sha256,
        )
        incompatible = CoverageGap(
            gap_id="gap.alert.1",
            objective_id="objective.alert",
            expectation_id="expectation.alert",
            gap_kind="missing_prevention",
            severity="high",
            reason_code="wrong_gap_type",
            evidence_sha256=base.binding.evidence_sha256,
        )
        with self.assertRaisesRegex(DetectionValidationError, "expected effect"):
            self.contract(
                telemetry_observations=(),
                detector_observations=(detector,),
                control_outcomes=(outcome,),
                coverage_gaps=(incompatible,),
            )

    def test_replay_plan_rejects_unapproved_live_request(self) -> None:
        contract = self.contract()
        with self.assertRaisesRegex(DetectionValidationError, "separate authorization"):
            build_replay_plan(
                contract,
                control_change_sha256=digest("a"),
                replay_mode="separately_authorized_runtime",
                requested_action_tier="R1",
                live_action_requested=True,
            )

    def test_replay_plan_rejects_non_r0_offline_action(self) -> None:
        with self.assertRaisesRegex(DetectionValidationError, "must remain R0"):
            build_replay_plan(
                self.contract(),
                control_change_sha256=digest("a"),
                requested_action_tier="R1",
            )

    def test_replay_plan_live_request_requires_explicit_mode_and_authorization(self) -> None:
        plan = build_replay_plan(
            self.contract(),
            control_change_sha256=digest("a"),
            replay_mode="separately_authorized_runtime",
            requested_action_tier="R1",
            live_action_requested=True,
            live_action_authorization_sha256=digest("b"),
        )
        self.assertTrue(plan.live_action_requested)
        self.assertEqual(plan.to_dict()["effects"], dict(NO_EFFECTS))

    def test_replay_plan_tamper_and_unknown_field_fail(self) -> None:
        plan = build_replay_plan(self.contract(), control_change_sha256=digest("a"))
        document = plan.to_dict()
        document["maximum_attempts"] = 2
        with self.assertRaisesRegex(DetectionValidationError, "content address"):
            ReplaySafeValidationPlan.from_dict(document)
        document = plan.to_dict()
        document["network"] = "allowed"
        with self.assertRaisesRegex(DetectionValidationError, "fields"):
            ReplaySafeValidationPlan.from_dict(document)

    def test_effect_tamper_fails_closed(self) -> None:
        document = self.contract().to_dict()
        document["effects"]["network"] = "performed"
        with self.assertRaisesRegex(DetectionValidationError, "effects"):
            DetectionValidationContract.from_dict(document)

    def test_secret_like_identifiers_are_rejected(self) -> None:
        with self.assertRaisesRegex(DetectionValidationError, "secret"):
            ExecutionEvidenceBinding(
                **{**self.binding().to_dict(), "executor_profile_id": "api_key:abcdefghijk"}
            )

    def test_input_sequences_are_copied_and_sorted(self) -> None:
        objective = self.contract().objectives[0]
        mutable = ["application", "network"]
        copied = ControlObjective(
            objective_id="objective.copy",
            material_path_id="path.copy",
            control_id="control.copy",
            control_family="application",
            expected_effect="detect",
            control_config_sha256=digest("c"),
            required_domains=mutable,
            expectation_ids=("expectation.copy",),
        )
        mutable.append("cloud")
        self.assertEqual(
            [item.value for item in copied.required_domains], ["application", "network"]
        )
        self.assertEqual(objective.to_dict()["required_domains"], ["application"])

    def test_serialized_document_contains_no_mutable_effects_reference(self) -> None:
        first = self.contract().to_dict()
        second = copy.deepcopy(first)
        second["effects"]["network"] = "changed"
        self.assertEqual(first["effects"], dict(NO_EFFECTS))


if __name__ == "__main__":
    unittest.main()
