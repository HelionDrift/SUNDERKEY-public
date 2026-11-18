from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None  # type: ignore[assignment,misc]

import sunderkey
from sunderkey.defender_replay_harness import (
    NO_BUILTIN_NETWORK,
    NO_BUILTIN_PROVIDER_CALLS,
    NO_EFFECTS,
    NO_FILESYSTEM_DISCOVERY,
    NO_TARGET_ACTIONS,
    QUALIFICATION_EFFECT,
    RUNTIME_STATUS,
    AssessmentEvidenceBinding,
    DefenderReplayError,
    DetectionCorrelationBinding,
    DetectionExpectation,
    EvaluationContractBinding,
    FindingFixture,
    IndependentReplayReview,
    ReplayContext,
    ReplayRequest,
    SourceAvailability,
    TelemetryFixture,
    assess_replay_promotion,
    canonical_json,
    parse_defender_replay_receipt,
    run_defender_replay,
    verify_defender_replay_receipt,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "defender-replay-receipt-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "defender_replay_harness.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "defender-replay-harness.md",
)

ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
TWO = "sha256:" + "2" * 64
THREE = "sha256:" + "3" * 64
FOUR = "sha256:" + "4" * 64
FIVE = "sha256:" + "5" * 64
SIX = "sha256:" + "6" * 64
SEVEN = "sha256:" + "7" * 64
EIGHT = "sha256:" + "8" * 64
NINE = "sha256:" + "9" * 64


class DefenderReplayHarnessTests(unittest.TestCase):
    def context(self, **changes: object) -> ReplayContext:
        values: dict[str, object] = {
            "tenant_ref": "tenantref:alpha",
            "engagement_ref": "engagementref:assessment-01",
            "context_ref": "contextref:defender-replay-01",
            "scope_sha256": ZERO,
            "corpus_sha256": ONE,
            "provenance_policy_sha256": TWO,
        }
        values.update(changes)
        return ReplayContext(**values)  # type: ignore[arg-type]

    def assessment(self, **changes: object) -> AssessmentEvidenceBinding:
        values: dict[str, object] = {
            "tenant_ref": "tenantref:alpha",
            "engagement_ref": "engagementref:assessment-01",
            "context_ref": "contextref:defender-replay-01",
            "scope_sha256": ZERO,
            "assessment_ref": "assessmentref:offline-01",
            "assessment_sha256": THREE,
            "evidence_manifest_sha256": FOUR,
            "custody_sha256": FIVE,
            "completed_at": "2026-09-20T12:00:00Z",
        }
        values.update(changes)
        return AssessmentEvidenceBinding(**values)  # type: ignore[arg-type]

    def evaluation(self, **changes: object) -> EvaluationContractBinding:
        values: dict[str, object] = {
            "program_id": "EVP-" + "A" * 32,
            "program_sha256": SIX,
            "run_plan_id": "ERP-" + "B" * 32,
            "run_plan_sha256": SEVEN,
            "scoring_policy_sha256": EIGHT,
            "corpus_assembly_sha256": ONE,
            "evaluator_ref": "principalref:evaluator",
            "producer_ref": "principalref:producer",
        }
        values.update(changes)
        return EvaluationContractBinding(**values)  # type: ignore[arg-type]

    def correlation(self, **changes: object) -> DetectionCorrelationBinding:
        values: dict[str, object] = {
            "tenant_ref": "tenantref:alpha",
            "engagement_ref": "engagementref:assessment-01",
            "context_ref": "contextref:defender-replay-01",
            "scope_sha256": ZERO,
            "correlation_bundle_id": "DCB-" + "C" * 32,
            "correlation_bundle_sha256": THREE,
            "correlation_assessment_id": "DCA-" + "D" * 32,
            "correlation_assessment_sha256": FOUR,
            "correlation_review_plan_id": "DRP-" + "E" * 32,
            "correlation_review_plan_sha256": FIVE,
            "consumed_events_manifest_sha256": SIX,
            "evaluated_at": "2026-09-20T12:05:00Z",
        }
        values.update(changes)
        return DetectionCorrelationBinding(**values)  # type: ignore[arg-type]

    def finding(
        self,
        number: int,
        *,
        assessment: AssessmentEvidenceBinding | None = None,
        **changes: object,
    ) -> FindingFixture:
        binding = assessment or self.assessment()
        values: dict[str, object] = {
            "tenant_ref": "tenantref:alpha",
            "engagement_ref": "engagementref:assessment-01",
            "context_ref": "contextref:defender-replay-01",
            "scope_sha256": ZERO,
            "corpus_sha256": ONE,
            "assessment_binding_id": binding.binding_id,
            "assessment_binding_sha256": binding.binding_sha256,
            "finding_ref": f"findingref:finding-{number}",
            "finding_sha256": f"sha256:{number:064x}",
            "evidence_sha256": f"sha256:{number + 10:064x}",
            "provenance_sha256": f"sha256:{number + 20:064x}",
            "occurred_at": f"2026-09-20T12:00:{number:02d}Z",
        }
        values.update(changes)
        return FindingFixture(**values)  # type: ignore[arg-type]

    def telemetry(
        self,
        number: int,
        *,
        finding: FindingFixture | None = None,
        **changes: object,
    ) -> TelemetryFixture:
        bound_finding = finding or self.finding(number)
        values: dict[str, object] = {
            "tenant_ref": "tenantref:alpha",
            "engagement_ref": "engagementref:assessment-01",
            "context_ref": "contextref:defender-replay-01",
            "scope_sha256": ZERO,
            "corpus_sha256": ONE,
            "source_event_ref": f"eventref:telemetry-{number}",
            "normalized_event_id": "NTE-" + f"{number:032X}",
            "normalized_event_sha256": f"sha256:{number + 30:064x}",
            "source_artifact_sha256": f"sha256:{number + 40:064x}",
            "provenance_sha256": f"sha256:{number + 50:064x}",
            "finding_fixture_id": bound_finding.fixture_id,
            "finding_fixture_sha256": bound_finding.fixture_sha256,
            "telemetry_domain": "network",
            "operation_code": f"detector.control{number}",
            "occurred_at": f"2026-09-20T12:00:{number:02d}Z",
            "observed_at": f"2026-09-20T12:00:{number + 10:02d}Z",
        }
        values.update(changes)
        return TelemetryFixture(**values)  # type: ignore[arg-type]

    def availability(
        self, domain: str, state: str = "available", **changes: object
    ) -> SourceAvailability:
        values: dict[str, object] = {
            "tenant_ref": "tenantref:alpha",
            "engagement_ref": "engagementref:assessment-01",
            "context_ref": "contextref:defender-replay-01",
            "scope_sha256": ZERO,
            "corpus_sha256": ONE,
            "telemetry_domain": domain,
            "window_opens_at": "2026-09-20T12:00:00Z",
            "window_closes_at": "2026-09-20T12:12:00Z",
            "state": state,
            "evidence_sha256": EIGHT,
            "provenance_sha256": NINE,
        }
        values.update(changes)
        return SourceAvailability(**values)  # type: ignore[arg-type]

    def request(self, **changes: object) -> ReplayRequest:
        assessment = self.assessment()
        findings = tuple(self.finding(index, assessment=assessment) for index in range(1, 5))
        telemetry = (
            self.telemetry(1, finding=findings[0]),
            self.telemetry(
                2,
                finding=findings[1],
                telemetry_domain="endpoint",
                occurred_at="2026-09-20T12:00:02Z",
                observed_at="2026-09-20T12:01:32Z",
            ),
        )
        expectations = tuple(
            DetectionExpectation(
                control_ref=f"controlref:control-{index}",
                finding_fixture_id=findings[index - 1].fixture_id,
                finding_fixture_sha256=findings[index - 1].fixture_sha256,
                operation_code=f"detector.control{index}",
                telemetry_domains=(
                    "cloud" if index == 4 else "endpoint" if index == 2 else "network",
                ),
                maximum_latency_seconds=30,
            )
            for index in range(1, 5)
        )
        values: dict[str, object] = {
            "context": self.context(),
            "assessment_evidence": assessment,
            "detection_correlation": self.correlation(),
            "evaluation": self.evaluation(),
            "telemetry_fixtures": telemetry,
            "finding_fixtures": findings,
            "source_availability": (
                self.availability("network"),
                self.availability("endpoint"),
                self.availability("cloud", "absent"),
            ),
            "expectations": expectations,
            "replayed_at": "2026-09-20T12:11:00Z",
        }
        values.update(changes)
        return ReplayRequest(**values)  # type: ignore[arg-type]

    def review(
        self, receipt: object, role: str, number: int, **changes: object
    ) -> IndependentReplayReview:
        values: dict[str, object] = {
            "receipt_id": receipt.receipt_id,
            "receipt_sha256": receipt.receipt_sha256,
            "reviewer_ref": f"principalref:reviewer-{number}",
            "reviewer_role": role,
            "producer_ref": receipt.producer_ref,
            "decision": "accepted",
            "reviewed_at": f"2026-09-20T13:0{number}:00Z",
            "evidence_sha256": f"sha256:{number + 60:064x}",
            "rationale_code": "fixture_replay_verified",
        }
        values.update(changes)
        return IndependentReplayReview(**values)  # type: ignore[arg-type]

    def test_deterministic_replay_calculates_latency_and_coverage(self) -> None:
        request = self.request()
        first = run_defender_replay(request)
        second = run_defender_replay(request)
        self.assertEqual(first, second)
        self.assertEqual(
            [item.state for item in first.observations],
            [
                "detected_within_objective",
                "detected_late",
                "failed_detection",
                "absent_source_data",
            ],
        )
        self.assertEqual(first.observations[0].latency_seconds, 10)
        self.assertEqual(first.observations[1].latency_seconds, 90)
        self.assertEqual(first.summary.total_expectations, 4)
        self.assertEqual(first.summary.evaluable_expectations, 3)
        self.assertEqual(first.summary.detected_count, 2)
        self.assertEqual(first.summary.failed_detection_count, 1)
        self.assertEqual(first.summary.absent_source_data_count, 1)
        self.assertEqual(first.summary.detection_coverage_basis_points, 6667)
        self.assertEqual(first.summary.objective_coverage_basis_points, 3333)
        self.assertEqual(first.summary.mean_detection_latency_seconds, 50)
        self.assertEqual(first.summary.maximum_detection_latency_seconds, 90)

    def test_absent_source_data_is_not_counted_as_failed_detection(self) -> None:
        receipt = run_defender_replay(self.request())
        failed = receipt.observations[2]
        absent = receipt.observations[3]
        self.assertEqual(failed.state, "failed_detection")
        self.assertEqual(failed.reason_code, "expected_signal_not_observed")
        self.assertEqual(failed.available_domains, ("network",))
        self.assertEqual(absent.state, "absent_source_data")
        self.assertEqual(absent.reason_code, "source_data_absent")
        self.assertEqual(absent.absent_domains, ("cloud",))

    def test_receipt_is_nonqualifying_and_does_not_claim_effectiveness(self) -> None:
        document = run_defender_replay(self.request()).to_dict()
        self.assertEqual(document["effects"], dict(NO_EFFECTS))
        self.assertEqual(document["qualification_effect"], QUALIFICATION_EFFECT)
        self.assertEqual(document["runtime_status"], RUNTIME_STATUS)
        self.assertEqual(document["external_effectiveness_claim"], "not_asserted")
        self.assertEqual(document["review_status"], "pending_independent_review")
        self.assertEqual(document["promotion_status"], "blocked_pending_independent_review")
        self.assertTrue(NO_BUILTIN_NETWORK)
        self.assertTrue(NO_BUILTIN_PROVIDER_CALLS)
        self.assertTrue(NO_FILESYSTEM_DISCOVERY)
        self.assertTrue(NO_TARGET_ACTIONS)

    def test_context_tenant_scope_corpus_and_assessment_mixing_fail_closed(self) -> None:
        base = self.request()
        cases = (
            replace(base.telemetry_fixtures[0], tenant_ref="tenantref:other"),
            replace(base.telemetry_fixtures[0], engagement_ref="engagementref:other"),
            replace(base.telemetry_fixtures[0], context_ref="contextref:other"),
            replace(base.telemetry_fixtures[0], scope_sha256=NINE),
            replace(base.telemetry_fixtures[0], corpus_sha256=NINE),
        )
        for fixture in cases:
            with (
                self.subTest(fixture=fixture.fixture_id),
                self.assertRaisesRegex(DefenderReplayError, "bound context"),
            ):
                self.request(telemetry_fixtures=(fixture, *base.telemetry_fixtures[1:]))
        with self.assertRaisesRegex(DefenderReplayError, "assessment provenance"):
            bad = replace(base.finding_fixtures[0], assessment_binding_sha256=NINE)
            self.request(finding_fixtures=(bad, *base.finding_fixtures[1:]))
        with self.assertRaisesRegex(DefenderReplayError, "detection correlation"):
            self.request(detection_correlation=self.correlation(context_ref="contextref:other"))

    def test_sanitization_and_identity_separation_fail_closed(self) -> None:
        with self.assertRaisesRegex(DefenderReplayError, "sanitized"):
            self.telemetry(1, sanitized=False)
        with self.assertRaisesRegex(DefenderReplayError, "sanitized"):
            self.finding(1, sanitized=False)
        with self.assertRaisesRegex(DefenderReplayError, "separated"):
            self.evaluation(evaluator_ref="principalref:producer")
        with self.assertRaisesRegex(DefenderReplayError, "secret-like"):
            canonical_json({"authorization": "hidden-value"})

    def test_availability_must_be_explicit_and_unambiguous(self) -> None:
        request = self.request()
        missing = tuple(
            item for item in request.source_availability if item.telemetry_domain != "network"
        )
        with self.assertRaisesRegex(DefenderReplayError, "unambiguous"):
            run_defender_replay(self.request(source_availability=missing))
        duplicate = (*request.source_availability, self.availability("network"))
        with self.assertRaisesRegex(DefenderReplayError, "unique"):
            self.request(source_availability=duplicate)

    def test_failed_detection_requires_coverage_through_replay_cutoff(self) -> None:
        base = self.request()
        shortened = tuple(
            replace(item, window_closes_at="2026-09-20T12:10:00Z")
            if item.telemetry_domain == "network"
            else item
            for item in base.source_availability
        )
        receipt = run_defender_replay(self.request(source_availability=shortened))
        self.assertEqual(receipt.observations[0].state, "detected_within_objective")
        self.assertEqual(receipt.observations[2].state, "absent_source_data")
        self.assertEqual(receipt.summary.failed_detection_count, 0)

    def test_matching_signal_needs_declared_source_coverage(self) -> None:
        base = self.request()
        shortened = tuple(
            replace(item, window_closes_at="2026-09-20T12:00:08Z")
            if item.telemetry_domain == "network"
            else item
            for item in base.source_availability
        )
        receipt = run_defender_replay(self.request(source_availability=shortened))
        self.assertEqual(receipt.observations[0].state, "absent_source_data")
        self.assertEqual(receipt.observations[2].state, "absent_source_data")

    def test_source_gap_is_absent_and_overlap_fails_closed(self) -> None:
        base = self.request()
        others = tuple(
            item for item in base.source_availability if item.telemetry_domain != "network"
        )
        first = self.availability("network", window_closes_at="2026-09-20T12:02:00Z")
        gap = self.availability("network", window_opens_at="2026-09-20T12:03:00Z")
        receipt = run_defender_replay(self.request(source_availability=(*others, first, gap)))
        self.assertEqual(receipt.observations[2].state, "absent_source_data")
        overlap = replace(gap, window_opens_at="2026-09-20T12:01:00Z")
        with self.assertRaisesRegex(DefenderReplayError, "overlapping"):
            run_defender_replay(self.request(source_availability=(*others, first, overlap)))

    def test_replay_cutoff_rejects_future_findings_and_telemetry(self) -> None:
        base = self.request()
        with self.assertRaisesRegex(DefenderReplayError, "finding occurs after"):
            self.request(replayed_at="2026-09-20T11:59:00Z")
        with self.assertRaisesRegex(DefenderReplayError, "precedes detection objective"):
            self.request(telemetry_fixtures=(), replayed_at="2026-09-20T12:00:20Z")
        with self.assertRaisesRegex(DefenderReplayError, "telemetry observation follows"):
            self.request(
                telemetry_fixtures=(
                    *base.telemetry_fixtures,
                    self.telemetry(
                        3,
                        finding=base.finding_fixtures[2],
                        observed_at="2026-09-20T12:13:00Z",
                    ),
                )
            )

    def test_telemetry_cannot_be_reused_across_finding_boundaries(self) -> None:
        request = self.request()
        control_one = next(
            item for item in request.expectations if item.control_ref == "controlref:control-1"
        )
        control_one_finding = next(
            item
            for item in request.finding_fixtures
            if item.fixture_id == control_one.finding_fixture_id
        )
        unrelated = self.telemetry(
            5,
            finding=control_one_finding,
            operation_code="detector.control3",
        )
        receipt = run_defender_replay(
            self.request(telemetry_fixtures=(*request.telemetry_fixtures, unrelated))
        )
        control_three = next(
            item for item in receipt.observations if item.control_ref == "controlref:control-3"
        )
        self.assertEqual(control_three.state, "failed_detection")
        with self.assertRaisesRegex(DefenderReplayError, "telemetry finding content address"):
            bad = replace(unrelated, finding_fixture_sha256=NINE)
            self.request(telemetry_fixtures=(*request.telemetry_fixtures, bad))

    def test_independent_reviews_are_required_for_promotion(self) -> None:
        receipt = run_defender_replay(self.request())
        blocked = assess_replay_promotion(receipt, ())
        self.assertFalse(blocked.eligible)
        self.assertEqual(
            blocked.reason_codes,
            ("missing_independent_assurance", "missing_independent_control"),
        )
        assurance = self.review(receipt, "independent_assurance", 1)
        control = self.review(receipt, "independent_control", 2)
        eligible = assess_replay_promotion(receipt, (control, assurance))
        self.assertTrue(eligible.eligible)
        self.assertEqual(eligible.status, "eligible_for_promotion")
        rejected = replace(control, decision="rejected")
        blocked = assess_replay_promotion(receipt, (assurance, rejected))
        self.assertFalse(blocked.eligible)
        self.assertIn("independent_review_rejected", blocked.reason_codes)
        with self.assertRaisesRegex(DefenderReplayError, "cannot independently review"):
            self.review(
                receipt,
                "independent_control",
                3,
                reviewer_ref="principalref:producer",
            )

    def test_cross_receipt_and_duplicate_reviewer_evidence_fail_closed(self) -> None:
        receipt = run_defender_replay(self.request())
        assurance = self.review(receipt, "independent_assurance", 1)
        with self.assertRaisesRegex(DefenderReplayError, "bind"):
            bad = replace(assurance, receipt_sha256=NINE)
            assess_replay_promotion(receipt, (bad,))
        control = self.review(
            receipt,
            "independent_control",
            2,
            reviewer_ref=assurance.reviewer_ref,
        )
        with self.assertRaisesRegex(DefenderReplayError, "independent identities"):
            assess_replay_promotion(receipt, (assurance, control))

    def test_receipt_round_trip_and_tamper_detection(self) -> None:
        receipt = run_defender_replay(self.request())
        parsed = parse_defender_replay_receipt(canonical_json(receipt.to_dict()))
        self.assertEqual(parsed, receipt)
        verify_defender_replay_receipt(receipt)
        tampered = copy.deepcopy(receipt.to_dict())
        tampered["summary"]["failed_detection_count"] = 0
        with self.assertRaises(DefenderReplayError):
            parse_defender_replay_receipt(tampered)
        tampered = copy.deepcopy(receipt.to_dict())
        tampered["effects"]["network"] = "allowed"
        with self.assertRaisesRegex(DefenderReplayError, "metadata"):
            parse_defender_replay_receipt(tampered)

    def test_receipt_review_and_promotion_match_schema(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        receipt = run_defender_replay(self.request())
        assurance = self.review(receipt, "independent_assurance", 1)
        control = self.review(receipt, "independent_control", 2)
        validator.validate(receipt.to_dict())
        validator.validate(assurance.to_dict())
        validator.validate(assess_replay_promotion(receipt, (assurance, control)).to_dict())

    def test_outputs_are_immutable(self) -> None:
        receipt = run_defender_replay(self.request())
        with self.assertRaises(FrozenInstanceError):
            receipt.review_status = "accepted"  # type: ignore[misc]

    def test_files_have_no_markers_or_dash_codepoints(self) -> None:
        forbidden = (
            "generated" + " by",
            "written" + " by ai",
            "as" + " an ai",
            "chat" + "gpt",
            "code" + "x",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            lowered = text.lower()
            for marker in forbidden:
                self.assertNotIn(marker, lowered, path)

    def test_public_package_exports_defender_replay_boundary(self) -> None:
        self.assertIs(sunderkey.run_defender_replay, run_defender_replay)
        self.assertIs(
            sunderkey.assess_defender_replay_promotion,
            assess_replay_promotion,
        )
        self.assertIs(
            sunderkey.parse_defender_replay_receipt,
            parse_defender_replay_receipt,
        )


if __name__ == "__main__":
    unittest.main()
