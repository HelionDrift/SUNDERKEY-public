"""Phase 168 deterministic detection correlation runtime coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.detection_correlation_runtime import (
    NO_BUILTIN_NETWORK,
    NO_BUILTIN_SIEM_QUERY,
    NO_EFFECTS,
    QUALIFICATION_EFFECT,
    RUNTIME_STATUS,
    CorrelationBudget,
    CorrelationRequest,
    DetectionCorrelationError,
    ExecutionEvidenceReference,
    ExpectedDetection,
    FalsePositiveControl,
    NegativeControl,
    NormalizedSignalReference,
    canonical_json,
    correlate_detection_controls,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "detection-correlation-runtime-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "detection_correlation_runtime.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "detection-correlation-runtime.md",
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


class DetectionCorrelationRuntimePhase168Tests(unittest.TestCase):
    def execution(self, **changes: object) -> ExecutionEvidenceReference:
        values: dict[str, object] = {
            "tenant_ref": "tenantref:acme",
            "engagement_ref": "engagementref:assessment-168",
            "scope_sha256": ZERO,
            "execution_result_id": "ERE-" + "A" * 32,
            "execution_result_sha256": ONE,
            "action_sha256": TWO,
            "evidence_manifest_sha256": THREE,
            "custody_policy_sha256": FOUR,
            "artifact_ref": "artifactref:execution-evidence-001",
            "artifact_sha256": FIVE,
            "custody_sha256": SIX,
            "started_at": "2026-09-20T12:00:00Z",
            "completed_at": "2026-09-20T12:00:30Z",
        }
        values.update(changes)
        return ExecutionEvidenceReference(**values)

    def signal(self, sequence: int = 1, **changes: object) -> NormalizedSignalReference:
        character = format(sequence, "x")[-1]
        values: dict[str, object] = {
            "tenant_ref": "tenantref:acme",
            "engagement_ref": "engagementref:assessment-168",
            "scope_sha256": ZERO,
            "custody_policy_sha256": FOUR,
            "source_binding_id": "TSB-" + "B" * 32,
            "source_binding_sha256": SEVEN,
            "normalized_event_id": "NTE-" + character.upper() * 32,
            "normalized_event_sha256": "sha256:" + character * 64,
            "source_event_ref": f"eventref:source-{sequence:03d}",
            "raw_event_sha256": "sha256:" + format(sequence + 8, "x")[-1] * 64,
            "artifact_ref": f"artifactref:normalized-{sequence:03d}",
            "custody_sha256": SIX,
            "telemetry_domain": "network",
            "operation_code": "detector.alert",
            "outcome": "blocked",
            "severity": "high",
            "occurred_at": "2026-09-20T12:00:10Z",
            "normalized_at": "2026-09-20T12:00:20Z",
        }
        values.update(changes)
        return NormalizedSignalReference(**values)

    def budget(self, **changes: object) -> CorrelationBudget:
        values: dict[str, int] = {
            "maximum_expected_detections": 4,
            "maximum_observed_signals": 8,
            "maximum_negative_controls": 4,
            "maximum_false_positive_controls": 4,
            "maximum_control_results": 12,
            "maximum_derived_findings": 24,
            "maximum_window_seconds": 600,
            "maximum_signal_age_seconds": 600,
        }
        values.update(changes)
        return CorrelationBudget(**values)

    def request(self, **changes: object) -> CorrelationRequest:
        values: dict[str, object] = {
            "tenant_ref": "tenantref:acme",
            "engagement_ref": "engagementref:assessment-168",
            "scope_sha256": ZERO,
            "custody_policy_sha256": FOUR,
            "execution": self.execution(),
            "signals": (self.signal(),),
            "expected_detections": (
                ExpectedDetection(
                    control_ref="controlref:expected-alert",
                    expectation_ref="expectationref:network-alert",
                    operation_code="detector.alert",
                    telemetry_domains=("network",),
                    accepted_outcomes=("blocked", "success"),
                    opens_at="2026-09-20T12:00:00Z",
                    closes_at="2026-09-20T12:01:00Z",
                ),
            ),
            "negative_controls": (
                NegativeControl(
                    control_ref="controlref:negative-benign",
                    operation_code="detector.benign",
                    telemetry_domains=("network",),
                    opens_at="2026-09-20T12:00:00Z",
                    closes_at="2026-09-20T12:01:00Z",
                ),
            ),
            "false_positive_controls": (
                FalsePositiveControl(
                    control_ref="controlref:false-positive-baseline",
                    operation_code="detector.noise",
                    telemetry_domains=("network",),
                    opens_at="2026-09-20T12:00:00Z",
                    closes_at="2026-09-20T12:01:00Z",
                    maximum_signal_count=0,
                    baseline_evidence_sha256=EIGHT,
                ),
            ),
            "prior_consumed_event_sha256s": (),
            "budget": self.budget(),
            "evaluated_at": "2026-09-20T12:02:00Z",
        }
        values.update(changes)
        return CorrelationRequest(**values)

    def test_deterministic_correlation_passes_all_controls(self) -> None:
        request = self.request()
        first = correlate_detection_controls(request)
        second = correlate_detection_controls(request)
        self.assertEqual(first, second)
        self.assertEqual(first.assessment.overall_state, "passed")
        self.assertEqual(len(first.assessment.validation_results), 3)
        self.assertEqual(first.assessment.coverage_gaps, ())
        self.assertEqual(first.review_plan.review_status, "pending_independent_review")
        self.assertEqual(
            first.review_plan.required_reviewer_roles,
            ("independent_assurance", "independent_control"),
        )
        self.assertEqual(first.to_dict()["effects"], dict(NO_EFFECTS))
        self.assertEqual(first.to_dict()["runtime_status"], RUNTIME_STATUS)
        self.assertEqual(first.to_dict()["qualification_effect"], QUALIFICATION_EFFECT)
        self.assertTrue(NO_BUILTIN_NETWORK)
        self.assertTrue(NO_BUILTIN_SIEM_QUERY)

    def test_request_round_trip_and_content_address_are_exact(self) -> None:
        request = self.request()
        parsed = parse_contract(canonical_json(request.to_dict()))
        self.assertEqual(parsed, request)
        tampered = copy.deepcopy(request.to_dict())
        tampered["evaluated_at"] = "2026-09-20T12:03:00Z"
        with self.assertRaisesRegex(DetectionCorrelationError, "content address"):
            parse_contract(tampered)

    def test_schema_accepts_request_and_bundle(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        validator.validate(self.request().to_dict())
        validator.validate(correlate_detection_controls(self.request()).to_dict())

    def test_cross_tenant_context_scope_and_custody_fail_closed(self) -> None:
        for changes in (
            {"tenant_ref": "tenantref:other"},
            {"engagement_ref": "engagementref:other"},
            {"scope_sha256": ONE},
            {"custody_policy_sha256": NINE},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(DetectionCorrelationError, "bound context"),
            ):
                self.request(signals=(self.signal(**changes),))
        with self.assertRaisesRegex(DetectionCorrelationError, "bound context"):
            self.request(execution=self.execution(tenant_ref="tenantref:other"))

    def test_unverified_unredacted_and_stale_sources_fail_closed(self) -> None:
        with self.assertRaisesRegex(DetectionCorrelationError, "custody"):
            self.signal(custody_status="best_effort")
        with self.assertRaisesRegex(DetectionCorrelationError, "redacted"):
            self.signal(redacted=False)
        stale = self.signal(
            occurred_at="2026-09-20T11:00:10Z",
            normalized_at="2026-09-20T11:00:20Z",
        )
        with self.assertRaisesRegex(DetectionCorrelationError, "stale"):
            self.request(signals=(stale,))
        future = self.signal(normalized_at="2026-09-20T12:03:00Z")
        with self.assertRaisesRegex(DetectionCorrelationError, "future"):
            self.request(signals=(future,))

    def test_duplicate_identity_digest_source_and_raw_event_fail_closed(self) -> None:
        first = self.signal(1)
        cases = (
            replace(first, raw_event_sha256=NINE),
            self.signal(2, normalized_event_sha256=first.normalized_event_sha256),
            self.signal(2, source_event_ref=first.source_event_ref),
            self.signal(2, raw_event_sha256=first.raw_event_sha256),
        )
        patterns = ("identity", "digest", "reference", "raw event")
        for second, pattern in zip(cases, patterns, strict=True):
            with (
                self.subTest(pattern=pattern),
                self.assertRaisesRegex(DetectionCorrelationError, pattern),
            ):
                self.request(signals=(first, second))

    def test_prior_consumption_replay_fails_closed(self) -> None:
        signal = self.signal()
        with self.assertRaisesRegex(DetectionCorrelationError, "replay"):
            self.request(
                signals=(signal,),
                prior_consumed_event_sha256s=(signal.normalized_event_sha256,),
            )

    def test_strict_input_window_and_derived_budgets_fail_closed(self) -> None:
        with self.assertRaisesRegex(DetectionCorrelationError, "signal budget"):
            self.request(
                signals=(self.signal(1), self.signal(2)),
                budget=self.budget(maximum_observed_signals=1),
            )
        too_wide = ExpectedDetection(
            control_ref="controlref:expected-alert",
            expectation_ref="expectationref:network-alert",
            operation_code="detector.alert",
            telemetry_domains=("network",),
            accepted_outcomes=("blocked",),
            opens_at="2026-09-20T12:00:00Z",
            closes_at="2026-09-20T12:20:00Z",
        )
        with self.assertRaisesRegex(DetectionCorrelationError, "window"):
            self.request(expected_detections=(too_wide,))
        missing = replace(
            self.request().expected_detections[0],
            operation_code="detector.missing",
        )
        request = self.request(
            expected_detections=(missing,),
            budget=self.budget(maximum_derived_findings=2),
        )
        with self.assertRaisesRegex(DetectionCorrelationError, "derived finding"):
            correlate_detection_controls(request)

    def test_missing_detection_derives_gap_hypothesis_and_tuning(self) -> None:
        missing = replace(
            self.request().expected_detections[0],
            operation_code="detector.missing",
        )
        bundle = correlate_detection_controls(self.request(expected_detections=(missing,)))
        self.assertEqual(bundle.assessment.overall_state, "failed")
        self.assertEqual(bundle.assessment.coverage_gaps[0].code, "missing_detection")
        self.assertEqual(
            bundle.assessment.root_cause_hypotheses[0].code,
            "detector_mapping_mismatch",
        )
        self.assertEqual(
            bundle.assessment.tuning_recommendations[0].code,
            "tune_detector_mapping",
        )

    def test_missing_domain_and_out_of_window_signals_have_distinct_root_causes(self) -> None:
        expected = self.request().expected_detections[0]
        no_domain = correlate_detection_controls(
            self.request(signals=(self.signal(telemetry_domain="identity"),))
        )
        self.assertEqual(
            no_domain.assessment.root_cause_hypotheses[0].code,
            "source_telemetry_absent",
        )
        late = self.signal(
            occurred_at="2026-09-20T12:01:30Z",
            normalized_at="2026-09-20T12:01:40Z",
        )
        outside = correlate_detection_controls(self.request(signals=(late,)))
        self.assertEqual(
            outside.assessment.root_cause_hypotheses[0].code,
            "correlation_window_mismatch",
        )
        self.assertEqual(outside.request.expected_detections[0], expected)

    def test_negative_and_false_positive_failures_drive_tuning(self) -> None:
        negative_signal = self.signal(operation_code="detector.benign")
        negative_bundle = correlate_detection_controls(self.request(signals=(negative_signal,)))
        self.assertEqual(negative_bundle.assessment.overall_state, "failed")
        finding_codes = {item.code for item in negative_bundle.assessment.root_cause_hypotheses}
        self.assertIn("detector_overmatching", finding_codes)
        noise_signal = self.signal(operation_code="detector.noise")
        noise_bundle = correlate_detection_controls(self.request(signals=(noise_signal,)))
        self.assertIn(
            "narrow_detection_logic",
            {item.code for item in noise_bundle.assessment.tuning_recommendations},
        )

    def test_output_is_immutable_and_secret_like_references_are_rejected(self) -> None:
        bundle = correlate_detection_controls(self.request())
        with self.assertRaises(FrozenInstanceError):
            bundle.assessment.overall_state = "failed"  # type: ignore[misc]
        with self.assertRaisesRegex(DetectionCorrelationError, "opaque reference"):
            self.signal(artifact_ref="artifactref:authorization=hidden-value")

    def test_unknown_fields_and_metadata_escalation_fail_closed(self) -> None:
        document = self.request().to_dict()
        document["unexpected"] = True
        with self.assertRaisesRegex(DetectionCorrelationError, "fields"):
            parse_contract(document)
        document = self.request().to_dict()
        document["effects"]["network"] = "allowed"
        with self.assertRaisesRegex(DetectionCorrelationError, "metadata"):
            parse_contract(document)

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

    def test_public_package_exports_correlation_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.DetectionCorrelationRequest, CorrelationRequest)
        self.assertIs(
            sunderkey.correlate_detection_controls,
            correlate_detection_controls,
        )
        self.assertIs(
            sunderkey.parse_detection_correlation_contract,
            parse_contract,
        )


if __name__ == "__main__":
    unittest.main()
