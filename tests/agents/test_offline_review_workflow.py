"""Integrated offline review bundle stays bounded, exact, and effect-free."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.credential_exposure_triage import (
    CredentialExposureSignal,
    ExposureReviewConsent,
)
from sunderkey.decoy_lifecycle_review import DecoyLifecycleEvent, DecoyPlacementApproval
from sunderkey.detection_rule_hygiene import RedactedRuleSnapshot, RuleSourceObservation
from sunderkey.email_control_review import EmailDeliveryObservation, EmailTestApproval
from sunderkey.errors import SunderkeyError
from sunderkey.inert_resilience_readiness import (
    InertReadinessObservation,
    InertReadinessScenario,
)
from sunderkey.metadata_impact_review import DataMetadataObservation
from sunderkey.offline_review_workflow import (
    MAX_BUNDLE_BYTES,
    MAX_INPUT_BYTES,
    OfflineReviewWorkflowError,
    build_offline_review_bundle,
    verify_offline_review_bundle,
)
from sunderkey.restricted_asset_inference import RestrictedAssetCase, RestrictedAssetObservation
from sunderkey.synthetic_scenario_planning import (
    SyntheticScenarioConsent,
    SyntheticScenarioRequest,
)

TENANT = "tenant:one"
SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
AT = "2026-09-23T13:00:00Z"
OBSERVED = "2026-09-23T12:00:00Z"
EXPIRES = "2026-09-24T12:00:00Z"


def jobs():
    signal = CredentialExposureSignal(
        event_id="event:one", tenant_id=TENANT, scope_sha256=SCOPE,
        principal_ref="principal:sha256:" + "c" * 64,
        credential_ref="credential:sha256:" + "d" * 64,
        feed_ref="feed:approved", source_sha256=SOURCE,
        observed_at=OBSERVED, expires_at=EXPIRES,
        kind="breach_correlation",
    )
    signal_consent = ExposureReviewConsent(
        tenant_id=TENANT, scope_sha256=SCOPE, principal_ref=signal.principal_ref,
        allowed_kinds=("breach_correlation",), issued_at=OBSERVED,
        expires_at=EXPIRES, source_sha256=SOURCE,
    )
    scenario_request = SyntheticScenarioRequest(
        request_id="request:one", tenant_id=TENANT, scope_sha256=SCOPE,
        scenario_id="scenario:one", kind="synthetic_phishing_impact",
        synthetic_principal_ref="synthetic-principal:sha256:" + "e" * 64,
        surface_ref="surface:sha256:" + "f" * 64,
        created_at=OBSERVED, window_start="2026-09-23T14:00:00Z",
        window_end="2026-09-23T15:00:00Z", source_sha256=SOURCE,
    )
    scenario_consent = SyntheticScenarioConsent(
        tenant_id=TENANT, scope_sha256=SCOPE, scenario_id=scenario_request.scenario_id,
        kind=scenario_request.kind,
        synthetic_principal_refs=(scenario_request.synthetic_principal_ref,),
        surface_refs=(scenario_request.surface_ref,),
        issued_at=OBSERVED, expires_at=EXPIRES, source_sha256=SOURCE,
    )
    approval = DecoyPlacementApproval(
        tenant_id=TENANT, scope_sha256=SCOPE,
        decoy_ref="synthetic-decoy:sha256:" + "1" * 64,
        surface_ref="surface:sha256:" + "f" * 64,
        owner_id="owner:one", approved_at=OBSERVED,
        expires_at=EXPIRES, source_sha256=SOURCE,
    )
    decoy_event = DecoyLifecycleEvent(
        event_id="event:decoy", tenant_id=TENANT, scope_sha256=SCOPE,
        decoy_ref=approval.decoy_ref, approval_sha256=approval.approval_sha256,
        kind="placement_asserted", occurred_at=OBSERVED, evidence_sha256=SOURCE,
    )
    case = RestrictedAssetCase(
        tenant_id=TENANT, scope_sha256=SCOPE,
        asset_ref="asset:sha256:" + "2" * 64,
        technique_id="T1234", restriction_reason="unsafe_to_exploit",
        prerequisites=("asset_reachability",),
        mapping_source_sha256=SOURCE,
        restriction_source_sha256=SOURCE,
        recorded_at=OBSERVED, expires_at=EXPIRES,
    )
    asset_observation = RestrictedAssetObservation(
        tenant_id=TENANT, scope_sha256=SCOPE, asset_ref=case.asset_ref,
        technique_id=case.technique_id, facet="asset_reachability",
        state="supported_asserted", source_sha256=SOURCE,
        observed_at=OBSERVED, expires_at=EXPIRES,
    )
    inert = InertReadinessScenario(
        scenario_id="scenario:inert", tenant_id=TENANT, scope_sha256=SCOPE,
        synthetic_asset_ref="synthetic-asset:sha256:" + "3" * 64,
        inert_canary_ref="inert-canary:sha256:" + "4" * 64,
        source_sha256=SOURCE, recorded_at=OBSERVED, expires_at=EXPIRES,
    )
    inert_observation = InertReadinessObservation(
        tenant_id=TENANT, scope_sha256=SCOPE,
        scenario_sha256=inert.scenario_sha256,
        facet="propagation_boundary", outcome="protected_asserted",
        source_sha256=SOURCE, observed_at=OBSERVED, expires_at=EXPIRES,
    )
    rule = RedactedRuleSnapshot(
        tenant_id=TENANT, scope_sha256=SCOPE,
        rule_ref="rule:sha256:" + "5" * 64,
        enabled=True, query_health="valid_asserted",
        mapping_state="current_asserted",
        required_source_refs=("source:sha256:" + "6" * 64,),
        source_sha256=SOURCE, observed_at=OBSERVED, expires_at=EXPIRES,
    )
    rule_observation = RuleSourceObservation(
        tenant_id=TENANT, scope_sha256=SCOPE, rule_ref=rule.rule_ref,
        source_ref=rule.required_source_refs[0], state="available_asserted",
        evidence_sha256=SOURCE, observed_at=OBSERVED, expires_at=EXPIRES,
    )
    metadata_observation = DataMetadataObservation(
        tenant_id=TENANT, scope_sha256=SCOPE,
        dataset_ref="dataset:sha256:" + "7" * 64,
        source_record_id="source:metadata", source_sha256=SOURCE,
        observed_at=OBSERVED, expires_at=EXPIRES,
        category="personal_identifier", reachability="hypothesis",
        path_evidence_sha256=SOURCE, record_count_bucket="101_10000",
        business_criticality="high",
    )
    email_approval = EmailTestApproval(
        tenant_id=TENANT, scope_sha256=SCOPE, scenario_id="scenario:mail",
        test_mailbox_refs=("test-mailbox:sha256:" + "8" * 64,),
        allowed_artifact_classes=("header_only",),
        approved_at=OBSERVED, expires_at=EXPIRES, source_sha256=SOURCE,
    )
    email_observation = EmailDeliveryObservation(
        tenant_id=TENANT, scope_sha256=SCOPE,
        approval_sha256=email_approval.approval_sha256,
        test_mailbox_ref=email_approval.test_mailbox_refs[0],
        artifact_class="header_only", gateway_disposition="blocked_asserted",
        mailbox_disposition="not_delivered_asserted", source_sha256=SOURCE,
        observed_at=OBSERVED, expires_at=EXPIRES,
    )
    return [
        {"job_id": "job:credential", "kind": "credential_exposure",
         "payload": {"signals": [signal.to_dict()], "consents": [signal_consent.to_dict()]}},
        {"job_id": "job:scenario", "kind": "synthetic_scenario",
         "payload": {"requests": [scenario_request.to_dict()],
                     "consents": [scenario_consent.to_dict()]}},
        {"job_id": "job:decoy", "kind": "decoy_lifecycle",
         "payload": {"approval": approval.to_dict(), "events": [decoy_event.to_dict()]}},
        {"job_id": "job:restricted", "kind": "restricted_asset",
         "payload": {"case": case.to_dict(),
                     "observations": [asset_observation.to_dict()]}},
        {"job_id": "job:inert", "kind": "inert_resilience",
         "payload": {"scenario": inert.to_dict(),
                     "observations": [inert_observation.to_dict()]}},
        {"job_id": "job:rule", "kind": "detection_rule",
         "payload": {"snapshot": rule.to_dict(),
                     "observations": [rule_observation.to_dict()]}},
        {"job_id": "job:impact", "kind": "metadata_impact",
         "payload": {"observations": [metadata_observation.to_dict()]}},
        {"job_id": "job:email", "kind": "email_control",
         "payload": {"approval": email_approval.to_dict(),
                     "observations": [email_observation.to_dict()],
                     "cleanup_assertions": []}},
    ]


def request(selected_jobs=None):
    return {
        "schema_version": 1, "tenant_id": TENANT,
        "scope_sha256": SCOPE, "reviewed_at": AT,
        "jobs": jobs() if selected_jobs is None else selected_jobs,
    }


class OfflineReviewWorkflowTests(unittest.TestCase):
    def test_all_eight_review_types_form_one_deterministic_bundle(self):
        items = jobs()
        left = build_offline_review_bundle(request(items))
        right = build_offline_review_bundle(request(list(reversed(items))))
        self.assertEqual(left, right)
        self.assertEqual(len(left["jobs"]), 8)
        self.assertEqual(left["authority_effect"], "none")
        self.assertEqual(left["qualification_effect"], "none")
        self.assertFalse(left["network_call_performed"])
        self.assertEqual(left["effects"]["target_interaction"], "none")
        self.assertEqual(left["jobs"][0]["job_id"], "job:credential")
        self.assertTrue(left["bundle_sha256"].startswith("sha256:"))
        by_kind = {job["kind"]: job["result"] for job in left["jobs"]}
        self.assertEqual(
            by_kind["credential_exposure"]["items"][0]["disposition"],
            "human_review_candidate",
        )
        self.assertEqual(
            by_kind["synthetic_scenario"]["items"][0]["disposition"],
            "human_review_candidate",
        )
        self.assertEqual(by_kind["decoy_lifecycle"]["state"], "placed_asserted")
        self.assertEqual(by_kind["restricted_asset"]["status"], "insufficient_evidence")
        self.assertEqual(by_kind["inert_resilience"]["status"], "inconclusive")
        self.assertEqual(
            by_kind["detection_rule"]["status"], "metadata_healthy_for_review",
        )
        self.assertEqual(
            by_kind["metadata_impact"]["signals"][0]["review_status"],
            "triage_required",
        )
        self.assertEqual(
            by_kind["email_control"]["status"],
            "asserted_prevention_for_review",
        )

    def test_tampered_record_or_cross_tenant_anchor_blocks_entire_bundle(self):
        items = jobs()
        items[0]["payload"]["signals"][0]["kind"] = "reuse_indicator"
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "signal is invalid"):
            build_offline_review_bundle(request(items))
        items = jobs()
        items[2]["payload"]["approval"]["tenant_id"] = "tenant:other"
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "approval is invalid"):
            build_offline_review_bundle(request(items))

    def test_unknown_fields_duplicate_jobs_and_unknown_kind_fail_closed(self):
        raw = request()
        raw["extra"] = "not allowed"
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "request fields"):
            build_offline_review_bundle(raw)
        items = jobs()
        items[1]["job_id"] = items[0]["job_id"]
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "repeated"):
            build_offline_review_bundle(request(items))
        items = jobs()
        items[0]["kind"] = "execute_target"
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "kind is invalid"):
            build_offline_review_bundle(request(items))
        items = jobs()
        items[0]["payload"]["secret"] = "not allowed"
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "payload fields"):
            build_offline_review_bundle(request(items))

    def test_record_digest_and_list_shape_are_required(self):
        items = jobs()
        items[0]["payload"]["signals"][0]["signal_sha256"] = ""
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "content digests"):
            build_offline_review_bundle(request(items))
        items = jobs()
        items[1]["payload"]["requests"] = "not a list"
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "bounded list"):
            build_offline_review_bundle(request(items))

    def test_cli_runs_without_output_file_and_rejects_duplicate_json_keys(self):
        parser = build_parser()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.json"
            path.write_text(json.dumps(request(jobs()[:1])), encoding="utf-8")
            args = parser.parse_args(["offline-review-run", "--input", str(path)])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                args.handler(args)
            rendered = json.loads(output.getvalue())
            self.assertEqual(len(rendered["jobs"]), 1)
            path.write_text(
                '{"schema_version":1,"schema_version":1}', encoding="utf-8",
            )
            with self.assertRaisesRegex(SunderkeyError, "Could not validate"):
                args.handler(args)

    def test_cli_input_size_is_bounded(self):
        parser = build_parser()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b" " * (MAX_INPUT_BYTES + 1))
            args = parser.parse_args(["offline-review-run", "--input", str(path)])
            with self.assertRaisesRegex(SunderkeyError, "size limit"):
                args.handler(args)

    def test_verifier_reproduces_all_jobs_and_rejects_mutated_nested_result(self):
        raw = request()
        bundle = build_offline_review_bundle(raw)
        result = verify_offline_review_bundle(raw, bundle)
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["job_count"], 8)
        self.assertEqual(result["origin_authentication"], "not_verified")
        self.assertEqual(result["qualification_effect"], "none")
        bundle["jobs"][0]["result"]["items"][0]["disposition"] = "compromised"
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "does not reproduce"):
            verify_offline_review_bundle(raw, bundle)

    def test_verifier_rejects_reordered_jobs_and_type_substitution(self):
        raw = request()
        bundle = build_offline_review_bundle(raw)
        bundle["jobs"].reverse()
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "does not reproduce"):
            verify_offline_review_bundle(raw, bundle)
        bundle = build_offline_review_bundle(raw)
        bundle["network_call_performed"] = 0
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "does not reproduce"):
            verify_offline_review_bundle(raw, bundle)
        bundle = build_offline_review_bundle(raw)
        bundle["unexpected"] = float("nan")
        with self.assertRaisesRegex(OfflineReviewWorkflowError, "not valid JSON"):
            verify_offline_review_bundle(raw, bundle)

    def test_verify_cli_reads_bounded_files_and_rejects_duplicate_bundle_keys(self):
        parser = build_parser()
        raw = request(jobs()[:1])
        bundle = build_offline_review_bundle(raw)
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.json"
            bundle_path = Path(directory) / "bundle.json"
            input_path.write_text(json.dumps(raw), encoding="utf-8")
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            args = parser.parse_args([
                "offline-review-verify", "--input", str(input_path),
                "--bundle", str(bundle_path),
            ])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                args.handler(args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")
            bundle_path.write_text('{"jobs":[],"jobs":[]}', encoding="utf-8")
            with self.assertRaisesRegex(SunderkeyError, "Could not validate"):
                args.handler(args)
            bundle_path.write_bytes(b" " * (MAX_BUNDLE_BYTES + 1))
            with self.assertRaisesRegex(SunderkeyError, "size limit"):
                args.handler(args)


if __name__ == "__main__":
    unittest.main()
