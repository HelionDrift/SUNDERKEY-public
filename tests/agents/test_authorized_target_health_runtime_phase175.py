import copy
import hashlib
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sunderkey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.assessment_transport_contracts import BrowserAction
from sunderkey.authorized_browser_runtime import (
    BrowserActionReceipt,
    BrowserActionStatus,
    BrowserBudgetCompletion,
    BrowserBudgetReservation,
    BrowserBudgetState,
    BrowserTranscriptEvent,
)
from sunderkey.authorized_http_runtime import (
    ExchangeStatus,
    HttpExchangeReceipt,
    TranscriptEvent,
)
from sunderkey.authorized_target_health_runtime import (
    AuthorizedTargetHealthPolicy,
    AuthorizedTargetHealthRuntimeError,
    BoundarySourceKind,
    HealthDimension,
    HealthSignalState,
    TargetHealthBudgetState,
    TargetHealthObservation,
    TargetHealthSafetySnapshot,
    TargetHealthStatus,
    observe_authorized_target_health,
    parse_target_health_receipt,
    verify_target_health_receipt,
)
from sunderkey.authorized_target_session_runtime import (
    CleanupStatus,
    LeaseUseCompletionEvidence,
    LeaseUseReservationEvidence,
    LeaseUseReservationStatus,
    RevocationStatus,
    SessionAcquisitionStatus,
    SessionTranscriptEvent,
    TargetSessionReceipt,
)
from sunderkey.execution_control_runtime import (
    AdmissionReceipt,
    AdmissionStatus,
    ClockObservation,
    ExecutionBinding,
    ExecutionRequest,
    HealthState,
    canonical_json,
)
from sunderkey.signed_scope_compiler import (
    ScopeBudgetState,
    compile_signed_scope,
    verify_signed_scope,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "authorized_target_health_runtime.py"
SCHEMA = ROOT / "registry" / "schemas" / "authorized-target-health-observation-v1.schema.json"
DOC = ROOT / "docs" / "authorized-target-health-runtime.md"
FILES = (MODULE, Path(__file__), SCHEMA, DOC)
NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
TARGET_URL = "https://app.example.test/assess/health"
ORIGIN = "https://app.example.test"
TECHNIQUE = "TECH-HEALTH-001"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64


def sha(value) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def verified_scope():
    specification = {
        "schema_version": 1,
        "issuer": "assessment-authority.example",
        "key_id": "scope-signing-key.2026-09",
        "nonce": "ABCDEFGHIJKLMNOP",
        "sequence_number": 1,
        "issued_at": "2026-09-19T00:00:00Z",
        "expires_at": "2026-09-26T00:00:00Z",
        "assessment_window": {
            "starts_at": "2026-09-19T00:00:00Z",
            "ends_at": "2026-09-25T00:00:00Z",
        },
        "targets": {
            "https_origins": [ORIGIN],
            "exact_hosts": ["app.example.test"],
            "wildcard_subdomains": [],
            "cidrs": [],
            "ports": [443],
            "http_methods": ["GET", "HEAD"],
            "path_prefixes": ["/assess"],
        },
        "exclusions": [],
        "protected_endpoints": [],
        "budgets": {
            "max_requests": 20,
            "max_concurrency": 2,
            "max_requests_per_minute": 20,
        },
        "impact_tier_ceiling": "R1",
        "allowed_technique_ids": [TECHNIQUE],
        "data_handling": {
            "classification": "confidential",
            "collection": "metadata_only",
            "storage": "ephemeral_encrypted",
            "retention_days": 1,
            "redaction_required": True,
        },
        "emergency_stop_contact_id": "soc.primary",
    }
    key = Ed25519PrivateKey.generate()
    signed = compile_signed_scope(specification, key, now=NOW)
    return verify_signed_scope(
        signed,
        key.public_key(),
        expected_issuer="assessment-authority.example",
        expected_key_id="scope-signing-key.2026-09",
        now=NOW,
    )


class AuthorizedTargetHealthRuntimePhase175Tests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.AuthorizedTargetHealthPolicy, AuthorizedTargetHealthPolicy)
        self.assertIs(
            sunderkey.AuthorizedTargetHealthRuntimeError,
            AuthorizedTargetHealthRuntimeError,
        )
        self.assertIs(
            sunderkey.observe_authorized_target_health,
            observe_authorized_target_health,
        )
        self.assertIs(
            sunderkey.verify_target_health_receipt,
            verify_target_health_receipt,
        )

    def setUp(self) -> None:
        self.scope = verified_scope()
        self.binding = ExecutionBinding(
            tenant_id="tenant:acme",
            context_id="context:health-assessment-1",
            context_sha256=DIGEST_A,
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            target_id="target:app-example",
            target_sha256=DIGEST_B,
            session_id="session:health-1",
            lease_id="lease:health-1",
            fence_epoch=9,
        )
        self.policy = AuthorizedTargetHealthPolicy(
            binding=self.binding,
            execution_policy_id="ECP-0123456789ABCDEF0123456789ABCDEF",
            execution_policy_sha256=DIGEST_A,
            target_url=TARGET_URL,
            method="GET",
            technique_id=TECHNIQUE,
            impact_tier="R1",
            max_admission_age_seconds=120,
            max_signal_age_seconds=120,
            max_signal_ttl_seconds=300,
            healthy_latency_milliseconds=100,
            degraded_latency_milliseconds=500,
            request_ceiling=10,
            evidence_byte_ceiling=100_000,
            observation_ceiling=20,
            max_source_receipts=6,
        )
        self.request = ExecutionRequest(
            binding=self.binding,
            policy_id=self.policy.execution_policy_id,
            policy_sha256=self.policy.execution_policy_sha256,
            idempotency_key="health:assessment-1:observation-1",
            operation_code="authorized_target_health",
            payload_sha256=self.policy.policy_sha256,
            payload_size_bytes=len(canonical_json(self.policy.to_dict()).encode("ascii")),
            attempt_number=1,
            prior_execution_sha256=None,
            cleanup_obligation_sha256=DIGEST_B,
        )
        self.admission = AdmissionReceipt(
            request_id=self.request.request_id,
            request_sha256=self.request.request_sha256,
            policy_id=self.request.policy_id,
            policy_sha256=self.request.policy_sha256,
            status=AdmissionStatus.ADMITTED,
            reason=None,
            observed_at="2026-09-20T12:00:00Z",
            monotonic_tick=100,
            state_before_sha256=DIGEST_A,
            state_after_sha256=DIGEST_B,
        )
        self.clock = ClockObservation("2026-09-20T12:00:10Z", 110)
        binding_sha256 = sha(self.binding.to_dict())
        self.safety = TargetHealthSafetySnapshot(
            binding_sha256=binding_sha256,
            execution_request_sha256=self.request.request_sha256,
            health=HealthState.HEALTHY,
            canceled=False,
            emergency_stop=False,
            observed_at="2026-09-20T12:00:09Z",
            expires_at="2026-09-20T12:01:00Z",
        )
        self.budget = TargetHealthBudgetState(
            binding_sha256=binding_sha256,
            execution_request_sha256=self.request.request_sha256,
            requests_used=0,
            evidence_bytes_used=0,
            observations_used=0,
            observed_at="2026-09-20T12:00:09Z",
            expires_at="2026-09-20T12:01:00Z",
        )
        self.http_receipt = self.make_http_receipt()
        self.browser_receipt = self.make_browser_receipt()
        self.session_receipt = self.make_session_receipt()
        self.receipts = (
            self.http_receipt,
            self.browser_receipt,
            self.session_receipt,
        )
        self.observations = self.make_observations()
        self.scope_budget = ScopeBudgetState(0, 0, 0)

    def make_http_receipt(self) -> HttpExchangeReceipt:
        event = TranscriptEvent(
            sequence=1,
            stage="completed",
            observed_at="2026-09-20T12:00:01Z",
            monotonic_tick=101,
            detail_sha256=DIGEST_A,
            previous_event_sha256=None,
        )
        return HttpExchangeReceipt(
            status=ExchangeStatus.COMPLETED,
            reason="completed",
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            intent_sha256=DIGEST_A,
            execution_request_id="ECRQ-HTTP-HEALTH-1",
            execution_request_sha256=DIGEST_B,
            admission_receipt_id="ECAR-HTTP-HEALTH-1",
            admission_receipt_sha256=DIGEST_C,
            policy_id="AHP-HTTP-HEALTH-1",
            policy_sha256=DIGEST_D,
            binding=self.binding,
            transport_called=True,
            request_body_sha256=None,
            request_size_bytes=0,
            response_status_code=200,
            response_mime_type="application/json",
            response_body_sha256=DIGEST_A,
            response_size_bytes=32,
            dns_attestation_sha256=(DIGEST_B,),
            transcript=(event,),
            network_call_performed=True,
        )

    def make_browser_receipt(self) -> BrowserActionReceipt:
        event = BrowserTranscriptEvent(
            sequence=1,
            stage="completed",
            observed_at="2026-09-20T12:00:02Z",
            monotonic_tick=102,
            detail_sha256=DIGEST_B,
            previous_event_sha256=None,
        )
        principal = "principalref:alice"
        pre = sha(
            {
                "origin": ORIGIN,
                "phase": "pre",
                "principal_label": principal,
                "session_id": self.binding.session_id,
                "url": TARGET_URL,
            }
        )
        post = sha(
            {
                "origin": ORIGIN,
                "phase": "post",
                "principal_label": principal,
                "session_id": self.binding.session_id,
                "url": TARGET_URL,
            }
        )
        before = BrowserBudgetState(0, 0, 0, 0, 0)
        reserved = BrowserBudgetState(1, 0, 8192, 0, 5000)
        reservation = BrowserBudgetReservation(
            binding_sha256=sha(self.binding.to_dict()),
            session_id=self.binding.session_id,
            action=BrowserAction.READ_METADATA,
            idempotency_key="browser:health-source-1",
            state_before=before,
            state_reserved=reserved,
            reserved_observed_bytes=8192,
            reserved_elapsed_milliseconds=5000,
        )
        completion = BrowserBudgetCompletion(
            reservation_id=reservation.reservation_id,
            reservation_sha256=reservation.reservation_sha256,
            state_after=BrowserBudgetState(1, 0, 64, 0, 50),
            observed_bytes=64,
            screenshots_captured=0,
            elapsed_milliseconds=50,
        )
        return BrowserActionReceipt(
            status=BrowserActionStatus.COMPLETED,
            reason="completed",
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            intent_sha256=DIGEST_A,
            execution_request_id="ECRQ-BROWSER-HEALTH-1",
            execution_request_sha256=DIGEST_B,
            admission_receipt_id="ECAR-BROWSER-HEALTH-1",
            admission_receipt_sha256=DIGEST_C,
            policy_id="ABP-BROWSER-HEALTH-1",
            policy_sha256=DIGEST_D,
            binding=self.binding,
            binding_sha256=sha(self.binding.to_dict()),
            action=BrowserAction.READ_METADATA,
            session_id=self.binding.session_id,
            principal_label=principal,
            intended_origin=ORIGIN,
            driver_called=True,
            budget_reservation_id=reservation.reservation_id,
            budget_reservation_sha256=reservation.reservation_sha256,
            budget_completion_sha256=completion.completion_sha256,
            pre_url=TARGET_URL,
            pre_origin=ORIGIN,
            pre_session_attestation_sha256=pre,
            post_url=TARGET_URL,
            post_origin=ORIGIN,
            post_session_attestation_sha256=post,
            observed_bytes=64,
            screenshots_captured=0,
            elapsed_milliseconds=50,
            evidence_reference="evidref:browser-health",
            transcript=(event,),
            browser_action_performed=True,
        )

    def make_session_receipt(self) -> TargetSessionReceipt:
        reservation = LeaseUseReservationEvidence(DIGEST_D)
        completion = LeaseUseCompletionEvidence(
            reservation_id=reservation.reservation_id,
            reservation_sha256=reservation.reservation_sha256,
            reservation_key_sha256=reservation.reservation_key_sha256,
            outcome="completed",
            provider_called=True,
        )
        event = SessionTranscriptEvent(
            sequence=1,
            stage="completed",
            detail_sha256=DIGEST_C,
            observed_at="2026-09-20T12:00:03Z",
            monotonic_tick=103,
            previous_event_sha256=None,
        )
        return TargetSessionReceipt(
            status=SessionAcquisitionStatus.COMPLETED,
            reason="completed",
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            intent_sha256=DIGEST_A,
            execution_request_id="ECRQ-SESSION-HEALTH-1",
            execution_request_sha256=DIGEST_B,
            admission_receipt_id="ECAR-SESSION-HEALTH-1",
            admission_receipt_sha256=DIGEST_C,
            execution_policy_id="ECP-SESSION-HEALTH-1",
            execution_policy_sha256=DIGEST_D,
            runtime_policy_id="ASP-SESSION-HEALTH-1",
            runtime_policy_sha256=DIGEST_A,
            binding=self.binding,
            lease_source_kind="opaque_exact_binding",
            lease_id=self.binding.lease_id,
            lease_sha256=DIGEST_B,
            lease_binding_sha256=DIGEST_C,
            lease_use_number=1,
            lease_use_reservation_key_sha256=DIGEST_D,
            lease_use_reservation_status=LeaseUseReservationStatus.COMPLETED,
            lease_use_reservation_id=reservation.reservation_id,
            lease_use_reservation_sha256=reservation.reservation_sha256,
            lease_use_completion_sha256=completion.completion_sha256,
            provider_called=True,
            authentication_attempts=1,
            session_id=self.binding.session_id,
            principal_label="principalref:alice",
            session_expires_at="2026-09-20T12:05:00Z",
            session_attestation_sha256=DIGEST_D,
            principal_attestation_sha256=DIGEST_A,
            cleanup_obligation_ref="obligationref:cleanup-health-1",
            cleanup_status=CleanupStatus.PENDING_EXTERNAL_VERIFICATION,
            revocation_obligation_ref="obligationref:revoke-health-1",
            revocation_status=(RevocationStatus.CHECKED_NOT_REVOKED_AFTER_AUTHENTICATION),
            revocation_evidence_sha256=(DIGEST_B, DIGEST_C),
            credential_material_observed=False,
            transcript=(event,),
        )

    def make_observations(
        self,
        *,
        latency: int = 50,
        latency_state: HealthSignalState = HealthSignalState.HEALTHY,
        latency_detail: str = "within_latency_threshold",
        observed_at: str = "2026-09-20T12:00:04Z",
        expires_at: str = "2026-09-20T12:03:00Z",
    ) -> tuple[TargetHealthObservation, ...]:
        values = (
            (
                HealthDimension.REACHABILITY,
                HealthSignalState.HEALTHY,
                "reachable",
                BoundarySourceKind.HTTP,
                self.http_receipt,
                None,
            ),
            (
                HealthDimension.LATENCY,
                latency_state,
                latency_detail,
                BoundarySourceKind.BROWSER,
                self.browser_receipt,
                latency,
            ),
            (
                HealthDimension.AUTHENTICATION_CONTINUITY,
                HealthSignalState.HEALTHY,
                "session_continuous",
                BoundarySourceKind.TARGET_SESSION,
                self.session_receipt,
                None,
            ),
            (
                HealthDimension.WAF,
                HealthSignalState.HEALTHY,
                "expected_control_observed",
                BoundarySourceKind.HTTP,
                self.http_receipt,
                None,
            ),
            (
                HealthDimension.SERVICE_HEALTH,
                HealthSignalState.HEALTHY,
                "service_healthy",
                BoundarySourceKind.BROWSER,
                self.browser_receipt,
                None,
            ),
        )
        return tuple(
            TargetHealthObservation(
                dimension=dimension,
                state=state,
                detail_code=detail,
                source_kind=source_kind,
                source_receipt_id=receipt.receipt_id,
                source_receipt_sha256=receipt.receipt_sha256,
                evidence_sha256=DIGEST_D,
                observed_at=observed_at,
                expires_at=expires_at,
                latency_milliseconds=latency_value,
            )
            for dimension, state, detail, source_kind, receipt, latency_value in values
        )

    def observe(self, **changes):
        arguments = {
            "scope": self.scope,
            "execution_request": self.request,
            "admission": self.admission,
            "policy": self.policy,
            "scope_budget_state": self.scope_budget,
            "runtime_budget_state": self.budget,
            "safety_snapshot": self.safety,
            "clock_observation": self.clock,
            "observations": self.observations,
            "boundary_receipts": self.receipts,
        }
        arguments.update(changes)
        return observe_authorized_target_health(**arguments)

    def test_completed_receipt_composes_all_boundaries_and_dimensions(self) -> None:
        receipt = self.observe()
        self.assertEqual(receipt.status, TargetHealthStatus.COMPLETED)
        self.assertEqual(receipt.overall_health, HealthSignalState.HEALTHY)
        self.assertEqual(
            tuple(item.dimension for item in receipt.observations),
            tuple(HealthDimension),
        )
        self.assertEqual(
            {item.source_kind for item in receipt.source_receipts},
            set(BoundarySourceKind),
        )
        self.assertFalse(receipt.external_call_performed)
        self.assertFalse(receipt.network_call_performed)
        self.assertFalse(receipt.browser_action_performed)
        self.assertFalse(receipt.authentication_performed)
        self.assertEqual(receipt.authority_effect, "none")
        self.assertEqual(receipt.qualification_effect, "none")
        self.assertEqual(dict(verify_target_health_receipt(receipt.to_dict())), receipt.to_dict())

    def test_receipt_and_observations_are_deterministic(self) -> None:
        first = self.observe()
        second = self.observe()
        self.assertEqual(first.receipt_id, second.receipt_id)
        self.assertEqual(first.receipt_sha256, second.receipt_sha256)
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_completed_receipt_requires_exact_safety_and_budget_attestations(self) -> None:
        receipt = self.observe()
        for changes in (
            {"safety_attestation": None, "safety_attestation_sha256": None},
            {"budget_state": None, "budget_state_sha256": None},
        ):
            with (
                self.subTest(fields=tuple(changes)),
                self.assertRaisesRegex(
                    AuthorizedTargetHealthRuntimeError,
                    "requires exact safety and budget",
                ),
            ):
                replace(receipt, **changes, receipt_id="", receipt_sha256="")

        document = receipt.to_dict()
        document["safety_attestation"]["canceled"] = True
        body = {
            key: value
            for key, value in document.items()
            if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
        }
        digest = sha({"body": body, "kind": document["kind"]})
        document["receipt_sha256"] = digest
        document["receipt_id"] = "THR-" + digest[7:39].upper()
        with self.assertRaises(AuthorizedTargetHealthRuntimeError):
            verify_target_health_receipt(document)

    def test_latency_threshold_derives_degraded_overall_state(self) -> None:
        observations = self.make_observations(
            latency=250,
            latency_state=HealthSignalState.DEGRADED,
            latency_detail="above_healthy_latency_threshold",
        )
        receipt = self.observe(observations=observations)
        self.assertEqual(receipt.status, TargetHealthStatus.COMPLETED)
        self.assertEqual(receipt.overall_health, HealthSignalState.DEGRADED)
        self.assertEqual(receipt.reason, "observed_degraded")

    def test_scope_admission_and_policy_substitution_fail_closed(self) -> None:
        outside = replace(
            self.policy,
            target_url="https://outside.example/assess/health",
            policy_id="",
            policy_sha256="",
        )
        outside_request = replace(
            self.request,
            payload_sha256=outside.policy_sha256,
            payload_size_bytes=len(canonical_json(outside.to_dict()).encode("ascii")),
            request_id="",
            request_sha256="",
        )
        outside_admission = replace(
            self.admission,
            request_id=outside_request.request_id,
            request_sha256=outside_request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        receipt = self.observe(
            execution_request=outside_request,
            admission=outside_admission,
            policy=outside,
        )
        self.assertEqual(receipt.status, TargetHealthStatus.REJECTED)
        self.assertEqual(receipt.reason, "scope_rejected")
        blocked = replace(
            self.admission,
            status=AdmissionStatus.BLOCKED,
            reason="canceled",
            receipt_id="",
            receipt_sha256="",
        )
        blocked_receipt = self.observe(admission=blocked)
        self.assertEqual(blocked_receipt.reason, "admission_rejected")

    def test_safety_and_budget_attestations_fail_closed(self) -> None:
        canceled = replace(self.safety, canceled=True, attestation_sha256="")
        self.assertEqual(self.observe(safety_snapshot=canceled).reason, "safety_rejected")
        stale = replace(
            self.safety,
            observed_at="2026-09-20T11:57:00Z",
            expires_at="2026-09-20T12:00:09Z",
            attestation_sha256="",
        )
        self.assertEqual(self.observe(safety_snapshot=stale).reason, "stale_attestation")
        exhausted = replace(
            self.budget,
            requests_used=self.policy.request_ceiling,
            state_id="",
            state_sha256="",
        )
        self.assertEqual(
            self.observe(runtime_budget_state=exhausted).reason,
            "budget_rejected",
        )
        self.assertEqual(
            self.observe(safety_snapshot=None).reason,
            "missing_attestation",
        )

    def test_stale_missing_and_mismatched_observations_fail_closed(self) -> None:
        stale = self.make_observations(
            observed_at="2026-09-20T12:00:04Z",
            expires_at="2026-09-20T12:00:09Z",
        )
        self.assertEqual(self.observe(observations=stale).reason, "stale_attestation")
        self.assertEqual(
            self.observe(observations=self.observations[:-1]).reason,
            "missing_attestation",
        )
        wrong_source = replace(
            self.observations[0],
            source_receipt_sha256=DIGEST_A,
            observation_id="",
            observation_sha256="",
        )
        values = (wrong_source, *self.observations[1:])
        self.assertEqual(self.observe(observations=values).reason, "missing_attestation")

    def test_invalid_source_kind_latency_and_overclaim_fail_closed(self) -> None:
        waf = replace(
            self.observations[3],
            source_kind=BoundarySourceKind.TARGET_SESSION,
            source_receipt_id=self.session_receipt.receipt_id,
            source_receipt_sha256=self.session_receipt.receipt_sha256,
            observation_id="",
            observation_sha256="",
        )
        values = (*self.observations[:3], waf, self.observations[4])
        self.assertEqual(self.observe(observations=values).reason, "source_rejected")
        bad_latency = self.make_observations(
            latency=501,
            latency_state=HealthSignalState.DEGRADED,
            latency_detail="above_healthy_latency_threshold",
        )
        self.assertEqual(
            self.observe(observations=bad_latency).reason,
            "overclaim_rejected",
        )
        with self.assertRaisesRegex(
            AuthorizedTargetHealthRuntimeError,
            "overclaims",
        ):
            replace(
                self.observations[0],
                state=HealthSignalState.UNHEALTHY,
                observation_id="",
                observation_sha256="",
            )

    def test_source_receipt_binding_and_freshness_fail_closed(self) -> None:
        foreign_binding = replace(self.binding, target_id="target:other")
        foreign = replace(
            self.http_receipt,
            binding=foreign_binding,
            receipt_id="",
            receipt_sha256="",
        )
        receipt = self.observe(
            boundary_receipts=(foreign, self.browser_receipt, self.session_receipt)
        )
        self.assertEqual(receipt.reason, "binding_rejected")
        stale_event = replace(
            self.http_receipt.transcript[0],
            observed_at="2026-09-20T11:57:00Z",
            event_sha256="",
        )
        stale_receipt = replace(
            self.http_receipt,
            transcript=(stale_event,),
            transcript_id="",
            transcript_sha256="",
            receipt_id="",
            receipt_sha256="",
        )
        stale_observations = tuple(
            replace(
                item,
                source_receipt_id=stale_receipt.receipt_id,
                source_receipt_sha256=stale_receipt.receipt_sha256,
                observation_id="",
                observation_sha256="",
            )
            if item.source_kind is BoundarySourceKind.HTTP
            else item
            for item in self.observations
        )
        result = self.observe(
            boundary_receipts=(
                stale_receipt,
                self.browser_receipt,
                self.session_receipt,
            ),
            observations=stale_observations,
        )
        self.assertEqual(result.reason, "stale_attestation")

    def test_strict_verifier_rejects_tampering_unknown_duplicate_and_noncanonical(self) -> None:
        document = self.observe().to_dict()
        changed = copy.deepcopy(document)
        changed["overall_health"] = "degraded"
        with self.assertRaises(AuthorizedTargetHealthRuntimeError):
            verify_target_health_receipt(changed)
        unknown = copy.deepcopy(document)
        unknown["unexpected"] = True
        with self.assertRaises(AuthorizedTargetHealthRuntimeError):
            verify_target_health_receipt(unknown)
        text = canonical_json(document)
        with self.assertRaisesRegex(AuthorizedTargetHealthRuntimeError, "canonical"):
            verify_target_health_receipt(json.dumps(document))
        duplicate = text[:-1] + ',"status":"completed"}'
        with self.assertRaisesRegex(AuthorizedTargetHealthRuntimeError, "duplicate"):
            verify_target_health_receipt(duplicate)

    def test_typed_parser_preserves_receipt_identity_and_verifier_behavior(self) -> None:
        receipt = self.observe()
        document = receipt.to_dict()
        text = canonical_json(document)
        for raw in (document, text, text.encode("ascii")):
            parsed = parse_target_health_receipt(raw)
            self.assertEqual(parsed, receipt)
            self.assertEqual(parsed.receipt_id, receipt.receipt_id)
            self.assertEqual(parsed.receipt_sha256, receipt.receipt_sha256)
            self.assertEqual(dict(verify_target_health_receipt(raw)), document)

    @unittest.skipUnless(Draft202012Validator is not None, "jsonschema unavailable")
    def test_schema_accepts_receipts_and_rejects_unknown_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        document = self.observe().to_dict()
        validator.validate(document)
        rejected = self.observe(safety_snapshot=None).to_dict()
        validator.validate(rejected)
        mismatched = copy.deepcopy(rejected)
        mismatched["safety_attestation_sha256"] = DIGEST_A
        self.assertTrue(list(validator.iter_errors(mismatched)))
        changed = copy.deepcopy(document)
        changed["unexpected"] = True
        self.assertTrue(list(validator.iter_errors(changed)))
        for field in ("safety_attestation", "budget_state"):
            changed = copy.deepcopy(document)
            changed[field] = None
            self.assertTrue(list(validator.iter_errors(changed)))

    def test_artifacts_are_ascii_and_contain_no_authorship_markers(self) -> None:
        markers = tuple(
            "".join(parts)
            for parts in (
                ("generated", " by"),
                ("written", " by ai"),
                ("as", " an ai"),
                ("chat", "gpt"),
                ("code", "x"),
                ("clau", "de"),
                ("gem", "ini"),
                ("co-authored", "-by"),
            )
        )
        for path in FILES:
            data = path.read_bytes()
            data.decode("ascii")
            lowered = data.decode("ascii").lower()
            self.assertFalse(any(marker in lowered for marker in markers), path)
            self.assertNotIn("\u2013", lowered)
            self.assertNotIn("\u2014", lowered)


if __name__ == "__main__":
    unittest.main()
