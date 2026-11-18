from __future__ import annotations

import copy
import hashlib
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sunderkey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.assessment_transport_contracts import (
    AdapterIdentity,
    AssessmentBinding,
    AuthenticationMode,
    MimeLimit,
    PrincipalCredentialReference,
    TargetSessionIntent,
    TransportBudget,
    canonical_json,
)
from sunderkey.authorized_target_session_runtime import (
    AuthorizedTargetSessionPolicy,
    AuthorizedTargetSessionRuntimeError,
    CredentialSessionProviderFailure,
    CredentialSessionResult,
    LeaseUseCompletionEvidence,
    LeaseUseReservationEvidence,
    LeaseUseReservationStatus,
    LeaseUseStoreFailure,
    OpaqueLeaseBinding,
    RevocationObservation,
    RevocationStatus,
    SessionAcquisitionStatus,
    TargetSessionSafetySnapshot,
    execute_authorized_target_session,
    principal_attestation_sha256,
    session_attestation_sha256,
    verify_target_session_receipt,
)
from sunderkey.credential_broker_contracts import CredentialLease, LeaseMode
from sunderkey.execution_control_runtime import (
    AdmissionReceipt,
    AdmissionStatus,
    ClockObservation,
    ExecutionBinding,
    ExecutionRequest,
    HealthState,
)
from sunderkey.signed_scope_compiler import compile_signed_scope, verify_signed_scope

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "authorized-target-session-receipt-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "authorized_target_session_runtime.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "authorized-target-session-runtime.md",
)
NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
TECHNIQUE_ID = "TECH-SESSION-001"


def sha(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def scope_spec() -> dict:
    return {
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
            "https_origins": ["https://app.example.test"],
            "exact_hosts": ["app.example.test"],
            "wildcard_subdomains": [],
            "cidrs": [],
            "ports": [443],
            "http_methods": ["GET", "POST"],
            "path_prefixes": ["/login"],
        },
        "exclusions": [],
        "protected_endpoints": [],
        "budgets": {
            "max_requests": 20,
            "max_concurrency": 2,
            "max_requests_per_minute": 20,
        },
        "impact_tier_ceiling": "R2",
        "allowed_technique_ids": [TECHNIQUE_ID],
        "data_handling": {
            "classification": "confidential",
            "collection": "metadata_only",
            "storage": "ephemeral_encrypted",
            "retention_days": 1,
            "redaction_required": True,
        },
        "emergency_stop_contact_id": "soc.primary",
    }


def verified_scope():
    key = Ed25519PrivateKey.generate()
    signed = compile_signed_scope(scope_spec(), key, now=NOW)
    return verify_signed_scope(
        signed,
        key.public_key(),
        expected_issuer="assessment-authority.example",
        expected_key_id="scope-signing-key.2026-09",
        now=NOW,
    )


class FakeClock:
    def __init__(self, ticks: tuple[int, ...] = tuple(range(101, 140))) -> None:
        self.ticks = list(ticks)

    def observe(self) -> ClockObservation:
        tick = self.ticks.pop(0)
        return ClockObservation(f"2026-09-20T12:00:{tick - 100:02d}Z", tick)


class FailingClock:
    def observe(self) -> ClockObservation:
        raise RuntimeError("clock unavailable")


class FakeSafety:
    def __init__(
        self,
        binding_sha256: str,
        request_sha256: str,
        *,
        health: HealthState = HealthState.HEALTHY,
        canceled: bool = False,
        emergency_stop: bool = False,
        script: tuple[TargetSessionSafetySnapshot, ...] = (),
    ) -> None:
        self.snapshot = TargetSessionSafetySnapshot(
            binding_sha256,
            request_sha256,
            health,
            canceled,
            emergency_stop,
        )
        self.script = list(script)
        self.calls = 0

    def observe(self) -> TargetSessionSafetySnapshot:
        self.calls += 1
        if self.script:
            return self.script.pop(0)
        return self.snapshot


class FakeRevocation:
    def __init__(self, lease_id: str, lease_sha256: str, revoked_at: int | None = None) -> None:
        self.lease_id = lease_id
        self.lease_sha256 = lease_sha256
        self.revoked_at = revoked_at
        self.calls = 0

    def observe(self, lease_id: str, lease_sha256: str) -> RevocationObservation:
        self.calls += 1
        return RevocationObservation(
            self.lease_id,
            self.lease_sha256,
            self.revoked_at == self.calls,
            sha({"revocation_call": self.calls}),
        )


class FakeLeaseUseStore:
    def __init__(self, barrier: threading.Barrier | None = None) -> None:
        self.barrier = barrier
        self.lock = threading.Lock()
        self.reservations = {}
        self.used_numbers = set()
        self.one_time_leases = set()
        self.completions = {}

    def reserve(self, request):
        if self.barrier is not None:
            self.barrier.wait(timeout=5)
        lease_identity = (request.lease_id, request.lease_sha256)
        use_identity = (*lease_identity, request.lease_use_number)
        with self.lock:
            if use_identity in self.used_numbers or (
                request.lease_mode is LeaseMode.ONE_TIME and lease_identity in self.one_time_leases
            ):
                raise LeaseUseStoreFailure("lease_use_replayed")
            evidence = LeaseUseReservationEvidence(request.reservation_key_sha256)
            self.used_numbers.add(use_identity)
            if request.lease_mode is LeaseMode.ONE_TIME:
                self.one_time_leases.add(lease_identity)
            self.reservations[evidence.reservation_id] = evidence
            return evidence

    def complete(self, reservation, outcome, provider_called):
        with self.lock:
            if (
                self.reservations.get(reservation.reservation_id) != reservation
                or reservation.reservation_id in self.completions
            ):
                raise LeaseUseStoreFailure("lease_use_completion_failure")
            evidence = LeaseUseCompletionEvidence(
                reservation_id=reservation.reservation_id,
                reservation_sha256=reservation.reservation_sha256,
                reservation_key_sha256=reservation.reservation_key_sha256,
                outcome=outcome,
                provider_called=provider_called,
            )
            self.completions[reservation.reservation_id] = evidence
            return evidence


class FakeProvider:
    def __init__(
        self,
        *,
        result: CredentialSessionResult | None = None,
        failure: Exception | None = None,
        mutation: str | None = None,
    ) -> None:
        self.result = result
        self.failure = failure
        self.mutation = mutation
        self.calls = 0
        self.commands = []

    def acquire(self, command):
        self.calls += 1
        self.commands.append(command)
        if self.failure is not None:
            raise self.failure
        if self.result is not None:
            return self.result
        expires = "2026-09-20T12:05:00Z"
        values = {
            "succeeded": True,
            "failure_code": None,
            "session_id": command.requested_session_id,
            "principal_label": command.principal_label,
            "isolated": True,
            "expires_at": expires,
            "authentication_attempts": 1,
            "session_attestation_sha256": session_attestation_sha256(command, expires),
            "principal_attestation_sha256": principal_attestation_sha256(command),
            "cleanup_obligation_ref": "obligationref:cleanup-session",
            "revocation_obligation_ref": "obligationref:revoke-session",
        }
        mutations = {
            "session": ("session_id", "sessionref:other"),
            "principal": ("principal_label", "principalref:bob"),
            "isolation": ("isolated", False),
            "expiry": ("expires_at", "2026-09-20T12:20:00Z"),
            "session_attestation": ("session_attestation_sha256", DIGEST_A),
            "principal_attestation": ("principal_attestation_sha256", DIGEST_B),
            "cleanup": ("cleanup_obligation_ref", "obligationref:other-cleanup"),
            "revocation": ("revocation_obligation_ref", "obligationref:other-revocation"),
        }
        if self.mutation:
            key, value = mutations[self.mutation]
            values[key] = value
        return CredentialSessionResult(**values)


class AuthorizedTargetSessionRuntimePhase174Tests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.AuthorizedTargetSessionPolicy, AuthorizedTargetSessionPolicy)
        self.assertIs(
            sunderkey.AuthorizedTargetSessionRuntimeError,
            AuthorizedTargetSessionRuntimeError,
        )
        self.assertIs(
            sunderkey.execute_authorized_target_session,
            execute_authorized_target_session,
        )
        self.assertIs(
            sunderkey.verify_target_session_receipt,
            verify_target_session_receipt,
        )

    def setUp(self) -> None:
        self.scope = verified_scope()
        self.budget = TransportBudget(
            max_steps=5,
            max_request_bytes=1024,
            max_response_bytes=1024,
            max_total_request_bytes=4096,
            max_total_response_bytes=4096,
            max_redirects=0,
            mime_limits=(MimeLimit("text/html", 1024),),
        )
        self.assessment_binding = AssessmentBinding(
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            task_id="taskref:assessment-task",
            technique_id=TECHNIQUE_ID,
            authority_refs=("authority:scope-owner",),
            evidence_hashes=(DIGEST_A,),
            impact_tier="R1",
            decision_at="2026-09-20T12:00:00Z",
            stop_conditions=("Stop on health change.",),
            adapter=AdapterIdentity("adapter.injected-session", "1.0.0"),
            budget=self.budget,
        )
        self.intent = self.make_intent()
        self.lease = CredentialLease(
            descriptor_sha256=DIGEST_A,
            request_sha256=DIGEST_B,
            approval_sha256=sha({"approval": 1}),
            tenant_ref="tenantref:acme",
            assessment_ref="assessmentref:assessment-1",
            task_ref="taskref:assessment-task",
            requester_principal_ref="principalref:operator",
            subject_principal_ref="principalref:alice",
            target_ref="targetref:app-example",
            technique_ref=f"techniqueref:{TECHNIQUE_ID}",
            purpose_ref="purposeref:authorized-assessment",
            scope_refs=(f"scoperef:{self.scope.scope_id}",),
            action_tier="R1",
            lease_mode=LeaseMode.SESSION_BOUND,
            issuance_ref="issuanceref:lease-1",
            session_ref="sessionref:session-1",
            issued_at="2026-09-20T11:59:00Z",
            expires_at="2026-09-20T12:10:00Z",
            max_uses=2,
            renewal_of_lease_sha256=None,
        )
        self.execution_binding = ExecutionBinding(
            tenant_id="tenantref:acme",
            context_id="taskref:assessment-task",
            context_sha256=DIGEST_A,
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            target_id="targetref:app-example",
            target_sha256=DIGEST_B,
            session_id="sessionref:session-1",
            lease_id=self.lease.lease_id,
            fence_epoch=9,
        )
        self.policy = AuthorizedTargetSessionPolicy(
            execution_binding=self.execution_binding,
            execution_policy_id="ECP-0123456789ABCDEF0123456789ABCDEF",
            execution_policy_sha256=DIGEST_A,
            assessment_ref="assessmentref:assessment-1",
            task_ref="taskref:assessment-task",
            scope_ref=f"scoperef:{self.scope.scope_id}",
            target_ref="targetref:app-example",
            technique_ref=f"techniqueref:{TECHNIQUE_ID}",
            purpose_ref="purposeref:authorized-assessment",
            login_origin="https://app.example.test",
            cleanup_obligation_ref="obligationref:cleanup-session",
            revocation_obligation_ref="obligationref:revoke-session",
            max_session_ttl_seconds=600,
        )
        self.request = self.make_request()
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

    def make_intent(
        self,
        *,
        login_url: str = "https://app.example.test/login",
        references: tuple[PrincipalCredentialReference, ...] | None = None,
        principal: str = "principalref:alice",
        mode: AuthenticationMode = AuthenticationMode.FORM_LOGIN,
    ) -> TargetSessionIntent:
        return TargetSessionIntent(
            binding=self.assessment_binding,
            sequence=1,
            mode=mode,
            login_url=login_url,
            method="POST",
            principal_label=principal,
            credential_references=references
            or (PrincipalCredentialReference("principalref:alice", "credref:alice"),),
            requested_session_id="sessionref:session-1",
        )

    def make_request(
        self,
        *,
        intent: TargetSessionIntent | None = None,
        binding: ExecutionBinding | None = None,
        attempt: int = 1,
    ) -> ExecutionRequest:
        selected = intent or self.intent
        return ExecutionRequest(
            binding=binding or self.execution_binding,
            policy_id=self.policy.execution_policy_id,
            policy_sha256=self.policy.execution_policy_sha256,
            idempotency_key="session:assessment-1:attempt-1",
            operation_code="authorized_target_session",
            payload_sha256=selected.intent_sha256,
            payload_size_bytes=len(canonical_json(selected.to_dict()).encode("ascii")),
            attempt_number=attempt,
            prior_execution_sha256=DIGEST_B if attempt > 1 else None,
            cleanup_obligation_sha256=sha(
                {"cleanup_obligation_ref": self.policy.cleanup_obligation_ref}
            ),
        )

    def safety(self, request: ExecutionRequest | None = None, **changes) -> FakeSafety:
        selected = request or self.request
        return FakeSafety(
            sha(selected.binding.to_dict()),
            selected.request_sha256,
            **changes,
        )

    def invoke(self, **overrides):
        request = overrides.pop("execution_request", self.request)
        lease = overrides.pop("lease", self.lease)
        values = {
            "scope": self.scope,
            "intent": self.intent,
            "execution_request": request,
            "admission": self.admission,
            "policy": self.policy,
            "lease": lease,
            "lease_use_number": 1,
            "clock": FakeClock(),
            "safety_monitor": self.safety(request),
            "revocation_checker": FakeRevocation(lease.lease_id, lease.lease_sha256),
            "lease_use_store": FakeLeaseUseStore(),
            "provider": FakeProvider(),
        }
        values.update(overrides)
        return execute_authorized_target_session(**values)

    def opaque_lease(self, **changes) -> OpaqueLeaseBinding:
        values = {
            "lease_id": self.lease.lease_id,
            "lease_sha256": self.lease.lease_sha256,
            "tenant_ref": self.lease.tenant_ref,
            "assessment_ref": self.lease.assessment_ref,
            "task_ref": self.lease.task_ref,
            "subject_principal_ref": self.lease.subject_principal_ref,
            "target_ref": self.lease.target_ref,
            "technique_ref": self.lease.technique_ref,
            "purpose_ref": self.lease.purpose_ref,
            "scope_refs": self.lease.scope_refs,
            "lease_mode": self.lease.lease_mode,
            "session_ref": self.lease.session_ref,
            "issued_at": self.lease.issued_at,
            "expires_at": self.lease.expires_at,
            "max_uses": self.lease.max_uses,
        }
        values.update(changes)
        return OpaqueLeaseBinding(**values)

    def test_completed_session_is_single_attempt_content_addressed_and_secret_free(self) -> None:
        provider = FakeProvider()
        lease_use_store = FakeLeaseUseStore()
        revocation = FakeRevocation(self.lease.lease_id, self.lease.lease_sha256)
        receipt = self.invoke(
            provider=provider,
            revocation_checker=revocation,
            lease_use_store=lease_use_store,
        )
        self.assertEqual(receipt.status, SessionAcquisitionStatus.COMPLETED)
        self.assertEqual(
            receipt.lease_use_reservation_status,
            LeaseUseReservationStatus.COMPLETED,
        )
        self.assertIsNotNone(receipt.lease_use_completion_sha256)
        self.assertEqual(len(lease_use_store.reservations), 1)
        self.assertEqual(len(lease_use_store.completions), 1)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(revocation.calls, 3)
        command = provider.commands[0]
        self.assertEqual(command.maximum_attempts, 1)
        self.assertFalse(command.retries_allowed)
        self.assertEqual(command.credential_reference, "credref:alice")
        serialized = canonical_json(receipt.to_dict())
        self.assertNotIn("credref:alice", serialized)
        self.assertFalse(receipt.credential_material_observed)
        self.assertEqual(receipt.authority_effect, "none")
        self.assertEqual(receipt.qualification_effect, "none")
        verified = verify_target_session_receipt(serialized)
        self.assertEqual(verified["receipt_id"], receipt.receipt_id)

    def test_sequential_and_concurrent_replay_reserve_once_before_provider(self) -> None:
        store = FakeLeaseUseStore()
        first_provider = FakeProvider()
        first = self.invoke(lease_use_store=store, provider=first_provider)
        second_provider = FakeProvider()
        second = self.invoke(lease_use_store=store, provider=second_provider)
        self.assertEqual(first.status, SessionAcquisitionStatus.COMPLETED)
        self.assertEqual(
            second.status,
            SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION,
        )
        self.assertEqual(second.reason, "lease_use_replayed")
        self.assertEqual(first_provider.calls, 1)
        self.assertEqual(second_provider.calls, 0)

        concurrent_store = FakeLeaseUseStore(threading.Barrier(2))

        def invoke_once():
            provider = FakeProvider()
            receipt = self.invoke(lease_use_store=concurrent_store, provider=provider)
            return receipt, provider.calls

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(lambda _: invoke_once(), range(2)))
        self.assertEqual(sum(calls for _, calls in results), 1)
        self.assertEqual(
            sorted(receipt.reason for receipt, _ in results),
            ["completed", "lease_use_replayed"],
        )

    def test_one_time_lease_cannot_be_reused(self) -> None:
        lease = self.opaque_lease(
            lease_mode=LeaseMode.ONE_TIME,
            session_ref=None,
            max_uses=1,
        )
        store = FakeLeaseUseStore()
        first = self.invoke(
            lease=lease,
            revocation_checker=FakeRevocation(lease.lease_id, lease.lease_sha256),
            lease_use_store=store,
        )
        provider = FakeProvider()
        second = self.invoke(
            lease=lease,
            revocation_checker=FakeRevocation(lease.lease_id, lease.lease_sha256),
            lease_use_store=store,
            provider=provider,
        )
        self.assertEqual(first.status, SessionAcquisitionStatus.COMPLETED)
        self.assertEqual(second.reason, "lease_use_replayed")
        self.assertEqual(provider.calls, 0)

    def test_initial_clock_failure_returns_deterministic_rejected_receipt(self) -> None:
        provider = FakeProvider()
        first = self.invoke(clock=FailingClock(), provider=provider)
        second = self.invoke(clock=FailingClock(), provider=provider)
        self.assertEqual(first.status, SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION)
        self.assertEqual(first.reason, "clock_failure")
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(provider.calls, 0)

    def test_exact_opaque_lease_binding_is_accepted(self) -> None:
        opaque = self.opaque_lease()
        receipt = self.invoke(
            lease=opaque,
            revocation_checker=FakeRevocation(opaque.lease_id, opaque.lease_sha256),
        )
        self.assertEqual(receipt.status, SessionAcquisitionStatus.COMPLETED)
        self.assertEqual(receipt.lease_source_kind, "opaque_exact_binding")

    def test_admission_request_policy_and_lease_binding_mismatches_never_call_provider(
        self,
    ) -> None:
        blocked = replace(
            self.admission,
            status=AdmissionStatus.BLOCKED,
            reason="canceled",
            receipt_id="",
            receipt_sha256="",
        )
        other_binding = replace(self.execution_binding, tenant_id="tenantref:other")
        other_request = self.make_request(binding=other_binding)
        cases = (
            {"admission": blocked},
            {
                "execution_request": other_request,
                "safety_monitor": self.safety(other_request),
            },
            {"lease": self.opaque_lease(lease_id="CLZ-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
        )
        for changes in cases:
            with self.subTest(changes=tuple(changes)):
                provider = FakeProvider()
                receipt = self.invoke(provider=provider, **changes)
                self.assertEqual(
                    receipt.status,
                    SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION,
                )
                self.assertEqual(provider.calls, 0)

    def test_scope_origin_path_and_https_are_rechecked_before_provider(self) -> None:
        outside = self.make_intent(login_url="https://app.example.test/outside")
        request = self.make_request(intent=outside)
        admission = replace(
            self.admission,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        provider = FakeProvider()
        receipt = self.invoke(
            intent=outside,
            execution_request=request,
            admission=admission,
            safety_monitor=self.safety(request),
            provider=provider,
        )
        self.assertEqual(receipt.reason, "scope_rejected")
        self.assertEqual(provider.calls, 0)

    def test_credential_target_technique_purpose_expiry_and_usage_fail_closed(self) -> None:
        cases = (
            (self.opaque_lease(target_ref="targetref:other"), 1),
            (self.opaque_lease(technique_ref="techniqueref:TECH-OTHER-001"), 1),
            (self.opaque_lease(purpose_ref="purposeref:other"), 1),
            (self.opaque_lease(expires_at="2026-09-20T12:00:00Z"), 1),
            (self.opaque_lease(max_uses=1), 2),
        )
        for lease, use_number in cases:
            with self.subTest(lease=lease.binding_id, use_number=use_number):
                provider = FakeProvider()
                receipt = self.invoke(
                    lease=lease,
                    lease_use_number=use_number,
                    revocation_checker=FakeRevocation(lease.lease_id, lease.lease_sha256),
                    provider=provider,
                )
                self.assertEqual(
                    receipt.status,
                    SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION,
                )
                self.assertEqual(provider.calls, 0)

    def test_multi_principal_references_must_be_separate_and_selected_principal_exact(self) -> None:
        duplicate = self.make_intent(
            references=(
                PrincipalCredentialReference("principalref:alice", "credref:shared"),
                PrincipalCredentialReference("principalref:bob", "credref:shared"),
            ),
            mode=AuthenticationMode.MULTI_PRINCIPAL_TEST_ACCOUNTS,
        )
        request = self.make_request(intent=duplicate)
        admission = replace(
            self.admission,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        provider = FakeProvider()
        receipt = self.invoke(
            intent=duplicate,
            execution_request=request,
            admission=admission,
            safety_monitor=self.safety(request),
            provider=provider,
        )
        self.assertEqual(receipt.reason, "multi_principal_isolation_failure")
        self.assertEqual(provider.calls, 0)

    def test_health_cancellation_emergency_stop_and_clock_rollback_block_pre_call(self) -> None:
        cases = (
            {"safety_monitor": self.safety(health=HealthState.PAUSED)},
            {"safety_monitor": self.safety(canceled=True)},
            {"safety_monitor": self.safety(emergency_stop=True)},
            {"clock": FakeClock((101, 101, 102))},
        )
        for changes in cases:
            provider = FakeProvider()
            receipt = self.invoke(provider=provider, **changes)
            self.assertEqual(
                receipt.status,
                SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION,
            )
            self.assertEqual(provider.calls, 0)

    def test_second_time_observation_rechecks_scope_window_and_lease_before_reservation(
        self,
    ) -> None:
        for boundary in ("scope", "window", "lease"):
            with self.subTest(boundary=boundary):
                spec = scope_spec()
                if boundary == "scope":
                    spec["expires_at"] = "2026-09-20T12:00:02Z"
                    spec["assessment_window"]["ends_at"] = "2026-09-20T12:00:02Z"
                elif boundary == "window":
                    spec["assessment_window"]["ends_at"] = "2026-09-20T12:00:02Z"
                lease_type = CredentialLease

                def lease_factory(*args, **kwargs):
                    if boundary == "lease":
                        kwargs["expires_at"] = "2026-09-20T12:00:02Z"
                    return lease_type(*args, **kwargs)

                with (
                    mock.patch(__name__ + ".scope_spec", return_value=spec),
                    mock.patch(__name__ + ".CredentialLease", side_effect=lease_factory),
                ):
                    self.setUp()
                store = FakeLeaseUseStore()
                provider = FakeProvider()
                receipt = self.invoke(lease_use_store=store, provider=provider)
                self.assertEqual(provider.calls, 0)
                self.assertEqual(len(store.reservations), 0)
                self.assertEqual(len(store.completions), 0)
                self.assertEqual(
                    receipt.lease_use_reservation_status, LeaseUseReservationStatus.NOT_RESERVED
                )
                self.assertEqual(
                    receipt.reason, "lease_expired" if boundary == "lease" else "scope_rejected"
                )
                verify_target_session_receipt(receipt.to_dict())

    def test_final_time_observation_rechecks_scope_window_and_lease_after_reservation(
        self,
    ) -> None:
        for boundary in ("scope", "window", "lease"):
            with self.subTest(boundary=boundary):
                spec = scope_spec()
                if boundary == "scope":
                    spec["expires_at"] = "2026-09-20T12:00:03Z"
                    spec["assessment_window"]["ends_at"] = "2026-09-20T12:00:03Z"
                elif boundary == "window":
                    spec["assessment_window"]["ends_at"] = "2026-09-20T12:00:03Z"
                lease_type = CredentialLease

                def lease_factory(*args, **kwargs):
                    if boundary == "lease":
                        kwargs["expires_at"] = "2026-09-20T12:00:03Z"
                    return lease_type(*args, **kwargs)

                with (
                    mock.patch(__name__ + ".scope_spec", return_value=spec),
                    mock.patch(__name__ + ".CredentialLease", side_effect=lease_factory),
                ):
                    self.setUp()
                store = FakeLeaseUseStore()
                provider = FakeProvider()
                receipt = self.invoke(lease_use_store=store, provider=provider)
                self.assert_zero_call_reserved_rejection(receipt, store, provider)
                self.assertEqual(
                    receipt.reason, "lease_expired" if boundary == "lease" else "scope_rejected"
                )
                repeated = self.invoke(lease_use_store=store, provider=provider)
                self.assertEqual(repeated.reason, "lease_use_replayed")
                self.assertEqual(provider.calls, 0)

    def assert_zero_call_reserved_rejection(self, receipt, store, provider) -> None:
        self.assertEqual(receipt.status, SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION)
        self.assertFalse(receipt.provider_called)
        self.assertEqual(receipt.authentication_attempts, 0)
        self.assertEqual(provider.calls, 0)
        self.assertEqual(len(store.reservations), 1)
        self.assertEqual(len(store.completions), 1)
        self.assertEqual(receipt.lease_use_reservation_status, LeaseUseReservationStatus.COMPLETED)
        reservation = store.reservations[receipt.lease_use_reservation_id]
        completion = store.completions[receipt.lease_use_reservation_id]
        self.assertEqual(receipt.lease_use_reservation_sha256, reservation.reservation_sha256)
        self.assertEqual(receipt.lease_use_completion_sha256, completion.completion_sha256)
        self.assertEqual(completion.outcome, "rejected_before_authentication")
        self.assertFalse(completion.provider_called)
        self.assertEqual(receipt.cleanup_status.value, "not_required_before_provider")
        self.assertIsNone(receipt.session_id)
        verify_target_session_receipt(receipt.to_dict())

    def test_slow_reservation_refreshes_time_before_provider_without_refunding_use(self) -> None:
        clock = FakeClock()
        lease_type = CredentialLease

        def lease_factory(*args, **kwargs):
            kwargs["expires_at"] = "2026-09-20T12:00:05Z"
            return lease_type(*args, **kwargs)

        with mock.patch(__name__ + ".CredentialLease", side_effect=lease_factory):
            self.setUp()

        class SlowStore(FakeLeaseUseStore):
            def reserve(self, request):
                evidence = super().reserve(request)
                clock.ticks[0] = 107
                return evidence

        store = SlowStore()
        provider = FakeProvider()
        receipt = self.invoke(clock=clock, lease_use_store=store, provider=provider)
        self.assert_zero_call_reserved_rejection(receipt, store, provider)
        self.assertEqual(receipt.reason, "lease_expired")
        self.assertEqual(receipt.transcript[-1].observed_at, "2026-09-20T12:00:07Z")

    def test_reservation_callback_safety_and_revocation_changes_prevent_provider(self) -> None:
        for condition in ("canceled", "emergency_stop", "health", "revocation"):
            with self.subTest(condition=condition):
                self.setUp()
                safety = self.safety()
                revocation = FakeRevocation(self.lease.lease_id, self.lease.lease_sha256)

                class ChangingStore(FakeLeaseUseStore):
                    def reserve(self, request):
                        evidence = super().reserve(request)
                        if condition == "revocation":
                            revocation.revoked_at = revocation.calls + 1
                        elif condition == "health":
                            safety.snapshot = replace(safety.snapshot, health=HealthState.PAUSED)
                        else:
                            safety.snapshot = replace(safety.snapshot, **{condition: True})
                        return evidence

                store = ChangingStore()
                provider = FakeProvider()
                receipt = self.invoke(
                    safety_monitor=safety,
                    revocation_checker=revocation,
                    lease_use_store=store,
                    provider=provider,
                )
                self.assert_zero_call_reserved_rejection(receipt, store, provider)
                self.assertEqual(
                    receipt.reason,
                    {"revocation": "lease_revoked", "health": "health_not_healthy"}.get(
                        condition, condition
                    ),
                )
                if condition == "revocation":
                    self.assertEqual(receipt.revocation_status, RevocationStatus.REVOKED)
                    self.assertEqual(len(receipt.revocation_evidence_sha256), 1)

    def test_reserved_zero_call_settlement_failure_retains_pending_reservation(self) -> None:
        safety = self.safety()

        class FailingStore(FakeLeaseUseStore):
            def reserve(self, request):
                evidence = super().reserve(request)
                safety.snapshot = replace(safety.snapshot, canceled=True)
                return evidence

            def complete(self, reservation, outcome, provider_called):
                self.complete_arguments = (reservation, outcome, provider_called)
                raise LeaseUseStoreFailure("lease_use_completion_failure")

        store = FailingStore()
        provider = FakeProvider()
        receipt = self.invoke(safety_monitor=safety, lease_use_store=store, provider=provider)
        self.assertEqual(receipt.status, SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION)
        self.assertEqual(receipt.reason, "lease_use_completion_failure")
        self.assertFalse(receipt.provider_called)
        self.assertEqual(receipt.authentication_attempts, 0)
        self.assertEqual(provider.calls, 0)
        self.assertEqual(
            receipt.lease_use_reservation_status, LeaseUseReservationStatus.COMPLETION_FAILED
        )
        self.assertEqual(len(store.reservations), 1)
        self.assertEqual(len(store.completions), 0)
        self.assertEqual(store.complete_arguments[1:], ("rejected_before_authentication", False))
        self.assertIsNone(receipt.lease_use_completion_sha256)
        self.assertEqual(receipt.cleanup_status.value, "not_required_before_provider")
        verify_target_session_receipt(receipt.to_dict())

    def test_post_reservation_clock_failure_and_rollback_settle_without_provider(self) -> None:
        for fail in (False, True):
            with self.subTest(fail=fail):

                class FinalClock(FakeClock):
                    def observe(self):
                        if self.ticks[0] == 103:
                            if fail:
                                raise RuntimeError("clock unavailable")
                            return ClockObservation("2026-09-20T12:00:02Z", 102)
                        return super().observe()

                store = FakeLeaseUseStore()
                provider = FakeProvider()
                receipt = self.invoke(clock=FinalClock(), lease_use_store=store, provider=provider)
                self.assert_zero_call_reserved_rejection(receipt, store, provider)
                self.assertEqual(receipt.reason, "clock_failure" if fail else "clock_rollback")
                self.assertEqual(
                    [event.stage for event in receipt.transcript], ["pre_authentication"]
                )

    def test_fresh_revocation_proof_and_initial_transcript_remain_bound(self) -> None:
        clock = FakeClock()
        revocation = FakeRevocation(self.lease.lease_id, self.lease.lease_sha256)
        receipt = self.invoke(clock=clock, revocation_checker=revocation)
        self.assertEqual(receipt.status, SessionAcquisitionStatus.COMPLETED)
        self.assertEqual(revocation.calls, 3)
        initial, fresh, final = (sha({"revocation_call": number}) for number in (1, 2, 3))
        self.assertEqual(receipt.revocation_evidence_sha256, (fresh, final))
        self.assertEqual(
            receipt.transcript[0].detail_sha256,
            sha(
                {
                    "revocation_evidence_sha256": initial,
                    "safety_binding_sha256": sha(self.execution_binding.to_dict()),
                }
            ),
        )
        self.assertEqual(
            receipt.transcript[1].detail_sha256,
            sha(
                {
                    "reservation_sha256": receipt.lease_use_reservation_sha256,
                    "revocation_evidence_sha256": fresh,
                }
            ),
        )
        self.assertEqual(
            [
                (event.stage, event.observed_at, event.monotonic_tick)
                for event in receipt.transcript
            ],
            [
                ("pre_authentication", "2026-09-20T12:00:02Z", 102),
                ("lease_use_reserved", "2026-09-20T12:00:03Z", 103),
                ("completed", "2026-09-20T12:00:04Z", 104),
            ],
        )
        self.assertEqual(clock.ticks[0], 105)
        verify_target_session_receipt(receipt.to_dict())

    def test_revocation_state_survives_final_clock_and_settlement_failures(self) -> None:
        for check_fails in (False, True):
            for clock_fails in (False, True):
                for completion_fails in (False, True):
                    with self.subTest(
                        check_fails=check_fails,
                        clock_fails=clock_fails,
                        completion_fails=completion_fails,
                    ):

                        class FinalClock(FakeClock):
                            def observe(self):
                                if self.ticks[0] == 103:
                                    if clock_fails:
                                        raise RuntimeError("clock unavailable")
                                    return ClockObservation("2026-09-20T12:00:02Z", 102)
                                return super().observe()

                        class RevocationChecker(FakeRevocation):
                            def observe(self, lease_id, lease_sha256):
                                if check_fails and self.calls == 1:
                                    self.calls += 1
                                    raise RuntimeError("revocation unavailable")
                                return super().observe(lease_id, lease_sha256)

                        class SettlingStore(FakeLeaseUseStore):
                            def complete(self, reservation, outcome, provider_called):
                                if completion_fails:
                                    raise LeaseUseStoreFailure("lease_use_completion_failure")
                                return super().complete(reservation, outcome, provider_called)

                        revocation = RevocationChecker(
                            self.lease.lease_id, self.lease.lease_sha256, revoked_at=2
                        )
                        store = SettlingStore()
                        provider = FakeProvider()
                        receipt = self.invoke(
                            clock=FinalClock(),
                            revocation_checker=revocation,
                            lease_use_store=store,
                            provider=provider,
                        )
                        self.assertEqual(
                            receipt.status, SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION
                        )
                        self.assertEqual(
                            receipt.revocation_status,
                            RevocationStatus.CHECK_FAILED
                            if check_fails
                            else RevocationStatus.REVOKED,
                        )
                        self.assertEqual(
                            receipt.reason,
                            "lease_use_completion_failure"
                            if completion_fails
                            else ("clock_failure" if clock_fails else "clock_rollback"),
                        )
                        self.assertFalse(receipt.provider_called)
                        self.assertEqual(provider.calls, 0)
                        self.assertEqual(len(store.reservations), 1)
                        self.assertEqual(len(store.completions), 0 if completion_fails else 1)
                        if not check_fails:
                            self.assertEqual(
                                receipt.revocation_evidence_sha256, (sha({"revocation_call": 2}),)
                            )
                        verify_target_session_receipt(receipt.to_dict())

    def test_zero_call_completion_and_receipt_require_exact_rejected_compound_state(self) -> None:
        safety = self.safety()

        class CancelingStore(FakeLeaseUseStore):
            def reserve(self, request):
                evidence = super().reserve(request)
                safety.snapshot = replace(safety.snapshot, canceled=True)
                return evidence

        store = CancelingStore()
        receipt = self.invoke(safety_monitor=safety, lease_use_store=store)
        completion = store.completions[receipt.lease_use_reservation_id]
        for outcome in ("completed", "provider_failed", "postcondition_rejected", "other"):
            with self.subTest(outcome=outcome):
                with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "zero-call"):
                    replace(completion, outcome=outcome, completion_sha256="")
        for changes in (
            {"cleanup_status": self.invoke().cleanup_status},
            {"status": SessionAcquisitionStatus.PROVIDER_FAILED},
            {"status": SessionAcquisitionStatus.POSTCONDITION_REJECTED},
            {"authentication_attempts": 1},
            {"provider_called": True, "authentication_attempts": 1},
            {"lease_use_completion_sha256": DIGEST_A},
            {"lease_use_reservation_status": LeaseUseReservationStatus.NOT_RESERVED},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(AuthorizedTargetSessionRuntimeError):
                    replace(receipt, **changes, receipt_id="", receipt_sha256="")

    def test_provider_called_receipt_cannot_claim_rejection_before_authentication(self) -> None:
        store = FakeLeaseUseStore()
        completed = self.invoke(lease_use_store=store)
        actual_completion = store.completions[completed.lease_use_reservation_id]
        contradictory_completion = replace(
            actual_completion, outcome="rejected_before_authentication", completion_sha256=""
        )
        for reservation_status in (
            LeaseUseReservationStatus.COMPLETED,
            LeaseUseReservationStatus.COMPLETION_FAILED,
        ):
            with self.subTest(reservation_status=reservation_status):
                changes = {
                    "status": SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION,
                    "reason": "canceled",
                    "lease_use_reservation_status": reservation_status,
                    "lease_use_completion_sha256": (
                        contradictory_completion.completion_sha256
                        if reservation_status is LeaseUseReservationStatus.COMPLETED
                        else None
                    ),
                    "session_id": None,
                    "principal_label": None,
                    "session_expires_at": None,
                    "session_attestation_sha256": None,
                    "principal_attestation_sha256": None,
                    "receipt_id": "",
                    "receipt_sha256": "",
                }
                with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "provider call"):
                    replace(completed, **changes)
                if Draft202012Validator is not None:
                    validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
                    document = {
                        **completed.to_dict(),
                        **{
                            key: value
                            for key, value in changes.items()
                            if key not in {"receipt_id", "receipt_sha256"}
                        },
                    }
                    errors = list(validator.iter_errors(document))
                    self.assertTrue(any(list(error.path) == ["status"] for error in errors))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_only_bound_zero_call_reservation_states(self) -> None:
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        unreserved = self.invoke(safety_monitor=self.safety(canceled=True))
        receipts = [unreserved]
        for fail in (False, True):
            safety = self.safety()

            class SettlingStore(FakeLeaseUseStore):
                def reserve(self, request):
                    evidence = super().reserve(request)
                    safety.snapshot = replace(safety.snapshot, canceled=True)
                    return evidence

                def complete(self, reservation, outcome, provider_called):
                    if fail:
                        raise LeaseUseStoreFailure("lease_use_completion_failure")
                    return super().complete(reservation, outcome, provider_called)

            receipts.append(self.invoke(safety_monitor=safety, lease_use_store=SettlingStore()))
        for receipt in receipts:
            with self.subTest(status=receipt.lease_use_reservation_status):
                document = receipt.to_dict()
                validator.validate(document)
                for changes in (
                    {"authentication_attempts": 1},
                    {"cleanup_status": "pending_external_verification"},
                    {"status": "provider_failed"},
                ):
                    invalid = {**document, **changes}
                    self.assertTrue(list(validator.iter_errors(invalid)))
        completed = receipts[1].to_dict()
        for changes in (
            {"lease_use_reservation_id": None},
            {"lease_use_reservation_sha256": None},
            {"lease_use_completion_sha256": None},
            {"lease_use_reservation_status": "not_reserved"},
        ):
            self.assertTrue(list(validator.iter_errors({**completed, **changes})))
        pending = receipts[2].to_dict()
        self.assertTrue(
            list(validator.iter_errors({**pending, "lease_use_completion_sha256": DIGEST_A}))
        )

    def test_revocation_is_checked_before_and_after_provider(self) -> None:
        before = FakeRevocation(self.lease.lease_id, self.lease.lease_sha256, revoked_at=1)
        provider = FakeProvider()
        receipt = self.invoke(revocation_checker=before, provider=provider)
        self.assertEqual(receipt.revocation_status, RevocationStatus.REVOKED)
        self.assertEqual(provider.calls, 0)
        after = FakeRevocation(self.lease.lease_id, self.lease.lease_sha256, revoked_at=3)
        receipt = self.invoke(revocation_checker=after)
        self.assertEqual(receipt.status, SessionAcquisitionStatus.POSTCONDITION_REJECTED)
        self.assertEqual(receipt.revocation_status, RevocationStatus.REVOKED)

    def test_post_provider_stop_and_clock_rollback_reject_session(self) -> None:
        healthy = TargetSessionSafetySnapshot(
            sha(self.execution_binding.to_dict()),
            self.request.request_sha256,
            HealthState.HEALTHY,
            False,
            False,
        )
        canceled = replace(healthy, canceled=True)
        safety = FakeSafety(
            healthy.binding_sha256,
            healthy.request_sha256,
            script=(healthy, healthy, healthy, canceled),
        )
        receipt = self.invoke(safety_monitor=safety)
        self.assertEqual(receipt.status, SessionAcquisitionStatus.POSTCONDITION_REJECTED)
        self.assertEqual(receipt.reason, "canceled")
        receipt = self.invoke(clock=FakeClock((101, 102, 103, 103)))
        self.assertEqual(receipt.status, SessionAcquisitionStatus.POSTCONDITION_REJECTED)
        self.assertEqual(receipt.reason, "clock_rollback")

    def test_known_and_unexpected_provider_failures_are_single_call_and_sanitized(self) -> None:
        for failure, reason in (
            (CredentialSessionProviderFailure("identity_unavailable"), "identity_unavailable"),
            (RuntimeError("password=do-not-retain"), "provider_exception"),
        ):
            provider = FakeProvider(failure=failure)
            receipt = self.invoke(provider=provider)
            self.assertEqual(receipt.status, SessionAcquisitionStatus.PROVIDER_FAILED)
            self.assertEqual(receipt.reason, reason)
            self.assertEqual(provider.calls, 1)
            self.assertNotIn("do-not-retain", canonical_json(receipt.to_dict()))

    def test_failed_provider_result_cannot_claim_session(self) -> None:
        failed = CredentialSessionResult(
            succeeded=False,
            failure_code="authentication_denied",
            session_id=None,
            principal_label=None,
            isolated=False,
            expires_at=None,
            authentication_attempts=1,
            session_attestation_sha256=None,
            principal_attestation_sha256=None,
            cleanup_obligation_ref=None,
            revocation_obligation_ref=None,
        )
        receipt = self.invoke(provider=FakeProvider(result=failed))
        self.assertEqual(receipt.status, SessionAcquisitionStatus.PROVIDER_FAILED)
        self.assertIsNone(receipt.session_id)

    def test_session_principal_isolation_expiry_attestation_and_obligations_are_exact(self) -> None:
        for mutation in (
            "session",
            "principal",
            "isolation",
            "expiry",
            "session_attestation",
            "principal_attestation",
            "cleanup",
            "revocation",
        ):
            with self.subTest(mutation=mutation):
                provider = FakeProvider(mutation=mutation)
                receipt = self.invoke(provider=provider)
                self.assertEqual(
                    receipt.status,
                    SessionAcquisitionStatus.POSTCONDITION_REJECTED,
                )
                self.assertEqual(receipt.reason, "session_postcondition_rejected")
                self.assertEqual(provider.calls, 1)
                self.assertIsNone(receipt.session_id)

    def test_credential_material_result_is_rejected_before_it_can_cross_boundary(self) -> None:
        with self.assertRaisesRegex(
            AuthorizedTargetSessionRuntimeError,
            "unsafe flags",
        ):
            CredentialSessionResult(
                succeeded=False,
                failure_code="authentication_denied",
                session_id=None,
                principal_label=None,
                isolated=False,
                expires_at=None,
                authentication_attempts=1,
                session_attestation_sha256=None,
                principal_attestation_sha256=None,
                cleanup_obligation_ref=None,
                revocation_obligation_ref=None,
                credential_material_returned=True,
            )

    def test_strict_parser_rejects_unknown_duplicate_noncanonical_nonascii_and_tampering(
        self,
    ) -> None:
        receipt = self.invoke().to_dict()
        canonical = canonical_json(receipt)
        verify_target_session_receipt(canonical)
        with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "canonical"):
            verify_target_session_receipt(json.dumps(receipt, indent=2, sort_keys=True))
        with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "fields"):
            verify_target_session_receipt({**receipt, "authorization": "granted"})
        duplicate = canonical[:-1] + ',"status":"completed"}'
        with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "duplicate"):
            verify_target_session_receipt(duplicate)
        with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "ASCII"):
            verify_target_session_receipt(canonical + "\u2603")
        tampered = copy.deepcopy(receipt)
        tampered["reason"] = "validation_rejected"
        with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "reason"):
            verify_target_session_receipt(tampered)

    def test_completed_receipt_requires_exact_completed_reason(self) -> None:
        receipt = self.invoke()
        with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "reason"):
            replace(
                receipt,
                reason="validation_rejected",
                receipt_id="",
                receipt_sha256="",
            )
        document = receipt.to_dict()
        document["reason"] = "validation_rejected"
        body = {
            key: value
            for key, value in document.items()
            if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
        }
        digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_json({"body": body, "kind": document["kind"]}).encode("ascii")
            ).hexdigest()
        )
        document["receipt_sha256"] = digest
        document["receipt_id"] = "ASR-" + digest[7:39].upper()
        with self.assertRaisesRegex(AuthorizedTargetSessionRuntimeError, "reason"):
            verify_target_session_receipt(document)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_receipts_conform_to_draft_2020_12_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        receipt = self.invoke().to_dict()
        validator.validate(receipt)
        wrong_reason = copy.deepcopy(receipt)
        wrong_reason["reason"] = "validation_rejected"
        self.assertTrue(list(validator.iter_errors(wrong_reason)))
        incomplete_lease_use = copy.deepcopy(receipt)
        incomplete_lease_use["lease_use_reservation_status"] = "completion_failed"
        incomplete_lease_use["lease_use_completion_sha256"] = None
        body = {
            key: value
            for key, value in incomplete_lease_use.items()
            if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
        }
        digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_json({"body": body, "kind": incomplete_lease_use["kind"]}).encode("ascii")
            ).hexdigest()
        )
        incomplete_lease_use["receipt_sha256"] = digest
        incomplete_lease_use["receipt_id"] = "ASR-" + digest[7:39].upper()
        with self.assertRaisesRegex(
            AuthorizedTargetSessionRuntimeError,
            "lease-use completion evidence",
        ):
            verify_target_session_receipt(incomplete_lease_use)
        self.assertTrue(list(validator.iter_errors(incomplete_lease_use)))
        altered = copy.deepcopy(receipt)
        altered["credential_material_observed"] = True
        self.assertTrue(list(validator.iter_errors(altered)))

    def test_only_assigned_files_avoid_markers_and_unicode_dashes(self) -> None:
        markers = (
            "generated" + " by",
            "written" + " by ai",
            "as" + " an ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)
            lowered = text.lower()
            for marker in markers:
                self.assertNotIn(marker, lowered)


if __name__ == "__main__":
    unittest.main()
