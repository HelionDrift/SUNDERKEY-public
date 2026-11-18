"""Phase 207 repository-only target adapter conformance tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest
from dataclasses import replace
from pathlib import Path

import sunderkey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.authorized_http_runtime import (
    HttpBackendFailure,
    HttpBackendRequest,
)
from sunderkey.authorized_target_health_runtime import (
    TargetHealthReceipt,
    TargetHealthStatus,
)
from sunderkey.authorized_target_session_runtime import (
    CredentialSessionCommand,
    CredentialSessionProviderFailure,
    LeaseUseStoreFailure,
)
from sunderkey.execution_control_runtime import ExecutionBinding
from sunderkey.reference_http_adapter import (
    DigestBoundBodyProvider,
    ReferenceHttpBackend,
    ReferenceHttpTransportResponse,
    ReferenceTlsPeerEvidence,
    ScriptedDnsResolver,
)
from sunderkey.reference_target_session_adapter import (
    InMemoryAtomicLeaseUseStore,
    InMemoryLeaseRevocationChecker,
    OpaqueSessionTransportResult,
    ReferenceCredentialSessionProvider,
    SessionTransportStatus,
)
from sunderkey.target_adapter_conformance import (
    REQUIRED_REQUIREMENTS,
    AdapterStopState,
    TargetAdapterConformanceError,
    TargetAdapterConformanceObservation,
    build_target_adapter_conformance_report,
    canonical_json,
    canonical_sha256,
    verify_target_adapter_conformance_report,
)
from sunderkey.target_health_collector import (
    HealthSignatureMaterial,
    TargetHealthCollector,
    TargetHealthCollectorError,
    verify_signed_target_health_observation,
)

ROOT = Path(__file__).resolve().parents[2]
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
CERTIFICATE = "sha256:" + "c" * 64


class RecordingHttpTransport:
    def __init__(self, response: ReferenceHttpTransportResponse) -> None:
        self.response = response
        self.calls = 0
        self.request: HttpBackendRequest | None = None

    def exchange(self, request: HttpBackendRequest) -> ReferenceHttpTransportResponse:
        self.calls += 1
        self.request = request
        return self.response


class ScriptedSessionTransport:
    def __init__(self, result: OpaqueSessionTransportResult) -> None:
        self.result = result
        self.calls = 0
        self.credential_reference: str | None = None

    def acquire(self, command: CredentialSessionCommand) -> OpaqueSessionTransportResult:
        self.calls += 1
        self.credential_reference = command.credential_reference
        return self.result


class DeterministicSigner:
    def __init__(self) -> None:
        self.key = b"phase207-test-signing-key"

    def sign(self, payload: bytes) -> HealthSignatureMaterial:
        signature = hmac.new(self.key, payload, hashlib.sha256).digest()
        return HealthSignatureMaterial(
            algorithm="hmac_sha256_test_only",
            key_id="health-key:test-only",
            public_key_sha256="sha256:" + hashlib.sha256(self.key).hexdigest(),
            signature=base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        )

    def verify(self, payload: bytes, signature: HealthSignatureMaterial) -> bool:
        expected = self.sign(payload)
        return signature == expected


def command() -> CredentialSessionCommand:
    return CredentialSessionCommand(
        intent_sha256=DIGEST_A,
        execution_request_sha256=DIGEST_B,
        runtime_policy_sha256=CERTIFICATE,
        lease_id="lease:phase207",
        lease_sha256=DIGEST_A,
        lease_use_number=1,
        credential_reference="credref:phase207-opaque",
        login_url="https://app.example.test/login",
        method="POST",
        authentication_mode="password_brokered",
        requested_session_id="session:phase207",
        principal_label="principalref:alice",
    )


def rejected_health_receipt() -> TargetHealthReceipt:
    binding = ExecutionBinding(
        tenant_id="tenant:phase207",
        context_id="context:phase207",
        context_sha256=DIGEST_A,
        scope_id="scope:phase207",
        scope_sha256=DIGEST_B,
        target_id="target:phase207",
        target_sha256=CERTIFICATE,
        session_id="session:phase207",
        lease_id="lease:phase207",
        fence_epoch=1,
    )
    return TargetHealthReceipt(
        status=TargetHealthStatus.REJECTED,
        reason="source_rejected",
        overall_health=None,
        scope_id=binding.scope_id,
        scope_sha256=binding.scope_sha256,
        execution_request_id="request:phase207",
        execution_request_sha256=DIGEST_A,
        admission_receipt_id="admission:phase207",
        admission_receipt_sha256=DIGEST_B,
        execution_policy_id="policy:execution:phase207",
        execution_policy_sha256=CERTIFICATE,
        runtime_policy_id="policy:health:phase207",
        runtime_policy_sha256=DIGEST_A,
        binding=binding,
        binding_sha256=canonical_sha256(binding.to_dict()),
        target_url="https://app.example.test/health",
        observed_at="2026-09-21T12:00:00Z",
        monotonic_tick=1,
        safety_attestation=None,
        safety_attestation_sha256=None,
        budget_state=None,
        budget_state_sha256=None,
        source_receipts=(),
        observations=(),
        source_validation_performed=False,
    )


class TargetAdapterConformancePhase207Tests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(
            sunderkey.TargetHealthCollector,
            TargetHealthCollector,
        )
        self.assertIs(
            sunderkey.build_target_adapter_conformance_report,
            build_target_adapter_conformance_report,
        )

    def test_complete_conformance_report_is_strict_nonqualifying_evidence(self) -> None:
        observations = tuple(
            TargetAdapterConformanceObservation(
                requirement=requirement,
                passed=True,
                evidence_sha256=canonical_sha256({"requirement": requirement.value}),
                outcome_code="passed",
            )
            for requirement in REQUIRED_REQUIREMENTS
        )
        report = build_target_adapter_conformance_report(
            adapter_id="adapter:phase207-reference",
            adapter_release_sha256=DIGEST_A,
            observations=observations,
        )
        self.assertEqual(report.status, "passed_repository_conformance")
        self.assertFalse(report.live_deployment_qualified)
        self.assertEqual(report.authority_effect, "none")
        self.assertEqual(report.qualification_effect, "none")
        self.assertEqual(
            dict(verify_target_adapter_conformance_report(report.to_dict())),
            report.to_dict(),
        )
        encoded = canonical_json(report.to_dict())
        self.assertEqual(
            dict(verify_target_adapter_conformance_report(encoded)),
            report.to_dict(),
        )

    def test_report_rejects_missing_requirement_and_duplicate_json_key(self) -> None:
        observation = TargetAdapterConformanceObservation(
            requirement=REQUIRED_REQUIREMENTS[0],
            passed=True,
            evidence_sha256=DIGEST_A,
            outcome_code="passed",
        )
        with self.assertRaisesRegex(TargetAdapterConformanceError, "every requirement"):
            build_target_adapter_conformance_report(
                adapter_id="adapter:incomplete",
                adapter_release_sha256=DIGEST_A,
                observations=(observation,),
            )
        with self.assertRaisesRegex(TargetAdapterConformanceError, "duplicate key"):
            verify_target_adapter_conformance_report('{"kind":"x","kind":"y"}')

    def test_schema_accepts_report(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is unavailable")
        observations = tuple(
            TargetAdapterConformanceObservation(
                requirement=requirement,
                passed=True,
                evidence_sha256=DIGEST_A,
                outcome_code="passed",
            )
            for requirement in REQUIRED_REQUIREMENTS
        )
        report = build_target_adapter_conformance_report(
            adapter_id="adapter:schema",
            adapter_release_sha256=DIGEST_A,
            observations=observations,
        )
        schema = json.loads(
            (ROOT / "registry/schemas/target-adapter-conformance-report-v1.schema.json")
            .read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(report.to_dict())

    def test_http_backend_binds_tls_origin_address_and_single_attempt(self) -> None:
        peer = ReferenceTlsPeerEvidence(
            origin="https://app.example.test",
            sni_hostname="app.example.test",
            connected_address="192.0.2.10",
            certificate_sha256=CERTIFICATE,
            tls_verified=True,
        )
        transport = RecordingHttpTransport(
            ReferenceHttpTransportResponse(
                status_code=200,
                headers=(("content-type", "application/json"),),
                body=b"{}",
                body_complete=True,
                attempts=1,
                tls_peer=peer,
            )
        )
        backend = ReferenceHttpBackend(
            expected_origin="https://app.example.test",
            expected_certificate_sha256=CERTIFICATE,
            maximum_request_bytes=128,
            maximum_response_bytes=128,
            transport=transport,
            stop_state=AdapterStopState(),
        )
        request = HttpBackendRequest(
            method="GET",
            url="https://app.example.test/health",
            headers=(),
            body=b"",
            connect_addresses=("192.0.2.10",),
            follow_redirects=False,
            maximum_attempts=1,
            max_response_bytes=64,
        )
        response = backend.send(request)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.redirected)
        self.assertEqual(transport.calls, 1)
        self.assertFalse(transport.request.follow_redirects)

    def test_http_backend_never_follows_redirect_and_enforces_response_limit(self) -> None:
        peer = ReferenceTlsPeerEvidence(
            origin="https://app.example.test",
            sni_hostname="app.example.test",
            connected_address="192.0.2.10",
            certificate_sha256=CERTIFICATE,
            tls_verified=True,
        )
        for status, body, redirected, limited in (
            (302, b"", True, False),
            (200, b"x" * 65, False, True),
        ):
            with self.subTest(status=status, size=len(body)):
                transport = RecordingHttpTransport(
                    ReferenceHttpTransportResponse(
                        status_code=status,
                        headers=(("content-type", "text/plain"),),
                        body=body,
                        body_complete=True,
                        attempts=1,
                        tls_peer=peer,
                    )
                )
                backend = ReferenceHttpBackend(
                    expected_origin="https://app.example.test",
                    expected_certificate_sha256=CERTIFICATE,
                    maximum_request_bytes=64,
                    maximum_response_bytes=64,
                    transport=transport,
                    stop_state=AdapterStopState(),
                )
                result = backend.send(
                    HttpBackendRequest(
                        method="GET",
                        url="https://app.example.test/health",
                        headers=(),
                        body=b"",
                        connect_addresses=("192.0.2.10",),
                        max_response_bytes=64,
                    )
                )
                self.assertEqual(result.redirected, redirected)
                self.assertEqual(result.limit_exceeded, limited)
                self.assertEqual(transport.calls, 1)

    def test_http_stop_and_tls_substitution_fail_closed(self) -> None:
        wrong_peer = ReferenceTlsPeerEvidence(
            origin="https://other.example.test",
            sni_hostname="other.example.test",
            connected_address="192.0.2.10",
            certificate_sha256=CERTIFICATE,
            tls_verified=True,
        )
        transport = RecordingHttpTransport(
            ReferenceHttpTransportResponse(
                status_code=200,
                headers=(("content-type", "text/plain"),),
                body=b"ok",
                body_complete=True,
                attempts=1,
                tls_peer=wrong_peer,
            )
        )
        stop = AdapterStopState()
        backend = ReferenceHttpBackend(
            expected_origin="https://app.example.test",
            expected_certificate_sha256=CERTIFICATE,
            maximum_request_bytes=64,
            maximum_response_bytes=64,
            transport=transport,
            stop_state=stop,
        )
        request = HttpBackendRequest(
            method="GET",
            url="https://app.example.test/health",
            headers=(),
            body=b"",
            connect_addresses=("192.0.2.10",),
            max_response_bytes=64,
        )
        with self.assertRaisesRegex(HttpBackendFailure, "tls_origin_binding_mismatch"):
            backend.send(request)
        stop.cancel()
        with self.assertRaisesRegex(HttpBackendFailure, "canceled"):
            backend.send(request)
        self.assertEqual(transport.calls, 1)

    def test_dns_and_body_sources_are_exact_and_deterministic(self) -> None:
        resolver = ScriptedDnsResolver(
            "app.example.test",
            (("192.0.2.10",), ("192.0.2.11",)),
            "resolver:fixture",
        )
        self.assertNotEqual(
            resolver.resolve("app.example.test").addresses,
            resolver.resolve("app.example.test").addresses,
        )
        body = b'{"probe":"safe"}'
        provider = DigestBoundBodyProvider((body,))
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        self.assertEqual(provider.read(digest, len(body)), body)
        with self.assertRaisesRegex(ValueError, "binding is unavailable"):
            provider.read(digest, len(body) + 1)

    def test_opaque_session_provider_suspends_on_operator_challenge(self) -> None:
        challenge = "sha256:" + "d" * 64
        transport = ScriptedSessionTransport(
            OpaqueSessionTransportResult(
                status=SessionTransportStatus.OPERATOR_CHALLENGE,
                expires_at=None,
                challenge_reference_sha256=challenge,
            )
        )
        provider = ReferenceCredentialSessionProvider(
            transport=transport,
            stop_state=AdapterStopState(),
            cleanup_obligation_ref="obligationref:cleanup-phase207",
            revocation_obligation_ref="obligationref:revoke-phase207",
        )
        with self.assertRaisesRegex(
            CredentialSessionProviderFailure, "operator_challenge_required"
        ):
            provider.acquire(command())
        self.assertEqual(transport.calls, 1)
        self.assertEqual(transport.credential_reference, "credref:phase207-opaque")
        self.assertIsNotNone(provider.last_suspension)
        self.assertEqual(provider.last_suspension.authority_effect, "none")

    def test_session_success_is_isolated_and_stop_prevents_transport(self) -> None:
        transport = ScriptedSessionTransport(
            OpaqueSessionTransportResult(
                status=SessionTransportStatus.ACQUIRED,
                expires_at="2026-09-21T12:05:00Z",
            )
        )
        stop = AdapterStopState()
        provider = ReferenceCredentialSessionProvider(
            transport=transport,
            stop_state=stop,
            cleanup_obligation_ref="obligationref:cleanup-phase207",
            revocation_obligation_ref="obligationref:revoke-phase207",
        )
        result = provider.acquire(command())
        self.assertTrue(result.succeeded)
        self.assertTrue(result.isolated)
        self.assertFalse(result.credential_material_returned)
        stop.emergency_stop()
        with self.assertRaisesRegex(CredentialSessionProviderFailure, "emergency_stop"):
            provider.acquire(command())
        self.assertEqual(transport.calls, 1)

    def test_revocation_and_atomic_single_use_evidence(self) -> None:
        checker = InMemoryLeaseRevocationChecker()
        first = checker.observe("lease:phase207", DIGEST_A)
        self.assertFalse(first.revoked)
        checker.revoke("lease:phase207", DIGEST_A)
        second = checker.observe("lease:phase207", DIGEST_A)
        self.assertTrue(second.revoked)
        self.assertNotEqual(first.evidence_sha256, second.evidence_sha256)

        from sunderkey.authorized_target_session_runtime import LeaseUseReservationRequest
        from sunderkey.credential_broker_contracts import LeaseMode

        request = LeaseUseReservationRequest(
            lease_id="lease:phase207",
            lease_sha256=DIGEST_A,
            lease_binding_sha256=DIGEST_B,
            lease_use_number=1,
            lease_mode=LeaseMode.ONE_TIME,
            execution_request_id="request:phase207",
            execution_request_sha256=DIGEST_A,
            execution_binding_sha256=DIGEST_B,
            requested_session_id="session:phase207",
        )
        store = InMemoryAtomicLeaseUseStore()
        reservation = store.reserve(request)
        completion = store.complete(reservation, "completed", True)
        self.assertEqual(completion.reservation_id, reservation.reservation_id)
        with self.assertRaisesRegex(LeaseUseStoreFailure, "lease_use_replayed"):
            store.reserve(request)
        rebound = replace(
            request,
            execution_request_id="request:phase207-rebound",
            execution_request_sha256=CERTIFICATE,
            reservation_key_sha256="",
        )
        with self.assertRaisesRegex(LeaseUseStoreFailure, "lease_use_replayed"):
            store.reserve(rebound)

    def test_health_receipts_are_signed_chained_and_propose_pause(self) -> None:
        signer = DeterministicSigner()
        collector = TargetHealthCollector(
            collector_id="collector:phase207",
            signer=signer,
            stop_state=AdapterStopState(),
        )
        receipt = rejected_health_receipt()
        first, first_pause = collector.collect(receipt)
        second, second_pause = collector.collect(receipt)
        self.assertIsNotNone(first_pause)
        self.assertEqual(first_pause.reason, "health_evidence_rejected")
        self.assertEqual(second.previous_observation_sha256, first.observation_sha256)
        self.assertEqual(second.sequence, 2)
        self.assertIsNotNone(second_pause)
        self.assertEqual(
            dict(verify_signed_target_health_observation(first, signer)),
            first.to_dict(),
        )

    def test_health_signature_tampering_and_binding_substitution_fail_closed(self) -> None:
        signer = DeterministicSigner()
        collector = TargetHealthCollector(
            collector_id="collector:phase207",
            signer=signer,
            stop_state=AdapterStopState(),
        )
        signed, _ = collector.collect(rejected_health_receipt())

        class RejectingVerifier:
            def verify(self, payload: bytes, signature: HealthSignatureMaterial) -> bool:
                return False

        with self.assertRaisesRegex(TargetHealthCollectorError, "verification failed"):
            verify_signed_target_health_observation(signed, RejectingVerifier())
        foreign = rejected_health_receipt()
        object.__setattr__(foreign.binding, "target_id", "target:substituted")
        with self.assertRaises(ValueError):
            collector.collect(foreign)

    def test_sources_contain_no_network_client_or_live_claim(self) -> None:
        paths = (
            ROOT / "src/sunderkey/target_adapter_conformance.py",
            ROOT / "src/sunderkey/reference_http_adapter.py",
            ROOT / "src/sunderkey/reference_target_session_adapter.py",
            ROOT / "src/sunderkey/target_health_collector.py",
            ROOT / "docs/target-adapter-conformance.md",
        )
        combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        self.assertNotIn("import requests", combined)
        self.assertNotIn("from requests", combined)
        self.assertNotIn("urllib.request", combined)
        self.assertNotIn("socket.", combined)
        self.assertNotIn("live_deployment_qualified=True", combined)
        self.assertNotIn("\u2013", combined)
        self.assertNotIn("\u2014", combined)


if __name__ == "__main__":
    unittest.main()
