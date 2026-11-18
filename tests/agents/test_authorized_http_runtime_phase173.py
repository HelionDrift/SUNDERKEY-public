from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
from sunderkey.assessment_transport_contracts import (
    AdapterIdentity,
    AssessmentBinding,
    HeaderField,
    HttpRequestIntent,
    MimeLimit,
    SessionBinding,
    TransportBudget,
    canonical_json,
)
from sunderkey.authorized_http_runtime import (
    AuthorizedHttpPolicy,
    AuthorizedHttpRuntimeError,
    DnsResolution,
    ExchangeStatus,
    HttpBackendFailure,
    HttpBackendResponse,
    RuntimeSafetySnapshot,
    execute_authorized_http_exchange,
    verify_exchange_receipt,
)
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
SCHEMA = ROOT / "registry" / "schemas" / "authorized-http-exchange-receipt-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "authorized_http_runtime.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "authorized-http-runtime.md",
)
NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
TECHNIQUE = "TECH-HTTP-001"


def scope_spec(*, literal: bool = False) -> dict:
    host = "203.0.113.10" if literal else "app.example.test"
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
            "https_origins": [f"https://{host}"],
            "exact_hosts": [host],
            "wildcard_subdomains": [],
            "cidrs": ["203.0.113.0/24"],
            "ports": [443],
            "http_methods": ["GET", "POST"],
            "path_prefixes": ["/assess"],
        },
        "exclusions": [],
        "protected_endpoints": [],
        "budgets": {
            "max_requests": 20,
            "max_concurrency": 2,
            "max_requests_per_minute": 20,
        },
        "impact_tier_ceiling": "R2",
        "allowed_technique_ids": [TECHNIQUE],
        "data_handling": {
            "classification": "confidential",
            "collection": "minimized_content",
            "storage": "ephemeral_encrypted",
            "retention_days": 1,
            "redaction_required": True,
        },
        "emergency_stop_contact_id": "soc.primary",
    }


def verified_scope(*, literal: bool = False):
    key = Ed25519PrivateKey.generate()
    signed = compile_signed_scope(scope_spec(literal=literal), key, now=NOW)
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


class FakeSafety:
    def __init__(
        self,
        binding_sha256: str,
        request_sha256: str,
        *,
        health: HealthState = HealthState.HEALTHY,
        canceled: bool = False,
        emergency_stop: bool = False,
    ) -> None:
        self.snapshot = RuntimeSafetySnapshot(
            binding_sha256,
            request_sha256,
            health,
            canceled,
            emergency_stop,
        )
        self.calls = 0

    def observe(self) -> RuntimeSafetySnapshot:
        self.calls += 1
        return self.snapshot


class FakeResolver:
    def __init__(self, *answers: tuple[str, ...]) -> None:
        self.answers = list(answers or (("203.0.113.10",), ("203.0.113.10",)))
        self.calls = 0

    def resolve(self, host: str) -> DnsResolution:
        answer = self.answers.pop(0)
        self.calls += 1
        return DnsResolution(host, answer, "resolver.test")


class FakeBodyProvider:
    def __init__(self, body: bytes = b"") -> None:
        self.body = body
        self.calls = 0

    def read(self, body_sha256: str, size_bytes: int) -> bytes:
        self.calls += 1
        return self.body


class FakeBackend:
    def __init__(
        self, response: HttpBackendResponse | None = None, failure: Exception | None = None
    ):
        self.response = response or HttpBackendResponse(
            200,
            (("content-length", "2"), ("content-type", "application/json")),
            b"{}",
            True,
            False,
            False,
            1,
        )
        self.failure = failure
        self.calls = 0
        self.requests = []

    def send(self, request):
        self.calls += 1
        self.requests.append(request)
        if self.failure is not None:
            raise self.failure
        return self.response


class AuthorizedHttpRuntimePhase173Tests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.AuthorizedHttpPolicy, AuthorizedHttpPolicy)
        self.assertIs(sunderkey.AuthorizedHttpRuntimeError, AuthorizedHttpRuntimeError)
        self.assertIs(
            sunderkey.execute_authorized_http_exchange,
            execute_authorized_http_exchange,
        )
        self.assertIs(
            sunderkey.verify_authorized_http_exchange_receipt,
            verify_exchange_receipt,
        )

    def setUp(self) -> None:
        self.scope = verified_scope()
        self.transport_budget = TransportBudget(
            max_steps=8,
            max_request_bytes=1024,
            max_response_bytes=4096,
            max_total_request_bytes=4096,
            max_total_response_bytes=8192,
            max_redirects=0,
            mime_limits=(
                MimeLimit("application/json", 4096),
                MimeLimit("application/x-www-form-urlencoded", 4096),
                MimeLimit("text/plain", 1024),
            ),
        )
        self.assessment_binding = AssessmentBinding(
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            task_id="context:assessment-1",
            technique_id=TECHNIQUE,
            authority_refs=("authority:scope-owner",),
            evidence_hashes=(DIGEST_A,),
            impact_tier="R1",
            decision_at="2026-09-20T12:00:00Z",
            stop_conditions=("Stop on health change.",),
            adapter=AdapterIdentity("adapter.injected-http", "1.0.0"),
            budget=self.transport_budget,
        )
        self.session = SessionBinding("session:assessment-1", "principal:anonymous")
        self.intent = self.make_intent()
        self.execution_binding = ExecutionBinding(
            tenant_id="tenant:acme",
            context_id=self.assessment_binding.task_id,
            context_sha256=DIGEST_A,
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            target_id="target:app-example",
            target_sha256=DIGEST_B,
            session_id=self.session.session_id,
            lease_id="lease:assessment-1",
            fence_epoch=7,
        )
        self.execution_request = self.make_execution_request()
        self.admission = AdmissionReceipt(
            request_id=self.execution_request.request_id,
            request_sha256=self.execution_request.request_sha256,
            policy_id=self.execution_request.policy_id,
            policy_sha256=self.execution_request.policy_sha256,
            status=AdmissionStatus.ADMITTED,
            reason=None,
            observed_at="2026-09-20T12:00:00Z",
            monotonic_tick=100,
            state_before_sha256=DIGEST_A,
            state_after_sha256=DIGEST_B,
        )
        self.policy = AuthorizedHttpPolicy(
            binding=self.execution_binding,
            execution_policy_id=self.execution_request.policy_id,
            execution_policy_sha256=self.execution_request.policy_sha256,
            request_header_allowlist=("accept", "content-type", "user-agent"),
            response_header_allowlist=("content-length", "content-type", "location"),
            mime_limits=(
                MimeLimit("application/json", 4096),
                MimeLimit("application/x-www-form-urlencoded", 4096),
                MimeLimit("text/plain", 1024),
            ),
            max_request_bytes=1024,
            max_response_bytes=4096,
        )

    def make_intent(
        self,
        *,
        url: str = "https://app.example.test/assess/items",
        headers: tuple[HeaderField, ...] = (HeaderField("accept", "application/json"),),
        body: bytes = b"",
        session: SessionBinding | None = None,
    ) -> HttpRequestIntent:
        import hashlib

        return HttpRequestIntent(
            binding=self.assessment_binding,
            sequence=1,
            method="POST" if body else "GET",
            url=url,
            headers=headers,
            request_size_bytes=len(body),
            body_sha256=None if not body else "sha256:" + hashlib.sha256(body).hexdigest(),
            session=self.session if session is None and hasattr(self, "session") else session,
        )

    def make_execution_request(
        self,
        *,
        intent: HttpRequestIntent | None = None,
        binding: ExecutionBinding | None = None,
    ) -> ExecutionRequest:
        selected = intent or self.intent
        return ExecutionRequest(
            binding=binding or self.execution_binding,
            policy_id="ECP-0123456789ABCDEF0123456789ABCDEF",
            policy_sha256=DIGEST_A,
            idempotency_key="http:assessment-1:step-1",
            operation_code="authorized_http",
            payload_sha256=selected.intent_sha256,
            payload_size_bytes=len(canonical_json(selected.to_dict()).encode("ascii")),
            attempt_number=1,
            prior_execution_sha256=None,
            cleanup_obligation_sha256=DIGEST_B,
        )

    def invoke(self, **overrides):
        execution_request = overrides.pop("execution_request", self.execution_request)
        safety = overrides.pop(
            "safety_monitor",
            FakeSafety(
                "sha256:"
                + __import__("hashlib")
                .sha256(canonical_json(execution_request.binding.to_dict()).encode("ascii"))
                .hexdigest(),
                execution_request.request_sha256,
            ),
        )
        values = {
            "scope": self.scope,
            "intent": self.intent,
            "execution_request": execution_request,
            "admission": self.admission,
            "policy": self.policy,
            "clock": FakeClock(),
            "safety_monitor": safety,
            "resolver": FakeResolver(),
            "body_provider": FakeBodyProvider(),
            "backend": FakeBackend(),
        }
        values.update(overrides)
        return execute_authorized_http_exchange(**values)

    def test_completed_exchange_is_single_send_and_content_addressed(self) -> None:
        backend = FakeBackend()
        resolver = FakeResolver()
        receipt = self.invoke(backend=backend, resolver=resolver)
        self.assertEqual(receipt.status, ExchangeStatus.COMPLETED)
        self.assertEqual(backend.calls, 1)
        self.assertEqual(resolver.calls, 2)
        request = backend.requests[0]
        self.assertFalse(request.follow_redirects)
        self.assertEqual(request.maximum_attempts, 1)
        self.assertEqual(request.connect_addresses, ("203.0.113.10",))
        verified = verify_exchange_receipt(canonical_json(receipt.to_dict()))
        self.assertEqual(verified["receipt_id"], receipt.receipt_id)
        self.assertEqual(receipt.authority_effect, "none")
        self.assertEqual(receipt.qualification_effect, "none")

    def test_scope_and_window_expiry_at_final_send_observation_prevent_send(self) -> None:
        for expires, ends in ((3, 3), (10, 4)):
            with self.subTest(expires=expires, ends=ends):
                spec = scope_spec()
                spec["expires_at"] = f"2026-09-20T12:00:{expires:02d}Z"
                spec["assessment_window"]["ends_at"] = f"2026-09-20T12:00:{ends:02d}Z"
                with mock.patch(f"{__name__}.scope_spec", return_value=spec):
                    self.setUp()
                backend = FakeBackend()
                resolver = FakeResolver()
                receipt = self.invoke(backend=backend, resolver=resolver)
                self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
                self.assertEqual(receipt.reason, "scope_rejected")
                self.assertEqual(resolver.calls, 2)
                self.assertEqual(backend.calls, 0)
                self.assertFalse(receipt.transport_called)
                self.assertFalse(receipt.network_call_performed)
                self.assertNotIn("send_authorized", [item.stage for item in receipt.transcript])
                verify_exchange_receipt(canonical_json(receipt.to_dict()))

    def test_valid_final_scope_recheck_preserves_existing_trace_observations(self) -> None:
        clock = FakeClock()
        receipt = self.invoke(clock=clock)
        self.assertEqual(
            [(item.stage, item.observed_at, item.monotonic_tick) for item in receipt.transcript],
            [
                (stage, f"2026-09-20T12:00:{index:02d}Z", 100 + index)
                for index, stage in enumerate(
                    (
                        "validated",
                        "dns_preflight",
                        "dns_recheck",
                        "send_authorized",
                        "response_validated",
                    ),
                    start=1,
                )
            ],
        )
        self.assertEqual(clock.ticks[0], 106)
        verify_exchange_receipt(canonical_json(receipt.to_dict()))

    def test_blocked_admission_and_exact_binding_mismatches_never_send(self) -> None:
        blocked = replace(
            self.admission,
            status=AdmissionStatus.BLOCKED,
            reason="canceled",
            receipt_id="",
            receipt_sha256="",
        )
        other_binding = replace(self.execution_binding, tenant_id="tenant:other")
        other_request = self.make_execution_request(binding=other_binding)
        cases = (
            {"admission": blocked},
            {"execution_request": other_request},
            {
                "intent": replace(
                    self.intent, session=SessionBinding("session:other", "principal:anonymous")
                )
            },
        )
        for changes in cases:
            with self.subTest(changes=tuple(changes)):
                backend = FakeBackend()
                receipt = self.invoke(backend=backend, **changes)
                self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
                self.assertEqual(backend.calls, 0)

    def test_canonical_intent_size_mismatch_stops_before_body_dns_and_send(self) -> None:
        request = replace(
            self.execution_request,
            payload_size_bytes=self.execution_request.payload_size_bytes + 1,
            request_id="",
            request_sha256="",
        )
        admission = replace(
            self.admission,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        provider = FakeBodyProvider()
        resolver = FakeResolver()
        backend = FakeBackend()
        receipt = self.invoke(
            execution_request=request,
            admission=admission,
            body_provider=provider,
            resolver=resolver,
            backend=backend,
        )
        self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
        self.assertEqual(receipt.reason, "payload_rejected")
        self.assertEqual(provider.calls, 0)
        self.assertEqual(resolver.calls, 0)
        self.assertEqual(backend.calls, 0)

    def test_scope_path_and_protected_decisions_fail_before_send(self) -> None:
        intent = self.make_intent(url="https://app.example.test/outside")
        request = self.make_execution_request(intent=intent)
        admission = replace(
            self.admission,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        backend = FakeBackend()
        receipt = self.invoke(
            intent=intent,
            execution_request=request,
            admission=admission,
            backend=backend,
        )
        self.assertEqual(receipt.reason, "scope_rejected")
        self.assertEqual(backend.calls, 0)

    def test_dns_rebinding_and_out_of_cidr_answers_fail_before_send(self) -> None:
        for resolver in (
            FakeResolver(("203.0.113.10",), ("203.0.113.11",)),
            FakeResolver(("198.51.100.8",)),
        ):
            backend = FakeBackend()
            receipt = self.invoke(resolver=resolver, backend=backend)
            self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
            self.assertEqual(receipt.reason, "dns_rejected")
            self.assertEqual(backend.calls, 0)

    def test_literal_ip_bypasses_resolver_but_remains_scope_contained(self) -> None:
        literal_scope = verified_scope(literal=True)
        binding = replace(
            self.assessment_binding,
            scope_id=literal_scope.scope_id,
            scope_sha256=literal_scope.content_sha256,
        )
        intent = HttpRequestIntent(
            binding=binding,
            sequence=1,
            method="GET",
            url="https://203.0.113.10/assess/items",
            headers=(HeaderField("accept", "application/json"),),
            session=self.session,
        )
        execution_binding = replace(
            self.execution_binding,
            scope_id=literal_scope.scope_id,
            scope_sha256=literal_scope.content_sha256,
        )
        request = self.make_execution_request(intent=intent, binding=execution_binding)
        admission = replace(
            self.admission,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        policy = replace(self.policy, binding=execution_binding, policy_id="", policy_sha256="")
        resolver = FakeResolver()
        safety = FakeSafety(
            "sha256:"
            + __import__("hashlib")
            .sha256(canonical_json(execution_binding.to_dict()).encode("ascii"))
            .hexdigest(),
            request.request_sha256,
        )
        receipt = self.invoke(
            scope=literal_scope,
            intent=intent,
            execution_request=request,
            admission=admission,
            policy=policy,
            resolver=resolver,
            safety_monitor=safety,
        )
        self.assertEqual(receipt.status, ExchangeStatus.COMPLETED)
        self.assertEqual(resolver.calls, 0)

    def test_headers_body_hash_size_mime_and_secret_checks_are_fail_closed(self) -> None:
        secret = b"api_key=ABCDEFGHIJKLMNOP"
        good = b'{"probe":true}'
        cases = []
        cases.append(
            (
                self.make_intent(headers=(HeaderField("x-unlisted", "value"),)),
                FakeBodyProvider(),
            )
        )
        body_intent = self.make_intent(
            headers=(HeaderField("content-type", "application/json"),), body=good
        )
        cases.append((body_intent, FakeBodyProvider(b"different")))
        secret_intent = self.make_intent(
            headers=(HeaderField("content-type", "application/json"),), body=secret
        )
        cases.append((secret_intent, FakeBodyProvider(secret)))
        for intent, provider in cases:
            request = self.make_execution_request(intent=intent)
            admission = replace(
                self.admission,
                request_id=request.request_id,
                request_sha256=request.request_sha256,
                receipt_id="",
                receipt_sha256="",
            )
            backend = FakeBackend()
            receipt = self.invoke(
                intent=intent,
                execution_request=request,
                admission=admission,
                body_provider=provider,
                backend=backend,
            )
            self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
            self.assertEqual(backend.calls, 0)

    def test_mime_aware_nested_secrets_are_rejected_without_plain_digest_receipts(self) -> None:
        bodies = (
            (
                b'{"profile":{"clientSecret":"ABCDEFGHIJKLMNOP"}}',
                "application/json",
            ),
            (b'{"client_secret":"ABCDEFGHIJKLMNOP"', "application/json"),
            (b"account[refresh_token]=ABCDEFGHIJKLMNOP", "application/x-www-form-urlencoded"),
        )
        for body, mime_type in bodies:
            with self.subTest(mime_type=mime_type):
                intent = self.make_intent(
                    headers=(HeaderField("content-type", mime_type),),
                    body=body,
                )
                request = self.make_execution_request(intent=intent)
                admission = replace(
                    self.admission,
                    request_id=request.request_id,
                    request_sha256=request.request_sha256,
                    receipt_id="",
                    receipt_sha256="",
                )
                backend = FakeBackend()
                receipt = self.invoke(
                    intent=intent,
                    execution_request=request,
                    admission=admission,
                    body_provider=FakeBodyProvider(body),
                    backend=backend,
                )
                self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
                self.assertIsNone(receipt.request_body_sha256)
                self.assertNotIn(
                    "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
                    canonical_json(receipt.to_dict()),
                )
                self.assertEqual(backend.calls, 0)

    def test_malformed_structured_requests_fail_closed_before_send(self) -> None:
        bodies = (
            (b'{"\\u0061ccess_token":"ABCDEFGHIJKLMNOP"', "application/json"),
            (
                b"%61ccess_token=ABCDEFGHIJKLMNOP&broken",
                "application/x-www-form-urlencoded",
            ),
        )
        for body, mime_type in bodies:
            with self.subTest(mime_type=mime_type):
                intent = self.make_intent(
                    headers=(HeaderField("content-type", mime_type),),
                    body=body,
                )
                request = self.make_execution_request(intent=intent)
                admission = replace(
                    self.admission,
                    request_id=request.request_id,
                    request_sha256=request.request_sha256,
                    receipt_id="",
                    receipt_sha256="",
                )
                backend = FakeBackend()
                receipt = self.invoke(
                    intent=intent,
                    execution_request=request,
                    admission=admission,
                    body_provider=FakeBodyProvider(body),
                    backend=backend,
                )
                self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
                self.assertEqual(receipt.reason, "payload_rejected")
                self.assertIsNone(receipt.request_body_sha256)
                self.assertNotIn(
                    "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
                    canonical_json(receipt.to_dict()),
                )
                self.assertEqual(backend.calls, 0)

    def test_valid_benign_structured_request_and_response_remain_allowed(self) -> None:
        body = b'{"profile":{"name":"example"}}'
        intent = self.make_intent(
            headers=(HeaderField("content-type", "application/json"),),
            body=body,
        )
        request = self.make_execution_request(intent=intent)
        admission = replace(
            self.admission,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        backend = FakeBackend()
        receipt = self.invoke(
            intent=intent,
            execution_request=request,
            admission=admission,
            body_provider=FakeBodyProvider(body),
            backend=backend,
        )
        self.assertEqual(receipt.status, ExchangeStatus.COMPLETED)
        self.assertIsNotNone(receipt.request_body_sha256)
        self.assertIsNotNone(receipt.response_body_sha256)
        self.assertEqual(backend.calls, 1)

    def test_deep_json_request_screening_failure_is_digestless_and_never_sent(self) -> None:
        body = b"[" * 1100 + b'{"\\u0074oken":"ABCDEFGHIJKLMNOP"}' + b"]" * 1100
        budget = replace(
            self.transport_budget,
            max_request_bytes=4096,
            max_total_request_bytes=4096,
        )
        binding = replace(self.assessment_binding, budget=budget)
        intent = HttpRequestIntent(
            binding=binding,
            sequence=1,
            method="POST",
            url="https://app.example.test/assess/items",
            headers=(HeaderField("content-type", "application/json"),),
            request_size_bytes=len(body),
            body_sha256="sha256:" + __import__("hashlib").sha256(body).hexdigest(),
            session=self.session,
        )
        request = self.make_execution_request(intent=intent)
        admission = replace(
            self.admission,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        policy = replace(
            self.policy,
            max_request_bytes=4096,
            policy_id="",
            policy_sha256="",
        )
        backend = FakeBackend()
        receipt = self.invoke(
            intent=intent,
            execution_request=request,
            admission=admission,
            policy=policy,
            body_provider=FakeBodyProvider(body),
            backend=backend,
        )
        self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
        self.assertEqual(receipt.reason, "payload_rejected")
        self.assertIsNone(receipt.request_body_sha256)
        self.assertNotIn(
            "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
            canonical_json(receipt.to_dict()),
        )
        self.assertEqual(backend.calls, 0)

    def test_secret_response_is_rejected_without_plain_body_digest(self) -> None:
        body = b'{"outer":{"access_token":"ABCDEFGHIJKLMNOP"}}'
        backend = FakeBackend(
            response=HttpBackendResponse(
                200,
                (("content-type", "application/json"),),
                body,
                True,
                False,
                False,
                1,
            )
        )
        receipt = self.invoke(backend=backend)
        self.assertEqual(receipt.status, ExchangeStatus.RESPONSE_REJECTED)
        self.assertEqual(receipt.reason, "payload_rejected")
        self.assertIsNone(receipt.response_body_sha256)
        self.assertNotIn(
            "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
            canonical_json(receipt.to_dict()),
        )
        self.assertEqual(backend.calls, 1)

    def test_oversized_secret_response_is_rejected_without_plain_body_digest(self) -> None:
        body = b'{"\\u0074oken":"' + b"A" * 5000 + b'"}'
        backend = FakeBackend(
            response=HttpBackendResponse(
                200,
                (("content-type", "application/json"),),
                body,
                True,
                False,
                False,
                1,
            )
        )
        receipt = self.invoke(backend=backend)
        self.assertEqual(receipt.status, ExchangeStatus.RESPONSE_REJECTED)
        self.assertEqual(receipt.reason, "payload_rejected")
        self.assertIsNone(receipt.response_body_sha256)
        self.assertNotIn(
            "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
            canonical_json(receipt.to_dict()),
        )
        self.assertEqual(backend.calls, 1)

    def test_response_secret_screening_failure_is_digestless_and_not_retried(self) -> None:
        body = b"[" * 1100 + b'{"\\u0074oken":"ABCDEFGHIJKLMNOP"}' + b"]" * 1100
        backend = FakeBackend(
            response=HttpBackendResponse(
                200,
                (("content-type", "application/json"),),
                body,
                True,
                False,
                False,
                1,
            )
        )
        receipt = self.invoke(backend=backend)
        self.assertEqual(receipt.status, ExchangeStatus.RESPONSE_REJECTED)
        self.assertEqual(receipt.reason, "payload_rejected")
        self.assertIsNone(receipt.response_body_sha256)
        self.assertNotIn(
            "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
            canonical_json(receipt.to_dict()),
        )
        self.assertEqual(backend.calls, 1)

    def test_malformed_structured_responses_fail_closed_without_digest_or_retry(self) -> None:
        bodies = (
            (b'{"\\u0061ccess_token":"ABCDEFGHIJKLMNOP"', "application/json"),
            (
                b"%61ccess_token=ABCDEFGHIJKLMNOP&broken",
                "application/x-www-form-urlencoded",
            ),
        )
        for body, mime_type in bodies:
            with self.subTest(mime_type=mime_type):
                backend = FakeBackend(
                    response=HttpBackendResponse(
                        200,
                        (("content-type", mime_type),),
                        body,
                        True,
                        False,
                        False,
                        1,
                    )
                )
                receipt = self.invoke(backend=backend)
                self.assertEqual(receipt.status, ExchangeStatus.RESPONSE_REJECTED)
                self.assertEqual(receipt.reason, "payload_rejected")
                self.assertIsNone(receipt.response_body_sha256)
                self.assertNotIn(
                    "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
                    canonical_json(receipt.to_dict()),
                )
                self.assertEqual(backend.calls, 1)

    def test_health_cancellation_and_emergency_stop_are_checked_repeatedly(self) -> None:
        binding_sha = (
            "sha256:"
            + __import__("hashlib")
            .sha256(canonical_json(self.execution_binding.to_dict()).encode("ascii"))
            .hexdigest()
        )
        for changes in (
            {"health": HealthState.PAUSED},
            {"canceled": True},
            {"emergency_stop": True},
        ):
            monitor = FakeSafety(
                binding_sha,
                self.execution_request.request_sha256,
                **changes,
            )
            backend = FakeBackend()
            receipt = self.invoke(safety_monitor=monitor, backend=backend)
            self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
            self.assertEqual(backend.calls, 0)
            self.assertEqual(monitor.calls, 1)

    def test_backend_failure_and_exception_publish_failure_receipts_without_retry(self) -> None:
        for failure, reason in (
            (HttpBackendFailure("connection_failed"), "connection_failed"),
            (RuntimeError("sensitive backend message"), "backend_exception"),
        ):
            backend = FakeBackend(failure=failure)
            receipt = self.invoke(backend=backend)
            self.assertEqual(receipt.status, ExchangeStatus.BACKEND_FAILED)
            self.assertEqual(receipt.reason, reason)
            self.assertEqual(backend.calls, 1)
            self.assertNotIn("sensitive", canonical_json(receipt.to_dict()))

    def test_redirect_retry_truncation_and_limit_evidence_are_rejected(self) -> None:
        responses = (
            HttpBackendResponse(302, (("content-type", "text/plain"),), b"", True, False, True, 1),
            HttpBackendResponse(
                200, (("content-type", "text/plain"),), b"ok", True, False, False, 2
            ),
            HttpBackendResponse(
                200, (("content-type", "text/plain"),), b"ok", False, False, False, 1
            ),
            HttpBackendResponse(
                200, (("content-type", "text/plain"),), b"ok", True, True, False, 1
            ),
        )
        for response in responses:
            backend = FakeBackend(response=response)
            receipt = self.invoke(backend=backend)
            self.assertEqual(receipt.status, ExchangeStatus.RESPONSE_REJECTED)
            self.assertEqual(backend.calls, 1)

    def test_response_mime_headers_lengths_secrets_and_byte_ceiling_are_rejected(self) -> None:
        responses = (
            HttpBackendResponse(200, (("x-unknown", "value"),), b"ok", True, False, False, 1),
            HttpBackendResponse(
                200, (("content-type", "image/png"),), b"ok", True, False, False, 1
            ),
            HttpBackendResponse(
                200,
                (("content-length", "99"), ("content-type", "text/plain")),
                b"ok",
                True,
                False,
                False,
                1,
            ),
            HttpBackendResponse(
                200,
                (("content-type", "text/plain"),),
                b"password=ABCDEFGHIJKLMNOP",
                True,
                False,
                False,
                1,
            ),
            HttpBackendResponse(
                200,
                (("content-type", "text/plain"),),
                b"x" * 5000,
                True,
                False,
                False,
                1,
            ),
        )
        for response in responses:
            receipt = self.invoke(backend=FakeBackend(response=response))
            self.assertEqual(receipt.status, ExchangeStatus.RESPONSE_REJECTED)

    def test_clock_rollback_fails_closed_before_send(self) -> None:
        backend = FakeBackend()
        receipt = self.invoke(clock=FakeClock((101, 101, 102)), backend=backend)
        self.assertEqual(receipt.status, ExchangeStatus.REJECTED_BEFORE_SEND)
        self.assertEqual(backend.calls, 0)

    def test_strict_receipt_parser_rejects_unknown_duplicate_noncanonical_and_tampered(
        self,
    ) -> None:
        receipt = self.invoke().to_dict()
        canonical = canonical_json(receipt)
        verify_exchange_receipt(canonical)
        with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "canonical"):
            verify_exchange_receipt(json.dumps(receipt, indent=2, sort_keys=True))
        with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "fields"):
            verify_exchange_receipt({**receipt, "authorization": "granted"})
        duplicate = canonical[:-1] + ',"status":"completed"}'
        with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "duplicate"):
            verify_exchange_receipt(duplicate)
        tampered = copy.deepcopy(receipt)
        tampered["reason"] = "validation_rejected"
        with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "content address"):
            verify_exchange_receipt(tampered)

    def test_completed_receipt_requires_exact_response_evidence_in_constructor_and_verifier(
        self,
    ) -> None:
        receipt = self.invoke()
        with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "requires status"):
            replace(
                receipt,
                reason="validation_rejected",
                receipt_id="",
                receipt_sha256="",
            )
        wrong_reason = receipt.to_dict()
        wrong_reason["reason"] = "validation_rejected"
        wrong_reason_body = {
            key: value
            for key, value in wrong_reason.items()
            if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
        }
        wrong_reason_digest = (
            "sha256:"
            + __import__("hashlib")
            .sha256(
                canonical_json({"body": wrong_reason_body, "kind": wrong_reason["kind"]}).encode(
                    "ascii"
                )
            )
            .hexdigest()
        )
        wrong_reason["receipt_sha256"] = wrong_reason_digest
        wrong_reason["receipt_id"] = "AHR-" + wrong_reason_digest[7:39].upper()
        with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "semantic"):
            verify_exchange_receipt(wrong_reason)
        for field in ("response_status_code", "response_mime_type", "response_body_sha256"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "requires status"):
                    replace(receipt, **{field: None}, receipt_id="", receipt_sha256="")
                document = receipt.to_dict()
                document[field] = None
                body = {
                    key: value
                    for key, value in document.items()
                    if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
                }
                digest = (
                    "sha256:"
                    + __import__("hashlib")
                    .sha256(
                        canonical_json({"body": body, "kind": document["kind"]}).encode("ascii")
                    )
                    .hexdigest()
                )
                document["receipt_sha256"] = digest
                document["receipt_id"] = "AHR-" + digest[7:39].upper()
                with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "semantic"):
                    verify_exchange_receipt(document)

    def test_non_completed_receipt_rejects_response_body_digest_everywhere(self) -> None:
        rejected = self.invoke(
            backend=FakeBackend(
                response=HttpBackendResponse(
                    200,
                    (("content-type", "application/json"),),
                    b'{"access_token":"ABCDEFGHIJKLMNOP"}',
                    True,
                    False,
                    False,
                    1,
                )
            )
        )
        self.assertEqual(rejected.status, ExchangeStatus.RESPONSE_REJECTED)
        with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "non-completed"):
            replace(
                rejected,
                response_body_sha256=DIGEST_A,
                receipt_id="",
                receipt_sha256="",
            )

        forged = rejected.to_dict()
        forged["response_body_sha256"] = DIGEST_A
        forged_body = {
            key: value
            for key, value in forged.items()
            if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
        }
        forged_digest = (
            "sha256:"
            + __import__("hashlib")
            .sha256(canonical_json({"body": forged_body, "kind": forged["kind"]}).encode("ascii"))
            .hexdigest()
        )
        forged["receipt_sha256"] = forged_digest
        forged["receipt_id"] = "AHR-" + forged_digest[7:39].upper()
        with self.assertRaisesRegex(AuthorizedHttpRuntimeError, "semantic"):
            verify_exchange_receipt(forged)

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
        altered = copy.deepcopy(receipt)
        altered["qualification_effect"] = "granted"
        self.assertTrue(list(validator.iter_errors(altered)))
        for field in ("response_status_code", "response_mime_type", "response_body_sha256"):
            altered = copy.deepcopy(receipt)
            altered[field] = None
            self.assertTrue(list(validator.iter_errors(altered)))
        rejected = self.invoke(
            backend=FakeBackend(
                response=HttpBackendResponse(
                    200,
                    (("content-type", "application/json"),),
                    b'{"access_token":"ABCDEFGHIJKLMNOP"}',
                    True,
                    False,
                    False,
                    1,
                )
            )
        ).to_dict()
        rejected["response_body_sha256"] = DIGEST_A
        self.assertTrue(list(validator.iter_errors(rejected)))

    def test_only_assigned_files_avoid_unicode_dashes(self) -> None:
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)


if __name__ == "__main__":
    unittest.main()
