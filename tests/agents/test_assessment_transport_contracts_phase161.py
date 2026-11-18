"""Phase 161 assessment transport contract and deterministic mock coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.assessment_transport_contracts import (
    NO_EFFECTS,
    AdapterHealthState,
    AdapterIdentity,
    AssessmentBinding,
    AuthenticationMode,
    BrowserAction,
    BrowserActionIntent,
    BrowserResultSpec,
    CookieMetadata,
    DeterministicBrowserTransport,
    DeterministicHttpTransport,
    DeterministicTargetSessionTransport,
    ExecutionControl,
    HeaderField,
    HealthObservation,
    HttpMethod,
    HttpRequestIntent,
    HttpResponseSpec,
    MimeLimit,
    PrincipalCredentialReference,
    ScriptedBrowserAction,
    ScriptedHttpExchange,
    ScriptedSessionAcquisition,
    SessionBinding,
    SessionResultSpec,
    TargetSessionIntent,
    TransportBudget,
    TransportContractError,
    TransportStepState,
    TransportTranscript,
)
from sunderkey.signed_scope_compiler import compile_signed_scope, verify_signed_scope

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "assessment-transport-transcript-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "assessment_transport_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "assessment-transport-contracts.md",
)
NOW = datetime(2026, 9, 20, 3, 30, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
TECHNIQUE = "TECH-HTTP-001"


def specification() -> dict:
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


class AssessmentTransportContractsPhase161Tests(unittest.TestCase):
    def setUp(self) -> None:
        key = Ed25519PrivateKey.generate()
        signed = compile_signed_scope(specification(), key, now=NOW)
        self.scope = verify_signed_scope(
            signed,
            key.public_key(),
            expected_issuer="assessment-authority.example",
            expected_key_id="scope-signing-key.2026-09",
            now=NOW,
        )
        self.identity = AdapterIdentity("adapter.scripted", "1.0.0")
        self.budget = TransportBudget(
            max_steps=8,
            max_request_bytes=1024,
            max_response_bytes=4096,
            max_total_request_bytes=4096,
            max_total_response_bytes=8192,
            max_redirects=1,
            mime_limits=(
                MimeLimit("application/json", 4096),
                MimeLimit("text/html", 2048),
                MimeLimit("image/png", 1024),
            ),
        )
        self.binding = AssessmentBinding(
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            task_id="CST-0123456789ABCDEF0123456789ABCDEF",
            technique_id=TECHNIQUE,
            authority_refs=("authority:scope-owner",),
            evidence_hashes=(DIGEST_A,),
            impact_tier="R1",
            decision_at="2026-09-20T03:30:00Z",
            stop_conditions=("Stop on health change.", "Stop on scope rejection."),
            adapter=self.identity,
            budget=self.budget,
        )

    def health(self, *states: AdapterHealthState) -> tuple[HealthObservation, ...]:
        return tuple(
            HealthObservation(
                adapter=self.identity,
                sequence=index,
                state=state,
                evidence_sha256=DIGEST_B,
                detail=state.value,
            )
            for index, state in enumerate(states)
        )

    def http_intent(
        self,
        *,
        sequence: int = 1,
        url: str = "https://app.example.test/assess/items",
        method: str = "GET",
        binding: AssessmentBinding | None = None,
        headers: tuple[HeaderField, ...] = (),
        request_size: int = 0,
        body_sha256: str | None = None,
        session: SessionBinding | None = None,
    ) -> HttpRequestIntent:
        return HttpRequestIntent(
            binding=binding or self.binding,
            sequence=sequence,
            method=method,
            url=url,
            headers=headers,
            request_size_bytes=request_size,
            body_sha256=body_sha256,
            session=session,
        )

    def response(self, **changes) -> HttpResponseSpec:
        values = {
            "status_code": 200,
            "mime_type": "application/json",
            "response_size_bytes": 16,
            "body_sha256": DIGEST_C,
            "headers": (("content-type", "application/json"),),
            "cookies": (),
        }
        values.update(changes)
        return HttpResponseSpec(**values)

    def http_adapter(
        self,
        intent: HttpRequestIntent,
        *,
        response: HttpResponseSpec | None = None,
        binding: AssessmentBinding | None = None,
        health: tuple[HealthObservation, ...] | None = None,
        expected_hash: str | None = None,
    ) -> DeterministicHttpTransport:
        return DeterministicHttpTransport(
            binding or self.binding,
            (
                ScriptedHttpExchange(
                    expected_hash or intent.intent_sha256,
                    response or self.response(),
                ),
            ),
            health_script=health
            or self.health(AdapterHealthState.HEALTHY, AdapterHealthState.HEALTHY),
        )

    def test_closed_vocabularies_and_auth_modes(self) -> None:
        self.assertEqual(
            {item.value for item in BrowserAction},
            {
                "navigate",
                "click_selector",
                "fill_reference",
                "submit",
                "wait_condition",
                "read_metadata",
                "screenshot_reference",
            },
        )
        self.assertEqual(
            {item.value for item in AuthenticationMode},
            {
                "basic",
                "bearer",
                "form_login",
                "totp_reference",
                "magic_link_reference",
                "social_login_reference",
                "multi_principal_test_accounts",
            },
        )
        with self.assertRaisesRegex(TransportContractError, "unknown HTTP method"):
            self.http_intent(method="TRACE")
        with self.assertRaisesRegex(TransportContractError, "unknown browser action"):
            BrowserActionIntent(
                self.binding,
                1,
                "evaluate_script",
                "https://app.example.test/assess",
                SessionBinding("session:one", "principal:alice"),
            )
        with self.assertRaisesRegex(TransportContractError, "unknown target authentication"):
            TargetSessionIntent(
                self.binding,
                1,
                "password_login",
                "https://app.example.test/assess/login",
                "POST",
                "principal:alice",
                (PrincipalCredentialReference("principal:alice", "credref:test/alice"),),
                "session:one",
            )

    def test_http_mock_is_deterministic_and_content_addressed(self) -> None:
        intent = self.http_intent(headers=(HeaderField("accept", "application/json"),))
        first = self.http_adapter(intent)
        second = self.http_adapter(intent)
        result_one = first.exchange(self.scope, intent)
        result_two = second.exchange(self.scope, intent)
        self.assertEqual(result_one, result_two)
        self.assertEqual(first.transcript(), second.transcript())
        self.assertEqual(result_one.state, TransportStepState.COMPLETED)
        self.assertEqual(result_one.observation.intent_sha256, intent.intent_sha256)
        self.assertTrue(first.transcript().transcript_id.startswith("ATT-"))
        TransportTranscript.from_dict(first.transcript().to_dict())

    def test_scope_must_be_verified_bound_and_allow_the_intent(self) -> None:
        intent = self.http_intent()
        adapter = self.http_adapter(intent)
        with self.assertRaisesRegex(TransportContractError, "VerifiedAssessmentScope"):
            adapter.exchange(self.scope.signed_scope, intent)

        other_binding = replace(self.binding, scope_sha256=DIGEST_C)
        other_intent = self.http_intent(binding=other_binding)
        other_adapter = self.http_adapter(other_intent, binding=other_binding)
        with self.assertRaisesRegex(TransportContractError, "does not match"):
            other_adapter.exchange(self.scope, other_intent)

        out_of_scope = self.http_intent(url="https://other.example.test/assess")
        with self.assertRaisesRegex(TransportContractError, "scope rejected"):
            self.http_adapter(out_of_scope).exchange(self.scope, out_of_scope)

        escalated_binding = replace(self.binding, impact_tier="R3")
        escalated = self.http_intent(binding=escalated_binding)
        with self.assertRaisesRegex(TransportContractError, "impact tier"):
            self.http_adapter(
                escalated,
                binding=escalated_binding,
            ).exchange(self.scope, escalated)

    def test_scope_and_transport_budgets_fail_closed(self) -> None:
        exhausted_scope_budget = replace(
            self.budget,
            requests_completed=20,
            requests_in_current_minute=20,
        )
        binding = replace(self.binding, budget=exhausted_scope_budget)
        intent = self.http_intent(binding=binding)
        with self.assertRaisesRegex(TransportContractError, "budget exhausted"):
            self.http_adapter(intent, binding=binding).exchange(self.scope, intent)

        too_large = self.http_intent(
            request_size=1025,
            body_sha256=DIGEST_A,
        )
        with self.assertRaisesRegex(TransportContractError, "request size"):
            self.http_adapter(too_large).exchange(self.scope, too_large)

        one_step = replace(self.budget, max_steps=1)
        binding = replace(self.binding, budget=one_step)
        first = self.http_intent(binding=binding)
        second = self.http_intent(sequence=2, binding=binding)
        adapter = DeterministicHttpTransport(
            binding,
            (
                ScriptedHttpExchange(first.intent_sha256, self.response()),
                ScriptedHttpExchange(second.intent_sha256, self.response()),
            ),
            health_script=self.health(
                AdapterHealthState.HEALTHY,
                AdapterHealthState.HEALTHY,
                AdapterHealthState.HEALTHY,
            ),
        )
        adapter.exchange(self.scope, first)
        with self.assertRaisesRegex(TransportContractError, "step budget exhausted"):
            adapter.exchange(self.scope, second)

    def test_headers_are_allowlisted_redacted_and_secret_headers_rejected(self) -> None:
        with self.assertRaisesRegex(TransportContractError, "secret headers"):
            HeaderField("Authorization", "opaque")

        intent = self.http_intent(headers=(HeaderField("x-custom", "safe"),))
        with self.assertRaisesRegex(TransportContractError, "not allowlisted"):
            self.http_adapter(intent).exchange(self.scope, intent)

        intent = self.http_intent()
        response = self.response(headers=(("etag", "opaque-tag"), ("x-request-id", "request-123")))
        observation = (
            self.http_adapter(intent, response=response).exchange(self.scope, intent).observation
        )
        self.assertTrue(all(item.redacted for item in observation.headers))
        self.assertTrue(all(item.value is None for item in observation.headers))

        secret_response = self.response(headers=(("set-cookie", "sid=opaque"),))
        with self.assertRaisesRegex(TransportContractError, "secret response headers"):
            self.http_adapter(intent, response=secret_response).exchange(self.scope, intent)

        unlisted_response = self.response(headers=(("server", "example"),))
        with self.assertRaisesRegex(TransportContractError, "not allowlisted"):
            self.http_adapter(intent, response=unlisted_response).exchange(self.scope, intent)

    def test_cookie_contract_contains_metadata_never_values(self) -> None:
        cookie = CookieMetadata("sid", "app.example.test", "/", True, True, "strict")
        self.assertNotIn("value", cookie.to_dict())
        raw = cookie.to_dict()
        raw["value"] = "forbidden"
        with self.assertRaisesRegex(TransportContractError, "extra"):
            CookieMetadata.from_dict(raw)
        intent = self.http_intent()
        observation = (
            self.http_adapter(
                intent,
                response=self.response(cookies=(cookie,)),
            )
            .exchange(self.scope, intent)
            .observation
        )
        self.assertNotIn("value", observation.cookies[0].to_dict())

    def test_redirect_download_mime_and_size_limits(self) -> None:
        first = self.http_intent(sequence=1)
        second = self.http_intent(sequence=2)
        redirect = self.response(
            status_code=302, redirect_url="https://app.example.test/assess/next"
        )
        adapter = DeterministicHttpTransport(
            self.binding,
            (
                ScriptedHttpExchange(first.intent_sha256, redirect),
                ScriptedHttpExchange(second.intent_sha256, redirect),
            ),
            health_script=self.health(
                AdapterHealthState.HEALTHY,
                AdapterHealthState.HEALTHY,
                AdapterHealthState.HEALTHY,
            ),
        )
        adapter.exchange(self.scope, first)
        with self.assertRaisesRegex(TransportContractError, "redirect limit"):
            adapter.exchange(self.scope, second)

        cases = (
            (self.response(is_download=True), "downloads"),
            (self.response(mime_type="application/zip"), "MIME type"),
            (self.response(response_size_bytes=4097), "size ceiling"),
            (self.response(mime_type="image/png", response_size_bytes=1025), "MIME size"),
        )
        for response, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(TransportContractError, message),
            ):
                self.http_adapter(first, response=response).exchange(self.scope, first)

        small_total = replace(self.budget, max_total_response_bytes=20)
        binding = replace(self.binding, budget=small_total)
        first = self.http_intent(sequence=1, binding=binding)
        second = self.http_intent(sequence=2, binding=binding)
        adapter = DeterministicHttpTransport(
            binding,
            (
                ScriptedHttpExchange(first.intent_sha256, self.response()),
                ScriptedHttpExchange(second.intent_sha256, self.response()),
            ),
            health_script=self.health(
                AdapterHealthState.HEALTHY,
                AdapterHealthState.HEALTHY,
                AdapterHealthState.HEALTHY,
            ),
        )
        adapter.exchange(self.scope, first)
        with self.assertRaisesRegex(TransportContractError, "total response"):
            adapter.exchange(self.scope, second)

    def test_cancellation_stop_and_continuous_health_pause_are_recorded(self) -> None:
        intent = self.http_intent()
        cancelled = self.http_adapter(intent).exchange(
            self.scope,
            intent,
            ExecutionControl(cancel_requested=True, reason="operator cancellation"),
        )
        self.assertEqual(cancelled.state, TransportStepState.CANCELLED)
        self.assertIsNone(cancelled.observation)

        stopped = self.http_adapter(intent).exchange(
            self.scope,
            intent,
            ExecutionControl(stop_requested=True, reason="stop condition reached"),
        )
        self.assertEqual(stopped.state, TransportStepState.STOPPED)

        health = self.health(AdapterHealthState.HEALTHY, AdapterHealthState.DEGRADED)
        adapter = self.http_adapter(intent, health=health)
        self.assertEqual(adapter.preflight(self.scope).state, AdapterHealthState.HEALTHY)
        paused = adapter.exchange(self.scope, intent)
        self.assertEqual(paused.state, TransportStepState.HEALTH_PAUSED)
        self.assertIn("degraded", paused.step.stop_reason)

    def test_browser_actions_use_references_and_reject_script_or_file_access(self) -> None:
        session = SessionBinding("session:alice", "principal:alice")
        fill = BrowserActionIntent(
            self.binding,
            1,
            BrowserAction.FILL_REFERENCE,
            "https://app.example.test/assess/login",
            session,
            selector_or_condition="#username",
            value_reference="credref:test/alice",
        )
        result = BrowserResultSpec(
            metadata=(("title", "Login"),),
            evidence_references=("evidref:screenshot/login",),
        )
        adapter = DeterministicBrowserTransport(
            self.binding,
            (ScriptedBrowserAction(fill.intent_sha256, result),),
            health_script=self.health(AdapterHealthState.HEALTHY, AdapterHealthState.HEALTHY),
        )
        self.assertEqual(adapter.perform(self.scope, fill).state, TransportStepState.COMPLETED)

        with self.assertRaisesRegex(TransportContractError, "credref"):
            replace(fill, value_reference="plaintext-value")
        with self.assertRaisesRegex(TransportContractError, "script syntax"):
            replace(
                fill,
                action=BrowserAction.CLICK_SELECTOR,
                selector_or_condition="javascript:alert(1)",
                value_reference=None,
            )
        with self.assertRaisesRegex(TransportContractError, "file access"):
            replace(
                fill,
                action=BrowserAction.CLICK_SELECTOR,
                selector_or_condition="input[type=file]",
                value_reference=None,
            )

    def test_target_auth_is_reference_only_and_sessions_are_principal_isolated(self) -> None:
        with self.assertRaisesRegex(TransportContractError, "credref"):
            PrincipalCredentialReference("principal:alice", "raw-password")

        with self.assertRaisesRegex(TransportContractError, "at least two"):
            TargetSessionIntent(
                self.binding,
                1,
                AuthenticationMode.MULTI_PRINCIPAL_TEST_ACCOUNTS,
                "https://app.example.test/assess/login",
                HttpMethod.POST,
                "principal:alice",
                (PrincipalCredentialReference("principal:alice", "credref:test/alice"),),
                "session:shared",
            )
        with self.assertRaisesRegex(TransportContractError, "request isolation"):
            TargetSessionIntent(
                self.binding,
                1,
                AuthenticationMode.BASIC,
                "https://app.example.test/assess/login",
                HttpMethod.POST,
                "principal:alice",
                (PrincipalCredentialReference("principal:alice", "credref:test/alice"),),
                "session:alice",
                isolated=False,
            )

        alice = TargetSessionIntent(
            self.binding,
            1,
            AuthenticationMode.MULTI_PRINCIPAL_TEST_ACCOUNTS,
            "https://app.example.test/assess/login",
            HttpMethod.POST,
            "principal:alice",
            (
                PrincipalCredentialReference("principal:alice", "credref:test/alice"),
                PrincipalCredentialReference("principal:bob", "credref:test/bob"),
            ),
            "session:shared",
        )
        bob = replace(alice, sequence=2, principal_label="principal:bob")
        adapter = DeterministicTargetSessionTransport(
            self.binding,
            (
                ScriptedSessionAcquisition(
                    alice.intent_sha256,
                    SessionResultSpec("session:shared", "principal:alice"),
                ),
                ScriptedSessionAcquisition(
                    bob.intent_sha256,
                    SessionResultSpec("session:shared", "principal:bob"),
                ),
            ),
            health_script=self.health(
                AdapterHealthState.HEALTHY,
                AdapterHealthState.HEALTHY,
                AdapterHealthState.HEALTHY,
            ),
        )
        adapter.acquire(self.scope, alice)
        with self.assertRaisesRegex(TransportContractError, "cross-principal"):
            adapter.acquire(self.scope, bob)

    def test_session_and_result_substitution_fail_closed(self) -> None:
        reference = PrincipalCredentialReference("principal:alice", "credref:test/alice")
        intent = TargetSessionIntent(
            self.binding,
            1,
            AuthenticationMode.BASIC,
            "https://app.example.test/assess/login",
            HttpMethod.POST,
            "principal:alice",
            (reference,),
            "session:alice",
        )
        substituted = SessionResultSpec("session:other", "principal:alice")
        adapter = DeterministicTargetSessionTransport(
            self.binding,
            (ScriptedSessionAcquisition(intent.intent_sha256, substituted),),
            health_script=self.health(AdapterHealthState.HEALTHY, AdapterHealthState.HEALTHY),
        )
        with self.assertRaisesRegex(TransportContractError, "substituted session"):
            adapter.acquire(self.scope, intent)

        http = self.http_intent()
        with self.assertRaisesRegex(TransportContractError, "does not match intent hash"):
            self.http_adapter(http, expected_hash=DIGEST_A).exchange(self.scope, http)

    def test_effect_escalation_is_rejected_and_no_effect_fields_are_published(self) -> None:
        intent = self.http_intent()
        effects = dict(NO_EFFECTS)
        effects["authority"] = "grant"
        response = self.response(effects=effects)
        with self.assertRaisesRegex(TransportContractError, "effects must all be none"):
            self.http_adapter(intent, response=response).exchange(self.scope, intent)

        transcript = self.http_adapter(intent)
        transcript.exchange(self.scope, intent)
        document = transcript.transcript().to_dict()
        self.assertEqual(document["effects"], dict(NO_EFFECTS))
        self.assertEqual(document["steps"][0]["effects"], dict(NO_EFFECTS))
        self.assertEqual(document["steps"][0]["observation"]["effects"], dict(NO_EFFECTS))

    def test_transcript_tamper_sequence_effect_and_result_substitution_fail(self) -> None:
        intent = self.http_intent()
        adapter = self.http_adapter(intent)
        adapter.exchange(self.scope, intent)
        document = adapter.transcript().to_dict()

        mutations = []
        changed_observation = copy.deepcopy(document)
        changed_observation["steps"][0]["observation"]["status_code"] = 201
        mutations.append(changed_observation)
        changed_sequence = copy.deepcopy(document)
        changed_sequence["steps"][0]["sequence"] = 2
        mutations.append(changed_sequence)
        changed_effect = copy.deepcopy(document)
        changed_effect["effects"]["network"] = "performed"
        mutations.append(changed_effect)
        substituted = copy.deepcopy(document)
        substituted["steps"][0]["observation"]["intent_sha256"] = DIGEST_A
        mutations.append(substituted)
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation["steps"][0]["sequence"]),
                self.assertRaises(TransportContractError),
            ):
                TransportTranscript.from_dict(mutation)

    @unittest.skipUnless(Draft202012Validator is not None, "jsonschema is not installed")
    def test_transcript_matches_closed_published_schema(self) -> None:
        intent = self.http_intent()
        adapter = self.http_adapter(intent)
        adapter.exchange(self.scope, intent)
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(adapter.transcript().to_dict())

    def test_assigned_files_use_ascii_dashes_and_forbidden_backends_are_absent(self) -> None:
        forbidden_code = (
            "import socket",
            "import requests",
            "import urllib",
            "selenium",
            "playwright",
            "subprocess",
            "credential store",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            if path.suffix == ".py" and path.name.startswith("assessment_transport"):
                folded = text.casefold()
                for marker in forbidden_code:
                    self.assertNotIn(marker, folded, (path, marker))


if __name__ == "__main__":
    unittest.main()
