"""Phase201 OpenAI expert provider adapter tests."""

from __future__ import annotations

import json
import unicodedata
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.expert_model_execution_custody import ProviderInvocationRejected
from sunderkey.multi_model_routing import ModelCapabilityDeclaration, canonical_json
from sunderkey.openai_expert_provider_adapter import (
    OPENAI_ENDPOINT_ALLOWLIST,
    OPENAI_ENDPOINT_HOST,
    OPENAI_ENDPOINT_PATH,
    OPENAI_ENDPOINT_PORT,
    OPENAI_PROVIDER_ID,
    OPENAI_RESPONSES_API_VERSION,
    HttpsOpenAIExpertTransport,
    OpenAIExpertProviderAdapter,
)
from sunderkey.provider_credential_resolver import (
    OPENAI_ENVIRONMENT_CREDENTIAL_REFERENCE,
    EnvironmentProviderCredentialResolver,
    ProviderCredentialResolutionError,
)

from . import test_authenticated_expert_model_execution_phase193 as phase193_fixture

ROOT = Path(__file__).resolve().parents[2]
PHASE_FILES = (
    ROOT / "docs" / "openai-expert-provider-adapter.md",
    ROOT / "src" / "sunderkey" / "openai_expert_provider_adapter.py",
    ROOT / "src" / "sunderkey" / "provider_credential_resolver.py",
    Path(__file__),
)
TEST_API_KEY = "phase201-test-credential-value"


class DeterministicOpenAITransport:
    """One-call fixture that never retains authorization material."""

    def __init__(self, response: dict[str, object] | None = None) -> None:
        self.response = response
        self.call_count = 0
        self.endpoint: tuple[str, int, str] | None = None
        self.request: dict[str, object] | None = None
        self.authorization_valid = False
        self.header_names: tuple[str, ...] = ()
        self.failure: Exception | None = None
        self.raw_response_body: bytes | None = None
        self.status = 200
        self.response_headers: dict[str, str] = {"x-request-id": "req_phase201_success"}

    def post_json(
        self,
        *,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str],
        body: bytes,
        timeout_seconds: int,
    ) -> tuple[int, dict[str, str], bytes]:
        self.call_count += 1
        self.endpoint = (host, port, path)
        self.authorization_valid = headers.get("Authorization") == f"Bearer {TEST_API_KEY}"
        self.header_names = tuple(sorted(headers))
        self.request = json.loads(body)
        if timeout_seconds != 180:
            raise AssertionError("Unexpected timeout")
        if self.failure is not None:
            raise self.failure
        if self.raw_response_body is not None:
            return self.status, self.response_headers, self.raw_response_body
        response = self.response
        if response is None:
            raise AssertionError("Response fixture is not configured")
        return self.status, self.response_headers, json.dumps(response).encode("utf-8")

    def __repr__(self) -> str:
        return "DeterministicOpenAITransport(authorization=<not-retained>)"


class OpenAIExpertProviderAdapterPhase201Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests
        fixture.setUpClass()
        cls.registry = fixture.registry
        cls.catalog = fixture.catalog

    def setUp(self) -> None:
        phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests.setUp(self)

    def capability(self) -> ModelCapabilityDeclaration:
        original = phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests.capability(self)
        return replace(
            original,
            provider_id=OPENAI_PROVIDER_ID,
            provider_api_version=OPENAI_RESPONSES_API_VERSION,
            model_id="gpt-5.6-sol",
            model_version="gpt-5.6-sol",
        )

    def budget(self):
        return phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests.budget(self)

    def request(self, **changes: object):
        return phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests.request(
            self,
            **changes,
        )

    def admit(self):
        return phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests.admit(self)

    def product_json(self, envelope) -> str:
        return phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests.product_json(
            self,
            envelope,
        )

    def _response(self, envelope, *, model: str = "gpt-5.6-sol") -> dict[str, object]:
        body = json.loads(self.product_json(envelope))
        body.pop("product_id")
        body.pop("product_sha256")
        return {
            "id": "resp_phase201_success",
            "model": model,
            "status": "completed",
            "usage": {
                "input_tokens": 500,
                "output_tokens": 200,
                "total_tokens": 700,
            },
            "output": [
                {"type": "reasoning", "summary": []},
                {
                    "id": "msg_phase201_success",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": canonical_json(body),
                            "annotations": [],
                        }
                    ],
                },
            ],
        }

    def _resolver(self):
        return EnvironmentProviderCredentialResolver(
            approved_reference="ref:vault/provider/expert-runtime",
            environment_lookup=lambda name: TEST_API_KEY if name == "OPENAI_API_KEY" else None,
        )

    def _adapter(self, envelope, transport, **changes):
        values = {
            "adapter_principal_id": "adapter.fixture",
            "runtime_catalog": self.catalog,
            "runtime_pack": self.pack,
            "envelope": envelope,
            "credential_resolver": self._resolver(),
            "transport": transport,
            "clock": lambda: self.now,
        }
        values.update(changes)
        return OpenAIExpertProviderAdapter(**values)

    def test_success_uses_exact_response_api_and_phase193_custody(self) -> None:
        admission, values = self.admit()
        transport = DeterministicOpenAITransport(self._response(values[1]))
        adapter = self._adapter(values[1], transport)

        result = self.custody.execute(
            admission,
            self.catalog,
            self.pack,
            values[1],
            values[2],
            values[3],
            adapter,
        )

        self.assertEqual(result.receipt.execution_state, "completed_settled")
        self.assertEqual(result.observation.provider_request_id, "req_phase201_success")
        self.assertEqual(result.observation.input_tokens, 500)
        self.assertEqual(result.observation.output_tokens, 200)
        self.assertEqual(result.observation.terminal_state, "completed")
        self.assertFalse(result.observation.usage_trustworthy)
        self.assertIsNone(result.observation.billable_cost_micros)
        self.assertEqual(result.settlement.usage_basis, "full_reservation")
        self.assertIsNotNone(result.work_product)
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(
            transport.endpoint,
            (OPENAI_ENDPOINT_HOST, OPENAI_ENDPOINT_PORT, OPENAI_ENDPOINT_PATH),
        )
        self.assertTrue(transport.authorization_valid)
        request = transport.request
        assert request is not None
        self.assertEqual(request["model"], "gpt-5.6-sol")
        self.assertIs(request["store"], False)
        self.assertEqual(request["tools"], [])
        self.assertEqual(request["tool_choice"], "none")
        self.assertIs(request["parallel_tool_calls"], False)
        self.assertNotIn(TEST_API_KEY, canonical_json(request))
        self.assertNotIn("Authorization", request)
        self.assertNotIn(admission.authority.credential_reference, canonical_json(request))
        self.assertNotIn("OPENAI_API_KEY", canonical_json(request))
        self.assertNotIn("Authorization", repr(transport))
        self.assertNotIn(TEST_API_KEY.encode("utf-8"), self.path.read_bytes())
        self.assertEqual(self.store.verify_store(self.registry).status, "valid")

    def test_request_document_is_credential_free_and_schema_bound(self) -> None:
        admission, values = self.admit()
        transport = DeterministicOpenAITransport(self._response(values[1]))
        adapter = self._adapter(values[1], transport)
        request = adapter.request_document(admission.invocation_plan)
        encoded = canonical_json(request)
        self.assertNotIn(TEST_API_KEY, encoded)
        self.assertNotIn(admission.authority.credential_reference, encoded)
        self.assertNotIn("OPENAI_API_KEY", encoded)
        self.assertIn(admission.invocation_plan.plan_sha256, repr(admission.invocation_plan))
        self.assertEqual(request["text"]["format"]["type"], "json_schema")
        self.assertTrue(request["text"]["format"]["strict"])
        schema = request["text"]["format"]["schema"]
        self.assertEqual(schema["type"], "object")
        self.assertIs(schema["additionalProperties"], False)
        Draft202012Validator.check_schema(schema)
        output = self._response(values[1])["output"]
        assert isinstance(output, list)
        message = output[1]
        assert isinstance(message, dict)
        content = message["content"]
        assert isinstance(content, list)
        part = content[0]
        assert isinstance(part, dict)
        Draft202012Validator(schema).validate(json.loads(str(part["text"])))
        self.assertEqual(tuple(OPENAI_ENDPOINT_ALLOWLIST), ("api.openai.com:443",))

    def test_malformed_incomplete_substituted_and_timeout_quarantine(self) -> None:
        cases: list[tuple[str, object]] = []
        response = self._response_placeholder()
        cases.append(("malformed", b"{"))
        incomplete = dict(response)
        incomplete["status"] = "incomplete"
        incomplete["incomplete_details"] = {"reason": "max_output_tokens"}
        cases.append(("incomplete", incomplete))
        substituted = dict(response)
        substituted["model"] = "gpt-5.6-sol-substituted"
        cases.append(("substituted", substituted))
        cases.append(("timeout", TimeoutError("transport timed out with no outcome")))

        for label, outcome in cases:
            with self.subTest(label=label):
                self.setUp()
                admission, values = self.admit()
                transport = DeterministicOpenAITransport(self._response(values[1]))
                if isinstance(outcome, bytes):
                    transport.raw_response_body = outcome
                elif isinstance(outcome, Exception):
                    transport.failure = outcome
                else:
                    exact = dict(outcome)
                    if label in {"incomplete", "substituted"}:
                        exact["output"] = self._response(values[1])["output"]
                    transport.response = exact
                result = self.custody.execute(
                    admission,
                    self.catalog,
                    self.pack,
                    values[1],
                    values[2],
                    values[3],
                    self._adapter(values[1], transport),
                )
                self.assertEqual(result.receipt.execution_state, "indeterminate_quarantined")
                self.assertEqual(result.settlement.usage_basis, "full_reservation")
                self.assertIsNone(result.work_product)
                self.assertEqual(transport.call_count, 1)

    def _response_placeholder(self) -> dict[str, object]:
        return {
            "id": "resp_phase201_placeholder",
            "model": "gpt-5.6-sol",
            "status": "completed",
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "output": [],
        }

    def test_invalid_work_product_and_missing_request_id_quarantine(self) -> None:
        for label in ("invalid_work_product", "missing_request_id"):
            with self.subTest(label=label):
                self.setUp()
                admission, values = self.admit()
                response = self._response(values[1])
                transport = DeterministicOpenAITransport(response)
                if label == "invalid_work_product":
                    output = response["output"]
                    assert isinstance(output, list)
                    message = output[1]
                    assert isinstance(message, dict)
                    content = message["content"]
                    assert isinstance(content, list)
                    part = content[0]
                    assert isinstance(part, dict)
                    product_body = json.loads(str(part["text"]))
                    product_body["mission_id"] = "MISSION-SUBSTITUTED"
                    part["text"] = json.dumps(product_body, indent=2)
                else:
                    transport.response_headers = {}
                result = self.custody.execute(
                    admission,
                    self.catalog,
                    self.pack,
                    values[1],
                    values[2],
                    values[3],
                    self._adapter(values[1], transport),
                )
                self.assertEqual(result.receipt.execution_state, "indeterminate_quarantined")
                self.assertEqual(transport.call_count, 1)

    def test_credential_failure_rejects_before_network_without_secret_disclosure(self) -> None:
        admission, values = self.admit()
        transport = DeterministicOpenAITransport(self._response(values[1]))
        resolver = EnvironmentProviderCredentialResolver(
            approved_reference="ref:vault/provider/expert-runtime",
            environment_lookup=lambda _name: None,
        )
        adapter = self._adapter(values[1], transport, credential_resolver=resolver)
        result = self.custody.execute(
            admission,
            self.catalog,
            self.pack,
            values[1],
            values[2],
            values[3],
            adapter,
        )
        self.assertEqual(result.receipt.execution_state, "provider_failed_settled")
        self.assertEqual(transport.call_count, 0)
        self.assertNotIn(TEST_API_KEY, repr(adapter))
        self.assertNotIn(TEST_API_KEY, repr(resolver))

    def test_credential_lease_is_ephemeral_and_repr_is_redacted(self) -> None:
        resolver = EnvironmentProviderCredentialResolver(
            environment_lookup=lambda name: TEST_API_KEY if name == "OPENAI_API_KEY" else None,
        )
        with resolver.open_credential(OPENAI_ENVIRONMENT_CREDENTIAL_REFERENCE) as lease:
            self.assertEqual(lease.bearer_authorization(), f"Bearer {TEST_API_KEY}")
            self.assertNotIn(TEST_API_KEY, repr(lease))
        with self.assertRaises(ProviderCredentialResolutionError):
            lease.bearer_authorization()
        with self.assertRaises(ProviderCredentialResolutionError):
            resolver.open_credential("ref:env:OTHER").__enter__()

    def test_credential_material_in_request_is_rejected_before_transport(self) -> None:
        admission, values = self.admit()
        transport = DeterministicOpenAITransport(self._response(values[1]))
        colliding_value = "authorization_effect"
        resolver = EnvironmentProviderCredentialResolver(
            approved_reference="ref:vault/provider/expert-runtime",
            environment_lookup=lambda _name: colliding_value,
        )
        result = self.custody.execute(
            admission,
            self.catalog,
            self.pack,
            values[1],
            values[2],
            values[3],
            self._adapter(values[1], transport, credential_resolver=resolver),
        )
        self.assertEqual(result.receipt.execution_state, "provider_failed_settled")
        self.assertEqual(transport.call_count, 0)

    def test_smoke_is_explicit_plan_bound_and_nonqualifying(self) -> None:
        admission, values = self.admit()
        transport = DeterministicOpenAITransport(self._response(values[1]))
        adapter = OpenAIExpertProviderAdapter.for_operator_confirmed_network_smoke(
            confirm_invocation_plan_sha256=admission.invocation_plan.plan_sha256,
            adapter_principal_id="adapter.fixture",
            runtime_catalog=self.catalog,
            runtime_pack=self.pack,
            envelope=values[1],
            credential_resolver=self._resolver(),
            transport=transport,
            clock=lambda: self.now,
        )
        self.assertFalse(adapter.qualifying)
        with self.assertRaises(AttributeError):
            adapter.qualifying = True
        result = self.custody.execute(
            admission,
            self.catalog,
            self.pack,
            values[1],
            values[2],
            values[3],
            adapter,
        )
        self.assertEqual(result.receipt.execution_state, "completed_settled")
        self.assertEqual(transport.call_count, 1)

    def test_smoke_plan_substitution_and_endpoint_substitution_fail_before_call(self) -> None:
        admission, values = self.admit()
        transport = DeterministicOpenAITransport(self._response(values[1]))
        adapter = OpenAIExpertProviderAdapter.for_operator_confirmed_network_smoke(
            confirm_invocation_plan_sha256="sha256:" + "f" * 64,
            adapter_principal_id="adapter.fixture",
            runtime_catalog=self.catalog,
            runtime_pack=self.pack,
            envelope=values[1],
            credential_resolver=self._resolver(),
            transport=transport,
            clock=lambda: self.now,
        )
        with self.assertRaises(ProviderInvocationRejected):
            adapter.invoke(
                admission.invocation_plan,
                admission.authority.credential_reference,
            )
        self.assertEqual(transport.call_count, 0)
        with self.assertRaises(ProviderInvocationRejected):
            HttpsOpenAIExpertTransport().post_json(
                host="example.invalid",
                port=443,
                path=OPENAI_ENDPOINT_PATH,
                headers={},
                body=b"{}",
                timeout_seconds=180,
            )

    def test_public_exports_and_phase_file_hygiene(self) -> None:
        import sunderkey

        expected = {
            "EnvironmentProviderCredentialResolver",
            "HttpsOpenAIExpertTransport",
            "OpenAIExpertProviderAdapter",
            "OpenAIExpertTransport",
            "ProviderCredentialLease",
            "ProviderCredentialResolver",
            "build_openai_expert_output_schema",
            "build_openai_expert_response_request",
        }
        self.assertTrue(expected.issubset(sunderkey.__all__))
        self.assertTrue(all(hasattr(sunderkey, name) for name in expected))
        markers = ("Chat" + "GPT", "Generated" + " by", "Co-authored" + "-by:", "\u2013", "\u2014")
        for path in PHASE_FILES:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertTrue(all(marker not in text for marker in markers))
                self.assertFalse(
                    any(
                        unicodedata.category(character) in {"Cf", "Cs"}
                        or (
                            unicodedata.category(character) == "Cc"
                            and character not in "\t\n\r"
                        )
                        for character in text
                    )
                )


if __name__ == "__main__":
    unittest.main()
