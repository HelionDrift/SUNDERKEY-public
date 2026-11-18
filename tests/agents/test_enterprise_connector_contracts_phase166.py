"""Phase 166 Jira and Microsoft connector boundary coverage."""

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

from sunderkey.enterprise_connector_contracts import (
    NO_BUILTIN_NETWORK,
    ConnectorBinding,
    ConnectorDeliveryRequest,
    ConnectorTransportResponse,
    DeliveryDisposition,
    EnterpriseConnectorError,
    IntegrationProjection,
    RouteParameter,
    build_connector_delivery_request,
    deliver_with_connector,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "enterprise-connector-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "enterprise_connector_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "enterprise-connector-contracts.md",
)
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64


class FakeTransport:
    def __init__(self, response: ConnectorTransportResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, str, str]] = []

    def send(self, *, endpoint_ref: str, credential_ref: str, request):
        self.calls.append((endpoint_ref, credential_ref, request.request_id))
        return self.response


class EnterpriseConnectorContractsPhase166Tests(unittest.TestCase):
    def binding(self, operation: str = "jira_create_issue") -> ConnectorBinding:
        if operation == "jira_create_issue":
            kind = "jira_cloud"
            version = "3"
            route = (
                RouteParameter("project_ref", "projectref:security"),
                RouteParameter("issue_type_ref", "issuetyperef:vulnerability"),
            )
        elif operation == "sentinel_send_data":
            kind = "microsoft_sentinel"
            version = "2023-01-01"
            route = (
                RouteParameter("stream_ref", "streamref:Custom-Sunderkey_CL"),
                RouteParameter("dcr_immutable_ref", "dcrref:dcr-001"),
            )
        else:
            kind = "security_copilot"
            version = "3.0.1"
            route = (
                RouteParameter("plugin_manifest_ref", "artifactref:copilot-plugin"),
                RouteParameter("plugin_manifest_sha256", ZERO),
                RouteParameter("openapi_spec_ref", "artifactref:connector-openapi"),
                RouteParameter("openapi_spec_sha256", ONE),
            )
        return ConnectorBinding(
            tenant_ref="tenantref:acme",
            destination_ref=f"destinationref:{kind}",
            connector_kind=kind,
            operation=operation,
            endpoint_ref=f"endpointref:{kind}",
            credential_ref=f"credentialref:{kind}",
            api_version=version,
            route_parameters=route,
            enabled_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T13:00:00Z",
        )

    def event(self, **changes: object) -> IntegrationProjection:
        values: dict[str, object] = {
            "event_id": "event:finding-001",
            "event_sha256": ZERO,
            "event_type": "finding.changed",
            "subject_ref": "findingref:F-001",
            "state": "validated",
            "severity": "high",
            "summary": "Validated authorization boundary finding",
            "artifact_refs": ("reportref:R-001",),
            "occurred_at": "2026-09-20T12:01:00Z",
        }
        values.update(changes)
        return IntegrationProjection(**values)

    def request(self, binding: ConnectorBinding | None = None) -> ConnectorDeliveryRequest:
        active = binding or self.binding()
        return build_connector_delivery_request(
            active,
            self.event(),
            idempotency_key="idem:finding-001-delivery",
            created_at="2026-09-20T12:01:00Z",
            expires_at="2026-09-20T12:10:00Z",
        )

    def test_all_vendor_shapes_are_deterministic_and_secret_safe(self) -> None:
        cases = {
            "jira_create_issue": "/rest/api/3/issue",
            "sentinel_send_data": "/dataCollectionRules/{dcr_immutable_ref}/streams/{stream_ref}",
            "copilot_publish_plugin": "/security-copilot/plugins",
        }
        for operation, path in cases.items():
            with self.subTest(operation=operation):
                binding = self.binding(operation)
                first = self.request(binding)
                second = self.request(binding)
                self.assertEqual(first, second)
                self.assertEqual(first.path_template, path)
                self.assertNotIn(binding.credential_ref, first.body_json)
                self.assertNotIn(binding.endpoint_ref, first.body_json)
                self.assertTrue(first.request_id.startswith("ECD-"))

    def test_binding_and_request_round_trip_and_reject_tamper(self) -> None:
        for contract in (self.binding(), self.request()):
            document = contract.to_dict()
            parsed = parse_contract(json.dumps(document))
            self.assertEqual(parsed.to_dict(), document)
            tampered = copy.deepcopy(document)
            digest_field = (
                "binding_sha256" if isinstance(contract, ConnectorBinding) else "request_sha256"
            )
            tampered[digest_field] = ONE
            with self.assertRaises(EnterpriseConnectorError):
                parse_contract(tampered)

    def test_successful_delivery_passes_only_opaque_resolver_inputs(self) -> None:
        binding = self.binding()
        request = self.request(binding)
        transport = FakeTransport(
            ConnectorTransportResponse(
                status_code=201,
                response_sha256=ONE,
                external_resource_ref="ticketref:SEC-42",
            )
        )
        observation = deliver_with_connector(
            binding,
            request,
            transport,
            observed_at="2026-09-20T12:02:00Z",
        )
        self.assertEqual(observation.disposition, DeliveryDisposition.SUCCEEDED)
        self.assertEqual(
            transport.calls,
            [(binding.endpoint_ref, binding.credential_ref, request.request_id)],
        )
        self.assertTrue(observation.observation_id.startswith("ECO-"))

    def test_response_statuses_are_normalized_for_outbox_policy(self) -> None:
        cases = (
            (429, 60, DeliveryDisposition.RETRYABLE_FAILURE),
            (503, None, DeliveryDisposition.RETRYABLE_FAILURE),
            (400, None, DeliveryDisposition.PERMANENT_FAILURE),
        )
        for status, retry_after, expected in cases:
            with self.subTest(status=status):
                binding = self.binding("sentinel_send_data")
                request = self.request(binding)
                transport = FakeTransport(
                    ConnectorTransportResponse(
                        status_code=status,
                        response_sha256=ONE,
                        retry_after_seconds=retry_after,
                    )
                )
                observation = deliver_with_connector(
                    binding,
                    request,
                    transport,
                    observed_at="2026-09-20T12:02:00Z",
                )
                self.assertEqual(observation.disposition, expected)

    def test_stale_cross_context_and_rebound_requests_never_reach_transport(self) -> None:
        binding = self.binding()
        request = self.request(binding)
        transport = FakeTransport(
            ConnectorTransportResponse(
                status_code=201,
                response_sha256=ONE,
                external_resource_ref="ticketref:SEC-42",
            )
        )
        cases = (
            (binding, request, "2026-09-20T12:10:00Z"),
            (
                replace(
                    binding,
                    tenant_ref="tenantref:other",
                    binding_id="",
                    binding_sha256="",
                ),
                request,
                "2026-09-20T12:02:00Z",
            ),
            (
                replace(
                    binding,
                    destination_ref="destinationref:other",
                    binding_id="",
                    binding_sha256="",
                ),
                request,
                "2026-09-20T12:02:00Z",
            ),
        )
        for changed_binding, changed_request, observed_at in cases:
            with self.subTest(observed_at=observed_at), self.assertRaises(EnterpriseConnectorError):
                deliver_with_connector(
                    changed_binding,
                    changed_request,
                    transport,
                    observed_at=observed_at,
                )
        self.assertEqual(transport.calls, [])

    def test_route_parameters_and_versions_are_exact(self) -> None:
        with self.assertRaises(EnterpriseConnectorError):
            replace(self.binding(), api_version="latest")
        with self.assertRaises(EnterpriseConnectorError):
            replace(
                self.binding(),
                route_parameters=(RouteParameter("project_ref", "projectref:security"),),
            )
        with self.assertRaises(EnterpriseConnectorError):
            replace(self.binding(), connector_kind="microsoft_sentinel")

    def test_secret_like_and_exploit_material_is_rejected(self) -> None:
        for summary in (
            "authorization: Bearer abcdefghijklmnop",
            "token=abcdefghijklmnop",
            "curl https://example.invalid/collect",
        ):
            with self.subTest(summary=summary), self.assertRaises(EnterpriseConnectorError):
                self.event(summary=summary)

    def test_failed_transport_cannot_claim_external_resource(self) -> None:
        binding = self.binding()
        request = self.request(binding)
        transport = FakeTransport(
            ConnectorTransportResponse(
                status_code=500,
                response_sha256=ONE,
                external_resource_ref="ticketref:false-claim",
            )
        )
        with self.assertRaises(EnterpriseConnectorError):
            deliver_with_connector(
                binding,
                request,
                transport,
                observed_at="2026-09-20T12:02:00Z",
            )

    def test_records_are_immutable(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.binding().api_version = "4"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            self.request().body_json = "{}"  # type: ignore[misc]

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_binding_and_request(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for document in (self.binding().to_dict(), self.request().to_dict()):
            self.assertEqual(list(validator.iter_errors(document)), [])

    def test_public_package_exports_connector_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.EnterpriseConnectorBinding, ConnectorBinding)
        self.assertIs(
            sunderkey.build_connector_delivery_request,
            build_connector_delivery_request,
        )
        self.assertIs(sunderkey.deliver_with_connector, deliver_with_connector)
        self.assertIs(sunderkey.parse_enterprise_connector_contract, parse_contract)

    def test_created_files_have_no_markers_or_unicode_dashes(self) -> None:
        markers = (
            "generated " + "by",
            "written by " + "ai",
            "as an " + "ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)
            for marker in markers:
                self.assertNotIn(marker, lowered)
        self.assertTrue(NO_BUILTIN_NETWORK)


if __name__ == "__main__":
    unittest.main()
