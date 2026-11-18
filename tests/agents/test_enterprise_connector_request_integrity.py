"""Pinned enterprise request mapping and pre-transport replay regressions."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace

from sunderkey.enterprise_connector_contracts import (
    ConnectorBinding,
    ConnectorDeliveryRequest,
    ConnectorTransportResponse,
    DeliveryDisposition,
    EnterpriseConnectorError,
    RouteParameter,
    build_connector_delivery_request,
    canonical_json,
    deliver_with_connector,
    parse_contract,
)
from tests.agents import test_enterprise_connector_contracts_phase166 as fixture_module
from tests.agents.test_enterprise_connector_contracts_phase166 import ONE, FakeTransport

OPERATIONS = ("jira_create_issue", "sentinel_send_data", "copilot_publish_plugin")
OBSERVED_AT = "2026-09-20T12:02:00Z"
GOLDENS = {
    "jira_create_issue": (
        "ECB-C7109A8DA61DFB1AD21F896BCC430AB6",
        "sha256:c7109a8da61dfb1ad21f896bcc430ab6c759cbd1bd8636d2a9c738f72febc80d",
        "ECD-7C7BF88EA9B63E3B9184FAD2FBBB134B",
        "sha256:7c7bf88ea9b63e3b9184fad2fbbb134b5021bf6e2e569804d63c1e4c80ae6f6e",
    ),
    "sentinel_send_data": (
        "ECB-FEF1703400025DC421A2209D7B9E488F",
        "sha256:fef1703400025dc421a2209d7b9e488fcf0d762fb8b7b5a9bdc4431b003f7153",
        "ECD-5A18AF5DE8E73C0E091A28D35BA1C18B",
        "sha256:5a18af5de8e73c0e091a28d35ba1c18b0a43adae2f4706443edece5e5e01ff24",
    ),
    "copilot_publish_plugin": (
        "ECB-69D8107AC91A9E3D4AD28EE138BDDE1C",
        "sha256:69d8107ac91a9e3d4ad28ee138bdde1ce13a4346f5831287286aec349eda38ff",
        "ECD-551062D41297DB5FF94E5F1D8BE99E96",
        "sha256:551062d41297db5ff94e5f1d8be99e96efeda578fd22368f7824544d3f4e11e1",
    ),
}


class IntegerAlias(int):
    """An equal-valued, nonnative metadata fixture."""


class EnterpriseConnectorRequestIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        # These helpers construct native contracts only. No fixture setup,
        # store, endpoint resolver, credential resolver or provider is used.
        self.fixture = fixture_module.EnterpriseConnectorContractsPhase166Tests(
            methodName="runTest"
        )

    def transport(self) -> FakeTransport:
        return FakeTransport(
            ConnectorTransportResponse(
                status_code=201,
                response_sha256=ONE,
                external_resource_ref="remoteref:synthetic-accepted",
            )
        )

    def assert_rejected_before_send(self, binding, request) -> None:
        transport = self.transport()
        with self.assertRaises(EnterpriseConnectorError):
            deliver_with_connector(binding, request, transport, observed_at=OBSERVED_AT)
        self.assertEqual(transport.calls, [])

    def test_all_three_vendor_native_roundtrips_preserve_golden_ids_and_one_call(self) -> None:
        for operation in OPERATIONS:
            with self.subTest(operation=operation):
                binding = self.fixture.binding(operation)
                request = self.fixture.request(binding)
                self.assertEqual(
                    (
                        binding.binding_id,
                        binding.binding_sha256,
                        request.request_id,
                        request.request_sha256,
                    ),
                    GOLDENS[operation],
                )
                parsed_binding = parse_contract(json.dumps(binding.to_dict()))
                parsed_request = parse_contract(json.dumps(request.to_dict()))
                self.assertIs(type(parsed_binding), ConnectorBinding)
                self.assertIs(type(parsed_request), ConnectorDeliveryRequest)
                self.assertEqual(parsed_binding.to_dict(), binding.to_dict())
                self.assertEqual(parsed_request.to_dict(), request.to_dict())
                transport = self.transport()
                observation = deliver_with_connector(
                    parsed_binding, parsed_request, transport, observed_at=OBSERVED_AT
                )
                self.assertEqual(observation.disposition, DeliveryDisposition.SUCCEEDED)
                self.assertEqual(
                    transport.calls,
                    [(binding.endpoint_ref, binding.credential_ref, request.request_id)],
                )
                self.assertEqual(observation.request_sha256, request.request_sha256)

    def test_six_rehashed_native_wrong_path_or_body_requests_never_reach_transport(self) -> None:
        for operation in OPERATIONS:
            binding = self.fixture.binding(operation)
            original = self.fixture.request(binding)
            body = json.loads(original.body_json)
            if operation == "jira_create_issue":
                body["fields"]["project"]["reference"] = "projectref:unselected"
            elif operation == "sentinel_send_data":
                body[0]["EventId"] = "event:unrelated"
            else:
                body["openapi_spec_sha256"] = "sha256:" + "ab" * 32
            for case, changes in (
                ("path", {"path_template": "/unselected/path"}),
                ("body", {"body_json": canonical_json(body)}),
            ):
                with self.subTest(operation=operation, case=case):
                    altered = replace(original, **changes, request_id="", request_sha256="")
                    parsed = parse_contract(json.dumps(altered.to_dict()))
                    self.assertEqual(parsed.to_dict(), altered.to_dict())
                    self.assertEqual(parsed.binding_id, original.binding_id)
                    self.assertEqual(parsed.binding_sha256, original.binding_sha256)
                    self.assertEqual(parsed.event, original.event)
                    self.assertNotEqual(parsed.request_sha256, original.request_sha256)
                    self.assert_rejected_before_send(binding, parsed)

    def test_other_vendor_body_under_same_binding_and_event_is_rejected(self) -> None:
        for index, operation in enumerate(OPERATIONS):
            with self.subTest(operation=operation):
                binding = self.fixture.binding(operation)
                request = self.fixture.request(binding)
                other = self.fixture.request(self.fixture.binding(OPERATIONS[(index + 1) % 3]))
                altered = replace(
                    request, body_json=other.body_json, request_id="", request_sha256=""
                )
                parsed = parse_contract(json.dumps(altered.to_dict()))
                self.assertEqual(parsed.event, request.event)
                self.assert_rejected_before_send(binding, parsed)

    def test_body_from_old_event_cannot_claim_a_different_event_projection(self) -> None:
        for operation in OPERATIONS:
            with self.subTest(operation=operation):
                binding = self.fixture.binding(operation)
                request = self.fixture.request(binding)
                changed_event = self.fixture.event(
                    summary="A different supplied summary", event_sha256=ONE
                )
                altered = replace(request, event=changed_event, request_id="", request_sha256="")
                parsed = parse_contract(json.dumps(altered.to_dict()))
                self.assert_rejected_before_send(binding, parsed)

    def test_readdressed_source_route_change_requires_rebuilt_vendor_body(self) -> None:
        binding = self.fixture.binding()
        request = self.fixture.request(binding)
        changed_binding = replace(
            binding,
            route_parameters=(
                RouteParameter("project_ref", "projectref:other-selected"),
                RouteParameter("issue_type_ref", "issuetyperef:vulnerability"),
            ),
            binding_id="",
            binding_sha256="",
        )
        stale_body = replace(
            request,
            binding_id=changed_binding.binding_id,
            binding_sha256=changed_binding.binding_sha256,
            request_id="",
            request_sha256="",
        )
        self.assert_rejected_before_send(
            changed_binding, parse_contract(json.dumps(stale_body.to_dict()))
        )
        rebuilt = build_connector_delivery_request(
            changed_binding,
            request.event,
            idempotency_key=request.idempotency_key,
            created_at=request.created_at,
            expires_at=request.expires_at,
        )
        transport = self.transport()
        deliver_with_connector(changed_binding, rebuilt, transport, observed_at=OBSERVED_AT)
        self.assertEqual(len(transport.calls), 1)

    def test_unrehashed_path_or_body_tampering_is_rejected_by_parser(self) -> None:
        for operation in OPERATIONS:
            request = self.fixture.request(self.fixture.binding(operation))
            for field, value in (("path_template", "/unselected/path"), ("body_json", "{}")):
                with self.subTest(operation=operation, field=field):
                    changed = request.to_dict()
                    changed[field] = value
                    transport = self.transport()
                    with self.assertRaises(EnterpriseConnectorError):
                        parsed = parse_contract(json.dumps(changed))
                        deliver_with_connector(
                            self.fixture.binding(operation),
                            parsed,
                            transport,
                            observed_at=OBSERVED_AT,
                        )
                    self.assertEqual(transport.calls, [])

    def test_noncanonical_vendor_body_is_rejected_before_transport(self) -> None:
        for operation in OPERATIONS:
            with self.subTest(operation=operation):
                binding = self.fixture.binding(operation)
                request = self.fixture.request(binding)
                raw = request.to_dict()
                raw["body_json"] = json.dumps(json.loads(request.body_json), indent=2)
                transport = self.transport()
                with self.assertRaises(EnterpriseConnectorError):
                    parsed = parse_contract(raw)
                    deliver_with_connector(binding, parsed, transport, observed_at=OBSERVED_AT)
                self.assertEqual(transport.calls, [])

    def test_native_wire_schema_aliases_cannot_normalize_to_unchanged_identity(self) -> None:
        for contract in (self.fixture.binding(), self.fixture.request()):
            for value in (True, 1.0, IntegerAlias(1)):
                with self.subTest(kind=contract.KIND, value=value, family=type(value)):
                    raw = copy.deepcopy(contract.to_dict())
                    raw["schema_version"] = value
                    digest_field = (
                        "binding_sha256"
                        if isinstance(contract, ConnectorBinding)
                        else "request_sha256"
                    )
                    self.assertEqual(raw[digest_field], contract.to_dict()[digest_field])
                    document = canonical_json(raw) if type(value) in {bool, float} else raw
                    with self.assertRaises(EnterpriseConnectorError):
                        parse_contract(document)

    def test_direct_native_request_tamper_is_rejected_before_transport(self) -> None:
        for field, value in (
            ("path_template", "/unselected/path"),
            ("body_json", "{}"),
            ("request_id", "ECD-" + "0" * 32),
            ("request_sha256", ONE),
        ):
            with self.subTest(field=field):
                binding = self.fixture.binding()
                request = self.fixture.request(binding)
                object.__setattr__(request, field, value)
                self.assert_rejected_before_send(binding, request)

    def test_direct_native_binding_tamper_is_rejected_before_transport(self) -> None:
        for field, value in (
            ("endpoint_ref", "endpointref:other"),
            ("credential_ref", "credentialref:other"),
            ("api_version", "4"),
        ):
            with self.subTest(field=field):
                binding = self.fixture.binding()
                request = self.fixture.request(binding)
                object.__setattr__(binding, field, value)
                self.assert_rejected_before_send(binding, request)

    def test_request_window_and_binding_window_semantics_are_unchanged(self) -> None:
        binding = self.fixture.binding()
        request = self.fixture.request(binding)
        for observed_at in (
            "2026-09-20T11:59:59Z",
            "2026-09-20T12:00:59Z",
            request.expires_at,
            binding.expires_at,
        ):
            with self.subTest(observed_at=observed_at):
                transport = self.transport()
                with self.assertRaises(EnterpriseConnectorError):
                    deliver_with_connector(binding, request, transport, observed_at=observed_at)
                self.assertEqual(transport.calls, [])

    def test_valid_status_normalization_still_uses_one_call_and_no_retry(self) -> None:
        for operation in OPERATIONS:
            for status, expected in (
                (204, DeliveryDisposition.SUCCEEDED),
                (429, DeliveryDisposition.RETRYABLE_FAILURE),
                (503, DeliveryDisposition.RETRYABLE_FAILURE),
                (400, DeliveryDisposition.PERMANENT_FAILURE),
            ):
                with self.subTest(operation=operation, status=status):
                    binding = self.fixture.binding(operation)
                    request = self.fixture.request(binding)
                    transport = FakeTransport(
                        ConnectorTransportResponse(
                            status_code=status,
                            response_sha256=ONE,
                            external_resource_ref=(
                                "remoteref:synthetic-accepted" if status == 204 else None
                            ),
                            retry_after_seconds=60 if status == 429 else None,
                        )
                    )
                    observation = deliver_with_connector(
                        binding, request, transport, observed_at=OBSERVED_AT
                    )
                    self.assertEqual(observation.disposition, expected)
                    self.assertEqual(len(transport.calls), 1)


if __name__ == "__main__":
    unittest.main()
