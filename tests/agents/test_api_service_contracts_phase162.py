"""Phase 162 external API and webhook contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.api_service_contracts import (
    NO_EFFECTS,
    ApiContractError,
    ApiError,
    ApiOperation,
    ApiRequestEnvelope,
    ApiResponseEnvelope,
    DetachedSignature,
    PageRequest,
    PageResult,
    ReplayWindow,
    RequestBudget,
    ResourceReference,
    RetryPlan,
    TenantPrincipalBinding,
    WebhookAcknowledgement,
    WebhookDelivery,
    WebhookSubscription,
    accept_webhook_delivery,
    parse_contract,
    verify_api_exchange,
    verify_webhook_acknowledgement,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "api-service-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "api_service_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "api-service-contracts.md",
)
DIGESTS = tuple("sha256:" + character * 64 for character in "0123456789abcdef")
SIGNATURE = "A" * 43


class ApiServiceContractsPhase162Tests(unittest.TestCase):
    def binding(self) -> TenantPrincipalBinding:
        return TenantPrincipalBinding(
            tenant_id="tenant.acme",
            principal_id="principal.operator",
            principal_role="assessment_operator",
            authentication_context_ref="authctx.session-01",
        )

    def budget(self) -> RequestBudget:
        return RequestBudget(
            max_body_bytes=65_536,
            max_reference_count=100,
            max_page_size=50,
            max_requests_per_minute=120,
        )

    def signature(self, key_ref: str = "secretref:webhooks.acme.key-1") -> DetachedSignature:
        return DetachedSignature(key_ref, "ed25519", SIGNATURE)

    def resource(self, kind: str, index: int = 0) -> ResourceReference:
        prefixes = {
            "assessment": "assessmentref:",
            "scope_admission": "scoperef:",
            "schedule": "schedref:",
            "status": "statusref:",
            "evidence": "evidref:",
            "finding": "findingref:",
            "report": "reportref:",
            "cancellation": "statusref:",
            "emergency_stop": "statusref:",
        }
        return ResourceReference(kind, f"{prefixes[kind]}resource-{index}", DIGESTS[index], 1)

    def request(self, operation: str) -> ApiRequestEnvelope:
        kwargs: dict[str, object] = {
            "operation": operation,
            "request_id": f"request.{operation}",
            "binding": self.binding(),
            "issued_at": "2026-09-20T12:00:00Z",
            "body_size_bytes": 256,
            "budget": self.budget(),
        }
        if operation == "create_assessment":
            kwargs.update(
                idempotency_key="idem:create-assessment-0001",
                content_references=(self.resource("scope_admission"),),
            )
        else:
            kwargs["resource_id"] = "assessment.001"
        if operation in {
            "admit_scope",
            "create_schedule",
            "cancel_assessment",
            "emergency_stop",
        }:
            kwargs["idempotency_key"] = f"idem:{operation}-00000001"
        if operation in {"create_schedule", "cancel_assessment", "emergency_stop"}:
            kwargs["expected_resource_version"] = 7
        if operation == "admit_scope":
            kwargs["content_references"] = (self.resource("scope_admission"),)
        if operation == "create_schedule":
            kwargs["content_references"] = (
                self.resource("assessment"),
                self.resource("scope_admission", 1),
            )
        if operation in {"list_evidence", "list_findings"}:
            kwargs["page"] = PageRequest(25, None)
        if operation in {"cancel_assessment", "emergency_stop"}:
            kwargs["reason_code"] = "operator_request"
        return ApiRequestEnvelope(**kwargs)

    def subscription(self) -> WebhookSubscription:
        return WebhookSubscription(
            subscription_id="subscription.001",
            binding=self.binding(),
            endpoint_ref="endpointref:tenant.acme.receiver",
            signing_key_ref="secretref:webhooks.acme.key-1",
            event_filters=("finding.changed", "report.available"),
            max_in_flight=4,
            created_at="2026-09-20T12:00:00Z",
            signature=self.signature(),
        )

    def delivery(
        self,
        *,
        sequence: int = 1,
        delivery_id: str = "delivery.001",
        nonce: str = "nonce:AAAAAAAAAAAAAAAAAAAAAA",
        event_type: str = "finding.changed",
        state: str = "planned",
        attempt: int = 1,
        expires_at: str = "2026-09-20T12:10:00Z",
    ) -> WebhookDelivery:
        subscription = self.subscription()
        event_resource_kind = {
            "finding.changed": "finding",
            "status.changed": "status",
        }[event_type]
        return WebhookDelivery(
            delivery_id=delivery_id,
            subscription_id=subscription.subscription_id,
            subscription_sha256=subscription.subscription_sha256,
            sequence=sequence,
            nonce=nonce,
            event_type=event_type,
            resource=self.resource(event_resource_kind, 1),
            occurred_at="2026-09-20T12:01:00Z",
            expires_at=expires_at,
            attempt=attempt,
            state=state,
            retry_plan=RetryPlan((30, 120), 3),
            signature=self.signature(),
        )

    def test_all_api_operations_have_strict_versioned_round_trips(self) -> None:
        for operation in ApiOperation:
            with self.subTest(operation=operation.value):
                request = self.request(operation.value)
                self.assertEqual(request, ApiRequestEnvelope.from_json(request.to_json()))
                self.assertEqual(request, parse_contract(request.to_dict()))
                self.assertEqual(request.to_dict()["effects"], NO_EFFECTS)
                self.assertEqual(request.to_dict()["schema_version"], 1)
                with self.assertRaises(FrozenInstanceError):
                    request.operation = ApiOperation.GET_STATUS  # type: ignore[misc]

    def test_mutations_require_idempotency_and_resource_versions(self) -> None:
        values = dict(
            operation="cancel_assessment",
            request_id="request.cancel",
            binding=self.binding(),
            issued_at="2026-09-20T12:00:00Z",
            body_size_bytes=20,
            budget=self.budget(),
            resource_id="assessment.001",
            expected_resource_version=2,
            reason_code="operator_request",
        )
        with self.assertRaisesRegex(ApiContractError, "idempotency"):
            ApiRequestEnvelope(**values)
        values["idempotency_key"] = "idem:cancel-assessment-0001"
        values.pop("expected_resource_version")
        with self.assertRaisesRegex(ApiContractError, "expected_resource_version"):
            ApiRequestEnvelope(**values)
        with self.assertRaisesRegex(ApiContractError, "must not carry"):
            ApiRequestEnvelope(
                operation="get_status",
                request_id="request.status",
                binding=self.binding(),
                issued_at="2026-09-20T12:00:00Z",
                body_size_bytes=0,
                budget=self.budget(),
                resource_id="assessment.001",
                idempotency_key="idem:read-operation-0001",
            )

    def test_request_body_reference_and_page_budgets_fail_closed(self) -> None:
        base = dict(
            operation="list_findings",
            request_id="request.findings",
            binding=self.binding(),
            issued_at="2026-09-20T12:00:00Z",
            resource_id="assessment.001",
            body_size_bytes=1,
            budget=RequestBudget(10, 1, 2, 10),
        )
        with self.assertRaisesRegex(ApiContractError, "page exceeds"):
            ApiRequestEnvelope(**base, page=PageRequest(3))
        with self.assertRaisesRegex(ApiContractError, "body exceeds"):
            ApiRequestEnvelope(**{**base, "body_size_bytes": 11}, page=PageRequest(2))
        with self.assertRaisesRegex(ApiContractError, "reference count"):
            ApiRequestEnvelope(
                operation="create_assessment",
                request_id="request.create",
                binding=self.binding(),
                issued_at="2026-09-20T12:00:00Z",
                body_size_bytes=1,
                budget=RequestBudget(10, 1, 2, 10),
                idempotency_key="idem:create-assessment-0001",
                content_references=(
                    self.resource("scope_admission", 1),
                    ResourceReference("scope_admission", "scoperef:two", DIGESTS[2], 1),
                ),
            )

    def test_success_error_taxonomy_and_pagination_are_unambiguous(self) -> None:
        request = self.request("list_findings")
        resources = (self.resource("finding", 1), self.resource("finding", 2))
        response = ApiResponseEnvelope(
            operation=request.operation,
            request_contract_id=request.request_contract_id,
            request_sha256=request.request_sha256,
            binding=request.binding,
            responded_at="2026-09-20T12:00:01Z",
            status="completed",
            resources=resources,
            page=PageResult(2, "cursor:ABCDEFGHIJKLMNOP"),
        )
        self.assertEqual(response, ApiResponseEnvelope.from_dict(response.to_dict()))
        self.assertEqual(response, ApiResponseEnvelope.from_json(response.to_json()))
        self.assertEqual(response, parse_contract(response.to_dict()))
        verify_api_exchange(request, response)
        rejected = ApiResponseEnvelope(
            operation="get_report",
            request_contract_id=request.request_contract_id,
            request_sha256=request.request_sha256,
            binding=request.binding,
            responded_at="2026-09-20T12:00:01Z",
            status="rejected",
            error=ApiError("not_found", "Resource was not found.", False),
        )
        self.assertEqual(rejected.error.code.value, "not_found")
        with self.assertRaisesRegex(ApiContractError, "does not match"):
            verify_api_exchange(self.request("get_report"), response)
        with self.assertRaisesRegex(ApiContractError, "returned_count"):
            ApiResponseEnvelope(
                operation=request.operation,
                request_contract_id=request.request_contract_id,
                request_sha256=request.request_sha256,
                binding=request.binding,
                responded_at="2026-09-20T12:00:01Z",
                status="completed",
                resources=resources,
                page=PageResult(1),
            )

    def test_empty_list_page_is_valid_but_non_list_success_still_needs_resource(self) -> None:
        request = self.request("list_findings")
        response = ApiResponseEnvelope(
            operation=request.operation,
            request_contract_id=request.request_contract_id,
            request_sha256=request.request_sha256,
            binding=request.binding,
            responded_at="2026-09-20T12:00:01Z",
            status="completed",
            resources=(),
            page=PageResult(0),
        )
        self.assertEqual(response, ApiResponseEnvelope.from_dict(response.to_dict()))
        verify_api_exchange(request, response)
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator(schema).validate(response.to_dict())
        non_list = self.request("get_status")
        with self.assertRaisesRegex(ApiContractError, "non-list success requires"):
            ApiResponseEnvelope(
                operation=non_list.operation,
                request_contract_id=non_list.request_contract_id,
                request_sha256=non_list.request_sha256,
                binding=non_list.binding,
                responded_at="2026-09-20T12:00:01Z",
                status="completed",
                resources=(),
            )

    def test_response_resource_count_matches_schema_limit(self) -> None:
        request = self.request("get_status")
        oversized = tuple(
            ResourceReference(
                "status", f"statusref:item-{index:04d}", DIGESTS[0], 1,
            )
            for index in range(1_001)
        )
        with self.assertRaisesRegex(ApiContractError, "schema limit"):
            ApiResponseEnvelope(
                operation=request.operation,
                request_contract_id=request.request_contract_id,
                request_sha256=request.request_sha256,
                binding=request.binding,
                responded_at="2026-09-20T12:00:01Z",
                status="completed",
                resources=oversized,
            )

    def test_exchange_replays_typed_source_integrity(self) -> None:
        request = self.request("get_status")
        response = ApiResponseEnvelope(
            operation=request.operation,
            request_contract_id=request.request_contract_id,
            request_sha256=request.request_sha256,
            binding=request.binding,
            responded_at="2026-09-20T12:00:01Z",
            status="completed",
            resources=(self.resource("status", 1),),
        )
        verify_api_exchange(request, response)
        object.__setattr__(response, "resources", (self.resource("status", 2),))
        with self.assertRaisesRegex(ApiContractError, "source integrity"):
            verify_api_exchange(request, response)
        response = ApiResponseEnvelope.from_dict(
            ApiResponseEnvelope(
                operation=request.operation,
                request_contract_id=request.request_contract_id,
                request_sha256=request.request_sha256,
                binding=request.binding,
                responded_at="2026-09-20T12:00:01Z",
                status="completed",
                resources=(self.resource("status", 1),),
            ).to_dict()
        )
        object.__setattr__(request, "resource_id", "assessment.changed")
        with self.assertRaisesRegex(ApiContractError, "source integrity"):
            verify_api_exchange(request, response)

    def test_api_parsers_reject_boolean_schema_versions(self) -> None:
        request = self.request("get_status")
        response = ApiResponseEnvelope(
            operation=request.operation,
            request_contract_id=request.request_contract_id,
            request_sha256=request.request_sha256,
            binding=request.binding,
            responded_at="2026-09-20T12:00:01Z",
            status="completed",
            resources=(self.resource("status", 1),),
        )
        for document, parser in (
            (request.to_dict(), ApiRequestEnvelope.from_dict),
            (response.to_dict(), ApiResponseEnvelope.from_dict),
        ):
            document["schema_version"] = True
            with self.assertRaisesRegex(ApiContractError, "version"):
                parser(document)

    def test_content_hashes_and_exact_field_parsers_reject_tampering(self) -> None:
        request = self.request("get_status")
        tampered = copy.deepcopy(request.to_dict())
        tampered["resource_id"] = "assessment.changed"
        with self.assertRaises(ApiContractError):
            ApiRequestEnvelope.from_dict(tampered)
        extra = copy.deepcopy(request.to_dict())
        extra["grant_authority"] = True
        with self.assertRaisesRegex(ApiContractError, "fields"):
            ApiRequestEnvelope.from_dict(extra)
        escalated = copy.deepcopy(request.to_dict())
        escalated["effects"]["execution"] = "allowed"
        with self.assertRaisesRegex(ApiContractError, "effect escalation"):
            ApiRequestEnvelope.from_dict(escalated)
        with self.assertRaisesRegex(ApiContractError, "not canonical"):
            ApiRequestEnvelope.from_json(json.dumps(request.to_dict(), indent=2))

    def test_subscription_uses_only_opaque_endpoint_and_secret_references(self) -> None:
        subscription = self.subscription()
        self.assertEqual(subscription, WebhookSubscription.from_dict(subscription.to_dict()))
        self.assertEqual(subscription, WebhookSubscription.from_json(subscription.to_json()))
        serialized = json.dumps(subscription.to_dict()).lower()
        self.assertNotIn("https://", serialized)
        self.assertNotIn("private_key", serialized)
        with self.assertRaisesRegex(ApiContractError, "endpoint_ref"):
            WebhookSubscription(
                subscription_id="subscription.bad",
                binding=self.binding(),
                endpoint_ref="https://receiver.example/webhook",
                signing_key_ref="secretref:webhooks.acme.key-1",
                event_filters=("finding.changed",),
                max_in_flight=1,
                created_at="2026-09-20T12:00:00Z",
                signature=self.signature(),
            )
        with self.assertRaisesRegex(ApiContractError, "secret reference"):
            self.signature("literal-key-material")

    def test_delivery_round_trip_retry_plan_and_dead_letter_invariants(self) -> None:
        delivery = self.delivery()
        self.assertEqual(delivery, WebhookDelivery.from_dict(delivery.to_dict()))
        self.assertEqual(delivery, WebhookDelivery.from_json(delivery.to_json()))
        self.assertEqual(delivery, parse_contract(delivery.to_dict()))
        terminal = self.delivery(state="dead_lettered", attempt=3)
        self.assertEqual(terminal.state.value, "dead_lettered")
        with self.assertRaisesRegex(ApiContractError, "terminal attempt"):
            self.delivery(state="dead_lettered", attempt=2)
        with self.assertRaisesRegex(ApiContractError, "strictly increase"):
            RetryPlan((30, 30), 3)
        with self.assertRaisesRegex(ApiContractError, "self-assert"):
            self.delivery(state="acknowledged")
        with self.assertRaisesRegex(ApiContractError, "resource kind"):
            WebhookDelivery(
                delivery_id="delivery.wrong-kind",
                subscription_id=self.subscription().subscription_id,
                subscription_sha256=self.subscription().subscription_sha256,
                sequence=1,
                nonce="nonce:BBBBBBBBBBBBBBBBBBBBBB",
                event_type="finding.changed",
                resource=self.resource("report", 1),
                occurred_at="2026-09-20T12:01:00Z",
                expires_at="2026-09-20T12:10:00Z",
                attempt=1,
                state="planned",
                retry_plan=RetryPlan((30, 120), 3),
                signature=self.signature(),
            )

    def test_replay_window_rejects_duplicates_gaps_filters_keys_and_expiry(self) -> None:
        subscription = self.subscription()
        window = ReplayWindow(subscription.subscription_id, 0)
        first = self.delivery()
        accepted = accept_webhook_delivery(
            subscription, first, window, received_at="2026-09-20T12:02:00Z"
        )
        self.assertEqual(accepted.last_sequence, 1)
        with self.assertRaisesRegex(ApiContractError, "sequence|replay"):
            accept_webhook_delivery(
                subscription, first, accepted, received_at="2026-09-20T12:02:00Z"
            )
        gap = self.delivery(
            sequence=3,
            delivery_id="delivery.003",
            nonce="nonce:CCCCCCCCCCCCCCCCCCCCCC",
        )
        with self.assertRaisesRegex(ApiContractError, "contiguous"):
            accept_webhook_delivery(subscription, gap, accepted, received_at="2026-09-20T12:02:00Z")
        filtered = self.delivery(event_type="status.changed")
        with self.assertRaisesRegex(ApiContractError, "not allowed"):
            accept_webhook_delivery(
                subscription, filtered, window, received_at="2026-09-20T12:02:00Z"
            )
        expired = self.delivery(expires_at="2026-09-20T12:01:30Z")
        with self.assertRaisesRegex(ApiContractError, "expired"):
            accept_webhook_delivery(
                subscription, expired, window, received_at="2026-09-20T12:02:00Z"
            )

    def test_acknowledgement_is_signed_and_bound_to_exact_delivery(self) -> None:
        subscription = self.subscription()
        delivery = self.delivery()
        acknowledgement = WebhookAcknowledgement(
            acknowledgement_id="ack.001",
            subscription_id=subscription.subscription_id,
            delivery_id=delivery.delivery_id,
            delivery_sha256=delivery.delivery_sha256,
            sequence=delivery.sequence,
            acknowledged_at="2026-09-20T12:02:00Z",
            signature=self.signature(),
        )
        verify_webhook_acknowledgement(subscription, delivery, acknowledgement)
        self.assertEqual(
            acknowledgement,
            WebhookAcknowledgement.from_dict(acknowledgement.to_dict()),
        )
        self.assertEqual(
            acknowledgement,
            WebhookAcknowledgement.from_json(acknowledgement.to_json()),
        )
        wrong = WebhookAcknowledgement(
            acknowledgement_id="ack.002",
            subscription_id=subscription.subscription_id,
            delivery_id="delivery.other",
            delivery_sha256=delivery.delivery_sha256,
            sequence=delivery.sequence,
            acknowledged_at="2026-09-20T12:02:00Z",
            signature=self.signature(),
        )
        with self.assertRaisesRegex(ApiContractError, "does not match"):
            verify_webhook_acknowledgement(subscription, delivery, wrong)

    def test_schema_validates_every_published_contract(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is unavailable")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        request = self.request("list_findings")
        response = ApiResponseEnvelope(
            operation="list_findings",
            request_contract_id=request.request_contract_id,
            request_sha256=request.request_sha256,
            binding=request.binding,
            responded_at="2026-09-20T12:00:01Z",
            status="completed",
            resources=(self.resource("finding", 1),),
            page=PageResult(1),
        )
        delivery = self.delivery()
        acknowledgement = WebhookAcknowledgement(
            "ack.001",
            self.subscription().subscription_id,
            delivery.delivery_id,
            delivery.delivery_sha256,
            delivery.sequence,
            "2026-09-20T12:02:00Z",
            self.signature(),
        )
        for contract in (
            request,
            response,
            self.subscription(),
            delivery,
            acknowledgement,
        ):
            with self.subTest(kind=contract.to_dict()["kind"]):
                validator.validate(contract.to_dict())

    def test_module_has_no_live_transport_surface(self) -> None:
        module_text = FILES[0].read_text(encoding="utf-8")
        for forbidden in (
            "import requests",
            "import socket",
            "import urllib",
            "httpx",
            "aiohttp",
            "listen(",
            "connect(",
        ):
            self.assertNotIn(forbidden, module_text)
        self.assertEqual(self.delivery().to_dict()["effects"], NO_EFFECTS)

    def test_source_files_have_no_dash_or_marker_fingerprints(self) -> None:
        markers = (
            "TO" + "DO",
            "FIX" + "ME",
            "T" + "BD",
            "X" + "XX",
            "PLACE" + "HOLDER",
            "generated " + "by",
            "chat" + "gpt",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, str(path))
            self.assertNotIn("\u2014", text, str(path))
            lower = text.lower()
            for marker in markers:
                self.assertNotIn(marker.lower(), lower, str(path))


if __name__ == "__main__":
    unittest.main()
