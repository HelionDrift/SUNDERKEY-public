"""Phase 169 durable integration delivery worker coverage."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.api_service_contracts import (
    DetachedSignature,
    TenantPrincipalBinding,
    WebhookEventType,
    WebhookSubscription,
)
from sunderkey.enterprise_connector_contracts import (
    ConnectorBinding,
    ConnectorTransportResponse,
    RouteParameter,
)
from sunderkey.integration_delivery_worker import (
    DELIVERY_SEMANTIC,
    NO_BUILTIN_NETWORK,
    IntegrationDeliveryWorker,
    IntegrationDeliveryWorkerError,
    RouteKind,
    WebhookDeliveryRequest,
    WorkerOutcome,
    WorkerPolicy,
    WorkerRoute,
    parse_contract,
)
from sunderkey.integration_outbox import (
    DestinationKind,
    DigestReference,
    EventType,
    IntegrationOutbox,
    ObservationStatus,
    OpaqueLinkReference,
    RetryPolicy,
    Severity,
    create_delivery_observation,
    create_destination,
    create_integration_event,
    sign_delivery_observation,
    sign_integration_event,
    verify_integration_event,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "integration-delivery-worker-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "integration_delivery_worker.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "integration-delivery-worker.md",
)
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64


class TestAccessController:
    __test__ = False

    def protect_directory(self, path: Path) -> None:
        pass

    def verify_directory(self, path: Path) -> None:
        if not path.is_dir():
            raise ValueError("directory custody failed")

    def protect_file(self, path: Path) -> None:
        pass

    def verify_file(self, path: Path) -> None:
        if not path.is_file():
            raise ValueError("file custody failed")

    def sync_directory(self, path: Path) -> None:
        pass


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 20, 12, 2, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def text(self) -> str:
        return self.value.isoformat().replace("+00:00", "Z")

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class FakeTransport:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key
        self.responses: list[ConnectorTransportResponse] = []
        self.connector_calls: list[tuple[str, str, object]] = []
        self.webhook_calls: list[tuple[str, str, WebhookDeliveryRequest]] = []
        self.observations: list[object] = []
        self.tamper_attempt = False
        self.tamper_signature = False
        self.tamper_signer = False
        self.raise_on_send = False

    def queue(self, *responses: ConnectorTransportResponse) -> None:
        self.responses.extend(responses)

    def _response(self) -> ConnectorTransportResponse:
        if self.raise_on_send:
            raise RuntimeError("transport unavailable")
        return self.responses.pop(0)

    def send(self, *, endpoint_ref: str, credential_ref: str, request):
        self.connector_calls.append((endpoint_ref, credential_ref, request))
        return self._response()

    def send_webhook(self, *, endpoint_ref: str, signing_key_ref: str, request):
        self.webhook_calls.append((endpoint_ref, signing_key_ref, request))
        return self._response()

    def acknowledge(
        self,
        *,
        event,
        destination,
        idempotency_key: str,
        attempt_number: int,
        transport_observation,
    ):
        self.observations.append(transport_observation)
        disposition = transport_observation.disposition.value
        status = ObservationStatus(disposition)
        error_code = None if status is ObservationStatus.SUCCEEDED else "delivery_failed"
        observation = create_delivery_observation(
            event=event,
            destination=destination,
            idempotency_key=idempotency_key,
            attempt_number=attempt_number + (1 if self.tamper_attempt else 0),
            adapter_id="adapter.delivery",
            status=status,
            observed_at=transport_observation.observed_at,
            remote_receipt_ref=(
                transport_observation.external_resource_ref
                if status is ObservationStatus.SUCCEEDED
                else None
            ),
            error_code=error_code,
        )
        signed = sign_delivery_observation(
            observation,
            signer_key_id="adapter-key.other" if self.tamper_signer else "adapter-key.1",
            private_key=self.private_key,
        )
        if self.tamper_signature:
            replacement = "A" if signed.signature[0] != "A" else "B"
            signed = replace(signed, signature=replacement + signed.signature[1:])
        return signed


class IntegrationDeliveryWorkerPhase169Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.clock = MutableClock()
        self.event_private = Ed25519PrivateKey.generate()
        self.adapter_private = Ed25519PrivateKey.generate()
        self.store = IntegrationOutbox(
            Path(self.temporary.name) / "outbox",
            TestAccessController(),
            clock=self.clock,
            retry_policy=RetryPolicy(
                max_attempts=3,
                base_delay_seconds=5,
                max_delay_seconds=20,
            ),
        )
        self.store.initialize()
        self.transport = FakeTransport(self.adapter_private)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def event(self, aggregate_id: str = "finding.001"):
        event = create_integration_event(
            event_type=EventType.FINDING,
            occurred_at=self.clock.text(),
            producer_id="sunderkey.control-plane",
            aggregate_id=aggregate_id,
            subject_ids={"finding_id": aggregate_id},
            previous_state="candidate",
            state="confirmed",
            severity=Severity.HIGH,
            digest_references=(DigestReference("report:summary:001", ONE),),
            summary="Validated finding state changed after policy review.",
            link_references=(OpaqueLinkReference("details", "portal:finding:001"),),
        )
        signed = sign_integration_event(
            event,
            signer_key_id="producer-key.1",
            private_key=self.event_private,
        )
        return verify_integration_event(signed, self.event_private.public_key())

    def subscription(self, *, tenant_id: str = "acme") -> WebhookSubscription:
        return WebhookSubscription(
            subscription_id="subscription.webhook.1",
            binding=TenantPrincipalBinding(
                tenant_id=tenant_id,
                principal_id="principal.integration-worker",
                principal_role="integration_operator",
                authentication_context_ref="auth.context.1",
            ),
            endpoint_ref="endpointref:webhooks.acme.primary",
            signing_key_ref="secretref:webhooks.acme.key-1",
            event_filters=(WebhookEventType.FINDING_CHANGED,),
            max_in_flight=10,
            created_at="2026-09-20T12:00:00Z",
            signature=DetachedSignature(
                key_ref="secretref:webhooks.acme.key-1",
                algorithm="ed25519",
                signature="A" * 43,
            ),
        )

    def webhook_route(self, destination) -> WorkerRoute:
        return WorkerRoute(
            tenant_ref="tenantref:acme",
            destination_id=destination.destination_id,
            destination_sha256=destination.destination_sha256,
            route_kind=RouteKind.WEBHOOK,
            adapter_id="adapter.delivery",
            acknowledgement_signer_key_id="adapter-key.1",
            acknowledgement_public_key=self.adapter_private.public_key(),
            webhook_subscription=self.subscription(),
        )

    def connector_binding(self, destination) -> ConnectorBinding:
        return ConnectorBinding(
            tenant_ref="tenantref:acme",
            destination_ref=f"integrationdestination:{destination.destination_id}",
            connector_kind="jira_cloud",
            operation="jira_create_issue",
            endpoint_ref="endpointref:jira.primary",
            credential_ref="credentialref:jira.primary",
            api_version="3",
            route_parameters=(
                RouteParameter("project_ref", "projectref:security"),
                RouteParameter("issue_type_ref", "issuetyperef:vulnerability"),
            ),
            enabled_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T13:00:00Z",
        )

    def connector_route(self, destination, binding=None) -> WorkerRoute:
        return WorkerRoute(
            tenant_ref="tenantref:acme",
            destination_id=destination.destination_id,
            destination_sha256=destination.destination_sha256,
            route_kind=RouteKind.ENTERPRISE_CONNECTOR,
            adapter_id="adapter.delivery",
            acknowledgement_signer_key_id="adapter-key.1",
            acknowledgement_public_key=self.adapter_private.public_key(),
            connector_binding=binding or self.connector_binding(destination),
        )

    def worker(self, *routes: WorkerRoute, policy: WorkerPolicy | None = None):
        return IntegrationDeliveryWorker(
            outbox=self.store,
            worker_id="worker.delivery.1",
            tenant_ref="tenantref:acme",
            routes=tuple(routes),
            event_public_keys={"producer-key.1": self.event_private.public_key()},
            transport=self.transport,
            policy=policy or WorkerPolicy(lease_seconds=30, claim_limit=10, request_ttl_seconds=20),
        )

    def enqueue_webhook(self, aggregate_id: str = "finding.001"):
        destination = create_destination(
            destination_id=f"destination.webhook.{aggregate_id}",
            kind=DestinationKind.GENERIC_WEBHOOK,
            route={"endpoint_ref": "routing:webhook:primary"},
        )
        record = self.store.enqueue(self.event(aggregate_id), destination)
        return destination, record

    def enqueue_connector(self):
        destination = create_destination(
            destination_id="destination.jira.primary",
            kind=DestinationKind.JIRA_TICKET,
            route={
                "project_ref": "routing:ticket:project",
                "issue_type_ref": "routing:ticket:type",
            },
        )
        record = self.store.enqueue(self.event(), destination)
        return destination, record

    def test_webhook_success_is_fenced_content_addressed_and_at_least_once(self) -> None:
        destination, record = self.enqueue_webhook()
        self.transport.queue(
            ConnectorTransportResponse(202, ONE, external_resource_ref="receiptref:webhook-001")
        )
        receipts = self.worker(self.webhook_route(destination)).run_once(
            observed_at=self.clock.text()
        )
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual(receipt.outcome, WorkerOutcome.SUCCEEDED)
        self.assertEqual(receipt.delivery_semantic, DELIVERY_SEMANTIC)
        self.assertFalse(receipt.exactly_once_claimed)
        self.assertEqual(receipt.outbox_state, "delivered")
        self.assertEqual(self.store.get(record.outbox_id).state, "delivered")
        self.assertEqual(self.store.receipt_count(record.outbox_id), 1)
        self.assertEqual(parse_contract(json.dumps(receipt.to_dict())), receipt)
        self.assertEqual(self.transport.webhook_calls[0][0], "endpointref:webhooks.acme.primary")

    def test_enterprise_connector_uses_opaque_endpoint_and_credential_references(self) -> None:
        destination, _ = self.enqueue_connector()
        binding = self.connector_binding(destination)
        self.transport.queue(
            ConnectorTransportResponse(201, ONE, external_resource_ref="ticketref:SEC-42")
        )
        receipt = self.worker(self.connector_route(destination, binding)).run_once(
            observed_at=self.clock.text()
        )[0]
        self.assertEqual(receipt.binding_id, binding.binding_id)
        self.assertEqual(receipt.binding_sha256, binding.binding_sha256)
        endpoint, credential, request = self.transport.connector_calls[0]
        self.assertEqual((endpoint, credential), (binding.endpoint_ref, binding.credential_ref))
        self.assertNotIn(credential, request.body_json)
        self.assertEqual(receipt.remote_receipt_ref, "ticketref:SEC-42")

    def test_retry_backoff_preserves_idempotency_and_later_succeeds(self) -> None:
        destination, record = self.enqueue_webhook()
        self.transport.queue(
            ConnectorTransportResponse(503, ZERO),
            ConnectorTransportResponse(202, ONE, external_resource_ref="receiptref:webhook-002"),
        )
        worker = self.worker(self.webhook_route(destination))
        first = worker.run_once(observed_at=self.clock.text())[0]
        self.assertEqual(first.outcome, WorkerOutcome.RETRY_SCHEDULED)
        self.assertEqual(first.next_attempt_at, "2026-09-20T12:02:05Z")
        self.assertEqual(worker.run_once(observed_at=self.clock.text()), ())
        self.clock.advance(5)
        second = worker.run_once(observed_at=self.clock.text())[0]
        self.assertEqual(second.outcome, WorkerOutcome.SUCCEEDED)
        requests = [call[2] for call in self.transport.webhook_calls]
        self.assertEqual(requests[0].idempotency_key, requests[1].idempotency_key)
        self.assertEqual(requests[0].idempotency_key, record.idempotency_key)
        self.assertNotEqual(requests[0].request_id, requests[1].request_id)
        self.assertEqual(self.store.receipt_count(record.outbox_id), 2)

    def test_retry_budget_exhaustion_publishes_dead_letter_observation(self) -> None:
        destination, record = self.enqueue_webhook()
        self.transport.queue(*(ConnectorTransportResponse(503, ZERO) for _ in range(3)))
        worker = self.worker(self.webhook_route(destination))
        receipts = []
        for delay in (0, 5, 10):
            self.clock.advance(delay)
            receipts.extend(worker.run_once(observed_at=self.clock.text()))
        terminal = receipts[-1]
        self.assertEqual(terminal.outcome, WorkerOutcome.DEAD_LETTER)
        self.assertEqual(terminal.outbox_state, "dead_letter")
        self.assertEqual(terminal.attempt_number, terminal.max_attempts)
        self.assertEqual(self.store.get(record.outbox_id).state, "dead_letter")

    def test_permanent_failure_dead_letters_without_retry(self) -> None:
        destination, record = self.enqueue_webhook()
        self.transport.queue(ConnectorTransportResponse(400, ZERO))
        receipt = self.worker(self.webhook_route(destination)).run_once(
            observed_at=self.clock.text()
        )[0]
        self.assertEqual(receipt.disposition.value, "permanent_failure")
        self.assertEqual(receipt.outcome, WorkerOutcome.DEAD_LETTER)
        self.assertEqual(self.store.receipt_count(record.outbox_id), 1)

    def test_tenant_destination_and_in_flight_substitutions_are_rejected(self) -> None:
        destination, _ = self.enqueue_webhook()
        with self.assertRaises(IntegrationDeliveryWorkerError):
            WorkerRoute(
                tenant_ref="tenantref:other",
                destination_id=destination.destination_id,
                destination_sha256=destination.destination_sha256,
                route_kind="webhook",
                adapter_id="adapter.delivery",
                acknowledgement_signer_key_id="adapter-key.1",
                acknowledgement_public_key=self.adapter_private.public_key(),
                webhook_subscription=self.subscription(),
            )
        with self.assertRaises(IntegrationDeliveryWorkerError):
            self.worker(
                self.webhook_route(destination),
                policy=WorkerPolicy(lease_seconds=30, claim_limit=11, request_ttl_seconds=20),
            )
        changed = copy.copy(destination)
        object.__setattr__(changed, "destination_sha256", ZERO)
        with self.assertRaises(IntegrationDeliveryWorkerError):
            self.worker(self.webhook_route(changed)).run_once(observed_at=self.clock.text())
        self.assertEqual(self.transport.webhook_calls, [])

    def test_acknowledgement_attempt_and_signer_substitution_are_rejected(self) -> None:
        for attribute in ("tamper_attempt", "tamper_signature", "tamper_signer"):
            with self.subTest(attribute=attribute):
                self.tearDown()
                self.setUp()
                destination, record = self.enqueue_webhook()
                self.transport.queue(ConnectorTransportResponse(503, ZERO))
                setattr(self.transport, attribute, True)
                with self.assertRaises(IntegrationDeliveryWorkerError):
                    self.worker(self.webhook_route(destination)).run_once(
                        observed_at=self.clock.text()
                    )
                self.assertEqual(self.store.get(record.outbox_id).state, "leased")
                self.assertEqual(self.store.receipt_count(record.outbox_id), 0)

    def test_route_family_must_match_the_claimed_destination(self) -> None:
        destination, record = self.enqueue_connector()
        with self.assertRaisesRegex(IntegrationDeliveryWorkerError, "route kind"):
            self.worker(self.webhook_route(destination)).run_once(observed_at=self.clock.text())
        self.assertEqual(self.store.get(record.outbox_id).state, "leased")
        self.assertEqual(self.transport.webhook_calls, [])

    def test_expired_binding_stops_before_claim_or_transport(self) -> None:
        destination, record = self.enqueue_connector()
        binding = self.connector_binding(destination)
        expired = ConnectorBinding(
            tenant_ref=binding.tenant_ref,
            destination_ref=binding.destination_ref,
            connector_kind=binding.connector_kind,
            operation=binding.operation,
            endpoint_ref=binding.endpoint_ref,
            credential_ref=binding.credential_ref,
            api_version=binding.api_version,
            route_parameters=binding.route_parameters,
            enabled_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T12:00:00Z",
        )
        with self.assertRaisesRegex(IntegrationDeliveryWorkerError, "not active"):
            self.worker(self.connector_route(destination, expired)).run_once(
                observed_at=self.clock.text()
            )
        self.assertEqual(self.store.get(record.outbox_id).state, "pending")
        self.assertEqual(self.transport.connector_calls, [])

    def test_transport_exception_leaves_lease_for_fenced_redelivery(self) -> None:
        destination, record = self.enqueue_webhook()
        worker = self.worker(
            self.webhook_route(destination),
            policy=WorkerPolicy(lease_seconds=10, claim_limit=10, request_ttl_seconds=5),
        )
        self.transport.raise_on_send = True
        with self.assertRaises(RuntimeError):
            worker.run_once(observed_at=self.clock.text())
        self.assertEqual(self.store.get(record.outbox_id).state, "leased")
        self.clock.advance(10)
        self.transport.raise_on_send = False
        self.transport.queue(
            ConnectorTransportResponse(202, ONE, external_resource_ref="receiptref:redelivery")
        )
        receipt = worker.run_once(observed_at=self.clock.text())[0]
        self.assertEqual(receipt.attempt_number, 2)
        self.assertEqual(receipt.outcome, WorkerOutcome.SUCCEEDED)

    def test_claim_batch_is_in_sequence_order(self) -> None:
        first_destination, first = self.enqueue_webhook("finding.001")
        second_destination, second = self.enqueue_webhook("finding.002")
        self.transport.queue(
            ConnectorTransportResponse(202, ONE, external_resource_ref="receiptref:first"),
            ConnectorTransportResponse(202, ONE, external_resource_ref="receiptref:second"),
        )
        receipts = self.worker(
            self.webhook_route(first_destination),
            self.webhook_route(second_destination),
        ).run_once(observed_at=self.clock.text())
        self.assertEqual([item.sequence_number for item in receipts], [1, 2])
        self.assertEqual([item.outbox_id for item in receipts], [first.outbox_id, second.outbox_id])

    def test_contract_parser_rejects_extra_fields_and_content_tampering(self) -> None:
        destination, _ = self.enqueue_webhook()
        self.transport.queue(
            ConnectorTransportResponse(202, ONE, external_resource_ref="receiptref:webhook-003")
        )
        receipt = self.worker(self.webhook_route(destination)).run_once(
            observed_at=self.clock.text()
        )[0]
        request = self.transport.webhook_calls[0][2]
        self.assertEqual(parse_contract(request.to_dict()), request)
        for document, field in (
            (request.to_dict(), "request_sha256"),
            (receipt.to_dict(), "receipt_sha256"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(document)
                changed[field] = ZERO
                with self.assertRaises(IntegrationDeliveryWorkerError):
                    parse_contract(changed)
                extra = copy.deepcopy(document)
                extra["unexpected"] = True
                with self.assertRaises(IntegrationDeliveryWorkerError):
                    parse_contract(extra)

    def test_draft_2020_12_schema_accepts_request_and_receipt(self) -> None:
        destination, _ = self.enqueue_webhook()
        self.transport.queue(
            ConnectorTransportResponse(202, ONE, external_resource_ref="receiptref:webhook-004")
        )
        receipt = self.worker(self.webhook_route(destination)).run_once(
            observed_at=self.clock.text()
        )[0]
        request = self.transport.webhook_calls[0][2]
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        for document in (request.to_dict(), receipt.to_dict()):
            self.assertEqual(list(validator.iter_errors(document)), [])

    def test_worker_module_has_no_network_or_direct_filesystem_capability(self) -> None:
        source = FILES[0].read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(NO_BUILTIN_NETWORK)
        forbidden = {"socket", "requests", "httpx", "urllib", "pathlib", "os"}
        self.assertTrue(forbidden.isdisjoint(imports))

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

    def test_public_package_exports_delivery_worker_boundary(self) -> None:
        self.assertIs(sunderkey.IntegrationDeliveryWorker, IntegrationDeliveryWorker)
        self.assertIs(
            sunderkey.parse_integration_delivery_worker_contract,
            parse_contract,
        )
        self.assertEqual(sunderkey.INTEGRATION_DELIVERY_SEMANTIC, DELIVERY_SEMANTIC)


if __name__ == "__main__":
    unittest.main()
