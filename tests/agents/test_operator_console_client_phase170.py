"""Phase 170 operator console client coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
from sunderkey.local_api_service import (
    AccessContext,
    ResourceKind,
    ResourceRecord,
    ResponseStatus,
    ServicePage,
    ServiceResponse,
    canonical_sha256,
)
from sunderkey.operator_console_client import (
    OperatorConsoleClient,
    OperatorConsoleClientError,
    OperatorConsoleInteractionReceipt,
    canonical_json,
    operator_console_client_manifest,
    parse_operator_console_receipt,
    render_empty_state,
    render_error_state,
    render_projection,
)
from sunderkey.operator_console_projection import (
    BlockerSummary,
    BudgetSnapshot,
    Counter,
    CoverageSnapshot,
    MissionProjectionInput,
    OperatorIntentKind,
    ViewRole,
    WorkerSummary,
    build_operator_console_projection,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "operator-console-client-receipt-v1.schema.json"
NOW = "2026-09-20T18:00:00Z"
DIGESTS = tuple("sha256:" + character * 64 for character in "012345")


class FakeTransport:
    def __init__(self, records: tuple[ResourceRecord, ...]) -> None:
        self.records = records
        self.requests = []
        self.rebind = False
        self.replayed = False
        self.mutation_effect = False
        self.next_cursor: str | None = None

    def send(self, request):
        self.requests.append(request)
        records = self.records
        if request.resource_id is not None:
            records = tuple(
                record for record in records if record.resource_id == request.resource_id
            )
            resource = records[0] if records else None
            page = None
        else:
            resource = None
            page = ServicePage(records, self.next_cursor)
        return ServiceResponse(
            request_id="request-rebound" if self.rebind else request.request_id,
            request_sha256=DIGESTS[5] if self.rebind else request.request_sha256,
            status=ResponseStatus.REPLAYED if self.replayed else ResponseStatus.COMPLETED,
            authorization_ref="authzref:console-read",
            authorization_audit_ref="auditref:console-read",
            resource=resource,
            page=page,
            mutation_audit_ref="auditref:mutation" if self.mutation_effect else None,
        )


class OperatorConsoleClientPhase170Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.access = AccessContext(
            tenant_id="tenant-a",
            context_id="context-red",
            principal_id="principal-operator",
            session_ref="session-verified",
        )

    @staticmethod
    def source(**changes: object) -> MissionProjectionInput:
        values: dict[str, object] = {
            "assessment_ref": "assessmentref:mission-001",
            "assessment_version": 4,
            "mission_state": "running",
            "observed_at": NOW,
            "scope_sha256": DIGESTS[0],
            "schedule_sha256": DIGESTS[1],
            "status_sha256": DIGESTS[2],
            "health": "degraded",
            "coverage": CoverageSnapshot(5, 2, 1, 1, 1),
            "budget": BudgetSnapshot(
                requests=Counter(10, 100),
                cost_units=Counter(5, 100),
                tokens=Counter(20, 1000),
                tool_calls=Counter(3, 40),
                worker_minutes=Counter(8, 120),
                storage_bytes=Counter(256, 10_000),
            ),
            "workers": (
                WorkerSummary(
                    "workerref:worker-01",
                    "AOE-GA-D01-S01",
                    "running",
                    "healthy",
                    "taskref:task-01",
                    NOW,
                ),
            ),
            "approvals": (),
            "blockers": (
                BlockerSummary(
                    "blocker.budget",
                    "budget_low",
                    "warning",
                    "Request budget requires review.",
                    "assessment_operator",
                ),
            ),
            "graph_changes": (),
            "finding_refs": (),
            "evidence_refs": (),
            "report_refs": (),
            "emergency_stop_recorded": False,
        }
        values.update(changes)
        return MissionProjectionInput(**values)

    def record(
        self,
        *,
        role: ViewRole = ViewRole.ASSESSMENT_OPERATOR,
        source: MissionProjectionInput | None = None,
        tenant_id: str = "tenant-a",
        context_id: str = "context-red",
    ) -> ResourceRecord:
        projection = build_operator_console_projection(source or self.source(), role)
        payload = projection.to_dict()
        payload_sha256 = canonical_sha256(payload)
        audit_refs = ("auditref:projection-read-model",)
        token = (
            "ct:"
            + canonical_sha256(
                {
                    "audit_refs": list(audit_refs),
                    "context_id": context_id,
                    "payload_sha256": payload_sha256,
                    "resource_id": projection.projection_id,
                    "resource_kind": ResourceKind.OPERATOR_PROJECTION.value,
                    "tenant_id": tenant_id,
                    "version": 1,
                }
            )[7:]
        )
        return ResourceRecord(
            resource_kind=ResourceKind.OPERATOR_PROJECTION,
            resource_id=projection.projection_id,
            tenant_id=tenant_id,
            context_id=context_id,
            version=1,
            concurrency_token=token,
            payload=payload,
            payload_sha256=payload_sha256,
            audit_refs=audit_refs,
            created_at=NOW,
            updated_at=NOW,
        )

    def client(self, records=(), role=ViewRole.ASSESSMENT_OPERATOR):
        transport = FakeTransport(tuple(records))
        return OperatorConsoleClient(transport, self.access, role), transport

    def test_list_and_get_are_tenant_context_bound_read_requests(self) -> None:
        record = self.record()
        client, transport = self.client((record,))
        listed = client.list_projections(
            request_id="request-list-001", requested_at=NOW, page_size=10
        )
        self.assertEqual(listed.projections[0].projection_id, record.resource_id)
        self.assertEqual(listed.receipt.operation.value, "list_resources")
        request = transport.requests[0]
        self.assertEqual(request.resource_kind, ResourceKind.OPERATOR_PROJECTION)
        self.assertEqual(request.access.tenant_id, "tenant-a")
        self.assertFalse(request.is_mutation)

        get_client, _ = self.client((record,))
        fetched = get_client.get_projection(
            resource_id=record.resource_id,
            request_id="request-get-001",
            requested_at=NOW,
        )
        self.assertEqual(fetched.projections, listed.projections)
        self.assertEqual(fetched.receipt.operation.value, "get_resource")

    def test_stable_pagination_and_empty_state_are_explicit(self) -> None:
        first = self.record(source=self.source())
        second = self.record(
            source=self.source(
                assessment_ref="assessmentref:mission-002",
                assessment_version=2,
                status_sha256=DIGESTS[3],
            )
        )
        ordered = tuple(sorted((first, second), key=lambda item: item.resource_id))
        client, transport = self.client(ordered)
        transport.next_cursor = "cursor:page-001." + "a" * 64
        page = client.list_projections(request_id="request-page-001", requested_at=NOW, page_size=2)
        self.assertEqual(page.next_cursor, transport.next_cursor)
        self.assertEqual(
            [item.resource_id for item in page.receipt.items],
            sorted((first.resource_id, second.resource_id)),
        )

        empty_client, _ = self.client(())
        empty = empty_client.list_projections(
            request_id="request-empty-001", requested_at=NOW, page_size=10
        )
        self.assertEqual(empty.projections, ())
        self.assertIn("Status: EMPTY", render_empty_state(ViewRole.ASSESSMENT_OPERATOR))
        self.assertEqual(empty.receipt.view_role, ViewRole.ASSESSMENT_OPERATOR)

        unordered_client, _ = self.client(tuple(reversed(ordered)))
        with self.assertRaisesRegex(OperatorConsoleClientError, "stable and unique"):
            unordered_client.list_projections(
                request_id="request-unordered-001", requested_at=NOW, page_size=2
            )

        oversized_client, _ = self.client(ordered)
        with self.assertRaisesRegex(OperatorConsoleClientError, "page size"):
            oversized_client.list_projections(
                request_id="request-oversized-001", requested_at=NOW, page_size=1
            )

        cursor_client, cursor_transport = self.client(())
        cursor_transport.next_cursor = "cursor:invalid-empty." + "b" * 64
        with self.assertRaisesRegex(OperatorConsoleClientError, "empty response"):
            cursor_client.list_projections(
                request_id="request-empty-cursor-001", requested_at=NOW, page_size=10
            )

    def test_response_request_rebinding_replay_and_effects_fail_closed(self) -> None:
        record = self.record()
        client, transport = self.client((record,))
        transport.rebind = True
        with self.assertRaisesRegex(OperatorConsoleClientError, "not bound"):
            client.list_projections(
                request_id="request-rebound-001", requested_at=NOW, page_size=10
            )

        replay_client, replay_transport = self.client((record,))
        replay_transport.replayed = True
        with self.assertRaisesRegex(OperatorConsoleClientError, "newly completed"):
            replay_client.list_projections(
                request_id="request-replay-001", requested_at=NOW, page_size=10
            )

        effect_client, effect_transport = self.client((record,))
        effect_transport.mutation_effect = True
        with self.assertRaisesRegex(OperatorConsoleClientError, "mutation effect"):
            effect_client.list_projections(
                request_id="request-effect-001", requested_at=NOW, page_size=10
            )

    def test_request_ids_are_one_use_even_when_transport_fails(self) -> None:
        record = self.record()
        client, transport = self.client((record,))
        transport.rebind = True
        with self.assertRaises(OperatorConsoleClientError):
            client.list_projections(
                request_id="request-one-use-001", requested_at=NOW, page_size=10
            )
        transport.rebind = False
        with self.assertRaisesRegex(OperatorConsoleClientError, "already consumed"):
            client.list_projections(
                request_id="request-one-use-001", requested_at=NOW, page_size=10
            )

    def test_cross_tenant_context_role_and_resource_rebinding_fail_closed(self) -> None:
        for changes, pattern in (
            ({"tenant_id": "tenant-other"}, "outside"),
            ({"context_id": "context-other"}, "outside"),
        ):
            with self.subTest(changes=changes):
                record = self.record(**changes)
                client, _ = self.client((record,))
                with self.assertRaisesRegex(OperatorConsoleClientError, pattern):
                    client.list_projections(
                        request_id=f"request-{next(iter(changes))}",
                        requested_at=NOW,
                        page_size=10,
                    )

        role_record = self.record(role=ViewRole.EXECUTIVE_OBSERVER)
        role_client, _ = self.client((role_record,))
        with self.assertRaisesRegex(OperatorConsoleClientError, "role"):
            role_client.list_projections(
                request_id="request-role-001", requested_at=NOW, page_size=10
            )

        rebound = copy.copy(self.record())
        object.__setattr__(rebound, "resource_id", "OCP-" + "F" * 32)
        rebound_client, _ = self.client((rebound,))
        with self.assertRaisesRegex(OperatorConsoleClientError, "identity"):
            rebound_client.list_projections(
                request_id="request-resource-001", requested_at=NOW, page_size=10
            )

    def test_get_rejects_another_valid_projection_before_acceptance(self) -> None:
        wanted = self.record()
        other = self.record(source=self.source(assessment_ref="assessmentref:mission-002"))
        client, transport = self.client((wanted,))
        valid = client.get_projection(
            resource_id=wanted.resource_id, request_id="request-wanted", requested_at=NOW
        )
        self.assertEqual(valid.projections[0].projection_id, wanted.resource_id)

        def wrong_response(request):
            return ServiceResponse(
                request_id=request.request_id,
                request_sha256=request.request_sha256,
                status=ResponseStatus.COMPLETED,
                authorization_ref="authzref:console-read",
                authorization_audit_ref="auditref:console-read",
                resource=other,
            )

        with (
            mock.patch.object(transport, "send", side_effect=wrong_response),
            self.assertRaisesRegex(OperatorConsoleClientError, "requested resource"),
        ):
            client.get_projection(
                resource_id=wanted.resource_id,
                request_id="request-rebound-resource",
                requested_at=NOW,
            )
        self.assertNotIn(
            (other.resource_id, other.payload["projection_sha256"]), client._accepted_projections
        )

    def test_malformed_and_unsafe_projection_payloads_fail_closed(self) -> None:
        record = self.record()
        malformed_payload = dict(record.payload)
        malformed_payload.pop("projection_sha256")
        malformed = copy.copy(record)
        object.__setattr__(malformed, "payload", malformed_payload)
        object.__setattr__(malformed, "payload_sha256", canonical_sha256(malformed_payload))
        malformed_client, _ = self.client((malformed,))
        with self.assertRaisesRegex(OperatorConsoleClientError, "payload"):
            malformed_client.list_projections(
                request_id="request-malformed-001", requested_at=NOW, page_size=10
            )

        unsafe_source = self.source(
            blockers=(
                BlockerSummary(
                    "blocker.unsafe",
                    "unsafe_text",
                    "warning",
                    "Unsafe unicode caf" + chr(233) + " display text.",
                    "assessment_operator",
                ),
            )
        )
        unsafe_record = self.record(source=unsafe_source)
        unsafe_client, _ = self.client((unsafe_record,))
        with self.assertRaisesRegex(OperatorConsoleClientError, "printable ASCII"):
            unsafe_client.list_projections(
                request_id="request-unsafe-001", requested_at=NOW, page_size=10
            )

    def test_intent_preparation_is_no_effect_and_only_when_advertised(self) -> None:
        record = self.record()
        client, _ = self.client((record,))
        result = client.list_projections(
            request_id="request-intent-001", requested_at=NOW, page_size=10
        )
        intent = client.prepare_intent(
            result.projections[0],
            intent_kind=OperatorIntentKind.REQUEST_PAUSE,
            requested_at=NOW,
            idempotency_key="idem:console-intent-00000001",
            rationale="Operator requests a controlled review pause.",
        )
        self.assertEqual(intent.effect, "none")
        self.assertEqual(intent.authorization_status, "external_required")

        with self.assertRaisesRegex(OperatorConsoleClientError, "does not advertise"):
            client.prepare_intent(
                result.projections[0],
                intent_kind=OperatorIntentKind.REQUEST_RESUME,
                requested_at=NOW,
                idempotency_key="idem:console-intent-00000002",
                rationale="This intent is not offered for a running mission.",
            )

        other_client, _ = self.client((record,))
        with self.assertRaisesRegex(OperatorConsoleClientError, "not accepted"):
            other_client.prepare_intent(
                result.projections[0],
                intent_kind=OperatorIntentKind.REQUEST_PAUSE,
                requested_at=NOW,
                idempotency_key="idem:console-intent-00000003",
                rationale="Unbound projection must fail closed.",
            )

    def test_plain_text_rendering_has_hierarchy_labels_and_meaningful_states(self) -> None:
        record = self.record()
        client, _ = self.client((record,))
        result = client.list_projections(
            request_id="request-render-001", requested_at=NOW, page_size=10
        )
        first = render_projection(result.projections[0])
        second = render_projection(result.projections[0])
        self.assertEqual(first, second)
        self.assertIn("State: RUNNING", first)
        self.assertIn("Health: DEGRADED", first)
        self.assertIn("Attention [1]", first)
        self.assertIn("WARNING budget_low", first)
        self.assertIn("External approval required", first)
        self.assertNotIn("\x1b", first)

        error = OperatorConsoleClientError("response_invalid", "untrusted detail")
        rendered_error = render_error_state(error)
        self.assertIn("Status: ERROR", rendered_error)
        self.assertIn("Code: response_invalid", rendered_error)
        self.assertNotIn("untrusted detail", rendered_error)

    def test_receipt_is_content_addressed_strict_and_schema_valid(self) -> None:
        record = self.record()
        client, _ = self.client((record,))
        result = client.list_projections(
            request_id="request-receipt-001", requested_at=NOW, page_size=10
        )
        document = result.receipt.document
        parsed = parse_operator_console_receipt(document)
        self.assertIsInstance(parsed, OperatorConsoleInteractionReceipt)
        self.assertEqual(parsed, result.receipt)

        tampered = json.loads(document)
        tampered["items"][0]["assessment_version"] = 99
        with self.assertRaisesRegex(OperatorConsoleClientError, "identity"):
            parse_operator_console_receipt(canonical_json(tampered))
        with self.assertRaisesRegex(OperatorConsoleClientError, "not canonical"):
            parse_operator_console_receipt(json.dumps(result.receipt.to_dict()))

        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(result.receipt.to_dict())
            unexpected = copy.deepcopy(result.receipt.to_dict())
            unexpected["unexpected"] = True
            self.assertTrue(list(Draft202012Validator(schema).iter_errors(unexpected)))

    def test_manifest_is_honest_about_boundaries(self) -> None:
        manifest = operator_console_client_manifest()
        self.assertEqual(manifest["work_queue_id"], "WQ-008")
        self.assertEqual(manifest["effects"]["network"], "none_by_client")
        self.assertEqual(manifest["effects"]["intent_publication"], "none")
        self.assertEqual(manifest["operations"], ["get_resource", "list_resources"])

    def test_public_package_exports_operator_client_boundary(self) -> None:
        self.assertIs(sunderkey.OperatorConsoleClient, OperatorConsoleClient)
        self.assertIs(
            sunderkey.parse_operator_console_receipt,
            parse_operator_console_receipt,
        )
        self.assertIs(
            sunderkey.render_operator_console_projection,
            render_projection,
        )


if __name__ == "__main__":
    unittest.main()
