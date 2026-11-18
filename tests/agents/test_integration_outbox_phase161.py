"""Phase 161 signed integration event and durable outbox tests."""

from __future__ import annotations

import ast
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from sunderkey.integration_outbox import (
    DATABASE_FILENAME,
    DeliveryObservation,
    DestinationKind,
    DigestReference,
    EventType,
    IntegrationConflictError,
    IntegrationOutbox,
    IntegrationValidationError,
    ObservationStatus,
    OpaqueLinkReference,
    RetryPolicy,
    Severity,
    SignedDeliveryObservation,
    create_delivery_observation,
    create_destination,
    create_integration_event,
    deliver_with_adapter,
    sign_delivery_observation,
    sign_integration_event,
    verify_delivery_observation,
    verify_integration_event,
)

ROOT = Path(__file__).resolve().parents[2]


class TestAccessController:
    """Host-neutral custody controller for store behavior tests."""

    __test__ = False

    def __init__(self) -> None:
        self.directories: list[Path] = []
        self.files: list[Path] = []
        self.syncs: list[Path] = []
        self.fail = False

    def protect_directory(self, path: Path) -> None:
        self.directories.append(path)

    def verify_directory(self, path: Path) -> None:
        if self.fail or path.is_symlink() or not path.is_dir():
            raise ValueError("directory custody failed")

    def protect_file(self, path: Path) -> None:
        self.files.append(path)

    def verify_file(self, path: Path) -> None:
        if self.fail or path.is_symlink() or not path.is_file():
            raise ValueError("file custody failed")

    def sync_directory(self, path: Path) -> None:
        self.syncs.append(path)


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 19, 18, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class IntegrationOutboxPhase161Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "integration-custody"
        self.access = TestAccessController()
        self.clock = MutableClock()
        self.event_private = Ed25519PrivateKey.generate()
        self.adapter_private = Ed25519PrivateKey.generate()
        self.policy = RetryPolicy(max_attempts=3, base_delay_seconds=5, max_delay_seconds=20)
        self.store = IntegrationOutbox(
            self.directory,
            self.access,
            clock=self.clock,
            retry_policy=self.policy,
        )
        self.store.initialize()
        self.destination = create_destination(
            destination_id="destination.primary",
            kind=DestinationKind.GENERIC_WEBHOOK,
            route={"endpoint_ref": "routing:webhook:primary"},
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def event(
        self,
        *,
        aggregate_id: str = "finding.001",
        state: str = "confirmed",
        occurred_at: str | None = None,
        event_type: EventType = EventType.FINDING,
    ):
        event = create_integration_event(
            event_type=event_type,
            occurred_at=occurred_at or self.clock().isoformat().replace("+00:00", "Z"),
            producer_id="sunderkey.control-plane",
            aggregate_id=aggregate_id,
            subject_ids={"finding_id": aggregate_id, "assessment_id": "assessment.001"},
            previous_state="candidate",
            state=state,
            severity=Severity.HIGH,
            digest_references=(DigestReference("report:summary:001", "sha256:" + "a" * 64),),
            summary="Validated finding state changed after policy review.",
            link_references=(OpaqueLinkReference("details", "portal:finding:001"),),
        )
        signed = sign_integration_event(
            event,
            signer_key_id="producer-key.1",
            private_key=self.event_private,
        )
        return verify_integration_event(signed, self.event_private.public_key())

    def claim(self, *, worker: str = "worker.1"):
        leases = self.store.claim(
            worker_id=worker,
            event_public_key_resolver=lambda key_id: self.event_private.public_key(),
            lease_seconds=10,
        )
        self.assertEqual(len(leases), 1)
        return leases[0]

    def observation(
        self,
        lease,
        status: ObservationStatus,
        *,
        destination=None,
        signer_key_id: str = "adapter-key.1",
        error_code: str | None = None,
    ):
        destination = destination or lease.destination_reference
        body = create_delivery_observation(
            event=lease.event,
            destination=destination,
            idempotency_key=lease.record.idempotency_key,
            attempt_number=lease.attempt_number,
            adapter_id="adapter.external",
            status=status,
            observed_at=self.clock().isoformat().replace("+00:00", "Z"),
            remote_receipt_ref=(
                "remote:receipt:001" if status is ObservationStatus.SUCCEEDED else None
            ),
            error_code=error_code,
        )
        signed = sign_delivery_observation(
            body,
            signer_key_id=signer_key_id,
            private_key=self.adapter_private,
        )
        return verify_delivery_observation(
            signed,
            self.adapter_private.public_key(),
            expected_event=lease.event,
            expected_destination=lease.destination_reference,
            expected_idempotency_key=lease.record.idempotency_key,
            expected_attempt_number=lease.attempt_number,
        )

    def test_all_event_families_are_immutable_and_content_addressed(self) -> None:
        identities = set()
        for event_type in EventType:
            verified = self.event(
                aggregate_id=event_type.value.replace(".changed", ".001"),
                event_type=event_type,
            )
            identities.add(verified.signed.event.event_id)
            with self.assertRaises(FrozenInstanceError):
                verified.signed.event.state = "mutated"
        self.assertEqual(len(identities), 6)
        first = self.event()
        second = self.event()
        self.assertEqual(first.signed.event, second.signed.event)
        self.assertEqual(first.signed.signature, second.signed.signature)

    def test_destination_kinds_are_strict_and_opaque(self) -> None:
        routes = {
            DestinationKind.GENERIC_WEBHOOK: {"endpoint_ref": "routing:webhook:primary"},
            DestinationKind.JIRA_TICKET: {
                "project_ref": "routing:ticket:project",
                "issue_type_ref": "routing:ticket:type",
            },
            DestinationKind.SIEM: {"stream_ref": "routing:siem:alerts"},
            DestinationKind.COLLABORATION: {"channel_ref": "routing:collab:security"},
        }
        for index, (kind, route) in enumerate(routes.items()):
            descriptor = create_destination(
                destination_id=f"destination.{index}", kind=kind, route=route
            )
            self.assertEqual(descriptor.kind, kind)
            self.assertNotIn("http", json.dumps(descriptor.to_dict()))
        with self.assertRaisesRegex(IntegrationValidationError, "opaque"):
            create_destination(
                destination_id="destination.url",
                kind=DestinationKind.GENERIC_WEBHOOK,
                route={"endpoint_ref": "https://example.invalid/hook"},
            )
        with self.assertRaisesRegex(IntegrationValidationError, "fields"):
            create_destination(
                destination_id="destination.secret",
                kind=DestinationKind.SIEM,
                route={"stream_ref": "routing:siem:a", "api_key": "opaque"},
            )

    def test_secret_payload_and_effect_escalation_are_rejected(self) -> None:
        with self.assertRaisesRegex(IntegrationValidationError, "secret"):
            create_integration_event(
                event_type=EventType.REPORT,
                occurred_at="2026-09-19T18:00:00Z",
                producer_id="producer.1",
                aggregate_id="report.1",
                subject_ids={"report_id": "report.1"},
                previous_state="draft",
                state="published",
                severity=Severity.NOT_APPLICABLE,
                digest_references=(),
                summary="Authorization: Bearer abcdefghijklmnop",
            )
        with self.assertRaisesRegex(IntegrationValidationError, "exploit payload"):
            create_integration_event(
                event_type=EventType.FINDING,
                occurred_at="2026-09-19T18:00:00Z",
                producer_id="producer.1",
                aggregate_id="finding.1",
                subject_ids={"finding_id": "finding.1"},
                previous_state="new",
                state="confirmed",
                severity=Severity.HIGH,
                digest_references=(),
                summary="Run curl https://example.invalid/payload",
            )
        raw = self.event().signed.event.to_dict()
        raw["authorization_effect"] = "grant"
        with self.assertRaisesRegex(IntegrationValidationError, "authority or effects"):
            type(self.event().signed.event).from_dict(raw)

    def test_signatures_require_out_of_band_keys_and_detect_mutation(self) -> None:
        verified = self.event()
        wrong_key = Ed25519PrivateKey.generate().public_key()
        with self.assertRaisesRegex(IntegrationValidationError, "substitution"):
            verify_integration_event(verified.signed, wrong_key)
        raw = verified.signed.to_dict()
        raw["event"]["summary"] = "Changed summary."
        with self.assertRaisesRegex(IntegrationValidationError, "content address"):
            type(verified.signed).from_dict(raw)

    def test_atomic_idempotent_enqueue_and_immutable_sqlite_custody(self) -> None:
        event = self.event()
        first = self.store.enqueue(event, self.destination)
        second = self.store.enqueue(event, self.destination)
        self.assertEqual(first, second)
        self.assertEqual(first.state, "pending")
        self.assertTrue(self.access.directories and self.access.files and self.access.syncs)
        with closing(sqlite3.connect(self.directory / DATABASE_FILENAME)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE integration_events SET event_sha256 = ?",
                    ("sha256:" + "f" * 64,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                connection.execute("DELETE FROM integration_events")

    def test_concurrent_claim_has_one_winner(self) -> None:
        record = self.store.enqueue(self.event(), self.destination)
        second_store = IntegrationOutbox(
            self.directory, self.access, clock=self.clock, retry_policy=self.policy
        )
        second_store.initialize()
        barrier = threading.Barrier(3)
        winners: list[str] = []
        lock = threading.Lock()

        def run(store: IntegrationOutbox, worker: str) -> None:
            barrier.wait()
            leases = store.claim(
                worker_id=worker,
                event_public_key_resolver=lambda key_id: self.event_private.public_key(),
                lease_seconds=10,
            )
            with lock:
                winners.extend(lease.worker_id for lease in leases)

        threads = [
            threading.Thread(target=run, args=(self.store, "worker.a")),
            threading.Thread(target=run, args=(second_store, "worker.b")),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(len(winners), 1)
        self.assertEqual(self.store.get(record.outbox_id).attempt_count, 1)

    def test_expired_lease_reopens_with_new_fence_and_rejects_stale_completion(self) -> None:
        self.store.enqueue(self.event(), self.destination)
        first = self.claim(worker="worker.first")
        self.clock.advance(11)
        reopened = IntegrationOutbox(
            self.directory, self.access, clock=self.clock, retry_policy=self.policy
        )
        reopened.initialize()
        second = reopened.claim(
            worker_id="worker.second",
            event_public_key_resolver=lambda key_id: self.event_private.public_key(),
            lease_seconds=10,
        )[0]
        self.assertGreater(second.fencing_token, first.fencing_token)
        with self.assertRaisesRegex(IntegrationConflictError, "fencing token"):
            reopened.complete(
                first,
                self.observation(first, ObservationStatus.SUCCEEDED),
            )

    def test_retry_schedule_and_bounded_dead_letter(self) -> None:
        record = self.store.enqueue(self.event(), self.destination)
        first = self.claim()
        result = self.store.complete(
            first,
            self.observation(first, ObservationStatus.RETRYABLE_FAILURE, error_code="temporary"),
        )
        self.assertEqual(result.state, "retry")
        self.assertEqual(
            self.store.claim(
                worker_id="worker.2",
                event_public_key_resolver=lambda key_id: self.event_private.public_key(),
            ),
            (),
        )
        self.clock.advance(5)
        second = self.claim(worker="worker.2")
        self.store.complete(
            second,
            self.observation(second, ObservationStatus.RETRYABLE_FAILURE, error_code="temporary"),
        )
        self.clock.advance(10)
        third = self.claim(worker="worker.3")
        terminal = self.store.complete(
            third,
            self.observation(third, ObservationStatus.RETRYABLE_FAILURE, error_code="temporary"),
        )
        self.assertEqual(terminal.state, "dead_letter")
        self.assertEqual(terminal.attempt_count, 3)
        self.assertEqual(self.store.receipt_count(record.outbox_id), 3)

    def test_partition_order_blocks_later_event_until_terminal(self) -> None:
        first = self.store.enqueue(self.event(state="confirmed"), self.destination)
        self.clock.advance(1)
        second = self.store.enqueue(self.event(state="reported"), self.destination)
        lease = self.claim()
        self.assertEqual(lease.record.outbox_id, first.outbox_id)
        self.assertEqual(
            self.store.claim(
                worker_id="worker.other",
                event_public_key_resolver=lambda key_id: self.event_private.public_key(),
            ),
            (),
        )
        self.store.complete(lease, self.observation(lease, ObservationStatus.SUCCEEDED))
        next_lease = self.claim(worker="worker.next")
        self.assertEqual(next_lease.record.outbox_id, second.outbox_id)

    def test_ack_substitution_self_ack_and_duplicate_success_are_rejected(self) -> None:
        self.store.enqueue(self.event(), self.destination)
        lease = self.claim()
        other_destination = create_destination(
            destination_id="destination.other",
            kind=DestinationKind.SIEM,
            route={"stream_ref": "routing:siem:alerts"},
        )
        substituted = create_delivery_observation(
            event=lease.event,
            destination=other_destination.reference,
            idempotency_key=lease.record.idempotency_key,
            attempt_number=lease.attempt_number,
            adapter_id="adapter.external",
            status=ObservationStatus.SUCCEEDED,
            observed_at="2026-09-19T18:00:00Z",
            remote_receipt_ref="remote:receipt:other",
        )
        substituted_signed = sign_delivery_observation(
            substituted,
            signer_key_id="adapter-key.1",
            private_key=self.adapter_private,
        )
        with self.assertRaisesRegex(IntegrationValidationError, "substitution"):
            verify_delivery_observation(
                substituted_signed,
                self.adapter_private.public_key(),
                expected_event=lease.event,
                expected_destination=lease.destination_reference,
                expected_idempotency_key=lease.record.idempotency_key,
                expected_attempt_number=lease.attempt_number,
            )
        valid = self.observation(lease, ObservationStatus.SUCCEEDED)
        self.store.complete(lease, valid)
        with self.assertRaisesRegex(IntegrationConflictError, "not actively leased"):
            self.store.complete(lease, valid)
        body = create_delivery_observation(
            event=lease.event,
            destination=lease.destination_reference,
            idempotency_key=lease.record.idempotency_key,
            attempt_number=lease.attempt_number,
            adapter_id="adapter.external",
            status=ObservationStatus.SUCCEEDED,
            observed_at="2026-09-19T18:00:00Z",
            remote_receipt_ref="remote:receipt:self",
        )
        with self.assertRaisesRegex(IntegrationValidationError, "own events"):
            sign_delivery_observation(
                body,
                signer_key_id=lease.event.signed.signer_key_id,
                private_key=self.adapter_private,
            )
        with self.assertRaisesRegex(IntegrationValidationError, "own events"):
            sign_delivery_observation(
                body,
                signer_key_id="producer-key.relabelled",
                private_key=self.event_private,
            )

    def test_cancellation_revokes_active_lease(self) -> None:
        record = self.store.enqueue(self.event(), self.destination)
        lease = self.claim()
        cancelled = self.store.cancel(record.outbox_id, reason="operator_request")
        self.assertEqual(cancelled.state, "cancelled")
        with self.assertRaisesRegex(IntegrationConflictError, "not actively leased"):
            self.store.complete(lease, self.observation(lease, ObservationStatus.SUCCEEDED))
        self.assertEqual(self.store.cancel(record.outbox_id, reason="operator_request"), cancelled)

    def test_external_adapter_gets_only_verified_event_and_opaque_reference(self) -> None:
        self.store.enqueue(self.event(), self.destination)
        lease = self.claim()

        class Adapter:
            def deliver(inner_self, event, destination):
                self.assertIs(event, lease.event)
                self.assertEqual(destination, lease.destination_reference)
                observation = create_delivery_observation(
                    event=event,
                    destination=destination,
                    idempotency_key=lease.record.idempotency_key,
                    attempt_number=lease.attempt_number,
                    adapter_id="adapter.external",
                    status=ObservationStatus.SUCCEEDED,
                    observed_at="2026-09-19T18:00:00Z",
                    remote_receipt_ref="remote:receipt:adapter",
                )
                return sign_delivery_observation(
                    observation,
                    signer_key_id="adapter-key.1",
                    private_key=self.adapter_private,
                )

        verified = deliver_with_adapter(
            Adapter(),
            event=lease.event,
            destination=lease.destination_reference,
            idempotency_key=lease.record.idempotency_key,
            attempt_number=lease.attempt_number,
            observation_public_key=self.adapter_private.public_key(),
        )
        self.assertEqual(verified.signed.observation.status, ObservationStatus.SUCCEEDED)

    def test_event_schema_validates_and_forbids_extra_or_response_body_fields(self) -> None:
        schema = json.loads(
            (ROOT / "registry/schemas/integration-outbox-event-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        raw = self.event().signed.to_dict()
        validator.validate(raw)
        raw["event"]["response_body"] = "forbidden"
        self.assertTrue(list(validator.iter_errors(raw)))

    def test_module_has_no_network_client_imports_and_contract_has_no_effects(self) -> None:
        module_path = ROOT / "src/sunderkey/integration_outbox.py"
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            imported.isdisjoint({"http", "httpx", "requests", "socket", "urllib", "aiohttp"})
        )
        event_raw = self.event().signed.event.to_dict()
        destination_raw = self.destination.to_dict()
        for raw in (event_raw, destination_raw):
            effect_values = [value for key, value in raw.items() if key.endswith("_effect")]
            self.assertTrue(effect_values)
            self.assertEqual(set(effect_values), {"none"})

    def test_observation_parser_rejects_response_bodies_and_signature_changes(self) -> None:
        self.store.enqueue(self.event(), self.destination)
        lease = self.claim()
        verified = self.observation(lease, ObservationStatus.SUCCEEDED)
        raw = verified.signed.observation.to_dict()
        raw["response_body_stored"] = True
        with self.assertRaisesRegex(IntegrationValidationError, "response bodies"):
            DeliveryObservation.from_dict(raw)
        signed_raw = verified.signed.to_dict()
        signed_raw["signature"] = ("A" if signed_raw["signature"][0] != "A" else "B") + signed_raw[
            "signature"
        ][1:]
        changed = SignedDeliveryObservation.from_dict(signed_raw)
        with self.assertRaisesRegex(IntegrationValidationError, "signature"):
            verify_delivery_observation(
                changed,
                self.adapter_private.public_key(),
                expected_event=lease.event,
                expected_destination=lease.destination_reference,
                expected_idempotency_key=lease.record.idempotency_key,
                expected_attempt_number=lease.attempt_number,
            )

    def test_destination_id_cannot_be_rebound(self) -> None:
        self.store.enqueue(self.event(), self.destination)
        changed = create_destination(
            destination_id=self.destination.destination_id,
            kind=DestinationKind.GENERIC_WEBHOOK,
            route={"endpoint_ref": "routing:webhook:changed"},
        )
        with self.assertRaisesRegex(IntegrationConflictError, "substituted"):
            self.store.enqueue(self.event(aggregate_id="finding.002"), changed)

    def test_frozen_dataclass_replace_cannot_bypass_content_verification(self) -> None:
        verified = self.event()
        mutated = replace(verified.signed.event, state="closed")
        with self.assertRaisesRegex(IntegrationValidationError, "content address"):
            sign_integration_event(
                mutated,
                signer_key_id="producer-key.1",
                private_key=self.event_private,
            )


if __name__ == "__main__":
    unittest.main()
