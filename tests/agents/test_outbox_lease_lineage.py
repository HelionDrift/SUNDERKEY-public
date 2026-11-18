"""Signed outbox completion must retain the immutable selected source lineage.

Only the filesystem connection seam is replaced by SQLite :memory:. The actual
schema, constraints, triggers, transactions and public signature checks run.
These fixtures do not establish independent host custody or external delivery.
"""

from __future__ import annotations

import json
import sqlite3
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey import integration_outbox as outbox
from tests.agents import test_integration_outbox_phase161 as fixtures


def _canonical(value: Any) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )


class _MemoryOutbox(outbox.IntegrationOutbox):
    """Use the production schema without invoking filesystem custody callbacks."""

    def __init__(self, fixture: fixtures.IntegrationOutboxPhase161Tests) -> None:
        super().__init__(
            Path.cwd() / "outbox-memory-only",
            fixtures.TestAccessController(),
            clock=fixture.clock,
            retry_policy=fixture.policy,
        )
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(outbox._SCHEMA)
        self.connection.execute(f"PRAGMA application_id = {outbox.APPLICATION_ID}")
        self.connection.execute(f"PRAGMA user_version = {outbox.SCHEMA_VERSION}")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        # A memory database has no file or rollback-journal custody to verify.
        # No content, signature, transaction or completion check is replaced.
        yield self.connection


class OutboxLeaseLineageTests(unittest.TestCase):
    def _fixture(self) -> fixtures.IntegrationOutboxPhase161Tests:
        fixture = fixtures.IntegrationOutboxPhase161Tests("runTest")
        fixture.clock = fixtures.MutableClock()
        # Fixed synthetic test seeds, never operational or persisted keys.
        fixture.event_private = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
        fixture.adapter_private = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
        fixture.policy = outbox.RetryPolicy(3, 5, 20)
        fixture.store = _MemoryOutbox(fixture)
        self.addCleanup(fixture.store.connection.close)
        fixture.destination = outbox.create_destination(
            destination_id="destination.primary",
            kind=outbox.DestinationKind.GENERIC_WEBHOOK,
            route={"endpoint_ref": "routing:webhook:primary"},
        )
        return fixture

    def _claimed(self, fixture: fixtures.IntegrationOutboxPhase161Tests) -> outbox.DeliveryLease:
        fixture.store.enqueue(fixture.event(), fixture.destination)
        return fixture.claim()

    def _dump(self, fixture: fixtures.IntegrationOutboxPhase161Tests) -> tuple[str, ...]:
        return tuple(fixture.store.connection.iterdump())

    def _other_destination(self) -> outbox.DestinationDescriptor:
        return outbox.create_destination(
            destination_id="destination.other",
            kind=outbox.DestinationKind.GENERIC_WEBHOOK,
            route={"endpoint_ref": "routing:webhook:other"},
        )

    def _assert_genuine_observation(
        self,
        fixture: fixtures.IntegrationOutboxPhase161Tests,
        lease: outbox.DeliveryLease,
        observation: outbox.VerifiedDeliveryObservation,
    ) -> None:
        verified = outbox.verify_delivery_observation(
            observation.signed,
            fixture.adapter_private.public_key(),
            expected_event=lease.event,
            expected_destination=lease.destination_reference,
            expected_idempotency_key=lease.record.idempotency_key,
            expected_attempt_number=lease.attempt_number,
        )
        self.assertEqual(verified.signed.to_dict(), observation.signed.to_dict())

    def _assert_receipt_join(
        self,
        fixture: fixtures.IntegrationOutboxPhase161Tests,
        lease: outbox.DeliveryLease,
        observation: outbox.VerifiedDeliveryObservation,
    ) -> None:
        row = fixture.store.connection.execute(
            "SELECT * FROM integration_delivery_receipts "
            "WHERE outbox_id = ? AND attempt_number = ?",
            (lease.record.outbox_id, lease.attempt_number),
        ).fetchone()
        self.assertIsNotNone(row)
        event = lease.event.signed.event
        self.assertEqual(
            (
                row["outbox_id"],
                row["event_id"],
                row["event_sha256"],
                row["destination_id"],
                row["destination_sha256"],
                row["attempt_number"],
            ),
            (
                lease.record.outbox_id,
                event.event_id,
                event.event_sha256,
                lease.destination.destination_id,
                lease.destination.destination_sha256,
                lease.attempt_number,
            ),
        )
        self.assertEqual(row["signed_observation_json"], _canonical(observation.signed.to_dict()))
        signed = outbox.SignedDeliveryObservation.from_dict(
            json.loads(row["signed_observation_json"])
        )
        verified = outbox.verify_delivery_observation(
            signed,
            fixture.adapter_private.public_key(),
            expected_event=lease.event,
            expected_destination=lease.destination_reference,
            expected_idempotency_key=lease.record.idempotency_key,
            expected_attempt_number=lease.attempt_number,
        )
        self.assertEqual(verified.signed.to_dict(), observation.signed.to_dict())
        stored_event = fixture.store.connection.execute(
            "SELECT signed_event_json FROM integration_events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()[0]
        stored_destination = fixture.store.connection.execute(
            "SELECT descriptor_json FROM integration_destinations WHERE destination_id = ?",
            (lease.destination.destination_id,),
        ).fetchone()[0]
        self.assertEqual(stored_event, _canonical(lease.event.signed.to_dict()))
        self.assertEqual(stored_destination, _canonical(lease.destination.to_dict()))

    def _assert_rejected_then_original_completes(
        self,
        fixture: fixtures.IntegrationOutboxPhase161Tests,
        original: outbox.DeliveryLease,
        changed: outbox.DeliveryLease,
        observation: outbox.VerifiedDeliveryObservation | None = None,
    ) -> None:
        observation = observation or fixture.observation(
            changed, outbox.ObservationStatus.SUCCEEDED
        )
        self._assert_genuine_observation(fixture, changed, observation)
        before = self._dump(fixture)
        with self.assertRaises(outbox.IntegrationOutboxError):
            fixture.store.complete(changed, observation)
        self.assertEqual(self._dump(fixture), before)
        self.assertEqual(fixture.store.get(original.record.outbox_id), original.record)
        self.assertEqual(fixture.store.receipt_count(original.record.outbox_id), 0)
        correct = fixture.observation(original, outbox.ObservationStatus.SUCCEEDED)
        self._assert_genuine_observation(fixture, original, correct)
        result = fixture.store.complete(original, correct)
        self.assertEqual(result.state, "delivered")
        self.assertEqual(result.event_sha256, original.record.event_sha256)
        self.assertEqual(result.destination_sha256, original.record.destination_sha256)
        self.assertEqual(result.idempotency_key, original.record.idempotency_key)
        self.assertEqual(fixture.store.receipt_count(original.record.outbox_id), 1)
        self._assert_receipt_join(fixture, original, correct)

    def _two_claims(
        self, fixture: fixtures.IntegrationOutboxPhase161Tests
    ) -> tuple[outbox.DeliveryLease, outbox.DeliveryLease]:
        first = fixture.store.enqueue(fixture.event(), fixture.destination)
        second = fixture.store.enqueue(
            fixture.event(aggregate_id="finding.other"), self._other_destination()
        )
        leases = fixture.store.claim(
            worker_id="worker.two-items",
            event_public_key_resolver=lambda key_id: fixture.event_private.public_key(),
            lease_seconds=10,
            limit=2,
        )
        self.assertEqual(len(leases), 2)
        self.assertEqual(
            tuple(lease.record.outbox_id for lease in leases),
            (first.outbox_id, second.outbox_id),
        )
        return leases

    def test_original_signed_completion_preserves_literal_addresses_and_effects(self) -> None:
        fixture = self._fixture()
        lease = self._claimed(fixture)
        observation = fixture.observation(lease, outbox.ObservationStatus.SUCCEEDED)
        self.assertEqual(lease.event.signed.event.event_id, "IOE-F905A30AFCB6B5EE21939D851560D146")
        self.assertEqual(
            lease.event.signed.event.event_sha256,
            "sha256:f905a30afcb6b5ee21939d851560d1465b2d646aa68003c84d7014f5b390e458",
        )
        self.assertEqual(
            lease.destination.destination_sha256,
            "sha256:78df2770ad94159f328faec5d0eb90ae9e9fd71a7a4e7f0265acaf725120b73b",
        )
        self.assertEqual(lease.record.outbox_id, "OBX-48B7BF2147FF088C906E95A782FC325D")
        self.assertEqual(
            lease.record.idempotency_key,
            "sha256:89768dcfb99a3c3b6d2149965bb12b3147d61458c21c9495db0c0bd384d3ddb3",
        )
        self.assertEqual(
            observation.signed.observation.observation_id, "IDO-467CB488FFDB7B0CE3459136EDF197AA"
        )
        self.assertEqual(
            observation.signed.observation.observation_sha256,
            "sha256:467cb488ffdb7b0ce3459136edf197aa83f0e3f457dea28416a4a10138fd4ac4",
        )
        self._assert_genuine_observation(fixture, lease, observation)
        self.assertEqual(fixture.store.complete(lease, observation).state, "delivered")
        self.assertEqual(fixture.store.receipt_count(lease.record.outbox_id), 1)
        self._assert_receipt_join(fixture, lease, observation)
        for document in (
            lease.event.signed.event.to_dict(),
            lease.destination.to_dict(),
            observation.signed.observation.to_dict(),
        ):
            effects = {value for key, value in document.items() if key.endswith("_effect")}
            self.assertEqual(effects, {"none"})
        self.assertEqual(fixture.store.access.directories, [])
        self.assertEqual(fixture.store.access.files, [])
        self.assertEqual(fixture.store.access.syncs, [])

    def test_truthfully_verified_foreign_event_cannot_complete_original_lease(self) -> None:
        fixture = self._fixture()
        original = self._claimed(fixture)
        other = fixture.event(aggregate_id="finding.other")
        self.assertEqual(
            outbox.verify_integration_event(other.signed, fixture.event_private.public_key()), other
        )
        self.assertNotEqual(other.signed.event.event_sha256, original.record.event_sha256)
        self._assert_rejected_then_original_completes(
            fixture, original, replace(original, event=other)
        )

    def test_valid_alternate_destination_cannot_complete_original_lease(self) -> None:
        fixture = self._fixture()
        original = self._claimed(fixture)
        other = self._other_destination()
        self.assertEqual(outbox.DestinationDescriptor.from_dict(other.to_dict()), other)
        self._assert_rejected_then_original_completes(
            fixture, original, replace(original, destination=other)
        )

    def test_same_destination_id_with_new_route_cannot_replace_original_source(self) -> None:
        fixture = self._fixture()
        original = self._claimed(fixture)
        other = outbox.create_destination(
            destination_id=original.destination.destination_id,
            kind=outbox.DestinationKind.GENERIC_WEBHOOK,
            route={"endpoint_ref": "routing:webhook:changed"},
        )
        self.assertEqual(other.destination_id, original.record.destination_id)
        self.assertNotEqual(other.destination_sha256, original.record.destination_sha256)
        self.assertEqual(outbox.DestinationDescriptor.from_dict(other.to_dict()), other)
        self._assert_rejected_then_original_completes(
            fixture, original, replace(original, destination=other)
        )

    def test_changed_record_idempotency_cannot_complete_original_lease(self) -> None:
        fixture = self._fixture()
        original = self._claimed(fixture)
        changed = replace(
            original, record=replace(original.record, idempotency_key="sha256:" + "b" * 64)
        )
        self._assert_rejected_then_original_completes(fixture, original, changed)

    def test_bounded_source_substitution_combinations_preserve_original_work(self) -> None:
        for fields in (
            ("event", "destination"),
            ("event", "idempotency"),
            ("destination", "idempotency"),
            ("event", "destination", "idempotency"),
        ):
            with self.subTest(fields=fields):
                fixture = self._fixture()
                original = self._claimed(fixture)
                changes = {}
                if "event" in fields:
                    changes["event"] = fixture.event(aggregate_id="finding.other")
                if "destination" in fields:
                    changes["destination"] = self._other_destination()
                if "idempotency" in fields:
                    changes["record"] = replace(
                        original.record, idempotency_key="sha256:" + "b" * 64
                    )
                self._assert_rejected_then_original_completes(
                    fixture, original, replace(original, **changes)
                )

    def test_two_genuine_queued_sources_cannot_cross_complete_original_work(self) -> None:
        fixture = self._fixture()
        original, other = self._two_claims(fixture)
        changed = replace(
            original,
            event=other.event,
            destination=other.destination,
            record=replace(original.record, idempotency_key=other.record.idempotency_key),
        )
        observation = fixture.observation(other, outbox.ObservationStatus.SUCCEEDED)
        self._assert_rejected_then_original_completes(fixture, original, changed, observation)
        self.assertEqual(fixture.store.get(other.record.outbox_id), other.record)
        self.assertEqual(fixture.store.receipt_count(other.record.outbox_id), 0)
        correct = fixture.observation(other, outbox.ObservationStatus.SUCCEEDED)
        self.assertEqual(fixture.store.complete(other, correct).state, "delivered")
        self._assert_receipt_join(fixture, other, correct)

    def test_same_event_body_different_signer_cannot_replace_signed_source_custody(self) -> None:
        for change_id, change_key in ((True, False), (False, True), (True, True)):
            with self.subTest(change_id=change_id, change_key=change_key):
                fixture = self._fixture()
                original = self._claimed(fixture)
                private = (
                    Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32)
                    if change_key
                    else fixture.event_private
                )
                signer_id = (
                    "producer-key.alternate" if change_id else original.event.signed.signer_key_id
                )
                signed = outbox.sign_integration_event(
                    original.event.signed.event, signer_key_id=signer_id, private_key=private
                )
                verified = outbox.verify_integration_event(signed, private.public_key())
                self.assertEqual(verified.signed.event, original.event.signed.event)
                self.assertNotEqual(verified.signed.to_dict(), original.event.signed.to_dict())
                self._assert_rejected_then_original_completes(
                    fixture, original, replace(original, event=verified)
                )

    def test_two_native_source_pairs_complete_with_separate_receipt_joins(self) -> None:
        fixture = self._fixture()
        leases = self._two_claims(fixture)
        for lease in reversed(leases):
            observation = fixture.observation(lease, outbox.ObservationStatus.SUCCEEDED)
            self._assert_genuine_observation(fixture, lease, observation)
            self.assertEqual(fixture.store.complete(lease, observation).state, "delivered")
            self.assertEqual(fixture.store.receipt_count(lease.record.outbox_id), 1)
            self._assert_receipt_join(fixture, lease, observation)

    def test_wrong_ack_against_unchanged_lease_still_rejects_without_writes(self) -> None:
        fixture = self._fixture()
        original, other = self._two_claims(fixture)
        wrong = fixture.observation(other, outbox.ObservationStatus.SUCCEEDED)
        self._assert_genuine_observation(fixture, other, wrong)
        before = self._dump(fixture)
        with self.assertRaisesRegex(outbox.IntegrationValidationError, "binding"):
            fixture.store.complete(original, wrong)
        self.assertEqual(self._dump(fixture), before)
        for lease in (original, other):
            correct = fixture.observation(lease, outbox.ObservationStatus.SUCCEEDED)
            self.assertEqual(fixture.store.complete(lease, correct).state, "delivered")
            self._assert_receipt_join(fixture, lease, correct)

    def test_retry_and_bounded_dead_letter_keep_exact_source_and_receipt_counts(self) -> None:
        fixture = self._fixture()
        first = self._claimed(fixture)
        lease = first
        for attempt, expected_state in ((1, "retry"), (2, "retry"), (3, "dead_letter")):
            observation = fixture.observation(
                lease, outbox.ObservationStatus.RETRYABLE_FAILURE, error_code="temporary"
            )
            result = fixture.store.complete(lease, observation)
            self.assertEqual(result.state, expected_state)
            self.assertEqual(result.attempt_count, attempt)
            self.assertEqual(fixture.store.receipt_count(first.record.outbox_id), attempt)
            self._assert_receipt_join(fixture, lease, observation)
            if attempt < 3:
                self.assertEqual(
                    fixture.store.claim(
                        worker_id="worker.not-due",
                        event_public_key_resolver=lambda key_id: fixture.event_private.public_key(),
                    ),
                    (),
                )
                fixture.clock.advance(fixture.policy.delay_for(attempt))
                lease = fixture.claim(worker=f"worker.retry-{attempt}")
                self.assertEqual(lease.event.signed.to_dict(), first.event.signed.to_dict())
                self.assertEqual(lease.destination.to_dict(), first.destination.to_dict())
                self.assertGreater(lease.fencing_token, first.fencing_token)

    def test_cancellation_and_duplicate_success_keep_existing_rejections(self) -> None:
        for cancel in (True, False):
            with self.subTest(cancel=cancel):
                fixture = self._fixture()
                lease = self._claimed(fixture)
                observation = fixture.observation(lease, outbox.ObservationStatus.SUCCEEDED)
                if cancel:
                    fixture.store.cancel(lease.record.outbox_id, reason="operator_request")
                else:
                    fixture.store.complete(lease, observation)
                before = self._dump(fixture)
                with self.assertRaisesRegex(outbox.IntegrationConflictError, "not actively leased"):
                    fixture.store.complete(lease, observation)
                self.assertEqual(self._dump(fixture), before)
                self.assertEqual(
                    fixture.store.receipt_count(lease.record.outbox_id), int(not cancel)
                )

    def test_genuine_reclaim_still_fences_old_lease_and_current_lease_completes(self) -> None:
        fixture = self._fixture()
        first = self._claimed(fixture)
        fixture.clock.advance(11)
        current = fixture.claim(worker="worker.current")
        self.assertGreater(current.fencing_token, first.fencing_token)
        old = fixture.observation(first, outbox.ObservationStatus.SUCCEEDED)
        before = self._dump(fixture)
        with self.assertRaisesRegex(outbox.IntegrationConflictError, "fencing token"):
            fixture.store.complete(first, old)
        self.assertEqual(self._dump(fixture), before)
        correct = fixture.observation(current, outbox.ObservationStatus.SUCCEEDED)
        self.assertEqual(fixture.store.complete(current, correct).state, "delivered")
        self.assertEqual(fixture.store.receipt_count(current.record.outbox_id), 1)
        self._assert_receipt_join(fixture, current, correct)

    def test_memory_scaffold_retains_actual_identity_foreign_keys_and_immutable_guards(
        self,
    ) -> None:
        fixture = self._fixture()
        lease = self._claimed(fixture)
        connection = fixture.store.connection
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(
            connection.execute("PRAGMA application_id").fetchone()[0], outbox.APPLICATION_ID
        )
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
        before = self._dump(fixture)
        for sql, message in (
            ("UPDATE integration_events SET event_sha256 = 'changed'", "immutable"),
            ("UPDATE integration_destinations SET destination_sha256 = 'changed'", "immutable"),
            ("UPDATE integration_outbox SET idempotency_key = 'changed'", "immutable"),
            ("DELETE FROM integration_outbox", "append-only"),
        ):
            with self.subTest(sql=sql), self.assertRaisesRegex(sqlite3.IntegrityError, message):
                connection.execute(sql)
            self.assertEqual(self._dump(fixture), before)
        observation = fixture.observation(lease, outbox.ObservationStatus.SUCCEEDED)
        fixture.store.complete(lease, observation)
        completed = self._dump(fixture)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            connection.execute("DELETE FROM integration_delivery_receipts")
        self.assertEqual(self._dump(fixture), completed)


if __name__ == "__main__":
    unittest.main()
