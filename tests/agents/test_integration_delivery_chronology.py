"""Declared event-to-observation causality, not shared-clock or expiry policy.

The fixtures use genuine local Ed25519 signatures, disposable SQLite custody,
and inert delivery ports. Historical parsing alone has no full event-time source.
"""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey import integration_delivery_worker as worker
from sunderkey import integration_outbox as outbox
from sunderkey.enterprise_connector_contracts import ConnectorTransportResponse
from tests.agents import test_integration_delivery_worker_phase169 as worker_fixtures
from tests.agents import test_integration_outbox_phase161 as outbox_fixtures


def _canonical(value: Any) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class _AdvancingTransport(worker_fixtures.FakeTransport):
    """One inert response also advances the explicitly supplied store clock."""

    def __init__(self, private_key, clock, advance_seconds: int) -> None:
        super().__init__(private_key)
        self.clock = clock
        self.advance_seconds = advance_seconds

    def _response(self) -> ConnectorTransportResponse:
        response = super()._response()
        self.clock.advance(self.advance_seconds)
        return response


class IntegrationDeliveryChronologyTests(unittest.TestCase):
    def _outbox_fixture(self) -> outbox_fixtures.IntegrationOutboxPhase161Tests:
        fixture = outbox_fixtures.IntegrationOutboxPhase161Tests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        # These fixed disposable test seeds are never operational keys.
        fixture.event_private = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
        fixture.adapter_private = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
        return fixture

    def _worker_fixture(self) -> worker_fixtures.IntegrationDeliveryWorkerPhase169Tests:
        fixture = worker_fixtures.IntegrationDeliveryWorkerPhase169Tests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.event_private = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
        fixture.adapter_private = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
        fixture.transport = worker_fixtures.FakeTransport(fixture.adapter_private)
        return fixture

    def _claimed(
        self,
        fixture: outbox_fixtures.IntegrationOutboxPhase161Tests,
        *,
        occurred_at: str | None = None,
    ) -> outbox.DeliveryLease:
        fixture.store.enqueue(fixture.event(occurred_at=occurred_at), fixture.destination)
        return fixture.claim()

    def _create(
        self,
        lease: outbox.DeliveryLease,
        observed_at: str,
        status: outbox.ObservationStatus = outbox.ObservationStatus.SUCCEEDED,
    ) -> outbox.DeliveryObservation:
        return outbox.create_delivery_observation(
            event=lease.event,
            destination=lease.destination_reference,
            idempotency_key=lease.record.idempotency_key,
            attempt_number=lease.attempt_number,
            adapter_id="adapter.external",
            status=status,
            observed_at=observed_at,
            remote_receipt_ref=(
                "remote:receipt:001" if status is outbox.ObservationStatus.SUCCEEDED else None
            ),
            error_code=None if status is outbox.ObservationStatus.SUCCEEDED else "temporary",
        )

    def _signed_readdressed(
        self,
        fixture: outbox_fixtures.IntegrationOutboxPhase161Tests,
        lease: outbox.DeliveryLease,
        observed_at: str,
        status: outbox.ObservationStatus = outbox.ObservationStatus.SUCCEEDED,
    ) -> outbox.SignedDeliveryObservation:
        # A standalone parser has no event body. Readdress its native document
        # independently, then use the genuine public signer and public-key check.
        original = self._create(lease, lease.event.signed.event.occurred_at, status)
        body = original.to_dict()
        body.pop("observation_id")
        body.pop("observation_sha256")
        body["observed_at"] = observed_at
        digest = (
            "sha256:"
            + hashlib.sha256(
                _canonical({"domain": outbox.OBSERVATION_DOMAIN, "observation": body}).encode(
                    "ascii"
                )
            ).hexdigest()
        )
        observation = outbox.DeliveryObservation.from_dict(
            {
                **body,
                "observation_id": "IDO-" + digest[7:39].upper(),
                "observation_sha256": digest,
            }
        )
        signed = outbox.sign_delivery_observation(
            observation,
            signer_key_id="adapter-key.1",
            private_key=fixture.adapter_private,
        )
        self._assert_signature(fixture, signed)
        return signed

    def _assert_signature(
        self,
        fixture: outbox_fixtures.IntegrationOutboxPhase161Tests,
        signed: outbox.SignedDeliveryObservation,
    ) -> None:
        payload = _canonical(
            {
                "domain": outbox.OBSERVATION_SIGNATURE_DOMAIN,
                "body": {
                    "observation": signed.observation.to_dict(),
                    "public_key_sha256": signed.public_key_sha256,
                    "signer_key_id": signed.signer_key_id,
                },
            }
        ).encode("ascii")
        signature = base64.urlsafe_b64decode(signed.signature + "=" * (-len(signed.signature) % 4))
        fixture.adapter_private.public_key().verify(signature, payload)

    def _verify(
        self,
        fixture: outbox_fixtures.IntegrationOutboxPhase161Tests,
        lease: outbox.DeliveryLease,
        signed: outbox.SignedDeliveryObservation,
    ) -> outbox.VerifiedDeliveryObservation:
        return outbox.verify_delivery_observation(
            signed,
            fixture.adapter_private.public_key(),
            expected_event=lease.event,
            expected_destination=lease.destination_reference,
            expected_idempotency_key=lease.record.idempotency_key,
            expected_attempt_number=lease.attempt_number,
        )

    def _route_and_record(self, fixture, *, connector: bool):
        if connector:
            destination, record = fixture.enqueue_connector()
            route = fixture.connector_route(destination)
        else:
            destination, record = fixture.enqueue_webhook()
            route = fixture.webhook_route(destination)
        return route, record

    def _assert_pre_event_worker_denied(self, *, connector: bool) -> None:
        fixture = self._worker_fixture()
        route, record = self._route_and_record(fixture, connector=connector)
        fixture.transport.queue(
            ConnectorTransportResponse(
                202, worker_fixtures.ONE, external_resource_ref="receiptref:chronology"
            )
        )
        caught = None
        try:
            fixture.worker(route).run_once(observed_at="2026-09-20T12:01:59Z")
        except (worker.IntegrationDeliveryWorkerError, outbox.IntegrationOutboxError) as exc:
            caught = exc
        # The injected methods are the only port allowed to resolve opaque key
        # or credential references. No claim of separate credential resolution.
        self.assertEqual(fixture.transport.webhook_calls, [])
        self.assertEqual(fixture.transport.connector_calls, [])
        self.assertEqual(fixture.transport.observations, [])
        self.assertIsInstance(caught, worker.IntegrationDeliveryWorkerError)
        current = fixture.store.get(record.outbox_id)
        self.assertEqual(current.state, "leased")
        self.assertEqual((current.attempt_count, current.fencing_token), (1, 1))
        self.assertEqual(fixture.store.receipt_count(record.outbox_id), 0)

    def test_producer_rejects_observation_before_event_for_every_status(self) -> None:
        fixture = self._outbox_fixture()
        lease = self._claimed(fixture)
        for status in outbox.ObservationStatus:
            with self.subTest(status=status):
                with self.assertRaises(outbox.IntegrationValidationError):
                    self._create(lease, "2026-09-19T17:59:59Z", status)
                self.assertEqual(fixture.store.get(lease.record.outbox_id), lease.record)
                self.assertEqual(fixture.store.receipt_count(lease.record.outbox_id), 0)

    def test_expected_event_verifier_rejects_genuine_signed_pre_event_ack(self) -> None:
        fixture = self._outbox_fixture()
        lease = self._claimed(fixture)
        for status in outbox.ObservationStatus:
            with self.subTest(status=status):
                signed = self._signed_readdressed(fixture, lease, "2026-09-19T17:59:59Z", status)
                self.assertEqual(signed.observation.event_sha256, lease.record.event_sha256)
                self.assertEqual(
                    signed.observation.destination_sha256, lease.record.destination_sha256
                )
                self.assertEqual(signed.observation.idempotency_key, lease.record.idempotency_key)
                self.assertEqual(signed.observation.attempt_number, lease.attempt_number)
                with self.assertRaises(outbox.IntegrationValidationError):
                    self._verify(fixture, lease, signed)
                self.assertEqual(fixture.store.get(lease.record.outbox_id), lease.record)
                self.assertEqual(fixture.store.receipt_count(lease.record.outbox_id), 0)

    def test_producer_rejects_one_microsecond_before_declared_event(self) -> None:
        fixture = self._outbox_fixture()
        lease = self._claimed(fixture, occurred_at="2026-09-19T18:00:00.000001Z")
        with self.assertRaises(outbox.IntegrationValidationError):
            self._create(lease, "2026-09-19T18:00:00Z")

    def test_expected_event_verifier_rejects_one_microsecond_before_event(self) -> None:
        fixture = self._outbox_fixture()
        lease = self._claimed(fixture, occurred_at="2026-09-19T18:00:00.000001Z")
        signed = self._signed_readdressed(fixture, lease, "2026-09-19T18:00:00Z")
        with self.assertRaises(outbox.IntegrationValidationError):
            self._verify(fixture, lease, signed)

    def test_webhook_pre_event_observation_stops_before_transport(self) -> None:
        self._assert_pre_event_worker_denied(connector=False)

    def test_connector_pre_event_observation_stops_before_credential_port(self) -> None:
        self._assert_pre_event_worker_denied(connector=True)

    def test_equal_and_later_observations_remain_valid_for_every_status(self) -> None:
        fixture = self._outbox_fixture()
        lease = self._claimed(fixture)
        for observed_at in ("2026-09-19T18:00:00Z", "2026-09-19T18:00:01Z"):
            for status in outbox.ObservationStatus:
                with self.subTest(observed_at=observed_at, status=status):
                    created = self._create(lease, observed_at, status)
                    signed = outbox.sign_delivery_observation(
                        created,
                        signer_key_id="adapter-key.1",
                        private_key=fixture.adapter_private,
                    )
                    self._assert_signature(fixture, signed)
                    verified = self._verify(fixture, lease, signed)
                    self.assertEqual(verified.signed.to_dict(), signed.to_dict())
                    self.assertEqual(
                        outbox.SignedDeliveryObservation.from_dict(
                            json.loads(_canonical(signed.to_dict()))
                        ),
                        signed,
                    )

    def test_valid_fractional_instants_are_compared_as_times_not_text(self) -> None:
        for occurred_at, observed_at in (
            ("2026-09-19T18:00:00Z", "2026-09-19T18:00:00.000001Z"),
            ("2026-09-19T18:00:00.000001Z", "2026-09-19T18:00:00.000001Z"),
            ("2026-09-19T18:00:00.999999Z", "2026-09-19T18:00:01Z"),
        ):
            with self.subTest(occurred_at=occurred_at, observed_at=observed_at):
                fixture = self._outbox_fixture()
                lease = self._claimed(fixture, occurred_at=occurred_at)
                created = self._create(lease, observed_at)
                signed = outbox.sign_delivery_observation(
                    created,
                    signer_key_id="adapter-key.1",
                    private_key=fixture.adapter_private,
                )
                self.assertEqual(self._verify(fixture, lease, signed).signed, signed)

    def test_equivalent_aware_clock_offsets_keep_canonical_utc_settlement(self) -> None:
        for hours in (-6, 5):
            with self.subTest(hours=hours):
                fixture = self._outbox_fixture()
                instant = fixture.clock.value
                fixture.clock.value = instant.astimezone(timezone(timedelta(hours=hours)))
                lease = self._claimed(fixture, occurred_at=_utc(instant))
                self.assertEqual(lease.lease_expires_at, "2026-09-19T18:00:10Z")
                signed = self._signed_readdressed(fixture, lease, _utc(fixture.clock()))
                verified = self._verify(fixture, lease, signed)
                result = fixture.store.complete(lease, verified)
                self.assertEqual(result.state, "delivered")
                self.assertEqual(fixture.store.receipt_count(result.outbox_id), 1)
                with fixture.store._connection() as connection:
                    row = connection.execute(
                        "SELECT recorded_at FROM integration_delivery_receipts WHERE outbox_id = ?",
                        (result.outbox_id,),
                    ).fetchone()
                self.assertEqual(row["recorded_at"], _utc(instant))

    def test_source_free_historical_parsing_and_signature_inspection_remain_valid(self) -> None:
        fixture = self._outbox_fixture()
        lease = self._claimed(fixture)
        signed = self._signed_readdressed(fixture, lease, "2026-09-19T17:59:59Z")
        # Neither the signed document parser nor a bare signature check receives
        # the event body. This is not a source-free verified delivery capability.
        parsed = outbox.SignedDeliveryObservation.from_dict(
            json.loads(_canonical(signed.to_dict()))
        )
        self._assert_signature(fixture, parsed)
        self.assertEqual(parsed, signed)
        effects = {
            value for key, value in parsed.observation.to_dict().items() if key.endswith("_effect")
        }
        self.assertEqual(effects, {"none"})
        self.assertEqual(fixture.store.receipt_count(lease.record.outbox_id), 0)

    def test_valid_expected_event_verification_does_not_require_old_time_currentness(self) -> None:
        fixture = self._outbox_fixture()
        lease = self._claimed(fixture)
        signed = self._signed_readdressed(fixture, lease, "2026-09-19T18:00:00Z")
        fixture.clock.advance(86_400 * 365)
        self.assertEqual(self._verify(fixture, lease, signed).signed, signed)
        self.assertEqual(fixture.store.receipt_count(lease.record.outbox_id), 0)

    def test_original_literal_addresses_and_none_effects_are_unchanged(self) -> None:
        fixture = self._outbox_fixture()
        lease = self._claimed(fixture)
        signed = self._signed_readdressed(fixture, lease, "2026-09-19T18:00:00Z")
        self.assertEqual(lease.event.signed.event.event_id, "IOE-F905A30AFCB6B5EE21939D851560D146")
        self.assertEqual(lease.record.outbox_id, "OBX-48B7BF2147FF088C906E95A782FC325D")
        self.assertEqual(signed.observation.observation_id, "IDO-467CB488FFDB7B0CE3459136EDF197AA")
        self.assertEqual(
            signed.observation.observation_sha256,
            "sha256:467cb488ffdb7b0ce3459136edf197aa83f0e3f457dea28416a4a10138fd4ac4",
        )
        self.assertEqual(
            fixture.store.complete(lease, self._verify(fixture, lease, signed)).state, "delivered"
        )
        for document in (
            lease.event.signed.event.to_dict(),
            lease.destination.to_dict(),
            signed.observation.to_dict(),
        ):
            self.assertEqual(
                {value for key, value in document.items() if key.endswith("_effect")}, {"none"}
            )

    def test_same_fence_terminal_settlement_at_and_after_expiry_remains_valid(self) -> None:
        for delay in (10, 11):
            for status in outbox.ObservationStatus:
                with self.subTest(delay=delay, status=status):
                    fixture = self._outbox_fixture()
                    lease = self._claimed(fixture)
                    fixture.clock.advance(delay)
                    signed = self._signed_readdressed(fixture, lease, _utc(fixture.clock()), status)
                    result = fixture.store.complete(lease, self._verify(fixture, lease, signed))
                    expected_state = {
                        outbox.ObservationStatus.SUCCEEDED: "delivered",
                        outbox.ObservationStatus.RETRYABLE_FAILURE: "retry",
                        outbox.ObservationStatus.PERMANENT_FAILURE: "dead_letter",
                    }[status]
                    self.assertEqual(result.state, expected_state)
                    self.assertEqual(result.fencing_token, lease.fencing_token)
                    self.assertEqual(result.attempt_count, lease.attempt_number)
                    self.assertEqual(fixture.store.receipt_count(result.outbox_id), 1)

    def test_worker_equal_and_later_event_times_do_not_require_shared_store_clock(self) -> None:
        for connector in (False, True):
            for observed_delta, store_delta in ((0, 0), (1, 0), (0, 5)):
                with self.subTest(
                    connector=connector, observed_delta=observed_delta, store_delta=store_delta
                ):
                    fixture = self._worker_fixture()
                    event_instant = fixture.clock.value
                    route, record = self._route_and_record(fixture, connector=connector)
                    fixture.clock.advance(store_delta)
                    fixture.transport.queue(
                        ConnectorTransportResponse(
                            202,
                            worker_fixtures.ONE,
                            external_resource_ref="receiptref:independent-clock",
                        )
                    )
                    observed_at = _utc(event_instant + timedelta(seconds=observed_delta))
                    receipts = fixture.worker(route).run_once(observed_at=observed_at)
                    self.assertEqual(len(receipts), 1)
                    self.assertEqual(receipts[0].outcome, worker.WorkerOutcome.SUCCEEDED)
                    self.assertEqual(receipts[0].completed_at, observed_at)
                    self.assertEqual(fixture.store.get(record.outbox_id).state, "delivered")
                    self.assertEqual(fixture.store.receipt_count(record.outbox_id), 1)
                    self.assertEqual(len(fixture.transport.connector_calls), int(connector))
                    self.assertEqual(len(fixture.transport.webhook_calls), int(not connector))
                    self.assertEqual(len(fixture.transport.observations), 1)

    def test_worker_callback_crossing_expiry_keeps_same_fence_terminal_settlement(self) -> None:
        for connector in (False, True):
            for delay in (10, 11):
                with self.subTest(connector=connector, delay=delay):
                    fixture = self._worker_fixture()
                    route, record = self._route_and_record(fixture, connector=connector)
                    observed_at = fixture.clock.text()
                    fixture.transport = _AdvancingTransport(
                        fixture.adapter_private, fixture.clock, delay
                    )
                    fixture.transport.queue(
                        ConnectorTransportResponse(
                            202,
                            worker_fixtures.ONE,
                            external_resource_ref="receiptref:late-settlement",
                        )
                    )
                    receipt = fixture.worker(
                        route,
                        policy=worker.WorkerPolicy(
                            lease_seconds=10, claim_limit=10, request_ttl_seconds=5
                        ),
                    ).run_once(observed_at=observed_at)[0]
                    self.assertEqual(receipt.outcome, worker.WorkerOutcome.SUCCEEDED)
                    self.assertEqual(receipt.lease_expires_at, "2026-09-20T12:02:10Z")
                    self.assertEqual(receipt.completed_at, observed_at)
                    self.assertGreaterEqual(fixture.clock.text(), receipt.lease_expires_at)
                    current = fixture.store.get(record.outbox_id)
                    self.assertEqual((current.state, current.attempt_count), ("delivered", 1))
                    self.assertEqual(current.fencing_token, receipt.fencing_token)
                    self.assertEqual(fixture.store.receipt_count(record.outbox_id), 1)
                    self.assertEqual(len(fixture.transport.connector_calls), int(connector))
                    self.assertEqual(len(fixture.transport.webhook_calls), int(not connector))
                    self.assertEqual(len(fixture.transport.observations), 1)


if __name__ == "__main__":
    unittest.main()
