"""Historical telemetry imports reject cross-batch gaps and replay."""

from __future__ import annotations

import copy
import unittest

from sunderkey.defender_telemetry_adapters import normalize_import_batch
from sunderkey.offline_telemetry_ingest_chain import (
    OfflineTelemetryIngestChainError,
    build_offline_telemetry_ingest_chain,
    verify_offline_telemetry_ingest_chain,
)
from tests.agents import test_defender_telemetry_adapters_phase167 as telemetry_fixture


class OfflineTelemetryIngestChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = telemetry_fixture.DefenderTelemetryAdaptersPhase167Tests()
        self.binding = self.helper.binding()

    def batch(self, sequence: int, imported_at: str, **changes):
        envelope = self.helper.envelope(self.binding, sequence, **changes)
        return normalize_import_batch(
            self.binding, (envelope,), telemetry_fixture.FakeNormalizer(),
            imported_at=imported_at,
        )

    def test_gap_free_chain_is_reproducible_and_non_authorizing(self) -> None:
        first = self.batch(4, "2026-09-20T12:01:00Z")
        second = self.batch(5, "2026-09-20T12:02:00Z")
        result = build_offline_telemetry_ingest_chain((first, second))
        self.assertEqual(result["event_count"], 2)
        self.assertEqual(result["first_source_sequence"], 4)
        self.assertEqual(result["last_source_sequence"], 5)
        self.assertEqual(result["initial_sequence_assurance"], "first_supplied_event_only")
        self.assertFalse(result["live_currentness_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(result["effects"]["collection"], "none")
        self.assertEqual(
            verify_offline_telemetry_ingest_chain(
                batches=(first, second), document=result
            ),
            result,
        )

    def test_gap_reversal_import_time_and_binding_change_fail(self) -> None:
        first = self.batch(1, "2026-09-20T12:01:00Z")
        gap = self.batch(3, "2026-09-20T12:02:00Z")
        with self.assertRaisesRegex(OfflineTelemetryIngestChainError, "gap"):
            build_offline_telemetry_ingest_chain((first, gap))
        reversed_sequence = self.batch(0, "2026-09-20T12:02:00Z")
        with self.assertRaisesRegex(OfflineTelemetryIngestChainError, "gap"):
            build_offline_telemetry_ingest_chain((first, reversed_sequence))
        same_time = self.batch(2, "2026-09-20T12:01:00Z")
        with self.assertRaisesRegex(OfflineTelemetryIngestChainError, "did not advance"):
            build_offline_telemetry_ingest_chain((first, same_time))
        other_binding = self.helper.binding("identity")
        other = normalize_import_batch(
            other_binding,
            (self.helper.envelope(other_binding, 2),),
            telemetry_fixture.FakeNormalizer(),
            imported_at="2026-09-20T12:02:00Z",
        )
        with self.assertRaisesRegex(OfflineTelemetryIngestChainError, "binding changed"):
            build_offline_telemetry_ingest_chain((first, other))

    def test_historical_source_reference_and_payload_replay_fail(self) -> None:
        first = self.batch(1, "2026-09-20T12:01:00Z")
        repeated_ref = self.batch(
            2, "2026-09-20T12:02:00Z", source_event_ref="eventref:event-001"
        )
        with self.assertRaisesRegex(OfflineTelemetryIngestChainError, "historical"):
            build_offline_telemetry_ingest_chain((first, repeated_ref))
        repeated_raw = self.batch(
            2, "2026-09-20T12:02:00Z",
            raw_event_sha256=first.envelopes[0].raw_event_sha256,
        )
        with self.assertRaisesRegex(OfflineTelemetryIngestChainError, "historical"):
            build_offline_telemetry_ingest_chain((first, repeated_raw))

    def test_tampered_chain_and_noncanonical_batch_fail(self) -> None:
        first = self.batch(1, "2026-09-20T12:01:00Z")
        result = build_offline_telemetry_ingest_chain((first,))
        changed = copy.deepcopy(result)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineTelemetryIngestChainError, "does not match"):
            verify_offline_telemetry_ingest_chain(
                batches=(first,), document=changed
            )
        with self.assertRaisesRegex(OfflineTelemetryIngestChainError, "batch count"):
            build_offline_telemetry_ingest_chain(())


if __name__ == "__main__":
    unittest.main()
