"""Paged in-memory telemetry rehearsal preserves cursor and source continuity."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_telemetry_pipeline_rehearsal import (
    OfflineTelemetryPipelineError,
    build_offline_telemetry_pipeline_rehearsal,
    verify_offline_telemetry_pipeline_rehearsal,
)
from tests.agents import test_defender_telemetry_adapters_phase167 as telemetry_fixture


class OfflineTelemetryPipelineRehearsalTests(unittest.TestCase):
    def setUp(self) -> None:
        helper = telemetry_fixture.DefenderTelemetryAdaptersPhase167Tests()
        self.binding = helper.binding()
        self.first = helper.envelope(self.binding, 1)
        self.second = helper.envelope(self.binding, 2)
        self.pages = [
            {
                "cursor_before": "cursorref:start",
                "cursor_after": "cursorref:one",
                "imported_at": "2026-09-20T12:01:00Z",
                "envelopes": [self.first],
                "end_of_stream": False,
            },
            {
                "cursor_before": "cursorref:one",
                "cursor_after": "cursorref:two",
                "imported_at": "2026-09-20T12:02:00Z",
                "envelopes": [self.second],
                "end_of_stream": True,
            },
        ]

    def run_pipeline(self, pages=None):
        return build_offline_telemetry_pipeline_rehearsal(
            binding=self.binding,
            start_cursor="cursorref:start",
            pages=self.pages if pages is None else pages,
            normalizer=telemetry_fixture.FakeNormalizer(),
        )

    def test_two_page_rehearsal_is_reproducible_and_effect_free(self) -> None:
        result = self.run_pipeline()
        self.assertEqual(result["page_count"], 2)
        self.assertEqual(result["event_count"], 2)
        self.assertEqual(result["end_cursor"], "cursorref:two")
        self.assertEqual(result["effects"]["collection"], "none")
        self.assertFalse(result["positive_use_approved"])
        self.assertFalse(result["live_currentness_verified"])
        self.assertEqual(
            verify_offline_telemetry_pipeline_rehearsal(
                binding=self.binding,
                start_cursor="cursorref:start",
                pages=self.pages,
                normalizer=telemetry_fixture.FakeNormalizer(),
                document=result,
            ),
            result,
        )

    def test_cursor_gap_loop_and_end_claim_fail(self) -> None:
        changed = [dict(page) for page in self.pages]
        changed[1]["cursor_before"] = "cursorref:wrong"
        with self.assertRaisesRegex(OfflineTelemetryPipelineError, "cursor gap"):
            self.run_pipeline(changed)
        changed = [dict(page) for page in self.pages]
        changed[1]["cursor_after"] = "cursorref:start"
        with self.assertRaisesRegex(OfflineTelemetryPipelineError, "cursor gap"):
            self.run_pipeline(changed)
        changed = [dict(page) for page in self.pages]
        changed[0]["end_of_stream"] = True
        with self.assertRaisesRegex(OfflineTelemetryPipelineError, "end_of_stream"):
            self.run_pipeline(changed)

    def test_sequence_gap_replay_and_binding_change_fail(self) -> None:
        helper = telemetry_fixture.DefenderTelemetryAdaptersPhase167Tests()
        changed = [dict(page) for page in self.pages]
        changed[1]["envelopes"] = [helper.envelope(self.binding, 3)]
        with self.assertRaisesRegex(OfflineTelemetryPipelineError, "cross-page"):
            self.run_pipeline(changed)
        changed = [dict(page) for page in self.pages]
        changed[1]["envelopes"] = [
            helper.envelope(self.binding, 2, source_event_ref=self.first.source_event_ref)
        ]
        with self.assertRaisesRegex(OfflineTelemetryPipelineError, "normalization"):
            self.run_pipeline(changed)
        changed = [dict(page) for page in self.pages]
        changed[1]["envelopes"] = [helper.envelope(helper.binding("identity"), 2)]
        with self.assertRaisesRegex(OfflineTelemetryPipelineError, "normalization"):
            self.run_pipeline(changed)

    def test_result_tamper_and_missing_normalizer_fail(self) -> None:
        result = self.run_pipeline()
        changed = copy.deepcopy(result)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineTelemetryPipelineError, "does not match"):
            verify_offline_telemetry_pipeline_rehearsal(
                binding=self.binding,
                start_cursor="cursorref:start",
                pages=self.pages,
                normalizer=telemetry_fixture.FakeNormalizer(),
                document=changed,
            )
        with self.assertRaisesRegex(OfflineTelemetryPipelineError, "normalizer"):
            build_offline_telemetry_pipeline_rehearsal(
                binding=self.binding,
                start_cursor="cursorref:start",
                pages=self.pages,
                normalizer=object(),
            )


if __name__ == "__main__":
    unittest.main()
