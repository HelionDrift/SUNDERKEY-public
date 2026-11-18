"""Supplied stream offsets do not prove broker records or consumer state."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_stream_offset_projection import (
    StreamOffsetProjection,
    StreamOffsetProjectionError,
    analyze_supplied_stream_offsets,
    verify_supplied_stream_offsets,
)


def model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-stream-offsets-v1",
        "partition_ref": "partition:sha256:" + "a" * 64,
        "range_start": 10,
        "range_end": 14,
        "history_complete": False,
        "observed_offsets": [10, 11, 11, 13],
        "commits": [
            {"commit_id": "c1", "declared_processed_offset": 10},
            {"commit_id": "c2", "declared_processed_offset": 12},
            {"commit_id": "c3", "declared_processed_offset": 11},
        ],
        "maximum_lag": 1,
    }


class StreamOffsetProjectionTests(unittest.TestCase):
    def test_declared_duplicates_gaps_and_commit_regression(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_stream_offsets(source)
        self.assertEqual(source, original)
        row = report.to_dict()["observations"]
        self.assertEqual(row["duplicate_offsets"], [11])
        self.assertEqual(
            row["unlisted_intervals"], [{"start": 12, "end": 12}, {"start": 14, "end": 14}]
        )
        self.assertEqual(row["unlisted_intervals_disposition"], "unknown_incomplete_history")
        self.assertEqual(row["commit_regression_ids"], ["c3"])
        self.assertEqual(row["lag"], 2)
        self.assertEqual(row["commit_disposition"], "exceeds_supplied_lag")
        self.assertFalse(report.to_dict()["flags"]["message_loss_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_stream_offsets(report, model=source).to_json(), report.to_json()
        )
        source["history_complete"] = True
        self.assertEqual(
            analyze_supplied_stream_offsets(source).to_dict()["observations"][
                "unlisted_intervals_disposition"
            ],
            "missing_in_declared_complete_history",
        )

    def test_commit_ahead_empty_observations_and_invalid_bounds(self) -> None:
        source = model()
        source["commits"] = [{"commit_id": "c1", "declared_processed_offset": 14}]
        self.assertEqual(
            analyze_supplied_stream_offsets(source).to_dict()["observations"]["commit_disposition"],
            "commit_ahead_of_supplied_observations",
        )
        source["observed_offsets"] = []
        self.assertEqual(
            analyze_supplied_stream_offsets(source).to_dict()["observations"]["commit_disposition"],
            "no_supplied_observation",
        )
        source["range_end"] = 9
        with self.assertRaises(StreamOffsetProjectionError):
            analyze_supplied_stream_offsets(source)
        source = model()
        source["observed_offsets"][0] = 9
        with self.assertRaises(StreamOffsetProjectionError):
            analyze_supplied_stream_offsets(source)

    def test_invalid_types_duplicate_commit_and_tamper_refused(self) -> None:
        source = model()
        source["history_complete"] = 1
        with self.assertRaises(StreamOffsetProjectionError):
            analyze_supplied_stream_offsets(source)
        source = model()
        source["commits"][1]["commit_id"] = "c1"
        with self.assertRaises(StreamOffsetProjectionError):
            analyze_supplied_stream_offsets(source)
        source = model()
        source["partition_ref"] = "real-topic"
        with self.assertRaises(StreamOffsetProjectionError):
            analyze_supplied_stream_offsets(source)
        source = model()
        source["observed_offsets"][0] = object()
        with self.assertRaises(StreamOffsetProjectionError):
            analyze_supplied_stream_offsets(source)
        source = model()
        report = analyze_supplied_stream_offsets(source)
        tampered = report.to_dict()
        tampered["flags"]["message_loss_proven"] = True
        with self.assertRaises(StreamOffsetProjectionError):
            StreamOffsetProjection(tampered)
        source["maximum_lag"] = 2
        with self.assertRaises(StreamOffsetProjectionError):
            verify_supplied_stream_offsets(report, model=source)


if __name__ == "__main__":
    unittest.main()
