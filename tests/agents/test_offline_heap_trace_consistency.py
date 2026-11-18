"""Supplied heap-trace consistency and source-replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_heap_trace_consistency import (
    HeapTraceConsistencyError,
    HeapTraceConsistencyReport,
    analyze_supplied_heap_trace,
    component_fixture,
    verify_supplied_heap_trace,
)


class HeapTraceConsistencyTests(unittest.TestCase):
    def test_supplied_overlap_bounds_and_lifetime_anomalies(self) -> None:
        report = analyze_supplied_heap_trace(component_fixture()).to_dict()
        self.assertEqual(
            [row["code"] for row in report["anomalies"]],
            [
                "overlapping_live_ranges", "out_of_declared_bounds",
                "access_after_free", "duplicate_free",
            ],
        )
        self.assertEqual(report["active_allocation_ids_at_end"], ["b"])
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["heap_state_observed"])
        self.assertFalse(report["memory_access_verified"])

    def test_unknown_ids_are_separate_from_freed_ids(self) -> None:
        model = component_fixture()
        model["events"].append({
            "event_id": "free_unknown", "kind": "free", "allocation_id": "missing"
        })
        model["events"].append({
            "event_id": "access_unknown", "kind": "access", "allocation_id": "missing",
            "offset": 0, "length": 1, "mode": "read",
        })
        report = analyze_supplied_heap_trace(model).to_dict()
        self.assertEqual(
            [row["code"] for row in report["anomalies"][-2:]],
            ["unknown_free", "unknown_access"],
        )

    def test_incomplete_trace_remains_unknown(self) -> None:
        model = component_fixture()
        model["trace_complete"] = False
        report = analyze_supplied_heap_trace(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["anomaly_count"], 4)

    def test_rejects_id_reuse_and_invalid_bounds(self) -> None:
        model = component_fixture()
        duplicate = copy.deepcopy(model["events"][0])
        duplicate["event_id"] = "alloc_a_again"
        model["events"].append(duplicate)
        with self.assertRaises(HeapTraceConsistencyError):
            analyze_supplied_heap_trace(model)
        model = component_fixture()
        model["events"][0]["size"] = 0
        with self.assertRaises(HeapTraceConsistencyError):
            analyze_supplied_heap_trace(model)
        model = component_fixture()
        model["events"][2]["offset"] = True
        with self.assertRaises(HeapTraceConsistencyError):
            analyze_supplied_heap_trace(model)

    def test_original_source_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_heap_trace(model)
        self.assertEqual(
            verify_supplied_heap_trace(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["events"][2]["length"] = 1
        with self.assertRaises(HeapTraceConsistencyError):
            verify_supplied_heap_trace(report, model=changed)
        with self.assertRaises(HeapTraceConsistencyError):
            HeapTraceConsistencyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
