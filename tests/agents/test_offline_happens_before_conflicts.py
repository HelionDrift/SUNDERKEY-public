"""Supplied happens-before conflict projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_happens_before_conflicts import (
    HappensBeforeConflictsError,
    HappensBeforeConflictsReport,
    analyze_supplied_happens_before,
    component_fixture,
    verify_supplied_happens_before,
)


class HappensBeforeConflictsTests(unittest.TestCase):
    def test_unordered_write_conflicts_are_only_graph_projection(self) -> None:
        report = analyze_supplied_happens_before(component_fixture()).to_dict()
        self.assertEqual(report["unordered_conflicting_pair_count"], 2)
        self.assertEqual(
            [(row["left_event_id"], row["right_event_id"])
             for row in report["unordered_conflicting_pairs"]],
            [("a_read", "b_write"), ("a_write", "b_write")],
        )
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["execution_trace_verified"])
        self.assertFalse(report["race_verified"])

    def test_transitive_order_removes_unordered_pairs(self) -> None:
        model = component_fixture()
        model["ordering_edges"].append({
            "before_event_id": "b_read", "after_event_id": "b_write"
        })
        report = analyze_supplied_happens_before(model).to_dict()
        self.assertEqual(report["unordered_conflicting_pair_count"], 0)

    def test_incomplete_trace_remains_unknown(self) -> None:
        model = component_fixture()
        model["trace_complete"] = False
        report = analyze_supplied_happens_before(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["unordered_conflicting_pair_count"], 2)

    def test_rejects_cycles_and_missing_event_references(self) -> None:
        model = component_fixture()
        model["ordering_edges"].append({
            "before_event_id": "b_read", "after_event_id": "a_write"
        })
        with self.assertRaises(HappensBeforeConflictsError):
            analyze_supplied_happens_before(model)
        model = component_fixture()
        model["ordering_edges"][0]["after_event_id"] = "missing"
        with self.assertRaises(HappensBeforeConflictsError):
            analyze_supplied_happens_before(model)
        model = component_fixture()
        model["events"].append(copy.deepcopy(model["events"][0]))
        with self.assertRaises(HappensBeforeConflictsError):
            analyze_supplied_happens_before(model)

    def test_read_read_pairs_are_not_conflicts(self) -> None:
        model = component_fixture()
        for item in model["events"]:
            item["access"] = "read"
        report = analyze_supplied_happens_before(model).to_dict()
        self.assertEqual(report["unordered_conflicting_pair_count"], 0)

    def test_original_model_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_happens_before(model)
        self.assertEqual(
            verify_supplied_happens_before(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["events"][0]["access"] = "read"
        with self.assertRaises(HappensBeforeConflictsError):
            verify_supplied_happens_before(report, model=changed)
        with self.assertRaises(HappensBeforeConflictsError):
            HappensBeforeConflictsReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
