"""Supplied binary-reference graph projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_binary_reference_graph import (
    BinaryReferenceGraphError,
    BinaryReferenceGraphReport,
    analyze_supplied_binary_references,
    component_fixture,
    verify_supplied_binary_references,
)


class BinaryReferenceGraphTests(unittest.TestCase):
    def test_reachability_and_cycles_are_only_supplied_graph_facts(self) -> None:
        report = analyze_supplied_binary_references(component_fixture()).to_dict()
        self.assertEqual(report["reachable_symbol_ids"], ["entry", "helper", "parse"])
        self.assertEqual(report["unreachable_symbol_ids"], ["unused"])
        self.assertEqual(report["recursive_symbol_groups"], [["helper", "parse"]])
        self.assertEqual(report["supplied_call_reference_count"], 3)
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["binary_bytes_read"])
        self.assertFalse(report["references_disassembled_or_verified"])

    def test_unreachable_self_cycle_is_still_reported(self) -> None:
        model = component_fixture()
        model["functions"][-1]["call_symbol_ids"] = ["unused"]
        report = analyze_supplied_binary_references(model).to_dict()
        self.assertEqual(report["recursive_symbol_groups"], [["helper", "parse"], ["unused"]])

    def test_incomplete_inventory_is_unknown(self) -> None:
        model = component_fixture()
        model["function_inventory_complete"] = False
        report = analyze_supplied_binary_references(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["unknown_count"], 1)

    def test_rejects_duplicate_and_unresolved_references(self) -> None:
        model = component_fixture()
        model["functions"].append(copy.deepcopy(model["functions"][0]))
        with self.assertRaises(BinaryReferenceGraphError):
            analyze_supplied_binary_references(model)
        model = component_fixture()
        model["functions"][0]["call_symbol_ids"] = ["missing"]
        with self.assertRaises(BinaryReferenceGraphError):
            analyze_supplied_binary_references(model)
        model = component_fixture()
        model["entry_symbol_ids"] = ["entry", "entry"]
        with self.assertRaises(BinaryReferenceGraphError):
            analyze_supplied_binary_references(model)

    def test_original_source_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_binary_references(model)
        self.assertEqual(
            verify_supplied_binary_references(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["functions"][1]["call_symbol_ids"] = []
        with self.assertRaises(BinaryReferenceGraphError):
            verify_supplied_binary_references(report, model=changed)
        with self.assertRaises(BinaryReferenceGraphError):
            BinaryReferenceGraphReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
