"""Synthetic desktop IPC graph projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_desktop_ipc_boundary import (
    DesktopIpcBoundaryError,
    DesktopIpcBoundaryReport,
    analyze_supplied_desktop_ipc,
    component_fixture,
    verify_supplied_desktop_ipc,
)


class DesktopIpcBoundaryTests(unittest.TestCase):
    def test_unguarded_path_is_only_a_projection(self) -> None:
        report = analyze_supplied_desktop_ipc(component_fixture()).to_dict()
        self.assertEqual(report["declared_unguarded_privileged_paths"], [{
            "node_id": "helper", "declared_unguarded_path": ["user", "app", "helper"],
        }])
        self.assertFalse(report["application_inspected"])
        self.assertFalse(report["ipc_executed"])
        self.assertFalse(report["privilege_transition_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_guard_blocks_abstract_path_and_incomplete_model_is_unknown(self) -> None:
        model = component_fixture()
        model["edges"][1]["guard_declared"] = True
        model["inventory_complete"] = False
        report = analyze_supplied_desktop_ipc(model).to_dict()
        self.assertEqual(report["declared_unguarded_privileged_paths"], [])
        self.assertEqual(report["declared_guarded_edge_count"], 1)
        self.assertEqual(report["disposition"], "unknown")

    def test_cycle_does_not_expand_path_and_duplicates_reject(self) -> None:
        model = component_fixture()
        model["edges"].append({
            "source_id": "app", "destination_id": "user", "guard_declared": False,
        })
        report = analyze_supplied_desktop_ipc(model).to_dict()
        self.assertEqual(
            report["declared_unguarded_privileged_paths"][0]["declared_unguarded_path"],
            ["user", "app", "helper"],
        )
        model["edges"].append(copy.deepcopy(model["edges"][0]))
        with self.assertRaises(DesktopIpcBoundaryError):
            analyze_supplied_desktop_ipc(model)

    def test_rejects_nonfixture_and_privileged_entry(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(DesktopIpcBoundaryError):
            analyze_supplied_desktop_ipc(model)
        model = component_fixture()
        model["entry_node_ids"] = ["helper"]
        with self.assertRaises(DesktopIpcBoundaryError):
            analyze_supplied_desktop_ipc(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_desktop_ipc(model)
        self.assertEqual(
            verify_supplied_desktop_ipc(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["edges"][1]["guard_declared"] = True
        with self.assertRaises(DesktopIpcBoundaryError):
            verify_supplied_desktop_ipc(report, model=changed)
        with self.assertRaises(DesktopIpcBoundaryError):
            DesktopIpcBoundaryReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
