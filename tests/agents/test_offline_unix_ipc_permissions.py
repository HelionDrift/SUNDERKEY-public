"""Synthetic Unix IPC permission projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_unix_ipc_permissions import (
    UnixIpcPermissionError,
    UnixIpcPermissionReport,
    analyze_supplied_unix_ipc,
    component_fixture,
    verify_supplied_unix_ipc,
)


class UnixIpcPermissionTests(unittest.TestCase):
    def test_overlap_is_not_unauthorized_access(self) -> None:
        report = analyze_supplied_unix_ipc(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_artifact_ids"], ["socket-a"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["permissions_verified"])
        self.assertFalse(report["ipc_connected"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_nonoverlap_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["artifacts"][0]["world_writable_declared"] = False
        report = analyze_supplied_unix_ipc(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_artifact_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["artifacts"].append(copy.deepcopy(model["artifacts"][0]))
        with self.assertRaises(UnixIpcPermissionError):
            analyze_supplied_unix_ipc(model)
        model = component_fixture()
        model["artifacts"][0]["artifact_kind"] = "unknown"
        with self.assertRaises(UnixIpcPermissionError):
            analyze_supplied_unix_ipc(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(UnixIpcPermissionError):
            analyze_supplied_unix_ipc(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_unix_ipc(model)
        self.assertEqual(
            verify_supplied_unix_ipc(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["artifacts"][0]["world_writable_declared"] = False
        with self.assertRaises(UnixIpcPermissionError):
            verify_supplied_unix_ipc(report, model=changed)
        with self.assertRaises(UnixIpcPermissionError):
            UnixIpcPermissionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
