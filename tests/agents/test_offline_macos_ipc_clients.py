"""Synthetic macOS IPC-client projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_macos_ipc_clients import (
    MacosIpcClientError,
    MacosIpcClientReport,
    analyze_supplied_ipc_clients,
    component_fixture,
    verify_supplied_ipc_clients,
)


class MacosIpcClientTests(unittest.TestCase):
    def test_client_gap_is_not_ipc_access(self) -> None:
        report = analyze_supplied_ipc_clients(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_interface_ids"], ["service-a"])
        self.assertEqual(
            report["interface_projections"][0]["outside_supplied_policy_client_ids"],
            ["client-b"],
        )
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["ipc_interface_connected"])
        self.assertFalse(report["message_sent"])
        self.assertEqual(report["candidate_count"], 0)

    def test_approved_clients_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["interfaces"][0]["declared_client_ids"] = ["client-a"]
        report = analyze_supplied_ipc_clients(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_interface_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["interfaces"].append(copy.deepcopy(model["interfaces"][0]))
        with self.assertRaises(MacosIpcClientError):
            analyze_supplied_ipc_clients(model)
        model = component_fixture()
        model["interfaces"][0]["interface_kind"] = "unknown"
        with self.assertRaises(MacosIpcClientError):
            analyze_supplied_ipc_clients(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MacosIpcClientError):
            analyze_supplied_ipc_clients(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ipc_clients(model)
        self.assertEqual(
            verify_supplied_ipc_clients(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["interfaces"][0]["declared_client_ids"] = ["client-a"]
        with self.assertRaises(MacosIpcClientError):
            verify_supplied_ipc_clients(report, model=changed)
        with self.assertRaises(MacosIpcClientError):
            MacosIpcClientReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
