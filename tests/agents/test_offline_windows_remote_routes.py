"""Synthetic Windows remote-route policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_windows_remote_routes import (
    WindowsRemoteRouteError,
    WindowsRemoteRouteReport,
    analyze_supplied_remote_routes,
    component_fixture,
    verify_supplied_remote_routes,
)


class WindowsRemoteRouteTests(unittest.TestCase):
    def test_route_gap_is_not_lateral_movement(self) -> None:
        report = analyze_supplied_remote_routes(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_session_ids"], ["session-a"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["remote_session_opened"])
        self.assertFalse(report["credential_used"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_approved_route_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["sessions"][0]["destination_host_id"] = "host-b"
        report = analyze_supplied_remote_routes(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_session_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["sessions"].append(copy.deepcopy(model["sessions"][0]))
        with self.assertRaises(WindowsRemoteRouteError):
            analyze_supplied_remote_routes(model)
        model = component_fixture()
        model["sessions"][0]["channel"] = "unknown"
        with self.assertRaises(WindowsRemoteRouteError):
            analyze_supplied_remote_routes(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(WindowsRemoteRouteError):
            analyze_supplied_remote_routes(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_remote_routes(model)
        self.assertEqual(
            verify_supplied_remote_routes(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["sessions"][0]["session_declared"] = False
        with self.assertRaises(WindowsRemoteRouteError):
            verify_supplied_remote_routes(report, model=changed)
        with self.assertRaises(WindowsRemoteRouteError):
            WindowsRemoteRouteReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
