"""Synthetic Linux logging-route projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_linux_logging_routes import (
    LinuxLoggingRouteError,
    LinuxLoggingRouteReport,
    analyze_supplied_logging_routes,
    component_fixture,
    verify_supplied_logging_routes,
)


class LinuxLoggingRouteTests(unittest.TestCase):
    def test_disabled_sink_is_not_impairment_proof(self) -> None:
        report = analyze_supplied_logging_routes(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_stream_ids"], ["security"])
        self.assertFalse(report["host_connected"])
        self.assertFalse(report["log_record_read"])
        self.assertFalse(report["sink_connected"])
        self.assertFalse(report["control_changed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_enabled_sink_and_missing_required_stream(self) -> None:
        model = component_fixture()
        model["sink_states"][0]["enabled_declared"] = True
        model["required_stream_ids"].append("audit")
        report = analyze_supplied_logging_routes(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_stream_ids"], [])
        self.assertEqual(report["missing_required_stream_ids"], ["audit"])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_unknown_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["stream_routes"].append(copy.deepcopy(model["stream_routes"][0]))
        with self.assertRaises(LinuxLoggingRouteError):
            analyze_supplied_logging_routes(model)
        model = component_fixture()
        model["stream_routes"][0]["sink_ids"] = ["unknown"]
        with self.assertRaises(LinuxLoggingRouteError):
            analyze_supplied_logging_routes(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(LinuxLoggingRouteError):
            analyze_supplied_logging_routes(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_logging_routes(model)
        self.assertEqual(
            verify_supplied_logging_routes(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["sink_states"][0]["enabled_declared"] = True
        with self.assertRaises(LinuxLoggingRouteError):
            verify_supplied_logging_routes(report, model=changed)
        with self.assertRaises(LinuxLoggingRouteError):
            LinuxLoggingRouteReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
