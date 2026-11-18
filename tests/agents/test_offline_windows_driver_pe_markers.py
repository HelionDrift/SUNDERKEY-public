"""Source-bound synthetic Windows driver PE marker tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_windows_driver_pe_markers import (
    WindowsDriverPeMarkerError,
    WindowsDriverPeMarkerReport,
    analyze_supplied_windows_driver_pe_markers,
    component_fixture,
    verify_supplied_windows_driver_pe_markers,
)


class WindowsDriverPeMarkerTests(unittest.TestCase):
    def test_marker_bits_are_not_driver_or_kernel_proof(self) -> None:
        body = analyze_supplied_windows_driver_pe_markers(component_fixture()).to_dict()
        self.assertTrue(body["marker_flags_declared"]["native_subsystem"])
        self.assertTrue(body["marker_flags_declared"]["coff_system"])
        self.assertTrue(body["marker_flags_declared"]["wdm_driver"])
        self.assertEqual(body["missing_required_marker_ids"], [])
        self.assertEqual(body["disposition"], "unknown")
        self.assertFalse(body["driver_identity_verified"])
        self.assertFalse(body["kernel_loading_verified"])
        self.assertEqual(body["candidate_count"], 0)

    def test_missing_required_marker_is_reported_without_finding(self) -> None:
        model = component_fixture()
        model["required_marker_ids"].append("force_integrity")
        body = analyze_supplied_windows_driver_pe_markers(model).to_dict()
        self.assertEqual(body["missing_required_marker_ids"], ["force_integrity"])
        self.assertFalse(body["finding_claimed"])

    def test_duplicate_marker_and_nonsynthetic_input_rejected(self) -> None:
        model = component_fixture()
        model["required_marker_ids"].append("wdm_driver")
        with self.assertRaises(WindowsDriverPeMarkerError):
            analyze_supplied_windows_driver_pe_markers(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(WindowsDriverPeMarkerError):
            analyze_supplied_windows_driver_pe_markers(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_windows_driver_pe_markers(model)
        self.assertEqual(
            verify_supplied_windows_driver_pe_markers(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["required_marker_ids"].pop()
        with self.assertRaises(WindowsDriverPeMarkerError):
            verify_supplied_windows_driver_pe_markers(report, model=changed)
        with self.assertRaises(WindowsDriverPeMarkerError):
            WindowsDriverPeMarkerReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
