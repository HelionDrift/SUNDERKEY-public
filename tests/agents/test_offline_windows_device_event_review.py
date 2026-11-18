"""Synthetic Windows 6416 tests preserve device-use uncertainty."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_windows_device_event_review import (
    WindowsDeviceEventReviewError,
    WindowsDeviceEventReviewReport,
    analyze_supplied_windows_device_event,
    component_fixture,
    verify_supplied_windows_device_event,
)


class WindowsDeviceEventReviewTests(unittest.TestCase):
    def test_recognition_is_not_media_access_or_device_placement(self) -> None:
        report = analyze_supplied_windows_device_event(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["event_id"], 6416)
        self.assertTrue(body["external_device_recognition_declared"])
        self.assertTrue(body["device_matches_supplied_expectation"])
        self.assertFalse(body["removable_storage_confirmed"])
        self.assertFalse(body["media_read_or_written"])
        self.assertFalse(body["device_placed_by_actor"])
        self.assertNotIn("USBSTOR", report.to_json())

    def test_device_mismatch_is_not_a_finding(self) -> None:
        model = component_fixture()
        model["expected_device_id"] = "USBSTOR\\SYNTHETIC\\0002"
        body = analyze_supplied_windows_device_event(model).to_dict()
        self.assertFalse(body["device_matches_supplied_expectation"])
        self.assertEqual(body["candidate_count"], 0)

    def test_bad_event_id_duplicate_data_and_dtd_reject(self) -> None:
        model = component_fixture()
        model["event_xml"] = model["event_xml"].replace(
            "<EventID>6416</EventID>", "<EventID>4663</EventID>"
        )
        with self.assertRaises(WindowsDeviceEventReviewError):
            analyze_supplied_windows_device_event(model)
        model = component_fixture()
        model["event_xml"] = model["event_xml"].replace(
            "</EventData>", '<Data Name="DeviceId">duplicate</Data></EventData>'
        )
        with self.assertRaises(WindowsDeviceEventReviewError):
            analyze_supplied_windows_device_event(model)
        model = component_fixture()
        model["event_xml"] = "<!DOCTYPE Event>" + model["event_xml"]
        with self.assertRaises(WindowsDeviceEventReviewError):
            analyze_supplied_windows_device_event(model)

    def test_nonsynthetic_source_rejects(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(WindowsDeviceEventReviewError):
            analyze_supplied_windows_device_event(model)

    def test_replay_requires_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_windows_device_event(model)
        self.assertEqual(
            verify_supplied_windows_device_event(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["expected_device_id"] = "USBSTOR\\SYNTHETIC\\0002"
        with self.assertRaises(WindowsDeviceEventReviewError):
            verify_supplied_windows_device_event(report, model=changed)
        with self.assertRaises(WindowsDeviceEventReviewError):
            WindowsDeviceEventReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
