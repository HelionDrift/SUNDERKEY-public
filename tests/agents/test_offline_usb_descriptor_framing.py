"""Supplied USB descriptor framing and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_usb_descriptor_framing import (
    UsbDescriptorFramingError,
    analyze_supplied_usb_descriptors,
    component_fixture,
    verify_supplied_usb_descriptors,
    verify_supplied_usb_descriptors_bytes,
)


class UsbDescriptorFramingTests(unittest.TestCase):
    def test_invalid_framing_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_usb_descriptors(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["issues"], [{"offset": 2, "issue": "invalid_descriptor_length"}])
        self.assertEqual(body["parsed_descriptors"][0]["descriptor_type"], 1)
        self.assertFalse(body["usb_device_contacted"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_usb_descriptors(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_usb_descriptors_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_complete_unknown_descriptor_and_incomplete_capture(self) -> None:
        model = component_fixture()
        model["descriptor_bytes"] = [3, 255, 17]
        body = analyze_supplied_usb_descriptors(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["parsed_descriptors"][0]["descriptor_type"], 255)
        model["capture_complete"] = False
        self.assertEqual(analyze_supplied_usb_descriptors(model).to_dict()["unknown_count"], 1)

    def test_truncated_descriptor_and_short_header(self) -> None:
        model = component_fixture()
        model["descriptor_bytes"] = [5, 1, 0]
        self.assertEqual(
            analyze_supplied_usb_descriptors(model).to_dict()["issues"][0]["issue"],
            "truncated_descriptor",
        )
        model["descriptor_bytes"] = [1]
        self.assertEqual(
            analyze_supplied_usb_descriptors(model).to_dict()["issues"][0]["issue"],
            "short_descriptor_header",
        )

    def test_rejects_invalid_bytes_and_replay_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_usb_descriptors(model)
        for invalid in (-1, 256, True):
            changed = copy.deepcopy(model)
            changed["descriptor_bytes"][0] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(UsbDescriptorFramingError):
                analyze_supplied_usb_descriptors(changed)
        changed = copy.deepcopy(model)
        changed["source_id"] = "other"
        with self.assertRaises(UsbDescriptorFramingError):
            verify_supplied_usb_descriptors(report, model=changed)
        with self.assertRaises(UsbDescriptorFramingError):
            verify_supplied_usb_descriptors(report.to_dict(), model=model)
        with self.assertRaises(UsbDescriptorFramingError):
            verify_supplied_usb_descriptors_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()
