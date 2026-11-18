"""Bounded supplied-frame projections for a custom protocol hypothesis."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_custom_protocol_framing import (
    CustomProtocolFramingError,
    CustomProtocolFramingReport,
    analyze_supplied_custom_protocol_framing,
    component_fixture,
    verify_supplied_custom_protocol_framing,
)


class CustomProtocolFramingTests(unittest.TestCase):
    def test_exact_frame_lengths_and_direction_kinds(self) -> None:
        report = analyze_supplied_custom_protocol_framing(component_fixture()).to_dict()
        self.assertEqual(report["supplied_frame_count"], 2)
        self.assertEqual(report["length_mismatch_frame_ids"], [])
        self.assertEqual(
            report["direction_kind_pairs"],
            [
                {"direction": "client_to_server", "kind_hex": "01"},
                {"direction": "server_to_client", "kind_hex": "02"},
            ],
        )
        self.assertFalse(report["framing_hypothesis_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_mismatch_is_structural_only(self) -> None:
        model = component_fixture()
        model["frames"][0]["wire_hex"] = "010003aabb"
        report = analyze_supplied_custom_protocol_framing(model).to_dict()
        self.assertEqual(report["length_mismatch_frame_ids"], ["f1"])
        self.assertEqual(report["frame_projections"][0]["observed_payload_bytes"], 2)
        self.assertFalse(report["finding_claimed"])

    def test_rejects_overlap_duplicate_and_short_frame(self) -> None:
        model = component_fixture()
        model["framing"]["length_offset"] = 0
        with self.assertRaises(CustomProtocolFramingError):
            analyze_supplied_custom_protocol_framing(model)
        model = component_fixture()
        model["frames"][1]["frame_id"] = "f1"
        with self.assertRaises(CustomProtocolFramingError):
            analyze_supplied_custom_protocol_framing(model)
        model = component_fixture()
        model["frames"][0]["wire_hex"] = "01"
        with self.assertRaises(CustomProtocolFramingError):
            analyze_supplied_custom_protocol_framing(model)

    def test_incomplete_capture_and_original_model_replay(self) -> None:
        model = component_fixture()
        model["capture_inventory_complete"] = False
        report = analyze_supplied_custom_protocol_framing(model)
        self.assertEqual(report.to_dict()["disposition"], "unknown")
        self.assertEqual(
            verify_supplied_custom_protocol_framing(
                report, model=copy.deepcopy(model)
            ).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["frames"][0]["wire_hex"] = "010003aabb"
        with self.assertRaises(CustomProtocolFramingError):
            verify_supplied_custom_protocol_framing(report, model=changed)
        with self.assertRaises(CustomProtocolFramingError):
            CustomProtocolFramingReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
