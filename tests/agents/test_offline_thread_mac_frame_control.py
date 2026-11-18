"""Source-bound synthetic Thread MAC frame-control tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_thread_mac_frame_control import (
    ThreadMacFrameControlError,
    ThreadMacFrameControlReport,
    analyze_supplied_thread_frame_control,
    component_fixture,
    verify_supplied_thread_frame_control,
)


class ThreadMacFrameControlTests(unittest.TestCase):
    def test_data_security_bit_is_only_a_static_policy_projection(self) -> None:
        body = analyze_supplied_thread_frame_control(component_fixture()).to_dict()
        self.assertEqual(body["outside_supplied_policy_word_ids"], ["unsecured-data"])
        secured = body["word_projections"][0]
        self.assertEqual(secured["frame_type"], 1)
        self.assertEqual(secured["frame_version"], 2)
        self.assertTrue(secured["security_enabled_bit_declared"])
        self.assertFalse(body["mic_verified"])
        self.assertFalse(body["radio_interacted"])
        self.assertEqual(body["candidate_count"], 0)

    def test_reserved_values_and_incomplete_inventory_remain_unknown(self) -> None:
        model = component_fixture()
        model["word_inventory_complete"] = False
        model["words"][0]["frame_control_le_hex"] = "29b8"
        body = analyze_supplied_thread_frame_control(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertIn("one_or_more_unsupported_field_values", body["uncertainty"])

    def test_malformed_word_and_duplicate_id_rejected(self) -> None:
        model = component_fixture()
        model["words"][0]["frame_control_le_hex"] = "29a800"
        with self.assertRaises(ThreadMacFrameControlError):
            analyze_supplied_thread_frame_control(model)
        model = component_fixture()
        model["words"][1]["word_id"] = "secured-data"
        with self.assertRaises(ThreadMacFrameControlError):
            analyze_supplied_thread_frame_control(model)

    def test_nonsynthetic_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(ThreadMacFrameControlError):
            analyze_supplied_thread_frame_control(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_thread_frame_control(model)
        self.assertEqual(
            verify_supplied_thread_frame_control(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["words"][0]["frame_control_le_hex"] = "21a8"
        with self.assertRaises(ThreadMacFrameControlError):
            verify_supplied_thread_frame_control(report, model=changed)
        with self.assertRaises(ThreadMacFrameControlError):
            ThreadMacFrameControlReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
