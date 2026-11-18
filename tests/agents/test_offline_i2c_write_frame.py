"""Synthetic I2C write-frame projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_i2c_write_frame import (
    I2cWriteFrameError,
    I2cWriteFrameReport,
    analyze_supplied_i2c_write,
    component_fixture,
    verify_supplied_i2c_write,
)


class I2cWriteFrameTests(unittest.TestCase):
    def test_declared_write_frame_is_not_bus_finding(self) -> None:
        report = analyze_supplied_i2c_write(component_fixture()).to_dict()
        self.assertEqual(report["final_declared_state"], "done")
        self.assertEqual(report["supplied_data_octet_count"], 1)
        self.assertEqual(report["declared_framing_deviation_event_ids"], [])
        self.assertFalse(report["hardware_connected"])
        self.assertFalse(report["bus_capture_verified"])
        self.assertFalse(report["protocol_conformance_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_nack_and_out_of_order_event_remain_declarations(self) -> None:
        model = component_fixture()
        model["events"][2]["kind"] = "NACK"
        report = analyze_supplied_i2c_write(model).to_dict()
        self.assertIn("e4", report["declared_framing_deviation_event_ids"])
        self.assertEqual(report["candidate_count"], 0)
        model = component_fixture()
        model["inventory_complete"] = False
        self.assertEqual(analyze_supplied_i2c_write(model).to_dict()["disposition"], "unknown")

    def test_rejects_unbounded_or_nonfixture_input(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(I2cWriteFrameError):
            analyze_supplied_i2c_write(model)
        model = component_fixture()
        model["events"][1]["byte_hex"] = "A0"
        with self.assertRaises(I2cWriteFrameError):
            analyze_supplied_i2c_write(model)
        model = component_fixture()
        model["events"][1]["byte_hex"] = "a1"
        with self.assertRaises(I2cWriteFrameError):
            analyze_supplied_i2c_write(model)
        model = component_fixture()
        model["events"].append(copy.deepcopy(model["events"][0]))
        with self.assertRaises(I2cWriteFrameError):
            analyze_supplied_i2c_write(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_i2c_write(model)
        self.assertEqual(
            verify_supplied_i2c_write(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["events"][3]["byte_hex"] = "43"
        with self.assertRaises(I2cWriteFrameError):
            verify_supplied_i2c_write(report, model=changed)
        with self.assertRaises(I2cWriteFrameError):
            I2cWriteFrameReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
