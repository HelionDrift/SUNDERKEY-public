"""Firmware emulation trace declaration and original-model replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_firmware_emulation_trace import (
    FirmwareEmulationTraceReport,
    analyze_supplied_firmware_emulation_trace,
    component_fixture,
    verify_supplied_firmware_emulation_trace,
    verify_supplied_firmware_emulation_trace_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class FirmwareEmulationTraceTests(unittest.TestCase):
    def test_candidate_negative_and_replay(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        example = json.loads(
            (ROOT / "examples/offline-firmware-emulation-trace-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_firmware_emulation_trace(model)
        body = report.to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 0))
        self.assertEqual(body["emulation_projections"][1]["issues"], [])
        self.assertFalse(body["emulator_executed"])
        self.assertFalse(body["firmware_executed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_firmware_emulation_trace(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_firmware_emulation_trace_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_incomplete_and_tampered_fail_closed(self) -> None:
        model = component_fixture()
        model["emulation_runs"][0]["trace_complete"] = False
        body = analyze_supplied_firmware_emulation_trace(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        self.assertIsNone(body["emulation_projections"][0]["issues"])
        model = component_fixture()
        report = analyze_supplied_firmware_emulation_trace(model)
        changed = copy.deepcopy(model)
        changed["emulation_runs"][0]["declared_trace_sha256"] = "sha256:" + "a" * 64
        with self.assertRaises(ValueError):
            verify_supplied_firmware_emulation_trace(report, model=changed)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_emulation_trace(report.to_dict(), model=model)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_emulation_trace_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            FirmwareEmulationTraceReport({})
        duplicate = copy.deepcopy(model)
        duplicate["emulation_runs"][1]["image_id"] = duplicate["emulation_runs"][0]["image_id"]
        with self.assertRaises(ValueError):
            analyze_supplied_firmware_emulation_trace(duplicate)


if __name__ == "__main__":
    unittest.main()
