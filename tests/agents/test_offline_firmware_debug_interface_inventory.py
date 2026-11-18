"""Firmware debug-interface declaration and original-model replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_firmware_debug_interface_inventory import (
    FirmwareDebugInterfaceInventoryReport,
    analyze_supplied_firmware_debug_interface_inventory,
    component_fixture,
    verify_supplied_firmware_debug_interface_inventory,
    verify_supplied_firmware_debug_interface_inventory_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class FirmwareDebugInterfaceInventoryTests(unittest.TestCase):
    def test_candidate_negative_and_replay(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        example = json.loads(
            (
                ROOT / "examples/offline-firmware-debug-interface-inventory-component.json"
            ).read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_firmware_debug_interface_inventory(model)
        body = report.to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 0))
        self.assertEqual(body["interface_projections"][1]["issues"], [])
        self.assertFalse(body["debug_probe_connected"])
        self.assertFalse(body["interface_state_observed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_firmware_debug_interface_inventory(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_firmware_debug_interface_inventory_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_unknown_and_tampered_fail_closed(self) -> None:
        model = component_fixture()
        model["interfaces"][0]["declared_enabled"] = None
        body = analyze_supplied_firmware_debug_interface_inventory(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        self.assertIsNone(body["interface_projections"][0]["issues"])
        model = component_fixture()
        report = analyze_supplied_firmware_debug_interface_inventory(model)
        changed = copy.deepcopy(model)
        changed["interfaces"][0]["declared_enabled"] = False
        with self.assertRaises(ValueError):
            verify_supplied_firmware_debug_interface_inventory(report, model=changed)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_debug_interface_inventory(report.to_dict(), model=model)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_debug_interface_inventory_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            FirmwareDebugInterfaceInventoryReport({})
        invalid = copy.deepcopy(model)
        invalid["interfaces"][0]["interface_kind"] = "other"
        with self.assertRaises(ValueError):
            analyze_supplied_firmware_debug_interface_inventory(invalid)


if __name__ == "__main__":
    unittest.main()
