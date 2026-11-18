"""Synthetic BLE GATT permission projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ble_gatt_permissions import (
    BleGattPermissionError,
    BleGattPermissionReport,
    analyze_supplied_ble_gatt,
    component_fixture,
    verify_supplied_ble_gatt,
)


class BleGattPermissionTests(unittest.TestCase):
    def test_declared_gap_is_not_device_finding(self) -> None:
        report = analyze_supplied_ble_gatt(component_fixture()).to_dict()
        self.assertEqual(report["declared_control_gap_characteristic_ids"], ["char-a"])
        self.assertEqual(
            report["characteristic_projections"][0]["missing_declared_control_keys"],
            ["authentication"],
        )
        self.assertFalse(report["device_connected"])
        self.assertFalse(report["gatt_discovery_performed"])
        self.assertFalse(report["link_security_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_complete_declaration_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["characteristics"][0]["authentication_declared"] = True
        report = analyze_supplied_ble_gatt(model).to_dict()
        self.assertEqual(report["declared_control_gap_characteristic_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_service_duplicate_operation_and_nonfixture(self) -> None:
        model = component_fixture()
        model["characteristics"][0]["service_id"] = "missing"
        with self.assertRaises(BleGattPermissionError):
            analyze_supplied_ble_gatt(model)
        model = component_fixture()
        model["characteristics"][0]["operation_ids"] = ["read", "read"]
        with self.assertRaises(BleGattPermissionError):
            analyze_supplied_ble_gatt(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(BleGattPermissionError):
            analyze_supplied_ble_gatt(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ble_gatt(model)
        self.assertEqual(
            verify_supplied_ble_gatt(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["characteristics"][0]["authentication_declared"] = True
        with self.assertRaises(BleGattPermissionError):
            verify_supplied_ble_gatt(report, model=changed)
        with self.assertRaises(BleGattPermissionError):
            BleGattPermissionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
