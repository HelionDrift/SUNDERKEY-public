"""Supplied BACnet Device identity arithmetic and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_bacnet_device_identity import (
    BacnetDeviceIdentityError,
    analyze_supplied_bacnet_device_identity,
    component_fixture,
    verify_supplied_bacnet_device_identity,
    verify_supplied_bacnet_device_identity_bytes,
)


class BacnetDeviceIdentityTests(unittest.TestCase):
    def test_duplicate_device_identifier_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_bacnet_device_identity(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["duplicate_instance_groups"][0]["instance"], 17)
        self.assertEqual(
            body["duplicate_instance_groups"][0]["device_ids"],
            ["controller-a", "controller-b"],
        )
        self.assertFalse(body["network_contacted"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_bacnet_device_identity(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_bacnet_device_identity_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_distinct_identifiers_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["devices"][1]["object_identifier"] = (8 << 22) | 19
        self.assertEqual(
            analyze_supplied_bacnet_device_identity(model).to_dict()["candidate_count"], 0
        )
        model["inventory_complete"] = False
        self.assertEqual(
            analyze_supplied_bacnet_device_identity(model).to_dict()["unknown_count"], 1
        )

    def test_rejects_invalid_device_identifiers(self) -> None:
        for identifier in (-1, 1 << 32, (7 << 22) | 17, (8 << 22) | ((1 << 22) - 1)):
            model = component_fixture()
            model["devices"][0]["object_identifier"] = identifier
            with self.subTest(identifier=identifier), self.assertRaises(BacnetDeviceIdentityError):
                analyze_supplied_bacnet_device_identity(model)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_bacnet_device_identity(model)
        changed = copy.deepcopy(model)
        changed["internetwork_id"] = "different-network"
        with self.assertRaises(BacnetDeviceIdentityError):
            verify_supplied_bacnet_device_identity(report, model=changed)
        with self.assertRaises(BacnetDeviceIdentityError):
            verify_supplied_bacnet_device_identity(report.to_dict(), model=model)
        with self.assertRaises(BacnetDeviceIdentityError):
            verify_supplied_bacnet_device_identity_bytes(b"{}", model=model)

    def test_rejects_duplicate_device_rows(self) -> None:
        model = component_fixture()
        model["devices"].append(copy.deepcopy(model["devices"][0]))
        with self.assertRaises(BacnetDeviceIdentityError):
            analyze_supplied_bacnet_device_identity(model)


if __name__ == "__main__":
    unittest.main()
