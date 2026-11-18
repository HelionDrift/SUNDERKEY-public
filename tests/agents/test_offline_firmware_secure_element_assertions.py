"""Firmware secure-element declaration and original-model replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_firmware_secure_element_assertions import (
    FirmwareSecureElementAssertionsReport,
    analyze_supplied_firmware_secure_element_assertions,
    component_fixture,
    verify_supplied_firmware_secure_element_assertions,
    verify_supplied_firmware_secure_element_assertions_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class FirmwareSecureElementAssertionsTests(unittest.TestCase):
    def test_candidate_negative_and_replay(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        example = json.loads(
            (
                ROOT / "examples/offline-firmware-secure-element-assertions-component.json"
            ).read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_firmware_secure_element_assertions(model)
        body = report.to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 0))
        self.assertEqual(len(body["asset_projections"][0]["issues"]), 2)
        self.assertEqual(body["asset_projections"][1]["issues"], [])
        self.assertFalse(body["attestation_verified"])
        self.assertFalse(body["key_material_accessed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_firmware_secure_element_assertions(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_firmware_secure_element_assertions_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_unknown_and_tampered_fail_closed(self) -> None:
        model = component_fixture()
        model["assets"][0]["hardware_backed_declared"] = None
        body = analyze_supplied_firmware_secure_element_assertions(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        self.assertIsNone(body["asset_projections"][0]["issues"])
        model = component_fixture()
        report = analyze_supplied_firmware_secure_element_assertions(model)
        changed = copy.deepcopy(model)
        changed["assets"][0]["supplied_identity_sha256"] = "sha256:" + "a" * 64
        with self.assertRaises(ValueError):
            verify_supplied_firmware_secure_element_assertions(report, model=changed)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_secure_element_assertions(report.to_dict(), model=model)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_secure_element_assertions_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            FirmwareSecureElementAssertionsReport({})
        invalid = copy.deepcopy(model)
        invalid["assets"][0]["expected_identity_sha256"] = "sha256:bad"
        with self.assertRaises(ValueError):
            analyze_supplied_firmware_secure_element_assertions(invalid)


if __name__ == "__main__":
    unittest.main()
