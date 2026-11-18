"""Firmware tamper and provenance declaration and original-model replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_firmware_tamper_provenance import (
    FirmwareTamperProvenanceReport,
    analyze_supplied_firmware_tamper_provenance,
    component_fixture,
    verify_supplied_firmware_tamper_provenance,
    verify_supplied_firmware_tamper_provenance_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class FirmwareTamperProvenanceTests(unittest.TestCase):
    def test_candidate_negative_and_replay(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        example = json.loads(
            (ROOT / "examples/offline-firmware-tamper-provenance-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_firmware_tamper_provenance(model)
        body = report.to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 0))
        self.assertEqual(len(body["component_projections"][0]["issues"]), 2)
        self.assertEqual(body["component_projections"][1]["issues"], [])
        self.assertFalse(body["physical_inspection_performed"])
        self.assertFalse(body["supply_chain_authenticated"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_firmware_tamper_provenance(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_firmware_tamper_provenance_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_unknown_and_tampered_fail_closed(self) -> None:
        model = component_fixture()
        model["components"][0]["declared_seal_state"] = "unknown"
        body = analyze_supplied_firmware_tamper_provenance(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        self.assertIsNone(body["component_projections"][0]["issues"])
        model = component_fixture()
        report = analyze_supplied_firmware_tamper_provenance(model)
        changed = copy.deepcopy(model)
        changed["components"][0]["declared_seal_state"] = "intact"
        with self.assertRaises(ValueError):
            verify_supplied_firmware_tamper_provenance(report, model=changed)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_tamper_provenance(report.to_dict(), model=model)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_tamper_provenance_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            FirmwareTamperProvenanceReport({})
        invalid = copy.deepcopy(model)
        invalid["components"][0]["declared_seal_state"] = "maybe"
        with self.assertRaises(ValueError):
            analyze_supplied_firmware_tamper_provenance(invalid)


if __name__ == "__main__":
    unittest.main()
