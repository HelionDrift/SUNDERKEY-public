"""Bounded HMI tag mapping declaration and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_ot_hmi_tag_mapping import (
    OtHmiTagMappingError,
    analyze_supplied_ot_hmi_tag_mapping,
    component_fixture,
    verify_supplied_ot_hmi_tag_mapping,
    verify_supplied_ot_hmi_tag_mapping_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class OtHmiTagMappingTests(unittest.TestCase):
    def test_candidate_is_only_a_supplied_mapping_difference(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        example = json.loads(
            (ROOT / "examples/offline-ot-hmi-tag-mapping-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        body = analyze_supplied_ot_hmi_tag_mapping(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 0))
        self.assertEqual(len(body["tag_projections"][0]["issues"]), 2)
        self.assertFalse(body["hmi_or_scada_contacted"])
        self.assertFalse(body["effective_write_access_verified"])
        self.assertFalse(body["process_safety_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        report = analyze_supplied_ot_hmi_tag_mapping(model)
        self.assertEqual(
            verify_supplied_ot_hmi_tag_mapping(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_ot_hmi_tag_mapping_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_negative_and_missing_observations_fail_closed(self) -> None:
        model = component_fixture()
        tag = model["tag_bindings"][0]
        tag["project_point_ref"] = tag["baseline_point_ref"]
        tag["project_access_mode"] = tag["baseline_access_mode"]
        self.assertEqual(analyze_supplied_ot_hmi_tag_mapping(model).to_dict()["candidate_count"], 0)
        tag["project_access_mode"] = None
        body = analyze_supplied_ot_hmi_tag_mapping(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        self.assertIsNone(body["tag_projections"][0]["issues"])
        tag["project_access_mode"] = "read_write"
        tag["context_complete"] = False
        self.assertEqual(analyze_supplied_ot_hmi_tag_mapping(model).to_dict()["candidate_count"], 0)
        tag["context_complete"] = True
        model["inventory_complete"] = False
        body = analyze_supplied_ot_hmi_tag_mapping(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 2))

    def test_malformed_and_tampered_inputs_fail(self) -> None:
        model = component_fixture()
        with self.assertRaises(ValueError):
            analyze_supplied_ot_hmi_tag_mapping(
                {**model, "tag_bindings": tuple(model["tag_bindings"])}
            )
        with self.assertRaises(ValueError):
            analyze_supplied_ot_hmi_tag_mapping({**model, "inventory_complete": 1})
        duplicate = copy.deepcopy(model)
        duplicate["tag_bindings"][1]["tag_id"] = duplicate["tag_bindings"][0]["tag_id"]
        with self.assertRaises(OtHmiTagMappingError):
            analyze_supplied_ot_hmi_tag_mapping(duplicate)
        malformed = copy.deepcopy(model)
        malformed["tag_bindings"][0]["project_access_mode"] = "write_only"
        with self.assertRaises(ValueError):
            analyze_supplied_ot_hmi_tag_mapping(malformed)
        report = analyze_supplied_ot_hmi_tag_mapping(model)
        changed = copy.deepcopy(model)
        changed["tag_bindings"][0]["project_point_ref"] = "point-z"
        with self.assertRaises(OtHmiTagMappingError):
            verify_supplied_ot_hmi_tag_mapping(report, model=changed)
        with self.assertRaises(OtHmiTagMappingError):
            verify_supplied_ot_hmi_tag_mapping(report.to_dict(), model=model)
        with self.assertRaises(OtHmiTagMappingError):
            verify_supplied_ot_hmi_tag_mapping_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_ot_hmi_tag_mapping_bytes(b'{"x":1,"x":2}', model=model)


if __name__ == "__main__":
    unittest.main()
