"""Bounded synthetic Yosys netlist shape comparison tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_yosys_netlist_delta import (
    YosysNetlistDeltaError,
    YosysNetlistDeltaReport,
    analyze_supplied_yosys_netlist_delta,
    component_fixture,
    verify_supplied_yosys_netlist_delta,
)


class YosysNetlistDeltaTests(unittest.TestCase):
    def test_added_cell_and_driver_change_are_not_trojan_proof(self) -> None:
        body = analyze_supplied_yosys_netlist_delta(component_fixture()).to_dict()
        self.assertEqual(body["added_cell_type_counts"], {"$xor": 1})
        self.assertEqual(body["changed_output_cell_driver_port_ids"], ["Y"])
        self.assertEqual(body["unapproved_candidate_cell_type_ids"], ["$xor"])
        self.assertTrue(body["structural_delta_present"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertFalse(body["hardware_trojan_detected"])
        self.assertFalse(body["functional_equivalence_verified"])
        self.assertFalse(body["finding_claimed"])

    def test_equal_bounded_shape_is_not_functional_equivalence(self) -> None:
        model = component_fixture()
        model["candidate_netlist"] = copy.deepcopy(model["baseline_netlist"])
        body = analyze_supplied_yosys_netlist_delta(model).to_dict()
        self.assertFalse(body["structural_delta_present"])
        self.assertFalse(body["functional_equivalence_verified"])
        self.assertIn(
            "structural_shape_does_not_prove_functional_equivalence", body["uncertainty"]
        )

    def test_invalid_bit_and_missing_top_are_rejected(self) -> None:
        model = component_fixture()
        model["candidate_netlist"]["modules"]["top"]["ports"]["A"]["bits"] = [0]
        with self.assertRaises(YosysNetlistDeltaError):
            analyze_supplied_yosys_netlist_delta(model)
        model = component_fixture()
        model["candidate_netlist"]["modules"].pop("top")
        with self.assertRaises(YosysNetlistDeltaError):
            analyze_supplied_yosys_netlist_delta(model)

    def test_nonsynthetic_and_duplicate_type_list_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(YosysNetlistDeltaError):
            analyze_supplied_yosys_netlist_delta(model)
        model = component_fixture()
        model["approved_cell_type_ids"].append("$not")
        with self.assertRaises(YosysNetlistDeltaError):
            analyze_supplied_yosys_netlist_delta(model)

    def test_missing_direction_metadata_is_explicit_uncertainty(self) -> None:
        model = component_fixture()
        model["candidate_netlist"]["modules"]["top"]["cells"]["u_xor"].pop(
            "port_directions"
        )
        body = analyze_supplied_yosys_netlist_delta(model).to_dict()
        self.assertIn("cell_port_direction_metadata_incomplete", body["uncertainty"])
        self.assertFalse(body["candidate"]["cell_direction_metadata_complete"])

    def test_replay_requires_original_model_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_yosys_netlist_delta(model)
        self.assertEqual(
            verify_supplied_yosys_netlist_delta(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["approved_cell_type_ids"].append("$xor")
        with self.assertRaises(YosysNetlistDeltaError):
            verify_supplied_yosys_netlist_delta(report, model=changed)
        with self.assertRaises(YosysNetlistDeltaError):
            YosysNetlistDeltaReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
