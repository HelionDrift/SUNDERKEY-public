"""Supplied fixed-width arithmetic and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_integer_width_arithmetic import (
    IntegerWidthArithmeticError,
    IntegerWidthArithmeticReport,
    analyze_supplied_integer_width,
    component_fixture,
    verify_supplied_integer_width,
)


class IntegerWidthArithmeticTests(unittest.TestCase):
    def test_unsigned_and_signed_wrap_are_exact_supplied_model_math(self) -> None:
        report = analyze_supplied_integer_width(component_fixture()).to_dict()
        rows = {row["operation_id"]: row for row in report["results"]}
        self.assertEqual(rows["unsigned_add"]["mathematical_result_decimal"], "260")
        self.assertEqual(rows["unsigned_add"]["wrapped_result"], 4)
        self.assertEqual(rows["signed_multiply"]["mathematical_result_decimal"], "200")
        self.assertEqual(rows["signed_multiply"]["wrapped_result"], -56)
        self.assertEqual(report["overflow_operation_count"], 2)
        self.assertEqual(report["observed_mismatch_count"], 0)
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["program_operations_verified"])

    def test_64_bit_arithmetic_and_supplied_observation_mismatch(self) -> None:
        model = component_fixture()
        model["operations"] = [{
            "operation_id": "wide", "width_bits": 64, "signed": True,
            "operator": "add", "left": (1 << 63) - 1, "right": 1,
            "observed_result": 1,
        }]
        report = analyze_supplied_integer_width(model).to_dict()
        self.assertEqual(report["results"][0]["wrapped_result"], -(1 << 63))
        self.assertEqual(report["observed_mismatch_count"], 1)

    def test_incomplete_inventory_remains_unknown(self) -> None:
        model = component_fixture()
        model["operation_inventory_complete"] = False
        report = analyze_supplied_integer_width(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["overflow_operation_count"], 2)

    def test_rejects_out_of_range_and_invalid_values(self) -> None:
        model = component_fixture()
        model["operations"][0]["left"] = 256
        with self.assertRaises(IntegerWidthArithmeticError):
            analyze_supplied_integer_width(model)
        model = component_fixture()
        model["operations"][0]["left"] = True
        with self.assertRaises(IntegerWidthArithmeticError):
            analyze_supplied_integer_width(model)
        model = component_fixture()
        model["operations"][0]["width_bits"] = 7
        with self.assertRaises(IntegerWidthArithmeticError):
            analyze_supplied_integer_width(model)
        model = component_fixture()
        model["operations"][0]["width_bits"] = 64
        with self.assertRaises(IntegerWidthArithmeticError):
            analyze_supplied_integer_width(model)
        model = component_fixture()
        model["operations"].append(copy.deepcopy(model["operations"][0]))
        with self.assertRaises(IntegerWidthArithmeticError):
            analyze_supplied_integer_width(model)

    def test_original_model_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_integer_width(model)
        self.assertEqual(
            verify_supplied_integer_width(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["operations"][0]["observed_result"] = 5
        with self.assertRaises(IntegerWidthArithmeticError):
            verify_supplied_integer_width(report, model=changed)
        with self.assertRaises(IntegerWidthArithmeticError):
            IntegerWidthArithmeticReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
