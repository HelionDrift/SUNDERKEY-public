"""Supplied minor-unit arithmetic does not imply a real checkout defect."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_price_rounding_analysis import (
    PriceRoundingAnalysis,
    PriceRoundingAnalysisError,
    analyze_supplied_price_rounding,
    verify_supplied_price_rounding,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-minor-unit-price-rounding-v1",
        "currency_label": "TST",
        "minor_unit_scale": 2,
        "lines": [
            {"line_id": "a", "unit_minor": 1, "quantity": 1, "discount_minor": 0},
            {"line_id": "b", "unit_minor": 1, "quantity": 1, "discount_minor": 0},
        ],
        "tax_rate_basis_points": 5000,
        "tax_basis": "line",
        "rounding_mode": "half_up",
        "declared_subtotal_minor": 2,
        "declared_discount_minor": 0,
        "declared_tax_minor": 2,
        "declared_total_minor": 4,
    }


class PriceRoundingAnalysisTests(unittest.TestCase):
    def test_line_order_rounding_gap_and_selected_total(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_price_rounding(model)
        body = report.to_dict()
        self.assertEqual(body["expected"]["line_tax_minor"], 2)
        self.assertEqual(body["expected"]["order_tax_minor"], 1)
        self.assertEqual(body["expected"]["line_order_rounding_gap_minor"], 1)
        self.assertEqual(body["expected"]["total_minor"], 4)
        self.assertEqual(set(body["comparison"].values()), {"match"})
        self.assertFalse(body["flags"]["payment_executed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_price_rounding(report, model=model).to_dict(), body)
        model = _model()
        model["tax_basis"] = "order"
        model["declared_tax_minor"] = 1
        model["declared_total_minor"] = 3
        body = analyze_supplied_price_rounding(model).to_dict()
        self.assertEqual(body["expected"]["selected_tax_minor"], 1)
        self.assertEqual(set(body["comparison"].values()), {"match"})

    def test_supplied_mismatch_and_discount_arithmetic_are_distinct(self):
        model = _model()
        model["lines"][1]["discount_minor"] = 1
        model["declared_discount_minor"] = 1
        model["declared_tax_minor"] = 1
        model["declared_total_minor"] = 5
        body = analyze_supplied_price_rounding(model).to_dict()
        self.assertEqual(body["expected"]["discount_minor"], 1)
        self.assertEqual(body["expected"]["selected_tax_minor"], 1)
        self.assertEqual(body["expected"]["total_minor"], 2)
        self.assertEqual(body["comparison"]["total"], "mismatch")
        self.assertEqual(body["comparison"]["tax"], "match")

    def test_boolean_negative_overflow_discount_and_tamper_are_refused(self):
        for field, invalid in (
            ("minor_unit_scale", True),
            ("tax_rate_basis_points", -1),
            ("declared_total_minor", True),
        ):
            with self.subTest(field=field):
                model = _model()
                model[field] = invalid
                with self.assertRaises(PriceRoundingAnalysisError):
                    analyze_supplied_price_rounding(model)
        model = _model()
        model["lines"][0]["discount_minor"] = 2
        with self.assertRaises(PriceRoundingAnalysisError):
            analyze_supplied_price_rounding(model)
        model = _model()
        model["lines"][0]["unit_minor"] = 1_000_000_001
        with self.assertRaises(PriceRoundingAnalysisError):
            analyze_supplied_price_rounding(model)
        body = analyze_supplied_price_rounding(_model()).to_dict()
        body["flags"]["economic_impact_proven"] = True
        with self.assertRaises(PriceRoundingAnalysisError):
            PriceRoundingAnalysis(body)
        report = analyze_supplied_price_rounding(_model())
        model = _model()
        model["rounding_mode"] = "floor"
        with self.assertRaises(PriceRoundingAnalysisError):
            verify_supplied_price_rounding(report, model=model)

    def test_non_native_value_is_rejected_before_comparison(self):
        class ComparisonTrap:
            def __eq__(self, other):
                raise AssertionError("Non-native value was compared")

        model = _model()
        model["semantics_profile"] = ComparisonTrap()
        with self.assertRaises(PriceRoundingAnalysisError):
            analyze_supplied_price_rounding(model)


if __name__ == "__main__":
    unittest.main()
