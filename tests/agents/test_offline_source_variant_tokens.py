"""Supplied source-token variant projection and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_source_variant_tokens import (
    SourceVariantTokensError,
    SourceVariantTokensReport,
    analyze_supplied_source_variant_tokens,
    component_fixture,
    verify_supplied_source_variant_tokens,
)


class SourceVariantTokensTests(unittest.TestCase):
    def test_classifies_supplied_token_lists_without_parsing_source(self) -> None:
        report = analyze_supplied_source_variant_tokens(component_fixture()).to_dict()
        self.assertEqual(report["added_function_ids"], ["new"])
        self.assertEqual(report["removed_function_ids"], ["old"])
        self.assertEqual(report["unchanged_function_ids"], ["same"])
        self.assertEqual(len(report["modified_functions"]), 1)
        self.assertEqual(report["modified_functions"][0]["function_id"], "parse")
        self.assertEqual(report["modified_functions"][0]["common_subsequence_token_count"], 3)
        self.assertEqual(report["modified_functions"][0]["token_similarity_milli"], 857)
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["source_files_read"])
        self.assertFalse(report["behavioral_equivalence_verified"])

    def test_function_input_order_does_not_change_comparison(self) -> None:
        model = component_fixture()
        first = analyze_supplied_source_variant_tokens(model).to_dict()
        model["left_functions"].reverse()
        model["right_functions"].reverse()
        second = analyze_supplied_source_variant_tokens(model).to_dict()
        for field in (
            "added_function_ids", "removed_function_ids", "unchanged_function_ids",
            "modified_functions",
        ):
            self.assertEqual(first[field], second[field])

    def test_incomplete_side_remains_unknown(self) -> None:
        model = component_fixture()
        model["left_inventory_complete"] = False
        report = analyze_supplied_source_variant_tokens(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["unknown_count"], 1)

    def test_rejects_duplicate_empty_and_oversized_tokens(self) -> None:
        model = component_fixture()
        model["left_functions"].append(copy.deepcopy(model["left_functions"][0]))
        with self.assertRaises(SourceVariantTokensError):
            analyze_supplied_source_variant_tokens(model)
        model = component_fixture()
        model["left_functions"][0]["tokens"] = []
        with self.assertRaises(SourceVariantTokensError):
            analyze_supplied_source_variant_tokens(model)
        model = component_fixture()
        model["left_functions"][0]["tokens"] = ["x"] * 65
        with self.assertRaises(ValueError):
            analyze_supplied_source_variant_tokens(model)
        model = component_fixture()
        model["left_source_id"] = model["right_source_id"]
        with self.assertRaises(SourceVariantTokensError):
            analyze_supplied_source_variant_tokens(model)

    def test_original_source_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_source_variant_tokens(model)
        self.assertEqual(
            verify_supplied_source_variant_tokens(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["right_functions"][0]["tokens"].append("extra")
        with self.assertRaises(SourceVariantTokensError):
            verify_supplied_source_variant_tokens(report, model=changed)
        with self.assertRaises(SourceVariantTokensError):
            SourceVariantTokensReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
