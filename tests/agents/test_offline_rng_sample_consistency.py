"""Supplied RNG sample consistency projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_rng_sample_consistency import (
    RngSampleConsistencyError,
    RngSampleConsistencyReport,
    analyze_supplied_rng_samples,
    component_fixture,
    verify_supplied_rng_samples,
)


class RngSampleConsistencyTests(unittest.TestCase):
    def test_counts_without_entropy_or_weakness_claim(self) -> None:
        report = analyze_supplied_rng_samples(component_fixture()).to_dict()
        self.assertEqual(report["supplied_sample_count"], 3)
        self.assertEqual(report["distinct_value_count"], 2)
        self.assertEqual(report["repeated_value_sample_id_groups"], [["s1", "s3"]])
        self.assertEqual(report["adjacent_equal_pair_count"], 0)
        self.assertEqual(report["bit_one_counts_lsb_first"], [2, 1, 0, 0, 0, 0, 0, 0])
        self.assertFalse(report["entropy_estimated"])
        self.assertFalse(report["cryptographic_weakness_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_adjacent_repetition_and_incomplete_sequence(self) -> None:
        model = component_fixture()
        model["samples"][1]["value_hex"] = "01"
        model["sample_sequence_complete"] = False
        report = analyze_supplied_rng_samples(model).to_dict()
        self.assertEqual(report["adjacent_equal_pair_count"], 2)
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_width_encoding_and_duplicate_ids(self) -> None:
        model = component_fixture()
        model["bit_width"] = 7
        with self.assertRaises(RngSampleConsistencyError):
            analyze_supplied_rng_samples(model)
        model = component_fixture()
        model["samples"][0]["value_hex"] = "0A"
        with self.assertRaises(RngSampleConsistencyError):
            analyze_supplied_rng_samples(model)
        model = component_fixture()
        model["samples"][1]["sample_id"] = "s1"
        with self.assertRaises(RngSampleConsistencyError):
            analyze_supplied_rng_samples(model)

    def test_original_model_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_rng_samples(model)
        self.assertEqual(
            verify_supplied_rng_samples(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["samples"][0]["value_hex"] = "03"
        with self.assertRaises(RngSampleConsistencyError):
            verify_supplied_rng_samples(report, model=changed)
        with self.assertRaises(RngSampleConsistencyError):
            RngSampleConsistencyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
