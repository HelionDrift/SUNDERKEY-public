"""Offline supplied spot and time-weighted price projection tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_oracle_twap_deviation import (
    OracleTwapDeviationError,
    analyze_supplied_oracle_twap,
    component_fixture,
    verify_supplied_oracle_twap,
    verify_supplied_oracle_twap_bytes,
)


class OracleTwapDeviationTests(unittest.TestCase):
    def test_weighted_deviation_is_an_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_oracle_twap(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["twap_weighted_price_numerator"], 120_000_000)
        self.assertEqual(body["relative_deviation_numerator"], 600_000_000_000)
        self.assertEqual(body["relative_deviation_denominator"], 120_000_000)
        self.assertFalse(body["oracle_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_oracle_twap(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_oracle_twap_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_threshold_and_missing_premise(self) -> None:
        model = component_fixture()
        model["spot_price_micro"] = 1_100_000
        self.assertEqual(analyze_supplied_oracle_twap(model).to_dict()["candidate_count"], 0)
        model["reference_independent"] = False
        self.assertEqual(analyze_supplied_oracle_twap(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_oracle_twap(model)
        changed = copy.deepcopy(model)
        changed["twap_samples"][0]["price_micro"] += 1
        with self.assertRaises(OracleTwapDeviationError):
            verify_supplied_oracle_twap(report, model=changed)
        with self.assertRaises(OracleTwapDeviationError):
            verify_supplied_oracle_twap(report.to_dict(), model=model)
        with self.assertRaises(OracleTwapDeviationError):
            verify_supplied_oracle_twap_bytes(b"{}", model=model)

    def test_rejects_duplicate_and_invalid_sample(self) -> None:
        model = component_fixture()
        model["twap_samples"][1]["sample_id"] = "window-one"
        with self.assertRaises(OracleTwapDeviationError):
            analyze_supplied_oracle_twap(model)
        model = component_fixture()
        model["twap_samples"][0]["duration_seconds"] = 0
        with self.assertRaises(OracleTwapDeviationError):
            analyze_supplied_oracle_twap(model)


if __name__ == "__main__":
    unittest.main()
