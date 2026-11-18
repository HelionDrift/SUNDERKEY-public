"""Synthetic cache-set mapping tests retain microarchitectural uncertainty."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_cache_set_projection import (
    CacheSetProjectionError,
    CacheSetProjectionReport,
    analyze_supplied_cache_set_projection,
    component_fixture,
    verify_supplied_cache_set_projection,
)


class CacheSetProjectionTests(unittest.TestCase):
    def test_declared_pressure_is_not_measured_leakage(self) -> None:
        body = analyze_supplied_cache_set_projection(component_fixture()).to_dict()
        self.assertEqual(body["access_count"], 4)
        self.assertEqual(body["observed_set_count"], 2)
        self.assertEqual(body["declared_pressure_set_count"], 1)
        self.assertEqual(body["set_observations"][0]["distinct_line_count"], 3)
        self.assertFalse(body["timing_or_leakage_observed"])
        self.assertFalse(body["side_channel_claimed"])
        self.assertFalse(body["finding_claimed"])
        self.assertEqual(body["candidate_count"], 0)

    def test_duplicate_line_does_not_increase_distinct_count(self) -> None:
        model = component_fixture()
        model["accesses"].append({"address_hex": "0x1"})
        body = analyze_supplied_cache_set_projection(model).to_dict()
        self.assertEqual(body["set_observations"][0]["access_count"], 4)
        self.assertEqual(body["set_observations"][0]["distinct_line_count"], 3)

    def test_invalid_cache_shape_and_address_rejected(self) -> None:
        model = component_fixture()
        model["set_count"] = 3
        with self.assertRaises(CacheSetProjectionError):
            analyze_supplied_cache_set_projection(model)
        model = component_fixture()
        model["accesses"][0]["address_hex"] = "0xXYZ"
        with self.assertRaises(CacheSetProjectionError):
            analyze_supplied_cache_set_projection(model)

    def test_nonsynthetic_and_unbounded_accesses_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(CacheSetProjectionError):
            analyze_supplied_cache_set_projection(model)
        model = component_fixture()
        model["accesses"] = [{"address_hex": "0x0"}] * 129
        with self.assertRaises(CacheSetProjectionError):
            analyze_supplied_cache_set_projection(model)

    def test_replay_requires_original_model_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_cache_set_projection(model)
        self.assertEqual(
            verify_supplied_cache_set_projection(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["way_count"] = 4
        with self.assertRaises(CacheSetProjectionError):
            verify_supplied_cache_set_projection(report, model=changed)
        with self.assertRaises(CacheSetProjectionError):
            CacheSetProjectionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
