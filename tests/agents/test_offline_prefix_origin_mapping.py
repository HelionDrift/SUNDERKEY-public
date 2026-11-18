"""Supplied prefix-origin matching never proves live routing or ownership."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_prefix_origin_mapping import (
    PrefixOriginAnalysis,
    PrefixOriginMappingError,
    analyze_supplied_prefix_origins,
    verify_supplied_prefix_origins,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-prefix-origin-snapshot-v1",
        "routes": [
            {
                "route_id": "default-v4",
                "prefix": "0.0.0.0/0",
                "origin_asn": 64500,
                "source_id": "synthetic-feed-a",
            },
            {
                "route_id": "specific-a",
                "prefix": "203.0.113.0/24",
                "origin_asn": 64501,
                "source_id": "synthetic-feed-a",
            },
            {
                "route_id": "specific-b",
                "prefix": "203.0.113.0/24",
                "origin_asn": 64502,
                "source_id": "synthetic-feed-b",
            },
            {
                "route_id": "v6",
                "prefix": "2001:db8::/32",
                "origin_asn": 64503,
                "source_id": "synthetic-feed-a",
            },
        ],
        "queries": [
            {"query_id": "conflict", "address": "203.0.113.8"},
            {"query_id": "default", "address": "198.51.100.2"},
            {"query_id": "v6", "address": "2001:db8::1"},
            {"query_id": "missing", "address": "2001:db9::1"},
        ],
    }


class PrefixOriginMappingTests(unittest.TestCase):
    def test_longest_prefix_conflict_family_and_missing_are_distinct(self):
        model = _model()
        analysis = analyze_supplied_prefix_origins(model)
        report = analysis.to_dict()
        rows = {row["query_id"]: row for row in report["observations"]}
        self.assertEqual(rows["conflict"]["status"], "conflicting_supplied_origins")
        self.assertEqual(rows["conflict"]["selected_prefix"], "203.0.113.0/24")
        self.assertEqual(rows["conflict"]["origin_asns"], [64501, 64502])
        self.assertEqual(rows["conflict"]["route_ids"], ["specific-a", "specific-b"])
        self.assertEqual(rows["default"]["origin_asns"], [64500])
        self.assertEqual(rows["default"]["selected_prefix"], "0.0.0.0/0")
        self.assertEqual(rows["v6"]["origin_asns"], [64503])
        self.assertEqual(rows["missing"]["status"], "not_in_supplied_table")
        self.assertEqual(rows["missing"]["origin_asns"], [])
        self.assertFalse(report["flags"]["actual_route_proven"])
        self.assertFalse(report["flags"]["asn_ownership_proven"])
        self.assertTrue(all(value == "none" for value in report["operational_effects"].values()))
        self.assertEqual(verify_supplied_prefix_origins(analysis, model=model).to_dict(), report)

    def test_noncanonical_and_duplicate_observations_are_refused(self):
        for invalid in ("203.0.113.8/24", "2001:DB8::/32", "10.0.0.0/33"):
            with self.subTest(invalid=invalid):
                model = _model()
                model["routes"][1]["prefix"] = invalid
                with self.assertRaises(PrefixOriginMappingError):
                    analyze_supplied_prefix_origins(model)
        model = _model()
        model["routes"][1]["route_id"] = model["routes"][0]["route_id"]
        with self.assertRaises(PrefixOriginMappingError):
            analyze_supplied_prefix_origins(model)
        model = _model()
        model["routes"][2]["origin_asn"] = model["routes"][1]["origin_asn"]
        model["routes"][2]["source_id"] = model["routes"][1]["source_id"]
        with self.assertRaises(PrefixOriginMappingError):
            analyze_supplied_prefix_origins(model)

    def test_untyped_and_tampered_reports_are_refused(self):
        model = _model()
        model["routes"][0]["origin_asn"] = True
        with self.assertRaises(PrefixOriginMappingError):
            analyze_supplied_prefix_origins(model)
        model = _model()
        model["queries"][0]["address"] = "203.0.113.008"
        with self.assertRaises(PrefixOriginMappingError):
            analyze_supplied_prefix_origins(model)
        report = analyze_supplied_prefix_origins(_model()).to_dict()
        report["flags"]["actual_route_proven"] = True
        with self.assertRaises(PrefixOriginMappingError):
            PrefixOriginAnalysis(report)
        report = analyze_supplied_prefix_origins(_model()).to_dict()
        changed = copy.deepcopy(report)
        changed["observations"][0]["origin_asns"] = (64501, 64502)
        with self.assertRaises(PrefixOriginMappingError):
            PrefixOriginAnalysis(changed)
        analysis = analyze_supplied_prefix_origins(_model())
        model = _model()
        model["routes"][1]["origin_asn"] = 64509
        with self.assertRaises(PrefixOriginMappingError):
            verify_supplied_prefix_origins(analysis, model=model)


if __name__ == "__main__":
    unittest.main()
