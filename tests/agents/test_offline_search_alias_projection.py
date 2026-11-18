"""Search alias projections remain supplied declarations, not query proof."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_search_alias_projection import (
    SearchAliasProjection,
    SearchAliasProjectionError,
    analyze_supplied_search_alias,
    verify_supplied_search_alias,
)


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def model() -> dict:
    tenant_a = _ref("tenant", "a")
    tenant_b = _ref("tenant", "b")
    index_a = _ref("index", "c")
    index_b = _ref("index", "d")
    index_shared = _ref("index", "e")
    alias = _ref("alias", "f")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-search-alias-v1",
        "indexes": [
            {"index_ref": index_a, "tenant_ref": tenant_a},
            {"index_ref": index_b, "tenant_ref": tenant_b},
            {"index_ref": index_shared, "tenant_ref": "shared"},
        ],
        "alias_routes": [
            {"route_id": "a", "alias_ref": alias, "index_ref": index_a, "filter_tenant_ref": None},
            {"route_id": "b", "alias_ref": alias, "index_ref": index_b, "filter_tenant_ref": None},
            {
                "route_id": "c",
                "alias_ref": alias,
                "index_ref": index_shared,
                "filter_tenant_ref": None,
            },
            {
                "route_id": "d",
                "alias_ref": alias,
                "index_ref": index_shared,
                "filter_tenant_ref": tenant_b,
            },
            {
                "route_id": "e",
                "alias_ref": alias,
                "index_ref": index_shared,
                "filter_tenant_ref": tenant_a,
            },
        ],
        "objectives": [
            {"alias_ref": alias, "expected_tenant_ref": tenant_a},
            {"alias_ref": _ref("alias", "0"), "expected_tenant_ref": tenant_a},
        ],
    }


class SearchAliasProjectionTests(unittest.TestCase):
    def test_supplied_route_comparisons_and_no_route(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_search_alias(source)
        self.assertEqual(source, original)
        findings = report.to_dict()["findings"]
        self.assertEqual(findings[0]["route_status"], "supplied_routes")
        self.assertEqual(
            [row["disposition"] for row in findings[0]["routes"]],
            [
                "declared_aligned_route",
                "declared_index_tenant_mismatch",
                "declared_unscoped_shared_index",
                "declared_excluded_by_filter",
                "declared_aligned_route",
            ],
        )
        self.assertEqual(findings[1]["route_status"], "no_supplied_route")
        self.assertFalse(report.to_dict()["flags"]["cross_tenant_exposure_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_search_alias(report, model=source).to_json(), report.to_json()
        )

    def test_invalid_undeclared_duplicate_and_non_native_refused(self) -> None:
        source = model()
        source["alias_routes"][0]["index_ref"] = _ref("index", "1")
        with self.assertRaises(SearchAliasProjectionError):
            analyze_supplied_search_alias(source)
        source = model()
        source["alias_routes"][1]["route_id"] = "a"
        with self.assertRaises(SearchAliasProjectionError):
            analyze_supplied_search_alias(source)
        source = model()
        source["indexes"][0]["tenant_ref"] = "real-tenant"
        with self.assertRaises(SearchAliasProjectionError):
            analyze_supplied_search_alias(source)
        source = model()
        source["indexes"][0]["tenant_ref"] = object()
        with self.assertRaises(SearchAliasProjectionError):
            analyze_supplied_search_alias(source)

    def test_tamper_and_changed_input_refused(self) -> None:
        source = model()
        report = analyze_supplied_search_alias(source)
        tampered = report.to_dict()
        tampered["flags"]["cross_tenant_exposure_proven"] = True
        with self.assertRaises(SearchAliasProjectionError):
            SearchAliasProjection(tampered)
        source["alias_routes"][2]["filter_tenant_ref"] = source["objectives"][0][
            "expected_tenant_ref"
        ]
        with self.assertRaises(SearchAliasProjectionError):
            verify_supplied_search_alias(report, model=source)


if __name__ == "__main__":
    unittest.main()
