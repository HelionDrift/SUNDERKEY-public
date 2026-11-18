"""Supplied directed trust paths do not prove cross-domain authentication."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_directory_trust_paths import (
    DirectoryTrustPaths,
    DirectoryTrustPathsError,
    analyze_supplied_directory_trusts,
    verify_supplied_directory_trusts,
)


def _domain(letter: str) -> str:
    return "domain:sha256:" + letter * 64


def _numbered_domain(index: int) -> str:
    return f"domain:sha256:{index:064x}"


def _model() -> dict:
    a, b, c = _domain("a"), _domain("b"), _domain("c")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-directory-trust-paths-v1",
        "inventory_complete": False,
        "domains": [a, b, c],
        "trusts": [
            {
                "edge_id": "t1",
                "from_domain_ref": a,
                "to_domain_ref": b,
                "enabled": True,
                "supplied_chainable": True,
                "selective_authentication": True,
                "sid_filtering": False,
            },
            {
                "edge_id": "t2",
                "from_domain_ref": b,
                "to_domain_ref": c,
                "enabled": True,
                "supplied_chainable": False,
                "selective_authentication": False,
                "sid_filtering": True,
            },
        ],
        "queries": [
            {"from_domain_ref": a, "to_domain_ref": c},
            {"from_domain_ref": c, "to_domain_ref": a},
        ],
    }


class DirectoryTrustPathsTests(unittest.TestCase):
    def test_direction_gates_and_completeness_stay_separate(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_directory_trusts(model)
        rows = report.to_dict()["queries"]
        self.assertEqual(rows[0]["trust_edge_ids"], ["t1", "t2"])
        self.assertEqual(rows[0]["disposition"], "supplied_enabled_path_with_gates")
        self.assertTrue(rows[0]["selective_authentication_declared"])
        self.assertTrue(rows[0]["sid_filtering_declared"])
        self.assertEqual(rows[1]["disposition"], "unknown_incomplete_inventory")
        self.assertFalse(report.to_dict()["flags"]["authentication_or_authorization_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_directory_trusts(report, model=model).to_json(), report.to_json()
        )
        model["inventory_complete"] = True
        self.assertEqual(
            analyze_supplied_directory_trusts(model).to_dict()["queries"][1]["disposition"],
            "no_supplied_enabled_path",
        )

    def test_nonchainable_intermediate_and_disabled_edge_block_supplied_path(self):
        model = _model()
        model["trusts"][0]["supplied_chainable"] = False
        self.assertEqual(
            analyze_supplied_directory_trusts(model).to_dict()["queries"][0]["disposition"],
            "unknown_incomplete_inventory",
        )
        model = _model()
        model["trusts"][1]["enabled"] = False
        self.assertEqual(
            analyze_supplied_directory_trusts(model).to_dict()["queries"][0]["trust_edge_ids"], []
        )

    def test_advertised_bounds_have_bounded_report(self):
        model = _model()
        model["domains"] = [_numbered_domain(index) for index in range(64)]
        model["trusts"] = [
            {
                "edge_id": "t" + str(index),
                "from_domain_ref": model["domains"][index % 63],
                "to_domain_ref": model["domains"][(index % 63) + 1],
                "enabled": True,
                "supplied_chainable": True,
                "selective_authentication": False,
                "sid_filtering": False,
            }
            for index in range(256)
        ]
        model["queries"] = [
            {"from_domain_ref": model["domains"][0], "to_domain_ref": model["domains"][index + 1]}
            for index in range(16)
        ]
        report = analyze_supplied_directory_trusts(model)
        self.assertEqual(len(report.to_dict()["queries"]), 16)
        self.assertLessEqual(len(report.to_json()), 524_288)

    def test_plain_domain_boolean_duplicate_and_tamper_are_refused(self):
        model = _model()
        model["domains"][0] = "real-domain.example"
        with self.assertRaises(DirectoryTrustPathsError):
            analyze_supplied_directory_trusts(model)
        model = _model()
        model["trusts"][0]["enabled"] = 1
        with self.assertRaises(DirectoryTrustPathsError):
            analyze_supplied_directory_trusts(model)
        model = _model()
        model["trusts"][1]["edge_id"] = "t1"
        with self.assertRaises(DirectoryTrustPathsError):
            analyze_supplied_directory_trusts(model)
        model = _model()
        model["trusts"][0]["to_domain_ref"] = []
        with self.assertRaises(DirectoryTrustPathsError):
            analyze_supplied_directory_trusts(model)
        body = analyze_supplied_directory_trusts(_model()).to_dict()
        body["flags"]["authentication_or_authorization_proven"] = True
        with self.assertRaises(DirectoryTrustPathsError):
            DirectoryTrustPaths(body)
        report = analyze_supplied_directory_trusts(_model())
        changed = _model()
        changed["trusts"][0]["enabled"] = False
        with self.assertRaises(DirectoryTrustPathsError):
            verify_supplied_directory_trusts(report, model=changed)


if __name__ == "__main__":
    unittest.main()
