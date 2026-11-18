"""Supplied directory paths never become effective-access claims."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_directory_entitlement_path import (
    DirectoryEntitlementPath,
    DirectoryEntitlementPathError,
    analyze_supplied_directory_paths,
    verify_supplied_directory_paths,
)


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def _numbered_ref(kind: str, index: int) -> str:
    return f"{kind}:sha256:{index:064x}"


def _model() -> dict:
    source = _ref("principal", "a")
    group_b = _ref("group", "b")
    group_c = _ref("group", "c")
    resource_d = _ref("resource", "d")
    resource_e = _ref("resource", "e")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-directory-entitlement-path-v1",
        "source_principal_ref": source,
        "graph_complete": False,
        "groups": [group_b, group_c],
        "memberships": [
            {"edge_id": "m1", "member_ref": source, "group_ref": group_b},
            {"edge_id": "m2", "member_ref": group_b, "group_ref": group_c},
            {"edge_id": "m3", "member_ref": group_c, "group_ref": group_b},
        ],
        "grants": [
            {
                "edge_id": "g1",
                "grantee_ref": group_b,
                "resource_ref": resource_d,
                "right_label": "declared_read",
            },
            {
                "edge_id": "g2",
                "grantee_ref": group_c,
                "resource_ref": resource_d,
                "right_label": "declared_read",
            },
            {
                "edge_id": "g3",
                "grantee_ref": source,
                "resource_ref": resource_e,
                "right_label": "declared_control",
            },
        ],
        "objectives": [
            {"resource_ref": resource_d, "right_label": "declared_read"},
            {"resource_ref": resource_e, "right_label": "declared_control"},
            {"resource_ref": resource_d, "right_label": "declared_write"},
        ],
    }


class DirectoryEntitlementPathTests(unittest.TestCase):
    def test_shortest_supplied_path_direct_grant_and_unknown_absence(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_directory_paths(model)
        rows = report.to_dict()["objectives"]
        self.assertEqual(rows[0]["disposition"], "supplied_path")
        self.assertEqual(rows[0]["membership_edge_ids"], ["m1"])
        self.assertEqual(rows[0]["grant_edge_id"], "g1")
        self.assertEqual(rows[1]["membership_edge_ids"], [])
        self.assertEqual(rows[1]["grant_edge_id"], "g3")
        self.assertEqual(rows[2]["disposition"], "unknown_incomplete_graph")
        self.assertIsNone(rows[2]["grant_edge_id"])
        self.assertFalse(report.to_dict()["flags"]["effective_access_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_directory_paths(report, model=model).to_json(), report.to_json()
        )
        model["graph_complete"] = True
        self.assertEqual(
            analyze_supplied_directory_paths(model).to_dict()["objectives"][2]["disposition"],
            "no_supplied_path",
        )

    def test_declared_upper_bounds_have_bounded_report(self):
        model = _model()
        model["groups"] = [_numbered_ref("group", index) for index in range(64)]
        model["memberships"] = [
            {
                "edge_id": "m" + str(index),
                "member_ref": model["source_principal_ref"]
                if index == 0
                else model["groups"][(index - 1) % 64],
                "group_ref": model["groups"][index % 64],
            }
            for index in range(256)
        ]
        model["grants"] = [
            {
                "edge_id": "g" + str(index),
                "grantee_ref": model["groups"][index % 64],
                "resource_ref": _numbered_ref("resource", index % 16),
                "right_label": "declared_read",
            }
            for index in range(256)
        ]
        model["objectives"] = [
            {"resource_ref": _numbered_ref("resource", index), "right_label": "declared_read"}
            for index in range(16)
        ]
        report = analyze_supplied_directory_paths(model)
        self.assertEqual(len(report.to_dict()["objectives"]), 16)
        self.assertLessEqual(len(report.to_json()), 524_288)
        self.assertEqual(
            verify_supplied_directory_paths(report, model=model).to_json(), report.to_json()
        )

    def test_plain_principal_unhashable_member_duplicate_id_and_tamper_are_refused(self):
        model = _model()
        model["source_principal_ref"] = "real-user"
        with self.assertRaises(DirectoryEntitlementPathError):
            analyze_supplied_directory_paths(model)
        model = _model()
        model["memberships"][0]["member_ref"] = []
        with self.assertRaises(DirectoryEntitlementPathError):
            analyze_supplied_directory_paths(model)
        model = _model()
        model["grants"][0]["edge_id"] = "m1"
        with self.assertRaises(DirectoryEntitlementPathError):
            analyze_supplied_directory_paths(model)
        model = _model()
        model["graph_complete"] = 1
        with self.assertRaises(DirectoryEntitlementPathError):
            analyze_supplied_directory_paths(model)
        model = _model()
        model["memberships"][0]["group_ref"] = object()
        with self.assertRaises(DirectoryEntitlementPathError):
            analyze_supplied_directory_paths(model)
        body = analyze_supplied_directory_paths(_model()).to_dict()
        body["flags"]["effective_access_proven"] = True
        with self.assertRaises(DirectoryEntitlementPathError):
            DirectoryEntitlementPath(body)
        report = analyze_supplied_directory_paths(_model())
        changed = _model()
        changed["memberships"][0]["group_ref"] = changed["groups"][1]
        with self.assertRaises(DirectoryEntitlementPathError):
            verify_supplied_directory_paths(report, model=changed)


if __name__ == "__main__":
    unittest.main()
