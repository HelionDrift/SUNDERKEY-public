"""Supplied relational grant paths are not effective database access."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_relational_grant_path import (
    RelationalGrantPath,
    RelationalGrantPathError,
    analyze_supplied_relational_grants,
    verify_supplied_relational_grants,
)


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def model() -> dict:
    principal = _ref("principal", "a")
    role_b = _ref("role", "b")
    role_c = _ref("role", "c")
    relation = _ref("relation", "d")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-relational-grant-path-v1",
        "principal_ref": principal,
        "graph_complete": False,
        "roles": [role_b, role_c],
        "memberships": [
            {"edge_id": "m1", "member_ref": principal, "role_ref": role_b},
            {"edge_id": "m2", "member_ref": role_b, "role_ref": role_c},
            {"edge_id": "m3", "member_ref": role_c, "role_ref": role_b},
        ],
        "grants": [
            {
                "edge_id": "g1",
                "grantee_ref": role_c,
                "relation_ref": relation,
                "privilege": "declared_select",
            },
            {
                "edge_id": "g2",
                "grantee_ref": principal,
                "relation_ref": relation,
                "privilege": "declared_insert",
            },
        ],
        "objectives": [
            {"relation_ref": relation, "privilege": "declared_select"},
            {"relation_ref": relation, "privilege": "declared_insert"},
            {"relation_ref": relation, "privilege": "declared_update"},
        ],
    }


class RelationalGrantPathTests(unittest.TestCase):
    def test_nested_role_direct_grant_and_unknown_absence(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_relational_grants(source)
        rows = report.to_dict()["findings"]
        self.assertEqual(source, original)
        self.assertEqual(rows[0]["disposition"], "supplied_grant_path")
        self.assertEqual(rows[0]["membership_edge_ids"], ["m1", "m2"])
        self.assertEqual(rows[0]["grant_edge_id"], "g1")
        self.assertEqual(rows[1]["membership_edge_ids"], [])
        self.assertEqual(rows[1]["grant_edge_id"], "g2")
        self.assertEqual(rows[2]["disposition"], "unknown_incomplete_graph")
        self.assertFalse(report.to_dict()["flags"]["effective_privilege_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_relational_grants(report, model=source).to_json(), report.to_json()
        )
        source["graph_complete"] = True
        self.assertEqual(
            analyze_supplied_relational_grants(source).to_dict()["findings"][2]["disposition"],
            "no_supplied_path",
        )

    def test_invalid_role_duplicate_edge_privilege_and_native_type_refused(self) -> None:
        source = model()
        source["memberships"][0]["role_ref"] = _ref("role", "e")
        with self.assertRaises(RelationalGrantPathError):
            analyze_supplied_relational_grants(source)
        source = model()
        source["grants"][0]["edge_id"] = "m1"
        with self.assertRaises(RelationalGrantPathError):
            analyze_supplied_relational_grants(source)
        source = model()
        source["objectives"][0]["privilege"] = "superuser"
        with self.assertRaises(RelationalGrantPathError):
            analyze_supplied_relational_grants(source)
        source = model()
        source["graph_complete"] = 1
        with self.assertRaises(RelationalGrantPathError):
            analyze_supplied_relational_grants(source)
        source = model()
        source["principal_ref"] = object()
        with self.assertRaises(RelationalGrantPathError):
            analyze_supplied_relational_grants(source)

    def test_tamper_and_changed_model_refused(self) -> None:
        source = model()
        report = analyze_supplied_relational_grants(source)
        tampered = report.to_dict()
        tampered["flags"]["effective_privilege_proven"] = True
        with self.assertRaises(RelationalGrantPathError):
            RelationalGrantPath(tampered)
        source["grants"][0]["privilege"] = "declared_delete"
        with self.assertRaises(RelationalGrantPathError):
            verify_supplied_relational_grants(report, model=source)


if __name__ == "__main__":
    unittest.main()
