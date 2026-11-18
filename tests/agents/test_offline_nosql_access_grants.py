"""Synthetic exact NoSQL grant projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_nosql_access_grants as grants


def _row(model: dict, check_id: str = "candidate-delete") -> dict:
    body = grants.analyze_supplied_nosql_access_grants(model).to_dict()
    return next(row for row in body["check_observations"] if row["check_id"] == check_id)


class NoSqlAccessGrantsTests(unittest.TestCase):
    def _deny_before_address(self, model: dict) -> None:
        with patch.object(grants, "_address") as address:
            with self.assertRaises(grants.NoSqlAccessGrantsAnalysisError):
                grants.analyze_supplied_nosql_access_grants(model)
            address.assert_not_called()

    def test_fixture_determinism_effects_and_original_replay(self) -> None:
        model = grants.component_fixture()
        report = grants.analyze_supplied_nosql_access_grants(model)
        body = report.to_dict()
        self.assertEqual(body["profile_id"], grants.PROFILE_ID)
        self.assertEqual(body["wave_id"], "IW2-002")
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 1))
        self.assertEqual(
            [row["outcome"] for row in body["check_observations"]],
            ["matches_declared_grants", "candidate_declared_deny_allowed_contradiction", "unknown"],
        )
        self.assertEqual(set(body["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in body["flags"].values()))
        self.assertEqual(
            report.to_json(), grants.analyze_supplied_nosql_access_grants(model).to_json()
        )
        detached = grants.NoSqlAccessGrantsAnalysis.from_json(report.to_json())
        self.assertEqual(
            grants.verify_supplied_nosql_access_grants_analysis(detached, model=model).to_json(),
            report.to_json(),
        )
        model["roles"][0]["grants"].append({"collection_id": "accounts", "action": "write"})
        with self.assertRaises(grants.NoSqlAccessGrantsAnalysisError):
            grants.verify_supplied_nosql_access_grants_analysis(report, model=model)

    def test_exact_role_collection_action_and_denial(self) -> None:
        model = grants.component_fixture()
        self.assertEqual(_row(model)["expected_decision"], "deny")
        model["checks"][1]["supplied_decision"] = "deny"
        self.assertEqual(_row(model)["outcome"], "matches_declared_grants")
        model["checks"][0]["supplied_decision"] = "deny"
        self.assertEqual(
            _row(model, "allowed-read")["outcome"], "declared_allow_denied_contradiction"
        )
        self.assertEqual(
            grants.analyze_supplied_nosql_access_grants(model).to_dict()["candidate_count"], 0
        )

    def test_exact_direct_grant_prevents_false_deny_candidate(self) -> None:
        model = grants.component_fixture()
        model["principals"][0]["direct_grants"] = [
            {"collection_id": "accounts", "action": "delete"}
        ]
        row = _row(model)
        self.assertEqual(row["expected_decision"], "allow")
        self.assertEqual(row["outcome"], "matches_declared_grants")
        self.assertTrue(row["direct_grant_matched"])
        self.assertEqual(row["matched_role_ids"], [])
        self.assertEqual(
            grants.analyze_supplied_nosql_access_grants(model).to_dict()["candidate_count"], 0
        )

    def test_unknown_premises_do_not_become_candidates(self) -> None:
        changes = (
            (lambda x: x.update(grants_complete=False), "grant_inventory_incomplete"),
            (
                lambda x: x.update(alternate_grant_paths_complete=False),
                "alternate_grant_paths_incomplete",
            ),
            (lambda x: x.update(collections_complete=False), "collection_inventory_incomplete"),
            (
                lambda x: x["principals"][0].update(membership_complete=False),
                "role_membership_incomplete",
            ),
            (
                lambda x: x["roles"][0].update(policy_complete=False),
                "assigned_role_policy_incomplete",
            ),
            (
                lambda x: x["principals"][0].update(direct_grants_complete=False),
                "direct_grants_incomplete",
            ),
            (
                lambda x: x["checks"][1].update(policy_mode="wildcard_or_dynamic"),
                "wildcard_or_dynamic_policy",
            ),
            (lambda x: x["checks"][1].update(context_complete=False), "check_context_incomplete"),
            (
                lambda x: x["checks"][1].update(observation_complete=False),
                "supplied_decision_unknown",
            ),
            (
                lambda x: x["checks"][1].update(supplied_decision="unknown"),
                "supplied_decision_unknown",
            ),
        )
        for change, reason in changes:
            with self.subTest(reason=reason):
                model = grants.component_fixture()
                change(model)
                row = _row(model)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_closed_schema_types_references_and_order(self) -> None:
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x.update(grants_complete=1),
            lambda x: x.update(alternate_grant_paths_complete=1),
            lambda x: x["collections"].append("accounts"),
            lambda x: x["roles"][0]["grants"][0].update(collection_id="missing"),
            lambda x: x["roles"][0]["grants"][0].update(action="*"),
            lambda x: x["roles"][0].update(policy_complete=1),
            lambda x: x["principals"][0].update(role_ids=["missing"]),
            lambda x: x["principals"][0].update(direct_grants_complete=1),
            lambda x: x["principals"][0].update(
                direct_grants=[{"collection_id": "missing", "action": "read"}]
            ),
            lambda x: x["principals"][0].update(
                direct_grants=[
                    {"collection_id": "accounts", "action": "read"},
                    {"collection_id": "accounts", "action": "read"},
                ]
            ),
            lambda x: x["checks"][1].update(principal_id="missing"),
            lambda x: x["checks"][1].update(collection_id="missing"),
            lambda x: x["checks"][1].update(action="execute"),
            lambda x: x["checks"][1].update(context_complete=1),
            lambda x: x["checks"].reverse(),
        )
        for change in changes:
            with self.subTest(change=change):
                model = grants.component_fixture()
                change(model)
                self._deny_before_address(model)

    def test_bytes_and_forgery_rejected(self) -> None:
        model = grants.component_fixture()
        raw = json.dumps(model, sort_keys=True, separators=(",", ":")).encode("ascii")
        report = grants.analyze_supplied_nosql_access_grants(model)
        self.assertEqual(
            grants.analyze_supplied_nosql_access_grants_bytes(model_bytes=raw).to_json(),
            report.to_json(),
        )
        for invalid in (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        ):
            with self.subTest(invalid=invalid[:30]):
                with self.assertRaises(grants.NoSqlAccessGrantsAnalysisError):
                    grants.analyze_supplied_nosql_access_grants_bytes(model_bytes=invalid)
        forged = copy.deepcopy(report.to_dict())
        forged["candidate_count"] = 0
        with self.assertRaises(grants.NoSqlAccessGrantsAnalysisError):
            grants.NoSqlAccessGrantsAnalysis.from_dict(forged)
        with self.assertRaises(grants.NoSqlAccessGrantsAnalysisError):
            grants.verify_supplied_nosql_access_grants_analysis(report.to_dict(), model=model)

    def test_native_cycles_and_bounds(self) -> None:
        model = grants.component_fixture()
        model["cycle"] = model
        self._deny_before_address(model)
        model = grants.component_fixture()
        model["checks"] *= grants.MAX_CHECKS + 1
        self._deny_before_address(model)
        model = grants.component_fixture()
        model["roles"][0]["role_id"] = "x" * (grants.MAX_STRING_BYTES + 1)
        self._deny_before_address(model)


if __name__ == "__main__":
    unittest.main()
