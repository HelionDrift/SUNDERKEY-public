"""Synthetic CMS permission-graph projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_cms_permission_graph as graph


def _row(model: dict, check_id: str = "bob-edit") -> dict:
    body = graph.analyze_supplied_cms_permission_graph(model).to_dict()
    return next(row for row in body["check_observations"] if row["check_id"] == check_id)


class CmsPermissionGraphTests(unittest.TestCase):
    def _deny_before_address(self, model: dict) -> None:
        with patch.object(graph, "_address") as address:
            with self.assertRaises(graph.CmsPermissionGraphAnalysisError):
                graph.analyze_supplied_cms_permission_graph(model)
            address.assert_not_called()

    def test_fixture_replay_determinism_and_effects(self) -> None:
        model = graph.component_fixture()
        report = graph.analyze_supplied_cms_permission_graph(model)
        body = report.to_dict()
        self.assertEqual(body["profile_id"], graph.PROFILE_ID)
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 1)
        self.assertEqual(
            [row["outcome"] for row in body["check_observations"]],
            [
                "matches_declared_permission_graph",
                "candidate_declared_deny_allowed_contradiction",
                "unknown",
            ],
        )
        self.assertEqual(
            _row(model, "alice-inherited")["effective_permissions"],
            ["content.edit", "content.read"],
        )
        self.assertEqual(set(body["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in body["flags"].values()))
        self.assertEqual(
            report.to_json(), graph.analyze_supplied_cms_permission_graph(model).to_json()
        )
        detached = graph.CmsPermissionGraphAnalysis.from_json(report.to_json())
        self.assertEqual(
            graph.verify_supplied_cms_permission_graph_analysis(detached, model=model).to_json(),
            report.to_json(),
        )
        model["roles"][1]["grants"].append("content.write")
        with self.assertRaises(graph.CmsPermissionGraphAnalysisError):
            graph.verify_supplied_cms_permission_graph_analysis(report, model=model)

    def test_exact_inheritance_and_availability_disposition(self) -> None:
        model = graph.component_fixture()
        self.assertEqual(_row(model)["expected_outcome"], "deny")
        model["checks"][1]["supplied_outcome"] = "denied"
        self.assertEqual(_row(model)["outcome"], "matches_declared_permission_graph")
        model["checks"][0]["supplied_outcome"] = "denied"
        self.assertEqual(
            _row(model, "alice-inherited")["outcome"], "declared_allow_denied_contradiction"
        )
        self.assertEqual(
            graph.analyze_supplied_cms_permission_graph(model).to_dict()["candidate_count"], 0
        )

    def test_unknown_completeness_and_outcome_never_promote(self) -> None:
        changes = (
            (lambda x: x.update(graph_complete=False), "role_graph_incomplete"),
            (lambda x: x.update(policy_extensions_complete=False), "extension_policy_incomplete"),
            (
                lambda x: x["principals"][1].update(assignments_complete=False),
                "principal_assignments_incomplete",
            ),
            (
                lambda x: x["resources"][0].update(policy_complete=False),
                "resource_policy_incomplete",
            ),
            (
                lambda x: x["checks"][1].update(enforcement_scope_complete=False),
                "enforcement_scope_incomplete",
            ),
            (
                lambda x: x["checks"][1].update(observation_complete=False),
                "supplied_outcome_unknown",
            ),
            (
                lambda x: x["checks"][1].update(supplied_outcome="unknown"),
                "supplied_outcome_unknown",
            ),
        )
        for change, reason in changes:
            with self.subTest(reason=reason):
                model = graph.component_fixture()
                change(model)
                row = _row(model)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_closed_schema_cycles_references_and_sorting(self) -> None:
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x.update(platform_kind="other"),
            lambda x: x.update(graph_complete=1),
            lambda x: x["roles"][0].update(inherits=["missing"]),
            lambda x: x["roles"][1].update(inherits=["editor"]),
            lambda x: x["roles"][0].update(grants=["content.edit"] * 2),
            lambda x: x["principals"][0].update(roles=["missing"]),
            lambda x: x["resources"][0].update(policy_complete=1),
            lambda x: x["checks"][1].update(principal_id="missing"),
            lambda x: x["checks"][1].update(resource_id="missing"),
            lambda x: x["checks"][1].update(observation_complete=1),
            lambda x: x["roles"].reverse(),
        )
        for change in changes:
            with self.subTest(change=change):
                model = graph.component_fixture()
                change(model)
                self._deny_before_address(model)

    def test_bytes_duplicate_keys_and_report_forgery(self) -> None:
        model = graph.component_fixture()
        raw = json.dumps(model, sort_keys=True, separators=(",", ":")).encode("ascii")
        report = graph.analyze_supplied_cms_permission_graph(model)
        self.assertEqual(
            graph.analyze_supplied_cms_permission_graph_bytes(model_bytes=raw).to_json(),
            report.to_json(),
        )
        for invalid in (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        ):
            with self.subTest(invalid=invalid[:30]):
                with self.assertRaises(graph.CmsPermissionGraphAnalysisError):
                    graph.analyze_supplied_cms_permission_graph_bytes(model_bytes=invalid)
        forged = copy.deepcopy(report.to_dict())
        forged["candidate_count"] = 0
        with self.assertRaises(graph.CmsPermissionGraphAnalysisError):
            graph.CmsPermissionGraphAnalysis.from_dict(forged)
        with self.assertRaises(graph.CmsPermissionGraphAnalysisError):
            graph.verify_supplied_cms_permission_graph_analysis(report.to_dict(), model=model)

    def test_native_cycles_and_resource_bounds(self) -> None:
        model = graph.component_fixture()
        model["cycle"] = model
        self._deny_before_address(model)
        model = graph.component_fixture()
        model["checks"] = model["checks"] * (graph.MAX_CHECKS + 1)
        self._deny_before_address(model)
        model = graph.component_fixture()
        model["roles"][0]["role_id"] = "x" * (graph.MAX_STRING_BYTES + 1)
        self._deny_before_address(model)


if __name__ == "__main__":
    unittest.main()
