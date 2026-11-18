"""Value-free supplied Infrastructure-as-Code change-graph tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_iac_change_graph import (
    IacChangeGraphError,
    analyze_supplied_iac_change_graph,
    component_fixture,
    verify_supplied_iac_change_graph,
    verify_supplied_iac_change_graph_bytes,
)
from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)

ROOT = Path(__file__).resolve().parents[2]


class IacChangeGraphTests(unittest.TestCase):
    def test_catalog_dispatch_preserves_nonqualification_and_original_replay(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-iac-change-graph-component.json").read_text(encoding="utf-8")
        )
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(
            request,
            catalog=catalog,
            repository_root=ROOT,
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D17-S12")
        self.assertEqual(result["analysis"]["candidate_count"], 1)
        self.assertFalse(result["full_candidate_assembled"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result,
                request=request,
                catalog=catalog,
                repository_root=ROOT,
            ),
            result,
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["resources"][0]["actions"] = ["update"]
        with self.assertRaises(ValueError):
            verify_offline_specialist_component_result(
                result,
                request=changed,
                catalog=catalog,
                repository_root=ROOT,
            )
        changed = copy.deepcopy(request)
        changed["payload"]["extra"] = "not accepted"
        with self.assertRaises(ValueError):
            run_offline_specialist_component(
                changed,
                catalog=catalog,
                repository_root=ROOT,
            )

    def test_declared_protected_dependency_replacement_is_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_iac_change_graph(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "candidate_supplied_destructive_path")
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["declared_impacts"][0]["declared_path"],
            [
                "aws_instance.web",
                "aws_security_group.edge",
            ],
        )
        self.assertFalse(body["raw_plan_accepted"])
        self.assertFalse(body["terraform_executed"])
        self.assertFalse(body["provider_contacted"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_iac_change_graph(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_iac_change_graph_bytes(
                report.to_json().encode("ascii"),
                model=model,
            ).to_json(),
            report.to_json(),
        )

    def test_no_declared_destructive_path_is_not_a_safety_claim(self) -> None:
        model = component_fixture()
        model["resources"][0]["actions"] = ["update"]
        body = analyze_supplied_iac_change_graph(model).to_dict()
        self.assertEqual(body["disposition"], "no_declared_destructive_path")
        self.assertEqual(body["declared_impacts"], [])
        self.assertFalse(body["source_authenticated"])
        self.assertFalse(body["finding_claimed"])
        model["inventory_complete"] = False
        body = analyze_supplied_iac_change_graph(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertGreater(body["unknown_count"], 0)

    def test_destructive_protected_resource_and_transitive_dependency(self) -> None:
        model = component_fixture()
        model["resources"][1]["actions"] = ["delete"]
        model["resources"].append(
            {
                "address": "aws_lb.public",
                "actions": ["no-op"],
                "depends_on": ["aws_instance.web"],
            }
        )
        model["protected"] = ["aws_lb.public"]
        body = analyze_supplied_iac_change_graph(model).to_dict()
        self.assertEqual(body["candidate_count"], 2)
        self.assertEqual(
            [row["declared_path"] for row in body["declared_impacts"]],
            [
                ["aws_lb.public", "aws_instance.web"],
                ["aws_lb.public", "aws_instance.web", "aws_security_group.edge"],
            ],
        )

    def test_missing_nodes_and_cycles_keep_quality_uncertainty_visible(self) -> None:
        model = component_fixture()
        model["resources"][0]["actions"] = ["no-op"]
        model["resources"][0]["depends_on"] = ["aws_instance.web", "aws_vpc.missing"]
        body = analyze_supplied_iac_change_graph(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(
            {row["issue"] for row in body["model_quality_issues"]},
            {"declared_dependency_cycle", "undeclared_dependency"},
        )
        model["protected"] = ["aws_instance.absent"]
        body = analyze_supplied_iac_change_graph(model).to_dict()
        self.assertIn(
            "undeclared_protected_resource",
            {row["issue"] for row in body["model_quality_issues"]},
        )

    def test_raw_values_ambiguous_actions_and_duplicate_keys_are_rejected(self) -> None:
        cases = []
        model = component_fixture()
        model["resources"][0]["change"] = {"before": {"password": "example"}}
        cases.append(model)
        model = component_fixture()
        model["resources"][0]["actions"] = ["create", "update"]
        cases.append(model)
        model = component_fixture()
        model["resources"][0]["actions"] = [{"delete": True}]
        cases.append(model)
        model = component_fixture()
        model["resources"][0]["depends_on"] = ["aws_instance.web", "aws_instance.web"]
        cases.append(model)
        model = component_fixture()
        model["resources"].append(copy.deepcopy(model["resources"][0]))
        cases.append(model)
        model = component_fixture()
        model["resources"][0]["address"] = "secret value with spaces"
        cases.append(model)
        model = component_fixture()
        model["schema_version"] = True
        cases.append(model)
        model = component_fixture()
        model["inventory_complete"] = 1
        cases.append(model)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_iac_change_graph(model)

    def test_original_replay_rejects_substitution_and_forged_export(self) -> None:
        model = component_fixture()
        report = analyze_supplied_iac_change_graph(model)
        changed = copy.deepcopy(model)
        changed["resources"][0]["actions"] = ["update"]
        with self.assertRaises(IacChangeGraphError):
            verify_supplied_iac_change_graph(report, model=changed)
        with self.assertRaises(IacChangeGraphError):
            verify_supplied_iac_change_graph(report.to_dict(), model=model)
        forged = report.to_dict()
        forged["candidate_count"] = 0
        with self.assertRaises(IacChangeGraphError):
            verify_supplied_iac_change_graph_bytes(json.dumps(forged).encode(), model=model)
        duplicated = report.to_json().replace(
            '"schema_version":1',
            '"schema_version":1,"schema_version":1',
            1,
        )
        with self.assertRaises(ValueError):
            verify_supplied_iac_change_graph_bytes(duplicated.encode(), model=model)


if __name__ == "__main__":
    unittest.main()
