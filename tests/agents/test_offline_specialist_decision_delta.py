"""Semantic supplied-flow deltas require separate original/current replay."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_azure_nsg_analysis as azure
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_decision_delta as delta
from sunderkey import offline_specialist_task as task
from sunderkey import offline_specialist_task_relations as relations

ROOT = Path(__file__).resolve().parents[2]


class OfflineSpecialistDecisionDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        before_model = relations.task_fixture()
        before_model["task_id"] += ".before"
        after_model = copy.deepcopy(before_model)
        after_model["task_id"] += ".after"
        after_model["jobs"][1]["request"]["payload"]["model"]["nsgs"][0]["rules"][0]["access"] = (
            "Deny"
        )
        cls.contexts = {}
        for source_id, task_model in (("before", before_model), ("after", after_model)):
            task_report = task.run_offline_specialist_task(
                task_model, catalog=cls.catalog, repository_root=ROOT
            )
            relation_model = relations.component_fixture()
            if source_id == "after":
                azure_result = next(
                    row["result"]
                    for row in task_report.to_dict()["jobs"]
                    if row["job_id"] == "azure"
                )
                pin = azure_result["analysis"]["source_model_sha256"]
                for premise in relation_model["premises"]:
                    if premise["component_id"] == azure.COMPONENT_ID:
                        premise["source_model_sha256"] = pin
            relation_report = relations.analyze_offline_specialist_task_relations(
                relation_model,
                task_report=task_report,
                task_model=task_model,
                catalog=cls.catalog,
                repository_root=ROOT,
            )
            cls.contexts[source_id] = {
                "relation_report": relation_report,
                "relation_model": relation_model,
                "task_report": task_report,
                "task_model": task_model,
            }
        cls.model = {
            "schema_version": 1,
            "comparison_label": "synthetic.supplied-flow-delta",
            "sources": [{"source_id": "before"}, {"source_id": "after"}],
            "pairs": [
                {
                    "pair_id": "azure.changed",
                    "subject_id": "declared.azure.flow",
                    "basis": "caller_declared_unverified",
                    "before": {"source_id": "before", "premise_id": "azure.inbound"},
                    "after": {"source_id": "after", "premise_id": "azure.inbound"},
                },
                {
                    "pair_id": "gcp.same",
                    "subject_id": "declared.gcp.ingress",
                    "basis": "caller_declared_unverified",
                    "before": {"source_id": "before", "premise_id": "gcp.ingress"},
                    "after": {"source_id": "after", "premise_id": "gcp.ingress"},
                },
                {
                    "pair_id": "gcp.unknown",
                    "subject_id": "declared.gcp.egress",
                    "basis": "caller_declared_unverified",
                    "before": {"source_id": "before", "premise_id": "gcp.egress"},
                    "after": {"source_id": "after", "premise_id": "gcp.egress"},
                },
            ],
        }

    def analyze(self, model=None, contexts=None):
        return delta.analyze_offline_specialist_decision_delta(
            self.model if model is None else model,
            source_contexts=self.contexts if contexts is None else contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_changed_same_and_unknown_are_distinct_nonqualifying_states(self):
        report = self.analyze()
        states = {row["pair_id"]: row["state"] for row in report["pair_observations"]}
        self.assertEqual(
            states,
            {
                "azure.changed": "changed_supplied_decision",
                "gcp.same": "same_supplied_decision",
                "gcp.unknown": "unassessed",
            },
        )
        changed = report["pair_observations"][0]
        self.assertEqual(changed["before"]["component_id"], azure.COMPONENT_ID)
        self.assertEqual(changed["after"]["component_id"], azure.COMPONENT_ID)
        self.assertNotEqual(
            changed["before"]["actual_decision"], changed["after"]["actual_decision"]
        )
        self.assertFalse(report["flags"]["subject_equivalence_proven"])
        self.assertFalse(report["flags"]["time_order_proven"])
        self.assertFalse(report["flags"]["improvement_claimed"])
        self.assertTrue(all(value == "none" for value in report["operational_effects"].values()))
        self.assertEqual(
            delta.verify_offline_specialist_decision_delta(
                report,
                model=self.model,
                source_contexts=self.contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            ),
            report,
        )

    def test_changed_original_or_cross_component_pair_refused(self):
        contexts = {**self.contexts, "after": {**self.contexts["after"]}}
        contexts["after"]["task_model"] = copy.deepcopy(contexts["after"]["task_model"])
        contexts["after"]["task_model"]["task_id"] = "changed"
        with self.assertRaises(delta.OfflineSpecialistDecisionDeltaError):
            self.analyze(contexts=contexts)
        model = copy.deepcopy(self.model)
        model["pairs"][0]["after"]["premise_id"] = "gcp.ingress"
        with self.assertRaises(delta.OfflineSpecialistDecisionDeltaError):
            self.analyze(model=model)

    def test_metadata_tamper_and_untyped_subject_binding_refused(self):
        report = self.analyze()
        changed = copy.deepcopy(report)
        changed["flags"]["improvement_claimed"] = True
        with self.assertRaises(delta.OfflineSpecialistDecisionDeltaError):
            delta.verify_offline_specialist_decision_delta(
                changed,
                model=self.model,
                source_contexts=self.contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            )
        model = copy.deepcopy(self.model)
        model["pairs"][0]["basis"] = "verified"
        with self.assertRaises(delta.OfflineSpecialistDecisionDeltaError):
            self.analyze(model=model)


if __name__ == "__main__":
    unittest.main()
