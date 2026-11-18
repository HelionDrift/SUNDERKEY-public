"""Separate graph replay is required before unsigned claim-status comparison."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_azure_nsg_analysis as azure
from sunderkey import offline_collaboration_claim_delta as delta
from sunderkey import offline_collaboration_claim_graph as graph
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey import offline_specialist_task_relations as relations

ROOT = Path(__file__).resolve().parents[2]


class OfflineCollaborationClaimDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        shared = cls._relation_context("first")
        before_second = cls._relation_context("before.second")
        after_second = cls._relation_context("after.second", deny_azure=True)
        graph_model = {
            "schema_version": 1,
            "graph_label": "synthetic.claim.delta",
            "sources": [{"source_id": "first"}, {"source_id": "second"}],
            "scope_bindings": [
                {
                    "scope_id": "declared.scope",
                    "source_ids": ["first", "second"],
                    "basis": "caller_declared_unverified",
                }
            ],
            "claims": [
                {
                    "claim_id": "first.allow",
                    "source_id": "first",
                    "observation_kind": "premise",
                    "observation_id": "gcp.ingress",
                    "scope_id": "declared.scope",
                },
                {
                    "claim_id": "second.azure",
                    "source_id": "second",
                    "observation_kind": "premise",
                    "observation_id": "azure.inbound",
                    "scope_id": "declared.scope",
                },
                {
                    "claim_id": "second.unknown",
                    "source_id": "second",
                    "observation_kind": "premise",
                    "observation_id": "gcp.egress",
                    "scope_id": "declared.scope",
                },
            ],
            "hypotheses": [
                {
                    "hypothesis_id": "combined",
                    "scope_id": "declared.scope",
                    "dependencies": [
                        {"kind": "claim", "id": "first.allow"},
                        {"kind": "claim", "id": "second.azure"},
                    ],
                },
                {
                    "hypothesis_id": "stable",
                    "scope_id": "declared.scope",
                    "dependencies": [{"kind": "claim", "id": "first.allow"}],
                },
                {
                    "hypothesis_id": "unknown",
                    "scope_id": "declared.scope",
                    "dependencies": [{"kind": "claim", "id": "second.unknown"}],
                },
            ],
        }
        cls.graph_contexts = {}
        for source_id, second in (("before", before_second), ("after", after_second)):
            model = copy.deepcopy(graph_model)
            model["graph_label"] += "." + source_id
            sources = {"first": shared, "second": second}
            report = graph.analyze_offline_collaboration_claim_graph(
                model, source_contexts=sources, catalog=cls.catalog, repository_root=ROOT
            )
            cls.graph_contexts[source_id] = {
                "graph_report": report,
                "graph_model": model,
                "source_contexts": sources,
            }
        cls.model = {
            "schema_version": 1,
            "comparison_label": "synthetic.claim-status-delta",
            "sources": [{"source_id": "before"}, {"source_id": "after"}],
            "pairs": [
                {
                    "pair_id": pair_id,
                    "subject_id": "declared.hypothesis." + hypothesis_id,
                    "basis": "caller_declared_unverified",
                    "before": {"source_id": "before", "hypothesis_id": hypothesis_id},
                    "after": {"source_id": "after", "hypothesis_id": hypothesis_id},
                }
                for pair_id, hypothesis_id in (
                    ("changed", "combined"),
                    ("same", "stable"),
                    ("unknown", "unknown"),
                )
            ],
        }

    @classmethod
    def _relation_context(cls, suffix: str, *, deny_azure: bool = False) -> dict:
        task_model = relations.task_fixture()
        task_model["task_id"] += "." + suffix
        if deny_azure:
            task_model["jobs"][1]["request"]["payload"]["model"]["nsgs"][0]["rules"][0][
                "access"
            ] = "Deny"
        task_report = task.run_offline_specialist_task(
            task_model, catalog=cls.catalog, repository_root=ROOT
        )
        relation_model = relations.component_fixture()
        if deny_azure:
            azure_result = next(
                row["result"] for row in task_report.to_dict()["jobs"] if row["job_id"] == "azure"
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
        return {
            "relation_report": relation_report,
            "relation_model": relation_model,
            "task_report": task_report,
            "task_model": task_model,
        }

    def analyze(self, model=None, contexts=None):
        return delta.analyze_offline_collaboration_claim_delta(
            self.model if model is None else model,
            graph_contexts=self.graph_contexts if contexts is None else contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_changed_same_and_unknown_stay_distinct_without_authority(self):
        report = self.analyze()
        self.assertEqual(
            {row["pair_id"]: row["state"] for row in report["pair_observations"]},
            {
                "changed": "changed_declared_status",
                "same": "same_declared_status",
                "unknown": "unassessed",
            },
        )
        self.assertFalse(report["flags"]["scope_equivalence_proven"])
        self.assertFalse(report["flags"]["time_order_proven"])
        self.assertFalse(report["flags"]["finding_claimed"])
        self.assertTrue(all(value == "none" for value in report["operational_effects"].values()))
        self.assertEqual(
            delta.verify_offline_collaboration_claim_delta(
                report,
                model=self.model,
                graph_contexts=self.graph_contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            ),
            report,
        )

    def test_changed_original_and_repeated_evidence_are_refused(self):
        contexts = {**self.graph_contexts, "after": {**self.graph_contexts["after"]}}
        contexts["after"]["source_contexts"] = {
            **contexts["after"]["source_contexts"],
            "second": {**contexts["after"]["source_contexts"]["second"]},
        }
        contexts["after"]["source_contexts"]["second"]["task_model"] = copy.deepcopy(
            contexts["after"]["source_contexts"]["second"]["task_model"]
        )
        contexts["after"]["source_contexts"]["second"]["task_model"]["task_id"] = "changed"
        with self.assertRaises(delta.OfflineCollaborationClaimDeltaError):
            self.analyze(contexts=contexts)
        with self.assertRaises(delta.OfflineCollaborationClaimDeltaError):
            self.analyze(
                contexts={
                    "before": self.graph_contexts["before"],
                    "after": self.graph_contexts["before"],
                }
            )

    def test_untyped_subject_and_tampered_packet_are_refused(self):
        model = copy.deepcopy(self.model)
        model["pairs"][0]["basis"] = "verified"
        with self.assertRaises(delta.OfflineCollaborationClaimDeltaError):
            self.analyze(model=model)
        report = self.analyze()
        report["flags"]["positive_use_approved"] = True
        with self.assertRaises(delta.OfflineCollaborationClaimDeltaError):
            delta.verify_offline_collaboration_claim_delta(
                report,
                model=self.model,
                graph_contexts=self.graph_contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            )


if __name__ == "__main__":
    unittest.main()
