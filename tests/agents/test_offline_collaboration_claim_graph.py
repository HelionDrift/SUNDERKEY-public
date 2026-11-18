"""Cross-task relation replay, explicit scope and fail-closed claim DAG tests."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_collaboration_claim_graph as graph
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey import offline_specialist_task_relations as relations

ROOT = Path(__file__).resolve().parents[2]


class OfflineCollaborationClaimGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        cls.contexts = {}
        for source_id in ("first", "second"):
            task_model = relations.task_fixture()
            task_model["task_id"] += "." + source_id
            task_report = task.run_offline_specialist_task(
                task_model, catalog=cls.catalog, repository_root=ROOT
            )
            relation_model = relations.component_fixture()
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
            "graph_label": "synthetic.cross-task-review",
            "sources": [{"source_id": "first"}, {"source_id": "second"}],
            "scope_bindings": [
                {
                    "scope_id": "declared.scope.one",
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
                    "scope_id": "declared.scope.one",
                },
                {
                    "claim_id": "second.allow",
                    "source_id": "second",
                    "observation_kind": "premise",
                    "observation_id": "azure.inbound",
                    "scope_id": "declared.scope.one",
                },
                {
                    "claim_id": "second.unknown",
                    "source_id": "second",
                    "observation_kind": "premise",
                    "observation_id": "gcp.egress",
                    "scope_id": "declared.scope.one",
                },
            ],
            "hypotheses": [
                {
                    "hypothesis_id": "known",
                    "scope_id": "declared.scope.one",
                    "dependencies": [
                        {"kind": "claim", "id": "first.allow"},
                        {"kind": "claim", "id": "second.allow"},
                    ],
                },
                {
                    "hypothesis_id": "overall",
                    "scope_id": "declared.scope.one",
                    "dependencies": [
                        {"kind": "hypothesis", "id": "known"},
                        {"kind": "claim", "id": "second.unknown"},
                    ],
                },
            ],
        }
        cls.report = graph.analyze_offline_collaboration_claim_graph(
            cls.model, source_contexts=cls.contexts, catalog=cls.catalog, repository_root=ROOT
        )

    def analyze(self, model=None, contexts=None):
        return graph.analyze_offline_collaboration_claim_graph(
            self.model if model is None else model,
            source_contexts=self.contexts if contexts is None else contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_replays_two_distinct_original_tasks_and_preserves_uncertainty(self):
        report = self.report
        self.assertEqual(len(report["source_bindings"]), 2)
        self.assertNotEqual(
            report["source_bindings"][0]["task_binding"]["task_result_sha256"],
            report["source_bindings"][1]["task_binding"]["task_result_sha256"],
        )
        self.assertEqual(
            {row["hypothesis_id"]: row["status"] for row in report["hypothesis_observations"]},
            {"known": "matches_declared_expectation", "overall": "unassessed"},
        )
        self.assertFalse(report["flags"]["scope_equivalence_proven"])
        self.assertFalse(report["flags"]["positive_use_approved"])
        self.assertTrue(all(value == "none" for value in report["operational_effects"].values()))
        self.assertEqual(
            graph.verify_offline_collaboration_claim_graph(
                report,
                model=self.model,
                source_contexts=self.contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            ),
            report,
        )

    def test_rejects_changed_original_and_tampered_report(self):
        contexts = {**self.contexts, "second": {**self.contexts["second"]}}
        contexts["second"]["task_model"] = copy.deepcopy(contexts["second"]["task_model"])
        contexts["second"]["task_model"]["task_id"] = "changed"
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            self.analyze(contexts=contexts)
        duplicate = {"first": self.contexts["first"], "second": self.contexts["first"]}
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            self.analyze(contexts=duplicate)
        altered = copy.deepcopy(self.report)
        altered["flags"]["scope_equivalence_proven"] = True
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            graph.verify_offline_collaboration_claim_graph(
                altered,
                model=self.model,
                source_contexts=self.contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            )

    def test_rejects_unbound_or_cross_scope_claims_before_replay(self):
        changed = copy.deepcopy(self.model)
        changed["scope_bindings"][0]["source_ids"] = ["first"]
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            self.analyze(model=changed)
        changed = copy.deepcopy(self.model)
        changed["claims"][0]["scope_id"] = "other"
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            self.analyze(model=changed)

    def test_rejects_cycles_missing_observations_and_untyped_inputs(self):
        changed = copy.deepcopy(self.model)
        changed["hypotheses"][0]["dependencies"].append({"kind": "hypothesis", "id": "overall"})
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            self.analyze(model=changed)
        changed = copy.deepcopy(self.model)
        changed["claims"][0]["observation_id"] = "missing"
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            self.analyze(model=changed)
        changed = copy.deepcopy(self.model)
        changed["schema_version"] = True
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            self.analyze(model=changed)
        changed = copy.deepcopy(self.model)
        changed["claims"][0]["source_id"] = []
        with self.assertRaises(graph.OfflineCollaborationClaimGraphError):
            self.analyze(model=changed)


if __name__ == "__main__":
    unittest.main()
