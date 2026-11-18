"""Only expiring, zero-confidence hypothesis facts cross the world boundary."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import attack_world_model as world
from sunderkey import offline_claim_world_projection as projection
from sunderkey import offline_collaboration_claim_graph as graph
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey import offline_specialist_task_relations as relations

ROOT = Path(__file__).resolve().parents[2]


class OfflineClaimWorldProjectionTests(unittest.TestCase):
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
        cls.graph_model = {
            "schema_version": 1,
            "graph_label": "synthetic.world-hypotheses",
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
                    "claim_id": "gcp.allow",
                    "source_id": "first",
                    "observation_kind": "premise",
                    "observation_id": "gcp.ingress",
                    "scope_id": "declared.scope",
                },
                {
                    "claim_id": "azure.allow",
                    "source_id": "second",
                    "observation_kind": "premise",
                    "observation_id": "azure.inbound",
                    "scope_id": "declared.scope",
                },
                {
                    "claim_id": "gcp.unknown",
                    "source_id": "second",
                    "observation_kind": "premise",
                    "observation_id": "gcp.egress",
                    "scope_id": "declared.scope",
                },
            ],
            "hypotheses": [
                {
                    "hypothesis_id": "known",
                    "scope_id": "declared.scope",
                    "dependencies": [
                        {"kind": "claim", "id": "gcp.allow"},
                        {"kind": "claim", "id": "azure.allow"},
                    ],
                },
                {
                    "hypothesis_id": "unknown",
                    "scope_id": "declared.scope",
                    "dependencies": [{"kind": "claim", "id": "gcp.unknown"}],
                },
            ],
        }
        cls.graph_report = graph.analyze_offline_collaboration_claim_graph(
            cls.graph_model,
            source_contexts=cls.contexts,
            catalog=cls.catalog,
            repository_root=ROOT,
        )
        cls.plan = {
            "schema_version": 1,
            "projection_label": "synthetic.review-world",
            "scope_id": "declared.scope",
            "projected_at": "2026-09-29T12:00:00Z",
            "expires_at": "2026-09-30T12:00:00Z",
            "nodes": [
                {"node_id": "asset:source", "node_kind": "asset", "label": "Synthetic source"},
                {"node_id": "service:middle", "node_kind": "service", "label": "Synthetic service"},
                {"node_id": "asset:target", "node_kind": "asset", "label": "Synthetic target"},
            ],
            "links": [
                {
                    "hypothesis_id": "known",
                    "source_node_id": "asset:source",
                    "target_node_id": "service:middle",
                    "technique_refs": ["technique:review"],
                },
                {
                    "hypothesis_id": "unknown",
                    "source_node_id": "service:middle",
                    "target_node_id": "asset:target",
                    "technique_refs": [],
                },
            ],
        }

    def project(self, model=None, report=None, contexts=None):
        return projection.project_offline_claims_to_world(
            self.plan if model is None else model,
            report=self.graph_report if report is None else report,
            graph_model=self.graph_model,
            source_contexts=self.contexts if contexts is None else contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_matches_are_only_hypothetical_and_unknown_edges_are_withheld(self):
        packet = self.project()
        snapshot = world.AttackWorldSnapshot.from_dict(packet["snapshot"])
        self.assertEqual(len(snapshot.nodes), 3)
        self.assertEqual(len(snapshot.edges), 1)
        self.assertEqual(packet["withheld_links"][0]["hypothesis_id"], "unknown")
        self.assertTrue(
            all(
                fact.evidence.verification_state is world.VerificationState.HYPOTHESIS
                and fact.evidence.confidence == 0.0
                for fact in (*snapshot.nodes, *snapshot.edges)
            )
        )
        result = world.query_candidate_attack_paths(
            snapshot,
            start_node_ids=["asset:source"],
            target_node_ids=["service:middle"],
            required_scope_refs=["declared.scope"],
            as_of=self.plan["projected_at"],
        )
        self.assertEqual(len(result.verified_paths), 0)
        self.assertEqual(len(result.hypothesis_paths), 1)
        expired = world.query_candidate_attack_paths(
            snapshot,
            start_node_ids=["asset:source"],
            target_node_ids=["service:middle"],
            as_of=self.plan["expires_at"],
        )
        self.assertEqual(len(expired.hypothesis_paths), 0)
        self.assertFalse(packet["flags"]["verified_path_created"])
        self.assertTrue(all(value == "none" for value in packet["operational_effects"].values()))
        self.assertEqual(
            projection.verify_offline_claim_world_projection(
                packet,
                model=self.plan,
                report=self.graph_report,
                graph_model=self.graph_model,
                source_contexts=self.contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            ),
            packet,
        )

    def test_rejects_unsafe_node_time_and_missing_hypothesis(self):
        changed = copy.deepcopy(self.plan)
        changed["nodes"][0]["node_kind"] = "credential"
        with self.assertRaises(projection.OfflineClaimWorldProjectionError):
            self.project(model=changed)
        changed = copy.deepcopy(self.plan)
        changed["expires_at"] = "2026-10-01T12:00:01Z"
        with self.assertRaises(projection.OfflineClaimWorldProjectionError):
            self.project(model=changed)
        changed = copy.deepcopy(self.plan)
        changed["projected_at"] = "9999-12-31T22:00:00Z"
        changed["expires_at"] = "9999-12-31T23:00:00Z"
        self.assertEqual(projection._plan(changed)["expires_at"], changed["expires_at"])
        changed = copy.deepcopy(self.plan)
        changed["links"] = changed["links"][:1]
        changed["nodes"] = changed["nodes"][:2]
        with self.assertRaises(projection.OfflineClaimWorldProjectionError):
            self.project(model=changed)

    def test_changed_original_and_claimed_verified_packet_are_refused(self):
        packet = self.project()
        changed = copy.deepcopy(packet)
        changed["snapshot"]["edges"][0]["evidence"]["verification_state"] = "verified"
        with self.assertRaises(projection.OfflineClaimWorldProjectionError):
            projection.verify_offline_claim_world_projection(
                changed,
                model=self.plan,
                report=self.graph_report,
                graph_model=self.graph_model,
                source_contexts=self.contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            )
        contexts = {**self.contexts, "second": {**self.contexts["second"]}}
        contexts["second"]["task_model"] = copy.deepcopy(contexts["second"]["task_model"])
        contexts["second"]["task_model"]["task_id"] = "changed"
        with self.assertRaises(projection.OfflineClaimWorldProjectionError):
            self.project(contexts=contexts)


if __name__ == "__main__":
    unittest.main()
