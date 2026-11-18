"""Current-source review preparation without assignment or qualification."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_collaboration_claim_graph as graph
from sunderkey import offline_collaboration_review_handoff as handoff
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey import offline_specialist_task_relations as relations

ROOT = Path(__file__).resolve().parents[2]


class OfflineCollaborationReviewHandoffTests(unittest.TestCase):
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
            "graph_label": "synthetic.commander-review",
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
                    "claim_id": "gcp",
                    "source_id": "first",
                    "observation_kind": "premise",
                    "observation_id": "gcp.ingress",
                    "scope_id": "declared.scope",
                },
                {
                    "claim_id": "azure",
                    "source_id": "second",
                    "observation_kind": "premise",
                    "observation_id": "azure.inbound",
                    "scope_id": "declared.scope",
                },
            ],
            "hypotheses": [
                {
                    "hypothesis_id": "joint",
                    "scope_id": "declared.scope",
                    "dependencies": [
                        {"kind": "claim", "id": "gcp"},
                        {"kind": "claim", "id": "azure"},
                    ],
                }
            ],
        }
        cls.report = graph.analyze_offline_collaboration_claim_graph(
            cls.model,
            source_contexts=cls.contexts,
            catalog=cls.catalog,
            repository_root=ROOT,
        )

    def prepare(self, report=None, contexts=None):
        return handoff.prepare_offline_collaboration_review_handoff(
            self.report if report is None else report,
            model=self.model,
            source_contexts=self.contexts if contexts is None else contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_packet_carries_current_catalog_owners_without_review_acceptance(self):
        packet = self.prepare()
        descriptors = {row["component_id"]: row for row in self.catalog.to_dict()["components"]}
        self.assertEqual(packet["review_status"], "prepared_not_reviewed")
        self.assertEqual(
            packet["required_reviewer_roles"], ["independent_control", "independent_assurance"]
        )
        self.assertFalse(packet["flags"]["independent_review_accepted"])
        self.assertTrue(all(value == "none" for value in packet["operational_effects"].values()))
        for item in packet["claim_review_items"]:
            claim = next(
                row
                for row in self.report["claim_observations"]
                if row["claim_id"] == item["claim_id"]
            )
            descriptor = descriptors[claim["component_id"]]
            self.assertEqual(item["ownership_reference"]["profile_id"], descriptor["profile_id"])
            self.assertEqual(
                item["ownership_reference"]["commander_profile_id"],
                descriptor["commander_profile_id"],
            )
            self.assertFalse(item["ownership_reference"]["assignment_accepted"])
            self.assertFalse(item["ownership_reference"]["review_accepted"])
        joint = packet["hypothesis_review_items"][0]
        self.assertEqual(joint["contributor_claim_ids"], ["azure", "gcp"])
        self.assertFalse(joint["ownership_incomplete"])
        self.assertEqual(
            handoff.verify_offline_collaboration_review_handoff(
                packet,
                report=self.report,
                model=self.model,
                source_contexts=self.contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            ),
            packet,
        )

    def test_changed_original_or_positive_use_packet_is_refused(self):
        packet = self.prepare()
        altered = copy.deepcopy(packet)
        altered["flags"]["positive_use_approved"] = True
        with self.assertRaises(handoff.OfflineCollaborationReviewHandoffError):
            handoff.verify_offline_collaboration_review_handoff(
                altered,
                report=self.report,
                model=self.model,
                source_contexts=self.contexts,
                catalog=self.catalog,
                repository_root=ROOT,
            )
        contexts = {**self.contexts, "second": {**self.contexts["second"]}}
        contexts["second"]["task_model"] = copy.deepcopy(contexts["second"]["task_model"])
        contexts["second"]["task_model"]["task_id"] = "changed"
        with self.assertRaises(handoff.OfflineCollaborationReviewHandoffError):
            self.prepare(contexts=contexts)


if __name__ == "__main__":
    unittest.main()
