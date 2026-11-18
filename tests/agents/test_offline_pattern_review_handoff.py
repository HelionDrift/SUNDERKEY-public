"""Current pattern premises remain unaccepted human review work."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_pattern_review_handoff as handoff
from sunderkey import offline_specialist_components as components
from tests.agents.test_offline_pattern_claim_graph import context, graph_fixture
from tests.agents.test_offline_pattern_task_relations import (
    expanded_plan_fixture,
    expanded_task_fixture,
    plan_fixture,
    task_fixture,
)
from sunderkey.offline_pattern_claim_graph import analyze_supplied_pattern_claim_graph

ROOT = Path(__file__).resolve().parents[2]


class PatternReviewHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )
        cls.contexts = {
            "three": context(cls.catalog, task_fixture(), plan_fixture()),
            "six": context(cls.catalog, expanded_task_fixture(), expanded_plan_fixture()),
        }
        cls.model = graph_fixture()
        cls.report = analyze_supplied_pattern_claim_graph(
            cls.model, source_contexts=cls.contexts,
            catalog=cls.catalog, repository_root=ROOT,
        )

    def prepare(self, report=None, contexts=None) -> dict:
        return handoff.prepare_pattern_review_handoff(
            self.report if report is None else report,
            model=self.model,
            source_contexts=self.contexts if contexts is None else contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_packet_refs_current_owners_without_review_acceptance(self) -> None:
        packet = self.prepare()
        descriptors = {
            row["component_id"]: row for row in self.catalog.to_dict()["components"]
        }
        self.assertEqual(packet["review_status"], "prepared_not_reviewed")
        self.assertEqual(packet["graph_analysis_sha256"], self.report.to_dict()["analysis_sha256"])
        self.assertFalse(packet["flags"]["independent_review_accepted"])
        self.assertFalse(packet["flags"]["positive_use_approved"])
        self.assertEqual(set(packet["operational_effects"].values()), {"none"})
        for item in packet["claim_review_items"]:
            claim = next(
                row for row in self.report.to_dict()["claim_observations"]
                if row["claim_id"] == item["claim_id"]
            )
            descriptor = descriptors[claim["component_id"]]
            self.assertEqual(item["ownership_reference"]["profile_id"], descriptor["profile_id"])
            self.assertFalse(item["ownership_reference"]["assignment_accepted"])
            self.assertFalse(item["ownership_reference"]["review_accepted"])
        self.assertEqual(
            packet["hypothesis_review_items"][0]["contributor_claim_ids"],
            ["claim-configuration", "claim-query"],
        )
        self.assertEqual(
            handoff.verify_pattern_review_handoff(
                packet, report=self.report, model=self.model,
                source_contexts=self.contexts, catalog=self.catalog,
                repository_root=ROOT,
            ),
            packet,
        )

    def test_changed_original_or_positive_use_packet_is_refused(self) -> None:
        packet = self.prepare()
        altered = copy.deepcopy(packet)
        altered["flags"]["positive_use_approved"] = True
        with self.assertRaises(handoff.PatternReviewHandoffError):
            handoff.verify_pattern_review_handoff(
                altered, report=self.report, model=self.model,
                source_contexts=self.contexts, catalog=self.catalog,
                repository_root=ROOT,
            )
        contexts = {**self.contexts, "six": {**self.contexts["six"]}}
        contexts["six"]["task_model"] = copy.deepcopy(contexts["six"]["task_model"])
        contexts["six"]["task_model"]["task_id"] = "changed"
        with self.assertRaises(handoff.PatternReviewHandoffError):
            self.prepare(contexts=contexts)


if __name__ == "__main__":
    unittest.main()
