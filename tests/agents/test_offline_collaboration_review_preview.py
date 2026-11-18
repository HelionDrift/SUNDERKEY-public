"""Bounded internal preview over separately replayed collaboration evidence."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_collaboration_review_handoff as handoff
from sunderkey import offline_collaboration_review_preview as preview
from sunderkey import offline_collaboration_claim_graph as graph

from . import test_offline_collaboration_review_handoff as fixture

ROOT = fixture.ROOT
SENTINEL = "PrivateSecretSentinelNeverInPreview"


class OfflineCollaborationReviewPreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.OfflineCollaborationReviewHandoffTests.setUpClass()
        source = fixture.OfflineCollaborationReviewHandoffTests
        cls.catalog = source.catalog
        cls.contexts = source.contexts
        cls.model = source.model
        cls.report = source.report
        with patch.object(
            graph, "verify_offline_collaboration_claim_graph", return_value=cls.report
        ):
            cls.packet = handoff.prepare_offline_collaboration_review_handoff(
                cls.report,
                model=cls.model,
                source_contexts=cls.contexts,
                catalog=cls.catalog,
                repository_root=ROOT,
            )

    def build(self, *, packet=None, report=None, model=None, contexts=None):
        return preview.prepare_offline_collaboration_review_preview(
            self.packet if packet is None else packet,
            report=self.report if report is None else report,
            model=self.model if model is None else model,
            source_contexts=self.contexts if contexts is None else contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def verify(self, produced, *, packet=None, report=None, model=None, contexts=None):
        return preview.verify_offline_collaboration_review_preview(
            produced,
            packet=self.packet if packet is None else packet,
            report=self.report if report is None else report,
            model=self.model if model is None else model,
            source_contexts=self.contexts if contexts is None else contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_preview_contains_only_metadata_and_no_supplied_labels(self):
        packet = copy.deepcopy(self.packet)
        packet["claim_review_items"][0]["claim_id"] = SENTINEL
        packet["hypothesis_review_items"][0]["hypothesis_id"] = SENTINEL
        packet["hypothesis_review_items"][0]["contributor_claim_ids"] = [SENTINEL]
        with patch.object(
            handoff, "verify_offline_collaboration_review_handoff", return_value=packet
        ):
            produced = self.build(packet=packet)
            self.assertEqual(self.verify(produced, packet=packet), produced)
        self.assertNotIn(SENTINEL, json.dumps(produced, sort_keys=True))
        self.assertEqual(produced["source_count"], 2)
        self.assertEqual(produced["claim_count"], 2)
        self.assertEqual(produced["hypothesis_count"], 1)
        self.assertEqual(sum(produced["claim_status_counts"].values()), 2)
        self.assertEqual(sum(produced["hypothesis_status_counts"].values()), 1)
        self.assertEqual(produced["review_status"], "internal_preview_not_reviewed")
        self.assertEqual(produced["qualification_effect"], "none")
        self.assertFalse(produced["customer_publication_approved"])
        self.assertTrue(all(value == "none" for value in produced["operational_effects"].values()))

    def test_nested_and_type_mutations_are_refused(self):
        with patch.object(
            handoff, "verify_offline_collaboration_review_handoff", return_value=self.packet
        ):
            produced = self.build()
            altered = copy.deepcopy(produced)
            altered["claim_status_counts"]["unassessed"] = True
            with self.assertRaises(preview.OfflineCollaborationReviewPreviewError):
                self.verify(altered)
            altered = copy.deepcopy(produced)
            altered["catalog_profile_ids"]["commander"].append(SENTINEL)
            with self.assertRaises(preview.OfflineCollaborationReviewPreviewError):
                self.verify(altered)
            altered = copy.deepcopy(produced)
            altered["raw_request"] = SENTINEL
            with self.assertRaises(preview.OfflineCollaborationReviewPreviewError):
                self.verify(altered)

    def test_source_count_uses_the_replayed_report_copy(self):
        source = copy.deepcopy(self.report)
        expected_count = len(source["source_bindings"])

        def change_original_after_capture(*args, **kwargs):
            source["source_bindings"].append(copy.deepcopy(source["source_bindings"][0]))
            return self.packet

        with patch.object(
            handoff,
            "verify_offline_collaboration_review_handoff",
            side_effect=change_original_after_capture,
        ):
            produced = self.build(report=source)
        self.assertEqual(produced["source_count"], expected_count)
        self.assertEqual(len(source["source_bindings"]), expected_count + 1)

    def test_original_drift_is_refused(self):
        with patch.object(
            handoff, "verify_offline_collaboration_review_handoff", return_value=self.packet
        ):
            produced = self.build()
        contexts = {**self.contexts, "second": {**self.contexts["second"]}}
        contexts["second"]["task_model"] = copy.deepcopy(contexts["second"]["task_model"])
        contexts["second"]["task_model"]["task_id"] = "different-task"
        with self.assertRaises(preview.OfflineCollaborationReviewPreviewError):
            self.verify(produced, contexts=contexts)


if __name__ == "__main__":
    unittest.main()
