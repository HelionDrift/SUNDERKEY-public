"""Unsigned review challenges can only suppress offline hypothesis edges."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import attack_world_model as world
from sunderkey import offline_claim_world_projection as base_projection
from sunderkey import offline_collaboration_review_custody as custody
from sunderkey import offline_collaboration_review_handoff as handoff
from sunderkey import offline_review_aware_world_projection as reviewed
from sunderkey import offline_specialist_components as components

from . import test_offline_collaboration_review_handoff as fixture

ROOT = Path(__file__).resolve().parents[2]


class ReviewAwareWorldProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = fixture.OfflineCollaborationReviewHandoffTests
        source.setUpClass()
        cls.catalog = source.catalog
        cls.contexts = source.contexts
        cls.graph_model = source.model
        cls.graph_report = source.report
        cls.plan = {
            "schema_version": 1,
            "projection_label": "synthetic.review-aware-world",
            "scope_id": "declared.scope",
            "projected_at": "2026-10-02T12:00:00Z",
            "expires_at": "2026-10-03T12:00:00Z",
            "nodes": [
                {"node_id": "asset:source", "node_kind": "asset", "label": "Source"},
                {"node_id": "service:target", "node_kind": "service", "label": "Target"},
            ],
            "links": [{
                "hypothesis_id": "joint",
                "source_node_id": "asset:source",
                "target_node_id": "service:target",
                "technique_refs": [],
            }],
        }
        with patch.object(
            components, "_catalog_document", return_value=cls.catalog.to_dict()
        ):
            cls.handoff = handoff.prepare_offline_collaboration_review_handoff(
                cls.graph_report, model=cls.graph_model, source_contexts=cls.contexts,
                catalog=cls.catalog, repository_root=ROOT,
            )
            cls.base = base_projection.project_offline_claims_to_world(
                cls.plan, report=cls.graph_report, graph_model=cls.graph_model,
                source_contexts=cls.contexts, catalog=cls.catalog, repository_root=ROOT,
            )
        if len(cls.base["snapshot"]["edges"]) != 1:
            raise AssertionError("fixture must contain one matching hypothesis edge")

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="review-aware-world-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "custody.sqlite3"
        self.store = custody.OfflineCollaborationReviewCustodyStore(
            self.path, tenant_id="tenant.example", declared_scope_id="declared.scope"
        )
        self.store.initialize()

    def sources(self, **changes) -> dict:
        values = {
            "projection_model": self.plan,
            "graph_report": self.graph_report,
            "graph_model": self.graph_model,
            "source_contexts": self.contexts,
            "catalog": self.catalog,
            "repository_root": ROOT,
            "handoff_packet": self.handoff,
            "review_store": self.store,
            "tenant_id": "tenant.example",
        }
        values.update(changes)
        return values

    def record(
        self, *, request_id: str = "request.one", item_kind: str = "claim",
        item_id: str = "gcp", reviewer_role: str = "independent_control",
        reviewer_subject: str = "person.control", disposition: str = "challenge",
        reason_code: str = "source_scope_challenge", recorded_at: str = "2026-10-02T12:00:00Z",
    ) -> dict:
        with patch.object(custody, "_checked_handoff", return_value=self.handoff):
            return self.store.record_review(
                request_id=request_id, item_kind=item_kind, item_id=item_id,
                reviewer_role=reviewer_role, reviewer_subject=reviewer_subject,
                disposition=disposition, reason_code=reason_code, recorded_at=recorded_at,
                packet=self.handoff, report=self.graph_report, model=self.graph_model,
                source_contexts=self.contexts, catalog=self.catalog, repository_root=ROOT,
            )

    def summary(self) -> dict:
        with patch.object(custody, "_checked_handoff", return_value=self.handoff):
            return self.store.verify_current(
                packet=self.handoff, report=self.graph_report, model=self.graph_model,
                source_contexts=self.contexts, catalog=self.catalog, repository_root=ROOT,
            )

    def derive(self) -> dict:
        return reviewed._derive(
            self.base, self.handoff, self.summary(),
            tenant_id="tenant.example", scope_id="declared.scope",
        )

    def test_real_current_replay_is_read_only_and_hypothesis_only(self) -> None:
        self.record()
        before = self.path.read_bytes()
        with patch.object(
            components, "_catalog_document", return_value=self.catalog.to_dict()
        ):
            packet = reviewed.project_review_aware_world(self.base, **self.sources())
            self.assertEqual(
                reviewed.verify_review_aware_world(packet, self.base, **self.sources()),
                packet,
            )
        self.assertEqual(before, self.path.read_bytes())
        snapshot = world.AttackWorldSnapshot.from_dict(packet["snapshot"])
        self.assertEqual(len(snapshot.edges), 0)
        self.assertFalse(packet["independent_review_accepted"])
        self.assertFalse(packet["positive_use_approved"])
        self.assertEqual(packet["identity_assurance"], "operator_asserted_unsigned")
        self.assertTrue(all(value == "none" for value in packet["operational_effects"].values()))

    def test_direct_hypothesis_challenge_suppresses_edge(self) -> None:
        self.record(item_kind="hypothesis", item_id="joint")
        packet = self.derive()
        self.assertEqual(len(packet["snapshot"]["edges"]), 0)
        self.assertEqual(
            packet["review_suppressed_links"][0]["blocking_items"],
            ["hypothesis:joint"],
        )

    def test_contributor_challenge_and_missing_evidence_suppress_edge(self) -> None:
        self.record()
        self.record(
            request_id="request.two", item_id="azure", reviewer_subject="person.other",
            disposition="needs_evidence", reason_code="missing_evidence",
            recorded_at="2026-10-02T12:01:00Z",
        )
        packet = self.derive()
        self.assertEqual(len(packet["snapshot"]["edges"]), 0)
        self.assertEqual(
            packet["review_suppressed_links"][0]["blocking_items"],
            ["claim:azure", "claim:gcp"],
        )

    def test_favorable_unsigned_assertions_do_not_upgrade_edge(self) -> None:
        self.record(disposition="accept_for_review_only", reason_code="declared_match")
        self.record(
            request_id="request.two", reviewer_role="independent_assurance",
            reviewer_subject="person.assurance", disposition="accept_for_review_only",
            reason_code="declared_match", recorded_at="2026-10-02T12:01:00Z",
        )
        packet = self.derive()
        snapshot = world.AttackWorldSnapshot.from_dict(packet["snapshot"])
        self.assertEqual(len(snapshot.edges), 1)
        self.assertEqual(snapshot.edges[0].evidence.confidence, 0.0)
        self.assertIs(
            snapshot.edges[0].evidence.verification_state,
            world.VerificationState.HYPOTHESIS,
        )
        self.assertFalse(packet["independent_review_accepted"])
        self.assertFalse(packet["verified_path_created"])

    def test_local_withdrawal_reopens_only_hypothesis_visibility(self) -> None:
        entry = self.record()
        self.assertEqual(len(self.derive()["snapshot"]["edges"]), 0)
        self.store.revoke_review(
            request_id="request.withdraw", target_entry_sha256=entry["entry_sha256"],
            reviewer_subject="person.control", reason_code="reviewer_correction",
            recorded_at="2026-10-02T12:01:00Z",
        )
        packet = self.derive()
        self.assertEqual(len(packet["snapshot"]["edges"]), 1)
        self.assertFalse(packet["positive_use_approved"])

    def test_source_joins_and_summary_forgery_fail_closed(self) -> None:
        summary = self.summary()
        changed = copy.deepcopy(self.base)
        changed["graph_sha256"] = "sha256:" + "d" * 64
        with self.assertRaises(reviewed.OfflineReviewAwareWorldProjectionError):
            reviewed._derive(
                changed, self.handoff, summary,
                tenant_id="tenant.example", scope_id="declared.scope",
            )
        for field, value in (
            ("handoff_sha256", "sha256:" + "d" * 64),
            ("history_head_sha256", "sha256:" + "d" * 63),
            ("tenant_id", "tenant.other"),
            ("declared_scope_id", "other.scope"),
            ("positive_use_approved", True),
        ):
            forged = copy.deepcopy(summary)
            forged[field] = value
            with self.subTest(field=field), self.assertRaises(
                reviewed.OfflineReviewAwareWorldProjectionError
            ):
                reviewed._derive(
                    self.base, self.handoff, forged,
                    tenant_id="tenant.example", scope_id="declared.scope",
                )
        forged = copy.deepcopy(summary)
        forged["item_review_states"][0]["state"] = "dual_operator_assertions_unverified"
        with self.assertRaises(reviewed.OfflineReviewAwareWorldProjectionError):
            reviewed._derive(
                self.base, self.handoff, forged,
                tenant_id="tenant.example", scope_id="declared.scope",
            )

    def test_changed_current_original_and_tampered_derivative_fail(self) -> None:
        changed_model = copy.deepcopy(self.graph_model)
        changed_model["graph_label"] = "changed"
        with patch.object(
            components, "_catalog_document", return_value=self.catalog.to_dict()
        ), self.assertRaises(reviewed.OfflineReviewAwareWorldProjectionError):
            reviewed.project_review_aware_world(
                self.base, **self.sources(graph_model=changed_model)
            )
        packet = self.derive()
        forged = copy.deepcopy(packet)
        forged["positive_use_approved"] = True
        with patch.object(reviewed, "project_review_aware_world", return_value=packet):
            with self.assertRaises(reviewed.OfflineReviewAwareWorldProjectionError):
                reviewed.verify_review_aware_world(forged, self.base, **self.sources())


if __name__ == "__main__":
    unittest.main()
