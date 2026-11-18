"""Review candidates share the exact reproduced offline API plan."""

from __future__ import annotations

import copy
import unittest

import tests.agents.test_offline_api_planning_bundle as planning_fixture
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from sunderkey.offline_api_review_handoff import build_offline_api_review_handoff
from sunderkey.offline_api_review_plan_bridge import (
    OfflineApiReviewPlanBridgeError,
    build_offline_api_review_plan_bridge,
    verify_offline_api_review_plan_bridge,
)


class OfflineApiReviewPlanBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        self.planning_options = fixture.options()
        self.planning_bundle = build_offline_api_planning_bundle(**self.planning_options)
        self.review_options = {
            "adapter": fixture.adapter,
            "sources": (fixture.source,),
            "batch": fixture.batch,
            "tenant_id": "tenant.synthetic.001",
            "scope_binding_sha256": fixture.scope.content_sha256,
            "originating_principal_id": "principal.synthetic.operator",
            "originating_team_id": "team.synthetic.assessment",
            "opened_at": "2026-09-24T12:00:00Z",
            "response_due_at": "2026-09-25T12:00:00Z",
            "planned_at": "2026-09-24T12:00:01Z",
        }
        self.review_handoff = build_offline_api_review_handoff(**self.review_options)

    def options(self) -> dict:
        return {
            "tenant_id": "tenant.synthetic.001",
            "planning_bundle": self.planning_bundle,
            "review_handoff": self.review_handoff,
            "planning_options": self.planning_options,
            "review_options": self.review_options,
        }

    def test_bridge_binds_review_candidate_to_schedule_without_publishing(self) -> None:
        packet = build_offline_api_review_plan_bridge(**self.options())
        self.assertEqual(
            verify_offline_api_review_plan_bridge(bridge=packet, **self.options()), packet
        )
        self.assertEqual(packet["batch_sha256"], self.planning_bundle["batch_sha256"])
        self.assertEqual(
            packet["schedule_sha256"],
            self.planning_bundle["schedule"]["schedule_sha256"],
        )
        self.assertEqual(packet["review_cases"][0]["review_status"], "pending")
        self.assertEqual(len(packet["plan_tasks"]), 6)
        self.assertEqual(packet["finding_state"], "not_published")
        self.assertEqual(packet["effects"]["review_decision"], "none")

    def test_scope_tenant_and_packet_tamper_fail_closed(self) -> None:
        changed_review = {
            **self.review_options,
            "scope_binding_sha256": "sha256:" + "f" * 64,
        }
        other_handoff = build_offline_api_review_handoff(**changed_review)
        with self.assertRaisesRegex(OfflineApiReviewPlanBridgeError, "context differs"):
            build_offline_api_review_plan_bridge(
                **{
                    **self.options(),
                    "review_options": changed_review,
                    "review_handoff": other_handoff,
                }
            )
        with self.assertRaisesRegex(OfflineApiReviewPlanBridgeError, "tenant"):
            build_offline_api_review_plan_bridge(
                **{**self.options(), "tenant_id": "tenant.other"}
            )
        packet = build_offline_api_review_plan_bridge(**self.options())
        changed = copy.deepcopy(packet)
        changed["review_cases"][0]["review_status"] = "accepted"
        with self.assertRaisesRegex(OfflineApiReviewPlanBridgeError, "does not match"):
            verify_offline_api_review_plan_bridge(bridge=changed, **self.options())


if __name__ == "__main__":
    unittest.main()
