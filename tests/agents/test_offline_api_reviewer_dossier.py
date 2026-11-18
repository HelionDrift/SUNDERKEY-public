"""A synthetic retest can be indexed for review without a finding claim."""

from __future__ import annotations

import copy
import json
import unittest

import tests.agents.test_offline_api_planning_bundle as planning_fixture
from scripts.run_offline_api_assessment import _prepare_case, run_case
from sunderkey.offline_api_assessment import OfflineApiCaseSource, build_offline_api_batch
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from sunderkey.offline_api_retest_lineage import build_initial_offline_api_retest_lineage
from sunderkey.offline_api_retest_transition_bridge import build_offline_api_retest_transition
from sunderkey.offline_api_review_handoff import build_offline_api_review_handoff
from sunderkey.offline_api_review_plan_bridge import build_offline_api_review_plan_bridge
from sunderkey.offline_api_reviewer_dossier import (
    OfflineApiReviewerDossierError,
    build_offline_api_reviewer_dossier,
    verify_offline_api_reviewer_dossier,
)
from sunderkey.offline_api_world_projection import build_offline_api_world_projection


class OfflineApiReviewerDossierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        planning_options = fixture.options()
        planning = build_offline_api_planning_bundle(**planning_options)
        review_options = {
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
        handoff = build_offline_api_review_handoff(**review_options)
        bridge_options = {
            "tenant_id": review_options["tenant_id"],
            "planning_bundle": planning,
            "review_handoff": handoff,
            "planning_options": planning_options,
            "review_options": review_options,
        }
        bridge = build_offline_api_review_plan_bridge(**bridge_options)
        first = build_initial_offline_api_retest_lineage(
            adapter=fixture.adapter,
            sources=(fixture.source,),
            batch=fixture.batch,
            projection=planning["projection"],
            observed_at="2026-09-24T12:00:00Z",
            expires_at="2026-09-25T12:00:00Z",
        )
        raw = json.loads(planning_fixture.NEGATIVE_EXAMPLE.read_text(encoding="utf-8"))
        raw["scope_id"] = fixture.scope.scope_id
        case_id, invocation, evidence = _prepare_case(raw, fixture.adapter)
        second = OfflineApiCaseSource(case_id, invocation, evidence, run_case(raw))
        second_batch = build_offline_api_batch(
            adapter=fixture.adapter, sources=(second,)
        ).to_dict()
        projection = build_offline_api_world_projection(
            adapter=fixture.adapter,
            sources=(second,),
            batch=second_batch,
            observed_at="2026-09-24T12:02:00Z",
            expires_at="2026-09-25T12:00:00Z",
        )
        transition_options = {
            "prior_lineage": first,
            "prior_source": fixture.source,
            "second_source": second,
            "second_batch": second_batch,
            "second_projection": projection,
            "adapter": fixture.adapter,
            "observed_at": "2026-09-24T12:02:00Z",
            "expires_at": "2026-09-25T12:00:00Z",
        }
        transition = build_offline_api_retest_transition(**transition_options)
        self.options = {
            "review_bridge": bridge,
            "transition": transition,
            "review_bridge_options": bridge_options,
            "transition_options": transition_options,
        }

    def test_dossier_binds_review_and_retest_without_finding(self) -> None:
        dossier = build_offline_api_reviewer_dossier(**self.options)
        self.assertEqual(
            verify_offline_api_reviewer_dossier(document=dossier, **self.options),
            dossier,
        )
        self.assertEqual(dossier["finding_count"], 0)
        self.assertEqual(dossier["report_state"], "nonfinding_reviewer_draft")
        self.assertEqual(dossier["review_status"], "awaiting_independent_human_review")
        self.assertEqual(dossier["effects"]["report_publication"], "none")

    def test_tenant_or_dossier_status_rebinding_fails(self) -> None:
        changed_options = {
            **self.options["review_bridge_options"],
            "tenant_id": "tenant.other",
        }
        with self.assertRaises(OfflineApiReviewerDossierError):
            build_offline_api_reviewer_dossier(
                **{**self.options, "review_bridge_options": changed_options}
            )
        dossier = build_offline_api_reviewer_dossier(**self.options)
        changed = copy.deepcopy(dossier)
        changed["finding_count"] = 1
        with self.assertRaisesRegex(OfflineApiReviewerDossierError, "does not match"):
            verify_offline_api_reviewer_dossier(document=changed, **self.options)


if __name__ == "__main__":
    unittest.main()
