"""One synthetic API case traverses Army planning and retest boundaries."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import tests.agents.test_offline_api_planning_bundle as planning_fixture
import tests.agents.test_offline_planning_preview as preview_fixture
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.run_offline_api_assessment import _prepare_case, run_case
from sunderkey.attack_world_model import AttackWorldSnapshot
from sunderkey.coverage_capacity_rehearsal import (
    bind_rehearsal_to_army_registry,
    plan_capacity_rehearsal,
)
from sunderkey.coverage_scheduler import CoverageSchedule, replan_coverage_schedule
from sunderkey.local_api_runtime_adapter import (
    PLANNING_PREVIEW_PATH,
    OfflinePlanningPreviewAsgiApp,
)
from sunderkey.offline_api_assessment import OfflineApiCaseSource, build_offline_api_batch
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from sunderkey.offline_api_retest_lineage import build_initial_offline_api_retest_lineage
from sunderkey.offline_api_retest_transition_bridge import build_offline_api_retest_transition
from sunderkey.offline_api_review_handoff import build_offline_api_review_handoff
from sunderkey.offline_api_review_plan_bridge import build_offline_api_review_plan_bridge
from sunderkey.offline_api_world_projection import build_offline_api_world_projection
from sunderkey.offline_planning_preview import PlanningBundleRecord
from sunderkey.offline_planning_preview_store import SQLitePlanningBundleStore
from sunderkey.offline_reviewed_outcome_rehearsal import build_offline_reviewed_outcome_rehearsal
from sunderkey.offline_task_review_receipts import (
    ReviewerKeyBinding,
    build_offline_task_review_packet,
    build_offline_task_work_product,
    sign_offline_task_review_attestation,
)
from tests.agents.test_local_api_runtime_adapter_phase168 import invoke

ROOT = Path(__file__).resolve().parents[2]
NEGATIVE = ROOT / "examples" / "offline-api-assessment" / "denied-synthetic-retest-case.json"


class OfflineApiIntegratedConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def test_case_to_army_retest_review_and_preview_has_no_target_effect(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        planning_options = fixture.options()
        bundle = build_offline_api_planning_bundle(**planning_options)
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
        bridge = build_offline_api_review_plan_bridge(
            tenant_id=review_options["tenant_id"],
            planning_bundle=bundle,
            review_handoff=handoff,
            planning_options=planning_options,
            review_options=review_options,
        )
        initial = build_initial_offline_api_retest_lineage(
            adapter=fixture.adapter,
            sources=(fixture.source,),
            batch=fixture.batch,
            projection=bundle["projection"],
            observed_at="2026-09-24T12:00:00Z",
            expires_at="2026-09-25T12:00:00Z",
        )
        raw = json.loads(NEGATIVE.read_text(encoding="utf-8"))
        raw["scope_id"] = fixture.scope.scope_id
        case_id, invocation, evidence = _prepare_case(raw, fixture.adapter)
        negative = OfflineApiCaseSource(case_id, invocation, evidence, run_case(raw))
        negative_batch = build_offline_api_batch(
            adapter=fixture.adapter, sources=(negative,)
        ).to_dict()
        negative_projection = build_offline_api_world_projection(
            adapter=fixture.adapter,
            sources=(negative,),
            batch=negative_batch,
            observed_at="2026-09-24T12:02:00Z",
            expires_at="2026-09-25T12:00:00Z",
        )
        transition = build_offline_api_retest_transition(
            prior_lineage=initial,
            prior_source=fixture.source,
            second_source=negative,
            second_batch=negative_batch,
            second_projection=negative_projection,
            adapter=fixture.adapter,
            observed_at="2026-09-24T12:02:00Z",
            expires_at="2026-09-25T12:00:00Z",
        )
        child = AttackWorldSnapshot.from_dict(
            transition["child_lineage"]["world_snapshot"]
        )
        first_schedule = CoverageSchedule.from_dict(bundle["schedule"])
        second_schedule = replan_coverage_schedule(
            first_schedule,
            fixture.scope,
            child,
            fixture.capabilities,
            fixture.validators,
            {},
            replace(fixture.limits, as_of="2026-09-24T12:03:00Z"),
        )
        rehearsal = plan_capacity_rehearsal(
            second_schedule,
            specialist_capacity={fixture.profile_id: 1},
            commander_capacity={fixture.commander_id: 1},
            validator_capacity={
                f"validator.{role}": 1 for role in ("evidence", "control", "assurance")
            },
        )
        roster = bind_rehearsal_to_army_registry(
            second_schedule, rehearsal, fixture.registry
        )
        task = first_schedule.tasks[0]
        candidate = build_offline_task_work_product(
            schedule=first_schedule,
            task_id=task.task_id,
            work_result_sha256="sha256:" + "a" * 64,
            evidence_sha256s=["sha256:" + "b" * 64],
            completed_at="2026-09-24T12:05:00Z",
        )
        keys = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
        roles = ("independent_control", "independent_assurance")
        bindings = {
            f"review.key.{index}": ReviewerKeyBinding(
                f"review.key.{index}",
                f"reviewer.synthetic.{index}",
                role,
                key.public_key(),
            )
            for index, (role, key) in enumerate(zip(roles, keys, strict=True))
        }
        attestations = [
            sign_offline_task_review_attestation(
                schedule=first_schedule,
                candidate=candidate,
                reviewer_id=f"reviewer.synthetic.{index}",
                role=role,
                key_id=f"review.key.{index}",
                reviewed_at="2026-09-24T12:06:00Z",
                decision="accepted",
                private_key=key,
            )
            for index, (role, key) in enumerate(zip(roles, keys, strict=True))
        ]
        packet = build_offline_task_review_packet(
            schedule=first_schedule,
            candidate=candidate,
            attestations=attestations,
        )
        outcome = build_offline_reviewed_outcome_rehearsal(
            schedule=first_schedule,
            observations={
                task.task_id: {
                    "status": "succeeded",
                    "evidence_digests": candidate["evidence_sha256s"],
                }
            },
            review_packets={task.task_id: packet},
            reviewer_keys=bindings,
            rehearsed_at="2026-09-24T12:07:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = SQLitePlanningBundleStore(
                Path(directory) / "preview.sqlite3", fixture.registry
            )
            store.put(
                PlanningBundleRecord(
                    "tenant.synthetic.001",
                    "context.synthetic.001",
                    bundle["bundle_sha256"],
                    bundle,
                )
            )
            app = OfflinePlanningPreviewAsgiApp(
                store,
                preview_fixture.Authorizer(),
                fixture.registry,
                clock=lambda: "2026-09-24T12:08:00Z",
            )
            status, response, _ = asyncio.run(
                invoke(
                    app,
                    {
                        "request_id": "preview.synthetic.integrated.001",
                        "access": {
                            "tenant_id": "tenant.synthetic.001",
                            "context_id": "context.synthetic.001",
                            "principal_id": "principal.operator.001",
                            "session_ref": "session.synthetic.001",
                        },
                        "bundle_sha256": bundle["bundle_sha256"],
                        "expected_scope_sha256": fixture.scope.content_sha256,
                    },
                    path=PLANNING_PREVIEW_PATH,
                )
            )
        self.assertEqual(status, 200)
        self.assertEqual(bridge["review_cases"][0]["review_status"], "pending")
        self.assertEqual(len(child.conflicts), 1)
        self.assertEqual(second_schedule.world_snapshot_sha256, child.snapshot_sha256)
        self.assertEqual(roster.task_count, len(second_schedule.tasks))
        self.assertFalse(outcome["positive_use_approved"])
        self.assertFalse(response["data"]["positive_use_approved"])
        self.assertEqual(transition["effects"]["finding_publication"], "none")


if __name__ == "__main__":
    unittest.main()
