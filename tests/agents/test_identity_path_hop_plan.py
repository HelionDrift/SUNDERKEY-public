"""Inert per-hop identity validation is bound to replayed graph evidence."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

import jsonschema

from sunderkey.identity_cloud_reasoning import (
    IndependentPathReview,
    build_complete_path_validation_plan,
    canonical_sha256,
    search_cross_surface_paths,
)
from sunderkey.identity_path_hop_plan import (
    HopKind,
    IdentityPathHopPlanError,
    IdentityPathHopValidationPlan,
    PathHopValidationStep,
    build_identity_path_hop_plan,
    verify_identity_path_hop_plan,
)
from tests.agents.test_identity_cloud_reasoning_phase166 import (
    NOW,
    Fixture,
    digest,
    review_context_digest,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "identity-path-hop-plan-v1.schema.json"


def reviewed_path(fixture: Fixture):
    result = search_cross_surface_paths(
        fixture.snapshot,
        start_id=fixture.workload.workload_identity_id,
        target_resource_id=fixture.resource.resource_id,
        action="data.read",
        attributes=fixture.attributes(),
        as_of=NOW,
    )
    path_digest = canonical_sha256(sorted(item.path_id for item in result.paths))
    context_digest = review_context_digest(result, fixture.attributes(), NOW)
    reviews = (
        IndependentPathReview(
            "reviewer.identity",
            "independent_identity",
            path_digest,
            digest("hop-identity"),
            NOW,
            context_digest,
        ),
        IndependentPathReview(
            "reviewer.assurance",
            "independent_assurance",
            path_digest,
            digest("hop-assurance"),
            NOW,
            context_digest,
        ),
    )
    plan = build_complete_path_validation_plan(
        fixture.snapshot, result, reviews=reviews, attributes=fixture.attributes(), as_of=NOW
    )
    return result, plan


class IdentityPathHopPlanTests(unittest.TestCase):
    def test_trust_path_lists_exact_binding_relation_and_permission_evidence(self) -> None:
        fixture = Fixture()
        result, review_plan = reviewed_path(fixture)
        plan = build_identity_path_hop_plan(
            fixture.snapshot, result, review_plan, attributes=fixture.attributes(), as_of=NOW
        )
        self.assertEqual(
            tuple(step.kind for step in plan.steps),
            (
                HopKind.WORKLOAD_BINDING,
                HopKind.TRUST_RELATION,
                HopKind.EFFECTIVE_PERMISSION,
            ),
        )
        self.assertEqual(plan.steps[0].relation_id, fixture.workload.workload_identity_id)
        self.assertEqual(plan.steps[1].relation_id, fixture.trust.trust_relation_id)
        self.assertIn(fixture.allow.permission_fact_id, plan.steps[2].record_ids)
        self.assertIn(fixture.policy.policy_id, plan.steps[2].record_ids)
        self.assertIn(fixture.permission_evidence.evidence_id, plan.steps[2].evidence_ids)
        self.assertTrue(all(step.credential_reference_id is None for step in plan.steps))
        self.assertEqual(plan.to_dict()["effects"]["target_action"], "none")
        jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(plan.to_dict())
        self.assertEqual(IdentityPathHopValidationPlan.from_dict(plan.to_dict()), plan)
        self.assertEqual(
            verify_identity_path_hop_plan(
                fixture.snapshot,
                result,
                review_plan,
                plan,
                attributes=fixture.attributes(),
                as_of=NOW,
            ),
            plan,
        )

    def test_session_transition_lists_opaque_credential_reference_only(self) -> None:
        fixture = Fixture(use_trust=False, use_transition=True)
        result, review_plan = reviewed_path(fixture)
        plan = build_identity_path_hop_plan(
            fixture.snapshot, result, review_plan, attributes=fixture.attributes(), as_of=NOW
        )
        self.assertEqual(plan.steps[1].kind, HopKind.SESSION_TRANSITION)
        self.assertEqual(plan.steps[1].credential_reference_id, fixture.credential.credential_id)
        self.assertIn(fixture.credential.evidence_id, plan.steps[1].evidence_ids)
        self.assertNotIn(fixture.credential.credential_key, str(plan.to_dict()))

    def test_rebinding_and_tampering_fail_closed(self) -> None:
        fixture = Fixture()
        result, review_plan = reviewed_path(fixture)
        plan = build_identity_path_hop_plan(
            fixture.snapshot, result, review_plan, attributes=fixture.attributes(), as_of=NOW
        )
        changed = {**fixture.attributes(), "network_zone": "internal"}
        with self.assertRaisesRegex(IdentityPathHopPlanError, "source replay"):
            verify_identity_path_hop_plan(
                fixture.snapshot, result, review_plan, plan, attributes=changed, as_of=NOW
            )
        tampered = copy.deepcopy(plan.to_dict())
        tampered["steps"][1]["evidence_ids"] = ["evidence.not.in.snapshot"]
        with self.assertRaisesRegex(IdentityPathHopPlanError, "content address"):
            IdentityPathHopValidationPlan.from_dict(tampered)
        tampered = copy.deepcopy(plan.to_dict())
        tampered["effects"]["target_action"] = "allowed"
        with self.assertRaisesRegex(IdentityPathHopPlanError, "effects"):
            IdentityPathHopValidationPlan.from_dict(tampered)
        tampered = copy.deepcopy(plan.to_dict())
        tampered["schema_version"] = True
        with self.assertRaisesRegex(IdentityPathHopPlanError, "version"):
            IdentityPathHopValidationPlan.from_dict(tampered)
        with self.assertRaisesRegex(IdentityPathHopPlanError, "credential reference"):
            PathHopValidationStep(
                plan.steps[0].path_id,
                0,
                plan.steps[0].source_id,
                plan.steps[0].target_id,
                plan.steps[0].relation_id,
                HopKind.WORKLOAD_BINDING,
                plan.steps[0].record_ids,
                plan.steps[0].evidence_ids,
                fixture.credential.credential_id,
            )
        with self.assertRaisesRegex(IdentityPathHopPlanError, "ordinal"):
            PathHopValidationStep(
                plan.steps[0].path_id,
                True,
                plan.steps[0].source_id,
                plan.steps[0].target_id,
                plan.steps[0].relation_id,
                HopKind.WORKLOAD_BINDING,
                plan.steps[0].record_ids,
                plan.steps[0].evidence_ids,
            )


if __name__ == "__main__":
    unittest.main()
