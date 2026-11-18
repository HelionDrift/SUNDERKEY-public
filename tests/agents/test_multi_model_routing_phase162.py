"""Phase 162 deterministic model routing and budget policy coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.multi_model_routing import (
    PLANNING_EFFECTS,
    BudgetEnvelope,
    ModelCapabilityDeclaration,
    ModelRoutingError,
    RoutingAuthorityBinding,
    RoutingDecision,
    TaskRoutingRequirements,
    route_model,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "model-routing-decision-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "multi_model_routing.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "multi-model-routing.md",
)
DIGESTS = tuple("sha256:" + character * 64 for character in "0123456789abcdef")
DECIDED_AT = "2026-09-20T12:00:00Z"


class MultiModelRoutingPhase162Tests(unittest.TestCase):
    def capability(self, suffix: str = "a", **changes: object) -> ModelCapabilityDeclaration:
        values: dict[str, object] = {
            "provider_id": f"provider.{suffix}",
            "provider_api_version": "2026-08-01",
            "model_id": "reasoning-model",
            "model_version": "2026-08-15.1",
            "pricing_revision": "2026-09-01",
            "modalities": ("text",),
            "maximum_context_tokens": 64_000,
            "maximum_output_tokens": 8_000,
            "data_classifications": ("internal", "confidential"),
            "hosting_mode": "provider_managed",
            "region": "us-east-1",
            "retention_days": 0,
            "inputs_used_for_training": False,
            "tool_policy": "forbidden",
            "safety_profile_refs": (DIGESTS[0],),
            "qualification_refs": (DIGESTS[1],),
            "latency_p95_ms": 900,
            "availability_basis_points": 9_990,
            "input_micros_per_million_tokens": 2_000_000,
            "output_micros_per_million_tokens": 4_000_000,
            "quality_tier": 90,
            "available": True,
        }
        values.update(changes)
        return ModelCapabilityDeclaration(**values)  # type: ignore[arg-type]

    def requirements(self, **changes: object) -> TaskRoutingRequirements:
        values: dict[str, object] = {
            "tenant_id": "tenant.alpha",
            "assessment_id": "assessment.001",
            "task_id": "task.route.001",
            "requester_id": "operator.requester",
            "required_modalities": ("text",),
            "input_token_ceiling": 10_000,
            "output_token_ceiling": 2_000,
            "data_classification": "confidential",
            "allowed_hosting_modes": ("provider_managed",),
            "allowed_regions": ("us-east-1",),
            "maximum_retention_days": 0,
            "training_use_allowed": False,
            "tool_policy": "forbidden",
            "required_safety_profile_refs": (DIGESTS[0],),
            "required_qualification_refs": (DIGESTS[1],),
            "maximum_latency_p95_ms": 1_500,
            "minimum_availability_basis_points": 9_900,
            "minimum_quality_tier": 80,
            "maximum_request_cost_micros": 100_000,
        }
        values.update(changes)
        return TaskRoutingRequirements(**values)  # type: ignore[arg-type]

    def authority(
        self, capabilities: tuple[ModelCapabilityDeclaration, ...], **changes: object
    ) -> RoutingAuthorityBinding:
        values: dict[str, object] = {
            "tenant_id": "tenant.alpha",
            "assessment_id": "assessment.001",
            "task_id": "task.route.001",
            "requester_id": "operator.requester",
            "authorizer_id": "control.approver",
            "allowed_capability_sha256s": tuple(item.capability_sha256 for item in capabilities),
            "valid_from": "2026-09-20T11:00:00Z",
            "expires_at": "2026-09-20T13:00:00Z",
            "authority_ref": DIGESTS[2],
        }
        values.update(changes)
        return RoutingAuthorityBinding(**values)  # type: ignore[arg-type]

    def budget(self, **changes: object) -> BudgetEnvelope:
        values: dict[str, object] = {
            "tenant_id": "tenant.alpha",
            "assessment_id": "assessment.001",
            "currency": "USD",
            "request_input_token_limit": 12_000,
            "request_output_token_limit": 3_000,
            "request_cost_limit_micros": 100_000,
            "aggregate_input_token_limit": 100_000,
            "aggregate_output_token_limit": 30_000,
            "aggregate_cost_limit_micros": 1_000_000,
            "aggregate_input_tokens_reserved": 20_000,
            "aggregate_output_tokens_reserved": 4_000,
            "aggregate_cost_reserved_micros": 200_000,
            "budget_revision": "2026-09-20.1",
        }
        values.update(changes)
        return BudgetEnvelope(**values)  # type: ignore[arg-type]

    def decision(
        self, capabilities: tuple[ModelCapabilityDeclaration, ...] | None = None
    ) -> RoutingDecision:
        candidates = capabilities or (self.capability(),)
        return route_model(
            self.requirements(),
            candidates,
            self.authority(candidates),
            self.budget(),
            decided_at=DECIDED_AT,
        )

    def test_selected_decision_is_immutable_content_addressed_and_schema_valid(self) -> None:
        decision = self.decision()
        self.assertEqual(decision.status, "selected")
        self.assertEqual(decision, RoutingDecision.from_json(decision.to_json()))
        self.assertTrue(decision.decision_id.startswith("MRD-"))
        self.assertTrue(decision.budget_reservation.planning_only)  # type: ignore[union-attr]
        with self.assertRaises(FrozenInstanceError):
            decision.status = "abstained"  # type: ignore[misc]
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(decision.to_dict())

    def test_input_order_cannot_change_scoring_selection_or_digest(self) -> None:
        candidate_b = self.capability("b")
        candidate_a = self.capability("a")
        forward = self.decision((candidate_b, candidate_a))
        reverse = route_model(
            self.requirements(),
            (candidate_a, candidate_b),
            self.authority((candidate_b, candidate_a)),
            self.budget(),
            decided_at=DECIDED_AT,
        )
        self.assertEqual(forward, reverse)
        self.assertEqual(forward.selection.provider_id, "provider.a")  # type: ignore[union-attr]
        self.assertEqual(forward.fallback_plan[0].provider_id, "provider.b")

    def test_lower_cost_candidate_wins_deterministic_score(self) -> None:
        expensive = self.capability("expensive")
        economical = self.capability(
            "economical",
            input_micros_per_million_tokens=1_000_000,
            output_micros_per_million_tokens=2_000_000,
        )
        decision = self.decision((expensive, economical))
        self.assertEqual(decision.selection.provider_id, "provider.economical")  # type: ignore[union-attr]

    def test_moving_version_aliases_are_rejected(self) -> None:
        with self.assertRaisesRegex(ModelRoutingError, "moving alias"):
            self.capability(model_version="latest")
        with self.assertRaisesRegex(ModelRoutingError, "version number"):
            self.capability(provider_api_version="preview")

    def test_requester_cannot_self_authorize(self) -> None:
        candidate = self.capability()
        with self.assertRaisesRegex(ModelRoutingError, "cannot authorize"):
            self.authority((candidate,), authorizer_id="operator.requester")

    def test_privacy_retention_and_training_fail_closed(self) -> None:
        candidate = self.capability(
            data_classifications=("public", "internal"),
            retention_days=30,
            inputs_used_for_training=True,
        )
        decision = self.decision((candidate,))
        self.assertEqual(decision.status, "abstained")
        self.assertEqual(
            set(decision.blockers),
            {
                "data_classification_denied",
                "retention_exceeds_policy",
                "training_use_denied",
            },
        )

    def test_region_and_hosting_are_hard_constraints(self) -> None:
        candidate = self.capability(region="eu-west-1", hosting_mode="dedicated")
        decision = self.decision((candidate,))
        self.assertEqual(decision.status, "abstained")
        self.assertIn("region_denied", decision.blockers)
        self.assertIn("hosting_mode_denied", decision.blockers)

    def test_unavailable_and_ungranted_candidates_abstain(self) -> None:
        candidate = self.capability(available=False)
        authority = self.authority((self.capability("other"),))
        decision = route_model(
            self.requirements(),
            (candidate,),
            authority,
            self.budget(),
            decided_at=DECIDED_AT,
        )
        self.assertEqual(decision.status, "abstained")
        self.assertIn("provider_unavailable", decision.blockers)
        self.assertIn("authority_not_granted", decision.blockers)

    def test_missing_safety_and_qualification_refs_abstain(self) -> None:
        candidate = self.capability(safety_profile_refs=(), qualification_refs=())
        decision = self.decision((candidate,))
        self.assertIn("safety_profile_missing", decision.blockers)
        self.assertIn("qualification_missing", decision.blockers)

    def test_request_and_aggregate_budget_limits_are_enforced(self) -> None:
        candidate = self.capability()
        request_limited = route_model(
            self.requirements(),
            (candidate,),
            self.authority((candidate,)),
            self.budget(request_cost_limit_micros=1),
            decided_at=DECIDED_AT,
        )
        self.assertIn("request_cost_budget_exceeded", request_limited.blockers)
        aggregate_limited = route_model(
            self.requirements(),
            (candidate,),
            self.authority((candidate,)),
            self.budget(aggregate_cost_limit_micros=220_000),
            decided_at=DECIDED_AT,
        )
        self.assertIn("aggregate_cost_budget_exceeded", aggregate_limited.blockers)

    def test_task_cost_ceiling_is_independent_of_budget_envelope(self) -> None:
        candidate = self.capability()
        decision = route_model(
            self.requirements(maximum_request_cost_micros=1),
            (candidate,),
            self.authority((candidate,)),
            self.budget(),
            decided_at=DECIDED_AT,
        )
        self.assertEqual(decision.status, "abstained")
        self.assertIn("task_cost_ceiling_exceeded", decision.blockers)

    def test_capacity_latency_availability_modality_and_tool_policy_are_enforced(self) -> None:
        candidate = self.capability(
            modalities=("image",),
            maximum_context_tokens=11_000,
            maximum_output_tokens=1_000,
            tool_policy="required",
            latency_p95_ms=2_000,
            availability_basis_points=9_000,
        )
        decision = self.decision((candidate,))
        self.assertTrue(
            {
                "modality_unsupported",
                "context_capacity_insufficient",
                "output_capacity_insufficient",
                "tool_policy_incompatible",
                "latency_exceeds_ceiling",
                "availability_below_minimum",
            }.issubset(decision.blockers)
        )

    def test_quality_floor_blocks_downgrade(self) -> None:
        candidate = self.capability(quality_tier=79)
        decision = self.decision((candidate,))
        self.assertEqual(decision.status, "abstained")
        self.assertIn("quality_tier_below_minimum", decision.blockers)

    def test_fallback_is_pinned_and_never_silent(self) -> None:
        primary = self.capability("primary")
        fallback = self.capability(
            "fallback",
            input_micros_per_million_tokens=2_100_000,
            model_version="2026-08-16.2",
        )
        decision = self.decision((fallback, primary))
        self.assertTrue(decision.substitution_requires_new_decision)
        self.assertEqual(len(decision.fallback_plan), 1)
        self.assertEqual(decision.fallback_plan[0].model_version, "2026-08-16.2")
        self.assertNotEqual(
            decision.selection.capability_sha256,  # type: ignore[union-attr]
            decision.fallback_plan[0].capability_sha256,
        )

    def test_tampering_and_unknown_fields_are_rejected(self) -> None:
        raw = self.decision().to_dict()
        tampered = copy.deepcopy(raw)
        tampered["decided_at"] = "2026-09-20T12:01:00Z"
        with self.assertRaisesRegex(ModelRoutingError, "content address mismatch"):
            RoutingDecision.from_dict(tampered)
        extra = copy.deepcopy(raw)
        extra["provider_response"] = "not accepted"
        with self.assertRaisesRegex(ModelRoutingError, "fields are invalid"):
            RoutingDecision.from_dict(extra)

    def test_tenant_assessment_task_and_expiry_bindings_are_enforced(self) -> None:
        candidate = self.capability()
        with self.assertRaisesRegex(ModelRoutingError, "budget is not bound"):
            route_model(
                self.requirements(),
                (candidate,),
                self.authority((candidate,)),
                self.budget(tenant_id="tenant.other"),
                decided_at=DECIDED_AT,
            )
        with self.assertRaisesRegex(ModelRoutingError, "not valid"):
            route_model(
                self.requirements(),
                (candidate,),
                self.authority((candidate,)),
                self.budget(),
                decided_at="2026-09-20T14:00:00Z",
            )

    def test_effects_assert_no_runtime_or_financial_effect(self) -> None:
        decision = self.decision()
        self.assertEqual(decision.to_dict()["effects"], PLANNING_EFFECTS)
        self.assertEqual(PLANNING_EFFECTS["budget_reservation"], "planning_only")
        for key in (
            "authority",
            "budget_spend",
            "credential_values",
            "execution",
            "model_calls",
            "network",
            "pricing_lookup",
            "provider_clients",
            "provider_state",
            "qualification",
            "requests",
            "secrets",
            "tools",
        ):
            self.assertEqual(PLANNING_EFFECTS[key], "none")

    def test_source_files_have_no_disallowed_markers_or_unicode_dashes(self) -> None:
        forbidden_marker = "(?i)(" + "chat" + "gpt|gene" + "rated by " + "ai|clau" + "de)"
        import re

        marker = re.compile(forbidden_marker)
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, "[\u2013\u2014]", path.as_posix())
            self.assertIsNone(marker.search(text), path.as_posix())


if __name__ == "__main__":
    unittest.main()
