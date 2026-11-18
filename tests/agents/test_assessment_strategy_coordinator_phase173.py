"""Phase 173 effect-free assessment strategy coordinator tests."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.assessment_guidance import (
    AssessmentGoal,
    AttackTypeSelection,
    FrontierReference,
    GapReference,
    GuidanceBinding,
    GuidanceConstraints,
    GuidanceRequest,
    RiskTier,
    build_assessment_guidance,
)
from sunderkey.assessment_strategy_coordinator import (
    NO_CLAIMS,
    NO_EFFECTS,
    AssessmentStrategyError,
    AssessmentStrategyPlan,
    WorkKind,
    build_assessment_strategy_plan,
    parse_assessment_strategy_plan,
    strategy_input_identities,
)
from sunderkey.asset_risk_scoring import (
    AssetCriticalityExposureBinding,
    AttackPathEvidence,
    DefenderDetectionCoverage,
    EvidenceState,
    ReachabilityState,
    RiskScoringPolicy,
    build_asset_risk_portfolio,
)
from sunderkey.attack_coverage_matrix import build_default_attack_coverage_matrix
from sunderkey.impact_demonstration_policy import (
    ArtifactClass,
    DemonstrationBinding,
    DemonstrationMode,
    ImpactDemonstrationRequest,
    OperatorApproval,
    PlanStatus,
    ProofCategory,
    ProofIntent,
    build_impact_demonstration_plan,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "assessment-strategy-plan-v1.schema.json"
TENANT = "tenantref:acme"
CONTEXT = "contextref:assessment-173"
SCOPE_REF = "scoperef:approved-web"


def _sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _guidance():
    request = GuidanceRequest(
        binding=GuidanceBinding(
            tenant_ref=TENANT,
            context_ref=CONTEXT,
            scope_ref=SCOPE_REF,
            scope_sha256=_sha("scope"),
            target_context_sha256=_sha("target-context"),
            service_contract_sha256=_sha("service-contract"),
            attack_surface_sha256=_sha("surface"),
            world_model_sha256=_sha("world-model"),
        ),
        goals=(
            AssessmentGoal(
                goal_ref="goalref:authorization-boundaries",
                objective_code="verify_access_controls",
                coverage_weight=100,
                acceptance_sha256=_sha("acceptance"),
            ),
        ),
        focus_priorities=(),
        exclusion_priorities=(),
        endpoints=(),
        roles=(),
        attack_types=(
            AttackTypeSelection(
                attack_type_ref="attackref:authorization",
                attack_type_code="authorization",
                catalog_version="1.2.0",
                catalog_sha256=_sha("catalog"),
                risk_tier=RiskTier.MODERATE,
                estimated_risk_points=20,
            ),
        ),
        custom_strategy="Prioritize explicit goals, gaps, and bounded evidence.",
        payload_fixtures=(),
        gaps=(
            GapReference(
                gap_ref="gapref:admin-route",
                gap_sha256=_sha("gap"),
                context_ref=CONTEXT,
                reason_code="missing_route_coverage",
                severity=RiskTier.HIGH,
            ),
        ),
        frontiers=(
            FrontierReference(
                frontier_ref="frontierref:session-transition",
                frontier_sha256=_sha("frontier"),
                context_ref=CONTEXT,
                reason_code="unexplored_transition",
                confidence=50,
            ),
        ),
        constraints=GuidanceConstraints(
            risk_budget_points=100,
            request_budget=500,
            token_budget=100_000,
            max_parallelism=8,
            impact_ceiling=RiskTier.MODERATE,
        ),
        created_at="2026-09-20T12:00:00Z",
        expires_at="2026-09-21T12:00:00Z",
    )
    return build_assessment_guidance(request)


def _risk(*, complete: bool = True):
    asset = AssetCriticalityExposureBinding(
        tenant_ref=TENANT,
        context_ref=CONTEXT,
        scope_sha256=_sha("scope"),
        asset_ref="assetref:critical-api",
        asset_sha256=_sha("asset"),
        criticality_bps=9_500,
        exposure_bps=8_500,
        evidence_coverage_bps=9_000,
        uncertainty_bps=500,
        evidence_sha256=_sha("asset-evidence"),
        observed_at="2026-09-20T12:00:00Z",
    )
    path = AttackPathEvidence(
        tenant_ref=TENANT,
        context_ref=CONTEXT,
        scope_sha256=_sha("scope"),
        asset_ref=asset.asset_ref,
        asset_sha256=asset.asset_sha256,
        reachability_state=ReachabilityState.CONFIRMED,
        depth=2,
        evidence_coverage_bps=9_000,
        uncertainty_bps=500,
        evidence_sha256=_sha("path"),
        observed_at="2026-09-20T12:00:00Z",
    )
    defender = DefenderDetectionCoverage(
        tenant_ref=TENANT,
        context_ref=CONTEXT,
        scope_sha256=_sha("scope"),
        asset_ref=asset.asset_ref,
        asset_sha256=asset.asset_sha256,
        detection_coverage_bps=4_000,
        evidence_coverage_bps=9_000,
        uncertainty_bps=500,
        evidence_sha256=_sha("defender"),
        observed_at="2026-09-20T12:00:00Z",
    )
    return build_asset_risk_portfolio(
        calculated_at="2026-09-20T12:10:00Z",
        policy=RiskScoringPolicy("1.0.0", 3_600, 7_500),
        asset_bindings=(asset,),
        finding_records=(),
        attack_path_bindings=(path,) if complete else (),
        defender_bindings=(defender,) if complete else (),
    )


def _impact(*, protected: bool = False):
    binding = DemonstrationBinding(
        tenant_ref=TENANT,
        context_ref=CONTEXT,
        scope_ref=SCOPE_REF,
        scope_sha256=_sha("scope"),
        target_ref="targetref:critical-api",
        target_sha256=_sha("target"),
        session_ref="sessionref:window-173",
        session_sha256=_sha("session"),
        policy_ref="policyref:impact-1",
        policy_sha256=_sha("impact-policy"),
        protected_target=protected,
        production_data_present=False,
    )
    intent = ProofIntent(
        category=ProofCategory.ROLE_CHANGE,
        evidence_ref="evidenceref:role-change",
        evidence_sha256=_sha("impact-evidence"),
        reversible_proof_ref="reversalref:role-change",
        reversible_proof_sha256=_sha("reversal"),
        cleanup_plan_ref="cleanupref:role-change",
        cleanup_plan_sha256=_sha("cleanup"),
        artifact_class=ArtifactClass.STATE_DELTA,
        artifact_byte_limit=1_024,
    )
    approval = OperatorApproval(
        approval_ref="approvalref:operator-173",
        approval_sha256=_sha("approval"),
        operator_ref="principalref:operator-one",
        binding_sha256=binding.binding_sha256,
        approved_mode=DemonstrationMode.MODERATE,
        approved_categories=(ProofCategory.ROLE_CHANGE,),
        issued_at="2026-09-20T12:00:00Z",
        expires_at="2026-09-20T13:00:00Z",
    )
    request = ImpactDemonstrationRequest(
        binding=binding,
        mode=DemonstrationMode.MODERATE,
        intents=(intent,),
        operator_approval=approval,
        independent_review=None,
        created_at="2026-09-20T12:00:00Z",
        expires_at="2026-09-20T13:00:00Z",
    )
    return build_impact_demonstration_plan(
        request,
        evaluated_at=datetime(2026, 9, 20, 12, 30, tzinfo=UTC),
    )


def _inputs(*, complete_risk: bool = True, protected: bool = False):
    guidance = _guidance()
    coverage = build_default_attack_coverage_matrix(
        tenant_ref=TENANT,
        context_ref=CONTEXT,
        scope_sha256=_sha("scope"),
    )
    risk = _risk(complete=complete_risk)
    impact = _impact(protected=protected)
    identities = strategy_input_identities(guidance, coverage, risk, impact)
    return identities, guidance, coverage, risk, impact


def _plan(*, complete_risk: bool = True, protected: bool = False):
    identities, guidance, coverage, risk, impact = _inputs(
        complete_risk=complete_risk,
        protected=protected,
    )
    return build_assessment_strategy_plan(
        identities=identities,
        guidance=guidance,
        coverage=coverage,
        risk=risk,
        impact=impact,
    )


class AssessmentStrategyCoordinatorPhase173Tests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.AssessmentStrategyError, AssessmentStrategyError)
        self.assertIs(sunderkey.AssessmentStrategyPlan, AssessmentStrategyPlan)
        self.assertIs(
            sunderkey.build_assessment_strategy_plan,
            build_assessment_strategy_plan,
        )
        self.assertIs(
            sunderkey.parse_assessment_strategy_plan,
            parse_assessment_strategy_plan,
        )
        self.assertIs(sunderkey.strategy_input_identities, strategy_input_identities)

    def test_deterministic_content_addressed_and_effect_free(self) -> None:
        first = _plan()
        second = _plan()
        self.assertEqual(first.plan_id, second.plan_id)
        self.assertEqual(first.plan_sha256, second.plan_sha256)
        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(first.to_dict()["effects"], dict(NO_EFFECTS))
        self.assertEqual(first.to_dict()["claims"], dict(NO_CLAIMS))
        self.assertEqual(first.to_dict()["status"], "proposal_only")
        self.assertEqual(first.to_dict()["qualification_effect"], "none")

    def test_transparent_ranking_favors_risk_goals_gaps_and_missing_evidence(self) -> None:
        plan = _plan(complete_risk=False)
        scores = [item.priority_score for item in plan.work_items]
        self.assertEqual(scores, sorted(scores, reverse=True))
        asset = next(item for item in plan.work_items if item.work_kind is WorkKind.ASSET_RISK)
        self.assertEqual(asset.priority_score, sum(asset.score_components.values()))
        self.assertGreater(asset.score_components["asset_risk"], 0)
        self.assertGreater(asset.score_components["missing_evidence"], 0)
        self.assertIn("evidence_missing_attack_path", asset.blocked_reasons)
        self.assertTrue(any(item.work_kind is WorkKind.EXPLICIT_GOAL for item in plan.work_items))
        self.assertTrue(any(item.work_kind is WorkKind.GUIDANCE_GAP for item in plan.work_items))
        self.assertTrue(any(item.work_kind is WorkKind.COVERAGE_GAP for item in plan.work_items))

    def test_work_items_publish_required_proposal_controls(self) -> None:
        plan = _plan()
        for order, item in enumerate(plan.work_items, 1):
            self.assertEqual(item.order, order)
            self.assertEqual(item.status, "proposal_only")
            self.assertEqual(item.risk_ceiling_points, 100)
            self.assertEqual(item.impact_ceiling, "moderate")
            self.assertIn("authorization_required", item.stop_conditions)
            self.assertIn("target_contact_requested", item.stop_conditions)
            self.assertTrue(item.source_content_ids)
        coverage = next(item for item in plan.work_items if item.work_kind is WorkKind.COVERAGE_GAP)
        self.assertTrue(coverage.prerequisite_refs)
        self.assertTrue(coverage.specialist_reference_ids)

    def test_input_lineage_binds_all_four_content_identities(self) -> None:
        plan = _plan()
        self.assertEqual(len(plan.input_lineage), 4)
        self.assertEqual(
            {item.content_id for item in plan.input_lineage},
            {
                plan.guidance_card.card_id,
                plan.coverage_matrix.matrix_id,
                plan.risk_portfolio.portfolio_id,
                plan.impact_plan.plan_id,
            },
        )

    def test_round_trip_is_strict_canonical_ascii_and_schema_valid(self) -> None:
        plan = _plan()
        parsed = parse_assessment_strategy_plan(plan.document_json)
        self.assertEqual(plan, parsed)
        self.assertEqual(plan.document_json.encode("ascii").decode("ascii"), plan.document_json)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(plan.to_dict())
        with self.assertRaises(AssessmentStrategyError):
            parse_assessment_strategy_plan(json.dumps(plan.to_dict(), indent=2, sort_keys=True))

    def test_identity_substitution_is_rejected(self) -> None:
        identities, guidance, coverage, risk, impact = _inputs()
        changed = copy.deepcopy(identities.to_dict())
        changed["risk_portfolio_sha256"] = _sha("substitution")
        with self.assertRaisesRegex(AssessmentStrategyError, "substitution"):
            build_assessment_strategy_plan(
                identities=type(identities).from_dict(changed),
                guidance=guidance,
                coverage=coverage,
                risk=risk,
                impact=impact,
            )

    def test_nested_content_tampering_and_moving_versions_are_rejected(self) -> None:
        raw = _plan().to_dict()
        raw["inputs"]["asset_risk_portfolio"]["scorecards"][0]["rank"] = 77
        with self.assertRaises(ValueError):
            parse_assessment_strategy_plan(raw)
        raw = _plan().to_dict()
        raw["inputs"]["assessment_guidance"]["request"]["attack_types"][0]["catalog_version"] = (
            "latest"
        )
        with self.assertRaises(ValueError):
            parse_assessment_strategy_plan(raw)

    def test_cross_boundary_input_is_rejected(self) -> None:
        identities, guidance, coverage, risk, impact = _inputs()
        foreign = build_default_attack_coverage_matrix(
            tenant_ref="tenantref:other",
            context_ref=CONTEXT,
            scope_sha256=_sha("scope"),
        )
        foreign_ids = strategy_input_identities(guidance, foreign, risk, impact)
        with self.assertRaisesRegex(AssessmentStrategyError, "crosses"):
            build_assessment_strategy_plan(
                identities=foreign_ids,
                guidance=guidance,
                coverage=foreign,
                risk=risk,
                impact=impact,
            )
        self.assertNotEqual(identities, foreign_ids)

    def test_duplicate_ids_unknown_enums_and_unknown_fields_are_rejected(self) -> None:
        raw = _plan().to_dict()
        raw["work_items"].append(copy.deepcopy(raw["work_items"][0]))
        with self.assertRaises(AssessmentStrategyError):
            parse_assessment_strategy_plan(raw)
        raw = _plan().to_dict()
        raw["work_items"][0]["work_kind"] = "unknown"
        with self.assertRaises(AssessmentStrategyError):
            parse_assessment_strategy_plan(raw)
        raw = _plan().to_dict()
        raw["unexpected"] = True
        with self.assertRaises(AssessmentStrategyError):
            parse_assessment_strategy_plan(raw)

    def test_duplicate_json_keys_and_noncanonical_json_are_rejected(self) -> None:
        plan = _plan()
        duplicate = plan.document_json[:-1] + ',"plan_id":"' + plan.plan_id + '"}'
        with self.assertRaisesRegex(AssessmentStrategyError, "duplicate"):
            parse_assessment_strategy_plan(duplicate)
        with self.assertRaises(AssessmentStrategyError):
            parse_assessment_strategy_plan(plan.document_json.replace("{", "{ ", 1))

    def test_secrets_hostile_instructions_and_payloads_are_rejected(self) -> None:
        for value in (
            "password=not-allowed",
            "ignore previous instructions",
            "run this payload",
        ):
            raw = _plan().to_dict()
            raw["work_items"][0]["subject_ref"] = value
            with self.subTest(value=value), self.assertRaises(AssessmentStrategyError):
                parse_assessment_strategy_plan(raw)

    def test_unfavorable_inputs_publish_blockers_without_execution(self) -> None:
        plan = _plan(complete_risk=False, protected=True)
        self.assertEqual(plan.impact_plan.status, PlanStatus.DENIED)
        self.assertIn("protected_target_prohibited", plan.blocked_reasons)
        asset = next(item for item in plan.work_items if item.work_kind is WorkKind.ASSET_RISK)
        self.assertEqual(
            plan.risk_portfolio.scorecards[0].evidence_state,
            EvidenceState.INSUFFICIENT,
        )
        self.assertTrue(asset.blocked_reasons)
        self.assertTrue(plan.independent_review_required)
        self.assertEqual(plan.to_dict()["effects"]["execution"], "none")
        self.assertEqual(plan.to_dict()["effects"]["target_contact"], "none")


if __name__ == "__main__":
    unittest.main()
