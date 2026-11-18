from __future__ import annotations

import copy
import json
import re
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.army_activation_contracts import (
    NO_EFFECTS,
    ActivationContext,
    ArmyActivationContractError,
    ArtifactBinding,
    BudgetLimits,
    CanaryActivationPacket,
    CanaryDisposition,
    CanaryStatus,
    CollaborationScorecard,
    EquivalenceStatus,
    EvidenceReference,
    EvidenceSafety,
    ExactSystemBinding,
    IndependentReview,
    ReadinessStatus,
    RetirementDisposition,
    ReviewDecision,
    ReviewerRole,
    RollbackWindow,
    ShadowRoutingObservation,
    StageStatus,
    StopCriterion,
    assess_activation_readiness,
    assess_route_equivalence,
    authorize_bounded_canary,
    build_rollback_contract,
    build_shadow_routing_report,
    canonical_json,
    decide_route_retirement,
    observe_bounded_canary,
    observe_route_restoration,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "army-activation-contract-v1.schema.json"
MODULE = ROOT / "src" / "sunderkey" / "army_activation_contracts.py"
DOC = ROOT / "docs" / "army-activation-contracts.md"
THIS_FILE = Path(__file__).resolve()


def _sha(seed: str) -> str:
    return "sha256:" + seed * 64


def _artifact(name: str, seed: str, version: str = "1.0.0") -> ArtifactBinding:
    return ArtifactBinding(name, version, _sha(seed))


def _binding() -> ExactSystemBinding:
    return ExactSystemBinding(
        candidate=_artifact("candidate.alpha", "1"),
        profile=_artifact("profile.api", "2"),
        model=_artifact("model.reasoning", "3"),
        provider=_artifact("provider.openai", "4"),
        tool=_artifact("tool.http", "5"),
        prompt=_artifact("prompt.attack", "6"),
        policy=_artifact("policy.activation", "7"),
        roadmap=_artifact("roadmap.a7.5", "8"),
        qualification=_artifact("qualification.pack", "9"),
    )


def _context(*, mission_seed: str = "b") -> ActivationContext:
    return ActivationContext(
        tenant=_artifact("tenant.one", "a"),
        mission=_artifact("mission.one", mission_seed),
        route=_artifact("route.candidate", "c"),
        cohort=_artifact("cohort.api", "d"),
    )


def _evidence(
    binding: ExactSystemBinding,
    context: ActivationContext,
    *,
    evidence_type: str = "shadow_comparison",
    seed: str = "e",
    contaminated: bool = False,
    safety: EvidenceSafety = EvidenceSafety.SAFE,
    observed_at: str = "2026-09-20T10:00:00Z",
    expires_at: str = "2026-09-21T10:00:00Z",
) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=f"evidence.{seed}",
        evidence_type=evidence_type,
        evidence_sha256=_sha(seed),
        binding_sha256=binding.binding_sha256,
        context_sha256=context.context_sha256,
        observed_at=observed_at,
        expires_at=expires_at,
        contaminated=contaminated,
        safety=safety,
    )


def _reviews(
    binding: ExactSystemBinding,
    context: ActivationContext,
    *,
    same_reviewer: bool = False,
    expires_at: str = "2026-09-21T10:00:00Z",
) -> tuple[IndependentReview, ...]:
    return (
        IndependentReview(
            ReviewerRole.INDEPENDENT_ASSURANCE,
            "reviewer.control" if same_reviewer else "reviewer.assurance",
            "1.0.0",
            ReviewDecision.APPROVED,
            "2026-09-20T10:10:00Z",
            expires_at,
            _sha("f"),
            binding.binding_sha256,
            context.context_sha256,
        ),
        IndependentReview(
            ReviewerRole.INDEPENDENT_CONTROL,
            "reviewer.control",
            "1.0.0",
            ReviewDecision.APPROVED,
            "2026-09-20T10:10:00Z",
            expires_at,
            _sha("0"),
            binding.binding_sha256,
            context.context_sha256,
        ),
    )


def _criteria() -> tuple[StopCriterion, ...]:
    return (
        StopCriterion("error-rate", "error_rate", "greater_than", 10_000, True),
        StopCriterion("latency", "latency_regression", "greater_than", 50_000, False),
    )


class Fixture:
    def __init__(self) -> None:
        self.binding = _binding()
        self.context = _context()
        self.failure = _evidence(
            self.binding,
            self.context,
            evidence_type="failure_evidence",
            seed="a",
        )
        self.reviews = _reviews(self.binding, self.context)
        observation = ShadowRoutingObservation.create(
            binding=self.binding,
            context=self.context,
            created_at="2026-09-20T10:05:00Z",
            request_fingerprint_sha256=_sha("1"),
            control_result_sha256=_sha("2"),
            candidate_result_sha256=_sha("3"),
            collaboration_trace_sha256=_sha("4"),
            matched=True,
            safe=True,
            evidence=_evidence(self.binding, self.context),
        )
        self.observation = observation
        self.report = build_shadow_routing_report(
            observations=(observation,),
            created_at="2026-09-20T10:15:00Z",
        )
        self.scorecard = CollaborationScorecard.create(
            report=self.report,
            created_at="2026-09-20T10:20:00Z",
            evaluated_handoffs=10,
            successful_handoffs=10,
            ownership_conflicts=0,
            evidence_losses=0,
            minimum_score_microunits=950_000,
        )
        self.assessment = assess_route_equivalence(
            report=self.report,
            scorecard=self.scorecard,
            reviews=self.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T10:25:00Z",
        )
        authorization = _evidence(
            self.binding,
            self.context,
            evidence_type="bounded_canary_activation_authorization",
            seed="b",
        )
        self.budgets = BudgetLimits(100, 100_000, 1_000_000, 3_600, 2)
        self.window = RollbackWindow("2026-09-20T11:00:00Z", "2026-09-20T15:00:00Z", 3_600)
        self.packet = authorize_bounded_canary(
            assessment=self.assessment,
            activation_authorization=authorization,
            traffic_basis_points=500,
            budgets=self.budgets,
            stop_criteria=_criteria(),
            rollback_window=self.window,
            reviews=self.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T10:30:00Z",
        )
        self.canary = observe_bounded_canary(
            packet=self.packet,
            created_at="2026-09-20T12:00:00Z",
            requests_used=100,
            tokens_used=100_000,
            cost_microunits_used=1_000_000,
            duration_seconds=3_600,
            errors=2,
            triggered_criteria=(),
            evidence=(
                _evidence(
                    self.binding,
                    self.context,
                    evidence_type="canary_observation",
                    seed="c",
                ),
            ),
        )
        self.decision = decide_route_retirement(
            observations=(self.canary,),
            reviews=self.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T12:10:00Z",
        )
        self.prior_route = _artifact("route.control", "f")
        rollback_authorization = _evidence(
            self.binding,
            self.context,
            evidence_type="route_rollback_authorization",
            seed="d",
        )
        self.rollback = build_rollback_contract(
            decision=self.decision,
            prior_route=self.prior_route,
            rollback_authorization=rollback_authorization,
            rollback_window=self.window,
            budgets=self.budgets,
            stop_criteria=_criteria(),
            reviews=self.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T12:20:00Z",
        )
        self.restoration = observe_route_restoration(
            contract=self.rollback,
            restored_route=self.prior_route,
            restored_at="2026-09-20T13:00:00Z",
            created_at="2026-09-20T13:05:00Z",
            evidence=_evidence(
                self.binding,
                self.context,
                evidence_type="route_restoration",
                seed="e",
            ),
        )
        self.readiness = assess_activation_readiness(
            assessment=self.assessment,
            packet=self.packet,
            decision=self.decision,
            rollback=self.rollback,
            restoration=None,
            reviews=self.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T13:10:00Z",
        )

    @property
    def records(self) -> tuple[object, ...]:
        return (
            self.observation,
            self.report,
            self.scorecard,
            self.assessment,
            self.packet,
            self.canary,
            self.decision,
            self.rollback,
            self.restoration,
            self.readiness,
        )


class ArmyActivationContractsPhase166Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.assess_army_activation_readiness,
            assess_activation_readiness,
        )
        self.assertIs(
            sunderkey.build_army_shadow_routing_report,
            build_shadow_routing_report,
        )
        self.assertIs(
            sunderkey.parse_army_activation_contract,
            parse_contract,
        )

    def setUp(self) -> None:
        self.fixture = Fixture()

    def test_complete_chain_is_content_addressed_and_has_no_effects(self) -> None:
        self.assertEqual(self.fixture.report.status, StageStatus.PASS)
        self.assertEqual(self.fixture.assessment.status, EquivalenceStatus.EQUIVALENT)
        self.assertEqual(self.fixture.packet.status, CanaryStatus.READY_FOR_SEPARATE_EXECUTION)
        self.assertEqual(self.fixture.canary.disposition, CanaryDisposition.PASS)
        self.assertEqual(self.fixture.decision.disposition, RetirementDisposition.RETIRE)
        self.assertEqual(
            self.fixture.readiness.status,
            ReadinessStatus.READY_FOR_SEPARATE_ACTIVATION,
        )
        for record in self.fixture.records:
            document = record.to_dict()
            self.assertEqual(document["effects"], dict(NO_EFFECTS))
            self.assertEqual(parse_contract(document), record)
            self.assertEqual(canonical_json(document), canonical_json(record.to_dict()))

    def test_all_record_types_round_trip_and_validate_against_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for record in self.fixture.records:
            document = record.to_dict()
            validator.validate(document)
            self.assertEqual(parse_contract(json.loads(json.dumps(document))), record)

    def test_tamper_and_unknown_fields_fail_closed_for_every_record(self) -> None:
        for record in self.fixture.records:
            raw = copy.deepcopy(record.to_dict())
            raw["created_at"] = "2026-09-20T13:11:00Z"
            with self.assertRaisesRegex(ArmyActivationContractError, "identity"):
                parse_contract(raw)
            raw = copy.deepcopy(record.to_dict())
            raw["unexpected"] = True
            with self.assertRaisesRegex(ArmyActivationContractError, "fields"):
                parse_contract(raw)

    def test_exact_candidate_through_qualification_bindings_are_required(self) -> None:
        raw = self.fixture.observation.to_dict()
        self.assertEqual(
            set(raw["binding"]),
            {
                "candidate",
                "model",
                "policy",
                "profile",
                "prompt",
                "provider",
                "qualification",
                "roadmap",
                "tool",
            },
        )
        tampered = copy.deepcopy(raw)
        del tampered["binding"]["qualification"]
        with self.assertRaisesRegex(ArmyActivationContractError, "fields"):
            ShadowRoutingObservation.from_dict(tampered)

    def test_cross_tenant_mission_route_or_cohort_context_fails_closed(self) -> None:
        other_context = _context(mission_seed="0")
        other = ShadowRoutingObservation.create(
            binding=self.fixture.binding,
            context=other_context,
            created_at="2026-09-20T10:05:00Z",
            request_fingerprint_sha256=_sha("1"),
            control_result_sha256=_sha("2"),
            candidate_result_sha256=_sha("3"),
            collaboration_trace_sha256=_sha("4"),
            matched=True,
            safe=True,
            evidence=_evidence(self.fixture.binding, other_context),
        )
        with self.assertRaisesRegex(ArmyActivationContractError, "context boundary"):
            build_shadow_routing_report(
                observations=(self.fixture.observation, other),
                created_at="2026-09-20T10:15:00Z",
            )

    def test_stale_contaminated_unsafe_and_mismatched_evidence_fail_closed(self) -> None:
        cases = (
            _evidence(
                self.fixture.binding,
                self.fixture.context,
                expires_at="2026-09-20T10:04:59Z",
            ),
            _evidence(
                self.fixture.binding,
                self.fixture.context,
                contaminated=True,
            ),
            _evidence(
                self.fixture.binding,
                self.fixture.context,
                safety=EvidenceSafety.UNSAFE,
            ),
            replace(
                _evidence(self.fixture.binding, self.fixture.context),
                context_sha256=_sha("0"),
            ),
        )
        for evidence in cases:
            with self.assertRaises(ArmyActivationContractError):
                ShadowRoutingObservation.create(
                    binding=self.fixture.binding,
                    context=self.fixture.context,
                    created_at="2026-09-20T10:05:00Z",
                    request_fingerprint_sha256=_sha("1"),
                    control_result_sha256=_sha("2"),
                    candidate_result_sha256=_sha("3"),
                    collaboration_trace_sha256=_sha("4"),
                    matched=True,
                    safe=True,
                    evidence=evidence,
                )

    def test_reviews_must_be_fresh_approved_and_independent(self) -> None:
        with self.assertRaisesRegex(ArmyActivationContractError, "must be independent"):
            assess_route_equivalence(
                report=self.fixture.report,
                scorecard=self.fixture.scorecard,
                reviews=_reviews(self.fixture.binding, self.fixture.context, same_reviewer=True),
                excluded_principals=("candidate.operator",),
                created_at="2026-09-20T10:25:00Z",
            )
        with self.assertRaisesRegex(ArmyActivationContractError, "not independent"):
            assess_route_equivalence(
                report=self.fixture.report,
                scorecard=self.fixture.scorecard,
                reviews=self.fixture.reviews,
                excluded_principals=("reviewer.control",),
                created_at="2026-09-20T10:25:00Z",
            )
        stale = _reviews(
            self.fixture.binding,
            self.fixture.context,
            expires_at="2026-09-20T10:24:59Z",
        )
        with self.assertRaisesRegex(ArmyActivationContractError, "stale"):
            assess_route_equivalence(
                report=self.fixture.report,
                scorecard=self.fixture.scorecard,
                reviews=stale,
                excluded_principals=("candidate.operator",),
                created_at="2026-09-20T10:25:00Z",
            )

    def test_collaboration_boundary_and_failure_evidence(self) -> None:
        edge = CollaborationScorecard.create(
            report=self.fixture.report,
            created_at="2026-09-20T10:20:00Z",
            evaluated_handoffs=20,
            successful_handoffs=19,
            ownership_conflicts=0,
            evidence_losses=0,
            minimum_score_microunits=950_000,
        )
        self.assertEqual(edge.status, StageStatus.PASS)
        with self.assertRaisesRegex(ArmyActivationContractError, "failure evidence"):
            CollaborationScorecard.create(
                report=self.fixture.report,
                created_at="2026-09-20T10:20:00Z",
                evaluated_handoffs=20,
                successful_handoffs=18,
                ownership_conflicts=0,
                evidence_losses=0,
                minimum_score_microunits=950_000,
            )

    def test_nonmatching_shadow_requires_failure_evidence(self) -> None:
        failed = ShadowRoutingObservation.create(
            binding=self.fixture.binding,
            context=self.fixture.context,
            created_at="2026-09-20T10:05:00Z",
            request_fingerprint_sha256=_sha("1"),
            control_result_sha256=_sha("2"),
            candidate_result_sha256=_sha("3"),
            collaboration_trace_sha256=_sha("4"),
            matched=False,
            safe=True,
            evidence=_evidence(self.fixture.binding, self.fixture.context),
        )
        with self.assertRaisesRegex(ArmyActivationContractError, "failure evidence"):
            build_shadow_routing_report(
                observations=(failed,),
                created_at="2026-09-20T10:15:00Z",
            )

    def test_canary_requires_separate_bounded_authorization(self) -> None:
        wrong = _evidence(
            self.fixture.binding,
            self.fixture.context,
            evidence_type="general_approval",
            seed="b",
        )
        with self.assertRaisesRegex(ArmyActivationContractError, "separate bounded"):
            authorize_bounded_canary(
                assessment=self.fixture.assessment,
                activation_authorization=wrong,
                traffic_basis_points=500,
                budgets=self.fixture.budgets,
                stop_criteria=_criteria(),
                rollback_window=self.fixture.window,
                reviews=self.fixture.reviews,
                excluded_principals=("candidate.operator",),
                created_at="2026-09-20T10:30:00Z",
            )

    def test_canary_traffic_boundary_is_enforced(self) -> None:
        raw = self.fixture.packet.to_dict()
        raw["traffic_basis_points"] = 1_001
        raw["record_id"] = "ACP-" + "0" * 32
        raw["record_sha256"] = _sha("0")
        with self.assertRaisesRegex(ArmyActivationContractError, "traffic_basis_points"):
            CanaryActivationPacket.from_dict(raw)

    def test_budget_edge_passes_and_one_over_stops(self) -> None:
        self.assertEqual(self.fixture.canary.disposition, CanaryDisposition.PASS)
        over = observe_bounded_canary(
            packet=self.fixture.packet,
            created_at="2026-09-20T12:00:00Z",
            requests_used=101,
            tokens_used=100_000,
            cost_microunits_used=1_000_000,
            duration_seconds=3_600,
            errors=2,
            triggered_criteria=(),
            evidence=(
                _evidence(
                    self.fixture.binding,
                    self.fixture.context,
                    evidence_type="canary_observation",
                    seed="c",
                ),
            ),
            failure_evidence=(self.fixture.failure,),
        )
        self.assertEqual(over.disposition, CanaryDisposition.STOPPED)

    def test_triggered_canary_requires_known_criterion_and_failure_evidence(self) -> None:
        with self.assertRaisesRegex(ArmyActivationContractError, "unknown stop"):
            observe_bounded_canary(
                packet=self.fixture.packet,
                created_at="2026-09-20T12:00:00Z",
                requests_used=1,
                tokens_used=1,
                cost_microunits_used=1,
                duration_seconds=1,
                errors=0,
                triggered_criteria=("unknown",),
                evidence=(self.fixture.failure,),
            )
        with self.assertRaisesRegex(ArmyActivationContractError, "failure evidence"):
            observe_bounded_canary(
                packet=self.fixture.packet,
                created_at="2026-09-20T12:00:00Z",
                requests_used=1,
                tokens_used=1,
                cost_microunits_used=1,
                duration_seconds=1,
                errors=0,
                triggered_criteria=("error-rate",),
                evidence=(self.fixture.failure,),
            )

    def test_retirement_rejects_cross_context_canary_observations(self) -> None:
        other_context = _context(mission_seed="0")
        other = copy.copy(self.fixture.canary)
        object.__setattr__(other, "context", other_context)
        with self.assertRaisesRegex(ArmyActivationContractError, "context boundary"):
            decide_route_retirement(
                observations=(self.fixture.canary, other),
                reviews=self.fixture.reviews,
                excluded_principals=("candidate.operator",),
                created_at="2026-09-20T12:10:00Z",
            )

    def test_rollback_requires_retirement_and_distinct_prior_route(self) -> None:
        stopped = observe_bounded_canary(
            packet=self.fixture.packet,
            created_at="2026-09-20T12:00:00Z",
            requests_used=101,
            tokens_used=1,
            cost_microunits_used=1,
            duration_seconds=1,
            errors=0,
            triggered_criteria=(),
            evidence=(self.fixture.failure,),
            failure_evidence=(self.fixture.failure,),
        )
        retained = decide_route_retirement(
            observations=(stopped,),
            reviews=self.fixture.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T12:10:00Z",
            failure_evidence=(self.fixture.failure,),
        )
        with self.assertRaisesRegex(ArmyActivationContractError, "retirement decision"):
            build_rollback_contract(
                decision=retained,
                prior_route=self.fixture.prior_route,
                rollback_authorization=_evidence(
                    self.fixture.binding,
                    self.fixture.context,
                    evidence_type="route_rollback_authorization",
                    seed="d",
                ),
                rollback_window=self.fixture.window,
                budgets=self.fixture.budgets,
                stop_criteria=_criteria(),
                reviews=self.fixture.reviews,
                excluded_principals=("candidate.operator",),
                created_at="2026-09-20T12:20:00Z",
            )
        with self.assertRaisesRegex(ArmyActivationContractError, "distinct"):
            build_rollback_contract(
                decision=self.fixture.decision,
                prior_route=self.fixture.context.route,
                rollback_authorization=_evidence(
                    self.fixture.binding,
                    self.fixture.context,
                    evidence_type="route_rollback_authorization",
                    seed="d",
                ),
                rollback_window=self.fixture.window,
                budgets=self.fixture.budgets,
                stop_criteria=_criteria(),
                reviews=self.fixture.reviews,
                excluded_principals=("candidate.operator",),
                created_at="2026-09-20T12:20:00Z",
            )

    def test_rollback_window_boundaries_and_restoration_failure_evidence(self) -> None:
        at_open = observe_route_restoration(
            contract=self.fixture.rollback,
            restored_route=self.fixture.prior_route,
            restored_at=self.fixture.window.opens_at,
            created_at="2026-09-20T11:00:01Z",
            evidence=_evidence(
                self.fixture.binding,
                self.fixture.context,
                evidence_type="route_restoration",
                seed="e",
            ),
        )
        self.assertTrue(at_open.verified)
        with self.assertRaisesRegex(ArmyActivationContractError, "failure evidence"):
            observe_route_restoration(
                contract=self.fixture.rollback,
                restored_route=self.fixture.prior_route,
                restored_at=self.fixture.window.closes_at,
                created_at="2026-09-20T15:00:01Z",
                evidence=_evidence(
                    self.fixture.binding,
                    self.fixture.context,
                    evidence_type="route_restoration",
                    seed="e",
                ),
            )

    def test_verified_restoration_produces_rollback_readiness(self) -> None:
        readiness = assess_activation_readiness(
            assessment=self.fixture.assessment,
            packet=self.fixture.packet,
            decision=self.fixture.decision,
            rollback=self.fixture.rollback,
            restoration=self.fixture.restoration,
            reviews=self.fixture.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T13:10:00Z",
        )
        self.assertEqual(readiness.status, ReadinessStatus.ROLLBACK_VERIFIED)

    def test_activation_readiness_rejects_broken_or_cross_context_chain(self) -> None:
        alternate_canary = observe_bounded_canary(
            packet=self.fixture.packet,
            created_at="2026-09-20T12:01:00Z",
            requests_used=99,
            tokens_used=99_999,
            cost_microunits_used=999_999,
            duration_seconds=3_599,
            errors=1,
            triggered_criteria=(),
            evidence=(self.fixture.failure,),
        )
        alternate_decision = decide_route_retirement(
            observations=(alternate_canary,),
            reviews=self.fixture.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T12:11:00Z",
        )
        alternate_rollback = build_rollback_contract(
            decision=alternate_decision,
            prior_route=self.fixture.prior_route,
            rollback_authorization=_evidence(
                self.fixture.binding,
                self.fixture.context,
                evidence_type="route_rollback_authorization",
                seed="d",
            ),
            rollback_window=self.fixture.window,
            budgets=self.fixture.budgets,
            stop_criteria=_criteria(),
            reviews=self.fixture.reviews,
            excluded_principals=("candidate.operator",),
            created_at="2026-09-20T12:21:00Z",
        )
        with self.assertRaisesRegex(ArmyActivationContractError, "chain is not intact"):
            assess_activation_readiness(
                assessment=self.fixture.assessment,
                packet=self.fixture.packet,
                decision=self.fixture.decision,
                rollback=alternate_rollback,
                restoration=None,
                reviews=self.fixture.reviews,
                excluded_principals=("candidate.operator",),
                created_at="2026-09-20T13:10:00Z",
            )

    def test_no_runtime_or_provider_effects_exist(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        forbidden_imports = (
            "import requests",
            "import httpx",
            "import socket",
            "import subprocess",
            "from openai",
            "from anthropic",
        )
        for marker in forbidden_imports:
            self.assertNotIn(marker, source)
        for record in self.fixture.records:
            self.assertEqual(record.to_dict()["effects"], dict(NO_EFFECTS))

    def test_files_have_no_markers_or_unicode_dashes(self) -> None:
        marker = re.compile(
            "|".join(
                (
                    "generated" + r"\s+by",
                    "written" + r"\s+by\s+(?:an\s+)?" + "a" + "i",
                    "as" + r"\s+an\s+" + "a" + "i",
                    "chat" + "gpt",
                    "co" + r"-authored-by",
                )
            ),
            re.IGNORECASE,
        )
        for path in (MODULE, SCHEMA, DOC, THIS_FILE):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(marker.search(text), path)
            self.assertNotIn(chr(0x2013), text, path)
            self.assertNotIn(chr(0x2014), text, path)


if __name__ == "__main__":
    unittest.main()
