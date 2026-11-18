"""Phase 165 critical-role and advanced-domain gate contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
from sunderkey.advanced_domain_gate_contracts import (
    EXPECTED_COMMANDERS,
    MAXIMUM_DOMAIN_TIERS,
    NO_EFFECTS,
    ActionTier,
    AdvancedDomain,
    AdvancedDomainGateError,
    ArtifactBinding,
    CanaryAdmission,
    CriticalRole,
    CriticalRolePair,
    CriticalRoleRoster,
    DomainActivationRequest,
    DomainGateDecision,
    DomainSafetyPolicy,
    EnvironmentClass,
    EvidenceKind,
    GateStatus,
    IndependentReview,
    QualificationEvidence,
    ReviewerRole,
    RoleCandidate,
    RuntimeKind,
    SafetyEvidence,
    evaluate_domain_activation,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "advanced-domain-gate-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "advanced_domain_gate_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "advanced-domain-gate-contracts.md",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def artifact(name: str, character: str, version: str = "1.0.0") -> ArtifactBinding:
    return ArtifactBinding(f"artifact:{name}", digest(character), version)


def qualification(index: int) -> QualificationEvidence:
    character = "abcdef0123456789"[index % 16]
    return QualificationEvidence(
        artifact(f"qualification-{index}", character),
        "qualified",
        "2026-09-01T00:00:00Z",
        "2026-10-01T00:00:00Z",
        "AOE-HQ-29",
    )


def candidate(
    index: int,
    profile_id: str,
    *,
    runtime_kind: RuntimeKind = RuntimeKind.HUMAN,
    provider_id: str | None = None,
) -> RoleCandidate:
    model_backed = runtime_kind is not RuntimeKind.HUMAN
    return RoleCandidate(
        candidate_id=f"candidate:critical-{index}",
        profile_id=profile_id,
        runtime_kind=runtime_kind,
        maintainer_id=f"maintainer:team-{index}",
        failure_domain_id=f"failure-domain:zone-{index}",
        qualification=qualification(index),
        provider_id=provider_id if model_backed else None,
        model_id=f"model:role-{index}" if model_backed else None,
        model_version="2026.9.1" if model_backed else None,
    )


def roster() -> CriticalRoleRoster:
    return CriticalRoleRoster(
        army_registry=artifact("army-v2", "a", "2.0.0"),
        qualification_standard=artifact("qualification-standard-v2", "b", "2.0.0"),
        role_pairs=(
            CriticalRolePair(
                CriticalRole.DOMAIN_COMMAND,
                candidate(1, "AOE-GD-D19-CMD"),
                candidate(2, "AOE-GD-D19-CMD"),
            ),
            CriticalRolePair(
                CriticalRole.SAFETY,
                candidate(3, "AOE-HQ-14"),
                candidate(4, "AOE-HQ-14"),
            ),
            CriticalRolePair(
                CriticalRole.VALIDATION,
                candidate(5, "AOE-HQ-19"),
                candidate(6, "AOE-HQ-20"),
            ),
            CriticalRolePair(
                CriticalRole.HIGH_VALUE_SPECIALTY,
                candidate(
                    7,
                    "AOE-GD-D19-S05",
                    runtime_kind=RuntimeKind.HYBRID,
                    provider_id="provider:alpha",
                ),
                candidate(
                    8,
                    "AOE-GD-D19-S05",
                    runtime_kind=RuntimeKind.MODEL,
                    provider_id="provider:bravo",
                ),
            ),
        ),
        issued_at="2026-09-01T00:00:00Z",
        expires_at="2026-10-01T00:00:00Z",
    )


POLICY_ARTIFACTS = {
    "hazard_method": artifact("hazard-analysis", "c"),
    "simulator_requirements": artifact("simulator-replica-proof", "d"),
    "monitoring_contract": artifact("monitoring", "e"),
    "stop_contract": artifact("stop", "f"),
    "cleanup_contract": artifact("cleanup", "1"),
    "restoration_contract": artifact("restoration", "2"),
    "custody_contract": artifact("custody", "3"),
}


def policy(
    selected_roster: CriticalRoleRoster,
    domain: AdvancedDomain = AdvancedDomain.OT_CYBER_PHYSICAL,
) -> DomainSafetyPolicy:
    commander = EXPECTED_COMMANDERS.get(domain, "AOE-GD-D18-CMD")
    return DomainSafetyPolicy(
        domain=domain,
        domain_commander_profile_id=commander,
        maximum_action_tier=MAXIMUM_DOMAIN_TIERS[domain],
        roster_id=selected_roster.roster_id,
        roster_sha256=selected_roster.roster_sha256,
        issued_at="2026-09-01T00:00:00Z",
        expires_at="2026-10-01T00:00:00Z",
        **POLICY_ARTIFACTS,
    )


def safety_evidence(
    selected_policy: DomainSafetyPolicy,
    scope: ArtifactBinding,
    target_authority: ArtifactBinding,
    environment: EnvironmentClass,
    action_tier: ActionTier,
) -> tuple[SafetyEvidence, ...]:
    artifacts = {
        EvidenceKind.HAZARD_ANALYSIS: selected_policy.hazard_method,
        EvidenceKind.SIMULATOR_OR_REPLICA: selected_policy.simulator_requirements,
        EvidenceKind.TARGET_AUTHORITY: target_authority,
        EvidenceKind.MONITORING: selected_policy.monitoring_contract,
        EvidenceKind.STOP: selected_policy.stop_contract,
        EvidenceKind.CLEANUP: selected_policy.cleanup_contract,
        EvidenceKind.RESTORATION: selected_policy.restoration_contract,
        EvidenceKind.CUSTODY: selected_policy.custody_contract,
    }
    return tuple(
        SafetyEvidence(
            evidence_kind=kind,
            artifact=binding,
            producer_profile_id=f"producer:{kind.value}",
            reviewer_profile_id=f"reviewer:{kind.value}",
            policy_sha256=selected_policy.policy_sha256,
            scope_sha256=scope.artifact_sha256,
            action_tier=action_tier,
            environment=(
                EnvironmentClass.REPLICA
                if kind is EvidenceKind.SIMULATOR_OR_REPLICA
                else environment
            ),
            disposition="accepted",
            issued_at="2026-09-10T00:00:00Z",
            expires_at="2026-09-25T00:00:00Z",
        )
        for kind, binding in artifacts.items()
    )


def request(
    selected_roster: CriticalRoleRoster,
    selected_policy: DomainSafetyPolicy,
    *,
    environment: EnvironmentClass = EnvironmentClass.REPLICA,
    action_tier: ActionTier = ActionTier.R0,
    include_canary: bool = False,
    evidence: tuple[SafetyEvidence, ...] | None = None,
    control_reviewer: str = "AOE-HQ-12",
) -> DomainActivationRequest:
    scope = artifact("signed-scope", "4", "3.1.0")
    target_authority = artifact("target-authority", "5", "1.2.0")
    evidence_items = evidence or safety_evidence(
        selected_policy, scope, target_authority, environment, action_tier
    )
    values = {
        "requester_profile_id": "operator:mission-owner",
        "domain": selected_policy.domain,
        "domain_commander_profile_id": selected_policy.domain_commander_profile_id,
        "environment": environment,
        "requested_action_tier": action_tier,
        "policy_id": selected_policy.policy_id,
        "policy_sha256": selected_policy.policy_sha256,
        "roster_id": selected_roster.roster_id,
        "roster_sha256": selected_roster.roster_sha256,
        "scope": scope,
        "target_authority": target_authority,
        "deployment_profile": artifact("deployment-profile", "6", "1.0.0"),
        "evidence": evidence_items,
        "canary_admission": None,
        "requested_at": "2026-09-15T00:00:00Z",
        "expires_at": "2026-09-21T00:00:00Z",
    }
    provisional = DomainActivationRequest(independent_reviews=(), **values)
    reviews = tuple(
        IndependentReview(
            reviewer_role=role,
            reviewer_profile_id=reviewer,
            activation_basis_sha256=provisional.activation_basis_sha256,
            artifact=artifact(f"review-{role.value}", character),
            decision="accepted",
            reviewed_at="2026-09-16T00:00:00Z",
            expires_at="2026-09-21T00:00:00Z",
        )
        for role, reviewer, character in (
            (ReviewerRole.INDEPENDENT_CONTROL, control_reviewer, "7"),
            (ReviewerRole.INDEPENDENT_ASSURANCE, "AOE-HQ-28", "8"),
        )
    )
    canary = None
    if include_canary:
        canary = CanaryAdmission.build(
            admission_ref="admission:live-canary-001",
            canary_evidence=artifact("canary-evidence", "9"),
            policy_sha256=selected_policy.policy_sha256,
            scope_sha256=scope.artifact_sha256,
            action_tier=action_tier,
            decision_maker_profile_id="AOE-HQ-13",
            independent_reviewer_profile_id="AOE-HQ-18",
            admitted_at="2026-09-16T00:00:00Z",
            expires_at="2026-09-21T00:00:00Z",
        )
    return DomainActivationRequest(
        independent_reviews=reviews,
        canary_admission=canary,
        **{key: value for key, value in values.items() if key != "canary_admission"},
    )


class AdvancedDomainGateContractsPhase165Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.evaluate_advanced_domain_activation,
            evaluate_domain_activation,
        )
        self.assertIs(
            sunderkey.parse_advanced_domain_gate_contract,
            parse_contract,
        )

    def test_roster_is_two_deep_deterministic_and_immutable(self) -> None:
        record = roster()
        self.assertEqual(len(record.role_pairs), 4)
        self.assertEqual(
            {pair.role for pair in record.role_pairs},
            set(CriticalRole),
        )
        self.assertEqual(record, CriticalRoleRoster.from_json(record.to_json()))
        self.assertEqual(record, parse_contract(record.to_dict()))
        self.assertEqual(record.to_dict()["effects"], dict(NO_EFFECTS))
        with self.assertRaises(FrozenInstanceError):
            record.expires_at = "2027-01-01T00:00:00Z"  # type: ignore[misc]

    def test_role_aliasing_shared_failure_domain_and_maintainer_fail_closed(self) -> None:
        primary = candidate(11, "AOE-HQ-14")
        with self.assertRaisesRegex(AdvancedDomainGateError, "must be distinct"):
            CriticalRolePair(CriticalRole.SAFETY, primary, primary)
        with self.assertRaisesRegex(AdvancedDomainGateError, "failure domain"):
            CriticalRolePair(
                CriticalRole.SAFETY,
                primary,
                replace(candidate(12, "AOE-HQ-14"), failure_domain_id=primary.failure_domain_id),
            )
        with self.assertRaisesRegex(AdvancedDomainGateError, "maintainer"):
            CriticalRolePair(
                CriticalRole.SAFETY,
                primary,
                replace(candidate(12, "AOE-HQ-14"), maintainer_id=primary.maintainer_id),
            )

    def test_missing_role_and_cross_role_candidate_alias_fail_closed(self) -> None:
        baseline = roster()
        with self.assertRaisesRegex(AdvancedDomainGateError, "every critical role"):
            replace(baseline, role_pairs=baseline.role_pairs[:-1])
        duplicate = replace(
            baseline.role_pairs[-1],
            alternate=baseline.role_pairs[0].primary,
        )
        with self.assertRaisesRegex(AdvancedDomainGateError, "aliased across roles"):
            replace(baseline, role_pairs=(*baseline.role_pairs[:-1], duplicate))

    def test_model_backed_alternatives_require_pins_and_distinct_providers(self) -> None:
        with self.assertRaisesRegex(AdvancedDomainGateError, "requires provider and model"):
            candidate(13, "AOE-GD-D20-S08", runtime_kind=RuntimeKind.MODEL)
        primary = candidate(
            14,
            "AOE-GD-D20-S08",
            runtime_kind=RuntimeKind.MODEL,
            provider_id="provider:one",
        )
        alternate = candidate(
            15,
            "AOE-GD-D20-S08",
            runtime_kind=RuntimeKind.HYBRID,
            provider_id="provider:one",
        )
        with self.assertRaisesRegex(AdvancedDomainGateError, "distinct providers"):
            CriticalRolePair(CriticalRole.HIGH_VALUE_SPECIALTY, primary, alternate)

    def test_all_advanced_domains_have_fixed_safe_policy_shapes(self) -> None:
        selected_roster = roster()
        for domain in AdvancedDomain:
            with self.subTest(domain=domain.value):
                record = policy(selected_roster, domain)
                self.assertEqual(record.maximum_action_tier, MAXIMUM_DOMAIN_TIERS[domain])
                self.assertEqual(record, DomainSafetyPolicy.from_json(record.to_json()))
                self.assertEqual(record, parse_contract(record.to_dict()))

    def test_wrong_commander_and_unsafe_policy_ceiling_fail_closed(self) -> None:
        selected_roster = roster()
        baseline = policy(selected_roster)
        with self.assertRaisesRegex(AdvancedDomainGateError, "does not match Army v2"):
            replace(baseline, domain_commander_profile_id="AOE-GD-D25-CMD")
        with self.assertRaisesRegex(AdvancedDomainGateError, "ceiling is unsafe"):
            replace(baseline, maximum_action_tier=ActionTier.R1)

    def test_replica_request_is_contract_ready_but_never_activated(self) -> None:
        selected_roster = roster()
        selected_policy = policy(selected_roster)
        selected_request = request(selected_roster, selected_policy)
        decision = evaluate_domain_activation(
            selected_policy,
            selected_roster,
            selected_request,
            evaluated_at="2026-09-20T00:00:00Z",
        )
        self.assertEqual(decision.status, GateStatus.CONTRACT_READY_UNVERIFIED)
        self.assertEqual(decision.blocker_codes, ())
        self.assertEqual(decision.to_dict()["effects"], dict(NO_EFFECTS))
        self.assertEqual(
            selected_request, DomainActivationRequest.from_json(selected_request.to_json())
        )
        self.assertEqual(decision, DomainGateDecision.from_json(decision.to_json()))
        self.assertEqual(decision, parse_contract(decision.to_dict()))

    def test_live_request_needs_separately_admitted_canary(self) -> None:
        selected_roster = roster()
        selected_policy = policy(selected_roster)
        denied = evaluate_domain_activation(
            selected_policy,
            selected_roster,
            request(selected_roster, selected_policy, environment=EnvironmentClass.LIVE),
            evaluated_at="2026-09-20T00:00:00Z",
        )
        self.assertEqual(denied.status, GateStatus.DENIED)
        self.assertIn("separate_canary_admission_missing", denied.blocker_codes)
        compatible = evaluate_domain_activation(
            selected_policy,
            selected_roster,
            request(
                selected_roster,
                selected_policy,
                environment=EnvironmentClass.LIVE,
                include_canary=True,
            ),
            evaluated_at="2026-09-20T00:00:00Z",
        )
        self.assertEqual(compatible.status, GateStatus.CONTRACT_READY_UNVERIFIED)

    def test_unsafe_action_tier_and_stale_qualification_fail_closed(self) -> None:
        selected_roster = roster()
        selected_policy = policy(selected_roster)
        unsafe = request(selected_roster, selected_policy, action_tier=ActionTier.R1)
        decision = evaluate_domain_activation(
            selected_policy,
            selected_roster,
            unsafe,
            evaluated_at="2026-09-20T00:00:00Z",
        )
        self.assertIn("unsafe_action_tier", decision.blocker_codes)
        stale = evaluate_domain_activation(
            selected_policy,
            selected_roster,
            request(selected_roster, selected_policy),
            evaluated_at="2026-10-02T00:00:00Z",
        )
        self.assertIn("qualification_evidence_not_current", stale.blocker_codes)
        self.assertIn("safety_evidence_not_current", stale.blocker_codes)
        self.assertIn("independent_review_not_current", stale.blocker_codes)
        self.assertIn("policy_not_current", stale.blocker_codes)

    def test_missing_recovery_proof_and_self_review_fail_closed(self) -> None:
        selected_roster = roster()
        selected_policy = policy(selected_roster)
        baseline = request(selected_roster, selected_policy)
        without_restoration = tuple(
            item for item in baseline.evidence if item.evidence_kind is not EvidenceKind.RESTORATION
        )
        denied = evaluate_domain_activation(
            selected_policy,
            selected_roster,
            request(selected_roster, selected_policy, evidence=without_restoration),
            evaluated_at="2026-09-20T00:00:00Z",
        )
        self.assertIn("required_safety_evidence_missing", denied.blocker_codes)
        self_review = evaluate_domain_activation(
            selected_policy,
            selected_roster,
            request(
                selected_roster,
                selected_policy,
                control_reviewer="candidate:critical-1",
            ),
            evaluated_at="2026-09-20T00:00:00Z",
        )
        self.assertIn("self_review_forbidden", self_review.blocker_codes)

    def test_binding_tampering_and_effect_escalation_fail_closed(self) -> None:
        selected_roster = roster()
        raw = selected_roster.to_dict()
        raw["roster_sha256"] = digest("0")
        with self.assertRaisesRegex(AdvancedDomainGateError, "identity or contents"):
            CriticalRoleRoster.from_dict(raw)
        raw = selected_roster.to_dict()
        raw["effects"]["activation"] = "allowed"
        with self.assertRaisesRegex(AdvancedDomainGateError, "effect escalation"):
            CriticalRoleRoster.from_dict(raw)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_every_record_and_rejects_extra_fields(self) -> None:
        selected_roster = roster()
        selected_policy = policy(selected_roster)
        selected_request = request(selected_roster, selected_policy)
        decision = evaluate_domain_activation(
            selected_policy,
            selected_roster,
            selected_request,
            evaluated_at="2026-09-20T00:00:00Z",
        )
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        for record in (selected_roster, selected_policy, selected_request, decision):
            document = record.to_dict()
            with self.subTest(kind=document["kind"]):
                validator.validate(document)
                changed = copy.deepcopy(document)
                changed["unexpected"] = True
                self.assertTrue(list(validator.iter_errors(changed)))

    def test_increment_files_are_free_of_unicode_dashes(self) -> None:
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)


if __name__ == "__main__":
    unittest.main()
