"""Phase 165 atomic action-admission contract coverage."""

from __future__ import annotations

import copy
import json
import re
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
from sunderkey.action_admission_contracts import (
    NO_EFFECTS,
    REQUIRED_EVIDENCE,
    ActionAdmissionContractError,
    ActionAdmissionDecision,
    ActionAdmissionRequest,
    ActionTier,
    AdmissionStatus,
    ApprovalBinding,
    ArtifactBinding,
    BudgetBinding,
    ContextBinding,
    CredentialLease,
    DenialReason,
    EvidenceObligation,
    HealthEvidence,
    HealthStatus,
    RequestedAction,
    RestorationDuties,
    StopConditions,
    TargetBinding,
    TargetEnvironment,
    WorkerSession,
    evaluate_action_admission,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "action-admission-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "action_admission_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "action-admission-contracts.md",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def artifact(name: str, character: str) -> ArtifactBinding:
    return ArtifactBinding(f"artifact:{name}", digest(character), "1.0.0")


def valid_request() -> ActionAdmissionRequest:
    tenant = "tenant:alpha"
    mission = "mission:assessment-001"
    scope = digest("a")
    target_sha = digest("b")
    action_sha = digest("c")
    worker_id = "worker:api-017"
    session_id = "session:lease-004"
    evidence = tuple(
        EvidenceObligation(
            evidence_kind=kind,
            evidence_sha256=digest("1234567"[index]),
            tenant_id=tenant,
            mission_id=mission,
            scope_sha256=scope,
            target_sha256=target_sha,
            action_sha256=action_sha,
            producer_id=f"producer:{kind.value}",
            issued_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T13:00:00Z",
        )
        for index, kind in enumerate(sorted(REQUIRED_EVIDENCE, key=lambda item: item.value))
    )
    return ActionAdmissionRequest(
        context=ContextBinding(
            tenant_id=tenant,
            mission_id=mission,
            scope_id="scope:approved-001",
            scope_sha256=scope,
            policy=artifact("admission-policy", "d"),
        ),
        worker_session=WorkerSession(
            worker_id=worker_id,
            worker_profile_id="AOE-GA-D01-S01",
            session_id=session_id,
            tenant_id=tenant,
            mission_id=mission,
            fence_token_sha256=digest("e"),
            leader_epoch=7,
            issued_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T13:00:00Z",
        ),
        approval=ApprovalBinding(
            approval_id="approval:001",
            approval_sha256=digest("f"),
            tenant_id=tenant,
            mission_id=mission,
            scope_sha256=scope,
            target_sha256=target_sha,
            action_sha256=action_sha,
            worker_id=worker_id,
            session_id=session_id,
            fence_token_sha256=digest("e"),
            leader_epoch=7,
            authorized_tier=ActionTier.R2,
            approver_id="operator:mission-owner",
            decision="approved",
            issued_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T13:00:00Z",
        ),
        credential_lease=CredentialLease(
            lease_id="credential-lease:001",
            credential_ref_sha256=digest("0"),
            tenant_id=tenant,
            mission_id=mission,
            scope_sha256=scope,
            worker_id=worker_id,
            session_id=session_id,
            fence_token_sha256=digest("e"),
            leader_epoch=7,
            permitted_action_sha256=action_sha,
            revoked=False,
            issued_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T13:00:00Z",
        ),
        health=HealthEvidence(
            worker_id=worker_id,
            session_id=session_id,
            fence_token_sha256=digest("e"),
            leader_epoch=7,
            status=HealthStatus.HEALTHY,
            evidence_sha256=digest("1"),
            observed_at="2026-09-20T11:55:00Z",
            expires_at="2026-09-20T12:05:00Z",
        ),
        budget=BudgetBinding(
            tenant_id=tenant,
            mission_id=mission,
            budget_sha256=digest("2"),
            request_limit=100,
            requests_used=99,
            token_limit=10000,
            tokens_used=9000,
            cost_limit_microunits=100000,
            cost_used_microunits=90000,
            action_request_cost=1,
            action_token_cost=1000,
            action_cost_microunits=10000,
        ),
        target=TargetBinding(
            target_id="target:api-001",
            target_sha256=target_sha,
            authority_sha256=digest("3"),
            tenant_id=tenant,
            mission_id=mission,
            scope_sha256=scope,
            environment=TargetEnvironment.LIVE,
        ),
        action=RequestedAction(
            action_id="action:request-001",
            action_type="api.request",
            action_tier=ActionTier.R2,
            action_sha256=action_sha,
            target_sha256=target_sha,
            parameters_sha256=digest("4"),
            tool=artifact("api-executor", "5"),
            idempotency_key_sha256=digest("6"),
        ),
        evidence_obligations=evidence,
        stop_conditions=StopConditions(
            stop_contract_sha256=digest("7"),
            monitor_session_id="session:monitor-009",
            monitor_worker_id="worker:safety-003",
            scope_sha256=scope,
            target_sha256=target_sha,
            action_sha256=action_sha,
            maximum_impact_events=1,
            stop_deadline_at="2026-09-20T12:10:00Z",
            expires_at="2026-09-20T12:05:00Z",
        ),
        restoration_duties=RestorationDuties(
            required=True,
            restoration_plan_sha256=digest("8"),
            owner_profile_id="AOE-HQ-14",
            verifier_profile_id="AOE-HQ-20",
            scope_sha256=scope,
            target_sha256=target_sha,
            action_sha256=action_sha,
            completion_evidence_required=True,
        ),
        requested_at="2026-09-20T11:50:00Z",
        expires_at="2026-09-20T12:05:00Z",
    )


def changed_request(request: ActionAdmissionRequest, **changes: object) -> ActionAdmissionRequest:
    values = {
        item.name: getattr(request, item.name)
        for item in fields(request)
        if item.name not in {"request_id", "request_sha256"}
    }
    values.update(changes)
    return ActionAdmissionRequest(**values)


class ActionAdmissionContractTests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(sunderkey.evaluate_action_admission, evaluate_action_admission)
        self.assertIs(
            sunderkey.parse_action_admission_contract,
            parse_contract,
        )

    def setUp(self) -> None:
        self.request = valid_request()

    def evaluate(
        self, request: ActionAdmissionRequest | None = None, at: str = "2026-09-20T12:00:00Z"
    ) -> ActionAdmissionDecision:
        return evaluate_action_admission(request or self.request, evaluated_at=at)

    def assert_denied(self, request: ActionAdmissionRequest, reason: DenialReason) -> None:
        decision = self.evaluate(request)
        self.assertIs(decision.status, AdmissionStatus.DENIED)
        self.assertIn(reason, decision.denial_reasons)

    def test_exact_boundaries_are_admitted_contract_only_and_deterministic(self) -> None:
        first = self.evaluate()
        second = self.evaluate()
        self.assertIs(first.status, AdmissionStatus.ADMITTED_CONTRACT_ONLY)
        self.assertEqual(first.denial_reasons, ())
        self.assertEqual(first, second)
        self.assertEqual(first.decision_sha256, second.decision_sha256)
        self.assertEqual(self.request.budget.requests_used + 1, self.request.budget.request_limit)
        self.assertEqual(self.request.action.action_tier, self.request.approval.authorized_tier)
        self.assertEqual(first.to_dict()["effects"], dict(NO_EFFECTS))

    def test_immutability_and_content_address_round_trip(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.request.context.tenant_id = "tenant:other"  # type: ignore[misc]
        parsed = parse_contract(self.request.to_json())
        self.assertEqual(parsed, self.request)
        decision = self.evaluate()
        self.assertEqual(parse_contract(decision.to_json()), decision)
        self.assertTrue(self.request.request_id.startswith("AAR-"))
        self.assertTrue(decision.decision_id.startswith("AAD-"))

    def test_tamper_unknown_field_noncanonical_json_and_effect_escalation_fail(self) -> None:
        raw = self.request.to_dict()
        raw["request_sha256"] = digest("9")
        with self.assertRaisesRegex(ActionAdmissionContractError, "does not match"):
            ActionAdmissionRequest.from_dict(raw)
        raw = self.request.to_dict()
        raw["unknown"] = True
        with self.assertRaisesRegex(ActionAdmissionContractError, "fields"):
            ActionAdmissionRequest.from_dict(raw)
        with self.assertRaisesRegex(ActionAdmissionContractError, "canonical"):
            ActionAdmissionRequest.from_json(json.dumps(self.request.to_dict(), indent=2))
        raw = self.request.to_dict()
        raw["effects"]["network"] = "allowed"
        with self.assertRaisesRegex(ActionAdmissionContractError, "effect escalation"):
            ActionAdmissionRequest.from_dict(raw)

    def test_cross_tenant_mission_scope_and_target_fail_closed(self) -> None:
        self.assert_denied(
            changed_request(
                self.request,
                approval=replace(self.request.approval, tenant_id="tenant:other"),
            ),
            DenialReason.CONTEXT_MISMATCH,
        )
        self.assert_denied(
            changed_request(
                self.request,
                target=replace(self.request.target, mission_id="mission:other"),
            ),
            DenialReason.CONTEXT_MISMATCH,
        )
        self.assert_denied(
            changed_request(
                self.request,
                target=replace(self.request.target, scope_sha256=digest("9")),
            ),
            DenialReason.TARGET_MISMATCH,
        )
        self.assert_denied(
            changed_request(
                self.request,
                action=replace(self.request.action, target_sha256=digest("9")),
            ),
            DenialReason.TARGET_MISMATCH,
        )

    def test_worker_fence_session_and_credential_cross_context_fail_closed(self) -> None:
        self.assert_denied(
            changed_request(
                self.request,
                credential_lease=replace(self.request.credential_lease, session_id="session:other"),
            ),
            DenialReason.WORKER_SESSION_MISMATCH,
        )
        self.assert_denied(
            changed_request(
                self.request,
                approval=replace(self.request.approval, worker_id="worker:other"),
            ),
            DenialReason.WORKER_SESSION_MISMATCH,
        )
        self.assert_denied(
            changed_request(
                self.request,
                credential_lease=replace(self.request.credential_lease, revoked=True),
            ),
            DenialReason.CREDENTIAL_MISMATCH,
        )
        altered = changed_request(
            self.request,
            worker_session=replace(self.request.worker_session, fence_token_sha256=digest("9")),
        )
        self.assertNotEqual(altered.request_sha256, self.request.request_sha256)
        self.assert_denied(altered, DenialReason.WORKER_SESSION_MISMATCH)

    def test_stale_prerequisites_are_all_reported(self) -> None:
        request = changed_request(
            self.request,
            requested_at="2026-09-20T10:00:00Z",
            expires_at="2026-09-20T11:00:00Z",
            worker_session=replace(
                self.request.worker_session,
                issued_at="2026-09-20T09:00:00Z",
                expires_at="2026-09-20T11:00:00Z",
            ),
            approval=replace(
                self.request.approval,
                issued_at="2026-09-20T09:00:00Z",
                expires_at="2026-09-20T11:00:00Z",
            ),
            credential_lease=replace(
                self.request.credential_lease,
                issued_at="2026-09-20T09:00:00Z",
                expires_at="2026-09-20T11:00:00Z",
            ),
            health=replace(
                self.request.health,
                observed_at="2026-09-20T09:00:00Z",
                expires_at="2026-09-20T11:00:00Z",
            ),
        )
        decision = self.evaluate(request)
        expected = {
            DenialReason.STALE_WORKER_SESSION,
            DenialReason.STALE_APPROVAL,
            DenialReason.STALE_CREDENTIAL,
            DenialReason.STALE_HEALTH,
            DenialReason.STALE_REQUEST,
        }
        self.assertTrue(expected.issubset(set(decision.denial_reasons)))

    def test_missing_mismatched_and_stale_evidence_fail_closed(self) -> None:
        self.assert_denied(
            changed_request(
                self.request,
                evidence_obligations=self.request.evidence_obligations[:-1],
            ),
            DenialReason.MISSING_EVIDENCE,
        )
        evidence = list(self.request.evidence_obligations)
        evidence[0] = replace(evidence[0], action_sha256=digest("9"))
        self.assert_denied(
            changed_request(self.request, evidence_obligations=tuple(evidence)),
            DenialReason.EVIDENCE_MISMATCH,
        )
        evidence = list(self.request.evidence_obligations)
        evidence[0] = replace(
            evidence[0], issued_at="2026-09-20T09:00:00Z", expires_at="2026-09-20T11:00:00Z"
        )
        self.assert_denied(
            changed_request(self.request, evidence_obligations=tuple(evidence)),
            DenialReason.STALE_EVIDENCE,
        )

    def test_tier_budget_health_stop_and_restoration_fail_closed(self) -> None:
        self.assert_denied(
            changed_request(
                self.request,
                action=replace(self.request.action, action_tier=ActionTier.R3),
            ),
            DenialReason.APPROVAL_TIER_EXCEEDED,
        )
        self.assert_denied(
            changed_request(
                self.request,
                budget=replace(self.request.budget, action_request_cost=2),
            ),
            DenialReason.BUDGET_EXCEEDED,
        )
        self.assert_denied(
            changed_request(
                self.request,
                health=replace(self.request.health, status=HealthStatus.DEGRADED),
            ),
            DenialReason.WORKER_UNHEALTHY,
        )
        self.assert_denied(
            changed_request(
                self.request,
                stop_conditions=replace(
                    self.request.stop_conditions,
                    monitor_worker_id=self.request.worker_session.worker_id,
                ),
            ),
            DenialReason.STOP_CONDITION_MISMATCH,
        )
        self.assert_denied(
            changed_request(
                self.request,
                restoration_duties=replace(
                    self.request.restoration_duties, target_sha256=digest("9")
                ),
            ),
            DenialReason.RESTORATION_DUTY_MISMATCH,
        )

    def test_constructor_boundaries_fail_closed(self) -> None:
        with self.assertRaises(ActionAdmissionContractError):
            replace(self.request.worker_session, leader_epoch=0)
        with self.assertRaises(ActionAdmissionContractError):
            replace(self.request.budget, requests_used=-1)
        with self.assertRaises(ActionAdmissionContractError):
            replace(self.request.stop_conditions, maximum_impact_events=0)
        with self.assertRaises(ActionAdmissionContractError):
            replace(self.request.restoration_duties, verifier_profile_id="AOE-HQ-14")
        with self.assertRaises(ActionAdmissionContractError):
            ActionAdmissionRequest.from_dict(
                {**self.request.to_dict(), "evidence_obligations": "invalid"}
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_records_and_rejects_boundaries(self) -> None:
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        validator.validate(self.request.to_dict())
        validator.validate(self.evaluate().to_dict())
        raw = copy.deepcopy(self.request.to_dict())
        raw["worker_session"]["leader_epoch"] = 0
        self.assertTrue(list(validator.iter_errors(raw)))
        raw = copy.deepcopy(self.request.to_dict())
        raw["context"]["extra"] = True
        self.assertTrue(list(validator.iter_errors(raw)))

    def test_source_has_no_markers_or_unicode_dashes(self) -> None:
        marker_parts = (
            "generated " + "by",
            "written " + "by (?:an )?ai",
            "as an " + "ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored-" + "by",
        )
        marker = re.compile("|".join(marker_parts), re.IGNORECASE)
        for path in FILES:
            content = path.read_text(encoding="utf-8")
            self.assertNotRegex(content, marker)
            self.assertNotIn("\u2013", content)
            self.assertNotIn("\u2014", content)

    def test_no_effects_are_exact_and_no_runtime_clients_exist(self) -> None:
        self.assertEqual(
            dict(NO_EFFECTS),
            {
                "authorization": "none",
                "credential_use": "none",
                "dispatch": "none",
                "network": "none",
                "restoration": "none",
                "stop": "none",
                "target_action": "none",
            },
        )
        source = FILES[0].read_text(encoding="utf-8")
        for forbidden in ("import requests", "import socket", "subprocess", "urllib.request"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
