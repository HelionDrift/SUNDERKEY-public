from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    Draft202012Validator = None
    ValidationError = None

import sunderkey
from sunderkey.cleanup_restoration_contracts import (
    NO_EFFECTS,
    CleanupCompletionAssessment,
    CleanupObservation,
    CleanupRestorationContractError,
    CleanupRestorationPlan,
    CleanupStep,
    CompensatingAction,
    CompletionStatus,
    EvidenceRequirement,
    FailureBehavior,
    ResidualArtifact,
    ResidualDisposition,
    StepKind,
    StepObservation,
    StepOutcome,
    TargetState,
    TargetStateObligation,
    assess_cleanup_completion,
    parse_contract,
)

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64
HASH_D = "sha256:" + "d" * 64
HASH_E = "sha256:" + "e" * 64
HASH_F = "sha256:" + "f" * 64


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def test_public_package_exports_are_available() -> None:
    case = _case()
    case.assertIs(sunderkey.assess_cleanup_completion, assess_cleanup_completion)
    case.assertIs(
        sunderkey.parse_cleanup_restoration_contract,
        parse_contract,
    )


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    del loader, tests, pattern
    suite = unittest.TestSuite()
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            suite.addTest(unittest.FunctionTestCase(value))
    return suite


def _requirement(ref: str = "evidenceref:state-verification") -> EvidenceRequirement:
    return EvidenceRequirement(ref, HASH_E, "1.0.0")


def _obligation(
    ref: str = "targetstateref:restore-service",
    target: str = "artifactref:service-config",
    state: TargetState = TargetState.RESTORED,
) -> TargetStateObligation:
    return TargetStateObligation(ref, target, HASH_D, state, HASH_A, HASH_B)


def _compensation() -> CompensatingAction:
    return CompensatingAction("actionref:rollback-config", HASH_C, "1.0.0", "rollback")


def _step(
    *,
    step_ref: str = "stepref:restore-config",
    sequence: int = 1,
    obligation_ref: str = "targetstateref:restore-service",
    behavior: FailureBehavior = FailureBehavior.ROLLBACK,
) -> CleanupStep:
    return CleanupStep(
        step_ref=step_ref,
        sequence=sequence,
        kind=StepKind.RESTORE,
        target_state_ref=obligation_ref,
        action_ref="actionref:restore-config",
        action_sha256=HASH_C,
        timeout_seconds=300,
        failure_behavior=behavior,
        evidence_requirements=(_requirement(),),
        compensating_actions=(_compensation(),) if behavior is not FailureBehavior.HALT else (),
    )


def _plan(**changes: object) -> CleanupRestorationPlan:
    values: dict[str, object] = {
        "tenant_ref": "tenantref:acme",
        "tenant_sha256": HASH_E,
        "mission_ref": "missionref:mission-42",
        "mission_sha256": HASH_F,
        "scope_sha256": HASH_A,
        "action_sha256": HASH_B,
        "worker_ref": "principalref:worker-7",
        "worker_profile_sha256": HASH_C,
        "target_sha256": HASH_D,
        "contract_version": "1.0.0",
        "contract_version_sha256": HASH_A,
        "approval_ref": "approvalref:cleanup-42",
        "approval_sha256": HASH_F,
        "obligations": (_obligation(),),
        "steps": (_step(),),
        "created_at": "2026-09-20T10:00:00Z",
        "expires_at": "2026-09-20T12:00:00Z",
    }
    values.update(changes)
    return CleanupRestorationPlan(**values)


def _step_observation(
    *,
    outcome: StepOutcome = StepOutcome.SUCCEEDED,
    evidence: tuple[EvidenceRequirement, ...] | None = None,
    compensated: bool = False,
) -> StepObservation:
    if evidence is None:
        evidence = (_requirement(),) if outcome is StepOutcome.SUCCEEDED else ()
    return StepObservation(
        step_ref="stepref:restore-config",
        sequence=1,
        outcome=outcome,
        started_at="2026-09-20T10:10:00Z",
        completed_at=(
            None
            if outcome in {StepOutcome.TIMED_OUT, StepOutcome.NOT_OBSERVED}
            else "2026-09-20T10:11:00Z"
        ),
        observed_evidence=evidence,
        compensation_observed=compensated,
        reason_code="observed",
    )


def _observation(
    plan: CleanupRestorationPlan,
    *,
    steps: tuple[StepObservation, ...] | None = None,
    residuals: tuple[ResidualArtifact, ...] = (),
    **changes: object,
) -> CleanupObservation:
    values: dict[str, object] = {
        "tenant_ref": plan.tenant_ref,
        "tenant_sha256": plan.tenant_sha256,
        "mission_ref": plan.mission_ref,
        "mission_sha256": plan.mission_sha256,
        "scope_sha256": plan.scope_sha256,
        "action_sha256": plan.action_sha256,
        "worker_ref": plan.worker_ref,
        "worker_profile_sha256": plan.worker_profile_sha256,
        "target_sha256": plan.target_sha256,
        "contract_version": plan.contract_version,
        "contract_version_sha256": plan.contract_version_sha256,
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "observer_ref": "principalref:independent-observer",
        "reviewer_ref": "reviewerref:independent-reviewer",
        "observations": steps or (_step_observation(),),
        "residual_artifacts": residuals,
        "observed_at": "2026-09-20T10:12:00Z",
    }
    values.update(changes)
    return CleanupObservation(**values)


def _assess(
    plan: CleanupRestorationPlan, observation: CleanupObservation
) -> CleanupCompletionAssessment:
    return assess_cleanup_completion(
        plan,
        observation,
        reviewer_ref="reviewerref:independent-reviewer",
        reviewed_at="2026-09-20T10:15:00Z",
    )


def test_happy_path_is_only_contract_complete_unverified() -> None:
    plan = _plan()
    observation = _observation(plan)
    assessment = _assess(plan, observation)
    _case().assertEqual(assessment.status, CompletionStatus.CONTRACT_COMPLETE_UNVERIFIED)
    _case().assertEqual(assessment.reason_codes, ("all_obligations_observed",))
    _case().assertEqual(dict(NO_EFFECTS), assessment.to_dict()["effects"])


def test_every_record_is_content_addressed_and_round_trips() -> None:
    plan = _plan()
    observation = _observation(plan)
    assessment = _assess(plan, observation)
    for value in (plan, observation, assessment):
        encoded = json.loads(json.dumps(value.to_dict()))
        parsed = parse_contract(encoded)
        _case().assertEqual(parsed, value)
        _case().assertTrue(any(key.endswith("_sha256") for key in encoded))


def test_tampered_content_address_is_rejected() -> None:
    raw = _plan().to_dict()
    raw["target_sha256"] = HASH_F
    with _case().assertRaises(CleanupRestorationContractError):
        parse_contract(raw)


def test_unknown_fields_and_mutated_effects_are_rejected() -> None:
    raw = _plan().to_dict()
    raw["unexpected"] = True
    with _case().assertRaises(CleanupRestorationContractError):
        parse_contract(raw)
    raw = _plan().to_dict()
    raw["effects"]["network"] = "performed"
    with _case().assertRaises(CleanupRestorationContractError):
        parse_contract(raw)


def test_all_context_bindings_fail_closed_across_plan_and_observation() -> None:
    plan = _plan()
    changes = {
        "tenant_ref": "tenantref:other",
        "tenant_sha256": HASH_D,
        "mission_ref": "missionref:other",
        "mission_sha256": HASH_D,
        "scope_sha256": HASH_F,
        "action_sha256": HASH_F,
        "worker_ref": "principalref:other-worker",
        "worker_profile_sha256": HASH_F,
        "target_sha256": HASH_F,
        "contract_version": "1.0.1",
        "contract_version_sha256": HASH_D,
    }
    for name, value in changes.items():
        observation = _observation(plan, **{name: value})
        with _case().assertRaises(CleanupRestorationContractError, msg=name):
            _assess(plan, observation)


def test_plan_requires_contiguous_steps_and_full_obligation_coverage() -> None:
    with _case().assertRaises(CleanupRestorationContractError):
        _plan(steps=(_step(sequence=2),))
    second = _obligation(
        "targetstateref:remove-agent", "artifactref:temporary-agent", TargetState.ABSENT
    )
    with _case().assertRaises(CleanupRestorationContractError):
        _plan(obligations=(_obligation(), second))


def test_rollback_behavior_requires_compensating_action() -> None:
    with _case().assertRaises(CleanupRestorationContractError):
        CleanupStep(
            step_ref="stepref:restore-config",
            sequence=1,
            kind=StepKind.RESTORE,
            target_state_ref="targetstateref:restore-service",
            action_ref="actionref:restore-config",
            action_sha256=HASH_C,
            timeout_seconds=300,
            failure_behavior=FailureBehavior.ROLLBACK,
            evidence_requirements=(_requirement(),),
            compensating_actions=(),
        )


def test_timeout_is_incomplete_and_requires_compensation_evidence() -> None:
    plan = _plan()
    result = _assess(
        plan,
        _observation(plan, steps=(_step_observation(outcome=StepOutcome.TIMED_OUT),)),
    )
    _case().assertEqual(result.status, CompletionStatus.INCOMPLETE)
    _case().assertIn("step_timed_out", result.reason_codes)
    _case().assertIn("compensation_unobserved", result.reason_codes)


def test_partial_failure_with_observed_compensation_remains_incomplete() -> None:
    plan = _plan()
    result = _assess(
        plan,
        _observation(
            plan,
            steps=(_step_observation(outcome=StepOutcome.FAILED, compensated=True),),
        ),
    )
    _case().assertEqual(result.status, CompletionStatus.INCOMPLETE)
    _case().assertIn("step_failed", result.reason_codes)
    _case().assertNotIn("compensation_unobserved", result.reason_codes)


def test_mismatched_evidence_fails_closed() -> None:
    plan = _plan()
    wrong = EvidenceRequirement("evidenceref:state-verification", HASH_F, "1.0.0")
    result = _assess(plan, _observation(plan, steps=(_step_observation(evidence=(wrong,)),)))
    _case().assertEqual(result.status, CompletionStatus.INCOMPLETE)
    _case().assertIn("required_evidence_missing_or_mismatched", result.reason_codes)


def test_residual_artifacts_and_unresolved_risk_prevent_completion() -> None:
    plan = _plan()
    residual = ResidualArtifact(
        risk_ref="riskref:orphan-session",
        artifact_ref="artifactref:orphan-session",
        expected_sha256=HASH_A,
        observed_sha256=HASH_B,
        disposition=ResidualDisposition.UNRESOLVED,
        separate_authority_ref=None,
        reason="Session state remains observable",
    )
    result = _assess(plan, _observation(plan, residuals=(residual,)))
    _case().assertEqual(result.status, CompletionStatus.INCOMPLETE)
    _case().assertIn("residual_artifact_present", result.reason_codes)
    _case().assertIn("residual_risk_unresolved", result.reason_codes)


def test_separate_residual_authority_does_not_turn_cleanup_complete() -> None:
    plan = _plan()
    residual = ResidualArtifact(
        risk_ref="riskref:retained-log",
        artifact_ref="artifactref:audit-log",
        expected_sha256=HASH_A,
        observed_sha256=HASH_A,
        disposition=ResidualDisposition.ACCEPTED_BY_SEPARATE_AUTHORITY,
        separate_authority_ref="approvalref:risk-acceptance",
        reason="Retention requirement remains active",
    )
    result = _assess(plan, _observation(plan, residuals=(residual,)))
    _case().assertEqual(result.status, CompletionStatus.INCOMPLETE)
    _case().assertIn("residual_artifact_present", result.reason_codes)


def test_unresolved_residual_cannot_claim_separate_authority() -> None:
    with _case().assertRaises(CleanupRestorationContractError):
        ResidualArtifact(
            "riskref:test",
            "artifactref:test",
            HASH_A,
            None,
            ResidualDisposition.UNRESOLVED,
            "approvalref:not-applicable",
            "Artifact remains unresolved",
        )


def test_observer_and_reviewer_independence_is_enforced() -> None:
    plan = _plan()
    with _case().assertRaises(CleanupRestorationContractError):
        _observation(plan, observer_ref=plan.worker_ref)
    with _case().assertRaises(CleanupRestorationContractError):
        _observation(plan, observer_ref="principalref:same", reviewer_ref="principalref:same")


def test_reviewer_binding_and_time_order_fail_closed() -> None:
    plan = _plan()
    observation = _observation(plan)
    with _case().assertRaises(CleanupRestorationContractError):
        assess_cleanup_completion(
            plan,
            observation,
            reviewer_ref="reviewerref:other",
            reviewed_at="2026-09-20T10:15:00Z",
        )
    with _case().assertRaises(CleanupRestorationContractError):
        assess_cleanup_completion(
            plan,
            observation,
            reviewer_ref=observation.reviewer_ref,
            reviewed_at="2026-09-20T10:11:00Z",
        )


def test_expired_plan_is_incomplete() -> None:
    plan = _plan(expires_at="2026-09-20T10:13:00Z")
    observation = _observation(plan)
    result = assess_cleanup_completion(
        plan,
        observation,
        reviewer_ref=observation.reviewer_ref,
        reviewed_at="2026-09-20T10:15:00Z",
    )
    _case().assertEqual(result.status, CompletionStatus.INCOMPLETE)
    _case().assertIn("plan_expired", result.reason_codes)


def test_missing_or_reordered_observations_are_incomplete() -> None:
    first_obligation = _obligation()
    second_obligation = _obligation(
        "targetstateref:remove-agent", "artifactref:temporary-agent", TargetState.ABSENT
    )
    second_step = CleanupStep(
        step_ref="stepref:remove-agent",
        sequence=2,
        kind=StepKind.REMOVE,
        target_state_ref=second_obligation.target_state_ref,
        action_ref="actionref:remove-agent",
        action_sha256=HASH_D,
        timeout_seconds=120,
        failure_behavior=FailureBehavior.HALT,
        evidence_requirements=(EvidenceRequirement("evidenceref:absence-proof", HASH_F, "1.0.0"),),
        compensating_actions=(),
    )
    plan = _plan(obligations=(first_obligation, second_obligation), steps=(_step(), second_step))
    result = _assess(plan, _observation(plan, steps=(_step_observation(),)))
    _case().assertEqual(result.status, CompletionStatus.INCOMPLETE)
    _case().assertIn("observation_set_incomplete", result.reason_codes)


def test_boundary_validation_rejects_bad_versions_times_and_limits() -> None:
    with _case().assertRaises(CleanupRestorationContractError):
        _plan(contract_version="latest")
    with _case().assertRaises(CleanupRestorationContractError):
        _plan(expires_at="2026-09-20T09:59:59Z")
    with _case().assertRaises(CleanupRestorationContractError):
        _step(sequence=0)
    with _case().assertRaises(CleanupRestorationContractError):
        CleanupStep(
            step_ref="stepref:restore-config",
            sequence=1,
            kind=StepKind.RESTORE,
            target_state_ref="targetstateref:restore-service",
            action_ref="actionref:restore-config",
            action_sha256=HASH_C,
            timeout_seconds=86_401,
            failure_behavior=FailureBehavior.ROLLBACK,
            evidence_requirements=(_requirement(),),
            compensating_actions=(_compensation(),),
        )


def test_schema_accepts_records_and_rejects_unknown_fields() -> None:
    if Draft202012Validator is None:
        return
    schema_path = Path("registry/schemas/cleanup-restoration-contract-v1.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    plan = _plan()
    observation = _observation(plan)
    assessment = _assess(plan, observation)
    for record in (plan.to_dict(), observation.to_dict(), assessment.to_dict()):
        validator.validate(record)
    invalid = copy.deepcopy(plan.to_dict())
    invalid["unknown"] = True
    with _case().assertRaises(ValidationError):
        validator.validate(invalid)


def test_source_and_artifacts_have_no_markers_or_unicode_dashes() -> None:
    paths = (
        Path("src/sunderkey/cleanup_restoration_contracts.py"),
        Path("tests/agents/test_cleanup_restoration_contracts_phase165.py"),
        Path("registry/schemas/cleanup-restoration-contract-v1.schema.json"),
        Path("docs/cleanup-restoration-contracts.md"),
    )
    markers = (
        "generated" + " by",
        "written" + " by ai",
        "as" + " an ai",
        "chat" + "gpt",
        "co" + "dex",
        "clau" + "de",
        "gem" + "ini",
        "co-authored" + "-by",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        _case().assertNotIn("\u2013", text, str(path))
        _case().assertNotIn("\u2014", text, str(path))
        lowered = text.lower()
        for marker in markers:
            _case().assertNotIn(marker, lowered, str(path))


def test_contracts_do_not_expose_execution_methods() -> None:
    forbidden = {"execute", "run", "delete", "restore", "cleanup", "connect", "persist"}
    for record_type in (
        CleanupRestorationPlan,
        CleanupObservation,
        CleanupCompletionAssessment,
    ):
        _case().assertTrue(forbidden.isdisjoint(set(record_type.__dict__)))
    _case().assertEqual(set(NO_EFFECTS.values()), {"none"})
