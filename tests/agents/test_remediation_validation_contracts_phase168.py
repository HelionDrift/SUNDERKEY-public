from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    Draft202012Validator = None
    ValidationError = None

from sunderkey.remediation_validation_contracts import (
    NO_EFFECTS,
    ClosureDecision,
    ClosureDisposition,
    CompensatingControl,
    ContextBinding,
    GateDisposition,
    GateObservation,
    OwnershipHandoff,
    RegressionGate,
    RemediationItem,
    RemediationPlan,
    RemediationValidationError,
    RetestObservation,
    RetestPlan,
    RiskException,
    build_remediation_plan,
    build_retest_plan,
    decide_closure,
    ensure_idempotent,
    parse_contract,
)

HASHES = tuple("sha256:" + f"{value:064x}" for value in range(1, 17))


def _case() -> unittest.TestCase:
    return unittest.TestCase()


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


def _context(**changes: object) -> ContextBinding:
    values: dict[str, object] = {
        "tenant_ref": "tenantref:acme",
        "tenant_sha256": HASHES[0],
        "assessment_ref": "assessmentref:assessment-42",
        "assessment_sha256": HASHES[1],
        "scope_sha256": HASHES[2],
        "world_sha256": HASHES[3],
        "findings_sha256": HASHES[4],
        "attack_paths_sha256": HASHES[5],
        "evidence_bundle_sha256": HASHES[6],
        "observed_at": "2026-09-20T10:00:00Z",
        "expires_at": "2026-09-21T10:00:00Z",
    }
    values.update(changes)
    return ContextBinding(**values)


def _item(
    suffix: str,
    *,
    dependency_refs: tuple[str, ...] = (),
    inherent: int = 100,
    residual: int = 25,
    effort: int = 5,
    owner: str | None = None,
) -> RemediationItem:
    index = int(suffix)
    return RemediationItem(
        item_ref=f"itemref:item-{suffix}",
        action_sha256=HASHES[index],
        finding_refs=(f"findingref:finding-{suffix}",),
        attack_path_refs=(f"pathref:path-{suffix}",),
        evidence_digests=(HASHES[index + 2],),
        dependency_refs=dependency_refs,
        owner_ref=owner or f"principalref:owner-{suffix}",
        inherent_risk_points=inherent,
        residual_risk_points=residual,
        effort_points=effort,
        rollback_ref=f"rollbackref:item-{suffix}",
        rollback_sha256=HASHES[index + 4],
        cleanup_ref=f"cleanupref:item-{suffix}",
        cleanup_sha256=HASHES[index + 6],
    )


def _handoff(item: RemediationItem) -> OwnershipHandoff:
    return OwnershipHandoff(
        handoff_ref=f"handoffref:{item.item_ref.split(':', 1)[1]}",
        item_refs=(item.item_ref,),
        from_owner_ref="principalref:triage",
        to_owner_ref=item.owner_ref,
        acceptance_evidence_sha256=HASHES[12],
        accepted_at="2026-09-20T10:01:00Z",
    )


def _control(items: tuple[RemediationItem, ...]) -> CompensatingControl:
    return CompensatingControl(
        control_ref="controlref:temporary-policy",
        control_sha256=HASHES[13],
        item_refs=tuple(item.item_ref for item in items),
        evidence_digests=(HASHES[14],),
        expected_risk_reduction_points=20,
        owner_ref="principalref:control-owner",
        expires_at="2026-09-21T09:00:00Z",
    )


def _plan(
    context: ContextBinding | None = None,
    *,
    items: tuple[RemediationItem, ...] | None = None,
    created_at: str = "2026-09-20T10:05:00Z",
    expires_at: str = "2026-09-21T09:30:00Z",
) -> RemediationPlan:
    context = context or _context()
    if items is None:
        first = _item("1", inherent=100, residual=20, effort=10)
        second = _item(
            "2",
            dependency_refs=(first.item_ref,),
            inherent=80,
            residual=10,
            effort=5,
        )
        items = (second, first)
    return build_remediation_plan(
        context,
        items,
        (_control(items),),
        tuple(_handoff(item) for item in items),
        idempotency_key="idemref:remediation-42",
        proposed_by="principalref:remediation-proposer",
        created_at=created_at,
        expires_at=expires_at,
    )


def _gates(plan: RemediationPlan) -> tuple[RegressionGate, ...]:
    return tuple(
        RegressionGate(
            gate_ref=f"gateref:{item.item_ref.split(':', 1)[1]}",
            gate_sha256=item.action_sha256,
            item_refs=(item.item_ref,),
            required_evidence_digests=item.evidence_digests,
            failure_code="finding_regressed",
        )
        for item in plan.items
    )


def _retest(plan: RemediationPlan) -> RetestPlan:
    return build_retest_plan(
        plan,
        _gates(plan),
        idempotency_key="idemref:retest-42",
        proposed_by="principalref:retest-proposer",
        created_at="2026-09-20T11:00:00Z",
        expires_at="2026-09-21T09:00:00Z",
    )


def _observation(
    plan: RemediationPlan,
    retest: RetestPlan,
    *,
    disposition: GateDisposition = GateDisposition.PASS,
    include_evidence: bool = True,
    include_restoration: bool = True,
    observed_by: str = "principalref:retest-observer",
) -> RetestObservation:
    gates = tuple(
        GateObservation(
            gate_ref=gate.gate_ref,
            disposition=disposition,
            evidence_digests=gate.required_evidence_digests if include_evidence else (),
            reason_code="observed_result",
        )
        for gate in retest.gates
    )
    return RetestObservation(
        context_id=plan.context_id,
        context_sha256=plan.context_sha256,
        remediation_plan_id=plan.plan_id,
        remediation_plan_sha256=plan.plan_sha256,
        retest_plan_id=retest.retest_plan_id,
        retest_plan_sha256=retest.retest_plan_sha256,
        observed_by=observed_by,
        observed_at="2026-09-20T12:00:00Z",
        gate_observations=gates,
        rollback_evidence_digests=(retest.rollback_evidence_digests if include_restoration else ()),
        cleanup_evidence_digests=(retest.cleanup_evidence_digests if include_restoration else ()),
    )


def _exception(plan: RemediationPlan, **changes: object) -> RiskException:
    values: dict[str, object] = {
        "context_id": plan.context_id,
        "context_sha256": plan.context_sha256,
        "remediation_plan_id": plan.plan_id,
        "remediation_plan_sha256": plan.plan_sha256,
        "exception_ref": "exceptionref:temporary-acceptance",
        "item_refs": tuple(item.item_ref for item in plan.items),
        "control_refs": tuple(control.control_ref for control in plan.compensating_controls),
        "requested_by": "principalref:risk-owner",
        "approved_by": "principalref:independent-risk-approver",
        "approved_at": "2026-09-20T11:30:00Z",
        "expires_at": "2026-09-21T08:00:00Z",
        "rationale_code": "temporary_compensation",
    }
    values.update(changes)
    return RiskException(**values)


def _decide(
    plan: RemediationPlan,
    retest: RetestPlan,
    observation: RetestObservation,
    *,
    exception: RiskException | None = None,
    reviewer_ref: str = "principalref:closure-reviewer",
    reviewed_at: str = "2026-09-20T12:30:00Z",
) -> ClosureDecision:
    return decide_closure(
        plan,
        retest,
        observation,
        reviewer_ref=reviewer_ref,
        reviewed_at=reviewed_at,
        idempotency_key="idemref:closure-42",
        exception=exception,
    )


def test_planner_orders_dependencies_and_prioritizes_ready_items_deterministically() -> None:
    first = _item("1", inherent=50, residual=10, effort=10)
    high = _item("2", inherent=100, residual=20, effort=4)
    dependent = _item("3", dependency_refs=(first.item_ref, high.item_ref))
    plan = _plan(items=(dependent, first, high))
    case = _case()
    case.assertEqual(plan.batches[0].item_refs, (high.item_ref, first.item_ref))
    case.assertEqual(plan.batches[1].item_refs, (dependent.item_ref,))
    case.assertEqual(plan.batches[1].dependency_refs, (first.item_ref, high.item_ref))
    case.assertEqual(_plan(items=(high, first, dependent)).plan_sha256, plan.plan_sha256)


def test_dependency_cycles_and_missing_accepted_handoffs_fail_closed() -> None:
    first = _item("1", dependency_refs=("itemref:item-2",))
    second = _item("2", dependency_refs=(first.item_ref,))
    with _case().assertRaisesRegex(RemediationValidationError, "cycle"):
        _plan(items=(first, second))
    context = _context()
    standalone = _item("1")
    with _case().assertRaisesRegex(RemediationValidationError, "every remediation item"):
        build_remediation_plan(
            context,
            (standalone,),
            (_control((standalone,)),),
            (),
            idempotency_key="idemref:no-handoff",
            proposed_by="principalref:proposer",
            created_at="2026-09-20T10:05:00Z",
            expires_at="2026-09-21T09:30:00Z",
        )


def test_stale_and_cross_context_plan_inputs_fail_closed() -> None:
    with _case().assertRaisesRegex(RemediationValidationError, "outlives"):
        _plan(expires_at="2026-09-22T00:00:00Z")
    with _case().assertRaisesRegex(RemediationValidationError, "predates"):
        _plan(created_at="2026-09-20T09:00:00Z")
    other = _context(tenant_ref="tenantref:other")
    _case().assertNotEqual(_plan(other).context_sha256, _plan().context_sha256)


def test_retest_gates_cover_all_items_and_bind_rollback_cleanup_requirements() -> None:
    plan = _plan()
    with _case().assertRaisesRegex(RemediationValidationError, "exactly all"):
        build_retest_plan(
            plan,
            _gates(plan)[:1],
            idempotency_key="idemref:partial-retest",
            proposed_by="principalref:retest-proposer",
            created_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-21T09:00:00Z",
        )
    retest = _retest(plan)
    _case().assertEqual(
        set(retest.rollback_evidence_digests),
        {item.rollback_sha256 for item in plan.items},
    )
    _case().assertEqual(
        set(retest.cleanup_evidence_digests),
        {item.cleanup_sha256 for item in plan.items},
    )


def test_complete_retest_yields_only_nonqualified_repository_closure() -> None:
    plan = _plan()
    retest = _retest(plan)
    decision = _decide(plan, retest, _observation(plan, retest))
    case = _case()
    case.assertEqual(decision.disposition, ClosureDisposition.CLOSED_NONQUALIFIED)
    case.assertIn("repository_only_nonqualified", decision.reason_codes)
    case.assertEqual(decision.to_dict()["effects"], dict(NO_EFFECTS))


def test_missing_gate_and_restoration_evidence_keeps_finding_open() -> None:
    plan = _plan()
    retest = _retest(plan)
    observation = _observation(
        plan,
        retest,
        disposition=GateDisposition.INCONCLUSIVE,
        include_evidence=False,
        include_restoration=False,
    )
    decision = _decide(plan, retest, observation)
    case = _case()
    case.assertEqual(decision.disposition, ClosureDisposition.OPEN)
    case.assertEqual(
        decision.reason_codes,
        (
            "regression_gate_not_passed",
            "required_evidence_missing",
            "rollback_cleanup_evidence_missing",
            "repository_only_nonqualified",
        ),
    )


def test_proposer_observer_and_reviewer_separation_is_enforced() -> None:
    plan = _plan()
    retest = _retest(plan)
    observation = _observation(plan, retest)
    for reviewer in (plan.proposed_by, retest.proposed_by, observation.observed_by):
        with _case().assertRaisesRegex(RemediationValidationError, "independent"):
            _decide(plan, retest, observation, reviewer_ref=reviewer)


def test_active_exception_requires_independent_approval_and_complete_live_controls() -> None:
    plan = _plan()
    retest = _retest(plan)
    observation = _observation(
        plan,
        retest,
        disposition=GateDisposition.FAIL,
        include_evidence=False,
        include_restoration=False,
    )
    exception = _exception(plan)
    decision = _decide(plan, retest, observation, exception=exception)
    _case().assertEqual(decision.disposition, ClosureDisposition.EXCEPTION_ACTIVE_NONQUALIFIED)
    with _case().assertRaisesRegex(RemediationValidationError, "independent"):
        _exception(plan, approved_by="principalref:risk-owner")
    with _case().assertRaisesRegex(RemediationValidationError, "90 days"):
        _exception(plan, expires_at="2027-01-01T00:00:00Z")
    partial_control = replace(plan.compensating_controls[0], item_refs=(plan.items[0].item_ref,))
    partial_plan = build_remediation_plan(
        _context(),
        plan.items,
        (partial_control,),
        tuple(_handoff(item) for item in plan.items),
        idempotency_key="idemref:partial-control-plan",
        proposed_by="principalref:remediation-proposer",
        created_at="2026-09-20T10:05:00Z",
        expires_at="2026-09-21T09:30:00Z",
    )
    partial_retest = _retest(partial_plan)
    partial_observation = _observation(
        partial_plan,
        partial_retest,
        disposition=GateDisposition.FAIL,
    )
    with _case().assertRaisesRegex(RemediationValidationError, "coverage"):
        _decide(
            partial_plan,
            partial_retest,
            partial_observation,
            exception=_exception(partial_plan),
        )


def test_expired_exception_and_stale_review_are_rejected() -> None:
    plan = _plan()
    retest = _retest(plan)
    observation = _observation(plan, retest, disposition=GateDisposition.FAIL)
    exception = _exception(plan, expires_at="2026-09-20T12:15:00Z")
    with _case().assertRaisesRegex(RemediationValidationError, "expired"):
        _decide(plan, retest, observation, exception=exception)
    with _case().assertRaisesRegex(RemediationValidationError, "stale"):
        _decide(plan, retest, observation, reviewed_at="2026-09-22T00:00:00Z")


def test_cross_context_and_rebound_records_are_rejected() -> None:
    plan = _plan()
    retest = _retest(plan)
    other = _plan(_context(tenant_ref="tenantref:other"))
    observation = RetestObservation(
        context_id=other.context_id,
        context_sha256=other.context_sha256,
        remediation_plan_id=plan.plan_id,
        remediation_plan_sha256=plan.plan_sha256,
        retest_plan_id=retest.retest_plan_id,
        retest_plan_sha256=retest.retest_plan_sha256,
        observed_by="principalref:retest-observer",
        observed_at="2026-09-20T12:00:00Z",
        gate_observations=tuple(
            GateObservation(
                gate.gate_ref,
                GateDisposition.PASS,
                gate.required_evidence_digests,
                "observed_result",
            )
            for gate in retest.gates
        ),
        rollback_evidence_digests=retest.rollback_evidence_digests,
        cleanup_evidence_digests=retest.cleanup_evidence_digests,
    )
    with _case().assertRaisesRegex(RemediationValidationError, "cross-context"):
        _decide(plan, retest, observation)


def test_content_addresses_round_trip_and_tampering_is_rejected() -> None:
    context = _context()
    plan = _plan(context)
    retest = _retest(plan)
    observation = _observation(plan, retest)
    exception = _exception(plan)
    decision = _decide(plan, retest, observation)
    for value in (context, plan, retest, observation, exception, decision):
        raw = json.loads(json.dumps(value.to_dict()))
        _case().assertEqual(parse_contract(raw), value)
        tampered = copy.deepcopy(raw)
        if "tenant_ref" in tampered:
            tampered["tenant_ref"] = "tenantref:tampered"
        else:
            tampered["effects"]["network"] = "allowed"
        with _case().assertRaises(RemediationValidationError):
            parse_contract(tampered)


def test_idempotency_accepts_exact_replay_and_rejects_key_rebinding() -> None:
    plan = _plan()
    replay = RemediationPlan.from_dict(plan.to_dict())
    ensure_idempotent(plan, replay)
    changed = _plan(items=(_item("1", inherent=101),))
    with _case().assertRaisesRegex(RemediationValidationError, "different content"):
        ensure_idempotent(plan, changed)
    with _case().assertRaisesRegex(RemediationValidationError, "same type"):
        ensure_idempotent(plan, _retest(plan))


def test_content_address_fields_cannot_be_substituted() -> None:
    plan = _plan()
    raw = plan.to_dict()
    raw["plan_sha256"] = HASHES[15]
    with _case().assertRaisesRegex(RemediationValidationError, "content address"):
        RemediationPlan.from_dict(raw)
    with _case().assertRaises(RemediationValidationError):
        replace(plan, plan_sha256=HASHES[15])


@unittest.skipIf(Draft202012Validator is None, "jsonschema is unavailable")
def test_json_schema_accepts_every_record_and_rejects_tampered_effects() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "registry"
        / "schemas"
        / "remediation-validation-contract-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    context = _context()
    plan = _plan(context)
    retest = _retest(plan)
    observation = _observation(plan, retest)
    values = (
        context,
        plan,
        retest,
        observation,
        _exception(plan),
        _decide(plan, retest, observation),
    )
    for value in values:
        validator.validate(value.to_dict())
    tampered = plan.to_dict()
    tampered["effects"]["ticketing"] = "create"
    with _case().assertRaises(ValidationError):
        validator.validate(tampered)


def test_module_exposes_no_live_ticketing_or_target_execution_capability() -> None:
    effects = dict(NO_EFFECTS)
    case = _case()
    case.assertEqual(effects["ticketing"], "none")
    case.assertEqual(effects["target_execution"], "none")
    case.assertEqual(effects["network"], "none")


def test_public_package_exports_remediation_boundary() -> None:
    import sunderkey

    case = _case()
    case.assertIs(sunderkey.RemediationPlan, RemediationPlan)
    case.assertIs(sunderkey.build_remediation_plan, build_remediation_plan)
    case.assertIs(sunderkey.build_remediation_retest_plan, build_retest_plan)
    case.assertIs(sunderkey.decide_remediation_closure, decide_closure)
    case.assertIs(sunderkey.parse_remediation_validation_contract, parse_contract)
