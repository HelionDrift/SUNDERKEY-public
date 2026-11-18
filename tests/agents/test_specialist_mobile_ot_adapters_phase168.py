"""Phase 168 mobile, desktop, wireless, IoT, and OT adapter tests."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.specialist_mobile_ot_adapters import (
    BOUNDARY_EFFECTS,
    ActionClass,
    ActionTier,
    AdapterDisposition,
    AdapterObservation,
    BudgetBinding,
    EnvironmentClass,
    ExecutionContext,
    ReceiptStatus,
    SpecialistActionRequest,
    SpecialistBoundaryError,
    SpecialistDomain,
    SystemCriticality,
    dispatch_specialist_action,
    parse_contract,
    recommended_capability_declarations,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "specialist-mobile-ot-adapter-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "specialist_mobile_ot_adapters.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "specialist-mobile-ot-adapters.md",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def context(
    *,
    environment: EnvironmentClass = EnvironmentClass.LAB,
    criticality: SystemCriticality = SystemCriticality.STANDARD,
    target: str = "device-one",
    changing: bool = False,
) -> ExecutionContext:
    return ExecutionContext(
        tenant_ref="tenantref:acme",
        mission_ref="missionref:assessment-88",
        environment=environment,
        criticality=criticality,
        scope_ref="scoperef:signed-v8",
        scope_sha256=digest("1"),
        target_ref=f"targetref:{target}",
        target_sha256=digest("2"),
        protocol_ref="protocolref:declared-profile",
        protocol_sha256=digest("3"),
        device_ref="deviceref:asset-17",
        device_sha256=digest("4"),
        session_ref="sessionref:run-91",
        session_sha256=digest("5"),
        evidence_plan_ref="evidenceref:plan-22",
        evidence_plan_sha256=digest("6"),
        restoration_plan_ref=(
            "restorationref:approved-plan" if changing else "restorationref:none"
        ),
        restoration_plan_sha256=digest("7"),
        approval_ref="approvalref:operator-44",
        approval_sha256=digest("8"),
        approving_actor_ref="actorref:operator-one",
        independent_approval_ref=(
            "approvalref:assurance-45"
            if criticality is not SystemCriticality.STANDARD
            else "approvalref:none"
        ),
        independent_approval_sha256=digest("9"),
        independent_actor_ref=(
            "actorref:assurance-two"
            if criticality is not SystemCriticality.STANDARD
            else "actorref:none"
        ),
        budget=BudgetBinding(
            budget_ref="budgetref:bounded-4",
            maximum_operations=10,
            maximum_bytes=100_000,
            maximum_changes=2 if changing else 0,
            maximum_duration_seconds=120,
        ),
    )


def action_tier(action_class: ActionClass) -> ActionTier:
    return {
        ActionClass.PASSIVE: ActionTier.R0,
        ActionClass.AUTHENTICATED_READ: ActionTier.R1,
        ActionClass.VALIDATION: ActionTier.R2,
        ActionClass.CONTROLLED_CHANGE: ActionTier.R3,
        ActionClass.DISRUPTIVE: ActionTier.R3,
    }[action_class]


def request(
    domain: SpecialistDomain = SpecialistDomain.MOBILE,
    action_class: ActionClass = ActionClass.PASSIVE,
    *,
    selected_context: ExecutionContext | None = None,
) -> SpecialistActionRequest:
    declaration = next(
        item for item in recommended_capability_declarations() if item.domain is domain
    )
    changing = action_class in (ActionClass.CONTROLLED_CHANGE, ActionClass.DISRUPTIVE)
    selected_context = selected_context or context(changing=changing)
    return SpecialistActionRequest(
        declaration_id=declaration.declaration_id,
        declaration_sha256=declaration.declaration_sha256,
        domain=domain,
        capability_ref=declaration.capability_ref,
        action_class=action_class,
        action_tier=action_tier(action_class),
        context=selected_context,
        intent_sha256=digest("a"),
        estimated_operations=2,
        estimated_bytes=2_048,
        estimated_changes=1 if changing else 0,
        estimated_duration_seconds=30,
        idempotency_sha256=digest("b"),
        issued_at="2026-09-20T10:00:00Z",
        expires_at="2026-09-20T10:10:00Z",
    )


def observation(
    selected_request: SpecialistActionRequest,
    *,
    changes: int = 0,
    restored: bool = False,
    disposition: AdapterDisposition = AdapterDisposition.COMPLETED,
) -> AdapterObservation:
    selected_context = selected_request.context
    return AdapterObservation(
        request_id=selected_request.request_id,
        request_sha256=selected_request.request_sha256,
        context_sha256=selected_context.context_sha256,
        target_sha256=selected_context.target_sha256,
        protocol_sha256=selected_context.protocol_sha256,
        device_sha256=selected_context.device_sha256,
        session_sha256=selected_context.session_sha256,
        disposition=disposition,
        evidence_sha256=digest("c"),
        actual_operations=2,
        actual_bytes=1_024,
        actual_changes=changes,
        actual_duration_seconds=20,
        restoration_complete=restored,
        restoration_evidence_sha256=digest("d") if restored else None,
        started_at="2026-09-20T10:01:00Z",
        completed_at="2026-09-20T10:02:00Z",
    )


class RecordingAdapter:
    def __init__(self, result: AdapterObservation):
        self.result = result
        self.calls: list[SpecialistActionRequest] = []

    def execute(self, selected_request: SpecialistActionRequest) -> AdapterObservation:
        self.calls.append(selected_request)
        return self.result


class SpecialistMobileOtAdapterTests(unittest.TestCase):
    def test_five_domain_declarations_are_deterministic_and_round_trip(self):
        declarations = recommended_capability_declarations()
        self.assertEqual({item.domain for item in declarations}, set(SpecialistDomain))
        self.assertEqual(len(declarations), 5)
        for declaration in declarations:
            self.assertEqual(parse_contract(declaration.to_dict()), declaration)
            self.assertEqual(declaration.maximum_tier, ActionTier.R3)
            self.assertEqual(declaration.to_dict()["boundary_effects"], dict(BOUNDARY_EFFECTS))

    def test_r0_through_r3_dispatch_once_through_injected_adapter(self):
        for action_class in ActionClass:
            with self.subTest(action_class=action_class):
                selected_request = request(action_class=action_class)
                changing = action_class in (
                    ActionClass.CONTROLLED_CHANGE,
                    ActionClass.DISRUPTIVE,
                )
                adapter = RecordingAdapter(
                    observation(
                        selected_request,
                        changes=1 if changing else 0,
                        restored=changing,
                    )
                )
                declaration = next(
                    item
                    for item in recommended_capability_declarations()
                    if item.domain is selected_request.domain
                )
                receipt = dispatch_specialist_action(
                    selected_request,
                    declaration,
                    selected_request.context,
                    adapter,
                    evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                )
                self.assertEqual(receipt.status, ReceiptStatus.COMPLETED)
                self.assertEqual(adapter.calls, [selected_request])
                self.assertEqual(parse_contract(receipt.to_dict()), receipt)

    def test_wrong_tier_fails_before_adapter(self):
        selected_request = replace(
            request(),
            action_tier=ActionTier.R1,
            request_id="",
            request_sha256="",
        )
        declaration = recommended_capability_declarations()[0]
        adapter = RecordingAdapter(observation(selected_request))
        with self.assertRaisesRegex(SpecialistBoundaryError, "action tier"):
            dispatch_specialist_action(
                selected_request,
                declaration,
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            )
        self.assertEqual(adapter.calls, [])

    def test_disruptive_actions_require_simulation_or_lab(self):
        for selected_domain in (SpecialistDomain.WIRELESS, SpecialistDomain.OT_ICS):
            for environment in (EnvironmentClass.STAGING, EnvironmentClass.PRODUCTION):
                with self.subTest(domain=selected_domain, environment=environment):
                    selected_context = context(environment=environment, changing=True)
                    selected_request = request(
                        selected_domain,
                        ActionClass.DISRUPTIVE,
                        selected_context=selected_context,
                    )
                    declaration = next(
                        item
                        for item in recommended_capability_declarations()
                        if item.domain is selected_domain
                    )
                    adapter = RecordingAdapter(
                        observation(selected_request, changes=1, restored=True)
                    )
                    with self.assertRaisesRegex(SpecialistBoundaryError, "simulation or lab"):
                        dispatch_specialist_action(
                            selected_request,
                            declaration,
                            selected_context,
                            adapter,
                            evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                        )
                    self.assertEqual(adapter.calls, [])

    def test_critical_systems_require_distinct_independent_approval(self):
        base = context(criticality=SystemCriticality.CRITICAL_INFRASTRUCTURE)
        with self.assertRaisesRegex(SpecialistBoundaryError, "independent approvers"):
            replace(base, independent_actor_ref=base.approving_actor_ref, context_sha256="")
        with self.assertRaisesRegex(SpecialistBoundaryError, "independent approval"):
            replace(base, independent_approval_ref="approvalref:none", context_sha256="")

    def test_scope_target_protocol_device_session_evidence_budget_and_restoration_bindings(self):
        selected_request = request(action_class=ActionClass.CONTROLLED_CHANGE)
        declaration = recommended_capability_declarations()[0]
        field_values = {
            "scope_sha256": digest("0"),
            "target_sha256": digest("0"),
            "protocol_sha256": digest("0"),
            "device_sha256": digest("0"),
            "session_sha256": digest("0"),
            "evidence_plan_sha256": digest("0"),
            "restoration_plan_sha256": digest("0"),
            "budget": replace(
                selected_request.context.budget,
                maximum_operations=9,
                budget_sha256="",
            ),
        }
        for field, value in field_values.items():
            with self.subTest(field=field):
                foreign = replace(
                    selected_request.context,
                    **{field: value, "context_sha256": ""},
                )
                adapter = RecordingAdapter(observation(selected_request, changes=1, restored=True))
                with self.assertRaisesRegex(SpecialistBoundaryError, "context"):
                    dispatch_specialist_action(
                        selected_request,
                        declaration,
                        foreign,
                        adapter,
                        evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                    )
                self.assertEqual(adapter.calls, [])

    def test_stale_replay_and_idempotency_replay_fail_before_adapter(self):
        selected_request = request()
        declaration = recommended_capability_declarations()[0]
        cases = (
            {
                "evaluated_at": datetime(2026, 9, 20, 10, 11, tzinfo=UTC),
            },
            {
                "evaluated_at": datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                "seen_request_ids": (selected_request.request_id,),
            },
            {
                "evaluated_at": datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                "seen_idempotency_sha256": (selected_request.idempotency_sha256,),
            },
        )
        for values in cases:
            adapter = RecordingAdapter(observation(selected_request))
            with self.assertRaises(SpecialistBoundaryError):
                dispatch_specialist_action(
                    selected_request,
                    declaration,
                    selected_request.context,
                    adapter,
                    **values,
                )
            self.assertEqual(adapter.calls, [])

    def test_naive_evaluation_time_fails_before_adapter(self):
        selected_request = request()
        declaration = recommended_capability_declarations()[0]
        adapter = RecordingAdapter(observation(selected_request))
        with self.assertRaisesRegex(SpecialistBoundaryError, "timezone aware"):
            dispatch_specialist_action(
                selected_request,
                declaration,
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1),
            )
        self.assertEqual(adapter.calls, [])

    def test_tamper_unknown_fields_and_secret_material_fail_closed(self):
        raw = request().to_dict()
        mutations = []
        changed_target = copy.deepcopy(raw)
        changed_target["context"]["target_ref"] = "targetref:foreign"
        mutations.append(changed_target)
        changed_effect = copy.deepcopy(raw)
        changed_effect["boundary_effects"]["builtin_network"] = "enabled"
        mutations.append(changed_effect)
        changed_identity = copy.deepcopy(raw)
        changed_identity["request_sha256"] = digest("0")
        mutations.append(changed_identity)
        extra = copy.deepcopy(raw)
        extra["unexpected"] = True
        mutations.append(extra)
        for candidate in mutations:
            with self.assertRaises(SpecialistBoundaryError):
                parse_contract(candidate)
        with self.assertRaises(SpecialistBoundaryError):
            parse_contract({**raw, "intent_sha256": "password=not-allowed"})

    def test_observation_mismatch_and_budget_overrun_fail_closed(self):
        selected_request = request()
        declaration = recommended_capability_declarations()[0]
        mismatches = (
            replace(observation(selected_request), device_sha256=digest("0")),
            replace(observation(selected_request), protocol_sha256=digest("0")),
            replace(observation(selected_request), actual_operations=11),
        )
        for result in mismatches:
            adapter = RecordingAdapter(result)
            with self.assertRaises(SpecialistBoundaryError):
                dispatch_specialist_action(
                    selected_request,
                    declaration,
                    selected_request.context,
                    adapter,
                    evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                )

    def test_unrestored_change_is_halted_not_completed(self):
        selected_request = request(action_class=ActionClass.CONTROLLED_CHANGE)
        declaration = recommended_capability_declarations()[0]
        receipt = dispatch_specialist_action(
            selected_request,
            declaration,
            selected_request.context,
            RecordingAdapter(observation(selected_request, changes=1)),
            evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
        )
        self.assertEqual(receipt.status, ReceiptStatus.HALTED_RESTORATION_REQUIRED)

    def test_records_are_content_addressed_and_immutable(self):
        selected_request = request()
        self.assertEqual(selected_request, parse_contract(selected_request.to_dict()))
        self.assertEqual(selected_request.request_id, request().request_id)
        with self.assertRaises(FrozenInstanceError):
            selected_request.domain = SpecialistDomain.OT_ICS

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_all_contract_records(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        declarations = recommended_capability_declarations()
        selected_request = request(action_class=ActionClass.CONTROLLED_CHANGE)
        receipt = dispatch_specialist_action(
            selected_request,
            declarations[0],
            selected_request.context,
            RecordingAdapter(observation(selected_request, changes=1, restored=True)),
            evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
        )
        for record in (*declarations, selected_request, receipt):
            self.assertEqual(list(validator.iter_errors(record.to_dict())), [])

    def test_files_have_no_unicode_dashes(self):
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)

    def test_public_package_exports_specialist_boundary(self):
        import sunderkey

        self.assertIs(sunderkey.SpecialistMobileOtActionRequest, SpecialistActionRequest)
        self.assertIs(
            sunderkey.dispatch_mobile_ot_specialist_action,
            dispatch_specialist_action,
        )
        self.assertIs(
            sunderkey.parse_mobile_ot_specialist_contract,
            parse_contract,
        )
        self.assertIs(
            sunderkey.mobile_ot_specialist_capabilities,
            recommended_capability_declarations,
        )


if __name__ == "__main__":
    unittest.main()
