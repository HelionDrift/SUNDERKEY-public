"""Phase 167 specialist adapter contract coverage."""

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

from sunderkey.specialist_adapter_contracts import (
    BOUNDARY_EFFECTS,
    ActionClass,
    ActionTier,
    AdapterDisposition,
    AdapterObservation,
    BudgetEnvelope,
    ReceiptStatus,
    SpecialistActionRequest,
    SpecialistAdapterContractError,
    SpecialistExecutionContext,
    SpecialistFamily,
    dispatch_specialist_action,
    parse_contract,
    recommended_capability_declarations,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "specialist-adapter-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "specialist_adapter_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "specialist-adapter-contracts.md",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def context(*, target: str = "primary", credential: bool = False, change: bool = False):
    return SpecialistExecutionContext(
        tenant_ref="tenantref:acme",
        mission_ref="missionref:assessment-77",
        scope_ref="scoperef:signed-v4",
        scope_sha256=digest("1"),
        target_ref=f"targetref:{target}",
        target_sha256=digest("2"),
        route_ref="routeref:approved-egress",
        route_sha256=digest("3"),
        worker_ref="workerref:specialist-one",
        session_ref="sessionref:run-44",
        fence_ref="fenceref:mission-77",
        fence_epoch=9,
        fencing_token_sha256=digest("4"),
        action_admission_ref="admissionref:atomic-55",
        action_admission_sha256=digest("5"),
        approval_ref="approvalref:operator-or-policy",
        approval_sha256=digest("6"),
        credential_lease_ref="leaseref:target-read" if credential else "leaseref:none",
        credential_lease_sha256=digest("7"),
        evidence_plan_ref="evidenceref:plan-22",
        evidence_plan_sha256=digest("8"),
        cleanup_plan_ref="cleanupref:required" if change else "cleanupref:none",
        cleanup_plan_sha256=digest("9"),
        restoration_plan_ref="restorationref:required" if change else "restorationref:none",
        restoration_plan_sha256=digest("a"),
        budget=BudgetEnvelope(
            budget_ref="budgetref:bounded-1",
            maximum_requests=10,
            maximum_bytes=100_000,
            maximum_changes=2 if change else 0,
            maximum_duration_seconds=120,
        ),
    )


def request(
    action_class: ActionClass = ActionClass.PASSIVE,
    *,
    selected_context: SpecialistExecutionContext | None = None,
) -> SpecialistActionRequest:
    declaration = recommended_capability_declarations()[0]
    needs_credential = action_class is not ActionClass.PASSIVE
    needs_change = action_class is ActionClass.CONTROLLED_CHANGE
    selected_context = selected_context or context(
        credential=needs_credential,
        change=needs_change,
    )
    return SpecialistActionRequest(
        declaration_id=declaration.declaration_id,
        declaration_sha256=declaration.declaration_sha256,
        family=declaration.family,
        capability_ref=declaration.capability_ref,
        action_class=action_class,
        action_tier=ActionTier(action_class_index(action_class)),
        context=selected_context,
        intent_sha256=digest("b"),
        estimated_requests=2,
        estimated_bytes=2_048,
        estimated_changes=1 if needs_change else 0,
        estimated_duration_seconds=30,
        idempotency_sha256=digest("c"),
        issued_at="2026-09-20T10:00:00Z",
        expires_at="2026-09-20T10:10:00Z",
    )


def action_class_index(action_class: ActionClass) -> int:
    return tuple(ActionClass).index(action_class)


def observation(
    selected_request: SpecialistActionRequest,
    *,
    changes: int = 0,
    cleanup: bool = False,
    restoration: bool = False,
    disposition: AdapterDisposition = AdapterDisposition.COMPLETED,
) -> AdapterObservation:
    return AdapterObservation(
        request_id=selected_request.request_id,
        request_sha256=selected_request.request_sha256,
        context_sha256=selected_request.context.context_sha256,
        disposition=disposition,
        evidence_sha256=digest("d"),
        actual_requests=2,
        actual_bytes=1_024,
        actual_changes=changes,
        actual_duration_seconds=20,
        cleanup_complete=cleanup,
        restoration_complete=restoration,
        cleanup_evidence_sha256=digest("e") if cleanup else None,
        restoration_evidence_sha256=digest("f") if restoration else None,
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


class SpecialistAdapterContractTests(unittest.TestCase):
    def test_six_family_declarations_are_deterministic_and_round_trip(self):
        declarations = recommended_capability_declarations()
        self.assertEqual({item.family for item in declarations}, set(SpecialistFamily))
        self.assertEqual(len(declarations), 6)
        for item in declarations:
            self.assertEqual(parse_contract(item.to_dict()), item)
            self.assertEqual(item.maximum_tier, ActionTier.R3)
            self.assertEqual(item.supported_action_classes, tuple(ActionClass))
            self.assertEqual(item.to_dict()["boundary_effects"], dict(BOUNDARY_EFFECTS))

    def test_all_action_classes_dispatch_through_injected_adapter_once(self):
        declaration = recommended_capability_declarations()[0]
        for action_class in ActionClass:
            with self.subTest(action_class=action_class):
                selected_request = request(action_class)
                changing = action_class is ActionClass.CONTROLLED_CHANGE
                adapter = RecordingAdapter(
                    observation(
                        selected_request,
                        changes=1 if changing else 0,
                        cleanup=changing,
                        restoration=changing,
                    )
                )
                receipt = dispatch_specialist_action(
                    selected_request,
                    declaration,
                    selected_request.context,
                    adapter,
                    evaluated_at=datetime(2026, 9, 20, 10, 0, 30, tzinfo=UTC),
                )
                self.assertEqual(receipt.status, ReceiptStatus.COMPLETED)
                self.assertEqual(adapter.calls, [selected_request])
                self.assertEqual(parse_contract(receipt.to_dict()), receipt)

    def test_request_and_receipt_are_content_addressed_and_immutable(self):
        selected_request = request()
        self.assertEqual(selected_request, parse_contract(selected_request.to_dict()))
        self.assertEqual(selected_request.request_id, request().request_id)
        with self.assertRaises(FrozenInstanceError):
            selected_request.family = SpecialistFamily.HOST

    def test_tamper_and_unknown_fields_fail_closed(self):
        raw = request().to_dict()
        for mutation in ("target", "admission", "budget", "identity", "effects", "extra"):
            candidate = copy.deepcopy(raw)
            if mutation == "target":
                candidate["context"]["target_ref"] = "targetref:foreign"
            elif mutation == "admission":
                candidate["context"]["action_admission_sha256"] = digest("0")
            elif mutation == "budget":
                candidate["context"]["budget"]["maximum_requests"] = 99
            elif mutation == "identity":
                candidate["request_sha256"] = digest("0")
            elif mutation == "effects":
                candidate["boundary_effects"]["builtin_network"] = "enabled"
            else:
                candidate["unexpected"] = True
            with self.subTest(mutation=mutation), self.assertRaises(SpecialistAdapterContractError):
                parse_contract(candidate)

    def test_stale_replay_and_cross_context_fail_before_adapter(self):
        selected_request = request()
        declaration = recommended_capability_declarations()[0]
        scenarios = (
            {
                "expected_context": selected_request.context,
                "evaluated_at": datetime(2026, 9, 20, 10, 11, tzinfo=UTC),
            },
            {
                "expected_context": selected_request.context,
                "evaluated_at": datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                "seen_request_ids": (selected_request.request_id,),
            },
            {
                "expected_context": selected_request.context,
                "evaluated_at": datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                "seen_idempotency_sha256": (selected_request.idempotency_sha256,),
            },
            {
                "expected_context": context(target="foreign"),
                "evaluated_at": datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            },
        )
        for values in scenarios:
            adapter = RecordingAdapter(observation(selected_request))
            with self.assertRaises(SpecialistAdapterContractError):
                dispatch_specialist_action(
                    selected_request,
                    declaration,
                    adapter=adapter,
                    **values,
                )
            self.assertEqual(adapter.calls, [])

    def test_wrong_declaration_and_observation_binding_fail_closed(self):
        selected_request = request()
        declarations = recommended_capability_declarations()
        adapter = RecordingAdapter(observation(selected_request))
        with self.assertRaises(SpecialistAdapterContractError):
            dispatch_specialist_action(
                selected_request,
                declarations[1],
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            )
        self.assertEqual(adapter.calls, [])

        wrong = replace(observation(selected_request), context_sha256=digest("0"))
        adapter = RecordingAdapter(wrong)
        with self.assertRaises(SpecialistAdapterContractError):
            dispatch_specialist_action(
                selected_request,
                declarations[0],
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            )
        self.assertEqual(len(adapter.calls), 1)

    def test_budget_failures_prevent_or_reject_execution(self):
        with self.assertRaises(SpecialistAdapterContractError):
            replace(request(), estimated_requests=11)

        selected_request = request()
        over_budget = replace(observation(selected_request), actual_requests=11)
        adapter = RecordingAdapter(over_budget)
        with self.assertRaises(SpecialistAdapterContractError):
            dispatch_specialist_action(
                selected_request,
                recommended_capability_declarations()[0],
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            )

    def test_incomplete_cleanup_never_produces_completed_receipt(self):
        selected_request = request(ActionClass.CONTROLLED_CHANGE)
        adapter = RecordingAdapter(observation(selected_request, changes=1))
        receipt = dispatch_specialist_action(
            selected_request,
            recommended_capability_declarations()[0],
            selected_request.context,
            adapter,
            evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
        )
        self.assertEqual(receipt.status, ReceiptStatus.HALTED_CLEANUP_REQUIRED)

    def test_tier_rules_reject_credential_and_change_escalation(self):
        with self.assertRaises(SpecialistAdapterContractError):
            request(ActionClass.PASSIVE, selected_context=context(credential=True))
        with self.assertRaises(SpecialistAdapterContractError):
            request(ActionClass.AUTHENTICATED_READ, selected_context=context())
        with self.assertRaises(SpecialistAdapterContractError):
            request(
                ActionClass.CONTROLLED_CHANGE,
                selected_context=context(credential=True, change=False),
            )
        with self.assertRaises(SpecialistAdapterContractError):
            replace(request(), action_tier=ActionTier.R3)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_all_wire_records(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        declaration = recommended_capability_declarations()[0]
        selected_request = request(ActionClass.CONTROLLED_CHANGE)
        receipt = dispatch_specialist_action(
            selected_request,
            declaration,
            selected_request.context,
            RecordingAdapter(
                observation(selected_request, changes=1, cleanup=True, restoration=True)
            ),
            evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
        )
        for record in (declaration.to_dict(), selected_request.to_dict(), receipt.to_dict()):
            errors = list(validator.iter_errors(record))
            self.assertEqual(errors, [], errors)

    def test_increment_has_no_forbidden_unicode(self):
        for path in FILES:
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", content, path)
            self.assertNotIn("\u2014", content, path)

    def test_public_package_exports_specialist_boundary(self):
        import sunderkey

        self.assertIs(sunderkey.SpecialistNetworkHostActionRequest, SpecialistActionRequest)
        self.assertIs(
            sunderkey.dispatch_network_host_specialist_action,
            dispatch_specialist_action,
        )
        self.assertIs(
            sunderkey.parse_network_host_specialist_contract,
            parse_contract,
        )
        self.assertIs(
            sunderkey.network_host_specialist_capabilities,
            recommended_capability_declarations,
        )


if __name__ == "__main__":
    unittest.main()
