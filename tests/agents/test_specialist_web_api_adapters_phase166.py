"""Phase 166 web, API, and authentication specialist adapter coverage."""

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

from sunderkey.specialist_web_api_adapters import (
    REPOSITORY_ONLY_EFFECTS,
    AdapterIdentity,
    AdapterObservation,
    ApprovalBinding,
    PrincipalSessionBinding,
    ResultState,
    SpecialistActionRequest,
    SpecialistAdapterError,
    SpecialistBudget,
    SpecialistContext,
    SpecialistExecutionAdapter,
    SpecialistFamily,
    SpecialistOperation,
    SpecialistReplayGuard,
    canonical_json,
    execute_specialist_action,
    parse_specialist_contract,
    specialist_capability_declarations,
)
from sunderkey.types import ActionTier

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "specialist-web-api-adapter-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "specialist_web_api_adapters.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "specialist-web-api-adapters.md",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def context(*, target: str = "app-one") -> SpecialistContext:
    return SpecialistContext(
        tenant_ref="tenantref:acme",
        mission_ref="missionref:assessment-44",
        scope_ref="scoperef:signed-v3",
        target_ref=f"targetref:{target}",
        worker_ref="workerref:specialist-one",
        action_ref="actionref:admission-77",
        action_admission_sha256=digest("a"),
    )


def session(
    selected_context: SpecialistContext,
    principal: str,
    *,
    session_name: str | None = None,
) -> PrincipalSessionBinding:
    session_name = session_name or principal
    return PrincipalSessionBinding(
        session_ref=f"sessionref:{session_name}",
        principal_ref=f"principalref:{principal}",
        authenticated_context_ref=f"authctxref:{principal}",
        authenticated_context_sha256=digest("b"),
        context_sha256=selected_context.context_sha256,
        issued_at="2026-09-20T10:00:00Z",
        expires_at="2026-09-20T12:00:00Z",
    )


def approval(
    selected_context: SpecialistContext,
    operation: SpecialistOperation,
    tier: ActionTier = ActionTier.R2,
) -> ApprovalBinding:
    return ApprovalBinding(
        approval_ref="approvalref:operator-77",
        approval_sha256=digest("c"),
        context_sha256=selected_context.context_sha256,
        operation=operation,
        maximum_tier=tier,
        issued_at="2026-09-20T10:00:00Z",
        expires_at="2026-09-20T11:00:00Z",
    )


def request(
    operation: SpecialistOperation = SpecialistOperation.AUTHZ_TENANT_ROLE,
    *,
    selected_context: SpecialistContext | None = None,
    sessions: tuple[PrincipalSessionBinding, ...] | None = None,
    idempotency_key: str = "idem:assessment-44-action-77",
) -> SpecialistActionRequest:
    selected_context = selected_context or context()
    if sessions is None:
        sessions = (
            session(selected_context, "alice"),
            session(selected_context, "bob"),
        )
    return SpecialistActionRequest(
        context=selected_context,
        operation=operation,
        requested_tier=ActionTier.R2,
        approval=approval(selected_context, operation),
        sessions=sessions,
        evidence_refs=("evidenceref:scope", "evidenceref:preflight"),
        tool_input_ref="toolref:fixture-77",
        tool_input_sha256=digest("d"),
        idempotency_key=idempotency_key,
        budget=SpecialistBudget(4, 4096, 8192, 8, 2),
        issued_at="2026-09-20T10:05:00Z",
        expires_at="2026-09-20T10:30:00Z",
    )


class FakeAdapter:
    def __init__(self, *, operation=SpecialistOperation.AUTHZ_TENANT_ROLE):
        self.identity = AdapterIdentity("adapter:fixture", "1.0.0", (operation,))
        self.calls: list[SpecialistActionRequest] = []
        self.mutation: dict[str, object] = {}

    def execute(self, selected_request: SpecialistActionRequest) -> AdapterObservation:
        self.calls.append(selected_request)
        values = {
            "request_id": selected_request.request_id,
            "request_sha256": selected_request.request_sha256,
            "context_sha256": selected_request.context.context_sha256,
            "idempotency_key": selected_request.idempotency_key,
            "state": ResultState.COMPLETED,
            "operations_performed": 2,
            "request_bytes": 512,
            "response_bytes": 1024,
            "redirect_count": 0,
            "evidence_refs": (
                "evidenceref:scope",
                "evidenceref:preflight",
                "evidenceref:observation",
            ),
            "evidence_sha256": (digest("1"), digest("2"), digest("3")),
            "observed_at": "2026-09-20T10:10:00Z",
        }
        values.update(self.mutation)
        return AdapterObservation(**values)


class SpecialistWebApiAdapterTests(unittest.TestCase):
    def test_capability_declarations_cover_a25_through_a211(self) -> None:
        declarations = specialist_capability_declarations()
        self.assertEqual(len(declarations), 7)
        self.assertEqual(
            {item.package_id for item in declarations},
            {"A2.5", "A2.6", "A2.7", "A2.8", "A2.9", "A2.10", "A2.11"},
        )
        self.assertEqual({item.family for item in declarations}, set(SpecialistFamily))
        self.assertTrue(all(item.repository_only for item in declarations))
        self.assertTrue(all(item.qualification_status == "not_qualified" for item in declarations))

    def test_request_and_receipt_are_deterministic_and_round_trip(self) -> None:
        selected = request()
        self.assertEqual(parse_specialist_contract(selected.to_dict()), selected)
        adapter = FakeAdapter()
        receipt = execute_specialist_action(
            selected,
            expected_context=selected.context,
            adapter=adapter,
            replay_guard=SpecialistReplayGuard(),
            evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
        )
        self.assertEqual(parse_specialist_contract(receipt.to_dict()), receipt)
        self.assertEqual(receipt.state, ResultState.COMPLETED)
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(receipt.to_dict()["effects"], dict(REPOSITORY_ONLY_EFFECTS))
        with self.assertRaises(FrozenInstanceError):
            receipt.state = ResultState.BLOCKED

    def test_protocol_is_runtime_checkable(self) -> None:
        self.assertIsInstance(FakeAdapter(), SpecialistExecutionAdapter)
        self.assertNotIsInstance(object(), SpecialistExecutionAdapter)

    def test_all_operation_families_construct_with_required_context(self) -> None:
        selected_context = context()
        for declaration in specialist_capability_declarations():
            for operation in declaration.operations:
                minimum = 2 if declaration.family is SpecialistFamily.AUTHORIZATION else 1
                sessions = tuple(
                    session(selected_context, name) for name in ("alice", "bob")[:minimum]
                )
                if declaration.family in {
                    SpecialistFamily.HTTP_PROTOCOL,
                    SpecialistFamily.API_TECHNOLOGY,
                    SpecialistFamily.INPUT_SERVICE_INTERACTION,
                }:
                    sessions = ()
                with self.subTest(operation=operation):
                    record = request(
                        operation,
                        selected_context=selected_context,
                        sessions=sessions,
                        idempotency_key=f"idem:{operation.value}",
                    )
                    self.assertEqual(
                        record.to_dict()["policy"]["package_id"],
                        declaration.package_id,
                    )

    def test_tier_and_approval_bindings_fail_closed(self) -> None:
        selected_context = context()
        operation = SpecialistOperation.INPUT_INJECTION_SSRF_DESERIALIZATION
        with self.assertRaisesRegex(SpecialistAdapterError, "below the operation minimum"):
            SpecialistActionRequest(
                context=selected_context,
                operation=operation,
                requested_tier=ActionTier.R1,
                approval=approval(selected_context, operation),
                sessions=(),
                evidence_refs=("evidenceref:scope",),
                tool_input_ref="toolref:fixture",
                tool_input_sha256=digest("d"),
                idempotency_key="idem:minimum-tier-rejection",
                budget=SpecialistBudget(1, 1, 1, 1, 0),
                issued_at="2026-09-20T10:05:00Z",
                expires_at="2026-09-20T10:30:00Z",
            )
        with self.assertRaisesRegex(SpecialistAdapterError, "approval operation"):
            replace(
                request(),
                operation=SpecialistOperation.AUTHZ_OBJECT_FUNCTION_FIELD,
                request_id="",
                request_sha256="",
            )

    def test_authenticated_and_multi_principal_requirements_fail_closed(self) -> None:
        selected_context = context()
        with self.assertRaisesRegex(SpecialistAdapterError, "required isolated principals"):
            request(
                SpecialistOperation.AUTH_LOGIN_SESSION,
                selected_context=selected_context,
                sessions=(),
            )
        with self.assertRaisesRegex(SpecialistAdapterError, "required isolated principals"):
            request(
                SpecialistOperation.AUTHZ_TENANT_ROLE,
                selected_context=selected_context,
                sessions=(session(selected_context, "alice"),),
            )
        with self.assertRaisesRegex(SpecialistAdapterError, "isolate unique principals"):
            request(
                SpecialistOperation.AUTHZ_TENANT_ROLE,
                selected_context=selected_context,
                sessions=(
                    session(selected_context, "alice", session_name="one"),
                    session(selected_context, "alice", session_name="two"),
                ),
            )

    def test_cross_context_request_session_and_execution_are_rejected_before_transport(
        self,
    ) -> None:
        primary = context()
        foreign = context(target="other-app")
        with self.assertRaisesRegex(SpecialistAdapterError, "session has a cross-context"):
            request(
                selected_context=primary,
                sessions=(session(primary, "alice"), session(foreign, "bob")),
            )
        selected = request(selected_context=primary)
        adapter = FakeAdapter()
        with self.assertRaisesRegex(SpecialistAdapterError, "request has a cross-context"):
            execute_specialist_action(
                selected,
                expected_context=foreign,
                adapter=adapter,
                replay_guard=SpecialistReplayGuard(),
                evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
            )
        self.assertEqual(adapter.calls, [])

    def test_replay_is_rejected_and_does_not_call_adapter_twice(self) -> None:
        selected = request()
        guard = SpecialistReplayGuard()
        adapter = FakeAdapter()
        execute_specialist_action(
            selected,
            expected_context=selected.context,
            adapter=adapter,
            replay_guard=guard,
            evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
        )
        self.assertTrue(guard.contains(selected.idempotency_key))
        with self.assertRaisesRegex(SpecialistAdapterError, "replay"):
            execute_specialist_action(
                selected,
                expected_context=selected.context,
                adapter=adapter,
                replay_guard=guard,
                evaluated_at=datetime(2026, 9, 20, 10, 11, tzinfo=UTC),
            )
        self.assertEqual(len(adapter.calls), 1)

        rebound_context = context(target="other-app")
        rebound = request(
            selected_context=rebound_context,
            sessions=(
                session(rebound_context, "alice"),
                session(rebound_context, "bob"),
            ),
            idempotency_key=selected.idempotency_key,
        )
        rebound_adapter = FakeAdapter()
        with self.assertRaisesRegex(SpecialistAdapterError, "replay"):
            execute_specialist_action(
                rebound,
                expected_context=rebound_context,
                adapter=rebound_adapter,
                replay_guard=guard,
                evaluated_at=datetime(2026, 9, 20, 10, 12, tzinfo=UTC),
            )
        self.assertEqual(rebound_adapter.calls, [])

    def test_stale_authority_and_session_fail_before_transport(self) -> None:
        selected = request()
        for evaluated_at, message in (
            (datetime(2026, 9, 20, 9, 59, tzinfo=UTC), "request is stale"),
            (datetime(2026, 9, 20, 11, 30, tzinfo=UTC), "request is stale"),
        ):
            adapter = FakeAdapter()
            with (
                self.subTest(evaluated_at=evaluated_at),
                self.assertRaisesRegex(SpecialistAdapterError, message),
            ):
                execute_specialist_action(
                    selected,
                    expected_context=selected.context,
                    adapter=adapter,
                    replay_guard=SpecialistReplayGuard(),
                    evaluated_at=evaluated_at,
                )
            self.assertEqual(adapter.calls, [])

        approval_stale = replace(
            selected,
            expires_at="2026-09-20T11:30:00Z",
            request_id="",
            request_sha256="",
        )
        with self.assertRaisesRegex(SpecialistAdapterError, "approval is stale"):
            execute_specialist_action(
                approval_stale,
                expected_context=approval_stale.context,
                adapter=FakeAdapter(),
                replay_guard=SpecialistReplayGuard(),
                evaluated_at=datetime(2026, 9, 20, 11, 15, tzinfo=UTC),
            )

        short_sessions = tuple(
            replace(value, expires_at="2026-09-20T10:08:00Z") for value in selected.sessions
        )
        session_stale = replace(
            selected,
            sessions=short_sessions,
            request_id="",
            request_sha256="",
        )
        with self.assertRaisesRegex(SpecialistAdapterError, "session is stale"):
            execute_specialist_action(
                session_stale,
                expected_context=session_stale.context,
                adapter=FakeAdapter(),
                replay_guard=SpecialistReplayGuard(),
                evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
            )

    def test_adapter_identity_result_and_evidence_substitution_fail_closed(self) -> None:
        selected = request()
        wrong_adapter = FakeAdapter(operation=SpecialistOperation.AUTH_LOGIN_SESSION)
        with self.assertRaisesRegex(SpecialistAdapterError, "does not declare"):
            execute_specialist_action(
                selected,
                expected_context=selected.context,
                adapter=wrong_adapter,
                replay_guard=SpecialistReplayGuard(),
                evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
            )
        for mutation, message in (
            ({"context_sha256": digest("9")}, "binding mismatch"),
            (
                {
                    "evidence_refs": ("evidenceref:scope",),
                    "evidence_sha256": (digest("1"),),
                },
                "omits required evidence",
            ),
            ({"observed_at": "2026-09-20T10:11:00Z"}, "observation time"),
        ):
            adapter = FakeAdapter()
            adapter.mutation = mutation
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(SpecialistAdapterError, message),
            ):
                execute_specialist_action(
                    selected,
                    expected_context=selected.context,
                    adapter=adapter,
                    replay_guard=SpecialistReplayGuard(),
                    evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
                )

    def test_bounded_observations_are_enforced(self) -> None:
        selected = request()
        for mutation in (
            {"operations_performed": 5},
            {"request_bytes": 4097},
            {"response_bytes": 8193},
            {"redirect_count": 3},
        ):
            adapter = FakeAdapter()
            adapter.mutation = mutation
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(SpecialistAdapterError, "exceeds the request budget"),
            ):
                execute_specialist_action(
                    selected,
                    expected_context=selected.context,
                    adapter=adapter,
                    replay_guard=SpecialistReplayGuard(),
                    evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
                )

    def test_tamper_extra_fields_and_effect_escalation_fail_runtime_parse(self) -> None:
        raw = request().to_dict()
        for mutation in ("digest", "extra", "effects", "policy"):
            candidate = copy.deepcopy(raw)
            if mutation == "digest":
                candidate["request_sha256"] = digest("0")
            elif mutation == "extra":
                candidate["unexpected"] = True
            elif mutation == "effects":
                candidate["effects"]["network_client"] = "included"
            else:
                candidate["policy"]["package_id"] = "A2.11"
            with self.subTest(mutation=mutation), self.assertRaises(SpecialistAdapterError):
                parse_specialist_contract(candidate)

        nested_extra = execute_specialist_action(
            request(),
            expected_context=request().context,
            adapter=FakeAdapter(),
            replay_guard=SpecialistReplayGuard(),
            evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
        ).to_dict()
        nested_extra["adapter"]["unexpected"] = True
        with self.assertRaisesRegex(SpecialistAdapterError, "receipt adapter fields"):
            parse_specialist_contract(nested_extra)

    def test_raw_secrets_have_no_contract_path(self) -> None:
        with self.assertRaisesRegex(SpecialistAdapterError, "secret material"):
            canonical_json({"authorization": "Bearer abcdefghijklmnop"})
        raw = request().to_dict()
        encoded = json.dumps(raw).lower()
        self.assertNotIn("password", encoded)
        self.assertNotIn("access_token", encoded)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_request_and_receipt_and_rejects_unknown_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        selected = request()
        receipt = execute_specialist_action(
            selected,
            expected_context=selected.context,
            adapter=FakeAdapter(),
            replay_guard=SpecialistReplayGuard(),
            evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
        )
        validator.validate(selected.to_dict())
        validator.validate(receipt.to_dict())
        changed = receipt.to_dict()
        changed["unexpected"] = True
        self.assertTrue(list(validator.iter_errors(changed)))

    def test_created_files_exclude_markers_and_dash_codepoints(self) -> None:
        markers = (
            "generated " + "by",
            "written by " + "ai",
            "as an " + "ai",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path.name)
            self.assertNotIn("\u2014", text, path.name)
            for marker in markers:
                self.assertNotIn(marker, text.lower(), path.name)

    def test_public_package_exports_specialist_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.SpecialistWebApiActionRequest, SpecialistActionRequest)
        self.assertIs(sunderkey.execute_web_api_specialist_action, execute_specialist_action)
        self.assertIs(sunderkey.parse_web_api_specialist_contract, parse_specialist_contract)
        self.assertIs(
            sunderkey.web_api_specialist_capabilities,
            specialist_capability_declarations,
        )


if __name__ == "__main__":
    unittest.main()
