"""Phase196 authenticated single-attempt action executor coverage."""

from __future__ import annotations

import inspect
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError

import sunderkey.authenticated_action_executor as execution
from scripts.build_authenticated_action_execution import build_schema
from sunderkey.action_resolution import (
    _address_record,
    parse_authenticated_action_admission_receipt,
)
from sunderkey.authenticated_action_executor import (
    ACTION_EXECUTE,
    AUTHORITY_CHECKS,
    ActionExecutionCommand,
    ActionExecutionError,
    ActionExecutionReconciliationRequired,
    AdapterBinding,
    AuthenticatedActionExecutionService,
    BrowserPrimitiveActionAdapter,
    CurrentActionExecutionMaterial,
    CurrentExecutionAuthorityState,
    ExecutionBudget,
    ExecutionResources,
    HttpPrimitiveActionAdapter,
    SessionPrimitiveActionAdapter,
    SpecialistPrimitiveActionAdapter,
    TerminalStatus,
    action_execute_authorization_intent_sha256,
)
from sunderkey.errors import StoreError
from sunderkey.qualification import _canonical_json
from tests.agents import test_action_resolution_phase195 as phase195_tests

ROOT = Path(__file__).resolve().parents[2]
FILES = (
    ROOT / "src/sunderkey/authenticated_action_executor.py",
    ROOT / "scripts/build_authenticated_action_execution.py",
    ROOT / "registry/schemas/authenticated-action-execution-v1.schema.json",
    Path(__file__),
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class OwnedExecutionAuthority:
    def __init__(self, material: CurrentActionExecutionMaterial) -> None:
        self.material = material
        self.authorization_failure = False
        self.assertion_character = "7"
        self.load_calls = 0
        self.authorization_calls = 0

    @staticmethod
    def _require_transaction(connection: sqlite3.Connection) -> None:
        if not connection.in_transaction:
            raise AssertionError("execution authority was called outside the transaction")

    def load_current_execution(
        self, connection, command, evaluated_at
    ):  # type: ignore[no-untyped-def]
        del command, evaluated_at
        self._require_transaction(connection)
        self.load_calls += 1
        return self.material

    def authorize_action_execute(
        self, connection, request, operation_intent_sha256, evaluated_at
    ):  # type: ignore[no-untyped-def]
        self._require_transaction(connection)
        self.authorization_calls += 1
        if self.authorization_failure:
            raise ActionExecutionError("injected execution authorization failure")
        if operation_intent_sha256 != action_execute_authorization_intent_sha256(request):
            raise AssertionError("operation intent differs from exact request")
        document = request.to_dict()
        receipt = document["admission_receipt"]
        state = document["authority_state"]
        character = self.assertion_character
        return {
            "operation": ACTION_EXECUTE,
            "role": "admission_control",
            "principal_profile_id": "service:action-executor",
            "principal_subject": "subject:action-executor",
            "assertion_issuer": "issuer:" + character,
            "assertion_id": "assertion:" + character,
            "assertion_sha256": digest(character),
            "assertion_key_sha256": digest("a"),
            "trust_policy_sha256": digest("b"),
            "scope_grant_sha256": digest("c"),
            "operation_intent_sha256": operation_intent_sha256,
            "canonical_replay_key_sha256": digest(character),
            "tenant_id": state["tenant_id"],
            "mission_id": state["mission_id"],
            "scope_sha256": state["scope_sha256"],
            "target_sha256": state["target_sha256"],
            "action_sha256": state["action_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "request_sha256": request.request_sha256,
            "decision": "approved",
            "issued_at": "2026-09-20T11:00:00Z",
            "expires_at": "2026-09-20T13:00:00Z",
        }


class PrimitiveAdapter:
    def __init__(self, binding: AdapterBinding) -> None:
        self.binding = binding
        self.calls = 0
        self.mode = "succeeded"
        self.axes = ("complete", "pending", "failed")

    def invoke_once(self, request):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.mode == "mutate_request":
            request["adapter_input"]["path"] = "/substituted"
        if self.mode == "exception":
            raise RuntimeError("injected adapter failure")
        if self.mode == "base_exception":
            raise KeyboardInterrupt("injected interrupt")
        if self.mode == "malformed":
            return {"outcome": "succeeded"}
        document = dict(request)
        request_bytes = len(
            _canonical_json(dict(document["adapter_input"])).encode("ascii")
        )
        resources = {
            "money_microunits": 30,
            "rate_units": 1,
            "request_bytes": request_bytes,
            "response_bytes": 32,
            "duration_ms": 5,
            "impact_events": 1,
        }
        if self.mode == "over_limit":
            resources["response_bytes"] = 1000000
        if self.mode == "underreport":
            resources["rate_units"] = 0
        if self.mode == "underreport_response":
            resources["response_bytes"] = 0
        if self.mode == "underreport_duration":
            resources["duration_ms"] = 0
        if self.mode == "underreport_impact":
            resources["impact_events"] = 0
        result = {
            "request_id": document["action_execution_request_id"],
            "request_sha256": document["action_execution_request_sha256"],
            "action_sha256": document["admission_receipt"]["action_sha256"],
            "adapter": self.binding.to_dict(),
            "outcome": "failed" if self.mode == "failed" else "succeeded",
            "evidence_status": self.axes[0],
            "cleanup_status": self.axes[1],
            "restoration_status": self.axes[2],
            "result_payload": {"provider_reference": "provider:result-001"},
            "resources_used": resources,
        }
        if self.mode == "substituted":
            result["request_sha256"] = digest("0")
        if self.mode == "control_character":
            result["result_payload"] = {"provider_reference": "bad\x00value"}
        if self.mode == "control_key":
            result["result_payload"] = {"bad\nkey": "value"}
        if self.mode == "delete_character":
            result["result_payload"] = {"provider_reference": "bad\x7fvalue"}
        return result


class ActionExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        portable = phase195_tests.ActionResolutionTests(methodName="runTest")
        portable.setUp()
        self.addCleanup(portable.doCleanups)
        self.receipt = portable.receipt
        receipt = self.receipt.to_dict()
        checks = {name: True for name in AUTHORITY_CHECKS}
        self.state = CurrentExecutionAuthorityState(
            tenant_id=receipt["tenant_id"],
            mission_id=receipt["mission_id"],
            plan_id="plan:001",
            scope_sha256=receipt["scope_sha256"],
            target_sha256=receipt["target_sha256"],
            action_sha256=receipt["action_sha256"],
            receipt_id=receipt["receipt_id"],
            receipt_sha256=receipt["receipt_sha256"],
            review_evidence_sha256=digest("1"),
            catalog_id="catalog:phase196",
            catalog_sha256=digest("2"),
            catalog_version="1.0.0",
            catalog_authority_sha256=digest("3"),
            authority_revision_sha256=digest("9"),
            checks=checks,
        )
        self.binding = AdapterBinding(
            adapter_id="adapter:api-primitive",
            adapter_kind="http",
            adapter_version="2.1.0",
            adapter_build_sha256=digest("d"),
            deployment_binding_sha256=digest("e"),
        )
        limits = ExecutionResources(1000, 10, 100000, 100000, 60000, 10)
        used = ExecutionResources(0, 0, 0, 0, 0, 0)
        reservation = ExecutionResources(100, 1, 4096, 4096, 30000, 2)
        self.budget = ExecutionBudget(
            budget_id="budget:action-001",
            budget_sha256=digest("8"),
            limits=limits,
            used=used,
            reservation=reservation,
        )
        admission = receipt["admission_authorization"]
        self.material = CurrentActionExecutionMaterial(
            admission_receipt=self.receipt,
            admission_custody_sha256=digest("6"),
            authority_state=self.state,
            adapter=self.binding,
            adapter_input={"method": "GET", "path": "/health"},
            budget=self.budget,
            prior_assertion_sha256s=(admission["assertion_sha256"],),
            prior_replay_key_sha256s=(admission["canonical_replay_key_sha256"],),
        )
        self.authority = OwnedExecutionAuthority(self.material)
        self.adapter = PrimitiveAdapter(self.binding)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "execution.sqlite3"
        self.service = AuthenticatedActionExecutionService(
            self.database,
            self.authority,
            self.adapter,
            clock=lambda: datetime(2026, 9, 20, 12, 5, tzinfo=UTC),
        )
        self.service.initialize()
        self.command = ActionExecutionCommand(
            receipt_id=self.receipt.receipt_id,
            idempotency_key_sha256=digest("5"),
        )

    def _counts(self) -> tuple[int, int, int, int, int]:
        connection = sqlite3.connect(self.database)
        try:
            return tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "action_execution_requests",
                    "action_execution_claims",
                    "action_execution_assertion_uses",
                    "action_execution_reservations",
                    "action_execution_terminals",
                )
            )  # type: ignore[return-value]
        finally:
            connection.close()

    def _receipt_variant(self, evaluated_at: str):  # type: ignore[no-untyped-def]
        document = self.receipt.to_dict()
        body = {
            key: value
            for key, value in document.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        body["evaluated_at"] = evaluated_at
        return parse_authenticated_action_admission_receipt(
            _address_record("authenticated_action_admission_receipt", body)
        )

    def _select_receipt(self, receipt) -> None:  # type: ignore[no-untyped-def]
        document = receipt.to_dict()
        state = replace(
            self.state,
            receipt_id=receipt.receipt_id,
            receipt_sha256=receipt.receipt_sha256,
        )
        self.authority.material = replace(
            self.material,
            admission_receipt=receipt,
            authority_state=state,
            prior_assertion_sha256s=(document["admission_authorization"]["assertion_sha256"],),
            prior_replay_key_sha256s=(
                document["admission_authorization"]["canonical_replay_key_sha256"],
            ),
        )

    @staticmethod
    def _restore_trigger(
        connection: sqlite3.Connection,
        trigger_name: str,
    ) -> None:
        statements = [
            statement
            for statement in execution._schema_statements()
            if statement.startswith(f"CREATE TRIGGER {trigger_name} ")
            or statement.startswith(f"CREATE TRIGGER {trigger_name}\n")
        ]
        if len(statements) != 1:
            raise AssertionError("expected one exact trigger definition")
        connection.execute(statements[0])

    def test_success_is_single_call_and_preserves_independent_axes(self) -> None:
        terminal = self.service.execute(self.command)
        document = terminal.to_dict()
        self.assertEqual(document["terminal_status"], "completed")
        self.assertEqual(document["action_outcome"], "succeeded")
        self.assertEqual(document["evidence_status"], "complete")
        self.assertEqual(document["cleanup_status"], "pending")
        self.assertEqual(document["restoration_status"], "failed")
        self.assertEqual(document["adapter_call_count"], 1)
        self.assertEqual(document["automatic_retry_count"], 0)
        self.assertEqual(self.adapter.calls, 1)
        self.assertEqual(self._counts(), (1, 1, 1, 1, 1))

    def test_exact_terminal_replay_never_calls_adapter_again(self) -> None:
        first = self.service.execute(self.command)
        restarted = AuthenticatedActionExecutionService(
            self.database,
            self.authority,
            self.adapter,
            clock=lambda: datetime(2026, 9, 20, 12, 6, tzinfo=UTC),
        )
        second = restarted.execute(self.command)
        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(self.adapter.calls, 1)

    def test_exact_terminal_replay_does_not_require_a_clock(self) -> None:
        first = self.service.execute(self.command)

        def unavailable_clock() -> datetime:
            raise RuntimeError("clock unavailable")

        restarted = AuthenticatedActionExecutionService(
            self.database,
            self.authority,
            self.adapter,
            clock=unavailable_clock,
        )
        second = restarted.execute(self.command)
        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(self.adapter.calls, 1)

    def test_adapter_exceptions_and_base_exceptions_quarantine_full_reservation(self) -> None:
        for mode in ("exception", "base_exception"):
            with self.subTest(mode=mode):
                self.setUp()
                self.adapter.mode = mode
                terminal = self.service.execute(self.command)
                self.assertEqual(
                    terminal.to_dict()["terminal_status"],
                    TerminalStatus.INDETERMINATE_QUARANTINED.value,
                )
                self.assertEqual(
                    terminal.to_dict()["charged_resources"],
                    self.budget.reservation.to_dict(),
                )

    def test_raw_secret_input_is_rejected_before_claim(self) -> None:
        self.authority.material = replace(
            self.material,
            adapter_input={
                "method": "GET",
                "path": "/health",
                "authorization": "Bearer abcdefghijklmnop",
            },
        )
        with self.assertRaisesRegex(ActionExecutionError, "raw secret"):
            self.service.execute(self.command)
        self.assertEqual(self.adapter.calls, 0)
        self.assertEqual(self._counts(), (0, 0, 0, 0, 0))

    def test_portable_request_parser_rejects_raw_secret_input(self) -> None:
        self.service.execute(self.command)
        connection = sqlite3.connect(self.database)
        try:
            request = json.loads(
                connection.execute("SELECT request_json FROM action_execution_requests").fetchone()[
                    0
                ]
            )
        finally:
            connection.close()
        request["adapter_input"]["password"] = "not-portable-material"
        with self.assertRaisesRegex(ActionExecutionError, "raw secret"):
            execution.parse_action_execution_request(request)

    def test_raw_secret_result_is_quarantined_at_full_reservation(self) -> None:
        original = self.adapter.invoke_once

        def secret_result(request):  # type: ignore[no-untyped-def]
            result = dict(original(request))
            result["result_payload"] = {"password": "not-durable-material"}
            return result

        service = AuthenticatedActionExecutionService(
            self.database,
            self.authority,
            HttpPrimitiveActionAdapter(self.binding, secret_result),
            clock=lambda: datetime(2026, 9, 20, 12, 5, tzinfo=UTC),
        )
        terminal = service.execute(self.command)
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            "indeterminate_quarantined",
        )
        self.assertEqual(
            terminal.to_dict()["charged_resources"],
            self.budget.reservation.to_dict(),
        )

    def test_malformed_substituted_over_limit_and_underreported_results_quarantine(self) -> None:
        for mode in (
            "malformed",
            "substituted",
            "over_limit",
            "underreport",
            "underreport_response",
            "underreport_duration",
            "underreport_impact",
            "control_character",
            "control_key",
            "delete_character",
            "mutate_request",
        ):
            with self.subTest(mode=mode):
                self.setUp()
                self.adapter.mode = mode
                terminal = self.service.execute(self.command)
                self.assertEqual(
                    terminal.to_dict()["terminal_status"],
                    "indeterminate_quarantined",
                )
                self.assertEqual(
                    terminal.to_dict()["charged_resources"],
                    self.budget.reservation.to_dict(),
                )

    def test_terminal_build_base_exception_quarantines_full_reservation(self) -> None:
        with patch.object(
            self.service,
            "_build_terminal",
            side_effect=KeyboardInterrupt("injected terminal construction interrupt"),
        ):
            terminal = self.service.execute(self.command)
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            "indeterminate_quarantined",
        )
        self.assertEqual(
            terminal.to_dict()["charged_resources"],
            self.budget.reservation.to_dict(),
        )

    def test_mutable_adapter_binding_substitution_before_claim_is_rejected(self) -> None:
        self.adapter.binding = replace(
            self.binding,
            adapter_build_sha256=digest("0"),
        )
        with self.assertRaisesRegex(ActionExecutionError, "binding changed"):
            self.service.execute(self.command)
        self.assertEqual(self.adapter.calls, 0)
        self.assertEqual(self._counts(), (0, 0, 0, 0, 0))

    def test_mutable_adapter_binding_substitution_after_claim_is_quarantined(self) -> None:
        original = self.service._insert_prepared

        def insert_and_substitute(*args, **kwargs):  # type: ignore[no-untyped-def]
            original(*args, **kwargs)
            self.adapter.binding = replace(
                self.binding,
                adapter_build_sha256=digest("0"),
            )

        with patch.object(
            self.service,
            "_insert_prepared",
            side_effect=insert_and_substitute,
        ):
            terminal = self.service.execute(self.command)
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            "indeterminate_quarantined",
        )
        self.assertEqual(
            terminal.to_dict()["charged_resources"],
            self.budget.reservation.to_dict(),
        )
        self.assertEqual(self.adapter.calls, 0)

    def test_known_failure_is_terminal_without_retry(self) -> None:
        self.adapter.mode = "failed"
        terminal = self.service.execute(self.command)
        self.assertEqual(terminal.to_dict()["terminal_status"], "failed_known")
        self.assertEqual(terminal.to_dict()["action_outcome"], "failed")
        self.assertEqual(self.adapter.calls, 1)

    def test_authority_failure_rolls_back_before_adapter(self) -> None:
        self.authority.authorization_failure = True
        with self.assertRaisesRegex(ActionExecutionError, "injected"):
            self.service.execute(self.command)
        self.assertEqual(self._counts(), (0, 0, 0, 0, 0))
        self.assertEqual(self.adapter.calls, 0)

    def test_each_current_authority_check_fails_before_claim(self) -> None:
        for check in AUTHORITY_CHECKS:
            with self.subTest(check=check):
                self.setUp()
                checks = {name: True for name in AUTHORITY_CHECKS}
                checks[check] = False
                self.authority.material = replace(
                    self.material,
                    authority_state=replace(self.state, checks=checks),
                )
                with self.assertRaisesRegex(ActionExecutionError, check):
                    self.service.execute(self.command)
                self.assertEqual(self._counts(), (0, 0, 0, 0, 0))

    def test_adapter_binding_is_service_owned(self) -> None:
        wrong = replace(self.binding, adapter_build_sha256=digest("0"))
        self.authority.material = replace(self.material, adapter=wrong)
        with self.assertRaisesRegex(ActionExecutionError, "service adapter"):
            self.service.execute(self.command)
        self.assertEqual(self.adapter.calls, 0)

    def test_primitive_wrappers_call_each_boundary_exactly_once(self) -> None:
        wrappers = (
            ("http", HttpPrimitiveActionAdapter),
            ("browser", BrowserPrimitiveActionAdapter),
            ("session", SessionPrimitiveActionAdapter),
            ("specialist", SpecialistPrimitiveActionAdapter),
        )
        for kind, wrapper_type in wrappers:
            with self.subTest(kind=kind):
                calls = []

                def primitive(
                    request,
                    calls=calls,
                    kind=kind,
                ):  # type: ignore[no-untyped-def]
                    calls.append(request)
                    return {"boundary": kind}

                wrapper = wrapper_type(
                    replace(self.binding, adapter_kind=kind),
                    primitive,
                )
                self.assertEqual(
                    wrapper.invoke_once({"request": "value"}),
                    {"boundary": kind},
                )
                self.assertEqual(len(calls), 1)
        with self.assertRaisesRegex(ValueError, "kind"):
            BrowserPrimitiveActionAdapter(self.binding, lambda request: request)

    def test_execute_authorization_cannot_reuse_admission_authentication(self) -> None:
        self.authority.assertion_character = "4"
        with self.assertRaisesRegex(ActionExecutionError, "reuses prior"):
            self.service.execute(self.command)
        self.assertEqual(self._counts(), (0, 0, 0, 0, 0))

    def test_global_execution_replay_conflict_rolls_back_second_claim(self) -> None:
        self.service.execute(self.command)
        second = ActionExecutionCommand(
            receipt_id=self.command.receipt_id,
            idempotency_key_sha256=digest("0"),
        )
        with self.assertRaisesRegex(StoreError, "replay"):
            self.service.execute(second)
        self.assertEqual(self.adapter.calls, 1)
        self.assertEqual(self._counts(), (1, 1, 1, 1, 1))

    def test_admission_receipt_is_single_use_across_idempotency_keys(self) -> None:
        self.service.execute(self.command)
        self.authority.assertion_character = "6"
        second = ActionExecutionCommand(
            receipt_id=self.command.receipt_id,
            idempotency_key_sha256=digest("0"),
        )
        with self.assertRaisesRegex(StoreError, "custody"):
            self.service.execute(second)
        self.assertEqual(self.adapter.calls, 1)
        self.assertEqual(self._counts(), (1, 1, 1, 1, 1))

    def test_concurrent_distinct_commands_cannot_reuse_one_admission(self) -> None:
        second_authority = OwnedExecutionAuthority(self.material)
        second_authority.assertion_character = "6"
        second_service = AuthenticatedActionExecutionService(
            self.database,
            second_authority,
            self.adapter,
            clock=lambda: datetime(2026, 9, 20, 12, 5, tzinfo=UTC),
        )
        second = ActionExecutionCommand(
            receipt_id=self.command.receipt_id,
            idempotency_key_sha256=digest("0"),
        )
        outcomes = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(self.service.execute, self.command),
                pool.submit(second_service.execute, second),
            )
            for future in futures:
                try:
                    outcomes.append(future.result())
                except StoreError:
                    outcomes.append("conflict")
        self.assertEqual(self.adapter.calls, 1)
        self.assertEqual(outcomes.count("conflict"), 1)
        self.assertEqual(self._counts(), (1, 1, 1, 1, 1))

    def test_claim_without_terminal_is_reconciliation_only(self) -> None:
        with patch.object(
            self.service,
            "_quarantine_after_claim",
            side_effect=ActionExecutionError("injected settlement outage"),
        ):
            self.adapter.mode = "exception"
            with self.assertRaisesRegex(ActionExecutionError, "settlement outage"):
                self.service.execute(self.command)
        self.assertEqual(self._counts(), (1, 1, 1, 1, 0))
        with self.assertRaises(ActionExecutionReconciliationRequired):
            self.service.execute(self.command)
        self.assertEqual(self.adapter.calls, 1)
        connection = sqlite3.connect(self.database)
        try:
            request_id = connection.execute(
                "SELECT request_id FROM action_execution_requests"
            ).fetchone()[0]
        finally:
            connection.close()
        terminal = self.service.reconcile_claim(request_id)
        self.assertEqual(terminal.to_dict()["adapter_call_count"], None)
        self.assertEqual(
            terminal.to_dict()["adapter_call_count_status"], "unknown_zero_or_one"
        )
        self.assertEqual(
            terminal.to_dict()["charged_resources"],
            self.budget.reservation.to_dict(),
        )
        self.assertEqual(self.adapter.calls, 1)

    def test_settlement_failure_falls_back_to_indeterminate(self) -> None:
        with patch.object(
            self.service,
            "_settle",
            side_effect=ActionExecutionError("injected terminal write failure"),
        ):
            terminal = self.service.execute(self.command)
        self.assertEqual(terminal.to_dict()["terminal_status"], "indeterminate_quarantined")
        self.assertEqual(
            terminal.to_dict()["charged_resources"], self.budget.reservation.to_dict()
        )

    def test_clock_failure_after_claim_is_indeterminate(self) -> None:
        calls = 0

        def clock() -> datetime:
            nonlocal calls
            calls += 1
            if calls == 1:
                return datetime(2026, 9, 20, 12, 5, tzinfo=UTC)
            raise RuntimeError("clock unavailable")

        service = AuthenticatedActionExecutionService(
            self.database, self.authority, self.adapter, clock=clock
        )
        terminal = service.execute(self.command)
        self.assertEqual(terminal.to_dict()["terminal_status"], "indeterminate_quarantined")
        self.assertEqual(
            terminal.to_dict()["charged_resources"], self.budget.reservation.to_dict()
        )

    def test_whole_store_verification_and_schema_substitution(self) -> None:
        self.service.execute(self.command)
        self.assertEqual(
            self.service.verify_store(),
            {
                "request_count": 1,
                "terminal_count": 1,
                "reconciliation_required_count": 0,
                "status": "valid",
            },
        )
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("DROP TRIGGER action_execution_requests_no_update")
            connection.execute(
                """
                CREATE TRIGGER action_execution_requests_no_update
                BEFORE UPDATE ON action_execution_requests
                BEGIN SELECT RAISE(ABORT, 'substituted'); END
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StoreError, "schema"):
            self.service.verify_store()

    def test_concurrent_exact_command_invokes_at_most_once(self) -> None:
        outcomes = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.service.execute, self.command) for _ in range(2)]
            for future in futures:
                try:
                    outcomes.append(future.result())
                except ActionExecutionReconciliationRequired:
                    outcomes.append("reconciliation")
        self.assertEqual(self.adapter.calls, 1)
        self.assertEqual(self._counts()[-1], 1)
        self.assertTrue(any(item != "reconciliation" for item in outcomes))

    def test_settled_usage_releases_unused_reservation_capacity(self) -> None:
        limits = ExecutionResources(150, 2, 100000, 100000, 60000, 10)
        budget = replace(self.budget, limits=limits)
        self.authority.material = replace(self.material, budget=budget)
        self.service.execute(self.command)

        second_receipt = self._receipt_variant("2026-09-20T12:04:00Z")
        self._select_receipt(second_receipt)
        self.authority.material = replace(self.authority.material, budget=budget)
        self.authority.assertion_character = "6"
        second = ActionExecutionCommand(
            receipt_id=second_receipt.receipt_id,
            idempotency_key_sha256=digest("0"),
        )
        self.service.execute(second)

        third_receipt = self._receipt_variant("2026-09-20T12:03:00Z")
        self._select_receipt(third_receipt)
        self.authority.material = replace(self.authority.material, budget=budget)
        self.authority.assertion_character = "1"
        third = ActionExecutionCommand(
            receipt_id=third_receipt.receipt_id,
            idempotency_key_sha256=digest("2"),
        )
        with self.assertRaisesRegex(ActionExecutionError, "budget"):
            self.service.execute(third)
        self.assertEqual(self.adapter.calls, 2)
        self.assertEqual(self._counts(), (2, 2, 2, 2, 2))

    def test_claim_and_budget_column_substitution_is_detected(self) -> None:
        self.service.execute(self.command)
        connection = sqlite3.connect(self.database, isolation_level=None)
        try:
            connection.execute("DROP TRIGGER action_execution_claims_no_update")
            connection.execute(
                "UPDATE action_execution_claims SET authorization_json = '{}'"
            )
            self._restore_trigger(
                connection,
                "action_execution_claims_no_update",
            )
        finally:
            connection.close()
        with self.assertRaisesRegex(StoreError, "claim custody"):
            self.service.verify_store()

        self.setUp()
        self.service.execute(self.command)
        connection = sqlite3.connect(self.database, isolation_level=None)
        try:
            connection.execute(
                "DROP TRIGGER action_execution_reservations_no_update"
            )
            connection.execute(
                """
                UPDATE action_execution_reservations
                SET budget_id = 'budget:substituted'
                """
            )
            self._restore_trigger(
                connection,
                "action_execution_reservations_no_update",
            )
        finally:
            connection.close()
        with self.assertRaisesRegex(StoreError, "reservation custody"):
            self.service.verify_store()

    def test_immutable_tables_and_strict_sql_types(self) -> None:
        self.service.execute(self.command)
        connection = sqlite3.connect(self.database, isolation_level=None)
        try:
            tables = (
                "action_execution_requests",
                "action_execution_claims",
                "action_execution_assertion_uses",
                "action_execution_reservations",
                "action_execution_terminals",
            )
            for table in tables:
                with (
                    self.subTest(table=table, operation="update"),
                    self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"),
                ):
                    connection.execute(f"UPDATE {table} SET rowid = rowid")
                with (
                    self.subTest(table=table, operation="delete"),
                    self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"),
                ):
                    connection.execute(f"DELETE FROM {table}")
            connection.execute(
                "DROP TRIGGER action_execution_reservations_no_update"
            )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE action_execution_reservations SET budget_id = ?",
                    (sqlite3.Binary(b"not-text"),),
                )
            self._restore_trigger(
                connection,
                "action_execution_reservations_no_update",
            )
        finally:
            connection.close()
        self.assertEqual(self.service.verify_store()["status"], "valid")

    def test_closed_schema_matches_builder_and_records(self) -> None:
        terminal = self.service.execute(self.command)
        document = json.loads(
            (ROOT / "registry/schemas/authenticated-action-execution-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(document, build_schema())
        Draft202012Validator.check_schema(document)
        validator = Draft202012Validator(document)
        connection = sqlite3.connect(self.database)
        try:
            request = json.loads(
                connection.execute(
                    "SELECT request_json FROM action_execution_requests"
                ).fetchone()[0]
            )
            claim = json.loads(
                connection.execute("SELECT claim_json FROM action_execution_claims").fetchone()[0]
            )
        finally:
            connection.close()
        for record in (request, claim, terminal.to_dict()):
            validator.validate(record)
        unknown = terminal.to_dict()
        unknown["unknown"] = True
        with self.assertRaises(ValidationError):
            validator.validate(unknown)

    def test_runtime_rejects_boolean_terminal_counters(self) -> None:
        terminal = self.service.execute(self.command).to_dict()
        for field, value in (
            ("adapter_call_count", True),
            ("automatic_retry_count", False),
        ):
            with self.subTest(field=field):
                body = {
                    key: item
                    for key, item in terminal.items()
                    if key
                    not in {
                        "action_execution_terminal_id",
                        "action_execution_terminal_sha256",
                    }
                }
                body[field] = value
                forged = execution._record(
                    "action_execution_terminal",
                    "AXT",
                    execution.TERMINAL_DOMAIN,
                    body,
                )
                with self.assertRaisesRegex(ActionExecutionError, "call count"):
                    execution.parse_action_execution_terminal(forged)

    def test_predispatch_abort_requires_zero_charged_resources(self) -> None:
        terminal = self.service.execute(self.command).to_dict()
        body = {
            key: item
            for key, item in terminal.items()
            if key
            not in {
                "action_execution_terminal_id",
                "action_execution_terminal_sha256",
            }
        }
        body.update(
            {
                "terminal_status": TerminalStatus.PREDISPATCH_ABORTED.value,
                "action_outcome": "failed",
                "evidence_status": "unknown",
                "cleanup_status": "unknown",
                "restoration_status": "unknown",
                "result_document": {
                    "reason_code": "predispatch_failure",
                    "trusted_result": False,
                },
                "reason_code": "predispatch_failure",
                "adapter_call_count": 0,
                "adapter_call_count_status": "exactly_zero",
            }
        )
        body["result_sha256"] = execution._canonical_sha256(
            {"domain": execution.RESULT_DOMAIN, "result": body["result_document"]}
        )
        body["charged_resources"] = {
            **body["charged_resources"],
            "rate_units": 1,
        }
        forged = execution._record(
            "action_execution_terminal",
            "AXT",
            execution.TERMINAL_DOMAIN,
            body,
        )
        with self.assertRaisesRegex(ActionExecutionError, "must not charge"):
            execution.parse_action_execution_terminal(forged)
        with self.assertRaises(ValidationError):
            Draft202012Validator(build_schema()).validate(forged)

    def test_no_retry_clients_markers_or_unicode_dashes(self) -> None:
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
        marker = __import__("re").compile("|".join(marker_parts), __import__("re").IGNORECASE)
        for path in FILES:
            content = path.read_text(encoding="utf-8")
            self.assertNotRegex(content, marker)
            self.assertNotIn("\u2013", content)
            self.assertNotIn("\u2014", content)
        source = inspect.getsource(AuthenticatedActionExecutionService.execute)
        self.assertEqual(source.count("invoke_once("), 1)
        self.assertNotIn("retry", source.lower())


if __name__ == "__main__":
    unittest.main()
