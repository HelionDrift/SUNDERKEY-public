"""MissionStore-integrated authenticated action execution tests."""

from __future__ import annotations

import json
import sqlite3
import threading
import unittest
from datetime import UTC, datetime
from unittest import mock

from sunderkey.authenticated_action_executor import (
    ACTION_EXECUTE,
    ActionExecutionCommand,
    ActionExecutionError,
    ActionExecutionReconciliationRequired,
    AdapterBinding,
    HttpPrimitiveActionAdapter,
    TerminalStatus,
    action_execute_authorization_intent_sha256,
    parse_action_execution_claim,
)
from sunderkey.errors import StoreConflictError, StoreIntegrityError
from sunderkey.identity import PrincipalOperation
from sunderkey.mission_store_action_executor import (
    ACTION_EXECUTION_RECONCILE,
    RECONCILIATION_INTENT_DOMAIN,
    ActionExecutionReconciliationIntent,
    MissionStoreAuthenticatedActionExecutionService,
    _parse_reconciliation_authorization,
    action_execution_reconciliation_authorization_intent_sha256,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.store import SCHEMA_VERSION, canonical_json, sha256_text

from . import test_mission_store_action_admission_phase195b as phase195b
from .test_store import remove_schema_v34_objects


class RecordingPrimitive:
    def __init__(
        self,
        *,
        raises: BaseException | None = None,
        release: threading.Event | None = None,
        entered: threading.Event | None = None,
        substitute_result: bool = False,
    ) -> None:
        self.raises = raises
        self.release = release
        self.entered = entered
        self.substitute_result = substitute_result
        self.calls = 0

    def __call__(self, request):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            self.release.wait(timeout=30)
        if self.raises is not None:
            raise self.raises
        document = dict(request)
        result = {
            "request_id": document["action_execution_request_id"],
            "request_sha256": document["action_execution_request_sha256"],
            "action_sha256": document["admission_receipt"]["action_sha256"],
            "adapter": dict(document["adapter"]),
            "outcome": "succeeded",
            "evidence_status": "complete",
            "cleanup_status": "complete",
            "restoration_status": "complete",
            "result_payload": {"status": "verified"},
            "resources_used": dict(document["reservation"]),
        }
        if self.substitute_result:
            result["request_sha256"] = "sha256:" + "0" * 64
        return result


class MissionStoreActionExecutorPhase196bTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase195b.MissionStoreActionAdmissionPhase195bTests.setUpClass()

    def setUp(self) -> None:
        fixture = phase195b.MissionStoreActionAdmissionPhase195bTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        (
            self.sources,
            _admission_command,
            self.resolution,
            _quorum,
            _request,
            self.receipt,
        ) = fixture._admit_complete_sources()
        resolution = self.resolution.to_dict()
        material = self.sources["material"].to_dict()
        self.binding = AdapterBinding(
            adapter_id=resolution["tool_artifact_ref"],
            adapter_kind="http",
            adapter_version=resolution["tool_exact_version"],
            adapter_build_sha256=resolution["tool_artifact_sha256"],
            deployment_binding_sha256=material["executor_deployment_sha256"],
        )
        self.primitive = RecordingPrimitive()
        self.adapter = HttpPrimitiveActionAdapter(self.binding, self.primitive)
        self.service = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            fixture.store,
            fixture.service,
            self.adapter,
            clock=lambda: fixture.root.now,
        )
        self.command = ActionExecutionCommand(
            receipt_id=self.receipt.receipt_id,
            idempotency_key_sha256=_canonical_sha256(
                {"execution": "phase196b-positive"}
            ),
        )
        self.request = self.service.prepare(self.command)
        self.assertion, self.authorization = self._authorization(
            self.request,
            marker="61",
            replay_label="phase196b-positive",
        )

    def _authorization(self, request, *, marker, replay_label):  # type: ignore[no-untyped-def]
        intent = action_execute_authorization_intent_sha256(request)
        replay_key = _canonical_sha256({"replay": replay_label})
        assertion = self.fixture._assertion(
            "admission",
            marker,
            PrincipalOperation.ACTION_EXECUTE,
            {
                "action_intent_sha256": intent,
                "idempotency_key_sha256": replay_key,
                "mission_id": self.fixture.mission_id,
                "principal_profile_id": phase195b.ADMISSION_PROFILE,
                "role": "admission_control",
            },
        )
        request_document = request.to_dict()
        receipt = request_document["admission_receipt"]
        state = request_document["authority_state"]
        return assertion, {
            "operation": ACTION_EXECUTE,
            "role": "admission_control",
            "principal_profile_id": assertion.profile_id,
            "principal_subject": assertion.subject,
            "assertion_issuer": assertion.issuer,
            "assertion_id": assertion.assertion_id,
            "assertion_sha256": sha256_text(canonical_json(assertion.to_dict())),
            "assertion_key_sha256": self.fixture.policy.key(
                assertion.key_id
            ).content_sha256,
            "trust_policy_sha256": self.fixture.policy.content_sha256,
            "scope_grant_sha256": assertion.scope_grant_sha256,
            "operation_intent_sha256": intent,
            "canonical_replay_key_sha256": replay_key,
            "tenant_id": state["tenant_id"],
            "mission_id": state["mission_id"],
            "scope_sha256": state["scope_sha256"],
            "target_sha256": state["target_sha256"],
            "action_sha256": state["action_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "request_sha256": request.request_sha256,
            "decision": "approved",
            "issued_at": "2026-07-30T10:13:00Z",
            "expires_at": "2026-07-30T10:20:00Z",
        }

    def _reconciliation_authority(
        self,
        intent: ActionExecutionReconciliationIntent,
        *,
        marker: str = "62",
        replay_label: str = "phase196b-reconciliation",
    ):  # type: ignore[no-untyped-def]
        document = intent.to_dict()
        intent_sha256 = action_execution_reconciliation_authorization_intent_sha256(
            intent
        )
        replay_key = _canonical_sha256({"reconciliation": replay_label})
        assertion = self.fixture._assertion(
            "control",
            marker,
            PrincipalOperation.ACTION_EXECUTION_RECONCILE,
            {
                "action_intent_sha256": intent_sha256,
                "idempotency_key_sha256": replay_key,
                "mission_id": self.fixture.mission_id,
                "principal_profile_id": self.fixture.control_profile,
                "role": "independent_control",
            },
            issued_at=document["prepared_at"],
            not_before=document["prepared_at"],
            expires_at=document["authority_expires_at"],
        )
        return assertion, {
            "operation": ACTION_EXECUTION_RECONCILE,
            "role": "independent_control",
            "principal_profile_id": assertion.profile_id,
            "principal_subject": assertion.subject,
            "assertion_issuer": assertion.issuer,
            "assertion_id": assertion.assertion_id,
            "assertion_sha256": assertion.content_sha256,
            "assertion_key_sha256": self.fixture.policy.key(
                assertion.key_id
            ).content_sha256,
            "trust_policy_sha256": self.fixture.policy.content_sha256,
            "scope_grant_sha256": assertion.scope_grant_sha256,
            "operation_intent_sha256": intent_sha256,
            "canonical_replay_key_sha256": replay_key,
            "tenant_id": document["tenant_id"],
            "mission_id": document["mission_id"],
            "request_id": document["request_id"],
            "request_sha256": document["request_sha256"],
            "claim_id": document["claim_id"],
            "claim_sha256": document["claim_sha256"],
            "reconciliation_intent_id": intent.reconciliation_intent_id,
            "reconciliation_intent_sha256": intent.reconciliation_intent_sha256,
            "decision": "approved",
            "issued_at": assertion.issued_at,
            "expires_at": assertion.expires_at,
        }

    def _reconcile(
        self,
        service: MissionStoreAuthenticatedActionExecutionService,
        request_id: str,
        *,
        reason_code: str = "claim_without_settlement",
        marker: str = "62",
        replay_label: str = "phase196b-reconciliation",
    ):  # type: ignore[no-untyped-def]
        intent = service.prepare_reconciliation(
            request_id,
            reason_code=reason_code,
            authority_expires_at="2026-07-30T10:29:00Z",
        )
        assertion, authorization = self._reconciliation_authority(
            intent,
            marker=marker,
            replay_label=replay_label,
        )
        return service.reconcile_claim(intent, assertion, authorization)

    @staticmethod
    def _rehash_reconciliation_intent(document):  # type: ignore[no-untyped-def]
        body = {
            field: value
            for field, value in document.items()
            if field
            not in {
                "reconciliation_intent_id",
                "reconciliation_intent_sha256",
            }
        }
        digest = _canonical_sha256(
            {"domain": RECONCILIATION_INTENT_DOMAIN, "record": body}
        )
        return {
            **body,
            "reconciliation_intent_id": (
                "AXI-" + digest.removeprefix("sha256:")[:32].upper()
            ),
            "reconciliation_intent_sha256": digest,
        }

    def test_production_service_rejects_caller_defined_adapter(self) -> None:
        with self.assertRaisesRegex(TypeError, "sealed repository capability"):
            MissionStoreAuthenticatedActionExecutionService(
                self.fixture.store,
                self.fixture.service,
                self.primitive,  # type: ignore[arg-type]
                clock=lambda: self.fixture.root.now,
            )

    def test_reference_adapter_implementation_is_immutable(self) -> None:
        with self.assertRaisesRegex(AttributeError, "immutable"):
            self.adapter._primitive = RecordingPrimitive()  # type: ignore[attr-defined]

    def test_replaced_primitive_is_rejected_before_dispatch(self) -> None:
        replacement = RecordingPrimitive()
        object.__setattr__(self.adapter, "_primitive", replacement)
        terminal = self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        document = terminal.to_dict()
        self.assertEqual(
            document["terminal_status"],
            TerminalStatus.PREDISPATCH_ABORTED.value,
        )
        self.assertEqual(document["adapter_call_count_status"], "exactly_zero")
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(replacement.calls, 0)
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_dispatch_attempts"
                ).fetchone()[0],
                0,
            )

    def test_replaced_primitive_after_dispatch_records_exact_zero_calls(self) -> None:
        replacement = RecordingPrimitive()
        original_commit = self.service._commit_dispatch_attempt

        def commit_then_replace(*args, **kwargs):  # type: ignore[no-untyped-def]
            original_commit(*args, **kwargs)
            object.__setattr__(self.adapter, "_primitive", replacement)

        self.service._commit_dispatch_attempt = commit_then_replace  # type: ignore[method-assign]
        terminal = self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        document = terminal.to_dict()
        self.assertEqual(
            document["terminal_status"],
            TerminalStatus.PREDISPATCH_ABORTED.value,
        )
        self.assertEqual(document["adapter_call_count"], 0)
        self.assertEqual(document["adapter_call_count_status"], "exactly_zero")
        self.assertEqual(
            document["charged_resources"],
            {field: 0 for field in document["charged_resources"]},
        )
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(replacement.calls, 0)

    def test_injected_cached_invocation_path_is_rejected_before_dispatch(self) -> None:
        malicious_calls = 0

        def malicious(request):  # type: ignore[no-untyped-def]
            nonlocal malicious_calls
            malicious_calls += 1
            return self.primitive(request)

        self.service._invoke_once = malicious  # type: ignore[attr-defined]
        terminal = self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        document = terminal.to_dict()
        self.assertEqual(
            document["terminal_status"],
            TerminalStatus.PREDISPATCH_ABORTED.value,
        )
        self.assertEqual(document["adapter_call_count_status"], "exactly_zero")
        self.assertEqual(malicious_calls, 0)
        self.assertEqual(self.primitive.calls, 0)
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_dispatch_attempts"
                ).fetchone()[0],
                0,
            )

    def test_complete_execution_replays_without_a_second_call_or_clock(self) -> None:
        terminal = self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            TerminalStatus.COMPLETED.value,
        )
        self.assertEqual(self.primitive.calls, 1)
        report = self.service.verify_store()
        self.assertEqual(report["terminal_count"], 1)

        def failing_clock():  # type: ignore[no-untyped-def]
            raise AssertionError("terminal replay must not read the clock")

        restarted = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            self.adapter,
            clock=failing_clock,
        )
        replay = restarted.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        self.assertEqual(replay.document_json, terminal.document_json)
        self.assertEqual(self.primitive.calls, 1)

    def test_base_exception_after_dispatch_full_charges_and_quarantines(self) -> None:
        primitive = RecordingPrimitive(raises=KeyboardInterrupt())
        adapter = HttpPrimitiveActionAdapter(self.binding, primitive)
        service = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            adapter,
            clock=lambda: self.fixture.root.now,
        )
        terminal = service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        document = terminal.to_dict()
        self.assertEqual(
            document["terminal_status"],
            TerminalStatus.INDETERMINATE_QUARANTINED.value,
        )
        self.assertEqual(
            document["charged_resources"],
            self.request.to_dict()["reservation"],
        )
        self.assertEqual(primitive.calls, 1)
        self.assertEqual(service.verify_store()["terminal_count"], 1)

    def test_substituted_result_full_charges_and_quarantines(self) -> None:
        primitive = RecordingPrimitive(substitute_result=True)
        adapter = HttpPrimitiveActionAdapter(self.binding, primitive)
        service = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            adapter,
            clock=lambda: self.fixture.root.now,
        )
        terminal = service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        document = terminal.to_dict()
        self.assertEqual(
            document["terminal_status"],
            TerminalStatus.INDETERMINATE_QUARANTINED.value,
        )
        self.assertEqual(
            document["charged_resources"],
            self.request.to_dict()["reservation"],
        )
        self.assertEqual(primitive.calls, 1)

    def test_terminal_build_failure_uses_independent_quarantine_builder(self) -> None:
        with mock.patch.object(
            self.service,
            "_build_terminal",
            side_effect=RuntimeError("terminal builder failed"),
        ):
            terminal = self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            TerminalStatus.INDETERMINATE_QUARANTINED.value,
        )
        self.assertEqual(self.primitive.calls, 1)

    def test_settlement_failure_rolls_back_and_quarantines_in_same_transaction(
        self,
    ) -> None:
        original = self.service._insert_terminal_and_settle
        calls = 0

        def fail_once(*args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("settlement failed")
            return original(*args, **kwargs)

        with mock.patch.object(
            self.service,
            "_insert_terminal_and_settle",
            side_effect=fail_once,
        ):
            terminal = self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            TerminalStatus.INDETERMINATE_QUARANTINED.value,
        )
        self.assertEqual(self.primitive.calls, 1)

    def test_clock_failure_after_dispatch_full_charges_and_quarantines(self) -> None:
        calls = 0

        def clock():  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            if calls >= 3:
                raise RuntimeError("clock unavailable")
            return self.fixture.root.now

        self.fixture.service._clock = clock
        terminal = self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            TerminalStatus.PREDISPATCH_ABORTED.value,
        )
        self.assertEqual(
            terminal.to_dict()["charged_resources"],
            {
                field: 0
                for field in terminal.to_dict()["charged_resources"]
            },
        )
        self.assertEqual(self.primitive.calls, 0)

    def test_reconciliation_contract_rejects_noncanonical_timestamps(self) -> None:
        def crash(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise SystemExit("simulated process loss")

        self.service._commit_dispatch_attempt = crash  # type: ignore[method-assign]
        self.service._quarantine = crash  # type: ignore[method-assign]
        with self.assertRaises(SystemExit):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.fixture.root.now = datetime(2026, 7, 30, 10, 20, tzinfo=UTC)
        intent = self.service.prepare_reconciliation(
            self.request.request_id,
            reason_code="claim_without_settlement",
            authority_expires_at="2026-07-30T10:29:00Z",
        )
        for field, invalid in (
            ("prepared_at", "2026-07-30T10:20:00+00:00"),
            ("authority_expires_at", "2026-07-30T10:29:00.000Z"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                ActionExecutionError,
                "canonical RFC3339 UTC",
            ):
                document = intent.to_dict()
                document[field] = invalid
                ActionExecutionReconciliationIntent.from_dict(
                    self._rehash_reconciliation_intent(document)
                )
        _assertion, authorization = self._reconciliation_authority(intent)
        for field, invalid in (
            ("issued_at", "2026-07-30 10:20:00Z"),
            ("expires_at", "2026-07-30T10:29:00.000Z"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                ActionExecutionError,
                "canonical RFC3339 UTC",
            ):
                substituted = dict(authorization)
                substituted[field] = invalid
                _parse_reconciliation_authorization(substituted)

    def test_crash_after_claim_is_reconciliation_only_on_restart(self) -> None:
        def crash(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise SystemExit("simulated process loss")

        self.service._commit_dispatch_attempt = crash  # type: ignore[method-assign]
        self.service._quarantine = crash  # type: ignore[method-assign]
        with self.assertRaises(SystemExit):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        restarted_primitive = RecordingPrimitive()
        restarted_adapter = HttpPrimitiveActionAdapter(
            self.binding,
            restarted_primitive,
        )
        restarted = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            restarted_adapter,
            clock=lambda: self.fixture.root.now,
        )
        with self.assertRaises(ActionExecutionReconciliationRequired):
            restarted.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.assertEqual(restarted_primitive.calls, 0)
        self.fixture.root.now = datetime(2026, 7, 30, 10, 20, tzinfo=UTC)
        terminal = self._reconcile(restarted, self.request.request_id)
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            TerminalStatus.PREDISPATCH_ABORTED.value,
        )
        self.assertEqual(
            terminal.to_dict()["adapter_call_count_status"],
            "exactly_zero",
        )
        self.assertEqual(
            terminal.to_dict()["charged_resources"],
            {field: 0 for field in self.request.to_dict()["reservation"]},
        )
        self.assertEqual(restarted_primitive.calls, 0)

    def test_crash_after_dispatch_commit_remains_unknown_and_never_redispatches(
        self,
    ) -> None:
        self.primitive.raises = SystemExit("simulated process loss")

        def crash(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise SystemExit("simulated process loss")

        self.service._quarantine_in_transaction = crash  # type: ignore[method-assign]
        with self.assertRaises(SystemExit):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        restarted_primitive = RecordingPrimitive()
        restarted_adapter = HttpPrimitiveActionAdapter(
            self.binding,
            restarted_primitive,
        )
        restarted = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            restarted_adapter,
            clock=lambda: self.fixture.root.now,
        )
        with self.assertRaises(ActionExecutionReconciliationRequired):
            restarted.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.fixture.root.now = datetime(2026, 7, 30, 10, 20, tzinfo=UTC)
        terminal = self._reconcile(restarted, self.request.request_id)
        document = terminal.to_dict()
        self.assertIsNone(document["adapter_call_count"])
        self.assertEqual(
            document["adapter_call_count_status"],
            "unknown_zero_or_one",
        )
        self.assertEqual(
            document["charged_resources"],
            self.request.to_dict()["reservation"],
        )
        self.assertEqual(restarted_primitive.calls, 0)

    def test_cross_operation_assertion_reuse_rolls_back_the_claim(self) -> None:
        wrong = self.fixture._assertion(
            "admission",
            "62",
            PrincipalOperation.ACTION_ADMIT,
            {
                "action_intent_sha256": self.authorization[
                    "operation_intent_sha256"
                ],
                "idempotency_key_sha256": self.authorization[
                    "canonical_replay_key_sha256"
                ],
                "mission_id": self.fixture.mission_id,
                "principal_profile_id": phase195b.ADMISSION_PROFILE,
                "role": "admission_control",
            },
        )
        with self.assertRaisesRegex(ActionExecutionError, "substituted"):
            self.service.execute(
                self.command,
                self.request,
                wrong,
                self.authorization,
            )
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_requests"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_admission_execution_consumptions"
                ).fetchone()[0],
                0,
            )

    def test_whole_store_rejects_orphan_admission_execution_consumption(self) -> None:
        execution_id = "EXE-PHASE196B-ORPHAN"
        claim_id = "ACL-PHASE196B-ORPHAN"
        execution_intent = _canonical_sha256(
            {"execution_id": execution_id, "receipt_id": self.receipt.receipt_id}
        )
        claim_sha256 = _canonical_sha256(
            {"claim_id": claim_id, "execution_intent_sha256": execution_intent}
        )
        receipt = self.receipt.to_dict()
        consumption_id = (
            "AEC-"
            + _canonical_sha256(
                {
                    "domain": "sunderkey.action-admission-execution-consumption.v1",
                    "execution_id": execution_id,
                    "execution_intent_sha256": execution_intent,
                    "claim_id": claim_id,
                    "claim_sha256": claim_sha256,
                    "receipt_id": self.receipt.receipt_id,
                    "receipt_sha256": self.receipt.receipt_sha256,
                }
            ).removeprefix("sha256:")[:32].upper()
        )
        with sqlite3.connect(self.fixture.root.path) as connection:
            custody = connection.execute(
                "SELECT custody_sha256 FROM action_admission_receipts "
                "WHERE receipt_id = ?",
                (self.receipt.receipt_id,),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO action_admission_execution_consumptions VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    consumption_id,
                    receipt["receipt_id"],
                    receipt["receipt_sha256"],
                    custody,
                    execution_id,
                    execution_intent,
                    claim_id,
                    claim_sha256,
                    "2026-07-30T10:13:03Z",
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "action_admission_execution_consumptions contains orphaned custody",
        ):
            self.service.verify_store()

    def test_two_services_cannot_dispatch_the_same_claim_twice(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        first_primitive = RecordingPrimitive(
            entered=entered,
            release=release,
        )
        first_adapter = HttpPrimitiveActionAdapter(
            self.binding,
            first_primitive,
        )
        first = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            first_adapter,
            clock=lambda: self.fixture.root.now,
        )
        second_primitive = RecordingPrimitive()
        second_adapter = HttpPrimitiveActionAdapter(
            self.binding,
            second_primitive,
        )
        second = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            second_adapter,
            clock=lambda: self.fixture.root.now,
        )
        outcome: list[object] = []

        def run_first() -> None:
            try:
                outcome.append(
                    first.execute(
                        self.command,
                        self.request,
                        self.assertion,
                        self.authorization,
                    )
                )
            except BaseException as exc:
                outcome.append(exc)

        worker = threading.Thread(target=run_first)
        worker.start()
        self.assertTrue(entered.wait(timeout=30))
        second_outcome: list[object] = []

        def run_second() -> None:
            try:
                second_outcome.append(
                    second.execute(
                        self.command,
                        self.request,
                        self.assertion,
                        self.authorization,
                    )
                )
            except BaseException as exc:
                second_outcome.append(exc)

        second_worker = threading.Thread(target=run_second)
        second_worker.start()
        self.assertTrue(second_worker.is_alive())
        release.set()
        worker.join(timeout=30)
        second_worker.join(timeout=30)
        self.assertFalse(worker.is_alive())
        self.assertFalse(second_worker.is_alive())
        self.assertEqual(first_primitive.calls, 1)
        self.assertEqual(second_primitive.calls, 0)
        self.assertEqual(len(outcome), 1)
        self.assertEqual(len(second_outcome), 1)
        self.assertFalse(isinstance(outcome[0], BaseException))
        self.assertFalse(isinstance(second_outcome[0], BaseException))
        self.assertEqual(
            outcome[0].document_json,  # type: ignore[union-attr]
            second_outcome[0].document_json,  # type: ignore[union-attr]
        )

    def test_reconciliation_blocks_while_reference_invocation_is_in_flight(
        self,
    ) -> None:
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        primitive = RecordingPrimitive(entered=entered, release=release)
        service = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            HttpPrimitiveActionAdapter(self.binding, primitive),
            clock=lambda: self.fixture.root.now,
        )
        execution_outcome: list[object] = []
        reconciliation_outcome: list[object] = []

        def run_execution() -> None:
            try:
                execution_outcome.append(
                    service.execute(
                        self.command,
                        self.request,
                        self.assertion,
                        self.authorization,
                    )
                )
            except BaseException as exc:
                execution_outcome.append(exc)

        worker = threading.Thread(target=run_execution)
        worker.start()
        self.assertTrue(entered.wait(timeout=30), repr(execution_outcome))
        self.fixture.root.now = datetime(2026, 7, 30, 10, 20, tzinfo=UTC)

        def run_reconciliation() -> None:
            try:
                reconciliation_outcome.append(
                    self._reconcile(service, self.request.request_id)
                )
            except BaseException as exc:
                reconciliation_outcome.append(exc)

        reconciler = threading.Thread(target=run_reconciliation)
        reconciler.start()
        self.assertTrue(reconciler.is_alive())
        release.set()
        worker.join(timeout=30)
        reconciler.join(timeout=30)
        self.assertFalse(worker.is_alive())
        self.assertFalse(reconciler.is_alive())
        self.assertEqual(primitive.calls, 1)
        self.assertEqual(len(execution_outcome), 1)
        self.assertEqual(len(reconciliation_outcome), 1)
        self.assertFalse(
            isinstance(execution_outcome[0], BaseException),
            repr(execution_outcome[0]),
        )
        self.assertIsInstance(
            reconciliation_outcome[0],
            StoreConflictError,
        )

    def test_expired_reconciliation_wins_after_dispatch_before_invocation_lock(
        self,
    ) -> None:
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        original = self.service._invoke_and_settle
        execution_outcome: list[object] = []

        def pause_before_invocation(*args, **kwargs):  # type: ignore[no-untyped-def]
            entered.set()
            if not release.wait(timeout=30):
                raise RuntimeError("test invocation pause timed out")
            return original(*args, **kwargs)

        self.service._invoke_and_settle = pause_before_invocation  # type: ignore[method-assign]

        def run_execution() -> None:
            try:
                execution_outcome.append(
                    self.service.execute(
                        self.command,
                        self.request,
                        self.assertion,
                        self.authorization,
                    )
                )
            except BaseException as exc:
                execution_outcome.append(exc)

        worker = threading.Thread(target=run_execution)
        worker.start()
        self.assertTrue(entered.wait(timeout=30))
        self.fixture.root.now = datetime(2026, 7, 30, 10, 20, tzinfo=UTC)
        reconciled = self._reconcile(self.service, self.request.request_id)
        release.set()
        worker.join(timeout=30)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(len(execution_outcome), 1)
        self.assertIsInstance(
            execution_outcome[0],
            ActionExecutionError,
        )
        self.assertEqual(
            str(execution_outcome[0]),
            "Action admission is not current",
        )
        self.assertEqual(
            reconciled.to_dict()["terminal_status"],
            TerminalStatus.PREDISPATCH_ABORTED.value,
        )
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = ?",
                    ("action_execution_terminal_replay_for_use",),
                ).fetchone()[0],
                0,
            )

    def test_reentrant_store_write_is_quarantined_with_one_reference_call(
        self,
    ) -> None:
        calls = 0

        def reentrant(request):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            with self.fixture.store._write_connection():
                raise AssertionError("nested write unexpectedly acquired")

        adapter = HttpPrimitiveActionAdapter(self.binding, reentrant)
        service = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            adapter,
            clock=lambda: self.fixture.root.now,
        )
        terminal = service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        self.assertEqual(calls, 1)
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            TerminalStatus.INDETERMINATE_QUARANTINED.value,
        )
        self.assertEqual(
            terminal.to_dict()["charged_resources"],
            self.request.to_dict()["reservation"],
        )

    def test_expired_claim_reconciliation_wins_before_dispatch_atomically(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        original_commit = self.service._commit_dispatch_attempt
        outcome: list[object] = []

        def pause_before_dispatch(*args, **kwargs):  # type: ignore[no-untyped-def]
            entered.set()
            if not release.wait(timeout=30):
                raise RuntimeError("test dispatch pause timed out")
            return original_commit(*args, **kwargs)

        self.service._commit_dispatch_attempt = pause_before_dispatch  # type: ignore[method-assign]

        def run_execution() -> None:
            try:
                outcome.append(
                    self.service.execute(
                        self.command,
                        self.request,
                        self.assertion,
                        self.authorization,
                    )
                )
            except BaseException as exc:
                outcome.append(exc)

        worker = threading.Thread(target=run_execution)
        worker.start()
        self.assertTrue(entered.wait(timeout=30))
        self.fixture.root.now = datetime(2026, 7, 30, 10, 20, tzinfo=UTC)
        reconciler_primitive = RecordingPrimitive()
        reconciler = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            HttpPrimitiveActionAdapter(self.binding, reconciler_primitive),
            clock=lambda: self.fixture.root.now,
        )
        reconciled = self._reconcile(reconciler, self.request.request_id)
        release.set()
        worker.join(timeout=30)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(
            outcome[0],
            ActionExecutionError,
            repr(outcome[0]),
        )
        self.assertEqual(str(outcome[0]), "Action admission is not current")
        self.assertEqual(
            reconciled.to_dict()["terminal_status"],
            TerminalStatus.PREDISPATCH_ABORTED.value,
        )
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(reconciler_primitive.calls, 0)
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_dispatch_attempts"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = ?",
                    ("action_execution_terminal_replay_for_use",),
                ).fetchone()[0],
                0,
            )

    def test_fresh_authority_concurrent_terminal_replay_records_live_use(
        self,
    ) -> None:
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        original_invoke = self.service._invoke_and_settle
        outcome: list[object] = []

        def pause_before_invocation(*args, **kwargs):  # type: ignore[no-untyped-def]
            entered.set()
            if not release.wait(timeout=30):
                raise RuntimeError("test invocation pause timed out")
            return original_invoke(*args, **kwargs)

        self.service._invoke_and_settle = pause_before_invocation  # type: ignore[method-assign]

        def run_execution() -> None:
            try:
                outcome.append(
                    self.service.execute(
                        self.command,
                        self.request,
                        self.assertion,
                        self.authorization,
                    )
                )
            except BaseException as exc:
                outcome.append(exc)

        worker = threading.Thread(target=run_execution)
        worker.start()
        self.assertTrue(entered.wait(timeout=30))
        with self.fixture.store._read_connection() as connection:
            request, claim = self.service._stored_request_claim(
                connection,
                self.request.request_id,
            )
            dispatch_id = connection.execute(
                "SELECT dispatch_id FROM action_execution_claims "
                "WHERE request_id = ?",
                (self.request.request_id,),
            ).fetchone()["dispatch_id"]
        concurrent_terminal = self.service._quarantine(
            request,
            claim,
            dispatch_id,
            "concurrent_fresh_terminal",
            invocation_known=False,
        )
        release.set()
        worker.join(timeout=30)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertFalse(isinstance(outcome[0], BaseException), repr(outcome[0]))
        self.assertEqual(
            outcome[0].to_dict(),  # type: ignore[union-attr]
            concurrent_terminal.to_dict(),  # type: ignore[union-attr]
        )
        self.assertEqual(self.primitive.calls, 0)
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = ?",
                    ("action_execution_terminal_replay_for_use",),
                ).fetchone()[0],
                1,
            )

    def test_whole_store_detects_custody_hash_substitution(self) -> None:
        self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        with sqlite3.connect(self.fixture.root.path) as connection:
            connection.execute("DROP TRIGGER action_execution_requests_immutable")
            connection.execute(
                "UPDATE action_execution_requests SET custody_sha256 = ?",
                ("sha256:" + "0" * 64,),
            )
            connection.execute(
                """
                CREATE TRIGGER action_execution_requests_immutable
                BEFORE UPDATE ON action_execution_requests BEGIN
                    SELECT RAISE(ABORT, 'action execution request is immutable');
                END
                """
            )
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "custody hash"):
            self.service.verify_store()
        with self.assertRaisesRegex(StoreIntegrityError, "custody hash"):
            self.fixture.store.verify_store(self.fixture.registry)
        with self.assertRaisesRegex(StoreIntegrityError, "custody hash"):
            self.fixture.store.verify_mission(
                self.fixture.registry,
                self.fixture.mission_id,
            )

    def test_reconcile_replay_rejects_closure_tamper(self) -> None:
        self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        with sqlite3.connect(self.fixture.root.path) as connection:
            connection.execute("DROP TRIGGER action_execution_closures_immutable")
            connection.execute(
                "UPDATE action_execution_closures SET evidence_status = 'unknown'"
            )
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "closure"):
            self.service.verify_store()

    def test_reconcile_replay_rejects_terminal_budget_event_tamper(self) -> None:
        self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        with sqlite3.connect(self.fixture.root.path) as connection:
            connection.execute("DROP TRIGGER action_budget_account_events_immutable")
            connection.execute(
                "UPDATE action_budget_account_events SET dispatch_id = ? "
                "WHERE event_kind != 'reserve'",
                ("AXD-" + "F" * 32,),
            )
            connection.commit()
        with self.assertRaises(StoreIntegrityError):
            self.service.verify_store()

    def test_whole_store_rejects_consistent_dispatch_id_replacement(self) -> None:
        self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        replacement = "AXD-" + "A" * 32
        with sqlite3.connect(self.fixture.root.path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = OFF")
            tables = (
                "action_execution_claims",
                "action_execution_dispatch_attempts",
                "action_execution_terminals",
                "action_budget_account_events",
                "action_budget_account_heads",
            )
            triggers = connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                f"AND tbl_name IN ({','.join('?' for _ in tables)}) AND sql IS NOT NULL",
                tables,
            ).fetchall()
            for trigger in triggers:
                connection.execute(f'DROP TRIGGER "{trigger["name"]}"')
            dispatch = connection.execute(
                "SELECT * FROM action_execution_dispatch_attempts"
            ).fetchone()
            dispatch_document = json.loads(dispatch["dispatch_json"])
            dispatch_document["dispatch_id"] = replacement
            dispatch_sha256 = _canonical_sha256(
                {
                    "domain": "sunderkey.authenticated-action-dispatch-attempt.v1",
                    "record": dispatch_document,
                }
            )
            terminal_event = connection.execute(
                "SELECT * FROM action_budget_account_events "
                "WHERE event_kind != 'reserve'"
            ).fetchone()
            event_body = {
                "account_id": terminal_event["account_id"],
                "budget_revision_id": terminal_event["budget_revision_id"],
                "budget_revision_sha256": terminal_event[
                    "budget_revision_sha256"
                ],
                "claim_id": terminal_event["claim_id"],
                "claim_sha256": terminal_event["claim_sha256"],
                "dispatch_id": replacement,
                "event_kind": terminal_event["event_kind"],
                "event_sequence": terminal_event["event_sequence"],
                "execution_id": terminal_event["execution_id"],
                "execution_intent_sha256": terminal_event[
                    "execution_intent_sha256"
                ],
                "idempotency_key_sha256": terminal_event[
                    "idempotency_key_sha256"
                ],
                "previous_event_sha256": terminal_event[
                    "previous_event_sha256"
                ],
                "receipt_id": terminal_event["receipt_id"],
                "recorded_at": terminal_event["recorded_at"],
                "reservation_id": terminal_event["reservation_id"],
                "reservation_sha256": terminal_event["reservation_sha256"],
                "resources": json.loads(terminal_event["resources_json"]),
            }
            event_sha256 = _canonical_sha256(
                {
                    "domain": "sunderkey.action-budget-account-event.v1",
                    "event": event_body,
                }
            )
            event_id = "ABE-" + event_sha256.removeprefix("sha256:")[:32].upper()
            connection.execute(
                "UPDATE action_execution_claims SET dispatch_id = ?",
                (replacement,),
            )
            connection.execute(
                "UPDATE action_execution_dispatch_attempts SET dispatch_id = ?, "
                "dispatch_sha256 = ?, dispatch_json = ?",
                (replacement, dispatch_sha256, canonical_json(dispatch_document)),
            )
            connection.execute(
                "UPDATE action_execution_terminals SET dispatch_id = ?",
                (replacement,),
            )
            connection.execute(
                "UPDATE action_budget_account_events SET event_id = ?, "
                "event_sha256 = ?, dispatch_id = ? WHERE event_kind != 'reserve'",
                (event_id, event_sha256, replacement),
            )
            connection.execute(
                "UPDATE action_budget_account_heads SET event_head_sha256 = ?",
                (event_sha256,),
            )
            for trigger in triggers:
                connection.execute(trigger["sql"])
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "claim columns"):
            self.service.verify_store()

    def _tamper_dispatch_duplicate(self, field: str) -> None:
        self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        with sqlite3.connect(self.fixture.root.path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = OFF")
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name = 'action_execution_dispatch_attempts_immutable'"
            ).fetchone()["sql"]
            connection.execute(
                "DROP TRIGGER action_execution_dispatch_attempts_immutable"
            )
            if field == "dispatch_json_id":
                row = connection.execute(
                    "SELECT dispatch_json FROM action_execution_dispatch_attempts"
                ).fetchone()
                document = json.loads(row["dispatch_json"])
                document["dispatch_id"] = "AXD-" + "B" * 32
                digest = _canonical_sha256(
                    {
                        "domain": "sunderkey.authenticated-action-dispatch-attempt.v1",
                        "record": document,
                    }
                )
                connection.execute(
                    "UPDATE action_execution_dispatch_attempts SET "
                    "dispatch_json = ?, dispatch_sha256 = ?",
                    (canonical_json(document), digest),
                )
            elif field == "row_claim_id":
                connection.execute(
                    "UPDATE action_execution_dispatch_attempts SET claim_id = ?",
                    ("AXC-" + "C" * 32,),
                )
            else:
                connection.execute(
                    "UPDATE action_execution_dispatch_attempts SET "
                    "adapter_binding_sha256 = ?",
                    ("sha256:" + "0" * 64,),
                )
            connection.execute(trigger)
            connection.commit()

    def test_whole_store_rejects_dispatch_json_id_substitution(self) -> None:
        self._tamper_dispatch_duplicate("dispatch_json_id")
        with self.assertRaisesRegex(StoreIntegrityError, "[Dd]ispatch attempt custody"):
            self.service.verify_store()

    def test_whole_store_rejects_dispatch_claim_id_substitution(self) -> None:
        self._tamper_dispatch_duplicate("row_claim_id")
        with self.assertRaisesRegex(StoreIntegrityError, "[Dd]ispatch attempt custody"):
            self.service.verify_store()

    def test_whole_store_rejects_dispatch_adapter_binding_substitution(self) -> None:
        self._tamper_dispatch_duplicate("row_adapter_binding")
        with self.assertRaisesRegex(StoreIntegrityError, "[Dd]ispatch attempt custody"):
            self.service.verify_store()

    def test_foreign_current_schema_abort_helper_cannot_commit_partial_rows(
        self,
    ) -> None:
        def crash(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise SystemExit("simulated process loss")

        self.service._commit_dispatch_attempt = crash  # type: ignore[method-assign]
        self.service._quarantine = crash  # type: ignore[method-assign]
        with self.assertRaises(SystemExit):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        foreign_path = self.fixture.root.path.with_name(
            "foreign-current-schema.sqlite3"
        )
        self.addCleanup(foreign_path.unlink, missing_ok=True)
        source = sqlite3.connect(self.fixture.root.path)
        target = sqlite3.connect(foreign_path)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        foreign = sqlite3.connect(foreign_path, isolation_level=None)
        try:
            foreign.row_factory = sqlite3.Row
            foreign.execute("BEGIN IMMEDIATE")
            claim = parse_action_execution_claim(
                json.loads(
                    foreign.execute(
                        "SELECT claim_json FROM action_execution_claims"
                    ).fetchone()["claim_json"]
                )
            )
            with self.assertRaisesRegex(
                StoreIntegrityError,
                "owned current-schema",
            ):
                self.service._quarantine_in_transaction(
                    foreign,
                    self.request,
                    claim,
                    foreign.execute(
                        "SELECT dispatch_id FROM action_execution_claims"
                    ).fetchone()["dispatch_id"],
                    "foreign_connection_rejected",
                    invocation_known=False,
                    settled_at=claim.to_dict()["claimed_at"],
                )
            foreign.execute("COMMIT")
            for table in (
                "action_execution_predispatch_aborts",
                "action_execution_terminals",
                "action_execution_closures",
            ):
                self.assertEqual(
                    foreign.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    0,
                )
        finally:
            foreign.close()

    def test_execution_custody_is_immutable_and_strictly_typed(self) -> None:
        self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        updates = {
            "action_execution_requests": "prepared_at",
            "action_execution_claims": "claimed_at",
            "action_execution_authority_consumptions": "consumed_at",
            "action_execution_reservations": "reserved_at",
            "action_execution_dispatch_attempts": "attempted_at",
            "action_execution_terminals": "settled_at",
            "action_execution_closures": "closed_at",
        }
        with sqlite3.connect(self.fixture.root.path) as connection:
            for table, column in updates.items():
                with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(f"UPDATE {table} SET {column} = {column}")
                connection.rollback()
            connection.execute("DROP TRIGGER action_execution_terminals_immutable")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE action_execution_terminals "
                    "SET rate_units_charged = 1.5"
                )
            connection.rollback()
            connection.execute(
                """
                CREATE TRIGGER action_execution_terminals_immutable
                BEFORE UPDATE ON action_execution_terminals BEGIN
                    SELECT RAISE(ABORT, 'action execution terminal is immutable');
                END
                """
            )
            connection.commit()
        self.assertEqual(self.service.verify_store()["terminal_count"], 1)

    def test_v33_to_current_migration_adds_empty_execution_custody(self) -> None:
        with sqlite3.connect(self.fixture.root.path) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v34_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '33' WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 33")
            connection.commit()
        backup = self.fixture.root.path.with_name("phase196b-v33-backup.sqlite3")
        report = self.fixture.store.migrate(self.fixture.registry, backup)
        self.assertEqual(
            (report.source_version, report.target_version),
            (33, SCHEMA_VERSION),
        )
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_requests"
                ).fetchone()[0],
                0,
            )


if __name__ == "__main__":
    unittest.main()
