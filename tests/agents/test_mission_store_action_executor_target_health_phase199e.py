"""Phase 199E execution target-health gate integration tests."""

from __future__ import annotations

import json
import sqlite3
import unittest
from dataclasses import replace
from datetime import UTC, timedelta
from unittest import mock

from sunderkey.action_target_health_gate_use import (
    ActionTargetHealthGateUseKind,
    verify_action_target_health_gate_use_store,
)
from sunderkey.authenticated_action_executor import (
    ActionExecutionCommand,
    ActionExecutionError,
    ActionExecutionReconciliationRequired,
    TerminalStatus,
)
from sunderkey.authorized_target_health_runtime import TargetHealthStatus
from sunderkey.mission_store_action_executor import (
    MissionStoreAuthenticatedActionExecutionService,
    verify_authenticated_action_execution_store,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.store import (
    EXPECTED_SCHEMA_MANIFEST_V34,
    EXPECTED_SCHEMA_MANIFEST_V35,
    EXPECTED_SCHEMA_MANIFEST_V36,
    _schema_manifest,
)
from sunderkey.target_health_gate_contracts import (
    TargetHealthGateState,
    execution_binding_sha256,
)

from . import test_mission_store_action_admission_phase195b as phase195b
from . import test_mission_store_action_executor_phase196b as phase196b
from .test_store import (
    remove_schema_v35_objects,
    remove_schema_v36_objects,
    remove_schema_v37_objects,
)


class MissionStoreActionExecutorTargetHealthPhase199ETests(unittest.TestCase):
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
        self.binding = phase196b.AdapterBinding(
            adapter_id=resolution["tool_artifact_ref"],
            adapter_kind="http",
            adapter_version=resolution["tool_exact_version"],
            adapter_build_sha256=resolution["tool_artifact_sha256"],
            deployment_binding_sha256=material["executor_deployment_sha256"],
        )
        self.primitive = phase196b.RecordingPrimitive()
        self.adapter = phase196b.HttpPrimitiveActionAdapter(
            self.binding,
            self.primitive,
        )
        self.service = (
            MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
                fixture.store,
                fixture.service,
                self.adapter,
                clock=lambda: fixture.root.now,
            )
        )
        self.command = ActionExecutionCommand(
            receipt_id=self.receipt.receipt_id,
            idempotency_key_sha256=_canonical_sha256(
                {"execution": "phase199e"}
            ),
        )
        self.request = self.service.prepare(self.command)
        helper = phase196b.MissionStoreActionExecutorPhase196bTests(
            methodName="runTest"
        )
        helper.fixture = fixture
        self.assertion, self.authorization = helper._authorization(
            self.request,
            marker="71",
            replay_label="phase199e",
        )
        self.health_binding = fixture.service._target_health_binding_from_material(
            self.sources["material"]
        )

    def _append_health(self, *, healthy: bool) -> None:
        binding_sha256 = execution_binding_sha256(self.health_binding)
        current = self.fixture.health_envelopes[binding_sha256]
        policy = self.fixture.health_policies[binding_sha256]
        self.fixture.root.now += timedelta(seconds=1)
        observed_at = self.fixture.root.now.astimezone(UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        receipt = phase195b._healthy_target_receipt(
            self.health_binding,
            observed_at,
        )
        if not healthy:
            receipt = replace(
                receipt,
                status=TargetHealthStatus.REJECTED,
                reason="missing_attestation",
                overall_health=None,
                safety_attestation=None,
                safety_attestation_sha256=None,
                budget_state=None,
                budget_state_sha256=None,
                source_receipts=(),
                observations=(),
                source_validation_performed=False,
                receipt_id="",
                receipt_sha256="",
            )
        receipt = replace(
            receipt,
            monotonic_tick=current.receipt.monotonic_tick + 1,
            receipt_id="",
            receipt_sha256="",
        )
        envelope = self.fixture.health_custody_factory.make_envelope(
            policy,
            sequence=current.sequence + 1,
            predecessor=current,
            observed_at=observed_at,
            monotonic_tick=receipt.monotonic_tick,
            receipt=receipt,
        )
        self.fixture.health_custody.append_envelope(envelope)
        self.fixture.health_envelopes[binding_sha256] = envelope

    def _use_counts(self) -> dict[str, int]:
        with self.fixture.store._read_connection() as connection:
            return {
                row[0]: row[1]
                for row in connection.execute(
                    "SELECT use_kind, COUNT(*) FROM "
                    "action_target_health_gate_uses GROUP BY use_kind"
                ).fetchall()
            }

    def _reconcile_after_committed_invocation_crash(self) -> None:
        original = self.service._commit_invocation_authorization

        def authorize_then_crash(*args, **kwargs):  # type: ignore[no-untyped-def]
            result = original(*args, **kwargs)
            self.assertIsNone(result)
            raise RuntimeError("crash after invocation authorization")

        with mock.patch.object(
            self.service,
            "_commit_invocation_authorization",
            side_effect=authorize_then_crash,
        ), self.assertRaisesRegex(RuntimeError, "crash after"):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.fixture.root.now = phase196b.datetime(
            2026,
            7,
            30,
            10,
            20,
            tzinfo=UTC,
        )
        helper = phase196b.MissionStoreActionExecutorPhase196bTests(
            methodName="runTest"
        )
        helper.fixture = self.fixture
        helper._reconcile(self.service, self.request.request_id)

    def test_claim_dispatch_and_terminal_replay_use_fresh_decisions(self) -> None:
        terminal = self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        counts = self._use_counts()
        self.assertEqual(
            counts[ActionTargetHealthGateUseKind.ACTION_EXECUTION_CLAIM.value],
            1,
        )
        self.assertEqual(
            counts[ActionTargetHealthGateUseKind.ACTION_EXECUTION_DISPATCH.value],
            1,
        )
        replay = self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        self.assertEqual(replay, terminal)
        self.assertEqual(self.primitive.calls, 1)
        self.assertEqual(
            self._use_counts()[
                ActionTargetHealthGateUseKind
                .ACTION_EXECUTION_TERMINAL_REPLAY_FOR_USE.value
            ],
            1,
        )

    def test_adverse_claim_commits_pause_without_execution_mutation(self) -> None:
        self._append_health(healthy=False)
        with self.assertRaisesRegex(ActionExecutionError, "claim"):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.assertEqual(self.primitive.calls, 0)
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_requests"
                ).fetchone()[0],
                0,
            )
        self.assertEqual(
            self.fixture.health_gate.load_head(
                self.health_binding
            ).latch_state,
            TargetHealthGateState.PAUSED,
        )

    def test_adverse_dispatch_commits_pause_and_zero_call_terminal(self) -> None:
        original = self.service._commit_dispatch_attempt
        causal_times: list[str] = []

        def turn_adverse(*args, **kwargs):  # type: ignore[no-untyped-def]
            self._append_health(healthy=False)
            result = original(*args, **kwargs)
            causal_times.append(
                self.fixture.health_gate.load_head(
                    self.health_binding
                ).updated_at
            )
            self.fixture.root.now -= timedelta(minutes=1)
            return result

        with mock.patch.object(
            self.service,
            "_commit_dispatch_attempt",
            side_effect=turn_adverse,
        ):
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
        self.assertEqual(terminal.to_dict()["adapter_call_count"], 0)
        self.assertEqual(self.primitive.calls, 0)
        counts = self._use_counts()
        self.assertEqual(
            counts[ActionTargetHealthGateUseKind.ACTION_EXECUTION_CLAIM.value],
            1,
        )
        self.assertNotIn(
            ActionTargetHealthGateUseKind.ACTION_EXECUTION_DISPATCH.value,
            counts,
        )
        with self.fixture.store._read_connection() as connection:
            settled_at = connection.execute(
                "SELECT settled_at FROM action_execution_terminals"
            ).fetchone()[0]
        self.assertGreaterEqual(settled_at, causal_times[0])

    def test_collector_failure_rolls_back_claim_and_health_mutation(self) -> None:
        with mock.patch.object(
            self.fixture.health_gate,
            "observe_current_in_transaction",
            side_effect=RuntimeError("collector failed"),
        ), self.assertRaisesRegex(RuntimeError, "collector failed"):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_requests"
                ).fetchone()[0],
                0,
            )

    def test_external_health_change_after_dispatch_does_not_block_settlement(
        self,
    ) -> None:
        def change_after_call(request):  # type: ignore[no-untyped-def]
            self._append_health(healthy=False)
            return phase196b.RecordingPrimitive()(request)

        primitive = phase196b.RecordingPrimitive()
        primitive.__call__ = change_after_call  # type: ignore[method-assign]
        adapter = phase196b.HttpPrimitiveActionAdapter(self.binding, change_after_call)
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
        self.assertEqual(
            terminal.to_dict()["terminal_status"],
            TerminalStatus.COMPLETED.value,
        )

    def test_adverse_preinvocation_commits_exact_zero_terminal(self) -> None:
        original = self.service._commit_invocation_authorization

        def turn_adverse(*args, **kwargs):  # type: ignore[no-untyped-def]
            self._append_health(healthy=False)
            result = original(*args, **kwargs)
            self.fixture.root.now += timedelta(seconds=1)
            return result

        with mock.patch.object(
            self.service,
            "_commit_invocation_authorization",
            side_effect=turn_adverse,
        ):
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
        self.assertEqual(terminal.to_dict()["adapter_call_count"], 0)
        self.assertEqual(self.primitive.calls, 0)
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM "
                    "action_execution_preinvocation_aborts"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM "
                    "action_execution_predispatch_aborts"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = 'action_execution_invocation'"
                ).fetchone()[0],
                0,
            )
        self.service.verify_store()

    def test_adverse_preinvocation_pause_survives_settlement_failure(self) -> None:
        original = self.service._commit_invocation_authorization

        def turn_adverse(*args, **kwargs):  # type: ignore[no-untyped-def]
            self._append_health(healthy=False)
            return original(*args, **kwargs)

        with mock.patch.object(
            self.service,
            "_commit_invocation_authorization",
            side_effect=turn_adverse,
        ), mock.patch.object(
            self.service,
            "_quarantine_in_transaction",
            side_effect=RuntimeError("settlement boom"),
        ), self.assertRaisesRegex(RuntimeError, "settlement boom"):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(
            self.fixture.health_gate.load_head(
                self.health_binding
            ).latch_state,
            TargetHealthGateState.PAUSED,
        )
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_dispatch_attempts"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_preinvocation_aborts"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_execution_terminals"
                ).fetchone()[0],
                0,
            )
        self.service.verify_store()

    def test_adverse_concurrent_terminal_before_invocation_denies_replay(
        self,
    ) -> None:
        original = self.service._invoke_and_settle

        def terminal_then_adverse(
            request, claim, dispatch_id, reservation  # type: ignore[no-untyped-def]
        ):
            self.service._quarantine(
                request,
                claim,
                dispatch_id,
                "concurrent_terminal_before_invocation",
                invocation_known=False,
            )
            self._append_health(healthy=False)
            return original(request, claim, dispatch_id, reservation)

        with mock.patch.object(
            self.service,
            "_invoke_and_settle",
            side_effect=terminal_then_adverse,
        ), self.assertRaisesRegex(ActionExecutionError, "terminal replay"):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(
            self.fixture.health_gate.load_head(
                self.health_binding
            ).latch_state,
            TargetHealthGateState.PAUSED,
        )
        counts = self._use_counts()
        self.assertNotIn(
            ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION.value,
            counts,
        )
        self.assertNotIn(
            ActionTargetHealthGateUseKind
            .ACTION_EXECUTION_TERMINAL_REPLAY_FOR_USE.value,
            counts,
        )
        self.service.verify_store()

    def test_adverse_concurrent_terminal_after_invocation_use_denies_replay(
        self,
    ) -> None:
        original = self.service._commit_invocation_authorization

        def authorize_then_terminal(
            request, claim, dispatch_id  # type: ignore[no-untyped-def]
        ):
            result = original(request, claim, dispatch_id)
            self.assertIsNone(result)
            self.service._quarantine(
                request,
                claim,
                dispatch_id,
                "concurrent_terminal_after_invocation",
                invocation_known=False,
            )
            self._append_health(healthy=False)
            return result

        with mock.patch.object(
            self.service,
            "_commit_invocation_authorization",
            side_effect=authorize_then_terminal,
        ), self.assertRaisesRegex(ActionExecutionError, "terminal replay"):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(
            self.fixture.health_gate.load_head(
                self.health_binding
            ).latch_state,
            TargetHealthGateState.PAUSED,
        )
        counts = self._use_counts()
        self.assertEqual(
            counts[ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION.value],
            1,
        )
        self.assertNotIn(
            ActionTargetHealthGateUseKind
            .ACTION_EXECUTION_TERMINAL_REPLAY_FOR_USE.value,
            counts,
        )
        self.service.verify_store()

    def test_committed_invocation_is_visible_before_adapter_call(self) -> None:
        observed_counts: list[int] = []
        primitive = phase196b.RecordingPrimitive()

        def inspect_before_call(request):  # type: ignore[no-untyped-def]
            with self.fixture.store._read_connection() as connection:
                observed_counts.append(
                    int(
                        connection.execute(
                            "SELECT COUNT(*) FROM "
                            "action_target_health_gate_uses "
                            "WHERE use_kind = 'action_execution_invocation'"
                        ).fetchone()[0]
                    )
                )
            return primitive(request)

        service = MissionStoreAuthenticatedActionExecutionService._reference_for_tests(
            self.fixture.store,
            self.fixture.service,
            phase196b.HttpPrimitiveActionAdapter(
                self.binding,
                inspect_before_call,
            ),
            clock=lambda: self.fixture.root.now,
        )
        service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        self.assertEqual(observed_counts, [1])
        self.assertEqual(primitive.calls, 1)

    def test_health_advance_after_authorization_aborts_without_call(self) -> None:
        original = self.service._commit_invocation_authorization
        causal_times: list[str] = []

        def authorize_then_pause(*args, **kwargs):  # type: ignore[no-untyped-def]
            result = original(*args, **kwargs)
            self._append_health(healthy=False)
            self.fixture.health_gate.observe_current(self.health_binding)
            causal_times.append(
                self.fixture.health_gate.load_head(
                    self.health_binding
                ).updated_at
            )
            self.fixture.root.now -= timedelta(minutes=1)
            return result

        with mock.patch.object(
            self.service,
            "_commit_invocation_authorization",
            side_effect=authorize_then_pause,
        ):
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
        self.assertEqual(self.primitive.calls, 0)
        with self.fixture.store._read_connection() as connection:
            row = connection.execute(
                "SELECT invocation_use_id, health_decision_json, aborted_at "
                "FROM action_execution_preinvocation_aborts"
            ).fetchone()
            self.assertIsNotNone(row[0])
            self.assertIsNotNone(row[1])
            terminal_time = connection.execute(
                "SELECT settled_at FROM action_execution_terminals"
            ).fetchone()[0]
            self.assertGreaterEqual(row[2], causal_times[0])
            self.assertGreaterEqual(terminal_time, causal_times[0])
        self.service.verify_store()

    def test_crash_after_invocation_authorization_never_redispatches(self) -> None:
        original = self.service._commit_invocation_authorization

        def authorize_then_crash(*args, **kwargs):  # type: ignore[no-untyped-def]
            result = original(*args, **kwargs)
            self.assertIsNone(result)
            raise RuntimeError("crash after invocation authorization")

        with mock.patch.object(
            self.service,
            "_commit_invocation_authorization",
            side_effect=authorize_then_crash,
        ), self.assertRaisesRegex(RuntimeError, "crash after"):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        with self.assertRaises(ActionExecutionReconciliationRequired):
            self.service.execute(
                self.command,
                self.request,
                self.assertion,
                self.authorization,
            )
        self.assertEqual(self.primitive.calls, 0)

    def test_adapter_substitution_after_authorization_is_known_zero(self) -> None:
        original = self.service._commit_invocation_authorization
        replacement = phase196b.RecordingPrimitive()

        def authorize_then_replace(*args, **kwargs):  # type: ignore[no-untyped-def]
            result = original(*args, **kwargs)
            object.__setattr__(self.adapter, "_primitive", replacement)
            return result

        with mock.patch.object(
            self.service,
            "_commit_invocation_authorization",
            side_effect=authorize_then_replace,
        ):
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
        self.assertEqual(terminal.to_dict()["adapter_call_count"], 0)
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(replacement.calls, 0)
        with self.fixture.store._read_connection() as connection:
            abort = connection.execute(
                "SELECT invocation_use_id, health_decision_id FROM "
                "action_execution_preinvocation_aborts"
            ).fetchone()
            self.assertIsNotNone(abort[0])
            self.assertIsNotNone(abort[1])
        self.service.verify_store()

    def test_invocation_collector_failure_is_known_zero(self) -> None:
        original = self.fixture.health_gate.observe_current_in_transaction
        calls = 0

        def fail_invocation(*args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeError("invocation collector unavailable")
            return original(*args, **kwargs)

        with mock.patch.object(
            self.fixture.health_gate,
            "observe_current_in_transaction",
            side_effect=fail_invocation,
        ):
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
        self.assertEqual(self.primitive.calls, 0)
        with self.fixture.store._read_connection() as connection:
            abort = connection.execute(
                "SELECT health_decision_id, invocation_use_id FROM "
                "action_execution_preinvocation_aborts"
            ).fetchone()
            self.assertIsNone(abort[0])
            self.assertIsNone(abort[1])
        self.service.verify_store()

    def test_healthy_head_advance_after_authorization_is_known_zero(self) -> None:
        original = self.service._commit_invocation_authorization

        def authorize_then_advance(*args, **kwargs):  # type: ignore[no-untyped-def]
            result = original(*args, **kwargs)
            self._append_health(healthy=True)
            self.fixture.health_gate.observe_current(self.health_binding)
            return result

        with mock.patch.object(
            self.service,
            "_commit_invocation_authorization",
            side_effect=authorize_then_advance,
        ):
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
        self.assertEqual(self.primitive.calls, 0)
        self.assertEqual(
            self.fixture.health_gate.load_head(
                self.health_binding
            ).latch_state,
            TargetHealthGateState.ACTIVE,
        )
        self.service.verify_store()

    def test_schema36_complete_execution_migrates_as_frozen_complete(self) -> None:
        self.service.execute(
            self.command,
            self.request,
            self.assertion,
            self.authorization,
        )
        with sqlite3.connect(self.fixture.store.path) as connection:
            connection.execute(
                "DROP TRIGGER action_target_health_gate_uses_immutable"
            )
            connection.execute(
                "DROP TRIGGER action_target_health_gate_uses_no_delete"
            )
            connection.execute(
                "DELETE FROM action_target_health_gate_uses "
                "WHERE use_kind = 'action_execution_invocation'"
            )
            connection.executescript(
                """
                CREATE TRIGGER action_target_health_gate_uses_immutable
                BEFORE UPDATE ON action_target_health_gate_uses BEGIN
                    SELECT RAISE(ABORT, 'target health gate use is immutable');
                END;
                CREATE TRIGGER action_target_health_gate_uses_no_delete
                BEFORE DELETE ON action_target_health_gate_uses BEGIN
                    SELECT RAISE(ABORT, 'target health gate use cannot be deleted');
                END;
                """
            )
            remove_schema_v37_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '36' "
                "WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 36")
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V36,
            )
        backup = self.fixture.root.directory / "phase199e-v36.sqlite3"
        report = self.fixture.store.migrate(self.fixture.registry, backup)
        self.assertEqual((report.source_version, report.target_version), (36, 39))
        with self.fixture.store._read_connection() as connection:
            row = connection.execute(
                "SELECT request_count, baseline_json FROM "
                "action_execution_target_health_gate_legacy_baselines"
            ).fetchone()
            verification = verify_action_target_health_gate_use_store(connection)
        self.assertEqual(row[0], 1)
        records = json.loads(row[1])["records"]
        self.assertEqual(
            records[0]["coverage_status"],
            "precutover_complete_coverage",
        )
        self.assertEqual(verification.legacy_execution_count, 1)

    def test_schema35_reconciliation_source_verifies_and_migrates(self) -> None:
        self._reconcile_after_committed_invocation_crash()
        with sqlite3.connect(self.fixture.store.path) as connection:
            connection.row_factory = sqlite3.Row
            remove_schema_v36_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '35' "
                "WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 35")
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V35,
            )
            verify_authenticated_action_execution_store(connection)
        backup = self.fixture.root.directory / "phase199e-v35.sqlite3"
        report = self.fixture.store.migrate(self.fixture.registry, backup)
        self.assertEqual((report.source_version, report.target_version), (35, 39))

    def test_schema34_reconciliation_source_verifies_and_migrates(self) -> None:
        self._reconcile_after_committed_invocation_crash()
        with sqlite3.connect(self.fixture.store.path) as connection:
            connection.row_factory = sqlite3.Row
            remove_schema_v35_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '34' "
                "WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 34")
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V34,
            )
            verify_authenticated_action_execution_store(connection)
        backup = self.fixture.root.directory / "phase199e-v34.sqlite3"
        report = self.fixture.store.migrate(self.fixture.registry, backup)
        self.assertEqual((report.source_version, report.target_version), (34, 39))


if __name__ == "__main__":
    unittest.main()
