"""Authenticated Phase 12 simulation consumption coverage."""

from __future__ import annotations

import ast
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

from sunderkey.approvals import ApprovalState
from sunderkey.authenticated_simulations import (
    AuthenticatedSimulationReceipt,
    AuthenticatedSimulationService,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    SimulationError,
    StoreConflictError,
    StoreIntegrityError,
)
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    compute_operation_intent_hash,
)
from sunderkey.scope import (
    ScopeGrantRevocationAcceptanceService,
)
from sunderkey.simulation import SimulationService
from sunderkey.store import canonical_json, format_timestamp, sha256_text

from .test_authenticated_approval_revocations_phase11 import (
    AUDIENCE,
    CONTROL_ID,
    EXECUTOR_ID,
    MISSION_ID,
    POLICY_VERSION,
)

ROOT = Path(__file__).resolve().parents[2]
SIMULATION_ASSERTION_ID = "PAS-12000000000000000000000000000001"
OTHER_ASSERTION_ID = "PAS-12000000000000000000000000000002"
CONCURRENT_FIRST_ID = "PAS-12000000000000000000000000000003"
CONCURRENT_SECOND_ID = "PAS-12000000000000000000000000000004"
IDEMPOTENCY_KEY = "phase12-simulate"


class AuthenticatedSimulationPhase12Tests(unittest.TestCase):
    def setUp(self) -> None:
        from .test_authenticated_approval_revocations_phase11 import (
            AuthenticatedApprovalRevocationPhase11Tests,
        )

        AuthenticatedApprovalRevocationPhase11Tests.setUpClass()
        fixture = AuthenticatedApprovalRevocationPhase11Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.store = fixture.store
        self.registry = fixture.registry
        self.now = fixture.now
        self.approval_id = fixture.approval_id
        self.service = AuthenticatedSimulationService(
            self.store,
            self.registry,
            clock=lambda: self.fixture.now,
        )

    def intent(
        self,
        *,
        approval_id: str | None = None,
        idempotency_key: str = IDEMPOTENCY_KEY,
        profile_id: str = EXECUTOR_ID,
    ) -> dict[str, str]:
        return {
            "approval_id": approval_id or self.approval_id,
            "idempotency_key_sha256": sha256_text(idempotency_key),
            "principal_profile_id": profile_id,
        }

    def assertion(
        self,
        *,
        assertion_id: str = SIMULATION_ASSERTION_ID,
        approval_id: str | None = None,
        idempotency_key: str = IDEMPOTENCY_KEY,
        profile_id: str = EXECUTOR_ID,
        intent_profile_id: str | None = None,
        operation: PrincipalOperation = PrincipalOperation.SIMULATION_RUN,
        mission_id: str = MISSION_ID,
        issued_at: str | None = None,
        not_before: str | None = None,
        expires_at: str | None = None,
    ) -> PrincipalAssertion:
        current = format_timestamp(self.fixture.now)
        bound_intent = self.intent(
            approval_id=approval_id,
            idempotency_key=idempotency_key,
            profile_id=intent_profile_id or profile_id,
        )
        return self.fixture.factory.assertion(
            grant=self.fixture.executor_grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.fixture.executor_grant.grant_id,
            subject=self.fixture.executor_grant.subject,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.fixture.store_id,
            mission_id=mission_id,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(
                operation,
                bound_intent,
            ),
            issued_at=issued_at or current,
            not_before=not_before or current,
            expires_at=expires_at
            or format_timestamp(
                self.fixture.now + timedelta(minutes=4)
            ),
        )

    def simulate(
        self,
        *,
        assertion: PrincipalAssertion | None = None,
        approval_id: str | None = None,
        idempotency_key: str = IDEMPOTENCY_KEY,
    ) -> AuthenticatedSimulationReceipt:
        return self.service.simulate(
            assertion
            or self.assertion(
                approval_id=approval_id,
                idempotency_key=idempotency_key,
            ),
            approval_id or self.approval_id,
            idempotency_key=idempotency_key,
        )

    def state(self) -> dict[str, object]:
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            mission = connection.execute(
                """
                SELECT revision, head_hash
                FROM missions
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            approval = connection.execute(
                """
                SELECT status, version, simulation_id
                FROM approval_queue
                WHERE approval_id = ?
                """,
                (self.approval_id,),
            ).fetchone()
            use = connection.execute(
                """
                SELECT *
                FROM principal_assertion_uses
                WHERE assertion_id = ?
                """,
                (SIMULATION_ASSERTION_ID,),
            ).fetchone()
            effect = connection.execute(
                """
                SELECT *
                FROM principal_assertion_effects
                WHERE assertion_id = ?
                """,
                (SIMULATION_ASSERTION_ID,),
            ).fetchone()
            receipt_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM simulation_receipts
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                ).fetchone()[0]
            )
        assert mission is not None
        assert approval is not None
        return {
            "mission_revision": int(mission["revision"]),
            "mission_head_hash": str(mission["head_hash"]),
            "approval_state": str(approval["status"]),
            "approval_version": int(approval["version"]),
            "simulation_id": approval["simulation_id"],
            "use": use,
            "effect": effect,
            "receipt_count": receipt_count,
        }

    def test_valid_simulation_derives_executor_and_records_exact_effect(
        self,
    ) -> None:
        before = self.state()

        receipt = self.simulate()
        after = self.state()

        self.assertIsInstance(receipt, AuthenticatedSimulationReceipt)
        self.assertEqual(
            receipt.operation,
            PrincipalOperation.SIMULATION_RUN,
        )
        self.assertEqual(receipt.principal_profile_id, EXECUTOR_ID)
        self.assertEqual(receipt.approval.state, ApprovalState.CONSUMED)
        self.assertEqual(receipt.approval.version, 3)
        self.assertEqual(receipt.simulation.evidence_level, "E0")
        self.assertFalse(receipt.simulation.external_actions_performed)
        self.assertEqual(after["approval_state"], "consumed")
        self.assertEqual(after["approval_version"], 3)
        self.assertEqual(after["receipt_count"], 1)
        self.assertEqual(
            after["mission_revision"],
            before["mission_revision"],
        )
        self.assertEqual(
            after["mission_head_hash"],
            before["mission_head_hash"],
        )
        use = after["use"]
        effect = after["effect"]
        self.assertIsInstance(use, sqlite3.Row)
        self.assertIsInstance(effect, sqlite3.Row)
        assert isinstance(use, sqlite3.Row)
        assert isinstance(effect, sqlite3.Row)
        self.assertEqual(
            use["operation"],
            PrincipalOperation.SIMULATION_RUN.value,
        )
        self.assertEqual(effect["effect_kind"], use["operation"])
        self.assertEqual(
            effect["effect_id"],
            receipt.simulation.simulation_id,
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_signed_intent_binds_all_fields(self) -> None:
        for changed_assertion, call_id, call_key in (
            (
                self.assertion(
                    approval_id="APR-PHASE12-OTHER",
                ),
                self.approval_id,
                IDEMPOTENCY_KEY,
            ),
            (
                self.assertion(
                    idempotency_key="phase12-other-key",
                ),
                self.approval_id,
                IDEMPOTENCY_KEY,
            ),
            (
                self.assertion(
                    intent_profile_id=CONTROL_ID,
                ),
                self.approval_id,
                IDEMPOTENCY_KEY,
            ),
        ):
            with (
                self.subTest(
                    assertion=changed_assertion.assertion_id
                ),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                self.service.simulate(
                    changed_assertion,
                    call_id,
                    idempotency_key=call_key,
                )

    def test_wrong_executor_mission_operation_and_signature_are_rejected(
        self,
    ) -> None:
        cases = (
            self.assertion(profile_id=CONTROL_ID),
            self.assertion(mission_id="MISSION-PHASE12-OTHER"),
            replace(
                self.assertion(),
                operation=PrincipalOperation.EVENT_APPEND,
            ),
            replace(
                self.assertion(),
                signature="A" * 86,
            ),
        )
        for credential in cases:
            with self.subTest(assertion=credential.to_dict()), self.assertRaises(
                (
                    PrincipalAuthenticationError,
                    StoreIntegrityError,
                )
            ):
                self.simulate(assertion=credential)
        self.assertEqual(self.state()["receipt_count"], 0)

    def test_direct_new_and_exact_retry_are_gated_after_policy(
        self,
    ) -> None:
        direct = SimulationService(
            self.store,
            self.registry,
            clock=lambda: self.fixture.now,
        )
        with self.assertRaisesRegex(
            SimulationError,
            "[Aa]uthenticated",
        ):
            direct.simulate(
                self.approval_id,
                idempotency_key=IDEMPOTENCY_KEY,
                principal_profile_id=EXECUTOR_ID,
            )

        self.simulate()
        with self.assertRaisesRegex(
            SimulationError,
            "[Aa]uthenticated",
        ):
            direct.simulate(
                self.approval_id,
                idempotency_key=IDEMPOTENCY_KEY,
                principal_profile_id=EXECUTOR_ID,
            )

    def test_exact_replay_survives_assertion_and_grant_expiry(self) -> None:
        assertion = self.assertion()
        original = self.simulate(assertion=assertion)
        self.fixture.now += timedelta(hours=2)

        replay = self.simulate(assertion=assertion)

        self.assertEqual(replay, original)
        self.assertEqual(self.state()["receipt_count"], 1)

    def test_exact_replay_survives_policy_advancement(self) -> None:
        assertion = self.assertion()
        original = self.simulate(assertion=assertion)
        self.fixture.now += timedelta(minutes=1)
        self.fixture.trust.apply_policy(
            self.fixture.make_policy(POLICY_VERSION + 1)
        )

        self.assertEqual(self.simulate(assertion=assertion), original)

    def test_exact_replay_survives_scope_revocation(self) -> None:
        assertion = self.assertion()
        original = self.simulate(assertion=assertion)
        self.fixture.now += timedelta(minutes=1)
        ScopeGrantRevocationAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.fixture.scope_revocation())

        self.assertEqual(self.simulate(assertion=assertion), original)

    def test_exact_replay_survives_mission_stop(self) -> None:
        assertion = self.assertion()
        original = self.simulate(assertion=assertion)
        self.fixture.stop_mission()

        self.assertEqual(self.simulate(assertion=assertion), original)

    def test_request_and_idempotency_key_cannot_rebind(self) -> None:
        self.simulate()
        with self.assertRaises(StoreConflictError):
            self.simulate(
                assertion=self.assertion(
                    assertion_id=OTHER_ASSERTION_ID,
                )
            )
        with self.assertRaises(StoreConflictError):
            self.simulate(
                assertion=self.assertion(
                    assertion_id=OTHER_ASSERTION_ID,
                    profile_id=CONTROL_ID,
                ),
            )

    def test_provenance_failure_rolls_back_all_writes(self) -> None:
        before = self.state()
        with (
            mock.patch.object(
                AuthenticatedSimulationService,
                "_simulation_effect",
                side_effect=StoreIntegrityError("injected failure"),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "injected failure",
            ),
        ):
            self.simulate()

        after = self.state()
        self.assertEqual(after, before)

    def test_concurrent_assertions_commit_one_simulation(self) -> None:
        assertions = (
            self.assertion(assertion_id=CONCURRENT_FIRST_ID),
            self.assertion(assertion_id=CONCURRENT_SECOND_ID),
        )
        barrier = threading.Barrier(2)

        def run(
            assertion: PrincipalAssertion,
        ) -> AuthenticatedSimulationReceipt | Exception:
            service = AuthenticatedSimulationService(
                self.store,
                self.registry,
                clock=lambda: self.fixture.now,
            )
            barrier.wait()
            try:
                return service.simulate(
                    assertion,
                    self.approval_id,
                    idempotency_key=IDEMPOTENCY_KEY,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(run, assertions))

        receipts = [
            result
            for result in results
            if isinstance(result, AuthenticatedSimulationReceipt)
        ]
        failures = [
            result
            for result in results
            if isinstance(result, Exception)
        ]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(
            failures[0],
            (StoreConflictError, StoreIntegrityError),
        )
        with closing(sqlite3.connect(self.store.path)) as connection:
            use_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM principal_assertion_uses
                WHERE operation = ?
                """,
                (PrincipalOperation.SIMULATION_RUN.value,),
            ).fetchone()[0]
            effect_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM principal_assertion_effects
                WHERE effect_kind = ?
                """,
                (PrincipalOperation.SIMULATION_RUN.value,),
            ).fetchone()[0]
        self.assertEqual(use_count, 1)
        self.assertEqual(effect_count, 1)
        self.assertEqual(self.state()["receipt_count"], 1)

    def test_effect_tampering_is_detected(self) -> None:
        self.simulate()
        with closing(sqlite3.connect(self.store.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'principal_assertion_effect_immutable'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER principal_assertion_effect_immutable"
            )
            connection.execute(
                """
                UPDATE principal_assertion_effects
                SET effect_json = ?
                WHERE assertion_id = ?
                """,
                (
                    canonical_json(
                        {
                            "effect_id": "SIM-TAMPERED",
                            "effect_kind": (
                                PrincipalOperation.SIMULATION_RUN.value
                            ),
                            "payload": {},
                            "recorded_at": format_timestamp(
                                self.fixture.now
                            ),
                            "schema_version": 1,
                        }
                    ),
                    SIMULATION_ASSERTION_ID,
                ),
            )
            connection.execute(str(trigger_sql))
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_authenticated_module_has_no_execution_surface(self) -> None:
        source_path = (
            ROOT / "src" / "sunderkey" / "authenticated_simulations.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_imports = {
            "http",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        forbidden_calls = {
            "__import__",
            "compile",
            "eval",
            "exec",
        }
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        }
        self.assertFalse(imported & forbidden_imports)
        self.assertFalse(called & forbidden_calls)


if __name__ == "__main__":
    unittest.main()
