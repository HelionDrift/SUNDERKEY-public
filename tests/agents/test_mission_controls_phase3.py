from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import sunderkey.store as store_module
from sunderkey.approvals import ApprovalService, ApprovalState
from sunderkey.errors import (
    ApprovalConflictError,
    ApprovalError,
    ApprovalExpiredError,
    MissionControlError,
    MissionStoppedError,
    SimulationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
    StoreMigrationRequiredError,
)
from sunderkey.events import MissionEvent
from sunderkey.mission import MissionRequest
from sunderkey.mission_control import (
    MissionControlService,
    MissionControlState,
)
from sunderkey.registry import load_registry
from sunderkey.simulation import SimulationService
from sunderkey.store import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    control_event_id,
    sha256_text,
)

from .test_store import (
    CONTROL_ID,
    MISSION_ID,
    REGISTRY_PATH,
    SPECIALIST_ID,
    downgrade_connection_to_schema_v1,
    mission_data,
    observation,
    proposal_data,
)

DECISION_TIME = datetime(2026, 1, 1, 10, 5, tzinfo=UTC)


class Phase3MissionControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.mission = MissionRequest.from_dict(mission_data())
        self.store = MissionStore(
            self.path,
            clock=lambda: DECISION_TIME,
        )
        self.store.initialize()
        self.store.create_mission(self.registry, self.mission)
        self.store.append_event(
            self.registry,
            MissionEvent.from_dict(proposal_data()),
            expected_revision=0,
        )
        self.approvals = ApprovalService(
            self.store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )
        self.controls = MissionControlService(
            self.store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )

    def new_runtime(
        self,
        name: str,
    ) -> tuple[
        MissionStore,
        ApprovalService,
        MissionControlService,
    ]:
        store = MissionStore(
            self.directory / f"{name}.sqlite3",
            clock=lambda: DECISION_TIME,
        )
        store.initialize()
        store.create_mission(self.registry, self.mission)
        store.append_event(
            self.registry,
            MissionEvent.from_dict(proposal_data()),
            expected_revision=0,
        )
        return (
            store,
            ApprovalService(
                store,
                self.registry,
                clock=lambda: DECISION_TIME,
            ),
            MissionControlService(
                store,
                self.registry,
                clock=lambda: DECISION_TIME,
            ),
        )

    def submit(self, key: str = "phase3-submit") -> str:
        return self.approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key=key,
            principal_profile_id=SPECIALIST_ID,
        ).approval_id

    def approve(self, approval_id: str) -> None:
        self.approvals.approve(
            approval_id,
            authority="phase3-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-01-01T11:00:00Z",
            idempotency_key="phase3-approve",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )

    def stop(self):
        return self.controls.stop(
            MISSION_ID,
            reason_code="operator_request",
            reason="Operator requested a terminal stop",
            risk="Continued work is no longer authorized",
            decision_owner="range-control",
            idempotency_key="phase3-stop",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )

    def test_terminal_stop_is_audited_idempotent_and_fail_closed(self) -> None:
        active = self.controls.get(MISSION_ID)
        self.assertEqual(active.state, MissionControlState.ACTIVE)
        self.assertEqual(active.version, 1)

        stopped = self.stop()
        self.assertEqual(stopped.state, MissionControlState.STOPPED)
        self.assertEqual(stopped.version, 2)
        self.assertIsNotNone(stopped.stop_event_id)
        revision = self.store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision

        replay = self.stop()
        self.assertEqual(replay, stopped)
        self.assertEqual(
            self.store.get_mission(
                self.registry,
                MISSION_ID,
            ).revision,
            revision,
        )
        with self.assertRaises(StoreConflictError):
            self.controls.stop(
                MISSION_ID,
                reason_code="scope_ambiguity",
                reason="A changed stop request",
                risk="Unknown scope",
                decision_owner="range-control",
                idempotency_key="phase3-stop-conflict",
                expected_version=1,
                principal_profile_id=CONTROL_ID,
            )
        with self.assertRaises(MissionStoppedError):
            self.store.append_event(
                self.registry,
                observation("EVT-AFTER-STOP", minute=6),
                expected_revision=revision,
            )
        replay = self.store.append_event(
            self.registry,
            MissionEvent.from_dict(proposal_data()),
            expected_revision=revision,
        )
        self.assertTrue(replay.idempotent)
        self.assertEqual(replay.revision, revision)
        with self.assertRaises(MissionStoppedError):
            self.store.append_events(
                self.registry,
                MISSION_ID,
                (
                    MissionEvent.from_dict(proposal_data()),
                    observation("EVT-MIXED-AFTER-STOP", minute=7),
                ),
                expected_revision=revision,
            )
        self.assertEqual(
            self.store.get_mission(
                self.registry,
                MISSION_ID,
            ).revision,
            revision,
        )
        self.store.verify_store(self.registry)

    def test_stop_blocks_pending_and_approved_mutations(self) -> None:
        second_proposal_data = proposal_data()
        second_proposal_data["event_id"] = "EVT-PROP-002"
        second_proposal_data["timestamp"] = "2026-01-01T10:01:00Z"
        second_proposal_data["payload"]["target"] = "synthetic://store/policy-model-two"
        self.store.append_event(
            self.registry,
            MissionEvent.from_dict(second_proposal_data),
            expected_revision=1,
        )
        approval_id = self.submit()
        submitted = self.approvals.get(approval_id)
        self.stop()
        submit_replay = self.approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="phase3-submit",
            principal_profile_id=SPECIALIST_ID,
        )
        self.assertEqual(submit_replay, submitted)
        with self.assertRaises(MissionStoppedError):
            self.approvals.submit(
                mission_id=MISSION_ID,
                proposal_id="EVT-PROP-002",
                executor_profile_id=SPECIALIST_ID,
                review_expires_at="2026-01-01T10:30:00Z",
                idempotency_key="phase3-submit-two",
                principal_profile_id=SPECIALIST_ID,
            )
        with self.assertRaises(MissionStoppedError):
            self.approve(approval_id)
        with self.assertRaises(MissionStoppedError):
            self.approvals.deny(
                approval_id,
                reason_code="operator-request",
                reason="Deny after terminal stop",
                risk="The mission is no longer active",
                decision_owner="range-control",
                idempotency_key="phase3-deny-after-stop",
                expected_version=1,
                principal_profile_id=CONTROL_ID,
            )

        other, approvals, controls = self.new_runtime("approved")
        approved = approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="other-submit",
            principal_profile_id=SPECIALIST_ID,
        )
        approvals.approve(
            approved.approval_id,
            authority="phase3-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-01-01T11:00:00Z",
            idempotency_key="other-approve",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        controls.stop(
            MISSION_ID,
            reason_code="authorization_withdrawn",
            reason="Authorization was withdrawn",
            risk="Execution would exceed current authority",
            decision_owner="range-control",
            idempotency_key="other-stop",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        with self.assertRaises(MissionStoppedError):
            approvals.revoke(
                approved.approval_id,
                reason_code="authorization-withdrawn",
                reason="Revoke after terminal stop",
                risk="The mission is no longer active",
                decision_owner="range-control",
                idempotency_key="other-revoke",
                expected_version=2,
                principal_profile_id=CONTROL_ID,
            )
        with self.assertRaises(MissionStoppedError):
            SimulationService(
                other,
                self.registry,
                clock=lambda: DECISION_TIME,
            ).simulate(
                approved.approval_id,
                idempotency_key="other-simulate",
                principal_profile_id=SPECIALIST_ID,
            )
        other.verify_store(self.registry)

    def test_stop_allows_exact_replays_that_do_not_write(self) -> None:
        approval_id = self.submit("replay-submit")
        self.approvals.approve(
            approval_id,
            authority="phase3-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-01-01T11:00:00Z",
            idempotency_key="replay-approve",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        revocation = self.approvals.revoke(
            approval_id,
            reason_code="operator-request",
            reason="Revoke before the mission stops",
            risk="Authorization changed",
            decision_owner="range-control",
            idempotency_key="replay-revoke",
            expected_version=2,
            principal_profile_id=CONTROL_ID,
        )
        self.stop()
        stopped_revision = self.store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision

        submit_replay = self.approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="replay-submit",
            principal_profile_id=SPECIALIST_ID,
        )
        approve_replay = self.approvals.approve(
            approval_id,
            authority="phase3-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-01-01T11:00:00Z",
            idempotency_key="replay-approve",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        revoke_replay = self.approvals.revoke(
            approval_id,
            reason_code="operator-request",
            reason="Revoke before the mission stops",
            risk="Authorization changed",
            decision_owner="range-control",
            idempotency_key="replay-revoke",
            expected_version=2,
            principal_profile_id=CONTROL_ID,
        )
        current = self.approvals.get(approval_id)
        self.assertEqual(submit_replay, current)
        self.assertEqual(approve_replay, current)
        self.assertEqual(revoke_replay, revocation)
        self.assertEqual(
            self.store.get_mission(
                self.registry,
                MISSION_ID,
            ).revision,
            stopped_revision,
        )

        denied_store, denied_approvals, denied_controls = self.new_runtime("denied-replay")
        denied_id = denied_approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="denied-submit",
            principal_profile_id=SPECIALIST_ID,
        ).approval_id
        denied = denied_approvals.deny(
            denied_id,
            reason_code="scope-denied",
            reason="The scope was not approved",
            risk="The proposed scope is not authorized",
            decision_owner="range-control",
            idempotency_key="denied-decision",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        denied_controls.stop(
            MISSION_ID,
            reason_code="operator_request",
            reason="Operator requested a terminal stop",
            risk="Continued work is no longer authorized",
            decision_owner="range-control",
            idempotency_key="denied-stop",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        denied_revision = denied_store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision
        denied_replay = denied_approvals.deny(
            denied_id,
            reason_code="scope-denied",
            reason="The scope was not approved",
            risk="The proposed scope is not authorized",
            decision_owner="range-control",
            idempotency_key="denied-decision",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        self.assertEqual(denied_replay, denied)
        self.assertEqual(
            denied_store.get_mission(
                self.registry,
                MISSION_ID,
            ).revision,
            denied_revision,
        )

        consumed_store, consumed_approvals, consumed_controls = self.new_runtime("consumed-replay")
        consumed_id = consumed_approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="consumed-submit",
            principal_profile_id=SPECIALIST_ID,
        ).approval_id
        consumed_approvals.approve(
            consumed_id,
            authority="phase3-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-01-01T11:00:00Z",
            idempotency_key="consumed-approve",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        simulations = SimulationService(
            consumed_store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )
        receipt = simulations.simulate(
            consumed_id,
            idempotency_key="consumed-simulate",
            principal_profile_id=SPECIALIST_ID,
        )
        consumed_controls.stop(
            MISSION_ID,
            reason_code="operator_request",
            reason="Operator requested a terminal stop",
            risk="Continued work is no longer authorized",
            decision_owner="range-control",
            idempotency_key="consumed-stop",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        consumed_revision = consumed_store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision
        receipt_replay = simulations.simulate(
            consumed_id,
            idempotency_key="consumed-simulate",
            principal_profile_id=SPECIALIST_ID,
        )
        self.assertEqual(receipt_replay, receipt)
        self.assertEqual(
            consumed_store.get_mission(
                self.registry,
                MISSION_ID,
            ).revision,
            consumed_revision,
        )
        denied_store.verify_store(self.registry)
        consumed_store.verify_store(self.registry)
        self.store.verify_store(self.registry)

    def test_control_actor_and_transition_rules_fail_closed(self) -> None:
        revision = self.store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision
        with self.assertRaises(MissionControlError):
            self.controls.stop(
                MISSION_ID,
                reason_code="operator_request",
                reason="An unauthorized stop request",
                risk="The caller is not Control",
                decision_owner="range-control",
                idempotency_key="unauthorized-stop",
                expected_version=1,
                principal_profile_id=SPECIALIST_ID,
            )
        self.assertEqual(
            self.controls.get(MISSION_ID).state,
            MissionControlState.ACTIVE,
        )
        self.assertEqual(
            self.store.get_mission(
                self.registry,
                MISSION_ID,
            ).revision,
            revision,
        )

        approval_id = self.submit()
        with self.assertRaises(ApprovalConflictError):
            self.approvals.revoke(
                approval_id,
                reason_code="operator-request",
                reason="Pending requests use denial",
                risk="No authorization exists",
                decision_owner="range-control",
                idempotency_key="pending-revoke",
                expected_version=1,
                principal_profile_id=CONTROL_ID,
            )
        self.assertEqual(
            self.approvals.get(approval_id).state,
            ApprovalState.PENDING,
        )

    def test_revoke_preserves_authorization_and_blocks_simulation(self) -> None:
        approval_id = self.submit()
        self.approve(approval_id)
        approved = self.approvals.get(approval_id)

        revocation = self.approvals.revoke(
            approval_id,
            reason_code="scope-withdrawn",
            reason="The delegated scope was withdrawn",
            risk="Simulation would use stale authority",
            decision_owner="range-control",
            idempotency_key="phase3-revoke",
            expected_version=2,
            principal_profile_id=CONTROL_ID,
        )
        revoked = self.approvals.get(approval_id)
        self.assertEqual(revoked.state, ApprovalState.REVOKED)
        self.assertEqual(revoked.version, 3)
        self.assertEqual(
            revoked.authorization_event_id,
            approved.authorization_event_id,
        )
        self.assertEqual(
            revoked.decision_event_id,
            approved.decision_event_id,
        )
        self.assertEqual(
            self.approvals.get_revocation(approval_id),
            revocation,
        )
        replay = self.approvals.revoke(
            approval_id,
            reason_code="scope-withdrawn",
            reason="The delegated scope was withdrawn",
            risk="Simulation would use stale authority",
            decision_owner="range-control",
            idempotency_key="phase3-revoke",
            expected_version=2,
            principal_profile_id=CONTROL_ID,
        )
        self.assertEqual(replay, revocation)
        with self.assertRaises(ApprovalConflictError):
            self.approvals.revoke(
                approval_id,
                reason_code="scope-withdrawn",
                reason="Changed content",
                risk="Simulation would use stale authority",
                decision_owner="range-control",
                idempotency_key="phase3-revoke",
                expected_version=2,
                principal_profile_id=CONTROL_ID,
            )
        with self.assertRaises(SimulationError):
            SimulationService(
                self.store,
                self.registry,
                clock=lambda: DECISION_TIME,
            ).simulate(
                approval_id,
                idempotency_key="phase3-simulate",
                principal_profile_id=SPECIALIST_ID,
            )
        self.store.verify_store(self.registry)

    def test_revocation_clock_boundaries_fail_closed(self) -> None:
        approval_id = self.submit()
        self.approve(approval_id)
        at_expiry = ApprovalService(
            self.store,
            self.registry,
            clock=lambda: datetime(
                2026,
                1,
                1,
                11,
                0,
                tzinfo=UTC,
            ),
        )
        with self.assertRaises(ApprovalExpiredError):
            at_expiry.revoke(
                approval_id,
                reason_code="operator-request",
                reason="Boundary test",
                risk="Authorization changed",
                decision_owner="range-control",
                idempotency_key="expiry-revoke",
                expected_version=2,
                principal_profile_id=CONTROL_ID,
            )
        before_issuance = ApprovalService(
            self.store,
            self.registry,
            clock=lambda: datetime(
                2026,
                1,
                1,
                10,
                4,
                tzinfo=UTC,
            ),
        )
        with self.assertRaises(ApprovalError):
            before_issuance.revoke(
                approval_id,
                reason_code="operator-request",
                reason="Backward clock test",
                risk="Clock is not trustworthy",
                decision_owner="range-control",
                idempotency_key="backward-revoke",
                expected_version=2,
                principal_profile_id=CONTROL_ID,
            )
        self.assertEqual(
            self.approvals.get(approval_id).state,
            ApprovalState.APPROVED,
        )

    def test_revoke_and_simulate_have_one_terminal_winner(self) -> None:
        approval_id = self.submit()
        self.approve(approval_id)

        def revoke() -> str:
            try:
                self.approvals.revoke(
                    approval_id,
                    reason_code="operator-request",
                    reason="Cancel before simulation",
                    risk="Authorization changed",
                    decision_owner="range-control",
                    idempotency_key="race-revoke",
                    expected_version=2,
                    principal_profile_id=CONTROL_ID,
                )
                return "revoked"
            except ApprovalConflictError:
                return "revoke-rejected"

        def simulate() -> str:
            try:
                SimulationService(
                    self.store,
                    self.registry,
                    clock=lambda: DECISION_TIME,
                ).simulate(
                    approval_id,
                    idempotency_key="race-simulate",
                    principal_profile_id=SPECIALIST_ID,
                )
                return "consumed"
            except SimulationError:
                return "simulate-rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            revoke_future = executor.submit(revoke)
            simulate_future = executor.submit(simulate)
            outcomes = {
                revoke_future.result(),
                simulate_future.result(),
            }
        terminal = self.approvals.get(approval_id).state
        self.assertIn(
            terminal,
            {ApprovalState.REVOKED, ApprovalState.CONSUMED},
        )
        if terminal is ApprovalState.REVOKED:
            self.assertIn("revoked", outcomes)
            self.assertIn("simulate-rejected", outcomes)
        else:
            self.assertIn("consumed", outcomes)
            self.assertIn("revoke-rejected", outcomes)
        self.store.verify_store(self.registry)

    def test_revocation_tampering_is_detected(self) -> None:
        approval_id = self.submit()
        self.approve(approval_id)
        self.approvals.revoke(
            approval_id,
            reason_code="operator-request",
            reason="Revoke for a tamper test",
            risk="Authorization changed",
            decision_owner="range-control",
            idempotency_key="tamper-revoke",
            expected_version=2,
            principal_profile_id=CONTROL_ID,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    UPDATE approval_revocations
                    SET reason = 'tampered'
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                )
            connection.rollback()
        self.store.verify_store(self.registry)

    def test_missing_control_state_blocks_mutation_and_verification(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "DELETE FROM mission_controls WHERE mission_id = ?",
                (MISSION_ID,),
            )
            connection.commit()
        with self.assertRaises(StoreIntegrityError):
            self.store.append_event(
                self.registry,
                observation("EVT-NO-CONTROL", minute=6),
            )
        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_explicit_v1_migration_preserves_historical_rows(self) -> None:
        approval_id = self.submit()
        self.approve(approval_id)
        with closing(sqlite3.connect(self.path)) as connection:
            before = {
                "missions": connection.execute(
                    "SELECT * FROM missions ORDER BY mission_id"
                ).fetchall(),
                "events": connection.execute(
                    "SELECT * FROM mission_events ORDER BY mission_id, sequence"
                ).fetchall(),
                "approvals": connection.execute(
                    "SELECT * FROM approval_queue ORDER BY approval_id"
                ).fetchall(),
                "receipts": connection.execute(
                    "SELECT * FROM simulation_receipts ORDER BY simulation_id"
                ).fetchall(),
            }
            downgrade_connection_to_schema_v1(connection)

        self.store.verify_store(self.registry)
        with self.assertRaises(StoreMigrationRequiredError):
            self.store.append_event(
                self.registry,
                observation("EVT-V1-MUTATE", minute=6),
            )
        backup = self.directory / "before-v2.sqlite3"
        report = self.store.migrate(self.registry, backup)
        self.assertEqual(report.status, "migrated")
        self.assertEqual(report.source_version, 1)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        self.assertTrue(backup.is_file())
        MissionStore(backup).verify_store(self.registry)

        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA application_id").fetchone()[0],
                APPLICATION_ID,
            )
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                1,
            )
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            after = {
                "missions": connection.execute(
                    "SELECT * FROM missions ORDER BY mission_id"
                ).fetchall(),
                "events": connection.execute(
                    "SELECT * FROM mission_events ORDER BY mission_id, sequence"
                ).fetchall(),
                "approvals": connection.execute(
                    "SELECT * FROM approval_queue ORDER BY approval_id"
                ).fetchall(),
                "receipts": connection.execute(
                    "SELECT * FROM simulation_receipts ORDER BY simulation_id"
                ).fetchall(),
            }
            control = connection.execute(
                """
                SELECT state, version FROM mission_controls
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            revocations = connection.execute(
                "SELECT COUNT(*) FROM approval_revocations"
            ).fetchone()[0]
        self.assertEqual(after, before)
        self.assertEqual(control, ("active", 1))
        self.assertEqual(revocations, 0)
        self.assertEqual(
            self.approvals.get(approval_id).state,
            ApprovalState.APPROVED,
        )
        self.store.verify_store(self.registry)

    def test_failed_migration_rolls_back_and_keeps_v1_backup(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            downgrade_connection_to_schema_v1(connection)
        backup = self.directory / "rollback-backup.sqlite3"
        broken_statements = (
            *store_module.SCHEMA_V2_ADDITION_STATEMENTS,
            "THIS IS NOT VALID SQL",
        )
        with (
            mock.patch.object(
                store_module,
                "SCHEMA_V2_ADDITION_STATEMENTS",
                broken_statements,
            ),
            self.assertRaises(StoreError),
        ):
            self.store.migrate(self.registry, backup)
        self.assertTrue(backup.is_file())
        self.store.verify_store(self.registry)
        MissionStore(backup).verify_store(self.registry)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                1,
            )
            objects = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    """
                ).fetchall()
            }
        self.assertNotIn("mission_controls", objects)
        self.assertNotIn("approval_revocations", objects)

    def test_migration_preserves_legacy_control_prefixes_and_skips_collisions(
        self,
    ) -> None:
        approval_id = self.submit()
        self.approve(approval_id)

        stop_key_hash = sha256_text("phase3-stop")
        stop_request_hash = sha256_text(
            canonical_json(
                {
                    "mission_id": MISSION_ID,
                    "reason_code": "operator_request",
                    "reason": "Operator requested a terminal stop",
                    "risk": "Continued work is no longer authorized",
                    "decision_owner": "range-control",
                    "principal_profile_id": CONTROL_ID,
                    "expected_version": 1,
                }
            )
        )
        revoke_key_hash = sha256_text("legacy-revoke")
        revoke_request_hash = sha256_text(
            canonical_json(
                {
                    "approval_id": approval_id,
                    "reason_code": "scope-withdrawn",
                    "reason": "Legacy collision test",
                    "risk": "Authorization changed",
                    "decision_owner": "range-control",
                    "principal_profile_id": CONTROL_ID,
                    "expected_version": 2,
                }
            )
        )
        stop_collision_id = control_event_id(
            "STOP",
            MISSION_ID,
            stop_key_hash,
            stop_request_hash,
            0,
        )
        revoke_collision_id = control_event_id(
            "REVOKE",
            approval_id,
            revoke_key_hash,
            revoke_request_hash,
            0,
        )
        stop_collision = observation(stop_collision_id, minute=6)
        revoke_collision = observation(revoke_collision_id, minute=7)
        revision = self.store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision
        with self.store._write_connection() as connection:
            self.store._append_events_in_connection(
                connection,
                self.registry,
                MISSION_ID,
                (stop_collision, revoke_collision),
                expected_revision=revision,
                allow_control_events=True,
            )

        with closing(sqlite3.connect(self.path)) as connection:
            downgrade_connection_to_schema_v1(connection)
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        self.assertEqual(mode, "wal")
        self.store.verify_store(self.registry)

        backup = self.directory / "legacy-prefixes.sqlite3"
        with mock.patch.object(
            store_module,
            "sqlite_wal_reset_fix_available",
            return_value=True,
        ):
            self.store.migrate(self.registry, backup)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA journal_mode").fetchone()[0],
                "delete",
            )
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA journal_mode").fetchone()[0],
                "delete",
            )

        revoked = ApprovalService(
            self.store,
            self.registry,
            clock=lambda: datetime(
                2026,
                1,
                1,
                10,
                8,
                tzinfo=UTC,
            ),
        ).revoke(
            approval_id,
            reason_code="scope-withdrawn",
            reason="Legacy collision test",
            risk="Authorization changed",
            decision_owner="range-control",
            idempotency_key="legacy-revoke",
            expected_version=2,
            principal_profile_id=CONTROL_ID,
        )
        stopped = MissionControlService(
            self.store,
            self.registry,
            clock=lambda: datetime(
                2026,
                1,
                1,
                10,
                9,
                tzinfo=UTC,
            ),
        ).stop(
            MISSION_ID,
            reason_code="operator_request",
            reason="Operator requested a terminal stop",
            risk="Continued work is no longer authorized",
            decision_owner="range-control",
            idempotency_key="phase3-stop",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        self.assertNotEqual(
            revoked.revocation_event_id,
            revoke_collision_id,
        )
        self.assertIn("-C00000001-", revoked.revocation_event_id)
        self.assertNotEqual(stopped.stop_event_id, stop_collision_id)
        assert stopped.stop_event_id is not None
        self.assertIn("-C00000001-", stopped.stop_event_id)

        stop_replay = self.store.append_event(
            self.registry,
            stop_collision,
        )
        revoke_replay = self.store.append_event(
            self.registry,
            revoke_collision,
        )
        self.assertTrue(stop_replay.idempotent)
        self.assertTrue(revoke_replay.idempotent)
        self.store.verify_store(self.registry)

    def test_vulnerable_sqlite_rejects_legacy_wal_migration_before_mutation(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            downgrade_connection_to_schema_v1(connection)
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        self.assertEqual(mode, "wal")

        backup = self.directory / "unsafe-wal-backup.sqlite3"
        with (
            mock.patch.object(
                store_module,
                "sqlite_wal_reset_fix_available",
                return_value=False,
            ),
            self.assertRaisesRegex(
                StoreError,
                "WAL mission store requires SQLite",
            ),
        ):
            self.store.migrate(self.registry, backup)

        self.assertFalse(backup.exists())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute("PRAGMA journal_mode").fetchone()[0],
                "wal",
            )
        self.store.verify_store(self.registry)
