from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from sunderkey.approvals import ApprovalService, ApprovalState
from sunderkey.errors import (
    ApprovalError,
    SimulationError,
    StoreIntegrityError,
)
from sunderkey.events import MissionEvent
from sunderkey.mission import load_mission_request
from sunderkey.registry import load_registry
from sunderkey.simulation import (
    PolicySimulationAdapter,
    SimulationReceipt,
    SimulationService,
)
from sunderkey.store import MissionStore, canonical_json, sha256_text

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
MISSION_PATH = ROOT / "examples" / "missions" / "internet-api-to-data.json"
EVENTS_PATH = ROOT / "examples" / "events" / "internet-api-to-data.jsonl"
EXECUTOR_ID = "AOE-GB-D06-S09"
OTHER_PROFILE_ID = "AOE-GA-D03-S13"
CONTROL_ID = "AOE-HQ-12"


class MutableClock:
    def __init__(self, value: str) -> None:
        self.value = datetime.fromisoformat(value.replace("Z", "+00:00"))

    def __call__(self) -> datetime:
        return self.value


class ExplodingAdapter:
    def __init__(self) -> None:
        self.called = False

    def render(self, context: object) -> object:
        self.called = True
        raise AssertionError(f"Custom adapter executed: {context}")


class SimulationHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.clock = MutableClock("2026-07-29T15:06:00Z")
        self.registry = load_registry(REGISTRY_PATH)
        self.mission = load_mission_request(MISSION_PATH)
        self.store = MissionStore(
            Path(temporary.name) / "missions.sqlite3",
            clock=self.clock,
        )
        self.store.initialize()
        self.store.create_mission(self.registry, self.mission)
        raw_events = [
            json.loads(line)
            for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines()
        ]
        self.store.append_events(
            self.registry,
            self.mission.mission_id,
            tuple(MissionEvent.from_dict(raw) for raw in raw_events[:3]),
            expected_revision=0,
        )
        self.approvals = ApprovalService(
            self.store,
            self.registry,
            clock=self.clock,
        )

    def approved_request(self) -> str:
        submitted = self.approvals.submit(
            mission_id=self.mission.mission_id,
            proposal_id="EVT-003",
            executor_profile_id=EXECUTOR_ID,
            review_expires_at="2026-07-29T15:10:00Z",
            idempotency_key="hardening-submit-001",
            principal_profile_id=EXECUTOR_ID,
        )
        approved = self.approvals.approve(
            submitted.approval_id,
            authority="delegated-control",
            constraints=("Synthetic data only", "No external actions"),
            authorization_expires_at="2026-07-29T15:20:00Z",
            idempotency_key="hardening-approve-001",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        self.assertEqual(approved.state, ApprovalState.APPROVED)
        return approved.approval_id

    def receipt_count(self) -> int:
        connection = sqlite3.connect(self.store.path)
        try:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM simulation_receipts"
                ).fetchone()[0]
            )
        finally:
            connection.close()

    def tamper_submission_core(
        self,
        statement: str,
        parameters: tuple[object, ...],
    ) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'approval_submission_core_write_once'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER approval_submission_core_write_once"
            )
            connection.execute(statement, parameters)
            connection.execute(str(trigger_sql))
            connection.commit()
        finally:
            connection.close()

    def test_replay_validates_bound_executor_before_returning_receipt(self) -> None:
        approval_id = self.approved_request()
        service = SimulationService(
            self.store,
            self.registry,
            clock=self.clock,
        )
        service.simulate(
            approval_id,
            idempotency_key="hardening-simulate-001",
            principal_profile_id=EXECUTOR_ID,
        )

        with self.assertRaisesRegex(SimulationError, "bound executor"):
            service.simulate(
                approval_id,
                idempotency_key="hardening-simulate-001",
                principal_profile_id=OTHER_PROFILE_ID,
            )

        self.assertEqual(self.receipt_count(), 1)

    def test_submission_hash_is_validated_before_simulation(self) -> None:
        approval_id = self.approved_request()
        self.tamper_submission_core(
            """
            UPDATE approval_queue
            SET submit_request_hash = ?
            WHERE approval_id = ?
            """,
            ("sha256:" + ("0" * 64), approval_id),
        )

        service = SimulationService(
            self.store,
            self.registry,
            clock=self.clock,
        )
        with self.assertRaisesRegex(ApprovalError, "request hash"):
            service.simulate(
                approval_id,
                idempotency_key="hardening-simulate-002",
                principal_profile_id=EXECUTOR_ID,
            )

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "submit request hash",
        ):
            self.approvals.get(approval_id)
        self.assertEqual(self.receipt_count(), 0)

    def test_simulation_rejects_invalid_approval_versions(self) -> None:
        approval_id = self.approved_request()
        connection = sqlite3.connect(self.store.path)
        try:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'approval_decision_state_transition_guard'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER approval_decision_state_transition_guard"
            )
            connection.execute(
                """
                UPDATE approval_queue
                SET version = 99
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            connection.execute(str(trigger_sql))
            connection.commit()
        finally:
            connection.close()
        service = SimulationService(
            self.store,
            self.registry,
            clock=self.clock,
        )
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "version does not match state",
        ):
            service.simulate(
                approval_id,
                idempotency_key="hardening-invalid-approved-version",
                principal_profile_id=EXECUTOR_ID,
            )
        self.assertEqual(self.receipt_count(), 0)

        connection = sqlite3.connect(self.store.path)
        try:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'approval_decision_state_transition_guard'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER approval_decision_state_transition_guard"
            )
            simulation_trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'simulation_consumption_transition_guard'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER simulation_consumption_transition_guard"
            )
            connection.execute(
                """
                UPDATE approval_queue
                SET version = 2
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            connection.execute(str(trigger_sql))
            connection.execute(str(simulation_trigger_sql))
            connection.commit()
        finally:
            connection.close()
        receipt = service.simulate(
            approval_id,
            idempotency_key="hardening-invalid-consumed-version",
            principal_profile_id=EXECUTOR_ID,
        )
        connection = sqlite3.connect(self.store.path)
        try:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'approval_decision_state_transition_guard'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER approval_decision_state_transition_guard"
            )
            simulation_trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'simulation_consumption_transition_guard'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER simulation_consumption_transition_guard"
            )
            connection.execute(
                """
                UPDATE approval_queue
                SET version = 100
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            connection.execute(str(trigger_sql))
            connection.execute(str(simulation_trigger_sql))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "version does not match state",
        ):
            service.get(self.mission.mission_id, receipt.simulation_id)

    def test_mutated_submission_cannot_be_approved(self) -> None:
        submitted = self.approvals.submit(
            mission_id=self.mission.mission_id,
            proposal_id="EVT-003",
            executor_profile_id=EXECUTOR_ID,
            review_expires_at="2026-07-29T15:10:00Z",
            idempotency_key="hardening-submit-approve-tamper",
            principal_profile_id=EXECUTOR_ID,
        )
        self.tamper_submission_core(
            """
            UPDATE approval_queue
            SET executor_profile_id = ?
            WHERE approval_id = ?
            """,
            (OTHER_PROFILE_ID, submitted.approval_id),
        )

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "submit request hash",
        ):
            self.approvals.approve(
                submitted.approval_id,
                authority="delegated-control",
                constraints=("Synthetic data only",),
                authorization_expires_at="2026-07-29T15:20:00Z",
                idempotency_key="hardening-approve-tamper",
                expected_version=1,
                principal_profile_id=CONTROL_ID,
            )

        events = self.store.list_events(
            self.registry,
            self.mission.mission_id,
        )
        self.assertEqual(len(events), 3)

    def test_mutated_submission_cannot_be_denied(self) -> None:
        submitted = self.approvals.submit(
            mission_id=self.mission.mission_id,
            proposal_id="EVT-003",
            executor_profile_id=EXECUTOR_ID,
            review_expires_at="2026-07-29T15:10:00Z",
            idempotency_key="hardening-submit-deny-tamper",
            principal_profile_id=EXECUTOR_ID,
        )
        self.tamper_submission_core(
            """
            UPDATE approval_queue
            SET executor_profile_id = ?
            WHERE approval_id = ?
            """,
            (OTHER_PROFILE_ID, submitted.approval_id),
        )

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "submit request hash",
        ):
            self.approvals.deny(
                submitted.approval_id,
                reason_code="scope-not-confirmed",
                reason="Scope confirmation is incomplete",
                risk="Target identity is ambiguous",
                decision_owner="owner://mission/control",
                idempotency_key="hardening-deny-tamper",
                expected_version=1,
                principal_profile_id=CONTROL_ID,
            )

        events = self.store.list_events(
            self.registry,
            self.mission.mission_id,
        )
        self.assertEqual(len(events), 3)

    def test_get_and_list_reject_a_renamed_approval_id(self) -> None:
        submitted = self.approvals.submit(
            mission_id=self.mission.mission_id,
            proposal_id="EVT-003",
            executor_profile_id=EXECUTOR_ID,
            review_expires_at="2026-07-29T15:10:00Z",
            idempotency_key="hardening-submit-renamed-id",
            principal_profile_id=EXECUTOR_ID,
        )
        forged_id = "NOT-A-STABLE-ID"
        connection = sqlite3.connect(self.store.path)
        try:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'approval_identity_write_once'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER approval_identity_write_once"
            )
            connection.execute(
                """
                UPDATE approval_queue
                SET approval_id = ?
                WHERE approval_id = ?
                """,
                (forged_id, submitted.approval_id),
            )
            connection.execute(str(trigger_sql))
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "Approval ID binding is invalid",
        ):
            self.approvals.get(forged_id)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "Approval ID binding is invalid",
        ):
            self.approvals.list(self.mission.mission_id)

    def test_get_and_list_reject_a_forged_approved_state(self) -> None:
        submitted = self.approvals.submit(
            mission_id=self.mission.mission_id,
            proposal_id="EVT-003",
            executor_profile_id=EXECUTOR_ID,
            review_expires_at="2026-07-29T15:10:00Z",
            idempotency_key="hardening-submit-forged-state",
            principal_profile_id=EXECUTOR_ID,
        )
        connection = sqlite3.connect(self.store.path)
        try:
            connection.execute(
                """
                UPDATE approval_queue
                SET status = 'approved',
                    version = 2,
                    authorization_expires_at = ?
                WHERE approval_id = ?
                """,
                ("2026-07-29T15:20:00Z", submitted.approval_id),
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "decision actor is not Control",
        ):
            self.approvals.get(submitted.approval_id)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "decision actor is not Control",
        ):
            self.approvals.list(self.mission.mission_id)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "decision actor is not Control",
        ):
            self.approvals.submit(
                mission_id=self.mission.mission_id,
                proposal_id="EVT-003",
                executor_profile_id=EXECUTOR_ID,
                review_expires_at="2026-07-29T15:10:00Z",
                idempotency_key="hardening-submit-forged-state",
                principal_profile_id=EXECUTOR_ID,
            )

    def test_custom_adapter_is_rejected_without_running_it(self) -> None:
        adapter = ExplodingAdapter()

        with self.assertRaisesRegex(SimulationError, "Custom simulation adapters"):
            SimulationService(
                self.store,
                self.registry,
                adapter=adapter,  # type: ignore[arg-type]
                clock=self.clock,
            )

        self.assertFalse(adapter.called)

    def test_mismatched_fixed_receipt_is_rejected_before_consumption(self) -> None:
        approval_id = self.approved_request()
        original_render = PolicySimulationAdapter.render

        def render_mismatched(
            adapter: PolicySimulationAdapter,
            context: object,
        ) -> SimulationReceipt:
            receipt = original_render(adapter, context)  # type: ignore[arg-type]
            raw = receipt.to_dict()
            raw["executor_profile_id"] = OTHER_PROFILE_ID
            content = {
                key: value
                for key, value in raw.items()
                if key != "receipt_hash"
            }
            raw["receipt_hash"] = sha256_text(canonical_json(content))
            return SimulationReceipt.from_dict(raw)

        service = SimulationService(
            self.store,
            self.registry,
            clock=self.clock,
        )
        with (
            mock.patch.object(
                PolicySimulationAdapter,
                "render",
                new=render_mismatched,
            ),
            self.assertRaisesRegex(SimulationError, "authorized context"),
        ):
            service.simulate(
                approval_id,
                idempotency_key="hardening-simulate-003",
                principal_profile_id=EXECUTOR_ID,
            )

        self.assertEqual(self.approvals.get(approval_id).state, ApprovalState.APPROVED)
        self.assertEqual(self.receipt_count(), 0)

    def test_get_rejects_a_self_consistent_forged_receipt(self) -> None:
        approval_id = self.approved_request()
        service = SimulationService(
            self.store,
            self.registry,
            clock=self.clock,
        )
        receipt = service.simulate(
            approval_id,
            idempotency_key="hardening-simulate-004",
            principal_profile_id=EXECUTOR_ID,
        )
        raw = receipt.to_dict()
        raw["action_hash"] = "sha256:" + ("0" * 64)
        content = {
            key: value
            for key, value in raw.items()
            if key != "receipt_hash"
        }
        raw["receipt_hash"] = sha256_text(canonical_json(content))
        forged_json = canonical_json(raw)
        connection = sqlite3.connect(self.store.path)
        try:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'simulation_receipt_immutable'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER simulation_receipt_immutable"
            )
            connection.execute(
                """
                UPDATE simulation_receipts
                SET receipt_json = ?, receipt_hash = ?
                WHERE mission_id = ? AND simulation_id = ?
                """,
                (
                    forged_json,
                    raw["receipt_hash"],
                    self.mission.mission_id,
                    receipt.simulation_id,
                ),
            )
            connection.execute(str(trigger_sql))
            connection.commit()
        finally:
            connection.close()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "receipt indexes are invalid",
        ):
            service.get(self.mission.mission_id, receipt.simulation_id)


if __name__ == "__main__":
    unittest.main()
