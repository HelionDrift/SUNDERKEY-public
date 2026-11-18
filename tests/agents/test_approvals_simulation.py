from __future__ import annotations

import ast
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from sunderkey.approvals import ApprovalService, ApprovalState
from sunderkey.errors import (
    ApprovalConflictError,
    ApprovalError,
    ApprovalExpiredError,
    SimulationError,
)
from sunderkey.events import MissionEvent
from sunderkey.mission import load_mission_request
from sunderkey.registry import load_registry
from sunderkey.simulation import SimulationService
from sunderkey.store import MissionStore
from sunderkey.types import EventType, EvidenceLevel

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
MISSION_PATH = ROOT / "examples" / "missions" / "internet-api-to-data.json"
EVENTS_PATH = ROOT / "examples" / "events" / "internet-api-to-data.jsonl"


class MutableClock:
    def __init__(self, value: str) -> None:
        self.set(value)

    def set(self, value: str) -> None:
        self.value = datetime.fromisoformat(value.replace("Z", "+00:00"))

    def __call__(self) -> datetime:
        return self.value


class ApprovalSimulationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = MutableClock("2026-07-29T15:06:00Z")
        self.registry = load_registry(REGISTRY_PATH)
        self.mission = load_mission_request(MISSION_PATH)
        self.store = MissionStore(
            Path(self.temporary.name) / "missions.sqlite3",
            clock=self.clock,
        )
        self.store.initialize()
        self.store.create_mission(self.registry, self.mission)
        raw_events = [
            json.loads(line)
            for line in EVENTS_PATH.read_text(encoding="utf-8").splitlines()
        ]
        self.initial_events = tuple(
            MissionEvent.from_dict(raw)
            for raw in raw_events[:3]
        )
        self.store.append_events(
            self.registry,
            self.mission.mission_id,
            self.initial_events,
            expected_revision=0,
        )
        self.approvals = ApprovalService(
            self.store,
            self.registry,
            clock=self.clock,
        )

    def submit(self) -> str:
        record = self.approvals.submit(
            mission_id=self.mission.mission_id,
            proposal_id="EVT-003",
            executor_profile_id="AOE-GB-D06-S09",
            review_expires_at="2026-07-29T15:10:00Z",
            idempotency_key="submit-001",
            principal_profile_id="AOE-GB-D06-S09",
        )
        self.assertEqual(record.state, ApprovalState.PENDING)
        return record.approval_id

    def approve(self, approval_id: str) -> None:
        record = self.approvals.approve(
            approval_id,
            authority="delegated-control",
            constraints=("Synthetic data only", "No external actions"),
            authorization_expires_at="2026-07-29T15:20:00Z",
            idempotency_key="approve-001",
            expected_version=1,
            principal_profile_id="AOE-HQ-12",
        )
        self.assertEqual(record.state, ApprovalState.APPROVED)
        self.assertEqual(record.version, 2)
        self.assertIsNotNone(record.authorization_event_id)

    def test_submit_is_idempotent_and_conflicts_fail_closed(self) -> None:
        approval_id = self.submit()
        replay = self.approvals.submit(
            mission_id=self.mission.mission_id,
            proposal_id="EVT-003",
            executor_profile_id="AOE-GB-D06-S09",
            review_expires_at="2026-07-29T15:10:00Z",
            idempotency_key="submit-001",
            principal_profile_id="AOE-GB-D06-S09",
        )
        self.assertEqual(replay.approval_id, approval_id)
        with self.assertRaises(ApprovalConflictError):
            self.approvals.submit(
                mission_id=self.mission.mission_id,
                proposal_id="EVT-003",
                executor_profile_id="AOE-GA-D03-S13",
                review_expires_at="2026-07-29T15:10:00Z",
                idempotency_key="submit-002",
                principal_profile_id="AOE-GB-D06-S09",
            )

    def test_approval_and_simulation_are_atomic_and_non_executing(self) -> None:
        approval_id = self.submit()
        self.approve(approval_id)
        events = self.store.list_events(
            self.registry,
            self.mission.mission_id,
        )
        self.assertEqual(len(events), 4)
        authorization = events[-1].event
        self.assertEqual(authorization.event_type, EventType.AUTHORIZATION)
        self.assertEqual(authorization.payload["purpose"], "simulation")
        self.assertEqual(authorization.payload["approval_id"], approval_id)

        service = SimulationService(
            self.store,
            self.registry,
            clock=self.clock,
        )
        receipt = service.simulate(
            approval_id,
            idempotency_key="simulate-001",
            principal_profile_id="AOE-GB-D06-S09",
        )
        self.assertFalse(receipt.external_actions_performed)
        self.assertTrue(receipt.approval_consumed)
        self.assertEqual(receipt.evidence_level, EvidenceLevel.E0)
        self.assertNotIn("target", receipt.to_dict())
        self.assertNotIn("method", receipt.to_dict())
        self.assertEqual(
            len(
                self.store.list_events(
                    self.registry,
                    self.mission.mission_id,
                )
            ),
            4,
        )
        consumed = self.approvals.get(approval_id)
        self.assertEqual(consumed.state, ApprovalState.CONSUMED)

        replay = service.simulate(
            approval_id,
            idempotency_key="simulate-001",
            principal_profile_id="AOE-GB-D06-S09",
        )
        self.assertEqual(replay, receipt)
        with self.assertRaises(ApprovalConflictError):
            service.simulate(
                approval_id,
                idempotency_key="simulate-002",
                principal_profile_id="AOE-GB-D06-S09",
            )

    def test_non_control_actor_cannot_approve(self) -> None:
        approval_id = self.submit()
        with self.assertRaises(ApprovalError):
            self.approvals.approve(
                approval_id,
                authority="self-asserted",
                constraints=("Synthetic data only",),
                authorization_expires_at="2026-07-29T15:20:00Z",
                idempotency_key="approve-invalid",
                expected_version=1,
                principal_profile_id="AOE-GA-D03-S13",
            )
        self.assertEqual(
            self.approvals.get(approval_id).state,
            ApprovalState.PENDING,
        )
        self.assertEqual(
            len(
                self.store.list_events(
                    self.registry,
                    self.mission.mission_id,
                )
            ),
            3,
        )

    def test_review_expiry_boundary_fails(self) -> None:
        approval_id = self.submit()
        self.clock.set("2026-07-29T15:10:00Z")
        with self.assertRaises(ApprovalExpiredError):
            self.approvals.approve(
                approval_id,
                authority="delegated-control",
                constraints=("Synthetic data only",),
                authorization_expires_at="2026-07-29T15:20:00Z",
                idempotency_key="approve-expired",
                expected_version=1,
                principal_profile_id="AOE-HQ-12",
            )
        self.assertEqual(
            self.approvals.get(approval_id).state,
            ApprovalState.EXPIRED,
        )

    def test_denial_adds_a_blocker_and_no_authorization(self) -> None:
        approval_id = self.submit()
        denied = self.approvals.deny(
            approval_id,
            reason_code="scope-not-confirmed",
            reason="Scope confirmation is incomplete",
            risk="Target identity is ambiguous",
            decision_owner="owner://mission/control",
            idempotency_key="deny-001",
            expected_version=1,
            principal_profile_id="AOE-HQ-12",
        )
        self.assertEqual(denied.state, ApprovalState.DENIED)
        events = self.store.list_events(
            self.registry,
            self.mission.mission_id,
        )
        self.assertEqual(events[-1].event.event_type, EventType.BLOCKER)
        self.assertNotIn(
            EventType.AUTHORIZATION,
            tuple(event.event.event_type for event in events),
        )

    def test_wrong_executor_and_expired_authorization_cannot_simulate(self) -> None:
        approval_id = self.submit()
        self.approve(approval_id)
        service = SimulationService(
            self.store,
            self.registry,
            clock=self.clock,
        )
        with self.assertRaises(SimulationError):
            service.simulate(
                approval_id,
                idempotency_key="simulate-wrong-actor",
                principal_profile_id="AOE-GA-D03-S13",
            )
        self.clock.set("2026-07-29T15:20:00Z")
        with self.assertRaises(ApprovalExpiredError):
            service.simulate(
                approval_id,
                idempotency_key="simulate-expired",
                principal_profile_id="AOE-GB-D06-S09",
            )

    def test_tampered_simulation_receipt_is_rejected(self) -> None:
        approval_id = self.submit()
        self.approve(approval_id)
        service = SimulationService(
            self.store,
            self.registry,
            clock=self.clock,
        )
        receipt = service.simulate(
            approval_id,
            idempotency_key="simulate-tamper",
            principal_profile_id="AOE-GB-D06-S09",
        )
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
                SET receipt_hash = ?
                WHERE mission_id = ? AND simulation_id = ?
                """,
                (
                    "sha256:" + "0" * 64,
                    self.mission.mission_id,
                    receipt.simulation_id,
                ),
            )
            connection.execute(str(trigger_sql))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(SimulationError):
            service.get(self.mission.mission_id, receipt.simulation_id)

    def test_simulation_module_has_no_execution_imports_or_calls(self) -> None:
        source_path = ROOT / "src" / "sunderkey" / "simulation.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_imports = {
            "socket",
            "subprocess",
            "urllib",
            "http",
            "requests",
        }
        forbidden_calls = {"eval", "exec", "compile", "__import__"}
        imported: set[str] = set()
        called: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called.add(node.func.id)
        self.assertFalse(imported & forbidden_imports)
        self.assertFalse(called & forbidden_calls)


if __name__ == "__main__":
    unittest.main()
