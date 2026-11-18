from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import sunderkey.approvals as approvals_module
from sunderkey.approvals import ApprovalService, ApprovalState
from sunderkey.errors import StoreError
from sunderkey.events import MissionEvent
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import (
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
FIRST_PROPOSAL_ID = "EVT-PROP-001"
SECOND_PROPOSAL_ID = "EVT-PROP-002"


def legacy_decision_event_id(kind: str, approval_id: str) -> str:
    digest = hashlib.sha256(f"{kind}\n{approval_id}".encode("ascii")).hexdigest()[:20].upper()
    return f"EVT-{kind}-{digest}"


class ApprovalDecisionCollisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.store = MissionStore(
            self.path,
            clock=lambda: DECISION_TIME,
        )
        self.store.initialize()
        self.store.create_mission(
            self.registry,
            MissionRequest.from_dict(mission_data()),
        )
        second_proposal = proposal_data()
        second_proposal["event_id"] = SECOND_PROPOSAL_ID
        second_proposal["timestamp"] = "2026-01-01T10:01:00Z"
        second_proposal["payload"]["target"] = "synthetic://store/second-policy-model"
        self.proposals = (
            MissionEvent.from_dict(proposal_data()),
            MissionEvent.from_dict(second_proposal),
        )
        self.store.append_events(
            self.registry,
            MISSION_ID,
            self.proposals,
            expected_revision=0,
        )
        self.approvals = ApprovalService(
            self.store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )

    def submit(self, proposal_id: str, key: str):
        return self.approvals.submit(
            mission_id=MISSION_ID,
            proposal_id=proposal_id,
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key=key,
            principal_profile_id=SPECIALIST_ID,
        )

    def downgrade_to_v1(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            downgrade_connection_to_schema_v1(connection)
        self.store.verify_store(self.registry)

    def migrate(self, name: str) -> Path:
        backup = self.directory / name
        report = self.store.migrate(self.registry, backup)
        self.assertEqual(report.status, "migrated")
        self.assertEqual(report.source_version, 1)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        self.assertTrue(backup.is_file())
        MissionStore(backup).verify_store(self.registry)
        return backup

    def test_migrated_orphans_force_auth_and_block_candidate_one(self) -> None:
        authorization = self.submit(FIRST_PROPOSAL_ID, "auth-submit")
        denial = self.submit(SECOND_PROPOSAL_ID, "block-submit")

        authority = "collision-control"
        constraints = ("Simulation only",)
        authorization_expires_at = "2026-01-01T11:00:00Z"
        auth_key = "auth-decision"
        auth_key_hash = sha256_text(auth_key)
        auth_request_hash = sha256_text(
            canonical_json(
                {
                    "approval_id": authorization.approval_id,
                    "authority": authority,
                    "constraints": list(constraints),
                    "authorization_expires_at": authorization_expires_at,
                    "principal_profile_id": CONTROL_ID,
                    "expected_version": 1,
                }
            )
        )
        auth_collision_id = control_event_id(
            "AUTH",
            authorization.approval_id,
            auth_key_hash,
            auth_request_hash,
            0,
        )

        reason_code = "scope-not-confirmed"
        reason = "Scope confirmation is incomplete"
        risk = "Target identity is ambiguous"
        decision_owner = "range-control"
        block_key = "block-decision"
        block_key_hash = sha256_text(block_key)
        block_request_hash = sha256_text(
            canonical_json(
                {
                    "approval_id": denial.approval_id,
                    "reason_code": reason_code,
                    "reason": reason,
                    "risk": risk,
                    "decision_owner": decision_owner,
                    "principal_profile_id": CONTROL_ID,
                    "expected_version": 1,
                }
            )
        )
        block_collision_id = control_event_id(
            "BLOCK",
            denial.approval_id,
            block_key_hash,
            block_request_hash,
            0,
        )
        auth_orphan = observation(auth_collision_id, minute=2)
        block_orphan = observation(block_collision_id, minute=3)
        with self.store._write_connection() as connection:
            self.store._append_events_in_connection(
                connection,
                self.registry,
                MISSION_ID,
                (auth_orphan, block_orphan),
                expected_revision=2,
                allow_control_events=True,
            )

        self.downgrade_to_v1()
        self.migrate("orphan-collisions-v1.sqlite3")

        approved = self.approvals.approve(
            authorization.approval_id,
            authority=authority,
            constraints=constraints,
            authorization_expires_at=authorization_expires_at,
            idempotency_key=auth_key,
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        denied = self.approvals.deny(
            denial.approval_id,
            reason_code=reason_code,
            reason=reason,
            risk=risk,
            decision_owner=decision_owner,
            idempotency_key=block_key,
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )

        expected_auth_id = control_event_id(
            "AUTH",
            authorization.approval_id,
            auth_key_hash,
            auth_request_hash,
            1,
        )
        expected_block_id = control_event_id(
            "BLOCK",
            denial.approval_id,
            block_key_hash,
            block_request_hash,
            1,
        )
        self.assertEqual(
            approved.authorization_event_id,
            expected_auth_id,
        )
        self.assertEqual(approved.decision_event_id, expected_auth_id)
        self.assertEqual(denied.decision_event_id, expected_block_id)
        self.assertIn("-C00000001-", expected_auth_id)
        self.assertIn("-C00000001-", expected_block_id)
        self.assertNotEqual(expected_auth_id, auth_collision_id)
        self.assertNotEqual(expected_block_id, block_collision_id)

        auth_replay = self.store.append_event(
            self.registry,
            auth_orphan,
        )
        block_replay = self.store.append_event(
            self.registry,
            block_orphan,
        )
        self.assertTrue(auth_replay.idempotent)
        self.assertTrue(block_replay.idempotent)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_bound_legacy_auth_and_block_ids_survive_migration(self) -> None:
        authorization = self.submit(FIRST_PROPOSAL_ID, "legacy-auth-submit")
        denial = self.submit(SECOND_PROPOSAL_ID, "legacy-block-submit")
        legacy_auth_id = legacy_decision_event_id(
            "AUTH",
            authorization.approval_id,
        )
        legacy_block_id = legacy_decision_event_id(
            "BLOCK",
            denial.approval_id,
        )

        with mock.patch.object(
            approvals_module,
            "allocate_control_event_id",
            return_value=legacy_auth_id,
        ):
            approved = self.approvals.approve(
                authorization.approval_id,
                authority="legacy-control",
                constraints=("Simulation only",),
                authorization_expires_at="2026-01-01T11:00:00Z",
                idempotency_key="legacy-auth-decision",
                expected_version=1,
                principal_profile_id=CONTROL_ID,
            )
        with mock.patch.object(
            approvals_module,
            "allocate_control_event_id",
            return_value=legacy_block_id,
        ):
            denied = self.approvals.deny(
                denial.approval_id,
                reason_code="scope-not-confirmed",
                reason="Scope confirmation is incomplete",
                risk="Target identity is ambiguous",
                decision_owner="range-control",
                idempotency_key="legacy-block-decision",
                expected_version=1,
                principal_profile_id=CONTROL_ID,
            )

        self.assertEqual(approved.state, ApprovalState.APPROVED)
        self.assertEqual(approved.authorization_event_id, legacy_auth_id)
        self.assertEqual(approved.decision_event_id, legacy_auth_id)
        self.assertEqual(denied.state, ApprovalState.DENIED)
        self.assertEqual(denied.decision_event_id, legacy_block_id)
        self.store.verify_store(self.registry)

        self.downgrade_to_v1()
        self.migrate("bound-legacy-decisions-v1.sqlite3")

        migrated_approved = self.approvals.get(authorization.approval_id)
        migrated_denied = self.approvals.get(denial.approval_id)
        self.assertEqual(
            migrated_approved.authorization_event_id,
            legacy_auth_id,
        )
        self.assertEqual(
            migrated_approved.decision_event_id,
            legacy_auth_id,
        )
        self.assertEqual(
            migrated_denied.decision_event_id,
            legacy_block_id,
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_public_append_reserves_only_derived_decision_namespaces(self) -> None:
        generic_events = (
            observation("EVT-AUTH-LEGACY-GENERIC", minute=2),
            observation("EVT-BLOCK-LEGACY-GENERIC", minute=3),
        )
        generic_receipts = self.store.append_events(
            self.registry,
            MISSION_ID,
            generic_events,
            expected_revision=2,
        )
        self.assertTrue(all(not receipt.idempotent for receipt in generic_receipts))

        reserved_ids = (
            control_event_id(
                "AUTH",
                "APR-RESERVED-AUTH",
                sha256_text("reserved-auth-key"),
                sha256_text("reserved-auth-request"),
                0,
            ),
            control_event_id(
                "BLOCK",
                "APR-RESERVED-BLOCK",
                sha256_text("reserved-block-key"),
                sha256_text("reserved-block-request"),
                0,
            ),
            "EVT-STOP-RESERVED",
            "EVT-REVOKE-RESERVED",
        )
        for minute, event_id in enumerate(reserved_ids, 4):
            with (
                self.subTest(event_id=event_id),
                self.assertRaisesRegex(
                    StoreError,
                    "must be created through their services",
                ),
            ):
                self.store.append_event(
                    self.registry,
                    observation(event_id, minute=minute),
                    expected_revision=4,
                )
        report = self.store.verify_store(self.registry)
        self.assertEqual(report.status, "valid")
        self.assertEqual(report.event_count, 4)


if __name__ == "__main__":
    unittest.main()
