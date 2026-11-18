"""Phase 124 read-only execution session status projection coverage."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_execution_session_status import (
    CollaborationExecutionSessionAuthorityStatus,
    CollaborationExecutionSessionAuthorityStatusService,
)
from sunderkey.errors import CollaborationPlanError

from . import (
    test_authenticated_collaboration_execution_session_authority_phase123 as phase123,
)
from .test_store_phase121_schema import insert_authority

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    ROOT
    / "registry/schemas/collaboration-execution-session-authority-status-v1.schema.json"
)


class CollaborationExecutionSessionStatusPhase124Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = (
            phase123.AuthenticatedCollaborationExecutionSessionAuthorityPhase123Tests(
                methodName="runTest"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.service = CollaborationExecutionSessionAuthorityStatusService(
            fixture.root.store,
            fixture.root.registry,
            clock=lambda: fixture.root.now,
        )

    def _insert_pending(self) -> None:
        with closing(sqlite3.connect(self.fixture.root.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            insert_authority(connection, self.fixture.authority)
            connection.commit()

    def _get(self):
        return self.service.get(self.fixture.authority.session_authority_id)

    def test_pending_authority_is_not_reported_as_running(self) -> None:
        self._insert_pending()
        document = self._get().to_dict()
        self.assertEqual(document["control_plane_state"], "pending_activation")
        self.assertEqual(document["external_worker_state"], "unobserved")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertIsNone(document["activation"])
        self.assertIsNone(document["revocation"])

    def test_activated_authority_is_only_available_for_executor(self) -> None:
        receipt = self.fixture._activate()
        status = self._get()
        document = status.to_dict()
        self.assertEqual(
            document["control_plane_state"],
            "available_for_executor",
        )
        self.assertEqual(document["external_worker_state"], "unobserved")
        self.assertEqual(
            document["activation"]["authentication_id"],
            receipt.authentication_id,
        )
        self.assertEqual(
            CollaborationExecutionSessionAuthorityStatus.from_dict(document),
            status,
        )

    def test_revoked_state_precedes_expiry_and_retains_reason(self) -> None:
        self.fixture._activate()
        receipt = self.fixture._revoke()
        document = self._get().to_dict()
        self.assertEqual(document["control_plane_state"], "revoked")
        self.assertEqual(
            document["revocation"]["authentication_id"],
            receipt.authentication_id,
        )
        self.assertEqual(
            document["revocation"]["reason_code"],
            "operator_request",
        )

    def test_expiry_distinguishes_activated_and_unactivated_authority(self) -> None:
        self._insert_pending()
        self.fixture.root.now = datetime(2026, 7, 30, 10, 31, tzinfo=UTC)
        self.assertEqual(
            self._get().to_dict()["control_plane_state"],
            "expired_unactivated",
        )

        other = (
            phase123.AuthenticatedCollaborationExecutionSessionAuthorityPhase123Tests(
                methodName="runTest"
            )
        )
        other.setUp()
        self.addCleanup(other.doCleanups)
        other._activate()
        other.root.now = datetime(2026, 7, 30, 10, 31, tzinfo=UTC)
        other_service = CollaborationExecutionSessionAuthorityStatusService(
            other.root.store,
            other.root.registry,
            clock=lambda: other.root.now,
        )
        self.assertEqual(
            other_service.get(
                other.authority.session_authority_id
            ).to_dict()["control_plane_state"],
            "expired",
        )

    def test_projection_is_deterministic_read_only_and_schema_valid(self) -> None:
        self.fixture._activate()
        with closing(sqlite3.connect(self.fixture.root.path)) as connection:
            before = connection.total_changes
            ledger_before = connection.execute(
                "SELECT assertion_count, effect_count, head_hash "
                "FROM mission_principal_ledgers WHERE mission_id = ?",
                (self.fixture.mission_id,),
            ).fetchone()
        first = self._get()
        second = self._get()
        listed = self.service.list_for_mission(self.fixture.mission_id)
        self.assertEqual(first, second)
        self.assertEqual(listed, (first,))
        with closing(sqlite3.connect(self.fixture.root.path)) as connection:
            self.assertEqual(connection.total_changes, before)
            ledger_after = connection.execute(
                "SELECT assertion_count, effect_count, head_hash "
                "FROM mission_principal_ledgers WHERE mission_id = ?",
                (self.fixture.mission_id,),
            ).fetchone()
        self.assertEqual(ledger_before, ledger_after)
        if Draft202012Validator is not None:
            Draft202012Validator(
                json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            ).validate(first.to_dict())

    def test_tampered_projection_is_rejected(self) -> None:
        self.fixture._activate()
        changed = self._get().to_dict()
        changed["external_worker_state"] = "running"
        with self.assertRaisesRegex(CollaborationPlanError, "boundary"):
            CollaborationExecutionSessionAuthorityStatus.from_dict(changed)


if __name__ == "__main__":
    unittest.main()
