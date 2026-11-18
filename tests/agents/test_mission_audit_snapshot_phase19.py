"""Phase 19 verified mission audit snapshot coverage."""

from __future__ import annotations

import ast
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from sunderkey.errors import StoreError, StoreIntegrityError
from sunderkey.mission import MissionRequest
from sunderkey.mission_audit import (
    MissionAuditSnapshotReceipt,
    MissionAuditSnapshotService,
)
from sunderkey.store import SCHEMA_VERSION, MissionStore

from . import test_authenticated_work_handoffs_phase18 as phase18
from .test_store import mission_data

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_ID = phase18.CANDIDATE_ID
MISSION_ID = phase18.MISSION_ID


class MissionAuditSnapshotPhase19Tests(unittest.TestCase):
    """Exercise verified point-in-time mission projections."""

    @classmethod
    def setUpClass(cls) -> None:
        phase18.AuthenticatedWorkHandoffPhase18Tests.setUpClass()
        cls.registry = (
            phase18.AuthenticatedWorkHandoffPhase18Tests.registry
        )

    def setUp(self) -> None:
        self.fixture = phase18.AuthenticatedWorkHandoffPhase18Tests(
            methodName=(
                "test_unclaimed_handoff_projects_owner_and_replays"
            )
        )
        self.fixture.registry = self.registry
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.service = MissionAuditSnapshotService(
            self.fixture.store,
            self.registry,
            clock=lambda: self.fixture.now,
        )

    def test_snapshot_is_deterministic_self_identifying_and_read_only(
        self,
    ) -> None:
        before = self.fixture.path.read_bytes()

        first = self.service.snapshot(MISSION_ID)
        second = self.service.snapshot(MISSION_ID)

        self.assertEqual(first, second)
        self.assertEqual(
            MissionAuditSnapshotReceipt.from_dict(first.to_dict()),
            first,
        )
        self.assertEqual(self.fixture.path.read_bytes(), before)
        snapshot = first.to_dict()
        self.assertEqual(snapshot["schema_version"], 1)
        self.assertRegex(snapshot["snapshot_id"], r"^MAS-[0-9A-F]{32}$")
        self.assertRegex(
            snapshot["snapshot_sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(snapshot["integrity"]["status"], "verified")
        self.assertTrue(
            snapshot["integrity"]["sqlite_query_only"]
        )
        self.assertEqual(
            snapshot["integrity"]["authorization_effect"],
            "none",
        )
        self.assertEqual(snapshot["store"]["schema_version"], SCHEMA_VERSION)
        self.assertEqual(
            snapshot["mission"]["mission_id"],
            MISSION_ID,
        )
        self.assertNotIn(
            self.fixture.mission.objective,
            first.document_json,
        )

    def test_snapshot_projects_effective_handoff_and_work_state(
        self,
    ) -> None:
        self.fixture._complete_readiness()
        _, handoff = self.fixture._handoff()
        claim = self.fixture._claim(
            self.fixture.source,
            CANDIDATE_ID,
            "3",
            0,
        )

        snapshot = self.service.snapshot(MISSION_ID).to_dict()
        collaboration = snapshot["collaboration"]
        source = next(
            item
            for item in collaboration["work"]["work_items"]
            if item["work_item_id"]
            == self.fixture.source.work_item_id
        )

        self.assertTrue(collaboration["activated"])
        self.assertEqual(collaboration["handoff_count"], 1)
        self.assertEqual(collaboration["transition_count"], 3)
        self.assertEqual(source["state"], "leased")
        self.assertEqual(source["owner_profile_id"], CANDIDATE_ID)
        self.assertEqual(
            source["planned_owner_profile_id"],
            self.fixture.source.owner_profile_id,
        )
        self.assertEqual(source["handoff_id"], handoff.handoff_id)
        self.assertEqual(
            source["current_transition_id"],
            claim.transition_id,
        )
        operations = snapshot["authentication"][
            "counts_by_operation"
        ]
        self.assertEqual(
            operations["sunderkey.work.handoff.authorize.v1"],
            1,
        )
        self.assertEqual(
            operations["sunderkey.work.handoff.accept.v1"],
            1,
        )
        self.assertEqual(
            operations["sunderkey.work.claim.v1"],
            2,
        )
        self.assertEqual(
            operations["sunderkey.work.complete.v1"],
            1,
        )

    def test_snapshot_rejects_protected_state_tampering(self) -> None:
        self.fixture._handoff()
        with closing(
            sqlite3.connect(self.fixture.path)
        ) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_schema
                WHERE type = 'trigger'
                  AND name =
                    'collaboration_work_item_handoffs_immutable'
                """
            ).fetchone()[0]
            connection.execute(
                """
                DROP TRIGGER
                    collaboration_work_item_handoffs_immutable
                """
            )
            connection.execute(
                """
                UPDATE collaboration_work_item_handoffs
                SET reason = 'Unreviewed replacement'
                """
            )
            connection.execute(trigger_sql)
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.service.snapshot(MISSION_ID)

    def test_receipt_rejects_tampering(self) -> None:
        document = self.service.snapshot(MISSION_ID).to_dict()
        document["events"]["count"] += 1

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "hash is invalid",
        ):
            MissionAuditSnapshotReceipt.from_dict(document)

    def test_preactivation_snapshot_has_no_work_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            now = datetime(2026, 7, 30, 9, 0, tzinfo=UTC)
            path = Path(temporary) / "preactivation.sqlite3"
            store = MissionStore(path, clock=lambda: now)
            store.initialize()
            mission = MissionRequest.from_dict(mission_data())
            store.create_mission(self.registry, mission)
            snapshot = MissionAuditSnapshotService(
                store,
                self.registry,
                clock=lambda: now,
            ).snapshot(mission.mission_id).to_dict()

        self.assertFalse(snapshot["collaboration"]["activated"])
        self.assertIsNone(snapshot["collaboration"]["activation"])
        self.assertIsNone(snapshot["collaboration"]["work"])
        self.assertEqual(snapshot["scope"]["accepted_grant_count"], 0)
        self.assertEqual(
            snapshot["authentication"]["assertion_count"],
            0,
        )

    def test_invalid_and_unknown_missions_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            StoreError,
            "not a valid mission ID",
        ):
            self.service.snapshot("../mission")
        with self.assertRaisesRegex(
            StoreError,
            "Unknown stored mission",
        ):
            self.service.snapshot("MISSION-NOT-STORED")

    def test_module_has_no_network_or_process_dependencies(self) -> None:
        source = (
            ROOT / "src" / "sunderkey" / "mission_audit.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module is not None
            and not node.level
        )
        self.assertTrue(
            {
                "http",
                "requests",
                "socket",
                "subprocess",
                "urllib",
            }.isdisjoint(imported)
        )


if __name__ == "__main__":
    unittest.main()
