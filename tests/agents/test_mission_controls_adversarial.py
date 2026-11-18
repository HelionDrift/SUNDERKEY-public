from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier
from unittest import mock

import sunderkey.store as store_module
from sunderkey.approvals import (
    ApprovalRevocationRecord,
    ApprovalService,
    ApprovalState,
)
from sunderkey.errors import (
    StoreConflictError,
    StoreIntegrityError,
    StoreMigrationRequiredError,
)
from sunderkey.events import MissionEvent
from sunderkey.mission import MissionRequest
from sunderkey.mission_control import MissionControlService
from sunderkey.registry import load_registry
from sunderkey.store import MissionStore, sha256_text

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


class Phase3AdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.mission = MissionRequest.from_dict(mission_data())

    def create_store(self, name: str) -> MissionStore:
        store = MissionStore(
            self.directory / name,
            clock=lambda: DECISION_TIME,
        )
        store.initialize()
        store.create_mission(self.registry, self.mission)
        store.append_event(
            self.registry,
            MissionEvent.from_dict(proposal_data()),
            expected_revision=0,
        )
        return store

    def stop_mission(self, store: MissionStore) -> None:
        MissionControlService(
            store,
            self.registry,
            clock=lambda: DECISION_TIME,
        ).stop(
            MISSION_ID,
            reason_code="operator_request",
            reason="Operator requested a terminal stop",
            risk="Continued work is no longer authorized",
            decision_owner="range-control",
            idempotency_key="adversarial-stop",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )

    def approved_request(
        self,
        store: MissionStore,
    ) -> tuple[ApprovalService, str]:
        approvals = ApprovalService(
            store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )
        submitted = approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="adversarial-submit",
            principal_profile_id=SPECIALIST_ID,
        )
        approvals.approve(
            submitted.approval_id,
            authority="adversarial-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-01-01T11:00:00Z",
            idempotency_key="adversarial-approve",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        return approvals, submitted.approval_id

    def test_mission_stop_row_hash_and_event_binding_tampering_is_detected(
        self,
    ) -> None:
        mutations = (
            (
                "row-content",
                """
                UPDATE mission_controls
                SET stop_reason = 'tampered reason'
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ),
            (
                "valid-but-wrong-request-hash",
                """
                UPDATE mission_controls
                SET stop_request_hash = ?
                WHERE mission_id = ?
                """,
                (sha256_text("different stop request"), MISSION_ID),
            ),
            (
                "foreign-key-valid-wrong-event",
                """
                UPDATE mission_controls
                SET stop_event_id = 'EVT-PROP-001'
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ),
        )

        for index, (label, statement, parameters) in enumerate(mutations):
            with self.subTest(tampering=label):
                store = self.create_store(f"tamper-{index}.sqlite3")
                self.stop_mission(store)
                with closing(sqlite3.connect(store.path)) as connection:
                    connection.execute(statement, parameters)
                    connection.commit()

                with self.assertRaises(StoreIntegrityError):
                    store.verify_store(self.registry)

    def test_wal_reset_fix_gate_tracks_fixed_sqlite_release_lines(
        self,
    ) -> None:
        cases = (
            ((3, 44, 5), False),
            ((3, 44, 6), True),
            ((3, 45, 0), False),
            ((3, 50, 6), False),
            ((3, 50, 7), True),
            ((3, 51, 2), False),
            ((3, 51, 3), True),
            ((3, 53, 3), True),
        )
        for version, expected in cases:
            with (
                self.subTest(version=version),
                mock.patch.object(
                    store_module.sqlite3,
                    "sqlite_version_info",
                    version,
                ),
            ):
                self.assertEqual(
                    store_module.sqlite_wal_reset_fix_available(),
                    expected,
                )

    def test_two_exact_concurrent_revocations_converge_once(self) -> None:
        store = self.create_store("concurrent-revoke.sqlite3")
        approvals, approval_id = self.approved_request(store)
        before = store.get_mission(self.registry, MISSION_ID)
        barrier = Barrier(2)

        def revoke() -> ApprovalRevocationRecord:
            service = ApprovalService(
                MissionStore(
                    store.path,
                    clock=lambda: DECISION_TIME,
                ),
                self.registry,
                clock=lambda: DECISION_TIME,
            )
            barrier.wait()
            return service.revoke(
                approval_id,
                reason_code="scope-withdrawn",
                reason="The delegated scope was withdrawn",
                risk="Simulation would use stale authority",
                decision_owner="range-control",
                idempotency_key="exact-concurrent-revocation",
                expected_version=2,
                principal_profile_id=CONTROL_ID,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(revoke)
            second_future = executor.submit(revoke)
            first = first_future.result()
            second = second_future.result()

        self.assertEqual(first, second)
        self.assertEqual(
            approvals.get(approval_id).state,
            ApprovalState.REVOKED,
        )
        self.assertEqual(approvals.get(approval_id).version, 3)
        after = store.get_mission(self.registry, MISSION_ID)
        self.assertEqual(after.revision, before.revision + 1)

        with closing(sqlite3.connect(store.path)) as connection:
            revocation_rows = connection.execute(
                """
                SELECT COUNT(*) FROM approval_revocations
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()[0]
            event_rows = connection.execute(
                """
                SELECT COUNT(*) FROM mission_events
                WHERE mission_id = ? AND event_id = ?
                """,
                (MISSION_ID, first.revocation_event_id),
            ).fetchone()[0]
            terminal_row = connection.execute(
                """
                SELECT status, version FROM approval_queue
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()

        self.assertEqual(revocation_rows, 1)
        self.assertEqual(event_rows, 1)
        self.assertEqual(terminal_row, ("revoked", 3))
        store.verify_store(self.registry)

    def test_migration_publication_race_preserves_racing_destination(
        self,
    ) -> None:
        store = self.create_store("legacy-race.sqlite3")
        with closing(sqlite3.connect(store.path)) as connection:
            historical_before = {
                "missions": connection.execute(
                    "SELECT * FROM missions ORDER BY mission_id"
                ).fetchall(),
                "events": connection.execute(
                    """
                    SELECT * FROM mission_events
                    ORDER BY mission_id, sequence
                    """
                ).fetchall(),
            }
            downgrade_connection_to_schema_v1(connection)
            journal_mode = str(
                connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            ).lower()
        self.assertEqual(journal_mode, "wal")

        backup = self.directory / "migration-backup.sqlite3"
        racing_content = b"racing publisher owns this path"
        real_link = store_module.os.link

        def publish_racing_file(
            source: str | bytes | Path,
            destination: str | bytes | Path,
        ) -> None:
            Path(destination).write_bytes(racing_content)
            real_link(source, destination)

        with (
            mock.patch.object(
                store_module.os,
                "link",
                side_effect=publish_racing_file,
            ),
            mock.patch.object(
                store_module,
                "sqlite_wal_reset_fix_available",
                return_value=True,
            ),
            self.assertRaises(StoreConflictError),
        ):
            store.migrate(self.registry, backup)

        self.assertEqual(backup.read_bytes(), racing_content)
        temporary_backups = tuple(self.directory.glob(f".{backup.name}.*.migration.tmp"))
        self.assertEqual(temporary_backups, ())

        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT value FROM store_metadata
                    WHERE key = 'schema_version'
                    """
                ).fetchone()[0],
                "1",
            )
            self.assertEqual(
                str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                "wal",
            )
            objects = {
                str(row[0])
                for row in connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    """
                ).fetchall()
            }
            historical_after = {
                "missions": connection.execute(
                    "SELECT * FROM missions ORDER BY mission_id"
                ).fetchall(),
                "events": connection.execute(
                    """
                    SELECT * FROM mission_events
                    ORDER BY mission_id, sequence
                    """
                ).fetchall(),
            }

        self.assertNotIn("mission_controls", objects)
        self.assertNotIn("approval_revocations", objects)
        self.assertEqual(historical_after, historical_before)
        store.verify_store(self.registry)
        with self.assertRaises(StoreMigrationRequiredError):
            store.append_event(
                self.registry,
                observation("EVT-AFTER-RACE", minute=6),
            )


if __name__ == "__main__":
    unittest.main()
