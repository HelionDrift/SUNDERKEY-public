"""Schema v13 authenticated same-owner recovery coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.errors import StoreIntegrityError
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import (
    EXPECTED_SCHEMA_MANIFEST_V12,
    EXPECTED_SCHEMA_MANIFEST_V13,
    SCHEMA_VERSION,
    WORK_ITEM_RECOVERY_SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import (
    REGISTRY_PATH,
    mission_data,
    remove_schema_v13_objects,
)


class Phase16StoreSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.mission = MissionRequest.from_dict(mission_data())

    def initialized_store(self) -> MissionStore:
        store = MissionStore(self.path)
        store.initialize()
        store.create_mission(self.registry, self.mission)
        return store

    def downgrade_to_v12(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v13_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '12'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 12")
            connection.commit()

    def recovery_fixture(self):
        from .test_authenticated_work_recovery_phase16 import (
            AuthenticatedWorkRecoveryPhase16Tests,
        )

        fixture = AuthenticatedWorkRecoveryPhase16Tests(
            methodName="runTest"
        )
        fixture.registry = self.registry
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v13_objects_preserve_exact_v12_manifest(self) -> None:
        self.assertEqual(WORK_ITEM_RECOVERY_SCHEMA_VERSION, 13)
        self.assertGreaterEqual(SCHEMA_VERSION, 13)
        v12_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V12
        }
        v13_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V13
        }
        self.assertNotIn(
            "collaboration_work_item_recovery_requests",
            v12_names,
        )
        self.assertIn(
            "collaboration_work_item_recovery_requests",
            v13_names,
        )
        self.assertTrue(v12_names < v13_names)

        self.initialized_store()
        self.downgrade_to_v12()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V12,
            )

    def test_v12_migration_starts_with_no_recovery_rows(self) -> None:
        store = self.initialized_store()
        self.downgrade_to_v12()

        report = store.migrate(
            self.registry,
            self.directory / "before-v13.sqlite3",
        )

        self.assertEqual(report.source_version, 12)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            for table in (
                "collaboration_work_item_recovery_requests",
                "collaboration_work_item_recovery_decisions",
                "collaboration_work_item_recovery_transitions",
            ):
                self.assertEqual(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0],
                    0,
                )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_recovery_history_is_immutable(self) -> None:
        fixture = self.recovery_fixture()
        latest = fixture._exhaust()
        fixture._request(latest)

        with closing(sqlite3.connect(fixture.path)) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable",
            ):
                connection.execute(
                    """
                    UPDATE collaboration_work_item_recovery_requests
                    SET requested_at = requested_at
                    """
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM
                        collaboration_work_item_recovery_requests
                    """
                )

    def test_recovery_semantic_tampering_is_detected(self) -> None:
        fixture = self.recovery_fixture()
        latest = fixture._exhaust()
        fixture._request(latest)

        with closing(sqlite3.connect(fixture.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_schema
                WHERE type = 'trigger'
                  AND name =
                    'collaboration_work_recovery_requests_immutable'
                """
            ).fetchone()[0]
            connection.execute(
                """
                DROP TRIGGER
                    collaboration_work_recovery_requests_immutable
                """
            )
            connection.execute(
                """
                UPDATE collaboration_work_item_recovery_requests
                SET remediation = 'Unreviewed replacement'
                """
            )
            connection.execute(trigger_sql)
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "recovery request",
        ):
            fixture.store.verify_store(fixture.registry)

    def test_pre_v13_recovery_provenance_is_rejected(self) -> None:
        fixture = self.recovery_fixture()
        latest = fixture._exhaust()
        fixture._request(latest)
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v13_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '12'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 12")
            connection.commit()

        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "before-v13.sqlite3"
            with self.assertRaisesRegex(
                StoreIntegrityError,
                "Pre-v13 work recovery provenance",
            ):
                fixture.store.migrate(
                    fixture.registry,
                    backup,
                )


if __name__ == "__main__":
    unittest.main()
