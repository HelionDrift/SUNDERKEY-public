"""Schema v14 authenticated work cancellation coverage."""

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
    EXPECTED_SCHEMA_MANIFEST_V13,
    EXPECTED_SCHEMA_MANIFEST_V14,
    SCHEMA_VERSION,
    WORK_ITEM_CANCELLATION_SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import (
    REGISTRY_PATH,
    mission_data,
    remove_schema_v14_objects,
)


class Phase17StoreSchemaTests(unittest.TestCase):
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

    def downgrade_to_v13(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v14_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '13'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 13")
            connection.commit()

    def cancellation_fixture(self):
        from .test_authenticated_work_cancellations_phase17 import (
            AuthenticatedWorkCancellationPhase17Tests,
        )

        fixture = AuthenticatedWorkCancellationPhase17Tests(
            methodName="runTest"
        )
        fixture.registry = self.registry
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v14_objects_preserve_exact_v13_manifest(self) -> None:
        self.assertEqual(WORK_ITEM_CANCELLATION_SCHEMA_VERSION, 14)
        self.assertGreaterEqual(SCHEMA_VERSION, 14)
        v13_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V13
        }
        v14_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V14
        }
        self.assertNotIn(
            "collaboration_work_item_cancellations",
            v13_names,
        )
        self.assertIn(
            "collaboration_work_item_cancellations",
            v14_names,
        )
        self.assertTrue(v13_names < v14_names)

        self.initialized_store()
        self.downgrade_to_v13()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V13,
            )

    def test_v13_migration_starts_with_no_cancellation_rows(
        self,
    ) -> None:
        store = self.initialized_store()
        self.downgrade_to_v13()

        report = store.migrate(
            self.registry,
            self.directory / "before-v14.sqlite3",
        )

        self.assertEqual(report.source_version, 13)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM collaboration_work_item_cancellations
                    """
                ).fetchone()[0],
                0,
            )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_cancellation_history_is_immutable(self) -> None:
        fixture = self.cancellation_fixture()
        fixture._cancel(fixture.readiness, "1")

        with closing(sqlite3.connect(fixture.path)) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable",
            ):
                connection.execute(
                    """
                    UPDATE collaboration_work_item_cancellations
                    SET cancelled_at = cancelled_at
                    """
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM collaboration_work_item_cancellations
                    """
                )

    def test_cancellation_semantic_tampering_is_detected(self) -> None:
        fixture = self.cancellation_fixture()
        fixture._cancel(fixture.readiness, "1")

        with closing(sqlite3.connect(fixture.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_schema
                WHERE type = 'trigger'
                  AND name =
                    'collaboration_work_item_cancellations_immutable'
                """
            ).fetchone()[0]
            connection.execute(
                """
                DROP TRIGGER
                    collaboration_work_item_cancellations_immutable
                """
            )
            connection.execute(
                """
                UPDATE collaboration_work_item_cancellations
                SET reason = 'Unreviewed replacement'
                """
            )
            connection.execute(trigger_sql)
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "work cancellation",
        ):
            fixture.store.verify_store(fixture.registry)

    def test_pre_v14_cancellation_provenance_is_rejected(self) -> None:
        fixture = self.cancellation_fixture()
        fixture._cancel(fixture.readiness, "1")
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v14_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '13'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 13")
            connection.commit()

        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "before-v14.sqlite3"
            with self.assertRaisesRegex(
                StoreIntegrityError,
                "Pre-v14 work cancellation provenance",
            ):
                fixture.store.migrate(
                    fixture.registry,
                    backup,
                )


if __name__ == "__main__":
    unittest.main()
