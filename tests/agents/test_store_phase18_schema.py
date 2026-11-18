"""Schema v15 authenticated specialist handoff coverage."""

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
    EXPECTED_SCHEMA_MANIFEST_V14,
    EXPECTED_SCHEMA_MANIFEST_V15,
    SCHEMA_VERSION,
    WORK_ITEM_HANDOFF_SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import (
    REGISTRY_PATH,
    mission_data,
    remove_schema_v15_objects,
)


class Phase18StoreSchemaTests(unittest.TestCase):
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

    def downgrade_to_v14(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v15_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '14'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 14")
            connection.commit()

    def handoff_fixture(self):
        from .test_authenticated_work_handoffs_phase18 import (
            AuthenticatedWorkHandoffPhase18Tests,
        )

        fixture = AuthenticatedWorkHandoffPhase18Tests(
            methodName="runTest"
        )
        fixture.registry = self.registry
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v15_objects_preserve_exact_v14_manifest(self) -> None:
        self.assertEqual(WORK_ITEM_HANDOFF_SCHEMA_VERSION, 15)
        self.assertGreaterEqual(SCHEMA_VERSION, 15)
        v14_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V14
        }
        v15_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V15
        }
        self.assertNotIn(
            "collaboration_work_item_handoffs",
            v14_names,
        )
        self.assertIn(
            "collaboration_work_item_handoffs",
            v15_names,
        )
        self.assertTrue(v14_names < v15_names)

        self.initialized_store()
        self.downgrade_to_v14()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V14,
            )

    def test_v14_migration_starts_with_no_handoff_rows(self) -> None:
        store = self.initialized_store()
        self.downgrade_to_v14()

        report = store.migrate(
            self.registry,
            self.directory / "before-v15.sqlite3",
        )

        self.assertEqual(report.source_version, 14)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM collaboration_work_item_handoffs
                    """
                ).fetchone()[0],
                0,
            )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_handoff_history_is_immutable(self) -> None:
        fixture = self.handoff_fixture()
        fixture._handoff()

        with closing(sqlite3.connect(fixture.path)) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable",
            ):
                connection.execute(
                    """
                    UPDATE collaboration_work_item_handoffs
                    SET transferred_at = transferred_at
                    """
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM collaboration_work_item_handoffs
                    """
                )

    def test_handoff_semantic_tampering_is_detected(self) -> None:
        fixture = self.handoff_fixture()
        fixture._handoff()

        with closing(sqlite3.connect(fixture.path)) as connection:
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

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "work handoff",
        ):
            fixture.store.verify_store(fixture.registry)

    def test_pre_v15_handoff_provenance_is_rejected(self) -> None:
        fixture = self.handoff_fixture()
        fixture._handoff()
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v15_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '14'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 14")
            connection.commit()

        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "before-v15.sqlite3"
            with self.assertRaisesRegex(
                StoreIntegrityError,
                "Pre-v15 work handoff provenance",
            ):
                fixture.store.migrate(
                    fixture.registry,
                    backup,
                )


if __name__ == "__main__":
    unittest.main()
