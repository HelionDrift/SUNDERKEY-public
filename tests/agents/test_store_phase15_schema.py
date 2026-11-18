"""Schema v12 authenticated owner lease coverage."""

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
    EXPECTED_SCHEMA_MANIFEST_V11,
    EXPECTED_SCHEMA_MANIFEST_V12,
    SCHEMA_VERSION,
    WORK_ITEM_CLAIM_SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import (
    REGISTRY_PATH,
    mission_data,
    remove_schema_v12_objects,
)


class Phase15StoreSchemaTests(unittest.TestCase):
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

    def downgrade_to_v11(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v12_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '11'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 11")
            connection.commit()

    def work_fixture(self):
        from .test_authenticated_work_phase15 import (
            AuthenticatedWorkPhase15Tests,
        )

        fixture = AuthenticatedWorkPhase15Tests(
            methodName="runTest"
        )
        fixture.registry = self.registry
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v12_objects_preserve_exact_v11_manifest(self) -> None:
        self.assertEqual(WORK_ITEM_CLAIM_SCHEMA_VERSION, 12)
        self.assertGreaterEqual(SCHEMA_VERSION, 12)
        v11_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V11
        }
        v12_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V12
        }
        self.assertNotIn(
            "collaboration_work_item_transitions",
            v11_names,
        )
        self.assertIn(
            "collaboration_work_item_transitions",
            v12_names,
        )
        self.assertTrue(v11_names < v12_names)

        self.initialized_store()
        self.downgrade_to_v11()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V11,
            )

    def test_v11_migration_starts_with_no_work_transitions(
        self,
    ) -> None:
        store = self.initialized_store()
        self.downgrade_to_v11()

        report = store.migrate(
            self.registry,
            self.directory / "before-v12.sqlite3",
        )

        self.assertEqual(report.source_version, 11)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM collaboration_work_item_transitions
                    """
                ).fetchone()[0],
                0,
            )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_transition_history_is_immutable(self) -> None:
        fixture = self.work_fixture()
        fixture._claim()

        with closing(sqlite3.connect(fixture.path)) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable",
            ):
                connection.execute(
                    """
                    UPDATE collaboration_work_item_transitions
                    SET recorded_at = recorded_at
                    """
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM collaboration_work_item_transitions
                    """
                )

    def test_semantic_tampering_is_detected(self) -> None:
        fixture = self.work_fixture()
        fixture._claim()

        with closing(sqlite3.connect(fixture.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_schema
                WHERE type = 'trigger'
                  AND name =
                    'collaboration_work_item_transitions_immutable'
                """
            ).fetchone()[0]
            connection.execute(
                """
                DROP TRIGGER
                    collaboration_work_item_transitions_immutable
                """
            )
            connection.execute(
                """
                UPDATE collaboration_work_item_transitions
                SET owner_profile_id = 'AOE-HQ-09'
                """
            )
            connection.execute(trigger_sql)
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "claim semantics|reconcile|binding",
        ):
            fixture.store.verify_store(fixture.registry)

    def test_pre_v12_claimed_work_is_rejected(self) -> None:
        fixture = self.work_fixture()
        fixture._claim()
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v12_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '11'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 11")
            connection.commit()

        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "before-v12.sqlite3"
            with self.assertRaisesRegex(
                StoreIntegrityError,
                "Pre-v12 work item transition provenance",
            ):
                fixture.store.migrate(
                    fixture.registry,
                    backup,
                )


if __name__ == "__main__":
    unittest.main()
