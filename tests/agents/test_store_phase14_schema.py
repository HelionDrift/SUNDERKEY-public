"""Schema v11 authenticated collaboration activation coverage."""

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
    COLLABORATION_ACTIVATION_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST_V10,
    EXPECTED_SCHEMA_MANIFEST_V11,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import (
    REGISTRY_PATH,
    mission_data,
    remove_schema_v11_objects,
)


class Phase14StoreSchemaTests(unittest.TestCase):
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

    def downgrade_to_v10(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v11_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '10'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 10")
            connection.commit()

    def test_v11_objects_preserve_exact_v10_manifest(self) -> None:
        self.assertEqual(
            COLLABORATION_ACTIVATION_SCHEMA_VERSION,
            11,
        )
        self.assertGreaterEqual(SCHEMA_VERSION, 14)
        v10_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V10
        }
        v11_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V11
        }
        self.assertNotIn(
            "collaboration_plan_activations",
            v10_names,
        )
        self.assertIn(
            "collaboration_plan_activations",
            v11_names,
        )
        self.assertTrue(v10_names < v11_names)

        self.initialized_store()
        self.downgrade_to_v10()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V10,
            )

    def test_v10_migration_starts_with_no_activated_plan(
        self,
    ) -> None:
        store = self.initialized_store()
        self.downgrade_to_v10()

        report = store.migrate(
            self.registry,
            self.directory / "before-v11.sqlite3",
        )

        self.assertEqual(report.source_version, 10)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM collaboration_plan_activations
                    """
                ).fetchone()[0],
                0,
            )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_activation_is_immutable_and_required(self) -> None:
        from .test_authenticated_collaboration_phase14 import (
            AuthenticatedCollaborationPhase14Tests,
        )

        fixture = AuthenticatedCollaborationPhase14Tests(
            methodName="runTest"
        )
        fixture.registry = self.registry
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.service.activate(
            fixture.assertion,
            fixture.plan,
        )

        with closing(sqlite3.connect(fixture.path)) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable",
            ):
                connection.execute(
                    """
                    UPDATE collaboration_plan_activations
                    SET activated_at = activated_at
                    """
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM collaboration_plan_activations
                    """
                )
            connection.rollback()
            connection.execute(
                """
                DROP TRIGGER
                    collaboration_plan_activations_no_delete
                """
            )
            connection.execute(
                "DELETE FROM collaboration_plan_activations"
            )
            connection.commit()
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "schema manifest|activation",
        ):
            fixture.store.verify_store(fixture.registry)

    def test_pre_v11_claimed_activation_is_rejected(self) -> None:
        from .test_authenticated_collaboration_phase14 import (
            AuthenticatedCollaborationPhase14Tests,
        )

        fixture = AuthenticatedCollaborationPhase14Tests(
            methodName="runTest"
        )
        fixture.registry = self.registry
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.service.activate(
            fixture.assertion,
            fixture.plan,
        )
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v11_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '10'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 10")
            connection.commit()

        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "before-v11.sqlite3"
            with self.assertRaisesRegex(
                StoreIntegrityError,
                "Pre-v11 collaboration activation provenance",
            ):
                fixture.store.migrate(
                    fixture.registry,
                    backup,
                )


if __name__ == "__main__":
    unittest.main()
