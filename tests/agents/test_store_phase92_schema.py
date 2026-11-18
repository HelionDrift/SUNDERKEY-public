"""Schema v17 authenticated collaboration ownership coverage."""

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
    COLLABORATION_OWNERSHIP_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST_V16,
    EXPECTED_SCHEMA_MANIFEST_V17,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import REGISTRY_PATH, mission_data, remove_schema_v17_objects


class Phase92StoreSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "phase92-schema.sqlite3"
        self.mission = MissionRequest.from_dict(mission_data())

    def initialized_store(self) -> MissionStore:
        store = MissionStore(self.path)
        store.initialize()
        store.create_mission(self.registry, self.mission)
        return store

    def downgrade_to_v16(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v17_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '16'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 16")
            connection.commit()

    def test_v17_objects_preserve_exact_v16_manifest(self) -> None:
        self.assertEqual(COLLABORATION_OWNERSHIP_SCHEMA_VERSION, 17)
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        v16_names = {item[1] for item in EXPECTED_SCHEMA_MANIFEST_V16}
        v17_names = {item[1] for item in EXPECTED_SCHEMA_MANIFEST_V17}
        self.assertNotIn("collaboration_ownership_chain_entries", v16_names)
        self.assertIn("collaboration_ownership_chain_entries", v17_names)
        self.assertTrue(v16_names < v17_names)

        self.initialized_store()
        self.downgrade_to_v16()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V16,
            )

    def test_v16_migration_starts_with_no_ownership_rows(self) -> None:
        store = self.initialized_store()
        self.downgrade_to_v16()
        report = store.migrate(
            self.registry,
            self.directory / "before-v17.sqlite3",
        )
        self.assertEqual(report.source_version, 16)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                0,
            )
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_pre_v17_ownership_provenance_is_rejected(self) -> None:
        from .test_authenticated_collaboration_ownership_phase92 import (
            AuthenticatedCollaborationOwnershipPhase92Tests,
        )

        fixture = AuthenticatedCollaborationOwnershipPhase92Tests(methodName="runTest")
        AuthenticatedCollaborationOwnershipPhase92Tests.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture._commit()
        with closing(sqlite3.connect(fixture.fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v17_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '16'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 16")
            connection.commit()
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "Pre-v17 collaboration ownership provenance",
        ):
            fixture.fixture.store.migrate(
                fixture.fixture.registry,
                self.directory / "blocked-v17.sqlite3",
            )


if __name__ == "__main__":
    unittest.main()
