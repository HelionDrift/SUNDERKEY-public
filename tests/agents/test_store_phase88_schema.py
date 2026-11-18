"""Schema v16 authenticated mission-policy commit coverage."""

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
    COLLABORATION_MISSION_POLICY_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST_V15,
    EXPECTED_SCHEMA_MANIFEST_V16,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import REGISTRY_PATH, mission_data, remove_schema_v16_objects


class Phase88StoreSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "phase88-schema.sqlite3"
        self.mission = MissionRequest.from_dict(mission_data())

    def initialized_store(self) -> MissionStore:
        store = MissionStore(self.path)
        store.initialize()
        store.create_mission(self.registry, self.mission)
        return store

    def downgrade_to_v15(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v16_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '15'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 15")
            connection.commit()

    def policy_fixture(self):
        from .test_authenticated_collaboration_mission_policy_phase88 import (
            AuthenticatedCollaborationMissionPolicyPhase88Tests,
        )

        fixture = AuthenticatedCollaborationMissionPolicyPhase88Tests(methodName="runTest")
        AuthenticatedCollaborationMissionPolicyPhase88Tests.setUpClass()
        fixture.registry = self.registry
        fixture.authority = AuthenticatedCollaborationMissionPolicyPhase88Tests.authority
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v16_objects_preserve_exact_v15_manifest(self) -> None:
        self.assertEqual(COLLABORATION_MISSION_POLICY_SCHEMA_VERSION, 16)
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        v15_names = {item[1] for item in EXPECTED_SCHEMA_MANIFEST_V15}
        v16_names = {item[1] for item in EXPECTED_SCHEMA_MANIFEST_V16}
        self.assertNotIn("collaboration_mission_policy_commits", v15_names)
        self.assertIn("collaboration_mission_policy_commits", v16_names)
        self.assertTrue(v15_names < v16_names)

        self.initialized_store()
        self.downgrade_to_v15()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V15,
            )

    def test_v15_migration_starts_with_no_policy_rows(self) -> None:
        store = self.initialized_store()
        self.downgrade_to_v15()
        report = store.migrate(
            self.registry,
            self.directory / "before-v16.sqlite3",
        )
        self.assertEqual(report.source_version, 15)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM collaboration_mission_policy_commits
                    """
                ).fetchone()[0],
                0,
            )
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_pre_v16_policy_provenance_is_rejected(self) -> None:
        fixture = self.policy_fixture()
        fixture._commit()
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v16_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '15'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 15")
            connection.commit()
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "before-v16.sqlite3"
            with self.assertRaisesRegex(
                StoreIntegrityError,
                "Pre-v16 collaboration mission policy provenance",
            ):
                fixture.store.migrate(fixture.registry, backup)


if __name__ == "__main__":
    unittest.main()
