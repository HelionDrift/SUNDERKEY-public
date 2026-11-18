"""Schema v10 authenticated mission-creation provenance coverage."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.errors import StoreIntegrityError
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import (
    EXPECTED_SCHEMA_MANIFEST_V9,
    EXPECTED_SCHEMA_MANIFEST_V10,
    MISSION_CREATION_AUTHENTICATION_SCHEMA_VERSION,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
    sha256_text,
)

from .test_store import (
    MISSION_ID,
    REGISTRY_PATH,
    mission_data,
    remove_schema_v10_objects,
)


class Phase13StoreSchemaTests(unittest.TestCase):
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

    def downgrade_to_v9(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v10_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '9'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 9")
            connection.commit()

    def test_v10_objects_preserve_exact_v9_manifest(self) -> None:
        self.assertEqual(
            MISSION_CREATION_AUTHENTICATION_SCHEMA_VERSION,
            10,
        )
        self.assertGreaterEqual(SCHEMA_VERSION, 13)
        v9_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V9
        }
        v10_names = {
            item[1] for item in EXPECTED_SCHEMA_MANIFEST_V10
        }
        self.assertNotIn(
            "mission_creation_provenance",
            v9_names,
        )
        self.assertIn(
            "mission_creation_provenance",
            v10_names,
        )
        self.assertTrue(v9_names < v10_names)

        self.initialized_store()
        self.downgrade_to_v9()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V9,
            )

    def test_fresh_direct_mission_is_marked_trusted_local(
        self,
    ) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM mission_creation_provenance
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert row is not None
        provenance = json.loads(str(row["provenance_json"]))
        self.assertEqual(
            row["provenance_kind"],
            "trusted_local_pre_policy",
        )
        self.assertEqual(
            provenance["provenance_status"],
            "trusted_local_creation_before_authenticated_mode",
        )
        self.assertEqual(
            row["provenance_hash"],
            sha256_text(str(row["provenance_json"])),
        )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_v9_migration_marks_existing_mission_historical(
        self,
    ) -> None:
        store = self.initialized_store()
        self.downgrade_to_v9()

        report = store.migrate(
            self.registry,
            self.directory / "before-v10.sqlite3",
        )

        self.assertEqual(report.source_version, 9)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM mission_creation_provenance
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert row is not None
        provenance = json.loads(str(row["provenance_json"]))
        self.assertEqual(
            row["provenance_kind"],
            "historical_pre_v10",
        )
        self.assertEqual(row["source_schema_version"], 9)
        self.assertEqual(
            provenance["provenance_status"],
            "historical_creation_not_principal_authenticated",
        )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_provenance_is_immutable_and_required(self) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable",
            ):
                connection.execute(
                    """
                    UPDATE mission_creation_provenance
                    SET recorded_at = recorded_at
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM mission_creation_provenance
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                )
            connection.rollback()
            connection.execute(
                """
                DROP TRIGGER
                    mission_creation_provenance_no_delete
                """
            )
            connection.execute(
                """
                DELETE FROM mission_creation_provenance
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            )
            connection.commit()
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "schema manifest|provenance",
        ):
            store.verify_store(self.registry)

    def test_pre_v10_claimed_creation_provenance_is_rejected(
        self,
    ) -> None:
        from .test_authenticated_mission_creation_phase13 import (
            AuthenticatedMissionCreationPhase13Tests,
        )

        fixture = AuthenticatedMissionCreationPhase13Tests(
            methodName="runTest"
        )
        fixture.registry = self.registry
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.service.create(
            fixture.assertion,
            fixture.grant,
            fixture.mission,
        )
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v10_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '9'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 9")
            connection.commit()

        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "before-v10.sqlite3"
            with self.assertRaisesRegex(
                StoreIntegrityError,
                "Pre-v10 mission-creation provenance",
            ):
                fixture.store.migrate(
                    fixture.registry,
                    backup,
                )


if __name__ == "__main__":
    unittest.main()
