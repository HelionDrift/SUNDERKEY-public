"""Schema v20 execution-channel policy custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.store import (
    EXECUTION_CHANNEL_POLICY_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V19,
    EXPECTED_SCHEMA_MANIFEST_V20,
    SCHEMA_VERSION,
    _schema_manifest,
)

from . import test_authenticated_collaboration_mission_policy_phase88 as phase88
from .test_store import remove_schema_v22_objects

V20_OBJECTS = {
    "execution_channel_policy_commits",
    "principal_execution_channel_policy_effect_identity",
    "principal_execution_channel_policy_use_guard",
    "execution_channel_policy_authenticated_guard",
    "execution_channel_policy_commits_immutable",
    "execution_channel_policy_commits_no_delete",
}


def downgrade_empty_channel_custody_to_v19(connection: sqlite3.Connection) -> None:
    remove_schema_v22_objects(connection)
    for name in (
        "execution_terminal_custody_participant_guard",
        "execution_terminal_custody_commits_immutable",
        "execution_terminal_custody_commits_no_delete",
        "execution_terminal_custody_participants_immutable",
        "execution_terminal_custody_participants_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {name}")
    connection.execute("DROP TABLE IF EXISTS execution_terminal_custody_participants")
    connection.execute("DROP TABLE IF EXISTS execution_terminal_custody_commits")
    for name in (
        "principal_execution_channel_policy_use_guard",
        "execution_channel_policy_authenticated_guard",
        "execution_channel_policy_commits_immutable",
        "execution_channel_policy_commits_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute(
        "DROP INDEX principal_execution_channel_policy_effect_identity"
    )
    connection.execute("DROP TABLE execution_channel_policy_commits")
    connection.execute(
        "UPDATE store_metadata SET value = '19' WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 19")


class Phase109StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = phase88.AuthenticatedCollaborationMissionPolicyPhase88Tests(
            methodName="runTest"
        )
        phase88.AuthenticatedCollaborationMissionPolicyPhase88Tests.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v20_adds_only_execution_channel_policy_custody_objects(self) -> None:
        self.assertEqual(EXECUTION_CHANNEL_POLICY_SCHEMA_VERSION, 20)
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        v19 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V19}
        v20 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V20}
        self.assertEqual(set(v20) - set(v19), V20_OBJECTS)
        self.assertFalse(set(v19) - set(v20))
        self.assertFalse(
            {
                name
                for name in v19.keys() & v20.keys()
                if v19[name] != v20[name]
            }
        )

    def test_v19_store_migrates_to_v20_without_existing_state_changes(self) -> None:
        fixture = self.fixture()
        fixture._commit()
        with closing(sqlite3.connect(fixture.path)) as connection:
            before = {
                "missions": connection.execute(
                    "SELECT COUNT(*) FROM missions"
                ).fetchone()[0],
                "policies": connection.execute(
                    "SELECT COUNT(*) FROM collaboration_mission_policy_commits"
                ).fetchone()[0],
                "uses": connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
            }
            downgrade_empty_channel_custody_to_v19(connection)
            connection.commit()
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V19,
            )
        with tempfile.TemporaryDirectory() as temporary:
            report = fixture.store.migrate(
                fixture.registry,
                Path(temporary) / "before-v20.sqlite3",
            )
        self.assertEqual(report.source_version, 19)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(fixture.path)) as connection:
            after = {
                "missions": connection.execute(
                    "SELECT COUNT(*) FROM missions"
                ).fetchone()[0],
                "policies": connection.execute(
                    "SELECT COUNT(*) FROM collaboration_mission_policy_commits"
                ).fetchone()[0],
                "uses": connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
            }
            self.assertEqual(before, after)
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST,
            )
        self.assertEqual(
            fixture.store.verify_store(fixture.registry).status,
            "valid",
        )


if __name__ == "__main__":
    unittest.main()
