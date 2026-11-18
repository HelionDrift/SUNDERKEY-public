"""Schema v23 execution session state custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.store import (
    EXECUTION_SESSION_STATE_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V22,
    EXPECTED_SCHEMA_MANIFEST_V23,
    SCHEMA_VERSION,
    _schema_manifest,
)

from . import test_collaboration_execution_session_authority_phase120 as phase120
from .test_store import remove_schema_v26_objects

V23_OBJECTS = {
    "execution_session_activation_commits",
    "execution_session_revocation_commits",
    "execution_session_activation_guard",
    "execution_session_revocation_guard",
    "execution_session_activation_commits_immutable",
    "execution_session_activation_commits_no_delete",
    "execution_session_revocation_commits_immutable",
    "execution_session_revocation_commits_no_delete",
}


def downgrade_empty_session_state_to_v22(
    connection: sqlite3.Connection,
) -> None:
    remove_schema_v26_objects(connection)
    for name in (
        "executor_dispatch_delivery_claim_guard",
        "executor_dispatch_delivery_claims_immutable",
        "executor_dispatch_delivery_claims_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP TABLE executor_dispatch_delivery_claims")
    for name in (
        "executor_dispatch_reservation_guard",
        "executor_dispatch_reservations_immutable",
        "executor_dispatch_reservations_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP TABLE executor_dispatch_reservations")
    for name in (
        "execution_session_activation_guard",
        "execution_session_revocation_guard",
        "execution_session_activation_commits_immutable",
        "execution_session_activation_commits_no_delete",
        "execution_session_revocation_commits_immutable",
        "execution_session_revocation_commits_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP TABLE execution_session_revocation_commits")
    connection.execute("DROP TABLE execution_session_activation_commits")
    connection.execute(
        "UPDATE store_metadata SET value = '22' WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 22")


class Phase123StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = phase120.CollaborationExecutionSessionAuthorityPhase120Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v23_adds_only_execution_session_state_objects(self) -> None:
        self.assertEqual(EXECUTION_SESSION_STATE_SCHEMA_VERSION, 23)
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        v22 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V22}
        v23 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V23}
        self.assertEqual(set(v23) - set(v22), V23_OBJECTS)
        self.assertFalse(set(v22) - set(v23))
        self.assertFalse(
            {name for name in v22.keys() & v23.keys() if v22[name] != v23[name]}
        )

    def test_v22_store_migrates_with_empty_session_state(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.fixture.fixture
        with closing(sqlite3.connect(root.store.path)) as connection:
            downgrade_empty_session_state_to_v22(connection)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V22)
        with tempfile.TemporaryDirectory() as directory:
            report = root.store.migrate(
                root.registry,
                Path(directory) / "before-v23.sqlite3",
            )
        self.assertEqual(report.source_version, 22)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(root.store.path)) as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_session_activation_commits"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_session_revocation_commits"
                ).fetchone()[0],
                0,
            )
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_session_state_tables_are_append_only(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.fixture.fixture
        with closing(sqlite3.connect(root.store.path)) as connection:
            trigger_names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND name LIKE 'execution_session_%commits_%'"
                )
            }
        self.assertTrue(
            {
                "execution_session_activation_commits_immutable",
                "execution_session_activation_commits_no_delete",
                "execution_session_revocation_commits_immutable",
                "execution_session_revocation_commits_no_delete",
            }.issubset(trigger_names)
        )


if __name__ == "__main__":
    unittest.main()
