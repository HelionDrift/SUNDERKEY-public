"""Schema v21 execution terminal custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.store import (
    EXECUTION_TERMINAL_CUSTODY_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V20,
    EXPECTED_SCHEMA_MANIFEST_V21,
    SCHEMA_VERSION,
    _schema_manifest,
)

from . import test_authenticated_collaboration_execution_channel_phase109 as phase109
from .test_store import remove_schema_v26_objects

V21_OBJECTS = {
    "execution_terminal_custody_commits",
    "execution_terminal_custody_participants",
    "execution_terminal_custody_participant_guard",
    "execution_terminal_custody_commits_immutable",
    "execution_terminal_custody_commits_no_delete",
    "execution_terminal_custody_participants_immutable",
    "execution_terminal_custody_participants_no_delete",
}


def downgrade_empty_terminal_custody_to_v20(connection: sqlite3.Connection) -> None:
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
    for name in (
        "execution_session_authority_basis_guard",
        "execution_session_authority_commits_immutable",
        "execution_session_authority_commits_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP INDEX execution_session_handoff_basis_identity")
    connection.execute("DROP TABLE execution_session_authority_commits")
    for name in (
        "execution_terminal_custody_participant_guard",
        "execution_terminal_custody_commits_immutable",
        "execution_terminal_custody_commits_no_delete",
        "execution_terminal_custody_participants_immutable",
        "execution_terminal_custody_participants_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP TABLE execution_terminal_custody_participants")
    connection.execute("DROP TABLE execution_terminal_custody_commits")
    connection.execute("UPDATE store_metadata SET value = '20' WHERE key = 'schema_version'")
    connection.execute("PRAGMA user_version = 20")


class Phase116StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = phase109.AuthenticatedCollaborationExecutionChannelPhase109Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v21_adds_only_execution_terminal_custody_objects(self) -> None:
        self.assertEqual(EXECUTION_TERMINAL_CUSTODY_SCHEMA_VERSION, 21)
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        v20 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V20}
        v21 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V21}
        self.assertEqual(set(v21) - set(v20), V21_OBJECTS)
        self.assertFalse(set(v20) - set(v21))
        self.assertFalse({name for name in v20.keys() & v21.keys() if v20[name] != v21[name]})

    def test_v20_store_migrates_to_v21_without_existing_state_changes(self) -> None:
        fixture = self.fixture()
        fixture._commit()
        with closing(sqlite3.connect(fixture.fixture.path)) as connection:
            before = {
                "missions": connection.execute("SELECT COUNT(*) FROM missions").fetchone()[0],
                "policies": connection.execute(
                    "SELECT COUNT(*) FROM execution_channel_policy_commits"
                ).fetchone()[0],
                "uses": connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
            }
            downgrade_empty_terminal_custody_to_v20(connection)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V20)
        with tempfile.TemporaryDirectory() as temporary:
            report = fixture.fixture.store.migrate(
                fixture.fixture.registry,
                Path(temporary) / "before-v21.sqlite3",
            )
        self.assertEqual(report.source_version, 20)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(fixture.fixture.path)) as connection:
            after = {
                "missions": connection.execute("SELECT COUNT(*) FROM missions").fetchone()[0],
                "policies": connection.execute(
                    "SELECT COUNT(*) FROM execution_channel_policy_commits"
                ).fetchone()[0],
                "uses": connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
            }
            self.assertEqual(before, after)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
        self.assertEqual(
            fixture.fixture.store.verify_store(fixture.fixture.registry).status,
            "valid",
        )

    def test_v21_tables_are_immutable_and_terminal_identity_is_unique(self) -> None:
        fixture = self.fixture()
        with closing(sqlite3.connect(fixture.fixture.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            commit_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' "
                "AND name = 'execution_terminal_custody_commits'"
            ).fetchone()[0]
            participant_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' "
                "AND name = 'execution_terminal_custody_participants'"
            ).fetchone()[0]
            trigger_names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND name LIKE 'execution_terminal_custody_%'"
                )
            }
        self.assertIn("UNIQUE (mission_id, work_item_id, transfer_request_id)", commit_sql)
        self.assertIn("UNIQUE (issuer, assertion_id)", participant_sql)
        self.assertTrue(
            {
                "execution_terminal_custody_commits_immutable",
                "execution_terminal_custody_commits_no_delete",
                "execution_terminal_custody_participants_immutable",
                "execution_terminal_custody_participants_no_delete",
            }.issubset(trigger_names)
        )


if __name__ == "__main__":
    unittest.main()
