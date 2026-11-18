"""Schema v18 collaboration ownership revocation custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.store import (
    COLLABORATION_OWNERSHIP_PRIVILEGED_SCHEMA_VERSION,
    COLLABORATION_OWNERSHIP_REVOCATION_SCHEMA_VERSION,
    COLLABORATION_OWNERSHIP_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V17,
    EXPECTED_SCHEMA_MANIFEST_V18,
    SCHEMA_VERSION,
    _schema_manifest,
)

from .test_store import remove_schema_v22_objects

V17_COLUMNS = (
    "entry_id",
    "entry_sha256",
    "chain_id",
    "mission_id",
    "plan_id",
    "plan_content_sha256",
    "work_item_id",
    "work_item_objective_sha256",
    "sequence",
    "owner_epoch",
    "previous_entry_sha256",
    "transition_kind",
    "from_owner_id",
    "to_owner_id",
    "entry_json",
    "preflight_id",
    "preflight_sha256",
    "preflight_json",
    "authentication_id",
    "authentication_sha256",
    "committed_at",
    "current_owner_issuer",
    "current_owner_assertion_id",
    "proposed_owner_issuer",
    "proposed_owner_assertion_id",
    "control_issuer",
    "control_assertion_id",
)


def downgrade_ownership_table_to_v17(connection: sqlite3.Connection) -> None:
    """Rebuild only the ownership table and its table-local v17 triggers."""

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
        connection.execute(f"DROP TRIGGER IF EXISTS {name}")
    connection.execute(
        "DROP INDEX IF EXISTS principal_execution_channel_policy_effect_identity"
    )
    connection.execute("DROP TABLE IF EXISTS execution_channel_policy_commits")
    v17_objects = {item[1]: item[3] for item in EXPECTED_SCHEMA_MANIFEST_V17}
    for trigger in (
        "collaboration_ownership_authenticated_guard",
        "collaboration_ownership_revocation_authenticated_guard",
        "collaboration_ownership_privileged_authenticated_guard",
        "collaboration_ownership_privileged_control_guard",
        "collaboration_ownership_chain_entries_immutable",
        "collaboration_ownership_chain_entries_no_delete",
        "principal_collaboration_ownership_use_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP INDEX IF EXISTS principal_collaboration_ownership_effect_identity"
    )
    connection.execute(
        "ALTER TABLE collaboration_ownership_chain_entries "
        "RENAME TO collaboration_ownership_chain_entries_v18"
    )
    connection.execute(v17_objects["collaboration_ownership_chain_entries"])
    columns = ", ".join(V17_COLUMNS)
    connection.execute(
        f"INSERT INTO collaboration_ownership_chain_entries ({columns}) "
        f"SELECT {columns} FROM collaboration_ownership_chain_entries_v18"
    )
    connection.execute("DROP TABLE collaboration_ownership_chain_entries_v18")
    for trigger in (
        "principal_collaboration_ownership_effect_identity",
        "principal_collaboration_ownership_use_guard",
        "collaboration_ownership_authenticated_guard",
        "collaboration_ownership_chain_entries_immutable",
        "collaboration_ownership_chain_entries_no_delete",
    ):
        connection.execute(v17_objects[trigger])
    connection.execute(
        "UPDATE store_metadata SET value = '17' "
        "WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 17")


class Phase98StoreSchemaTests(unittest.TestCase):
    def ownership_fixture(self):
        from .test_authenticated_collaboration_ownership_phase92 import (
            AuthenticatedCollaborationOwnershipPhase92Tests,
        )

        fixture = AuthenticatedCollaborationOwnershipPhase92Tests(
            methodName="runTest"
        )
        AuthenticatedCollaborationOwnershipPhase92Tests.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v18_replaces_only_the_ownership_custody_objects(self) -> None:
        self.assertEqual(COLLABORATION_OWNERSHIP_SCHEMA_VERSION, 17)
        self.assertEqual(COLLABORATION_OWNERSHIP_REVOCATION_SCHEMA_VERSION, 18)
        self.assertEqual(COLLABORATION_OWNERSHIP_PRIVILEGED_SCHEMA_VERSION, 19)
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        v17_objects = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V17}
        v18_objects = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V18}
        changed = {
            name
            for name in v17_objects.keys() & v18_objects.keys()
            if v17_objects[name] != v18_objects[name]
        }
        self.assertEqual(
            changed,
            {
                "collaboration_ownership_authenticated_guard",
                "collaboration_ownership_chain_entries",
            },
        )
        self.assertEqual(
            set(v18_objects) - set(v17_objects),
            {"collaboration_ownership_revocation_authenticated_guard"},
        )

    def test_v17_populated_chain_migrates_without_custody_loss(self) -> None:
        fixture = self.ownership_fixture()
        receipt = fixture._commit()
        path = fixture.fixture.path
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            columns = ", ".join(V17_COLUMNS)
            before = connection.execute(
                "SELECT "
                f"{columns} "
                "FROM collaboration_ownership_chain_entries"
            ).fetchone()
            downgrade_ownership_table_to_v17(connection)
            connection.commit()
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V17,
            )

        with tempfile.TemporaryDirectory() as temporary:
            report = fixture.fixture.store.migrate(
                fixture.fixture.registry,
                Path(temporary) / "before-v18.sqlite3",
            )
        self.assertEqual(report.source_version, 17)
        self.assertEqual(report.target_version, SCHEMA_VERSION)

        with closing(sqlite3.connect(path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM collaboration_ownership_chain_entries"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(
                tuple(row[column] for column in V17_COLUMNS),
                before,
            )
            self.assertEqual(row["entry_id"], receipt.entry.entry_id)
            self.assertIsNone(row["revocation_id"])
            self.assertIsNone(row["revocation_sha256"])
            self.assertIsNone(row["revocation_json"])
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST,
            )
        self.assertEqual(
            fixture.fixture.store.verify_store(fixture.fixture.registry).status,
            "valid",
        )

    def test_v18_current_owner_provenance_is_conditionally_nullable(self) -> None:
        fixture = self.ownership_fixture()
        with closing(sqlite3.connect(fixture.fixture.path)) as connection:
            columns = {
                row[1]: row
                for row in connection.execute(
                    "PRAGMA table_info(collaboration_ownership_chain_entries)"
                )
            }
            self.assertEqual(columns["current_owner_issuer"][3], 0)
            self.assertEqual(columns["current_owner_assertion_id"][3], 0)
            self.assertEqual(columns["proposed_owner_issuer"][3], 1)
            self.assertEqual(columns["control_issuer"][3], 1)
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'table' "
                "AND name = 'collaboration_ownership_chain_entries'"
            ).fetchone()[0]
        self.assertIn("transition_kind = 'control_revocation'", table_sql)
        self.assertIn("revocation_id IS NOT NULL", table_sql)
        self.assertIn("current_owner_issuer IS NULL", table_sql)
        self.assertIn("substr(preflight_id, 1, 4) = 'ORF-'", table_sql)
        self.assertIn("substr(authentication_id, 1, 4) = 'ORA-'", table_sql)


if __name__ == "__main__":
    unittest.main()
