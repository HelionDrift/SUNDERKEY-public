"""Schema v19 privileged ownership reassignment custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import tomllib
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.store import (
    COLLABORATION_OWNERSHIP_PRIVILEGED_SCHEMA_VERSION,
    COLLABORATION_OWNERSHIP_REVOCATION_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V18,
    EXPECTED_SCHEMA_MANIFEST_V19,
    SCHEMA_VERSION,
    _schema_manifest,
)

from .test_store import remove_schema_v22_objects

V18_COLUMNS = (
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
    "revocation_id",
    "revocation_sha256",
    "revocation_json",
    "committed_at",
    "current_owner_issuer",
    "current_owner_assertion_id",
    "proposed_owner_issuer",
    "proposed_owner_assertion_id",
    "control_issuer",
    "control_assertion_id",
)


def downgrade_ownership_table_to_v18(connection: sqlite3.Connection) -> None:
    """Rebuild the v18 ownership custody objects for migration testing."""

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
    v18_objects = {item[1]: item[3] for item in EXPECTED_SCHEMA_MANIFEST_V18}
    triggers = (
        "collaboration_ownership_authenticated_guard",
        "collaboration_ownership_revocation_authenticated_guard",
        "collaboration_ownership_privileged_authenticated_guard",
        "collaboration_ownership_privileged_control_guard",
        "collaboration_ownership_chain_entries_immutable",
        "collaboration_ownership_chain_entries_no_delete",
        "principal_collaboration_ownership_use_guard",
    )
    for trigger in triggers:
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP INDEX IF EXISTS principal_collaboration_ownership_effect_identity"
    )
    connection.execute(
        "ALTER TABLE collaboration_ownership_chain_entries "
        "RENAME TO collaboration_ownership_chain_entries_v19"
    )
    connection.execute(v18_objects["collaboration_ownership_chain_entries"])
    columns = ", ".join(V18_COLUMNS)
    connection.execute(
        f"INSERT INTO collaboration_ownership_chain_entries ({columns}) "
        f"SELECT {columns} FROM collaboration_ownership_chain_entries_v19"
    )
    connection.execute("DROP TABLE collaboration_ownership_chain_entries_v19")
    for name in (
        "principal_collaboration_ownership_effect_identity",
        "principal_collaboration_ownership_use_guard",
        "collaboration_ownership_authenticated_guard",
        "collaboration_ownership_revocation_authenticated_guard",
        "collaboration_ownership_chain_entries_immutable",
        "collaboration_ownership_chain_entries_no_delete",
    ):
        connection.execute(v18_objects[name])
    connection.execute(
        "UPDATE store_metadata SET value = '18' "
        "WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 18")


class Phase103StoreSchemaTests(unittest.TestCase):
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

    def test_v19_changes_only_privileged_ownership_custody_objects(self) -> None:
        self.assertEqual(COLLABORATION_OWNERSHIP_REVOCATION_SCHEMA_VERSION, 18)
        self.assertEqual(COLLABORATION_OWNERSHIP_PRIVILEGED_SCHEMA_VERSION, 19)
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        v18_objects = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V18}
        v19_objects = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V19}
        changed = {
            name
            for name in v18_objects.keys() & v19_objects.keys()
            if v18_objects[name] != v19_objects[name]
        }
        self.assertEqual(
            changed,
            {
                "collaboration_ownership_authenticated_guard",
                "collaboration_ownership_chain_entries",
                "principal_collaboration_ownership_effect_identity",
                "principal_collaboration_ownership_use_guard",
            },
        )
        self.assertEqual(
            set(v19_objects) - set(v18_objects),
            {
                "collaboration_ownership_privileged_authenticated_guard",
                "collaboration_ownership_privileged_control_guard",
            },
        )
        self.assertFalse(set(v18_objects) - set(v19_objects))

    def test_v18_populated_chain_migrates_without_custody_loss(self) -> None:
        fixture = self.ownership_fixture()
        receipt = fixture._commit()
        path = fixture.fixture.path
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            columns = ", ".join(V18_COLUMNS)
            before = connection.execute(
                f"SELECT {columns} "
                "FROM collaboration_ownership_chain_entries"
            ).fetchone()
            downgrade_ownership_table_to_v18(connection)
            connection.commit()
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V18,
            )

        with tempfile.TemporaryDirectory() as temporary:
            report = fixture.fixture.store.migrate(
                fixture.fixture.registry,
                Path(temporary) / "before-v19.sqlite3",
            )
        self.assertEqual(report.source_version, 18)
        self.assertEqual(report.target_version, SCHEMA_VERSION)

        with closing(sqlite3.connect(path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM collaboration_ownership_chain_entries"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(tuple(row[column] for column in V18_COLUMNS), before)
            self.assertEqual(row["entry_id"], receipt.entry.entry_id)
            self.assertIsNone(row["second_authority_issuer"])
            self.assertIsNone(row["second_authority_assertion_id"])
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST,
            )
        self.assertEqual(
            fixture.fixture.store.verify_store(fixture.fixture.registry).status,
            "valid",
        )

    def test_v19_represents_conditional_fourth_authority_custody(self) -> None:
        fixture = self.ownership_fixture()
        with closing(sqlite3.connect(fixture.fixture.path)) as connection:
            columns = {
                row[1]: row
                for row in connection.execute(
                    "PRAGMA table_info(collaboration_ownership_chain_entries)"
                )
            }
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'table' "
                "AND name = 'collaboration_ownership_chain_entries'"
            ).fetchone()[0]
            control_trigger = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'trigger' "
                "AND name = 'collaboration_ownership_privileged_control_guard'"
            ).fetchone()[0]
        self.assertEqual(columns["second_authority_issuer"][3], 0)
        self.assertEqual(columns["second_authority_assertion_id"][3], 0)
        self.assertIn("substr(preflight_id, 1, 4) = 'OPF-'", table_sql)
        self.assertIn("substr(authentication_id, 1, 4) = 'OPA-'", table_sql)
        self.assertIn("second_authority_issuer IS NOT NULL", table_sql)
        self.assertIn(
            "sunderkey.collaboration.ownership.second-authority-approve.v1",
            control_trigger,
        )
        self.assertIn(
            "second_use.use_sequence = control_use.use_sequence + 1",
            control_trigger,
        )

    def test_project_version_is_phase103(self) -> None:
        project = tomllib.loads(
            (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
