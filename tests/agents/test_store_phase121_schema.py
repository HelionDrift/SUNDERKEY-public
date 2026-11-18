"""Schema v22 execution session authority custody and verification coverage."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.errors import StoreIntegrityError
from sunderkey.store import (
    EXECUTION_SESSION_AUTHORITY_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V21,
    EXPECTED_SCHEMA_MANIFEST_V22,
    SCHEMA_VERSION,
    _schema_manifest,
    canonical_json,
)

from . import test_collaboration_execution_session_authority_phase120 as phase120
from .test_store import remove_schema_v26_objects

V22_OBJECTS = {
    "execution_session_authority_commits",
    "execution_session_handoff_basis_identity",
    "execution_session_authority_basis_guard",
    "execution_session_authority_commits_immutable",
    "execution_session_authority_commits_no_delete",
}


def downgrade_empty_session_authority_to_v21(
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
    for name in (
        "execution_session_authority_basis_guard",
        "execution_session_authority_commits_immutable",
        "execution_session_authority_commits_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP INDEX execution_session_handoff_basis_identity")
    connection.execute("DROP TABLE execution_session_authority_commits")
    connection.execute("UPDATE store_metadata SET value = '21' WHERE key = 'schema_version'")
    connection.execute("PRAGMA user_version = 21")


def insert_authority(
    connection: sqlite3.Connection,
    authority,
) -> None:
    document = authority.to_dict()
    session = document["session"]
    basis = document["authorization_basis"]
    connection.execute(
        """
        INSERT INTO execution_session_authority_commits(
            session_authority_id,
            session_authority_sha256,
            mission_id,
            collaboration_plan_id,
            collaboration_plan_sha256,
            work_item_id,
            authority_kind,
            basis_kind,
            basis_id,
            basis_sha256,
            channel_policy_id,
            channel_policy_sha256,
            session_id,
            session_sha256,
            owner_profile_id,
            owner_epoch,
            worker_principal_id,
            fence_generation,
            credential_reference_id,
            credential_sha256,
            effective_at,
            expires_at,
            authority_json,
            committed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            authority.session_authority_id,
            authority.session_authority_sha256,
            session["mission_id"],
            session["collaboration_plan_id"],
            session["collaboration_plan_sha256"],
            session["work_item_id"],
            document["authority_kind"],
            basis["basis_kind"],
            basis["basis_id"],
            basis["basis_sha256"],
            session["channel_policy"]["channel_policy_id"],
            session["channel_policy"]["channel_policy_sha256"],
            session["session_id"],
            session["session_sha256"],
            session["owner_profile_id"],
            session["owner_epoch"],
            session["worker_principal_id"],
            session["fence_generation"],
            session["credential_reference_id"],
            session["credential_sha256"],
            document["effective_at"],
            document["expires_at"],
            canonical_json(document),
            document["effective_at"],
        ),
    )


class Phase121StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = phase120.CollaborationExecutionSessionAuthorityPhase120Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v22_adds_only_execution_session_authority_objects(self) -> None:
        self.assertEqual(EXECUTION_SESSION_AUTHORITY_SCHEMA_VERSION, 22)
        self.assertGreaterEqual(SCHEMA_VERSION, 23)
        v21 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V21}
        v22 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V22}
        self.assertEqual(set(v22) - set(v21), V22_OBJECTS)
        self.assertFalse(set(v21) - set(v22))
        self.assertFalse(
            {name for name in v21.keys() & v22.keys() if v21[name] != v22[name]}
        )

    def test_v21_store_migrates_without_existing_state_changes(self) -> None:
        fixture = self.fixture()
        store = fixture.fixture.fixture.fixture.store
        registry = fixture.fixture.fixture.fixture.registry
        with closing(sqlite3.connect(store.path)) as connection:
            before = {
                "missions": connection.execute(
                    "SELECT COUNT(*) FROM missions"
                ).fetchone()[0],
                "policies": connection.execute(
                    "SELECT COUNT(*) FROM execution_channel_policy_commits"
                ).fetchone()[0],
                "terminal": connection.execute(
                    "SELECT COUNT(*) FROM execution_terminal_custody_commits"
                ).fetchone()[0],
            }
            downgrade_empty_session_authority_to_v21(connection)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V21)
        with tempfile.TemporaryDirectory() as directory:
            report = store.migrate(registry, Path(directory) / "before-v22.sqlite3")
        self.assertEqual(report.source_version, 21)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(store.path)) as connection:
            after = {
                "missions": connection.execute(
                    "SELECT COUNT(*) FROM missions"
                ).fetchone()[0],
                "policies": connection.execute(
                    "SELECT COUNT(*) FROM execution_channel_policy_commits"
                ).fetchone()[0],
                "terminal": connection.execute(
                    "SELECT COUNT(*) FROM execution_terminal_custody_commits"
                ).fetchone()[0],
            }
            self.assertEqual(before, after)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
        self.assertEqual(store.verify_store(registry).status, "valid")

    def test_initial_and_completed_handoff_authorities_reconstruct(self) -> None:
        fixture = self.fixture()
        store = fixture.fixture.fixture.fixture.store
        registry = fixture.fixture.fixture.fixture.registry
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            insert_authority(connection, fixture.initial_authority)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "basis is inconsistent"):
                insert_authority(connection, fixture.handoff_authority)
            connection.rollback()
        fixture.fixture._commit()
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            insert_authority(connection, fixture.initial_authority)
            insert_authority(connection, fixture.handoff_authority)
            connection.commit()
        self.assertEqual(store.verify_store(registry).status, "valid")
        mission_id = fixture.initial_session.to_dict()["mission_id"]
        self.assertEqual(
            store.verify_mission(registry, mission_id).status,
            "valid",
        )

    def test_noncanonical_authority_fails_whole_store_verification(self) -> None:
        fixture = self.fixture()
        store = fixture.fixture.fixture.fixture.store
        registry = fixture.fixture.fixture.fixture.registry
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            insert_authority(connection, fixture.initial_authority)
            trigger_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name = 'execution_session_authority_commits_immutable'"
            ).fetchone()[0]
            connection.execute("DROP TRIGGER execution_session_authority_commits_immutable")
            connection.execute(
                "UPDATE execution_session_authority_commits SET authority_json = ?",
                (json.dumps(fixture.initial_authority.to_dict(), indent=2),),
            )
            connection.execute(trigger_sql)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "does not reconcile"):
            store.verify_store(registry)

    def test_authority_table_is_append_only_and_fence_identity_is_unique(self) -> None:
        fixture = self.fixture()
        store = fixture.fixture.fixture.fixture.store
        with closing(sqlite3.connect(store.path)) as connection:
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' "
                "AND name = 'execution_session_authority_commits'"
            ).fetchone()[0]
            trigger_names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND name LIKE 'execution_session_authority_%'"
                )
            }
        self.assertIn(
            "UNIQUE (mission_id, work_item_id, fence_generation)",
            table_sql,
        )
        self.assertTrue(
            {
                "execution_session_authority_commits_immutable",
                "execution_session_authority_commits_no_delete",
            }.issubset(trigger_names)
        )


if __name__ == "__main__":
    unittest.main()
