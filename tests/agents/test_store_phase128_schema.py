"""Schema v24 executor dispatch reservation custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.store import (
    EXECUTOR_DISPATCH_CUSTODY_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V23,
    EXPECTED_SCHEMA_MANIFEST_V24,
    SCHEMA_VERSION,
    _schema_manifest,
)

from . import test_collaboration_execution_session_authority_phase120 as phase120
from .test_store import remove_schema_v26_objects

V24_OBJECTS = {
    "executor_dispatch_reservations",
    "executor_dispatch_reservation_guard",
    "executor_dispatch_reservations_immutable",
    "executor_dispatch_reservations_no_delete",
}


def downgrade_empty_dispatch_custody_to_v23(
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
    connection.execute(
        "UPDATE store_metadata SET value = '23' WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 23")


class Phase128StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = phase120.CollaborationExecutionSessionAuthorityPhase120Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v24_adds_only_executor_dispatch_custody_objects(self) -> None:
        self.assertEqual(EXECUTOR_DISPATCH_CUSTODY_SCHEMA_VERSION, 24)
        self.assertGreaterEqual(SCHEMA_VERSION, 24)
        v23 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V23}
        v24 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V24}
        self.assertEqual(set(v24) - set(v23), V24_OBJECTS)
        self.assertFalse(set(v23) - set(v24))
        self.assertFalse(
            {name for name in v23.keys() & v24.keys() if v23[name] != v24[name]}
        )

    def test_v23_store_migrates_with_empty_dispatch_custody(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.fixture.fixture
        with closing(sqlite3.connect(root.store.path)) as connection:
            before = {
                "missions": connection.execute(
                    "SELECT COUNT(*) FROM missions"
                ).fetchone()[0],
                "authorities": connection.execute(
                    "SELECT COUNT(*) FROM execution_session_authority_commits"
                ).fetchone()[0],
                "activations": connection.execute(
                    "SELECT COUNT(*) FROM execution_session_activation_commits"
                ).fetchone()[0],
            }
            downgrade_empty_dispatch_custody_to_v23(connection)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V23)
        with tempfile.TemporaryDirectory() as directory:
            report = root.store.migrate(
                root.registry,
                Path(directory) / "before-v24.sqlite3",
            )
        self.assertEqual(report.source_version, 23)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(root.store.path)) as connection:
            after = {
                "missions": connection.execute(
                    "SELECT COUNT(*) FROM missions"
                ).fetchone()[0],
                "authorities": connection.execute(
                    "SELECT COUNT(*) FROM execution_session_authority_commits"
                ).fetchone()[0],
                "activations": connection.execute(
                    "SELECT COUNT(*) FROM execution_session_activation_commits"
                ).fetchone()[0],
            }
            self.assertEqual(before, after)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_reservations"
                ).fetchone()[0],
                0,
            )
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_dispatch_reservations_are_append_only_and_sequence_unique(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.fixture.fixture
        with closing(sqlite3.connect(root.store.path)) as connection:
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' "
                "AND name = 'executor_dispatch_reservations'"
            ).fetchone()[0]
            trigger_names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND name LIKE 'executor_dispatch_reservation%'"
                )
            }
        self.assertIn("UNIQUE (session_id, operation_sequence)", table_sql)
        self.assertIn("reserved_pending_adapter", table_sql)
        self.assertTrue(
            {
                "executor_dispatch_reservation_guard",
                "executor_dispatch_reservations_immutable",
                "executor_dispatch_reservations_no_delete",
            }.issubset(trigger_names)
        )


if __name__ == "__main__":
    unittest.main()
