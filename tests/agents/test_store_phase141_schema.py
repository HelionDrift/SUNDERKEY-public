"""Schema v28 executor provider-report authentication custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.store import (
    EXECUTOR_PROVIDER_REPORT_AUTHENTICATION_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V27,
    EXPECTED_SCHEMA_MANIFEST_V28,
    SCHEMA_VERSION,
    _schema_manifest,
    canonical_json,
)

from . import (
    test_collaboration_executor_provider_report_authentication_phase140 as phase140,
)
from .test_store import remove_schema_v28_objects

V28_OBJECTS = {
    "executor_invocation_provider_report_authentications",
    "executor_invocation_provider_report_authentication_guard",
    "executor_invocation_provider_report_authentications_immutable",
    "executor_invocation_provider_report_authentications_no_delete",
}


def downgrade_empty_provider_report_authentication_to_v27(
    connection: sqlite3.Connection,
) -> None:
    remove_schema_v28_objects(connection)
    connection.execute(
        "UPDATE store_metadata SET value = '27' WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 27")


def insert_authentication(
    connection: sqlite3.Connection,
    document: dict,
) -> None:
    report = document["provider_report"]
    acknowledgement = report["provider_acknowledgement"]
    authentication = document["acknowledgement_authentication"]
    worker = authentication["worker_attestor"]
    connection.execute(
        """
        INSERT INTO executor_invocation_provider_report_authentications(
            report_authentication_id,
            report_authentication_sha256,
            report_custody_id,
            report_custody_sha256,
            attempt_id,
            mission_id,
            acknowledgement_authentication_id,
            acknowledgement_authentication_sha256,
            acknowledgement_id,
            acknowledgement_sha256,
            operation,
            worker_principal_id,
            worker_issuer,
            worker_assertion_id,
            worker_assertion_sha256,
            authenticated_at,
            authentication_json,
            authentication_status,
            evidence_verification_status,
            external_effect_status,
            runtime_effect
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            document["report_authentication_id"],
            document["report_authentication_sha256"],
            report["report_custody_id"],
            report["report_custody_sha256"],
            report["invocation_preparation"]["attempt_id"],
            worker["mission_id"],
            authentication["authentication_id"],
            authentication["authentication_sha256"],
            acknowledgement["acknowledgement_id"],
            acknowledgement["acknowledgement_sha256"],
            acknowledgement["dispatch"]["operation"],
            acknowledgement["worker"]["worker_principal_id"],
            worker["issuer"],
            worker["assertion_id"],
            worker["assertion_sha256"],
            authentication["authenticated_at"],
            canonical_json(document),
            document["authentication_status"],
            document["evidence_verification_status"],
            document["external_effect_status"],
            document["runtime_effect"],
        ),
    )


class Phase141StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = (
            phase140.CollaborationExecutorProviderReportAuthenticationPhase140Tests(
                methodName="runTest"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v28_adds_only_provider_report_authentication_objects(self) -> None:
        self.assertEqual(
            EXECUTOR_PROVIDER_REPORT_AUTHENTICATION_SCHEMA_VERSION,
            28,
        )
        self.assertGreaterEqual(SCHEMA_VERSION, 28)
        v27 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V27}
        v28 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V28}
        self.assertEqual(set(v28) - set(v27), V28_OBJECTS)
        self.assertFalse(set(v27) - set(v28))
        self.assertFalse(
            {name for name in v27.keys() & v28.keys() if v27[name] != v28[name]}
        )

    def test_v27_store_migrates_without_changing_provider_reports(self) -> None:
        fixture = self.fixture()
        root = fixture.root
        with closing(sqlite3.connect(root.store.path)) as connection:
            before = tuple(
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT report_custody_id, report_custody_sha256
                    FROM executor_invocation_provider_reports
                    """
                ).fetchall()
            )
            downgrade_empty_provider_report_authentication_to_v27(connection)
            connection.commit()
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V27,
            )
        with tempfile.TemporaryDirectory() as directory:
            report = root.store.migrate(
                root.registry,
                Path(directory) / "before-v28.sqlite3",
            )
        self.assertEqual(report.source_version, 27)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(root.store.path)) as connection:
            after = tuple(
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT report_custody_id, report_custody_sha256
                    FROM executor_invocation_provider_reports
                    """
                ).fetchall()
            )
            self.assertEqual(before, after)
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM executor_invocation_provider_report_authentications
                    """
                ).fetchone()[0],
                0,
            )
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_authentication_requires_exact_principal_use_and_effect(self) -> None:
        fixture = self.fixture()
        document = fixture._bind().to_dict()
        with closing(sqlite3.connect(fixture.root.store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "inconsistent"):
                insert_authentication(connection, document)

    def test_empty_authentication_custody_is_deeply_verified(self) -> None:
        fixture = self.fixture()
        self.assertEqual(
            fixture.root.store.verify_store(fixture.root.registry).status,
            "valid",
        )


if __name__ == "__main__":
    unittest.main()
