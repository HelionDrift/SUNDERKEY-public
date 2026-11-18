"""Schema v27 executor provider-report custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.collaboration_executor_invocation_attempt import (
    build_collaboration_executor_invocation_resolution,
)
from sunderkey.collaboration_executor_provider_report import (
    build_collaboration_executor_provider_report,
)
from sunderkey.store import (
    EXECUTOR_PROVIDER_REPORT_CUSTODY_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V26,
    EXPECTED_SCHEMA_MANIFEST_V27,
    SCHEMA_VERSION,
    _schema_manifest,
    canonical_json,
)

from . import test_collaboration_executor_provider_report_phase137 as phase137
from .test_store import remove_schema_v28_objects
from .test_store_phase134_schema import insert_preparation, insert_resolution

V27_OBJECTS = {
    "executor_invocation_provider_reports",
    "executor_invocation_provider_report_guard",
    "executor_invocation_provider_reports_immutable",
    "executor_invocation_provider_reports_no_delete",
}


def downgrade_empty_provider_report_custody_to_v26(
    connection: sqlite3.Connection,
) -> None:
    remove_schema_v28_objects(connection)
    for name in (
        "executor_invocation_provider_report_guard",
        "executor_invocation_provider_reports_immutable",
        "executor_invocation_provider_reports_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP TABLE executor_invocation_provider_reports")
    connection.execute(
        "UPDATE store_metadata SET value = '26' WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 26")


def insert_report(connection: sqlite3.Connection, document: dict) -> None:
    preparation = connection.execute(
        """
        SELECT * FROM executor_dispatch_invocation_preparations
        WHERE attempt_id = ?
        """,
        (document["invocation_preparation"]["attempt_id"],),
    ).fetchone()
    if preparation is None:
        raise AssertionError("test preparation is missing")
    acknowledgement = document["provider_acknowledgement"]
    connection.execute(
        """
        INSERT INTO executor_invocation_provider_reports(
            report_custody_id,
            report_custody_sha256,
            attempt_id,
            attempt_sha256,
            mission_id,
            authentication_id,
            acknowledgement_id,
            acknowledgement_sha256,
            dispatch_id,
            dispatch_sha256,
            operation,
            operation_sequence,
            adapter_id,
            adapter_version,
            adapter_build_sha256,
            session_id,
            session_sha256,
            fence_generation,
            worker_principal_id,
            runtime_instance_id,
            credential_reference_id,
            credential_sha256,
            outcome,
            provider_worker_state,
            provider_evidence_sha256,
            acknowledged_at,
            received_at,
            report_json,
            report_status,
            authentication_status,
            external_effect_status,
            runtime_effect
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            document["report_custody_id"],
            document["report_custody_sha256"],
            document["invocation_preparation"]["attempt_id"],
            document["invocation_preparation"]["attempt_sha256"],
            preparation["mission_id"],
            preparation["authentication_id"],
            acknowledgement["acknowledgement_id"],
            acknowledgement["acknowledgement_sha256"],
            acknowledgement["dispatch"]["dispatch_id"],
            acknowledgement["dispatch"]["dispatch_sha256"],
            acknowledgement["dispatch"]["operation"],
            acknowledgement["dispatch"]["operation_sequence"],
            acknowledgement["provider"]["adapter_id"],
            acknowledgement["provider"]["adapter_version"],
            acknowledgement["provider"]["adapter_build_sha256"],
            acknowledgement["session"]["session_id"],
            acknowledgement["session"]["session_sha256"],
            acknowledgement["worker"]["fence_generation"],
            acknowledgement["worker"]["worker_principal_id"],
            acknowledgement["worker"]["runtime_instance_id"],
            acknowledgement["credential"]["credential_reference_id"],
            acknowledgement["credential"]["credential_sha256"],
            acknowledgement["outcome"],
            acknowledgement["provider_worker_state"],
            acknowledgement["provider_evidence_sha256"],
            acknowledgement["acknowledged_at"],
            document["received_at"],
            canonical_json(document),
            document["report_status"],
            document["authentication_status"],
            document["external_effect_status"],
            document["runtime_effect"],
        ),
    )


class Phase138StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = phase137.CollaborationExecutorProviderReportPhase137Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v27_adds_only_provider_report_custody_objects(self) -> None:
        self.assertEqual(EXECUTOR_PROVIDER_REPORT_CUSTODY_SCHEMA_VERSION, 27)
        self.assertGreaterEqual(SCHEMA_VERSION, 27)
        v26 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V26}
        v27 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V27}
        self.assertEqual(set(v27) - set(v26), V27_OBJECTS)
        self.assertFalse(set(v26) - set(v27))
        self.assertFalse(
            {name for name in v26.keys() & v27.keys() if v26[name] != v27[name]}
        )

    def test_v26_store_migrates_without_changing_preparations(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.fixture.root
        with closing(sqlite3.connect(root.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            insert_preparation(connection, fixture.preparation.to_dict())
            before = tuple(
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT attempt_id, attempt_sha256
                    FROM executor_dispatch_invocation_preparations
                    """
                ).fetchall()
            )
            downgrade_empty_provider_report_custody_to_v26(connection)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V26)
        with tempfile.TemporaryDirectory() as directory:
            report = root.store.migrate(
                root.registry,
                Path(directory) / "before-v27.sqlite3",
            )
        self.assertEqual(report.source_version, 26)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(root.store.path)) as connection:
            after = tuple(
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT attempt_id, attempt_sha256
                    FROM executor_dispatch_invocation_preparations
                    """
                ).fetchall()
            )
            self.assertEqual(before, after)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_complete_report_is_append_only_and_deeply_verified(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.fixture.root
        report = fixture._report()
        with closing(sqlite3.connect(root.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            insert_preparation(connection, fixture.preparation.to_dict())
            insert_report(connection, report.to_dict())
            resolution = build_collaboration_executor_invocation_resolution(
                fixture.preparation,
                outcome="provider_report_received",
                provider_acknowledgement=report.provider_acknowledgement,
                resolved_at=report.to_dict()["received_at"],
            )
            insert_resolution(connection, resolution.to_dict())
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    """
                    UPDATE executor_invocation_provider_reports
                    SET outcome = 'failed' WHERE report_custody_id = ?
                    """,
                    (report.report_custody_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
                connection.execute(
                    """
                    DELETE FROM executor_invocation_provider_reports
                    WHERE report_custody_id = ?
                    """,
                    (report.report_custody_id,),
                )
            connection.commit()
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_one_report_per_attempt_is_enforced(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.fixture.root
        first = fixture._report()
        second = build_collaboration_executor_provider_report(
            fixture.preparation,
            fixture.acknowledgement,
            received_at="2026-07-30T10:08:36Z",
        )
        with closing(sqlite3.connect(root.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            insert_preparation(connection, fixture.preparation.to_dict())
            insert_report(connection, first.to_dict())
            with self.assertRaises(sqlite3.IntegrityError):
                insert_report(connection, second.to_dict())


if __name__ == "__main__":
    unittest.main()
