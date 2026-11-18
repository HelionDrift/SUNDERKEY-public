"""Schema v26 executor invocation attempt custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.collaboration_executor_invocation_attempt import (
    build_collaboration_executor_invocation_resolution,
)
from sunderkey.store import (
    EXECUTOR_INVOCATION_ATTEMPT_CUSTODY_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V25,
    EXPECTED_SCHEMA_MANIFEST_V26,
    SCHEMA_VERSION,
    _schema_manifest,
    canonical_json,
)

from . import test_collaboration_executor_invocation_attempt_phase133 as phase133
from .test_store import remove_schema_v27_objects

V26_OBJECTS = {
    "executor_dispatch_invocation_preparations",
    "executor_dispatch_invocation_resolutions",
    "executor_dispatch_invocation_preparation_guard",
    "executor_dispatch_invocation_resolution_guard",
    "executor_dispatch_invocation_preparations_immutable",
    "executor_dispatch_invocation_preparations_no_delete",
    "executor_dispatch_invocation_resolutions_immutable",
    "executor_dispatch_invocation_resolutions_no_delete",
}


def downgrade_empty_invocation_custody_to_v25(
    connection: sqlite3.Connection,
) -> None:
    remove_schema_v27_objects(connection)
    for name in (
        "executor_dispatch_invocation_preparation_guard",
        "executor_dispatch_invocation_resolution_guard",
        "executor_dispatch_invocation_preparations_immutable",
        "executor_dispatch_invocation_preparations_no_delete",
        "executor_dispatch_invocation_resolutions_immutable",
        "executor_dispatch_invocation_resolutions_no_delete",
    ):
        connection.execute(f"DROP TRIGGER {name}")
    connection.execute("DROP TABLE executor_dispatch_invocation_resolutions")
    connection.execute("DROP TABLE executor_dispatch_invocation_preparations")
    connection.execute(
        "UPDATE store_metadata SET value = '25' WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 25")


def insert_preparation(
    connection: sqlite3.Connection,
    document: dict,
) -> None:
    claim = connection.execute(
        "SELECT * FROM executor_dispatch_delivery_claims WHERE claim_id = ?",
        (document["delivery_claim"]["claim_id"],),
    ).fetchone()
    if claim is None:
        raise AssertionError("test claim is missing")
    connection.execute(
        """
        INSERT INTO executor_dispatch_invocation_preparations(
            attempt_id,
            attempt_sha256,
            claim_id,
            claim_sha256,
            authentication_id,
            authentication_sha256,
            dispatch_id,
            dispatch_sha256,
            mission_id,
            collaboration_plan_id,
            session_id,
            session_sha256,
            fence_generation,
            operation,
            operation_sequence,
            operation_input_sha256,
            adapter_id,
            adapter_version,
            adapter_build_sha256,
            deployment_binding_sha256,
            idempotency_status,
            idempotency_key_sha256,
            prepared_at,
            preparation_json,
            attempt_status,
            external_effect_status,
            runtime_effect
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?
        )
        """,
        (
            document["attempt_id"],
            document["attempt_sha256"],
            document["delivery_claim"]["claim_id"],
            document["delivery_claim"]["claim_sha256"],
            document["reservation"]["authentication_id"],
            document["reservation"]["authentication_sha256"],
            document["reservation"]["dispatch_id"],
            document["reservation"]["dispatch_sha256"],
            claim["mission_id"],
            claim["collaboration_plan_id"],
            document["session"]["session_id"],
            document["session"]["session_sha256"],
            document["session"]["fence_generation"],
            document["operation"]["name"],
            document["operation"]["sequence"],
            document["operation"]["operation_input_sha256"],
            document["adapter"]["adapter_id"],
            document["adapter"]["adapter_version"],
            document["adapter"]["adapter_build_sha256"],
            document["adapter"]["deployment_binding_sha256"],
            document["idempotency"]["status"],
            document["idempotency"]["key_sha256"],
            document["prepared_at"],
            canonical_json(document),
            document["attempt_status"],
            document["external_effect_status"],
            document["runtime_effect"],
        ),
    )


def insert_resolution(
    connection: sqlite3.Connection,
    document: dict,
) -> None:
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
        INSERT INTO executor_dispatch_invocation_resolutions(
            resolution_id,
            resolution_sha256,
            attempt_id,
            attempt_sha256,
            mission_id,
            authentication_id,
            idempotency_status,
            outcome,
            acknowledgement_id,
            acknowledgement_sha256,
            failure_code,
            resolved_at,
            retry_disposition,
            external_effect_status,
            resolution_json,
            runtime_effect
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            document["resolution_id"],
            document["resolution_sha256"],
            document["invocation_preparation"]["attempt_id"],
            document["invocation_preparation"]["attempt_sha256"],
            preparation["mission_id"],
            preparation["authentication_id"],
            document["invocation_preparation"]["idempotency_status"],
            document["outcome"],
            None if acknowledgement is None else acknowledgement[
                "acknowledgement_id"
            ],
            None if acknowledgement is None else acknowledgement[
                "acknowledgement_sha256"
            ],
            document["failure_code"],
            document["resolved_at"],
            document["retry_disposition"],
            document["external_effect_status"],
            canonical_json(document),
            document["runtime_effect"],
        ),
    )


class Phase134StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = phase133.CollaborationExecutorInvocationAttemptPhase133Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v26_adds_only_invocation_attempt_custody_objects(self) -> None:
        self.assertEqual(EXECUTOR_INVOCATION_ATTEMPT_CUSTODY_SCHEMA_VERSION, 26)
        self.assertGreaterEqual(SCHEMA_VERSION, 26)
        v25 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V25}
        v26 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V26}
        self.assertEqual(set(v26) - set(v25), V26_OBJECTS)
        self.assertFalse(set(v25) - set(v26))
        self.assertFalse(
            {name for name in v25.keys() & v26.keys() if v25[name] != v26[name]}
        )

    def test_v25_store_migrates_without_changing_claims(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.root
        with closing(sqlite3.connect(root.store.path)) as connection:
            before = connection.execute(
                "SELECT claim_id, claim_sha256 FROM executor_dispatch_delivery_claims"
            ).fetchall()
            downgrade_empty_invocation_custody_to_v25(connection)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V25)
        with tempfile.TemporaryDirectory() as directory:
            report = root.store.migrate(
                root.registry,
                Path(directory) / "before-v26.sqlite3",
            )
        self.assertEqual(report.source_version, 25)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(root.store.path)) as connection:
            after = connection.execute(
                "SELECT claim_id, claim_sha256 FROM executor_dispatch_delivery_claims"
            ).fetchall()
            self.assertEqual(before, after)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_unresolved_preparation_is_durable_and_append_only(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.root
        preparation = fixture._prepare()
        with closing(sqlite3.connect(root.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            insert_preparation(connection, preparation.to_dict())
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    """
                    UPDATE executor_dispatch_invocation_preparations
                    SET adapter_id = 'changed' WHERE attempt_id = ?
                    """,
                    (preparation.attempt_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
                connection.execute(
                    """
                    DELETE FROM executor_dispatch_invocation_preparations
                    WHERE attempt_id = ?
                    """,
                    (preparation.attempt_id,),
                )
            connection.commit()
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_one_terminal_resolution_is_bound_and_immutable(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.root
        preparation = fixture._prepare()
        resolution = build_collaboration_executor_invocation_resolution(
            preparation,
            outcome="failed_before_invocation",
            failure_code="adapter-not-started",
            resolved_at="2026-07-30T10:08:32Z",
        )
        later = build_collaboration_executor_invocation_resolution(
            preparation,
            outcome="failed_before_invocation",
            failure_code="adapter-still-not-started",
            resolved_at="2026-07-30T10:08:33Z",
        )
        with closing(sqlite3.connect(root.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            insert_preparation(connection, preparation.to_dict())
            insert_resolution(connection, resolution.to_dict())
            with self.assertRaises(sqlite3.IntegrityError):
                insert_resolution(connection, later.to_dict())
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    """
                    UPDATE executor_dispatch_invocation_resolutions
                    SET failure_code = 'changed' WHERE resolution_id = ?
                    """,
                    (resolution.resolution_id,),
                )
            connection.commit()
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_preparation_rejects_nonmatching_claim_binding(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.root
        preparation = fixture._prepare().to_dict()
        with closing(sqlite3.connect(root.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            claim = connection.execute(
                "SELECT * FROM executor_dispatch_delivery_claims"
            ).fetchone()
            self.assertIsNotNone(claim)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO executor_dispatch_invocation_preparations(
                        attempt_id, attempt_sha256, claim_id, claim_sha256,
                        authentication_id, authentication_sha256,
                        dispatch_id, dispatch_sha256, mission_id,
                        collaboration_plan_id, session_id, session_sha256,
                        fence_generation, operation, operation_sequence,
                        operation_input_sha256, adapter_id, adapter_version,
                        adapter_build_sha256, deployment_binding_sha256,
                        idempotency_status, idempotency_key_sha256, prepared_at,
                        preparation_json, attempt_status, external_effect_status,
                        runtime_effect
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        preparation["attempt_id"],
                        preparation["attempt_sha256"],
                        preparation["delivery_claim"]["claim_id"],
                        preparation["delivery_claim"]["claim_sha256"],
                        preparation["reservation"]["authentication_id"],
                        preparation["reservation"]["authentication_sha256"],
                        preparation["reservation"]["dispatch_id"],
                        preparation["reservation"]["dispatch_sha256"],
                        claim["mission_id"],
                        claim["collaboration_plan_id"],
                        preparation["session"]["session_id"],
                        preparation["session"]["session_sha256"],
                        preparation["session"]["fence_generation"] + 1,
                        preparation["operation"]["name"],
                        preparation["operation"]["sequence"],
                        preparation["operation"]["operation_input_sha256"],
                        preparation["adapter"]["adapter_id"],
                        preparation["adapter"]["adapter_version"],
                        preparation["adapter"]["adapter_build_sha256"],
                        preparation["adapter"]["deployment_binding_sha256"],
                        preparation["idempotency"]["status"],
                        preparation["idempotency"]["key_sha256"],
                        preparation["prepared_at"],
                        canonical_json(preparation),
                        preparation["attempt_status"],
                        preparation["external_effect_status"],
                        preparation["runtime_effect"],
                    ),
                )


if __name__ == "__main__":
    unittest.main()
