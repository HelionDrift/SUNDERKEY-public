"""Schema v25 executor dispatch delivery claim custody coverage."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.store import (
    EXECUTOR_DELIVERY_CLAIM_CUSTODY_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V24,
    EXPECTED_SCHEMA_MANIFEST_V25,
    SCHEMA_VERSION,
    _schema_manifest,
    canonical_json,
)

from . import test_collaboration_executor_delivery_claim_phase130 as phase130
from .test_store import remove_schema_v26_objects

V25_OBJECTS = {
    "executor_dispatch_delivery_claims",
    "executor_dispatch_delivery_claim_guard",
    "executor_dispatch_delivery_claims_immutable",
    "executor_dispatch_delivery_claims_no_delete",
}


def downgrade_empty_delivery_claim_custody_to_v24(
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
    connection.execute(
        "UPDATE store_metadata SET value = '24' WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 24")


def insert_claim(
    connection: sqlite3.Connection,
    document: dict,
) -> None:
    predecessor = document["predecessor"]
    connection.execute(
        """
        INSERT INTO executor_dispatch_delivery_claims(
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
            claimant_instance_id,
            claim_generation,
            predecessor_claim_id,
            predecessor_claim_sha256,
            predecessor_lease_expires_at,
            claimed_at,
            lease_expires_at,
            claim_json,
            claim_status,
            claimant_identity_status,
            external_effect_status,
            runtime_effect
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?
        )
        """,
        (
            document["claim_id"],
            document["claim_sha256"],
            document["reservation"]["authentication_id"],
            document["reservation"]["authentication_sha256"],
            document["reservation"]["dispatch_id"],
            document["reservation"]["dispatch_sha256"],
            document["mission"]["mission_id"],
            document["mission"]["collaboration_plan_id"],
            document["session"]["session_id"],
            document["session"]["session_sha256"],
            document["session"]["fence_generation"],
            document["operation"]["name"],
            document["operation"]["sequence"],
            document["operation"]["operation_input_sha256"],
            document["claimant"]["instance_id"],
            document["claim_generation"],
            None if predecessor is None else predecessor["claim_id"],
            None if predecessor is None else predecessor["claim_sha256"],
            None if predecessor is None else predecessor["lease_expires_at"],
            document["claimed_at"],
            document["lease_expires_at"],
            canonical_json(document),
            document["claim_status"],
            document["claimant_identity_status"],
            document["external_effect_status"],
            document["runtime_effect"],
        ),
    )


class Phase131StoreSchemaTests(unittest.TestCase):
    def fixture(self):
        fixture = phase130.CollaborationExecutorDeliveryClaimPhase130Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_v25_adds_only_delivery_claim_custody_objects(self) -> None:
        self.assertEqual(EXECUTOR_DELIVERY_CLAIM_CUSTODY_SCHEMA_VERSION, 25)
        self.assertGreaterEqual(SCHEMA_VERSION, 25)
        v24 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V24}
        v25 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V25}
        self.assertEqual(set(v25) - set(v24), V25_OBJECTS)
        self.assertFalse(set(v24) - set(v25))
        self.assertFalse(
            {name for name in v24.keys() & v25.keys() if v24[name] != v25[name]}
        )

    def test_v24_store_migrates_without_changing_reservations(self) -> None:
        fixture = self.fixture()
        root_fixture = fixture.fixture.root
        with closing(sqlite3.connect(root_fixture.store.path)) as connection:
            before = connection.execute(
                "SELECT authentication_id, authentication_sha256 "
                "FROM executor_dispatch_reservations"
            ).fetchall()
            downgrade_empty_delivery_claim_custody_to_v24(connection)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V24)
        with tempfile.TemporaryDirectory() as directory:
            report = root_fixture.store.migrate(
                root_fixture.registry,
                Path(directory) / "before-v25.sqlite3",
            )
        self.assertEqual(report.source_version, 24)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(root_fixture.store.path)) as connection:
            after = connection.execute(
                "SELECT authentication_id, authentication_sha256 "
                "FROM executor_dispatch_reservations"
            ).fetchall()
            self.assertEqual(before, after)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_delivery_claims"
                ).fetchone()[0],
                0,
            )
        self.assertEqual(
            root_fixture.store.verify_store(root_fixture.registry).status,
            "valid",
        )

    def test_claim_chain_is_append_only_and_deeply_verified(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.root
        first = fixture._claim()
        second = fixture._claim(
            claimed_at="2026-07-30T10:08:40Z",
            lease_expires_at="2026-07-30T10:08:50Z",
            previous_claim=first,
            claimant="executor-instance-b",
        )
        with closing(sqlite3.connect(root.store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            insert_claim(connection, first.to_dict())
            insert_claim(connection, second.to_dict())
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE executor_dispatch_delivery_claims "
                    "SET claimant_instance_id = 'changed' WHERE claim_id = ?",
                    (first.claim_id,),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
                connection.execute(
                    "DELETE FROM executor_dispatch_delivery_claims WHERE claim_id = ?",
                    (first.claim_id,),
                )
            connection.commit()
        self.assertEqual(
            root.store.verify_store(root.registry).status,
            "valid",
        )

    def test_parallel_generation_is_rejected(self) -> None:
        fixture = self.fixture()
        root = fixture.fixture.root
        first = fixture._claim()
        second_a = fixture._claim(
            claimed_at="2026-07-30T10:08:40Z",
            lease_expires_at="2026-07-30T10:08:50Z",
            previous_claim=first,
            claimant="executor-instance-b",
        )
        second_b = fixture._claim(
            claimed_at="2026-07-30T10:08:40Z",
            lease_expires_at="2026-07-30T10:08:55Z",
            previous_claim=first,
            claimant="executor-instance-c",
        )
        with closing(sqlite3.connect(root.store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            insert_claim(connection, first.to_dict())
            insert_claim(connection, second_a.to_dict())
            with self.assertRaises(sqlite3.IntegrityError):
                insert_claim(connection, second_b.to_dict())


if __name__ == "__main__":
    unittest.main()
