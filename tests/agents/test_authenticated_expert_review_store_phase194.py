"""Schema 32 authenticated expert review custody foundation tests."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.authenticated_expert_review import (
    verify_authenticated_expert_review_store,
)
from sunderkey.errors import PrincipalAuthenticationError, StoreIntegrityError
from sunderkey.identity import (
    SAFETY_REDUCING_OPERATIONS,
    PrincipalOperation,
    compute_operation_intent_hash,
)
from sunderkey.registry import load_registry
from sunderkey.store import (
    AUTHENTICATED_EXPERT_REVIEW_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V31,
    EXPECTED_SCHEMA_MANIFEST_V32,
    EXPECTED_SCHEMA_MANIFEST_V33,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)
from sunderkey.store import (
    SAFETY_REDUCING_OPERATIONS as STORE_SAFETY_REDUCING_OPERATIONS,
)

from .test_store import REGISTRY_PATH, remove_schema_v34_objects

ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64


def _drop_v32_objects(connection: sqlite3.Connection) -> None:
    old_names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V31}
    additions = [
        item for item in EXPECTED_SCHEMA_MANIFEST_V32 if (item[0], item[1]) not in old_names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(f'DROP {object_type.upper()} "{item[1]}"')
    tables = (
        "authenticated_expert_review_revocation_projections",
        "authenticated_expert_review_closure_projections",
        "authenticated_expert_review_revocations",
        "authenticated_expert_review_closure_receipts",
        "authenticated_expert_review_closures",
        "authenticated_expert_review_receipts",
        "authenticated_expert_review_snapshot_slots",
        "authenticated_expert_review_snapshot_products",
        "authenticated_expert_review_snapshot_registrations",
        "authenticated_expert_review_replay_uses",
    )
    for table in tables:
        connection.execute(f'DROP TABLE "{table}"')


def _drop_v33_objects(connection: sqlite3.Connection) -> None:
    old_names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V32}
    additions = [
        item
        for item in EXPECTED_SCHEMA_MANIFEST_V33
        if (item[0], item[1]) not in old_names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(f'DROP {object_type.upper()} "{item[1]}"')
    tables = [item[1] for item in additions if item[0] == "table"]
    for table in reversed(tables):
        connection.execute(f'DROP TABLE "{table}"')


def _snapshot_product_values(*, dependencies: str = "[]", attempt: object = 1) -> tuple:
    return (
        "ERS-" + "A" * 32,
        "WORK-PHASE194-001",
        "EWP-" + "B" * 32,
        ZERO,
        "action_proposal",
        "AOE-APP-01",
        "AOE-CMD-APP-01",
        "EXE-" + "C" * 32,
        ONE,
        attempt,
        1,
        1,
        dependencies,
        "[]",
        "[]",
    )


class AuthenticatedExpertReviewStorePhase194Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "phase194.sqlite3"
        self.store = MissionStore(self.path)
        self.store.initialize()

    def test_identity_contracts_are_closed_and_revocation_is_safety_reducing(self) -> None:
        operations = {
            PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
            PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW,
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE,
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE,
        }
        self.assertEqual(len(operations), 4)
        self.assertIn(
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE,
            SAFETY_REDUCING_OPERATIONS,
        )
        self.assertIn(
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE.value,
            STORE_SAFETY_REDUCING_OPERATIONS,
        )
        register = {
            "active_plan_id": "CLP-" + "A" * 24,
            "active_plan_sha256": ZERO,
            "active_plan_version": 1,
            "mission_id": "MISSION-PHASE194",
            "mission_revision": 4,
            "principal_profile_id": "AOE-HQ-12",
            "snapshot_id": "ERS-" + "A" * 32,
            "snapshot_sha256": ONE,
            "workspace_event_count": 8,
            "workspace_event_head_sha256": ZERO,
            "workspace_id": "EWS-" + "B" * 32,
            "workspace_revision": 7,
            "workspace_schema_version": 2,
            "workspace_sha256": ONE,
        }
        self.assertTrue(
            compute_operation_intent_hash(
                PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
                register,
            ).startswith("sha256:")
        )
        with self.assertRaises(PrincipalAuthenticationError):
            compute_operation_intent_hash(
                PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
                {**register, "unexpected": True},
            )
        with self.assertRaises(PrincipalAuthenticationError):
            compute_operation_intent_hash(
                PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
                {**register, "workspace_revision": False},
            )

    def test_schema_32_adds_closed_review_custody_without_changing_v31(self) -> None:
        self.assertEqual(AUTHENTICATED_EXPERT_REVIEW_SCHEMA_VERSION, 32)
        self.assertGreaterEqual(SCHEMA_VERSION, 32)
        v31 = {item[1] for item in EXPECTED_SCHEMA_MANIFEST_V31}
        v32 = {item[1] for item in EXPECTED_SCHEMA_MANIFEST_V32}
        expected = {
            "authenticated_expert_review_replay_uses",
            "authenticated_expert_review_snapshot_registrations",
            "authenticated_expert_review_snapshot_products",
            "authenticated_expert_review_snapshot_slots",
            "authenticated_expert_review_receipts",
            "authenticated_expert_review_closures",
            "authenticated_expert_review_closure_receipts",
            "authenticated_expert_review_revocations",
            "authenticated_expert_review_closure_projections",
            "authenticated_expert_review_revocation_projections",
        }
        self.assertTrue(expected <= v32)
        self.assertFalse(expected & v31)
        frozen_v32 = {
            (item[0], item[1]): (item[2], item[3]) for item in EXPECTED_SCHEMA_MANIFEST_V32
        }
        for object_type, name, table_name, statement in EXPECTED_SCHEMA_MANIFEST_V31:
            self.assertEqual(frozen_v32[(object_type, name)], (table_name, statement))
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)

    def test_v31_migration_adds_empty_review_custody(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v34_objects(connection)
            _drop_v33_objects(connection)
            _drop_v32_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '31' WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 31")
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V31)
        backup = self.path.with_name("phase194-v31-backup.sqlite3")
        report = self.store.migrate(self.registry, backup)
        self.assertEqual(report.source_version, 31)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
            for table in (
                "authenticated_expert_review_replay_uses",
                "authenticated_expert_review_snapshot_registrations",
                "authenticated_expert_review_receipts",
                "authenticated_expert_review_closures",
                "authenticated_expert_review_revocations",
            ):
                self.assertEqual(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    0,
                )
        self.assertEqual(self.store.verify_store(self.registry).status, "valid")

    def test_strict_table_rejects_nonintegral_custody_values(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO authenticated_expert_review_snapshot_products "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    _snapshot_product_values(attempt=1.5),
                )

    def test_schema_32_binds_cross_table_identity_as_exact_composites(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            slot_foreign_keys = {
                (row[2], row[3], row[4])
                for row in connection.execute(
                    "PRAGMA foreign_key_list(authenticated_expert_review_snapshot_slots)"
                )
            }
            self.assertTrue(
                {
                    (
                        "authenticated_expert_review_snapshot_products",
                        "product_id",
                        "product_id",
                    ),
                    (
                        "authenticated_expert_review_snapshot_products",
                        "product_sha256",
                        "product_sha256",
                    ),
                    (
                        "authenticated_expert_review_snapshot_products",
                        "work_id",
                        "work_id",
                    ),
                }
                <= slot_foreign_keys
            )
            receipt_foreign_keys = {
                (row[2], row[3], row[4])
                for row in connection.execute(
                    "PRAGMA foreign_key_list(authenticated_expert_review_receipts)"
                )
            }
            self.assertIn(
                (
                    "authenticated_expert_review_snapshot_registrations",
                    "mission_id",
                    "mission_id",
                ),
                receipt_foreign_keys,
            )
            self.assertIn(
                (
                    "authenticated_expert_review_snapshot_products",
                    "product_sha256",
                    "product_sha256",
                ),
                receipt_foreign_keys,
            )

    def test_verifier_rejects_noncanonical_json(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                "INSERT INTO authenticated_expert_review_snapshot_products "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                _snapshot_product_values(dependencies="[ ]"),
            )
            with self.assertRaisesRegex(StoreIntegrityError, "canonical JSON"):
                verify_authenticated_expert_review_store(connection)

    def test_verifier_rejects_orphaned_normalized_rows(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                "INSERT INTO authenticated_expert_review_snapshot_products "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                _snapshot_product_values(),
            )
            with self.assertRaisesRegex(StoreIntegrityError, "orphan"):
                verify_authenticated_expert_review_store(connection)


if __name__ == "__main__":
    unittest.main()
