"""Schema v4 migration and scope-revocation baseline coverage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from sunderkey.errors import StoreIntegrityError
from sunderkey.identity import PrincipalOperation
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import (
    AUTHENTICATED_PRINCIPAL_SCHEMA_VERSION,
    SCHEMA_V3_ADDITION_STATEMENTS,
    SCHEMA_VERSION,
    SCOPE_REVOCATION_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    scope_revocation_baseline_root_hash,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import (
    REGISTRY_PATH,
    mission_data,
    remove_schema_v5_objects,
)

MISSION_ID = "MISSION-PHASE7-SCHEMA"
FIXED_TIME = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)


class Phase7StoreSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.now = FIXED_TIME
        raw_mission = mission_data()
        raw_mission.update(
            {
                "mission_id": MISSION_ID,
                "scope_reference": SCOPE_REFERENCE,
                "scope_document_hash": SCOPE_DOCUMENT_HASH,
            }
        )
        self.mission = MissionRequest.from_dict(raw_mission)

    def initialized_store(self) -> MissionStore:
        store = MissionStore(self.path, clock=lambda: self.now)
        store.initialize()
        store.create_mission(self.registry, self.mission)
        return store

    def downgrade_to_v3(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v5_objects(connection)
            for trigger in (
                "mission_scope_grant_insert_once",
                "mission_scope_grant_requires_revocation_baseline",
                "mission_scope_grant_legacy_revocation_insert_empty",
                "mission_scope_grant_legacy_revocation_frozen",
            ):
                connection.execute(f"DROP TRIGGER {trigger}")
            connection.execute(
                "DROP TABLE mission_scope_grant_revocations"
            )
            connection.execute(
                "DROP TABLE mission_scope_revocation_baselines"
            )
            old_trigger = next(
                statement
                for statement in SCHEMA_V3_ADDITION_STATEMENTS
                if (
                    "mission_scope_grant_revocation_write_once"
                    in statement
                )
            )
            connection.execute(old_trigger)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (str(AUTHENTICATED_PRINCIPAL_SCHEMA_VERSION),),
            )
            connection.execute(
                "PRAGMA user_version = "
                f"{AUTHENTICATED_PRINCIPAL_SCHEMA_VERSION}"
            )
            connection.commit()

    def downgrade_to_v2(self) -> None:
        self.downgrade_to_v3()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            for table in (
                "principal_assertion_effects",
                "principal_assertion_uses",
                "mission_principal_ledgers",
                "mission_scope_grants",
                "trust_policy_history",
                "store_identity",
            ):
                connection.execute(f"DROP TABLE {table}")
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '2'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 2")
            connection.commit()

    def downgrade_to_v1(self) -> None:
        self.downgrade_to_v2()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("DROP TABLE approval_revocations")
            connection.execute("DROP TABLE mission_controls")
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '1'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 1")
            connection.commit()

    def accept_scope_grant(self, store: MissionStore):
        factory = CredentialFactory()
        trust = TrustProvisioningService(store)
        store_id = trust.status().store_id
        root_public_key = public_bytes(factory.root_private)
        trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
        )
        policy = factory.policy(store_id=store_id)
        trust.apply_policy(policy)
        stored = store.get_mission(self.registry, MISSION_ID)
        constraints_hash = sha256_text(
            canonical_json(self.mission.to_dict()["constraints"])
        )
        grant = factory.grant(
            store_id=store_id,
            mission_id=MISSION_ID,
            mission_context_hash=stored.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=constraints_hash,
            operations=[PrincipalOperation.MISSION_STOP.value],
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:30:00Z",
        )
        ScopeGrantAcceptanceService(
            store,
            self.registry,
        ).accept(grant)
        return grant

    def test_fresh_v4_mission_has_empty_revocation_baseline(self) -> None:
        store = self.initialized_store()

        self.assertEqual(SCOPE_REVOCATION_SCHEMA_VERSION, 4)
        with closing(store._open_existing_connection()) as connection:
            self.assertEqual(
                connection.execute(
                    "PRAGMA recursive_triggers"
                ).fetchone()[0],
                1,
            )

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            self.assertEqual(
                connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                SCHEMA_VERSION,
            )
            baseline = connection.execute(
                """
                SELECT * FROM mission_scope_revocation_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            signed_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM mission_scope_grant_revocations
                """
            ).fetchone()[0]
        assert baseline is not None
        raw_baseline = json.loads(str(baseline["baseline_json"]))
        self.assertEqual(baseline["baseline_kind"], "empty")
        self.assertEqual(
            baseline["source_schema_version"],
            SCOPE_REVOCATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            raw_baseline["provenance_status"],
            "no_pre_v4_scope_revocations",
        )
        self.assertEqual(
            raw_baseline["historical_revocations"]["count"],
            0,
        )
        self.assertEqual(
            baseline["baseline_hash"],
            sha256_text(str(baseline["baseline_json"])),
        )
        self.assertEqual(
            baseline["baseline_root_hash"],
            scope_revocation_baseline_root_hash(
                MISSION_ID,
                str(baseline["baseline_hash"]),
            ),
        )
        self.assertEqual(
            baseline["head_hash"],
            baseline["baseline_root_hash"],
        )
        self.assertEqual(baseline["signed_revocation_count"], 0)
        self.assertEqual(signed_count, 0)
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_v3_to_v4_captures_unsigned_historical_revocation(
        self,
    ) -> None:
        store = self.initialized_store()
        grant = self.accept_scope_grant(store)
        self.downgrade_to_v3()
        revoked_at = "2026-07-30T10:06:00Z"
        reason = "External authorization was withdrawn"
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                """
                UPDATE mission_scope_grants
                SET revoked_at = ?, revocation_reason = ?
                WHERE grant_hash = ?
                """,
                (revoked_at, reason, grant.content_sha256),
            )
            connection.commit()
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )
        backup = self.directory / "before-v4.sqlite3"
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)

        report = store.migrate(self.registry, backup)

        self.assertEqual(
            report.source_version,
            AUTHENTICATED_PRINCIPAL_SCHEMA_VERSION,
        )
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(
                connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                AUTHENTICATED_PRINCIPAL_SCHEMA_VERSION,
            )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            baseline = connection.execute(
                """
                SELECT * FROM mission_scope_revocation_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            signed_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM mission_scope_grant_revocations
                """
            ).fetchone()[0]
            grant_row = connection.execute(
                """
                SELECT revoked_at, revocation_reason
                FROM mission_scope_grants
                WHERE grant_hash = ?
                """,
                (grant.content_sha256,),
            ).fetchone()
        assert baseline is not None
        assert grant_row is not None
        baseline_json = json.loads(str(baseline["baseline_json"]))
        self.assertEqual(baseline["baseline_kind"], "historical_v3")
        self.assertEqual(
            baseline["historical_revocation_count"],
            1,
        )
        self.assertEqual(
            baseline_json["provenance_status"],
            "historical_v3_scope_revocations_not_signature_verified",
        )
        self.assertEqual(signed_count, 0)
        self.assertEqual(
            tuple(grant_row),
            (revoked_at, reason),
        )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

        with (
            closing(sqlite3.connect(self.path)) as connection,
            self.assertRaises(sqlite3.IntegrityError),
        ):
            connection.execute(
                """
                UPDATE mission_scope_grants
                SET revocation_reason = 'changed'
                WHERE grant_hash = ?
                """,
                (grant.content_sha256,),
            )

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA recursive_triggers = OFF")
            self.assertEqual(
                connection.execute(
                    "PRAGMA recursive_triggers"
                ).fetchone()[0],
                0,
            )
            stored_grant = connection.execute(
                """
                SELECT * FROM mission_scope_grants
                WHERE grant_hash = ?
                """,
                (grant.content_sha256,),
            ).fetchone()
            stored_baseline = connection.execute(
                """
                SELECT * FROM mission_scope_revocation_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assert stored_grant is not None
            assert stored_baseline is not None

            grant_columns = tuple(stored_grant.keys())
            grant_values = dict(stored_grant)
            grant_values["revoked_at"] = None
            grant_values["revocation_reason"] = None
            grant_sql = (
                "INSERT OR REPLACE INTO mission_scope_grants ("
                + ", ".join(grant_columns)
                + ") VALUES ("
                + ", ".join("?" for _ in grant_columns)
                + ")"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "scope grant identity is insert-only",
            ):
                connection.execute(
                    grant_sql,
                    tuple(
                        grant_values[column]
                        for column in grant_columns
                    ),
                )

            baseline_columns = tuple(stored_baseline.keys())
            baseline_sql = (
                "INSERT OR REPLACE INTO "
                "mission_scope_revocation_baselines ("
                + ", ".join(baseline_columns)
                + ") VALUES ("
                + ", ".join("?" for _ in baseline_columns)
                + ")"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "scope revocation baseline is insert-only",
            ):
                connection.execute(
                    baseline_sql,
                    tuple(
                        stored_baseline[column]
                        for column in baseline_columns
                    ),
                )

    def test_v2_to_v4_creates_empty_revocation_baseline(self) -> None:
        store = self.initialized_store()
        self.downgrade_to_v2()
        backup = self.directory / "before-v4-v2.sqlite3"

        report = store.migrate(self.registry, backup)

        self.assertEqual(report.source_version, 2)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                """
                SELECT baseline_kind, source_schema_version
                FROM mission_scope_revocation_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        self.assertEqual(row, ("empty", 2))
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_v1_to_v4_records_original_baseline_source(self) -> None:
        store = self.initialized_store()
        self.downgrade_to_v1()
        backup = self.directory / "before-v4-v1.sqlite3"

        report = store.migrate(self.registry, backup)

        self.assertEqual(report.source_version, 1)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            revocation_source = connection.execute(
                """
                SELECT source_schema_version
                FROM mission_scope_revocation_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
            principal_baseline_json = connection.execute(
                """
                SELECT baseline_json
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
        self.assertEqual(revocation_source, 1)
        self.assertEqual(
            json.loads(principal_baseline_json)[
                "source_schema_version"
            ],
            1,
        )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_scope_revocation_head_tampering_is_detected(self) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND name =
                    'mission_scope_revocation_baseline_advance_only'
                """
            ).fetchone()[0]
            connection.execute(
                """
                DROP TRIGGER
                    mission_scope_revocation_baseline_advance_only
                """
            )
            connection.execute(
                """
                UPDATE mission_scope_revocation_baselines
                SET head_hash = ?
                WHERE mission_id = ?
                """,
                ("sha256:" + "f" * 64, MISSION_ID),
            )
            connection.execute(trigger_sql)
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "counts or head",
        ):
            store.verify_store(self.registry)

    def test_create_mission_replay_reconciles_revocation_baseline(
        self,
    ) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND name =
                    'mission_scope_revocation_baseline_no_delete'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER "
                "mission_scope_revocation_baseline_no_delete"
            )
            connection.execute(
                """
                DELETE FROM mission_scope_revocation_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            )
            connection.execute(str(trigger_sql))
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "baseline is missing or duplicated",
        ):
            store.create_mission(self.registry, self.mission)


if __name__ == "__main__":
    unittest.main()
