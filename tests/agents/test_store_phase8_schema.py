"""Schema v5 event-authentication baseline coverage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from sunderkey.errors import StoreConflictError, StoreIntegrityError
from sunderkey.identity import PrincipalOperation
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import (
    EVENT_AUTHENTICATION_SCHEMA_VERSION,
    SCHEMA_VERSION,
    SCOPE_REVOCATION_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    event_authentication_baseline_root_hash,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import (
    MISSION_ID,
    REGISTRY_PATH,
    SPECIALIST_ID,
    mission_data,
    observation,
    remove_schema_v6_objects,
)

FIXED_TIME = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)
V5_TRIGGER_NAMES = (
    "mission_event_authentication_baseline_insert_once",
    "mission_event_authentication_baseline_snapshot_guard",
    "mission_event_authentication_baseline_immutable",
    "mission_event_authentication_baseline_no_delete",
    "mission_event_requires_authentication_baseline",
    "principal_assertion_use_insert_once",
    "principal_event_append_idempotency_null",
    "principal_assertion_effect_insert_once",
    "principal_event_append_effect_guard",
    "mission_principal_ledger_insert_once",
    "mission_principal_ledger_no_delete",
)


class Phase8StoreSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.now = FIXED_TIME
        self.mission = MissionRequest.from_dict(mission_data())

    def initialized_store(self) -> MissionStore:
        store = MissionStore(self.path, clock=lambda: self.now)
        store.initialize()
        store.create_mission(self.registry, self.mission)
        return store

    def downgrade_to_v4(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v6_objects(connection)
            for trigger_name in V5_TRIGGER_NAMES:
                connection.execute(
                    f"DROP TRIGGER IF EXISTS {trigger_name}"
                )
            connection.execute(
                "DROP INDEX principal_event_append_request_identity"
            )
            connection.execute(
                "DROP TABLE mission_event_authentication_baselines"
            )
            connection.execute(
                """
                UPDATE store_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (str(SCOPE_REVOCATION_SCHEMA_VERSION),),
            )
            connection.execute(
                f"PRAGMA user_version = {SCOPE_REVOCATION_SCHEMA_VERSION}"
            )
            connection.commit()

    def prepare_event_append_policy(
        self,
        store: MissionStore,
    ):
        factory = CredentialFactory()
        trust = TrustProvisioningService(store)
        store_id = trust.status().store_id
        root_public_key = public_bytes(factory.root_private)
        trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:"
            + hashlib.sha256(root_public_key).hexdigest(),
        )
        policy = factory.policy(
            store_id=store_id,
            allowed_profiles=[SPECIALIST_ID],
            allowed_operations=[
                PrincipalOperation.EVENT_APPEND.value,
            ],
        )
        return trust, policy

    def test_fresh_v5_mission_has_bound_empty_event_baseline(
        self,
    ) -> None:
        store = self.initialized_store()
        stored = store.get_mission(self.registry, MISSION_ID)

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            user_version = connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
            store_id = connection.execute(
                "SELECT store_id FROM store_identity"
            ).fetchone()[0]
            baseline_rows = connection.execute(
                """
                SELECT *
                FROM mission_event_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchall()
            event_count = connection.execute(
                "SELECT COUNT(*) FROM mission_events"
            ).fetchone()[0]
            assertion_count = connection.execute(
                "SELECT COUNT(*) FROM principal_assertion_uses"
            ).fetchone()[0]
            effect_count = connection.execute(
                "SELECT COUNT(*) FROM principal_assertion_effects"
            ).fetchone()[0]

        self.assertEqual(user_version, SCHEMA_VERSION)
        self.assertEqual(len(baseline_rows), 1)
        baseline = baseline_rows[0]
        baseline_json = str(baseline["baseline_json"])
        raw_baseline = json.loads(baseline_json)
        self.assertEqual(
            set(raw_baseline),
            {
                "schema",
                "baseline_kind",
                "provenance_status",
                "mission_id",
                "mission_context_hash",
                "source_schema_version",
                "event_count",
                "event_head_hash",
            },
        )
        self.assertEqual(
            raw_baseline,
            {
                "schema": (
                    "sunderkey.mission-event-authentication-baseline.v1"
                ),
                "baseline_kind": "empty",
                "provenance_status": "no_pre_v5_events",
                "mission_id": MISSION_ID,
                "mission_context_hash": stored.context_hash,
                "source_schema_version": (
                    EVENT_AUTHENTICATION_SCHEMA_VERSION
                ),
                "event_count": 0,
                "event_head_hash": stored.context_hash,
            },
        )
        self.assertEqual(baseline_json, canonical_json(raw_baseline))
        self.assertEqual(baseline["store_id"], store_id)
        self.assertEqual(baseline["baseline_kind"], "empty")
        self.assertEqual(
            baseline["source_schema_version"],
            EVENT_AUTHENTICATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            baseline["mission_context_hash"],
            stored.context_hash,
        )
        self.assertEqual(baseline["event_count"], 0)
        self.assertEqual(
            baseline["event_head_hash"],
            stored.context_hash,
        )
        self.assertEqual(
            baseline["baseline_hash"],
            sha256_text(baseline_json),
        )
        self.assertEqual(
            baseline["baseline_root_hash"],
            event_authentication_baseline_root_hash(
                MISSION_ID,
                str(baseline["baseline_hash"]),
            ),
        )
        self.assertEqual(
            baseline["created_at"],
            "2026-07-30T10:05:00Z",
        )
        self.assertEqual(
            (event_count, assertion_count, effect_count),
            (0, 0, 0),
        )
        report = store.verify_store(self.registry)
        self.assertEqual(
            (report.status, report.mission_count, report.event_count),
            ("valid", 1, 0),
        )

    def test_event_baseline_is_insert_only_immutable_and_not_deletable(
        self,
    ) -> None:
        self.initialized_store()

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            baseline = connection.execute(
                """
                SELECT *
                FROM mission_event_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assert baseline is not None
            columns = tuple(baseline.keys())
            replace_sql = (
                "INSERT OR REPLACE INTO "
                "mission_event_authentication_baselines ("
                + ", ".join(columns)
                + ") VALUES ("
                + ", ".join("?" for _ in columns)
                + ")"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "event authentication baseline is insert-only",
            ):
                connection.execute(
                    replace_sql,
                    tuple(baseline[column] for column in columns),
                )
            connection.rollback()

            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "event authentication baseline is immutable",
            ):
                connection.execute(
                    """
                    UPDATE mission_event_authentication_baselines
                    SET created_at = created_at
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                )
            connection.rollback()

            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "event authentication baseline cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM mission_event_authentication_baselines
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                )
            connection.rollback()
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM mission_event_authentication_baselines
                """
            ).fetchone()[0]

        self.assertEqual(count, 1)

    def test_v4_to_v5_captures_events_without_inventing_provenance(
        self,
    ) -> None:
        store = self.initialized_store()
        receipt = store.append_event(
            self.registry,
            observation("EVT-PHASE8-HISTORICAL-001"),
            expected_revision=0,
        )
        self.downgrade_to_v4()
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )
        with closing(sqlite3.connect(self.path)) as connection:
            historical_event = connection.execute(
                """
                SELECT *
                FROM mission_events
                WHERE mission_id = ? AND event_id = ?
                """,
                (MISSION_ID, receipt.event_id),
            ).fetchone()
        backup = self.directory / "before-v5.sqlite3"

        report = store.migrate(self.registry, backup)

        self.assertEqual(
            report.source_version,
            SCOPE_REVOCATION_SCHEMA_VERSION,
        )
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(
                connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                SCOPE_REVOCATION_SCHEMA_VERSION,
            )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            baseline = connection.execute(
                """
                SELECT *
                FROM mission_event_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            migrated_event = connection.execute(
                """
                SELECT *
                FROM mission_events
                WHERE mission_id = ? AND event_id = ?
                """,
                (MISSION_ID, receipt.event_id),
            ).fetchone()
            provenance_counts = (
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
            )
        assert baseline is not None
        raw_baseline = json.loads(str(baseline["baseline_json"]))
        self.assertEqual(
            (
                baseline["baseline_kind"],
                baseline["source_schema_version"],
                baseline["event_count"],
                baseline["event_head_hash"],
            ),
            (
                "historical_pre_v5",
                SCOPE_REVOCATION_SCHEMA_VERSION,
                1,
                receipt.entry_hash,
            ),
        )
        self.assertEqual(
            raw_baseline["provenance_status"],
            "historical_events_not_event_append_authenticated",
        )
        self.assertEqual(
            raw_baseline["source_schema_version"],
            SCOPE_REVOCATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            raw_baseline["event_count"],
            1,
        )
        self.assertEqual(
            raw_baseline["event_head_hash"],
            receipt.entry_hash,
        )
        assert migrated_event is not None
        self.assertEqual(tuple(migrated_event), historical_event)
        self.assertEqual(provenance_counts, (0, 0))
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )
        self.assertEqual(
            MissionStore(backup).verify_store(self.registry).status,
            "valid",
        )

    def test_policy_enrollment_rejects_post_baseline_direct_event(
        self,
    ) -> None:
        store = self.initialized_store()
        store.append_event(
            self.registry,
            observation("EVT-PHASE8-UNATTRIBUTED-001"),
            expected_revision=0,
        )
        trust, policy = self.prepare_event_append_policy(store)

        with self.assertRaisesRegex(
            StoreConflictError,
            "unattributed event append",
        ):
            trust.apply_policy(policy)

        status = trust.status()
        self.assertTrue(status.root_pinned)
        self.assertFalse(status.policy_applied)
        with closing(sqlite3.connect(self.path)) as connection:
            counts = (
                connection.execute(
                    "SELECT COUNT(*) FROM trust_policy_history"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM mission_events"
                ).fetchone()[0],
                connection.execute(
                    """
                    SELECT event_count
                    FROM mission_event_authentication_baselines
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
            )
        self.assertEqual(counts, (0, 1, 0, 0))

    def test_direct_append_is_blocked_after_policy_enrollment(
        self,
    ) -> None:
        store = self.initialized_store()
        trust, policy = self.prepare_event_append_policy(store)
        trust.apply_policy(policy)

        with self.assertRaisesRegex(
            StoreConflictError,
            "Direct event append is disabled",
        ):
            store.append_event(
                self.registry,
                observation("EVT-PHASE8-DIRECT-BLOCKED-001"),
                expected_revision=0,
            )

        with closing(sqlite3.connect(self.path)) as connection:
            counts = (
                connection.execute(
                    "SELECT COUNT(*) FROM mission_events"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
            )
        self.assertEqual(counts, (0, 0, 0))
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_event_baseline_tampering_is_detected(self) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name =
                    'mission_event_authentication_baseline_immutable'
                """
            ).fetchone()[0]
            connection.execute(
                """
                DROP TRIGGER
                    mission_event_authentication_baseline_immutable
                """
            )
            connection.execute(
                """
                UPDATE mission_event_authentication_baselines
                SET event_head_hash = ?
                WHERE mission_id = ?
                """,
                ("sha256:" + "f" * 64, MISSION_ID),
            )
            connection.execute(str(trigger_sql))
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "event authentication baseline",
        ):
            store.verify_store(self.registry)


if __name__ == "__main__":
    unittest.main()
