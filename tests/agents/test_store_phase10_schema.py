"""Schema v7 authenticated approval submission provenance coverage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from sunderkey.approvals import ApprovalService
from sunderkey.errors import StoreConflictError, StoreIntegrityError
from sunderkey.events import MissionEvent
from sunderkey.identity import PrincipalOperation
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.simulation import SimulationService
from sunderkey.store import (
    APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION,
    APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST_V6,
    EXPECTED_SCHEMA_MANIFEST_V7,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
    approval_submission_authentication_baseline_root_hash,
    approval_submission_history_root_hash,
    canonical_json,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    AUDIENCE,
    NOW,
    ROOT_KEY_ID,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import (
    CONTROL_ID,
    DECISION_TIME,
    FIXED_TIME,
    MISSION_ID,
    REGISTRY_PATH,
    SPECIALIST_ID,
    mission_data,
    proposal_data,
    remove_schema_v5_objects,
    remove_schema_v8_objects,
)
from .test_store_phase9_schema import (
    V6_INDEX_NAMES,
    V6_TRIGGER_NAMES,
)

V7_TRIGGER_NAMES = (
    "mission_approval_submission_authentication_baseline_insert_once",
    "mission_approval_submission_authentication_baseline_snapshot_guard",
    "mission_approval_submission_authentication_baseline_immutable",
    "mission_approval_submission_authentication_baseline_no_delete",
    "approval_submission_requires_authentication_baseline",
    "approval_submission_no_delete",
    "approval_submission_insert_once",
    "approval_submission_core_write_once",
    "principal_approval_submission_use_guard",
    "principal_approval_submission_effect_guard",
)
V7_INDEX_NAMES = (
    "principal_approval_submission_request_identity",
    "principal_approval_submission_idempotency_identity",
)


class Phase10StoreSchemaTests(unittest.TestCase):
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
        store = MissionStore(
            self.path,
            clock=lambda: self.now,
        )
        store.initialize()
        store.create_mission(self.registry, self.mission)
        return store

    def append_proposal(
        self,
        store: MissionStore,
        suffix: str,
    ) -> str:
        raw = json.loads(json.dumps(proposal_data()))
        proposal_id = f"EVT-PROP-PHASE10-{suffix}"
        raw["event_id"] = proposal_id
        raw["payload"]["target"] = (
            f"synthetic://store/phase10/{suffix.lower()}"
        )
        revision = store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision
        store.append_event(
            self.registry,
            MissionEvent.from_dict(raw),
            expected_revision=revision,
        )
        return proposal_id

    def submit(
        self,
        store: MissionStore,
        proposal_id: str,
        suffix: str,
    ) -> tuple[ApprovalService, str]:
        approvals = ApprovalService(
            store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )
        record = approvals.submit(
            mission_id=MISSION_ID,
            proposal_id=proposal_id,
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key=f"phase10-submit-{suffix}",
            principal_profile_id=SPECIALIST_ID,
        )
        return approvals, record.approval_id

    def remove_v7_objects(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        remove_schema_v8_objects(connection)
        for trigger_name in V7_TRIGGER_NAMES:
            connection.execute(
                f"DROP TRIGGER IF EXISTS {trigger_name}"
            )
        for index_name in V7_INDEX_NAMES:
            connection.execute(
                f"DROP INDEX IF EXISTS {index_name}"
            )
        connection.execute(
            "DROP TABLE "
            "mission_approval_submission_authentication_baselines"
        )

    def downgrade_to_v6(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            self.remove_v7_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (
                    str(
                        APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION
                    ),
                ),
            )
            connection.execute(
                "PRAGMA user_version = "
                f"{APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION}"
            )
            connection.commit()

    def downgrade_to_v4(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            self.remove_v7_objects(connection)
            for trigger_name in V6_TRIGGER_NAMES:
                connection.execute(
                    f"DROP TRIGGER IF EXISTS {trigger_name}"
                )
            for index_name in V6_INDEX_NAMES:
                connection.execute(
                    f"DROP INDEX IF EXISTS {index_name}"
                )
            connection.execute(
                "DROP TABLE "
                "mission_approval_decision_authentication_baselines"
            )
            remove_schema_v5_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '4'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 4")
            connection.commit()

    def test_fresh_v7_mission_has_bound_empty_submission_baseline(
        self,
    ) -> None:
        store = self.initialized_store()
        mission = store.get_mission(self.registry, MISSION_ID)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_submission_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert row is not None
        baseline = json.loads(str(row["baseline_json"]))
        expected = {
            "schema": (
                "sunderkey.mission-approval-submission-"
                "authentication-baseline.v1"
            ),
            "baseline_kind": "empty",
            "provenance_status": (
                "no_pre_v7_approval_submissions"
            ),
            "mission_id": MISSION_ID,
            "mission_context_hash": mission.context_hash,
            "source_schema_version": (
                APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION
            ),
            "historical_submissions": [],
            "historical_submission_root_hash": (
                approval_submission_history_root_hash(())
            ),
        }
        self.assertEqual(baseline, expected)
        self.assertEqual(
            row["baseline_hash"],
            sha256_text(canonical_json(expected)),
        )
        self.assertEqual(
            row["baseline_root_hash"],
            approval_submission_authentication_baseline_root_hash(
                MISSION_ID,
                str(row["baseline_hash"]),
            ),
        )
        self.assertEqual(
            row["historical_submission_count"],
            0,
        )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_v7_objects_preserve_the_exact_v6_manifest(
        self,
    ) -> None:
        self.assertEqual(
            APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION,
            7,
        )
        v6_names = {
            item[1]
            for item in EXPECTED_SCHEMA_MANIFEST_V6
        }
        v7_names = {
            item[1]
            for item in EXPECTED_SCHEMA_MANIFEST_V7
        }
        self.assertNotIn(
            "mission_approval_submission_authentication_baselines",
            v6_names,
        )
        self.assertIn(
            "mission_approval_submission_authentication_baselines",
            v7_names,
        )
        self.assertTrue(v6_names < v7_names)
        self.initialized_store()
        self.downgrade_to_v6()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V6,
            )

    def test_submission_baseline_is_insert_only_and_immutable(
        self,
    ) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA recursive_triggers = OFF")
            row = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_submission_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assert row is not None
            columns = tuple(row.keys())
            replace_sql = (
                "INSERT OR REPLACE INTO "
                "mission_approval_submission_authentication_baselines ("
                + ", ".join(columns)
                + ") VALUES ("
                + ", ".join("?" for _ in columns)
                + ")"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "baseline is insert-only",
            ):
                connection.execute(
                    replace_sql,
                    tuple(row[column] for column in columns),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "baseline is immutable",
            ):
                connection.execute(
                    """
                    UPDATE
                        mission_approval_submission_authentication_baselines
                    SET created_at = created_at
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "baseline cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM
                        mission_approval_submission_authentication_baselines
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_v6_migration_retains_pending_and_decided_descendants(
        self,
    ) -> None:
        store = self.initialized_store()
        states: dict[str, str] = {}
        proposal_ids = {
            suffix: self.append_proposal(store, suffix)
            for suffix in (
                "PENDING",
                "APPROVED",
                "DENIED",
                "CONSUMED",
                "REVOKED",
            )
        }
        for suffix in (
            "PENDING",
            "APPROVED",
            "DENIED",
            "CONSUMED",
            "REVOKED",
        ):
            approvals, approval_id = self.submit(
                store,
                proposal_ids[suffix],
                suffix.lower(),
            )
            states[approval_id] = suffix.lower()
            if suffix == "PENDING":
                continue
            if suffix == "DENIED":
                approvals.deny(
                    approval_id,
                    reason_code="phase10-denied",
                    reason="Denied by independent control",
                    risk="Outside the reviewed simulation plan",
                    decision_owner="phase10-control",
                    idempotency_key="phase10-deny",
                    expected_version=1,
                    principal_profile_id=CONTROL_ID,
                )
                continue
            approvals.approve(
                approval_id,
                authority="phase10-control",
                constraints=("Simulation only",),
                authorization_expires_at="2026-01-01T11:00:00Z",
                idempotency_key=f"phase10-approve-{suffix.lower()}",
                expected_version=1,
                principal_profile_id=CONTROL_ID,
            )
            if suffix == "CONSUMED":
                SimulationService(
                    store,
                    self.registry,
                    clock=lambda: DECISION_TIME,
                ).simulate(
                    approval_id,
                    idempotency_key="phase10-simulate",
                    principal_profile_id=SPECIALIST_ID,
                )
            elif suffix == "REVOKED":
                approvals.revoke(
                    approval_id,
                    reason_code="phase10-revoked",
                    reason="Authorization withdrawn",
                    risk="Review conditions changed",
                    decision_owner="phase10-control",
                    idempotency_key="phase10-revoke",
                    expected_version=2,
                    principal_profile_id=CONTROL_ID,
                )
        self.downgrade_to_v6()
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )
        backup = self.directory / "before-v7.sqlite3"

        report = store.migrate(self.registry, backup)

        self.assertEqual(
            report.source_version,
            APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            report.target_version,
            SCHEMA_VERSION,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            baseline_row = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_submission_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            proof_counts = (
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM principal_assertion_uses
                    WHERE operation = ?
                    """,
                    (
                        PrincipalOperation.APPROVAL_SUBMIT.value,
                    ),
                ).fetchone()[0],
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM principal_assertion_effects
                    WHERE effect_kind = ?
                    """,
                    (
                        PrincipalOperation.APPROVAL_SUBMIT.value,
                    ),
                ).fetchone()[0],
            )
        assert baseline_row is not None
        baseline = json.loads(str(baseline_row["baseline_json"]))
        submissions = baseline["historical_submissions"]
        self.assertEqual(
            baseline_row["baseline_kind"],
            "historical_pre_v7",
        )
        self.assertEqual(
            baseline_row["source_schema_version"],
            APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            baseline_row["historical_submission_count"],
            5,
        )
        self.assertEqual(proof_counts, (0, 0))
        self.assertEqual(
            [item["approval_id"] for item in submissions],
            sorted(states),
        )
        for item in submissions:
            record = item["approval_record"]
            self.assertEqual(record["state"], "pending")
            self.assertEqual(record["version"], 1)
            self.assertIsNone(record["decision_event_id"])
            self.assertIsNone(record["simulation_id"])
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )
        self.assertEqual(
            MissionStore(backup).verify_store(
                self.registry
            ).status,
            "valid",
        )

    def test_failed_v6_migration_rolls_back_after_backup(
        self,
    ) -> None:
        store = self.initialized_store()
        self.downgrade_to_v6()
        backup = self.directory / "rollback-v6.sqlite3"
        with (
            mock.patch.object(
                store,
                "_insert_approval_submission_authentication_baseline",
                side_effect=StoreIntegrityError(
                    "forced phase10 migration failure"
                ),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "forced phase10 migration failure",
            ),
        ):
            store.migrate(self.registry, backup)

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION,
            )
        self.assertTrue(backup.is_file())
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )
        self.assertEqual(
            MissionStore(backup).verify_store(
                self.registry
            ).status,
            "valid",
        )

    def test_pending_rows_resist_sqlite_conflict_algorithms(
        self,
    ) -> None:
        store = self.initialized_store()
        proposal_id = self.append_proposal(store, "GUARDS")
        _, approval_id = self.submit(
            store,
            proposal_id,
            "guards",
        )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA recursive_triggers = OFF")
            self.assertEqual(
                connection.execute(
                    "PRAGMA recursive_triggers"
                ).fetchone()[0],
                0,
            )
            row = connection.execute(
                """
                SELECT *
                FROM approval_queue
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
            assert row is not None
            columns = tuple(row.keys())
            placeholders = ", ".join("?" for _ in columns)
            replace_sql = (
                "INSERT OR REPLACE INTO approval_queue ("
                + ", ".join(columns)
                + ") VALUES ("
                + placeholders
                + ")"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval submission cannot be deleted",
            ):
                connection.execute(
                    "DELETE FROM approval_queue "
                    "WHERE approval_id = ?",
                    (approval_id,),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval submission identity is insert-only",
            ):
                connection.execute(
                    replace_sql,
                    tuple(row[column] for column in columns),
                )
            connection.rollback()
            replacement = dict(row)
            replacement["approval_id"] = (
                "APR-PHASE10-CONFLICT-REPLACEMENT"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval submission identity is insert-only",
            ):
                connection.execute(
                    replace_sql,
                    tuple(
                        replacement[column]
                        for column in columns
                    ),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval submission core is write-once",
            ):
                connection.execute(
                    """
                    UPDATE OR REPLACE approval_queue
                    SET submit_request_hash = ?
                    WHERE approval_id = ?
                    """,
                    ("sha256:" + "f" * 64, approval_id),
                )
            connection.rollback()
            upsert_sql = (
                "INSERT INTO approval_queue ("
                + ", ".join(columns)
                + ") VALUES ("
                + placeholders
                + ") ON CONFLICT(approval_id) DO UPDATE SET "
                "submit_request_hash = excluded.submit_request_hash"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval submission identity is insert-only",
            ):
                connection.execute(
                    upsert_sql,
                    tuple(row[column] for column in columns),
                )
            connection.rollback()
            remaining = connection.execute(
                """
                SELECT *
                FROM approval_queue
                WHERE mission_id = ? AND proposal_id = ?
                """,
                (MISSION_ID, proposal_id),
            ).fetchall()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(
            dict(remaining[0]),
            dict(row),
        )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_global_counts_include_submission_baselines(
        self,
    ) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "DROP TRIGGER "
                "mission_approval_submission_authentication_"
                "baseline_no_delete"
            )
            connection.execute(
                "DELETE FROM "
                "mission_approval_submission_authentication_baselines"
            )
            connection.commit()

        with (
            mock.patch.object(
                store,
                "_require_schema",
                return_value=(
                    APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION
                ),
            ),
            mock.patch.object(
                store,
                "_verify_phase4_mission_state",
                return_value=(1, 0, 0, 0, 0),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "Global mission store counts do not reconcile",
            ),
        ):
            store.verify_store(self.registry)

    def test_policy_enrollment_rejects_post_baseline_submission(
        self,
    ) -> None:
        store = self.initialized_store()
        proposal_id = self.append_proposal(store, "POLICY")
        self.downgrade_to_v4()
        store.migrate(
            self.registry,
            self.directory / "before-v7-policy.sqlite3",
        )
        self.submit(store, proposal_id, "policy")
        self.now = NOW
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
                PrincipalOperation.APPROVAL_SUBMIT.value,
            ],
        )

        with self.assertRaisesRegex(
            StoreConflictError,
            "unauthenticated approval submission",
        ):
            trust.apply_policy(policy)

        self.assertFalse(trust.status().policy_applied)


if __name__ == "__main__":
    unittest.main()
