"""Schema v6 authenticated approval decision provenance coverage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.approvals import ApprovalService
from sunderkey.errors import StoreConflictError, StoreIntegrityError
from sunderkey.events import MissionEvent
from sunderkey.identity import PrincipalOperation
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import (
    APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION,
    EVENT_AUTHENTICATION_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST_V5,
    EXPECTED_SCHEMA_MANIFEST_V6,
    SCHEMA_VERSION,
    MissionStore,
    approval_decision_authentication_baseline_root_hash,
    approval_decision_history_root_hash,
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
    remove_schema_v7_objects,
)

V6_TRIGGER_NAMES = (
    "mission_approval_decision_authentication_baseline_insert_once",
    "mission_approval_decision_authentication_baseline_snapshot_guard",
    "mission_approval_decision_authentication_baseline_immutable",
    "mission_approval_decision_authentication_baseline_no_delete",
    "approval_decision_requires_authentication_baseline",
    "approval_decision_core_write_once",
    "approval_decision_state_transition_guard",
    "approval_decision_no_delete",
    "approval_decision_insert_once",
    "approval_identity_write_once",
    "principal_approval_decision_use_guard",
    "principal_approval_decision_effect_guard",
)
V6_INDEX_NAMES = (
    "principal_approval_decision_request_identity",
    "principal_approval_decision_idempotency_identity",
)


class Phase9StoreSchemaTests(unittest.TestCase):
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

    def pending_approval(
        self,
        store: MissionStore,
    ) -> tuple[ApprovalService, str]:
        store.append_event(
            self.registry,
            MissionEvent.from_dict(proposal_data()),
            expected_revision=0,
        )
        approvals = ApprovalService(
            store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )
        record = approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="phase9-submit-001",
            principal_profile_id=SPECIALIST_ID,
        )
        return approvals, record.approval_id

    def approved_store(
        self,
    ) -> tuple[MissionStore, str]:
        store = self.initialized_store()
        approvals, approval_id = self.pending_approval(store)
        approvals.approve(
            approval_id,
            authority="phase9-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-01-01T11:00:00Z",
            idempotency_key="phase9-approve-001",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        return store, approval_id

    def denied_store(
        self,
    ) -> tuple[MissionStore, str]:
        store = self.initialized_store()
        approvals, approval_id = self.pending_approval(store)
        approvals.deny(
            approval_id,
            reason_code="phase9-denied",
            reason="Denied by independent control",
            risk="Outside the reviewed simulation plan",
            decision_owner="phase9-control",
            idempotency_key="phase9-deny-001",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        return store, approval_id

    def remove_v6_objects(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        remove_schema_v7_objects(connection)
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

    def downgrade_to_v5(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            self.remove_v6_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (str(EVENT_AUTHENTICATION_SCHEMA_VERSION),),
            )
            connection.execute(
                "PRAGMA user_version = "
                f"{EVENT_AUTHENTICATION_SCHEMA_VERSION}"
            )
            connection.commit()

    def downgrade_to_v4(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            self.remove_v6_objects(connection)
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

    def test_fresh_v6_mission_has_bound_empty_decision_baseline(
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
                    mission_approval_decision_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert row is not None
        baseline = json.loads(str(row["baseline_json"]))
        self.assertEqual(
            baseline,
            {
                "schema": (
                    "sunderkey.mission-approval-decision-"
                    "authentication-baseline.v1"
                ),
                "baseline_kind": "empty",
                "provenance_status": (
                    "no_pre_v6_events_or_decisions"
                ),
                "mission_id": MISSION_ID,
                "mission_context_hash": mission.context_hash,
                "source_schema_version": (
                    APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION
                ),
                "event_count": 0,
                "event_head_hash": mission.context_hash,
                "historical_decisions": [],
                "historical_decision_root_hash": (
                    approval_decision_history_root_hash(())
                ),
            },
        )
        self.assertEqual(
            row["baseline_hash"],
            sha256_text(canonical_json(baseline)),
        )
        self.assertEqual(
            row["baseline_root_hash"],
            approval_decision_authentication_baseline_root_hash(
                MISSION_ID,
                str(row["baseline_hash"]),
            ),
        )
        self.assertEqual(
            (
                row["historical_decision_count"],
                row["historical_decision_root_hash"],
            ),
            (
                0,
                approval_decision_history_root_hash(()),
            ),
        )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_v6_objects_do_not_change_the_exact_v5_manifest(
        self,
    ) -> None:
        self.assertEqual(
            APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION,
            6,
        )
        self.assertGreater(
            SCHEMA_VERSION,
            APPROVAL_DECISION_AUTHENTICATION_SCHEMA_VERSION,
        )
        v5_names = {
            item[1]
            for item in EXPECTED_SCHEMA_MANIFEST_V5
        }
        v6_names = {
            item[1]
            for item in EXPECTED_SCHEMA_MANIFEST_V6
        }
        self.assertNotIn(
            "mission_approval_decision_authentication_baselines",
            v5_names,
        )
        self.assertIn(
            "mission_approval_decision_authentication_baselines",
            v6_names,
        )
        self.assertTrue(v5_names < v6_names)

    def test_decision_baseline_and_decision_core_are_write_once(
        self,
    ) -> None:
        _, approval_id = self.approved_store()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            baseline = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_decision_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assert baseline is not None
            columns = tuple(baseline.keys())
            replace_sql = (
                "INSERT OR REPLACE INTO "
                "mission_approval_decision_authentication_baselines ("
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
                    tuple(baseline[column] for column in columns),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "baseline is immutable",
            ):
                connection.execute(
                    """
                    UPDATE
                        mission_approval_decision_authentication_baselines
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
                        mission_approval_decision_authentication_baselines
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "decision core is write-once",
            ):
                connection.execute(
                    """
                    UPDATE approval_queue
                    SET decision_reason = 'rewritten'
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "state transition is invalid",
            ):
                connection.execute(
                    """
                    UPDATE approval_queue
                    SET status = 'denied'
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                )

    def _assert_decided_approval_cannot_be_deleted_or_replaced(
        self,
        approval_id: str,
    ) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            recursive_triggers = int(
                connection.execute(
                    "PRAGMA recursive_triggers"
                ).fetchone()[0]
            )
            self.assertEqual(recursive_triggers, 0)
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
            replace_sql = (
                "INSERT OR REPLACE INTO approval_queue ("
                + ", ".join(columns)
                + ") VALUES ("
                + ", ".join("?" for _ in columns)
                + ")"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval decision cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM approval_queue
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval decision identity is insert-only",
            ):
                connection.execute(
                    replace_sql,
                    tuple(row[column] for column in columns),
                )
            connection.rollback()
            replacement = dict(row)
            replacement["approval_id"] = "APR-PHASE9-REPLACEMENT"
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval decision identity is insert-only",
            ):
                connection.execute(
                    replace_sql,
                    tuple(
                        replacement[column]
                        for column in columns
                    ),
                )
            connection.rollback()
            remaining = connection.execute(
                """
                SELECT approval_id, status, decision_event_id
                FROM approval_queue
                WHERE mission_id = ? AND proposal_id = ?
                """,
                (row["mission_id"], row["proposal_id"]),
            ).fetchall()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(
            (
                remaining[0]["approval_id"],
                remaining[0]["status"],
                remaining[0]["decision_event_id"],
            ),
            (
                row["approval_id"],
                row["status"],
                row["decision_event_id"],
            ),
        )

    def _assert_update_or_replace_cannot_rebind_pending_identity(
        self,
        store: MissionStore,
        decided_approval_id: str,
    ) -> None:
        second_proposal = proposal_data()
        second_proposal["event_id"] = "EVT-PROP-PHASE9-SECOND"
        second_proposal["timestamp"] = "2026-01-01T10:05:00Z"
        second_proposal["payload"] = dict(
            second_proposal["payload"]
        )
        second_proposal["payload"]["target"] = (
            "synthetic://store/phase9-second"
        )
        revision = store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision
        store.append_event(
            self.registry,
            MissionEvent.from_dict(second_proposal),
            expected_revision=revision,
        )
        approvals = ApprovalService(
            store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )
        second = approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-PHASE9-SECOND",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="phase9-submit-second",
            principal_profile_id=SPECIALIST_ID,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA recursive_triggers = OFF")
            decided = connection.execute(
                """
                SELECT *
                FROM approval_queue
                WHERE approval_id = ?
                """,
                (decided_approval_id,),
            ).fetchone()
            pending = connection.execute(
                """
                SELECT *
                FROM approval_queue
                WHERE approval_id = ?
                """,
                (second.approval_id,),
            ).fetchone()
            assert decided is not None
            assert pending is not None
            self.assertIn(
                decided["status"],
                {"approved", "denied"},
            )
            self.assertEqual(pending["status"], "pending")
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "approval identity is write-once",
            ):
                connection.execute(
                    """
                    UPDATE OR REPLACE approval_queue
                    SET
                        approval_id = ?,
                        mission_id = ?,
                        proposal_id = ?
                    WHERE approval_id = ?
                    """,
                    (
                        decided["approval_id"],
                        decided["mission_id"],
                        decided["proposal_id"],
                        pending["approval_id"],
                    ),
                )
            connection.rollback()
            rows = connection.execute(
                """
                SELECT approval_id, proposal_id, status,
                       decision_event_id
                FROM approval_queue
                WHERE approval_id IN (?, ?)
                ORDER BY approval_id
                """,
                (
                    decided_approval_id,
                    second.approval_id,
                ),
            ).fetchall()
        self.assertEqual(len(rows), 2)
        by_id = {
            str(row["approval_id"]): row
            for row in rows
        }
        self.assertEqual(
            by_id[decided_approval_id]["decision_event_id"],
            decided["decision_event_id"],
        )
        self.assertEqual(
            by_id[second.approval_id]["proposal_id"],
            "EVT-PROP-PHASE9-SECOND",
        )
        self.assertEqual(
            by_id[second.approval_id]["status"],
            "pending",
        )

    def test_approved_decision_cannot_be_deleted_or_replaced(
        self,
    ) -> None:
        store, approval_id = self.approved_store()

        self._assert_decided_approval_cannot_be_deleted_or_replaced(
            approval_id
        )
        self._assert_update_or_replace_cannot_rebind_pending_identity(
            store,
            approval_id,
        )

        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_denied_decision_cannot_be_deleted_or_replaced(
        self,
    ) -> None:
        store, approval_id = self.denied_store()

        self._assert_decided_approval_cannot_be_deleted_or_replaced(
            approval_id
        )
        self._assert_update_or_replace_cannot_rebind_pending_identity(
            store,
            approval_id,
        )

        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

    def test_decision_requires_a_bound_baseline(self) -> None:
        store = self.initialized_store()
        _, approval_id = self.pending_approval(store)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "DROP TRIGGER "
                "mission_approval_decision_authentication_baseline_no_delete"
            )
            connection.execute(
                "DELETE FROM "
                "mission_approval_decision_authentication_baselines"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "lacks an authentication baseline",
            ):
                connection.execute(
                    """
                    UPDATE approval_queue
                    SET status = 'denied', version = 2
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                )

    def test_v5_migration_captures_decision_without_inventing_proof(
        self,
    ) -> None:
        store, approval_id = self.approved_store()
        self.downgrade_to_v5()
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )
        backup = self.directory / "before-v6.sqlite3"

        report = store.migrate(self.registry, backup)

        self.assertEqual(
            report.source_version,
            EVENT_AUTHENTICATION_SCHEMA_VERSION,
        )
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            baseline = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_decision_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            counts = (
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
            )
        assert baseline is not None
        raw = json.loads(str(baseline["baseline_json"]))
        self.assertEqual(
            (
                baseline["baseline_kind"],
                baseline["source_schema_version"],
                baseline["event_count"],
                baseline["historical_decision_count"],
            ),
            (
                "historical_pre_v6",
                EVENT_AUTHENTICATION_SCHEMA_VERSION,
                2,
                1,
            ),
        )
        self.assertEqual(counts, (0, 0))
        decision = raw["historical_decisions"][0]
        self.assertEqual(decision["approval_id"], approval_id)
        self.assertEqual(
            (
                decision["operation"],
                decision["approval_record"]["state"],
                decision["approval_record"]["version"],
            ),
            (
                PrincipalOperation.APPROVAL_APPROVE.value,
                "approved",
                2,
            ),
        )
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

    def test_policy_enrollment_rejects_post_baseline_decision(
        self,
    ) -> None:
        store = self.initialized_store()
        store.append_event(
            self.registry,
            MissionEvent.from_dict(proposal_data()),
            expected_revision=0,
        )
        self.downgrade_to_v4()
        store.migrate(
            self.registry,
            self.directory / "before-v6-policy.sqlite3",
        )
        approvals = ApprovalService(
            store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )
        record = approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="phase9-policy-submit",
            principal_profile_id=SPECIALIST_ID,
        )
        approvals.deny(
            record.approval_id,
            reason_code="scope",
            reason="Not approved",
            risk="Outside reviewed plan",
            decision_owner="phase9-control",
            idempotency_key="phase9-policy-deny",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
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
            allowed_profiles=[CONTROL_ID],
            allowed_operations=[
                PrincipalOperation.APPROVAL_APPROVE.value,
                PrincipalOperation.APPROVAL_DENY.value,
            ],
        )

        with self.assertRaisesRegex(
            StoreConflictError,
            "unauthenticated approval decision",
        ):
            trust.apply_policy(policy)

        self.assertFalse(trust.status().policy_applied)

    def test_baseline_tampering_is_detected(self) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = ?
                """,
                (
                    "mission_approval_decision_authentication_"
                    "baseline_immutable",
                ),
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER "
                "mission_approval_decision_authentication_"
                "baseline_immutable"
            )
            connection.execute(
                """
                UPDATE
                    mission_approval_decision_authentication_baselines
                SET historical_decision_root_hash = ?
                WHERE mission_id = ?
                """,
                ("sha256:" + "f" * 64, MISSION_ID),
            )
            connection.execute(str(trigger_sql))
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "approval decision authentication baseline",
        ):
            store.verify_store(self.registry)


if __name__ == "__main__":
    unittest.main()
