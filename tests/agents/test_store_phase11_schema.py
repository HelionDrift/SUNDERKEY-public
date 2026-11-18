"""Schema v8 authenticated approval revocation provenance coverage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest import mock

from sunderkey.approvals import ApprovalService
from sunderkey.authenticated_approval_revocations import (
    AuthenticatedApprovalRevocationService,
)
from sunderkey.errors import StoreConflictError, StoreIntegrityError
from sunderkey.events import MissionEvent
from sunderkey.identity import (
    PrincipalOperation,
    ScopeGrant,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import (
    APPROVAL_REVOCATION_AUTHENTICATION_SCHEMA_VERSION,
    APPROVAL_REVOKE_EFFECT_KIND,
    APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST_V7,
    EXPECTED_SCHEMA_MANIFEST_V8,
    SCHEMA_VERSION,
    MissionStore,
    VerificationReport,
    _schema_manifest,
    approval_revocation_authentication_baseline_root_hash,
    approval_revocation_history_root_hash,
    canonical_json,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    AUDIENCE,
    NOW,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    SUBJECT,
    ZERO_SIGNATURE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import (
    CONTROL_ID,
    MISSION_ID,
    REGISTRY_PATH,
    SPECIALIST_ID,
    mission_data,
    proposal_data,
    remove_schema_v5_objects,
    remove_schema_v9_objects,
)

V8_TRIGGER_NAMES = (
    "mission_approval_revocation_authentication_baseline_insert_once",
    "mission_approval_revocation_authentication_baseline_snapshot_guard",
    "mission_approval_revocation_authentication_baseline_immutable",
    "mission_approval_revocation_authentication_baseline_no_delete",
    "approval_revocation_requires_authentication_baseline",
    "approval_revocation_insert_once",
    "approval_revocation_immutable",
    "approval_revocation_no_delete",
    "approval_revocation_insert_guard",
    "approval_revocation_transition_guard",
    "principal_approval_revocation_use_guard",
    "principal_approval_revocation_effect_guard",
)
V8_INDEX_NAMES = (
    "principal_approval_revocation_request_identity",
    "principal_approval_revocation_idempotency_identity",
)


class Phase11StoreSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.now = NOW
        raw_mission = mission_data()
        raw_mission.update(
            {
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

    @staticmethod
    def remove_v8_objects(
        connection: sqlite3.Connection,
    ) -> None:
        remove_schema_v9_objects(connection)
        for trigger_name in V8_TRIGGER_NAMES:
            connection.execute(
                f"DROP TRIGGER IF EXISTS {trigger_name}"
            )
        for index_name in V8_INDEX_NAMES:
            connection.execute(
                f"DROP INDEX IF EXISTS {index_name}"
            )
        connection.execute(
            "DROP TABLE IF EXISTS "
            "mission_approval_revocation_authentication_baselines"
        )

    def downgrade_to_v7(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            self.remove_v8_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (
                    str(
                        APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION
                    ),
                ),
            )
            connection.execute(
                "PRAGMA user_version = "
                f"{APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION}"
            )
            connection.commit()

    def downgrade_to_v4(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            self.remove_v8_objects(connection)
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

    def append_proposal(self, store: MissionStore) -> str:
        raw = proposal_data()
        raw["timestamp"] = "2026-07-30T10:05:00Z"
        raw["payload"]["target"] = "synthetic://phase11/revocation"
        proposal = MissionEvent.from_dict(raw)
        store.append_event(
            self.registry,
            proposal,
            expected_revision=0,
        )
        return proposal.event_id

    def approved(
        self,
        store: MissionStore,
    ) -> tuple[ApprovalService, str]:
        proposal_id = self.append_proposal(store)
        approvals = ApprovalService(
            store,
            self.registry,
            clock=lambda: self.now,
        )
        pending = approvals.submit(
            mission_id=MISSION_ID,
            proposal_id=proposal_id,
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-07-30T10:30:00Z",
            idempotency_key="phase11-submit",
            principal_profile_id=SPECIALIST_ID,
        )
        approvals.approve(
            pending.approval_id,
            authority="phase11-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-07-30T11:00:00Z",
            idempotency_key="phase11-approve",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        return approvals, pending.approval_id

    @staticmethod
    def revoke(
        approvals: ApprovalService,
        approval_id: str,
    ):
        return approvals.revoke(
            approval_id,
            reason_code="authorization_withdrawn",
            reason="The authorization was withdrawn",
            risk="Execution would exceed current approval",
            decision_owner="phase11-control",
            idempotency_key="phase11-revoke",
            expected_version=2,
            principal_profile_id=CONTROL_ID,
        )

    def test_fresh_v8_mission_has_bound_empty_baseline(self) -> None:
        store = self.initialized_store()
        mission = store.get_mission(self.registry, MISSION_ID)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_revocation_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert row is not None
        baseline = json.loads(str(row["baseline_json"]))
        expected = {
            "schema": (
                "sunderkey.mission-approval-revocation-"
                "authentication-baseline.v1"
            ),
            "baseline_kind": "empty",
            "provenance_status": (
                "no_pre_v8_events_or_revocations"
            ),
            "mission_id": MISSION_ID,
            "mission_context_hash": mission.context_hash,
            "source_schema_version": (
                APPROVAL_REVOCATION_AUTHENTICATION_SCHEMA_VERSION
            ),
            "event_count": 0,
            "event_head_hash": mission.context_hash,
            "historical_revocations": [],
            "historical_revocation_root_hash": (
                approval_revocation_history_root_hash(())
            ),
        }
        baseline_hash = sha256_text(canonical_json(expected))
        self.assertEqual(baseline, expected)
        self.assertEqual(row["baseline_hash"], baseline_hash)
        self.assertEqual(
            row["baseline_root_hash"],
            approval_revocation_authentication_baseline_root_hash(
                MISSION_ID,
                baseline_hash,
            ),
        )
        self.assertEqual(row["historical_revocation_count"], 0)
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_v8_objects_preserve_the_exact_v7_manifest(self) -> None:
        self.assertEqual(
            APPROVAL_REVOCATION_AUTHENTICATION_SCHEMA_VERSION,
            APPROVAL_REVOCATION_AUTHENTICATION_SCHEMA_VERSION,
        )
        v7_names = {
            item[1]
            for item in EXPECTED_SCHEMA_MANIFEST_V7
        }
        v8_names = {
            item[1]
            for item in EXPECTED_SCHEMA_MANIFEST_V8
        }
        self.assertNotIn(
            "mission_approval_revocation_authentication_baselines",
            v7_names,
        )
        self.assertIn(
            "mission_approval_revocation_authentication_baselines",
            v8_names,
        )
        self.assertTrue(v7_names < v8_names)
        self.initialized_store()
        self.downgrade_to_v7()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V7,
            )

    def test_v7_event_prefix_without_revocations_is_historical(self) -> None:
        store = self.initialized_store()
        self.append_proposal(store)
        self.downgrade_to_v7()
        report = store.migrate(
            self.registry,
            self.directory / "before-v8-event-prefix.sqlite3",
        )
        self.assertEqual(
            report.source_version,
            APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_revocation_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert row is not None
        baseline = json.loads(str(row["baseline_json"]))
        self.assertEqual(row["baseline_kind"], "historical_pre_v8")
        self.assertEqual(row["event_count"], 1)
        self.assertEqual(row["historical_revocation_count"], 0)
        self.assertEqual(
            baseline["provenance_status"],
            "historical_event_prefix_no_revocations",
        )
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_v7_migration_grandfathers_direct_revocation(self) -> None:
        store = self.initialized_store()
        approvals, approval_id = self.approved(store)
        revocation = self.revoke(approvals, approval_id)
        self.downgrade_to_v7()
        store.migrate(
            self.registry,
            self.directory / "before-v8-revocation.sqlite3",
        )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_revocation_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert row is not None
        baseline = json.loads(str(row["baseline_json"]))
        historical = baseline["historical_revocations"]
        self.assertEqual(row["baseline_kind"], "historical_pre_v8")
        self.assertEqual(row["event_count"], 3)
        self.assertEqual(row["historical_revocation_count"], 1)
        self.assertEqual(len(historical), 1)
        self.assertEqual(historical[0]["approval_id"], approval_id)
        self.assertEqual(
            historical[0]["revocation_record"],
            revocation.to_dict(),
        )
        self.assertEqual(
            historical[0]["operation"],
            APPROVAL_REVOKE_EFFECT_KIND,
        )
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_baseline_and_revocation_resist_conflict_algorithms(self) -> None:
        store = self.initialized_store()
        approvals, approval_id = self.approved(store)
        self.revoke(approvals, approval_id)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA recursive_triggers = OFF")
            baseline = connection.execute(
                """
                SELECT *
                FROM
                    mission_approval_revocation_authentication_baselines
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            revocation = connection.execute(
                """
                SELECT *
                FROM approval_revocations
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()
            assert baseline is not None
            assert revocation is not None
            baseline_columns = tuple(baseline.keys())
            baseline_replace = (
                "INSERT OR REPLACE INTO "
                "mission_approval_revocation_authentication_baselines ("
                + ", ".join(baseline_columns)
                + ") VALUES ("
                + ", ".join("?" for _ in baseline_columns)
                + ")"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "baseline is insert-only",
            ):
                connection.execute(
                    baseline_replace,
                    tuple(
                        baseline[column]
                        for column in baseline_columns
                    ),
                )
            connection.rollback()
            baseline_upsert = (
                "INSERT INTO "
                "mission_approval_revocation_authentication_baselines ("
                + ", ".join(baseline_columns)
                + ") VALUES ("
                + ", ".join("?" for _ in baseline_columns)
                + ") ON CONFLICT(mission_id) DO UPDATE SET "
                "created_at = excluded.created_at"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "baseline is insert-only",
            ):
                connection.execute(
                    baseline_upsert,
                    tuple(
                        baseline[column]
                        for column in baseline_columns
                    ),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "baseline is immutable",
            ):
                connection.execute(
                    """
                    UPDATE OR REPLACE
                        mission_approval_revocation_authentication_baselines
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
                        mission_approval_revocation_authentication_baselines
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                )
            connection.rollback()
            revocation_columns = tuple(revocation.keys())
            revocation_replace = (
                "INSERT OR REPLACE INTO approval_revocations ("
                + ", ".join(revocation_columns)
                + ") VALUES ("
                + ", ".join("?" for _ in revocation_columns)
                + ")"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                (
                    "identity is insert-only|"
                    "revocation row is inconsistent"
                ),
            ):
                connection.execute(
                    revocation_replace,
                    tuple(
                        revocation[column]
                        for column in revocation_columns
                    ),
                )
            connection.rollback()
            revocation_upsert = (
                "INSERT INTO approval_revocations ("
                + ", ".join(revocation_columns)
                + ") VALUES ("
                + ", ".join("?" for _ in revocation_columns)
                + ") ON CONFLICT(approval_id) DO UPDATE SET "
                "reason = excluded.reason"
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                (
                    "identity is insert-only|"
                    "revocation row is inconsistent"
                ),
            ):
                connection.execute(
                    revocation_upsert,
                    tuple(
                        revocation[column]
                        for column in revocation_columns
                    ),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "revocation is immutable",
            ):
                connection.execute(
                    """
                    UPDATE OR REPLACE approval_revocations
                    SET reason = reason
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "revocation cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM approval_revocations
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                )
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_global_counts_include_revocation_baselines(self) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "DROP TRIGGER "
                "mission_approval_revocation_authentication_"
                "baseline_no_delete"
            )
            connection.execute(
                "DELETE FROM "
                "mission_approval_revocation_authentication_baselines"
            )
            connection.commit()
        with (
            mock.patch.object(
                store,
                "_require_schema",
                return_value=SCHEMA_VERSION,
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

    def test_pre_v8_revoke_provenance_cannot_be_promoted(self) -> None:
        store = self.initialized_store()
        self.downgrade_to_v7()
        hash_one = sha256_text("one")
        hash_two = sha256_text("two")
        hash_three = sha256_text("three")
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            identity = connection.execute(
                "SELECT store_id FROM store_identity"
            ).fetchone()
            mission = connection.execute(
                """
                SELECT context_hash
                FROM missions
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assert identity is not None
            assert mission is not None
            connection.execute(
                """
                INSERT INTO mission_scope_grants(
                    grant_hash,
                    grant_id,
                    grant_json,
                    issuer,
                    key_id,
                    key_hash,
                    audience,
                    store_id,
                    mission_id,
                    mission_context_hash,
                    scope_document_hash,
                    environment,
                    max_action_tier,
                    constraints_hash,
                    issued_at,
                    not_before,
                    expires_at,
                    accepted_at,
                    revoked_at,
                    revocation_reason,
                    trust_policy_id,
                    trust_policy_version,
                    trust_policy_hash
                ) VALUES (
                    ?, 'SGR-PRE-V8', '{}', 'issuer', 'key', ?,
                    'audience', ?, ?, ?, ?, 'test', 'R2', ?,
                    '2026-07-30T10:00:00Z',
                    '2026-07-30T10:00:00Z',
                    '2026-07-30T11:00:00Z',
                    '2026-07-30T10:00:00Z',
                    NULL, NULL, 'policy', 1, ?
                )
                """,
                (
                    hash_one,
                    hash_two,
                    identity["store_id"],
                    MISSION_ID,
                    mission["context_hash"],
                    hash_two,
                    hash_three,
                    hash_three,
                ),
            )
            connection.execute(
                """
                INSERT INTO principal_assertion_uses(
                    mission_id,
                    use_sequence,
                    issuer,
                    assertion_id,
                    assertion_json,
                    assertion_hash,
                    subject,
                    principal_profile_id,
                    key_id,
                    key_hash,
                    audience,
                    store_id,
                    operation,
                    operation_intent_json,
                    signed_intent_hash,
                    domain_request_hash,
                    idempotency_key_hash,
                    scope_grant_hash,
                    trust_policy_id,
                    trust_policy_version,
                    trust_policy_hash,
                    issued_at,
                    not_before,
                    expires_at,
                    consumed_at,
                    effects_hash,
                    previous_hash,
                    entry_hash
                ) VALUES (
                    ?, 1, 'issuer', 'PAS-PRE-V8', '{}', ?,
                    'subject', ?, 'key', ?, 'audience', ?, ?, '{}',
                    ?, ?, ?, ?, 'policy', 1, ?,
                    '2026-07-30T10:00:00Z',
                    '2026-07-30T10:00:00Z',
                    '2026-07-30T10:05:00Z',
                    '2026-07-30T10:01:00Z',
                    ?, ?, ?
                )
                """,
                (
                    MISSION_ID,
                    hash_one,
                    CONTROL_ID,
                    hash_two,
                    identity["store_id"],
                    APPROVAL_REVOKE_EFFECT_KIND,
                    hash_one,
                    hash_two,
                    hash_three,
                    hash_one,
                    hash_three,
                    hash_one,
                    hash_two,
                    hash_three,
                ),
            )
            connection.execute(
                """
                INSERT INTO principal_assertion_effects(
                    issuer,
                    assertion_id,
                    mission_id,
                    effect_index,
                    effect_kind,
                    effect_id,
                    effect_json,
                    effect_hash,
                    recorded_at
                ) VALUES (
                    'issuer', 'PAS-PRE-V8', ?, 1, ?, 'effect',
                    '{}', ?, '2026-07-30T10:01:00Z'
                )
                """,
                (
                    MISSION_ID,
                    APPROVAL_REVOKE_EFFECT_KIND,
                    hash_one,
                ),
            )
            connection.commit()
        with (
            mock.patch.object(
                MissionStore,
                "verify_store",
                return_value=VerificationReport(
                    status="valid",
                    mission_count=1,
                    event_count=0,
                ),
            ),
            mock.patch.object(
                MissionStore,
                "_verify_connection",
                return_value=(1, 0),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "Pre-v8 approval-revocation provenance cannot be promoted",
            ),
        ):
            store.migrate(
                self.registry,
                self.directory / "before-v8-undefined.sqlite3",
            )
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                APPROVAL_SUBMISSION_AUTHENTICATION_SCHEMA_VERSION,
            )

    def test_authenticated_revocation_reconciles_exact_effect(self) -> None:
        store = self.initialized_store()
        _, approval_id = self.approved(store)
        self.downgrade_to_v4()
        store.migrate(
            self.registry,
            self.directory / "before-v8-authenticated.sqlite3",
        )
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
        policy = factory.policy(
            store_id=store_id,
            allowed_profiles=[CONTROL_ID],
            allowed_subjects=[SUBJECT],
            allowed_operations=[
                PrincipalOperation.APPROVAL_REVOKE.value,
            ],
        )
        trust.apply_policy(policy)
        constraints_hash = sha256_text(
            canonical_json(self.mission.to_dict()["constraints"])
        )
        raw_grant = factory.grant(
            profile_id=CONTROL_ID,
            subject=SUBJECT,
            audience=AUDIENCE,
            store_id=store_id,
            mission_id=MISSION_ID,
            mission_context_hash=store.get_mission(
                self.registry,
                MISSION_ID,
            ).context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=constraints_hash,
            operations=[
                PrincipalOperation.APPROVAL_REVOKE.value,
            ],
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T11:00:00Z",
        ).to_dict()
        raw_grant["grant_id"] = (
            "SGR-11000000000000000000000000000001"
        )
        raw_grant["signature"] = ZERO_SIGNATURE
        unsigned_grant = ScopeGrant.from_dict(raw_grant)
        grant = replace(
            unsigned_grant,
            signature=b64url(
                factory.scope_private.sign(
                    unsigned_grant.signing_bytes()
                )
            ),
        )
        ScopeGrantAcceptanceService(
            store,
            self.registry,
        ).accept(grant)
        arguments = {
            "reason_code": "authorization_withdrawn",
            "reason": "The authorization was withdrawn",
            "risk": "Execution would exceed current approval",
            "decision_owner": "phase11-control",
            "idempotency_key": "phase11-authenticated-revoke",
            "expected_version": 2,
        }
        intent = {
            "approval_id": approval_id,
            "decision_owner": arguments["decision_owner"],
            "expected_version": arguments["expected_version"],
            "idempotency_key_sha256": sha256_text(
                arguments["idempotency_key"]
            ),
            "principal_profile_id": CONTROL_ID,
            "reason": arguments["reason"],
            "reason_code": arguments["reason_code"],
            "risk": arguments["risk"],
        }
        assertion = factory.assertion(
            grant=grant,
            assertion_id="PAS-11000000000000000000000000000001",
            scope_grant_id=grant.grant_id,
            subject=grant.subject,
            profile_id=grant.profile_id,
            audience=AUDIENCE,
            store_id=store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.APPROVAL_REVOKE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.APPROVAL_REVOKE,
                intent,
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        receipt = AuthenticatedApprovalRevocationService(
            store,
            self.registry,
            clock=lambda: self.now,
        ).revoke(
            assertion,
            approval_id,
            **arguments,
        )
        self.assertEqual(receipt.approval.state.value, "revoked")
        self.assertEqual(receipt.approval.version, 3)
        self.assertEqual(
            receipt.revocation.revoked_at,
            receipt.consumed_at,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            effect = connection.execute(
                """
                SELECT *
                FROM principal_assertion_effects
                WHERE issuer = ? AND assertion_id = ?
                """,
                (assertion.issuer, assertion.assertion_id),
            ).fetchone()
        assert effect is not None
        raw_effect = json.loads(str(effect["effect_json"]))
        self.assertEqual(
            set(raw_effect["payload"]),
            {
                "approval_id",
                "approval_record",
                "revocation_record",
                "revocation_event",
                "append_receipt",
                "revocation_request_sha256",
                "idempotency_key_sha256",
                "expected_approval_version",
                "pre_approval_version",
                "pre_approval_state",
                "final_approval_version",
                "final_approval_state",
                "pre_mission_revision",
                "pre_mission_head_hash",
                "final_mission_revision",
                "final_mission_head_hash",
                "event_sequence",
                "event_previous_hash",
                "event_entry_hash",
                "event_stored_at",
            },
        )
        self.assertEqual(effect["effect_kind"], APPROVAL_REVOKE_EFFECT_KIND)
        self.assertEqual(effect["recorded_at"], receipt.consumed_at)
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_policy_enrollment_rejects_post_baseline_revocation(self) -> None:
        store = self.initialized_store()
        approvals, approval_id = self.approved(store)
        self.downgrade_to_v4()
        store.migrate(
            self.registry,
            self.directory / "before-v8-policy.sqlite3",
        )
        self.revoke(approvals, approval_id)
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
        policy = factory.policy(
            store_id=store_id,
            allowed_profiles=[CONTROL_ID],
            allowed_operations=[
                PrincipalOperation.APPROVAL_REVOKE.value,
            ],
        )
        with self.assertRaisesRegex(
            StoreConflictError,
            "unauthenticated approval revocation",
        ):
            trust.apply_policy(policy)
        self.assertFalse(trust.status().policy_applied)

    def test_policy_enrollment_rejects_corrupted_revocation_baseline(
        self,
    ) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            trigger = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = ?
                """,
                (
                    "mission_approval_revocation_authentication_"
                    "baseline_immutable",
                ),
            ).fetchone()
            assert trigger is not None
            trigger_sql = str(trigger[0])
            connection.execute(
                "DROP TRIGGER "
                "mission_approval_revocation_authentication_"
                "baseline_immutable"
            )
            connection.execute(
                """
                UPDATE
                    mission_approval_revocation_authentication_baselines
                SET baseline_hash = ?
                WHERE mission_id = ?
                """,
                (sha256_text("corrupted baseline"), MISSION_ID),
            )
            connection.execute(trigger_sql)
            connection.commit()

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
        policy = factory.policy(
            store_id=store_id,
            allowed_profiles=[CONTROL_ID],
            allowed_operations=[
                PrincipalOperation.APPROVAL_REVOKE.value,
            ],
        )
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "approval revocation authentication baseline",
        ):
            trust.apply_policy(policy)
        self.assertFalse(trust.status().policy_applied)


if __name__ == "__main__":
    unittest.main()
