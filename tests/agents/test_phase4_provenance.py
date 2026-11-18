"""Integration tests for durable Phase 4 principal provenance."""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sunderkey.errors import StoreIntegrityError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import (
    SCOPE_REVOCATION_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    ASSERTION_KEY_ID,
    AUDIENCE,
    IDEMPOTENCY_KEY_HASH,
    MISSION_ID,
    OTHER_ASSERTION_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_KEY_ID,
    SCOPE_REFERENCE,
    CredentialFactory,
    b64url,
    operation_intent,
    public_bytes,
)
from .test_store import (
    REGISTRY_PATH,
    mission_data,
    remove_schema_v5_objects,
)

POLICY_VERSION = 7
POLICY_APPLIED_AT = "2026-07-30T10:05:00Z"
GRANT_ACCEPTED_AT = "2026-07-30T10:05:00Z"
ASSERTION_CONSUMED_AT = "2026-07-30T10:05:00Z"
ASSERTION_EXPIRES_AT = "2026-07-30T10:09:00Z"
EFFECT_KIND = "sunderkey.phase4-provenance.fixture.v1"
EFFECT_ID = "PHASE4-PROVENANCE-1"


class Phase4ProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "phase4-provenance.sqlite3"
        self.now = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)
        self.store = MissionStore(self.path, clock=lambda: self.now)
        self.store.initialize()

        raw_mission = mission_data()
        raw_mission.update(
            {
                "mission_id": MISSION_ID,
                "scope_reference": SCOPE_REFERENCE,
                "scope_document_hash": SCOPE_DOCUMENT_HASH,
            }
        )
        self.mission = MissionRequest.from_dict(raw_mission)
        self.stored_mission = self.store.create_mission(
            self.registry,
            self.mission,
        )

        self.factory = CredentialFactory()
        self.trust = TrustProvisioningService(self.store)
        status = self.trust.status()
        root_public_key = public_bytes(self.factory.root_private)
        self.trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
        )
        self.policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=status.store_id,
        )
        self.trust.apply_policy(self.policy)
        self.store_id = status.store_id

    def downgrade_to_phase4(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v5_objects(connection)
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

    def grant(self):
        constraints_hash = sha256_text(
            canonical_json(self.mission.to_dict()["constraints"])
        )
        return self.factory.grant(
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored_mission.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=constraints_hash,
            operations=[PrincipalOperation.APPROVAL_APPROVE.value],
            issued_at=POLICY_APPLIED_AT,
            not_before=POLICY_APPLIED_AT,
            expires_at="2026-07-30T10:30:00Z",
            policy_version=self.policy.policy_version,
        )

    def insert_grant(
        self,
        connection: sqlite3.Connection,
        grant,
        *,
        accepted_at: str = GRANT_ACCEPTED_AT,
    ) -> None:
        grant_json = canonical_json(grant.to_dict())
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
                :grant_hash,
                :grant_id,
                :grant_json,
                :issuer,
                :key_id,
                :key_hash,
                :audience,
                :store_id,
                :mission_id,
                :mission_context_hash,
                :scope_document_hash,
                :environment,
                :max_action_tier,
                :constraints_hash,
                :issued_at,
                :not_before,
                :expires_at,
                :accepted_at,
                NULL,
                NULL,
                :trust_policy_id,
                :trust_policy_version,
                :trust_policy_hash
            )
            """,
            {
                "grant_hash": grant.content_sha256,
                "grant_id": grant.grant_id,
                "grant_json": grant_json,
                "issuer": grant.issuer,
                "key_id": grant.key_id,
                "key_hash": self.policy.key(SCOPE_KEY_ID).content_sha256,
                "audience": grant.audience,
                "store_id": grant.store_id,
                "mission_id": grant.mission_id,
                "mission_context_hash": grant.mission_context_hash,
                "scope_document_hash": grant.scope_document_hash,
                "environment": grant.environment.value,
                "max_action_tier": grant.max_action_tier.value,
                "constraints_hash": grant.constraints_hash,
                "issued_at": grant.issued_at,
                "not_before": grant.not_before,
                "expires_at": grant.expires_at,
                "accepted_at": accepted_at,
                "trust_policy_id": grant.policy_id,
                "trust_policy_version": grant.policy_version,
                "trust_policy_hash": self.policy.content_sha256,
            },
        )

    def insert_assertion_use(
        self,
        connection: sqlite3.Connection,
        grant,
        *,
        policy=None,
        consumed_at: str = ASSERTION_CONSUMED_AT,
        issued_at: str = POLICY_APPLIED_AT,
        tamper_assertion_id: bool = False,
    ) -> str:
        selected_policy = policy or self.policy
        operation = PrincipalOperation.APPROVAL_APPROVE
        intent = operation_intent(operation)
        intent_json = canonical_json(intent)
        signed_intent_hash = compute_operation_intent_hash(
            operation,
            intent,
        )
        assertion = self.factory.assertion(
            grant=grant,
            policy_version=selected_policy.policy_version,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=operation,
            operation_intent_sha256=signed_intent_hash,
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=ASSERTION_EXPIRES_AT,
        )
        if tamper_assertion_id:
            assertion = replace(
                assertion,
                assertion_id=OTHER_ASSERTION_ID,
            )
        assertion_json = canonical_json(assertion.to_dict())
        assertion_hash = sha256_text(assertion_json)

        effect = {
            "effect_id": EFFECT_ID,
            "effect_kind": EFFECT_KIND,
            "payload": {
                "approval_id": intent["approval_id"],
                "fixture": "phase4-provenance",
            },
            "recorded_at": consumed_at,
            "schema_version": 1,
        }
        effect_json = canonical_json(effect)
        effect_hash = sha256_text(effect_json)
        effects_hash = principal_assertion_effects_hash([effect_hash])
        previous_hash = str(
            connection.execute(
                """
                SELECT baseline_root_hash
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
        )

        entry: dict[str, Any] = {
            "mission_id": MISSION_ID,
            "use_sequence": 1,
            "issuer": assertion.issuer,
            "assertion_id": assertion.assertion_id,
            "assertion_hash": assertion_hash,
            "subject": assertion.subject,
            "principal_profile_id": assertion.profile_id,
            "key_id": assertion.key_id,
            "key_hash": selected_policy.key(
                ASSERTION_KEY_ID
            ).content_sha256,
            "audience": assertion.audience,
            "store_id": assertion.store_id,
            "operation": assertion.operation.value,
            "operation_intent_json": intent_json,
            "signed_intent_hash": signed_intent_hash,
            "domain_request_hash": sha256_text(intent_json),
            "idempotency_key_hash": IDEMPOTENCY_KEY_HASH,
            "scope_grant_hash": grant.content_sha256,
            "trust_policy_id": selected_policy.policy_id,
            "trust_policy_version": selected_policy.policy_version,
            "trust_policy_hash": selected_policy.content_sha256,
            "issued_at": assertion.issued_at,
            "not_before": assertion.not_before,
            "expires_at": assertion.expires_at,
            "consumed_at": consumed_at,
            "effects_hash": effects_hash,
            "previous_hash": previous_hash,
        }
        entry_hash = principal_assertion_entry_hash(entry)

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
                :mission_id,
                :use_sequence,
                :issuer,
                :assertion_id,
                :assertion_json,
                :assertion_hash,
                :subject,
                :principal_profile_id,
                :key_id,
                :key_hash,
                :audience,
                :store_id,
                :operation,
                :operation_intent_json,
                :signed_intent_hash,
                :domain_request_hash,
                :idempotency_key_hash,
                :scope_grant_hash,
                :trust_policy_id,
                :trust_policy_version,
                :trust_policy_hash,
                :issued_at,
                :not_before,
                :expires_at,
                :consumed_at,
                :effects_hash,
                :previous_hash,
                :entry_hash
            )
            """,
            {
                **entry,
                "assertion_json": assertion_json,
                "entry_hash": entry_hash,
            },
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
            ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (
                assertion.issuer,
                assertion.assertion_id,
                MISSION_ID,
                EFFECT_KIND,
                EFFECT_ID,
                effect_json,
                effect_hash,
                consumed_at,
            ),
        )
        connection.execute(
            """
            UPDATE mission_principal_ledgers
            SET
                head_hash = ?,
                assertion_count = 1,
                effect_count = 1,
                updated_at = ?
            WHERE mission_id = ?
            """,
            (entry_hash, consumed_at, MISSION_ID),
        )
        return entry_hash

    def test_complete_signed_provenance_chain_verifies(self) -> None:
        grant = self.grant()
        self.downgrade_to_phase4()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            self.insert_grant(connection, grant)
            entry_hash = self.insert_assertion_use(connection, grant)
            connection.commit()
            ledger = connection.execute(
                """
                SELECT head_hash, assertion_count, effect_count
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()

        self.assertEqual(ledger, (entry_hash, 1, 1))
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_tampered_signed_assertion_is_detected(self) -> None:
        grant = self.grant()
        self.downgrade_to_phase4()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            self.insert_grant(connection, grant)
            self.insert_assertion_use(
                connection,
                grant,
                tamper_assertion_id=True,
            )
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "authority chain is invalid",
        ):
            self.store.verify_store(self.registry)

    def test_stale_policy_assertion_use_is_detected(self) -> None:
        grant = self.grant()
        accepted_at = "2026-07-30T10:05:30Z"
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            self.insert_grant(
                connection,
                grant,
                accepted_at=accepted_at,
            )
            connection.commit()

        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        newer_policy = self.factory.policy(
            policy_version=POLICY_VERSION + 1,
            store_id=self.store_id,
        )
        self.trust.apply_policy(newer_policy)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )
        self.downgrade_to_phase4()

        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            self.insert_assertion_use(
                connection,
                grant,
                policy=self.policy,
                consumed_at="2026-07-30T10:06:00Z",
                issued_at=accepted_at,
            )
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "authority chain is inconsistent",
        ):
            self.store.verify_store(self.registry)

    def test_legacy_scope_revocation_is_frozen_and_grant_not_deletable(
        self,
    ) -> None:
        grant = self.grant()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            self.insert_grant(connection, grant)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "legacy scope grant revocation state is frozen",
            ):
                connection.execute(
                    """
                    UPDATE mission_scope_grants
                    SET revoked_at = ?, revocation_reason = ?
                    WHERE grant_hash = ?
                    """,
                    (
                        "2026-07-30T10:06:00Z",
                        "Operator withdrew scope",
                        grant.content_sha256,
                    ),
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM mission_scope_grants
                    WHERE grant_hash = ?
                    """,
                    (grant.content_sha256,),
                )
            connection.commit()

        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )


if __name__ == "__main__":
    unittest.main()
