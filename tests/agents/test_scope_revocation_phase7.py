"""Service coverage for signed scope-grant revocation acceptance."""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from sunderkey.authenticated import AuthenticatedMissionControlService
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrant,
    ScopeGrantRevocation,
    TrustKeyState,
    TrustKeyUse,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.mission_control import MissionControlService
from sunderkey.registry import load_registry
from sunderkey.scope import (
    ScopeGrantAcceptanceService,
    ScopeGrantRevocationAcceptanceService,
)
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    AUDIENCE,
    OTHER_GRANT_ID,
    PROFILE_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    SUBJECT,
    ZERO_SIGNATURE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, mission_data

MISSION_ID = "MISSION-SCOPE-REVOCATION"
POLICY_VERSION = 7
REVOCATION_KEY_ID = "REVOCATION-2026"
REVOCATION_ISSUER = "scope-revocation-authority"
REVOCATION_ID = "SRV-0123456789ABCDEF0123456789ABCDEF"


class ScopeGrantRevocationPhase7Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "scope-revocation.sqlite3"
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
        self.revocation_private = Ed25519PrivateKey.generate()
        self.trust = TrustProvisioningService(self.store)
        self.store_id = self.trust.status().store_id
        root_public_key = public_bytes(self.factory.root_private)
        self.trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
        )
        self.policy = self._policy(POLICY_VERSION)
        self.trust.apply_policy(self.policy)

        constraints_hash = sha256_text(
            canonical_json(self.mission.to_dict()["constraints"])
        )
        self.grant = self.factory.grant(
            profile_id=PROFILE_ID,
            subject=SUBJECT,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored_mission.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=constraints_hash,
            operations=[PrincipalOperation.MISSION_STOP.value],
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:30:00Z",
            policy_version=POLICY_VERSION,
        )
        ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.grant)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.service = ScopeGrantRevocationAcceptanceService(
            self.store,
            self.registry,
        )

    def _policy(self, version: int) -> PrincipalTrustPolicy:
        raw = self.factory.policy(
            policy_version=version,
            store_id=self.store_id,
            allowed_profiles=[PROFILE_ID],
            allowed_subjects=[SUBJECT],
            allowed_operations=[
                PrincipalOperation.MISSION_STOP.value
            ],
        ).to_dict()
        raw["signature"] = ZERO_SIGNATURE
        raw["keys"].append(
            {
                "key_id": REVOCATION_KEY_ID,
                "issuer": REVOCATION_ISSUER,
                "public_key": b64url(
                    public_bytes(self.revocation_private)
                ),
                "key_use": (
                    TrustKeyUse.SCOPE_GRANT_REVOCATION.value
                ),
                "state": TrustKeyState.ACTIVE.value,
                "not_before": "2026-07-30T09:00:00Z",
                "not_after": "2026-07-30T12:00:00Z",
                "retire_at": None,
                "allowed_profiles": [PROFILE_ID],
                "allowed_subjects": [SUBJECT],
                "allowed_operations": [
                    PrincipalOperation.MISSION_STOP.value
                ],
            }
        )
        raw["keys"].sort(key=lambda item: str(item["key_id"]))
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.factory.root_private.sign(
                    unsigned.signing_bytes()
                )
            ),
        )

    def revocation(self, **changes: Any) -> ScopeGrantRevocation:
        raw: dict[str, Any] = {
            "schema_version": 1,
            "revocation_id": REVOCATION_ID,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "issuer": REVOCATION_ISSUER,
            "key_id": REVOCATION_KEY_ID,
            "audience": AUDIENCE,
            "store_id": self.store_id,
            "mission_id": MISSION_ID,
            "mission_context_hash": self.stored_mission.context_hash,
            "scope_grant_issuer": self.grant.issuer,
            "scope_grant_id": self.grant.grant_id,
            "scope_grant_sha256": self.grant.content_sha256,
            "scope_grant_subject": self.grant.subject,
            "scope_grant_profile_id": self.grant.profile_id,
            "reason_code": "authorization_withdrawn",
            "reason": "The external authority withdrew this grant.",
            "issued_at": "2026-07-30T10:06:00Z",
            "not_before": "2026-07-30T10:06:00Z",
            "expires_at": "2026-07-30T10:10:00Z",
            "signature": ZERO_SIGNATURE,
        }
        raw.update(changes)
        unsigned = ScopeGrantRevocation.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.revocation_private.sign(
                    unsigned.signing_bytes()
                )
            ),
        )

    def second_grant(self) -> ScopeGrant:
        raw = self.grant.to_dict()
        raw["grant_id"] = OTHER_GRANT_ID
        raw["signature"] = ZERO_SIGNATURE
        unsigned = ScopeGrant.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.factory.scope_private.sign(
                    unsigned.signing_bytes()
                )
            ),
        )

    def stop_contract(self):
        arguments = {
            "reason_code": "operator_request",
            "reason": "Operator requested an authenticated stop",
            "risk": "Continued activity is outside the current decision",
            "decision_owner": "range-control",
            "idempotency_key": "phase7-revoked-stop",
            "expected_version": 1,
        }
        intent_hash = compute_operation_intent_hash(
            PrincipalOperation.MISSION_STOP,
            {
                "decision_owner": arguments["decision_owner"],
                "expected_version": arguments["expected_version"],
                "idempotency_key_sha256": sha256_text(
                    str(arguments["idempotency_key"])
                ),
                "mission_id": MISSION_ID,
                "principal_profile_id": PROFILE_ID,
                "reason": arguments["reason"],
                "reason_code": arguments["reason_code"],
                "risk": arguments["risk"],
            },
        )
        assertion = self.factory.assertion(
            grant=self.grant,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=self.grant.subject,
            profile_id=self.grant.profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.MISSION_STOP,
            operation_intent_sha256=intent_hash,
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        return assertion, arguments

    def row_count(self) -> int:
        with closing(sqlite3.connect(self.path)) as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) "
                    "FROM mission_scope_grant_revocations"
                ).fetchone()[0]
            )

    def remove_revocation_row_preserving_schema_manifest(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'mission_scope_grant_revocation_no_delete'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER mission_scope_grant_revocation_no_delete"
            )
            connection.execute(
                "DELETE FROM mission_scope_grant_revocations"
            )
            connection.execute(str(trigger_sql))
            connection.commit()

    def test_accepts_signed_revocation_without_legacy_projection(self) -> None:
        revocation = self.revocation()

        accepted = self.service.accept(revocation)

        self.assertFalse(accepted.idempotent)
        self.assertEqual(accepted.revocation, revocation)
        self.assertEqual(
            accepted.revocation_sha256,
            revocation.content_sha256,
        )
        self.assertEqual(
            accepted.target_grant_sha256,
            self.grant.content_sha256,
        )
        self.assertEqual(
            accepted.accepted_at,
            "2026-07-30T10:06:00Z",
        )
        self.assertEqual(self.row_count(), 1)
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                """
                SELECT revoked_at, revocation_reason
                FROM mission_scope_grants
                WHERE grant_hash = ?
                """,
                (self.grant.content_sha256,),
            ).fetchone()
        self.assertEqual(row, (None, None))
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_signed_revocation_unique_replace_is_blocked_without_recursive_triggers(
        self,
    ) -> None:
        second_grant = self.second_grant()
        ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        ).accept(second_grant)
        self.service.accept(self.revocation())

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA recursive_triggers = OFF")
            row = connection.execute(
                """
                SELECT * FROM mission_scope_grant_revocations
                WHERE scope_grant_hash = ?
                """,
                (self.grant.content_sha256,),
            ).fetchone()
            assert row is not None
            columns = tuple(row.keys())
            replacement = dict(row)
            replacement.update(
                {
                    "revocation_sequence": 2,
                    "revocation_hash": "sha256:" + "1" * 64,
                    "revocation_id": (
                        "SRV-FEDCBA9876543210FEDCBA9876543210"
                    ),
                    "revocation_json": "{}",
                    "scope_grant_hash": second_grant.content_sha256,
                    "scope_grant_issuer": second_grant.issuer,
                    "scope_grant_id": second_grant.grant_id,
                    "previous_hash": row["entry_hash"],
                }
            )
            statement = (
                "INSERT OR REPLACE INTO "
                "mission_scope_grant_revocations ("
                + ", ".join(columns)
                + ") VALUES ("
                + ", ".join("?" for _ in columns)
                + ")"
            )

            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "scope grant revocation identity is insert-only",
            ):
                connection.execute(
                    statement,
                    tuple(
                        replacement[column]
                        for column in columns
                    ),
                )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM mission_scope_grant_revocations
                    """
                ).fetchone()[0],
                1,
            )

    def test_same_second_principal_use_returns_retryable_conflict(
        self,
    ) -> None:
        assertion, arguments = self.stop_contract()
        AuthenticatedMissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).stop(assertion, MISSION_ID, **arguments)

        with self.assertRaisesRegex(
            StoreConflictError,
            "strictly later than the latest durable principal use",
        ):
            self.service.accept(self.revocation())
        self.assertEqual(self.row_count(), 0)

        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        accepted = self.service.accept(self.revocation())

        self.assertEqual(accepted.accepted_at, "2026-07-30T10:07:00Z")
        self.assertEqual(self.row_count(), 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_exact_replay_is_read_only_after_policy_advancement(self) -> None:
        revocation = self.revocation()
        first = self.service.accept(revocation)
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        self.policy = self._policy(POLICY_VERSION + 1)
        self.trust.apply_policy(self.policy)

        replay = self.service.accept(revocation)

        self.assertFalse(first.idempotent)
        self.assertTrue(replay.idempotent)
        self.assertEqual(replay.accepted_at, first.accepted_at)
        self.assertEqual(
            replay.revocation_sha256,
            first.revocation_sha256,
        )
        self.assertEqual(self.row_count(), 1)

    def test_altered_replay_and_second_target_revocation_conflict(
        self,
    ) -> None:
        first = self.revocation()
        self.service.accept(first)

        with self.assertRaisesRegex(
            StoreConflictError,
            "different content",
        ):
            self.service.accept(
                self.revocation(
                    reason="A different signed reason.",
                )
            )

        with self.assertRaisesRegex(
            StoreConflictError,
            "already has a durable revocation",
        ):
            self.service.accept(
                self.revocation(
                    revocation_id=(
                        "SRV-FEDCBA9876543210FEDCBA9876543210"
                    ),
                )
            )
        self.assertEqual(self.row_count(), 1)

    def test_invalid_signature_rolls_back_without_revocation(self) -> None:
        invalid = replace(
            self.revocation(),
            reason="Changed after signing.",
        )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "signature verification failed",
        ):
            self.service.accept(invalid)

        self.assertEqual(self.row_count(), 0)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_revocation_blocks_grant_reacceptance_and_authenticated_use(
        self,
    ) -> None:
        assertion, stop_arguments = self.stop_contract()
        self.service.accept(self.revocation())

        with self.assertRaisesRegex(
            StoreConflictError,
            "Revoked scope grant",
        ):
            ScopeGrantAcceptanceService(
                self.store,
                self.registry,
            ).accept(self.grant)

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "Scope grant is revoked",
        ):
            AuthenticatedMissionControlService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            ).stop(
                assertion,
                MISSION_ID,
                **stop_arguments,
            )

        with closing(sqlite3.connect(self.path)) as connection:
            state = connection.execute(
                """
                SELECT state, version FROM mission_controls
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assertion_count = connection.execute(
                "SELECT COUNT(*) FROM principal_assertion_uses"
            ).fetchone()[0]
        self.assertEqual(state, ("active", 1))
        self.assertEqual(assertion_count, 0)

    def test_pre_revocation_stop_retry_remains_read_only(self) -> None:
        assertion, stop_arguments = self.stop_contract()
        authenticated = AuthenticatedMissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        first = authenticated.stop(
            assertion,
            MISSION_ID,
            **stop_arguments,
        )
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        self.service.accept(self.revocation())
        self.now = datetime(2026, 7, 30, 10, 8, tzinfo=UTC)

        replay = authenticated.stop(
            assertion,
            MISSION_ID,
            **stop_arguments,
        )

        self.assertEqual(replay, first)
        with closing(sqlite3.connect(self.path)) as connection:
            assertion_count = connection.execute(
                "SELECT COUNT(*) FROM principal_assertion_uses"
            ).fetchone()[0]
            revocation_count = connection.execute(
                "SELECT COUNT(*) FROM mission_scope_grant_revocations"
            ).fetchone()[0]
        self.assertEqual(assertion_count, 1)
        self.assertEqual(revocation_count, 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_concurrent_exact_revocations_converge_to_one_row(self) -> None:
        revocation = self.revocation()
        barrier = threading.Barrier(2)

        def accept():
            barrier.wait()
            return ScopeGrantRevocationAcceptanceService(
                MissionStore(
                    self.path,
                    clock=lambda: self.now,
                ),
                self.registry,
            ).accept(revocation)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = (
                executor.submit(accept),
                executor.submit(accept),
            )
            acceptances = tuple(result.result() for result in results)

        self.assertEqual(
            sorted(item.idempotent for item in acceptances),
            [False, True],
        )
        self.assertEqual(self.row_count(), 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_concurrent_competing_revocations_have_one_winner(self) -> None:
        revocations = (
            self.revocation(),
            self.revocation(
                revocation_id="SRV-FEDCBA9876543210FEDCBA9876543210",
            ),
        )
        barrier = threading.Barrier(2)

        def accept(revocation):
            barrier.wait()
            return ScopeGrantRevocationAcceptanceService(
                MissionStore(
                    self.path,
                    clock=lambda: self.now,
                ),
                self.registry,
            ).accept(revocation)

        successes = []
        conflicts = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(
                executor.submit(accept, revocation)
                for revocation in revocations
            )
            for future in futures:
                try:
                    successes.append(future.result())
                except StoreConflictError as exc:
                    conflicts.append(exc)

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(conflicts), 1)
        self.assertFalse(successes[0].idempotent)
        self.assertEqual(self.row_count(), 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_expired_target_grant_can_still_be_revoked(self) -> None:
        self.now = datetime(2026, 7, 30, 10, 31, tzinfo=UTC)
        revocation = self.revocation(
            issued_at="2026-07-30T10:31:00Z",
            not_before="2026-07-30T10:31:00Z",
            expires_at="2026-07-30T10:35:00Z",
        )

        accepted = self.service.accept(revocation)

        self.assertFalse(accepted.idempotent)
        self.assertEqual(
            accepted.accepted_at,
            "2026-07-30T10:31:00Z",
        )
        self.assertEqual(self.row_count(), 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_deleted_revocation_row_blocks_every_scope_sensitive_path(
        self,
    ) -> None:
        assertion, stop_arguments = self.stop_contract()
        self.service.accept(self.revocation())
        self.remove_revocation_row_preserving_schema_manifest()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "counts or head",
        ):
            ScopeGrantAcceptanceService(
                self.store,
                self.registry,
            ).accept(self.grant)

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "counts or head",
        ):
            AuthenticatedMissionControlService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            ).stop(
                assertion,
                MISSION_ID,
                **stop_arguments,
            )

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "counts or head",
        ):
            MissionControlService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            ).get(MISSION_ID)

        with closing(sqlite3.connect(self.path)) as connection:
            control = connection.execute(
                """
                SELECT state, version FROM mission_controls
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assertion_count = connection.execute(
                "SELECT COUNT(*) FROM principal_assertion_uses"
            ).fetchone()[0]
        self.assertEqual(control, ("active", 1))
        self.assertEqual(assertion_count, 0)

    def test_policy_replacement_must_follow_revocation_acceptance(
        self,
    ) -> None:
        self.service.accept(self.revocation())
        newer_policy = self._policy(POLICY_VERSION + 1)

        with self.assertRaisesRegex(
            StoreConflictError,
            "later than all prior policy and credential records",
        ):
            self.trust.apply_policy(newer_policy)

        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        status = self.trust.apply_policy(newer_policy)
        self.assertEqual(status.policy_version, POLICY_VERSION + 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )


if __name__ == "__main__":
    unittest.main()
