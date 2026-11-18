"""Tests for signed scope grant acceptance."""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
)
from sunderkey.identity import PrincipalOperation
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.scope import (
    ScopeGrantAcceptance,
    ScopeGrantAcceptanceService,
)
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    ASSERTION_KEY_ID,
    AUDIENCE,
    OTHER_PROFILE_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, mission_data

MISSION_ID = "MISSION-PHASE5"
POLICY_VERSION = 7
OTHER_STORE_ID = "STR-FEDCBA9876543210FEDCBA9876543210"


class ScopeGrantAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "scope-phase5.sqlite3"
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
        initial = self.trust.status()
        self.store_id = initial.store_id
        root_public_key = public_bytes(self.factory.root_private)
        self.trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
        )
        self.policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
        )
        self.trust.apply_policy(self.policy)
        self.service = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )

    def grant(self, **changes):
        constraints_hash = sha256_text(
            canonical_json(self.mission.to_dict()["constraints"])
        )
        arguments = {
            "store_id": self.store_id,
            "mission_id": MISSION_ID,
            "mission_context_hash": self.stored_mission.context_hash,
            "scope_reference": SCOPE_REFERENCE,
            "scope_document_hash": SCOPE_DOCUMENT_HASH,
            "environment": self.mission.environment.value,
            "max_action_tier": self.mission.max_action_tier.value,
            "constraints_hash": constraints_hash,
            "operations": [PrincipalOperation.MISSION_STOP.value],
            "issued_at": "2026-07-30T10:05:00Z",
            "not_before": "2026-07-30T10:05:00Z",
            "expires_at": "2026-07-30T10:30:00Z",
            "policy_version": POLICY_VERSION,
        }
        arguments.update(changes)
        return self.factory.grant(**arguments)

    def grant_count(self) -> int:
        with closing(sqlite3.connect(self.path)) as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM mission_scope_grants"
                ).fetchone()[0]
            )

    def test_valid_scope_grant_is_verified_and_stored(self) -> None:
        grant = self.grant()
        accepted = self.service.accept(grant)

        self.assertFalse(accepted.idempotent)
        self.assertEqual(accepted.grant, grant)
        self.assertEqual(accepted.grant_sha256, grant.content_sha256)
        self.assertEqual(
            accepted.key_sha256,
            self.policy.key(grant.key_id).content_sha256,
        )
        self.assertEqual(
            accepted.policy_sha256,
            self.policy.content_sha256,
        )
        self.assertEqual(
            accepted.accepted_at,
            "2026-07-30T10:05:00Z",
        )
        self.assertIsNone(accepted.revoked_at)
        self.assertEqual(self.grant_count(), 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_exact_replay_is_idempotent_after_policy_advancement(self) -> None:
        grant = self.grant()
        first = self.service.accept(grant)

        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        newer_policy = self.factory.policy(
            policy_version=POLICY_VERSION + 1,
            store_id=self.store_id,
        )
        self.trust.apply_policy(newer_policy)
        replay = self.service.accept(grant)

        self.assertFalse(first.idempotent)
        self.assertTrue(replay.idempotent)
        self.assertEqual(replay.accepted_at, first.accepted_at)
        self.assertEqual(replay.grant_sha256, first.grant_sha256)
        self.assertEqual(replay.policy_sha256, first.policy_sha256)
        self.assertEqual(self.grant_count(), 1)

    def test_changed_replay_with_same_issuer_and_id_conflicts(self) -> None:
        grant = self.grant()
        self.service.accept(grant)
        changed = self.grant(
            expires_at="2026-07-30T10:29:00Z"
        )

        with self.assertRaisesRegex(
            StoreConflictError,
            "different content",
        ):
            self.service.accept(changed)
        self.assertEqual(self.grant_count(), 1)

    def test_unsigned_revocation_cannot_bypass_signed_boundary(self) -> None:
        grant = self.grant()
        first = self.service.accept(grant)
        with (
            closing(sqlite3.connect(self.path)) as connection,
            self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "legacy scope grant revocation state is frozen",
            ),
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

        replay = self.service.accept(grant)
        self.assertFalse(first.idempotent)
        self.assertTrue(replay.idempotent)
        self.assertEqual(self.grant_count(), 1)

    def test_invalid_signature_is_rejected_without_storage(self) -> None:
        grant = self.grant(
            signing_private=self.factory.assertion_private
        )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "signature verification failed",
        ):
            self.service.accept(grant)
        self.assertEqual(self.grant_count(), 0)

    def test_exact_mission_bindings_are_required(self) -> None:
        invalid = (
            self.grant(store_id=OTHER_STORE_ID),
            self.grant(mission_context_hash="sha256:" + "1" * 64),
            self.grant(scope_document_hash="sha256:" + "9" * 64),
            self.grant(environment="production"),
            self.grant(max_action_tier="R3"),
            self.grant(constraints_hash="sha256:" + "3" * 64),
        )
        for grant in invalid:
            with self.subTest(grant=grant.to_dict()), self.assertRaises(
                PrincipalAuthenticationError
            ):
                self.service.accept(grant)
        self.assertEqual(self.grant_count(), 0)

    def test_profile_assignment_and_key_use_are_enforced(self) -> None:
        self.assertNotIn(
            OTHER_PROFILE_ID,
            self.stored_mission.allowed_profile_ids,
        )
        unassigned = self.grant(profile_id=OTHER_PROFILE_ID)
        wrong_key_use = self.grant(
            key_id=ASSERTION_KEY_ID,
            issuer="identity-provider",
            signing_private=self.factory.assertion_private,
        )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "not assigned",
        ):
            self.service.accept(unassigned)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "cannot verify a scope_grant",
        ):
            self.service.accept(wrong_key_use)
        self.assertEqual(self.grant_count(), 0)

    def test_time_and_current_policy_high_water_are_enforced(self) -> None:
        not_yet_active = self.grant(
            not_before="2026-07-30T10:06:00Z"
        )
        expired = self.grant(
            issued_at="2026-07-30T10:00:00Z",
            not_before="2026-07-30T10:00:00Z",
            expires_at="2026-07-30T10:04:00Z",
        )
        for grant in (not_yet_active, expired):
            with self.subTest(grant=grant.to_dict()), self.assertRaises(
                PrincipalAuthenticationError
            ):
                self.service.accept(grant)

        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        newer_policy = self.factory.policy(
            policy_version=POLICY_VERSION + 1,
            store_id=self.store_id,
        )
        self.trust.apply_policy(newer_policy)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "policy version",
        ):
            self.service.accept(self.grant())
        self.assertEqual(self.grant_count(), 0)

    def test_concurrent_exact_acceptance_converges_to_one_row(self) -> None:
        grant = self.grant()
        first_service = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )
        second_service = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )
        barrier = threading.Barrier(2)

        def accept(
            service: ScopeGrantAcceptanceService,
        ) -> ScopeGrantAcceptance:
            barrier.wait()
            return service.accept(grant)

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = (
                executor.submit(accept, first_service),
                executor.submit(accept, second_service),
            )
            results = tuple(future.result(timeout=10) for future in futures)

        self.assertEqual(
            sorted(result.idempotent for result in results),
            [False, True],
        )
        self.assertEqual(
            {result.grant_sha256 for result in results},
            {grant.content_sha256},
        )
        self.assertEqual(self.grant_count(), 1)


if __name__ == "__main__":
    unittest.main()
