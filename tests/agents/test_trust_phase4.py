"""Tests for offline root trust and policy enrollment."""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreMigrationRequiredError,
)
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    TrustKeyState,
    TrustKeyUse,
)
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import StoreTrustStatus, TrustProvisioningService

from .test_store import downgrade_connection_to_schema_v1

NOW = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)
AUDIENCE = "sunderkey-runtime"
OTHER_AUDIENCE = "sunderkey-secondary"
ROOT_KEY_ID = "ROOT-2026"
OTHER_ROOT_KEY_ID = "ROOT-OTHER"
POLICY_ID = "POLICY-PHASE4"
OTHER_STORE_ID = "STR-FEDCBA9876543210FEDCBA9876543210"
ZERO_SIGNATURE = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_text(private_key: Ed25519PrivateKey) -> str:
    return b64url(public_bytes(private_key))


def raw_key_hash(private_key: Ed25519PrivateKey) -> str:
    return "sha256:" + hashlib.sha256(public_bytes(private_key)).hexdigest()


class PolicyFactory:
    def __init__(
        self,
        *,
        root_private: Ed25519PrivateKey,
        store_id: str,
    ) -> None:
        self.root_private = root_private
        self.store_id = store_id
        self.assertion_private = Ed25519PrivateKey.generate()

    def policy(
        self,
        *,
        policy_id: str = POLICY_ID,
        policy_version: int = 1,
        audience: str = AUDIENCE,
        store_id: str | None = None,
        root_key_id: str = ROOT_KEY_ID,
        signing_private: Ed25519PrivateKey | None = None,
        max_assertion_lifetime_seconds: int = 300,
    ) -> PrincipalTrustPolicy:
        operation = PrincipalOperation.MISSION_STOP.value
        raw: dict[str, Any] = {
            "schema_version": 1,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "issuer": "sunderkey-security",
            "audience": audience,
            "store_id": store_id or self.store_id,
            "issued_at": "2026-07-30T09:00:00Z",
            "not_before": "2026-07-30T09:00:00Z",
            "expires_at": "2026-07-30T12:00:00Z",
            "max_scope_lifetime_seconds": 3600,
            "max_assertion_lifetime_seconds": max_assertion_lifetime_seconds,
            "allowed_profiles": ["AOE-HQ-12"],
            "allowed_subjects": ["operator:alice"],
            "allowed_operations": [operation],
            "keys": [
                {
                    "key_id": "ASSERTION-2026",
                    "issuer": "identity-provider",
                    "public_key": public_text(self.assertion_private),
                    "key_use": TrustKeyUse.PRINCIPAL_ASSERTION.value,
                    "state": TrustKeyState.ACTIVE.value,
                    "not_before": "2026-07-30T09:00:00Z",
                    "not_after": "2026-07-30T12:00:00Z",
                    "retire_at": None,
                    "allowed_profiles": ["AOE-HQ-12"],
                    "allowed_subjects": ["operator:alice"],
                    "allowed_operations": [operation],
                }
            ],
            "root_key_id": root_key_id,
            "signature": ZERO_SIGNATURE,
        }
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        signer = signing_private or self.root_private
        return replace(
            unsigned,
            signature=b64url(signer.sign(unsigned.signing_bytes())),
        )


class TrustProvisioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.now = NOW
        self.path = Path(self.temporary_directory.name) / "mission.db"
        self.store = MissionStore(self.path, clock=lambda: self.now)
        self.store.initialize()
        self.service = TrustProvisioningService(self.store)
        self.root_private = Ed25519PrivateKey.generate()
        self.factory = PolicyFactory(
            root_private=self.root_private,
            store_id=self.service.status().store_id,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def pin(
        self,
        *,
        service: TrustProvisioningService | None = None,
        private_key: Ed25519PrivateKey | None = None,
        root_key_id: str = ROOT_KEY_ID,
        audience: str = AUDIENCE,
    ) -> StoreTrustStatus:
        selected_key = private_key or self.root_private
        return (service or self.service).pin_root(
            root_key_id,
            audience,
            public_text(selected_key),
            raw_key_hash(selected_key),
        )

    def test_root_pin_is_one_time_and_exact_replay_has_no_write(self) -> None:
        initial = self.service.status()
        self.assertFalse(initial.root_pinned)
        self.assertFalse(initial.policy_applied)

        pinned = self.pin()
        self.assertTrue(pinned.root_pinned)
        self.assertEqual(pinned.root_key_id, ROOT_KEY_ID)
        self.assertEqual(pinned.audience, AUDIENCE)
        self.assertEqual(pinned.root_public_key, public_text(self.root_private))
        self.assertEqual(pinned.root_key_hash, raw_key_hash(self.root_private))

        self.now += timedelta(minutes=1)
        self.assertEqual(self.pin(), pinned)
        with self.assertRaisesRegex(StoreConflictError, "already pinned"):
            self.pin(audience=OTHER_AUDIENCE)
        self.assertEqual(self.service.status(), pinned)

    def test_hash_mismatch_and_invalid_base64_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "does not match",
        ):
            self.service.pin_root(
                ROOT_KEY_ID,
                AUDIENCE,
                public_text(self.root_private),
                "sha256:" + "0" * 64,
            )
        for value in ("short", "!" * 43, public_text(self.root_private) + "="):
            with self.subTest(value=value), self.assertRaisesRegex(
                PrincipalAuthenticationError,
                "base64url",
            ):
                self.service.pin_root(
                    ROOT_KEY_ID,
                    AUDIENCE,
                    value,
                    raw_key_hash(self.root_private),
                )
        self.assertFalse(self.service.status().root_pinned)

    def test_weak_root_points_are_rejected_before_pinning(self) -> None:
        for raw_public_key in (bytes(32), b"\x01" + bytes(31)):
            with (
                self.subTest(public_key=raw_public_key.hex()),
                self.assertRaisesRegex(
                    PrincipalAuthenticationError,
                    "prime-order",
                ),
            ):
                self.service.pin_root(
                    ROOT_KEY_ID,
                    AUDIENCE,
                    b64url(raw_public_key),
                    "sha256:"
                    + hashlib.sha256(raw_public_key).hexdigest(),
                )
        self.assertFalse(self.service.status().root_pinned)

    def test_status_rejects_legacy_schema_with_domain_error(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            downgrade_connection_to_schema_v1(connection)
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(StoreMigrationRequiredError):
            self.service.status()

    def test_identifiers_and_audience_are_strict(self) -> None:
        cases = (
            ("bad key", AUDIENCE),
            ("AB", AUDIENCE),
            (ROOT_KEY_ID, "bad audience"),
            (ROOT_KEY_ID, "\u00e1udience"),
        )
        for key_id, audience in cases:
            with self.subTest(
                key_id=key_id,
                audience=audience,
            ), self.assertRaisesRegex(
                PrincipalAuthenticationError,
                "valid identifier",
            ):
                self.service.pin_root(
                    key_id,
                    audience,
                    public_text(self.root_private),
                    raw_key_hash(self.root_private),
                )

    def test_policy_cannot_select_its_own_root(self) -> None:
        attacker = Ed25519PrivateKey.generate()
        attacker_factory = PolicyFactory(
            root_private=attacker,
            store_id=self.factory.store_id,
        )
        attacker_policy = attacker_factory.policy(
            root_key_id=OTHER_ROOT_KEY_ID
        )
        with self.assertRaisesRegex(StoreConflictError, "must be pinned"):
            self.service.apply_policy(attacker_policy)

        self.pin()
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "does not match the pinned root",
        ):
            self.service.apply_policy(attacker_policy)
        self.assertFalse(self.service.status().policy_applied)

    def test_valid_policy_is_verified_and_stored_canonically(self) -> None:
        self.pin()
        policy = self.factory.policy()
        status = self.service.apply_policy(policy)

        expected_json = canonical_json(policy.to_dict())
        expected_hash = sha256_text(expected_json)
        self.assertTrue(status.policy_applied)
        self.assertEqual(status.policy_id, POLICY_ID)
        self.assertEqual(status.policy_version, 1)
        self.assertEqual(status.policy_hash, expected_hash)
        self.assertNotIn("policy_json", status.to_dict())

        connection = sqlite3.connect(self.path)
        try:
            stored = connection.execute(
                """
                SELECT trust_policy_json, trust_policy_hash
                FROM store_identity
                WHERE singleton_id = 1
                """
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(stored, (expected_json, expected_hash))

    def test_policy_signature_failure_does_not_change_store(self) -> None:
        self.pin()
        wrong_signer = Ed25519PrivateKey.generate()
        policy = self.factory.policy(signing_private=wrong_signer)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "signature verification failed",
        ):
            self.service.apply_policy(policy)
        self.assertFalse(self.service.status().policy_applied)

    def test_cross_store_and_audience_policies_are_rejected(self) -> None:
        self.pin()
        policies = (
            self.factory.policy(store_id=OTHER_STORE_ID),
            self.factory.policy(audience=OTHER_AUDIENCE),
        )
        for policy in policies:
            with self.subTest(
                store_id=policy.store_id,
                audience=policy.audience,
            ), self.assertRaises(PrincipalAuthenticationError):
                self.service.apply_policy(policy)
        self.assertFalse(self.service.status().policy_applied)

    def test_exact_policy_replay_returns_status_without_write(self) -> None:
        self.pin()
        policy = self.factory.policy()
        first = self.service.apply_policy(policy)
        self.now += timedelta(minutes=1)
        second = self.service.apply_policy(policy)

        self.assertEqual(second, first)
        self.assertEqual(second.policy_applied_at, "2026-07-30T10:05:00Z")

    def test_policy_version_rollback_is_rejected(self) -> None:
        self.pin()
        current = self.service.apply_policy(
            self.factory.policy(policy_version=2)
        )
        with self.assertRaisesRegex(StoreConflictError, "strictly increase"):
            self.service.apply_policy(
                self.factory.policy(policy_version=1)
            )
        self.assertEqual(self.service.status(), current)

    def test_changed_policy_at_same_version_is_rejected(self) -> None:
        self.pin()
        current = self.service.apply_policy(self.factory.policy())
        changed = self.factory.policy(
            max_assertion_lifetime_seconds=301
        )
        with self.assertRaisesRegex(StoreConflictError, "strictly increase"):
            self.service.apply_policy(changed)
        self.assertEqual(self.service.status(), current)

    def test_policy_id_cannot_change_at_a_higher_version(self) -> None:
        self.pin()
        current = self.service.apply_policy(self.factory.policy())
        replacement = self.factory.policy(
            policy_id="POLICY-OTHER",
            policy_version=2,
        )
        with self.assertRaisesRegex(StoreConflictError, "policy ID"):
            self.service.apply_policy(replacement)
        self.assertEqual(self.service.status(), current)

    def test_policy_history_is_immutable_and_time_ordered(self) -> None:
        self.pin()
        first_policy = self.factory.policy()
        first = self.service.apply_policy(first_policy)

        with self.assertRaisesRegex(StoreConflictError, "later than"):
            self.service.apply_policy(
                self.factory.policy(policy_version=2)
            )
        self.assertEqual(self.service.status(), first)

        self.now += timedelta(seconds=1)
        second_policy = self.factory.policy(policy_version=2)
        second = self.service.apply_policy(second_policy)
        self.assertEqual(second.policy_version, 2)
        self.assertEqual(
            second.policy_applied_at,
            "2026-07-30T10:05:01Z",
        )

        connection = sqlite3.connect(self.path)
        try:
            history = connection.execute(
                """
                SELECT policy_version, policy_json, applied_at
                FROM trust_policy_history
                ORDER BY policy_version
                """
            ).fetchall()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable",
            ):
                connection.execute(
                    """
                    UPDATE trust_policy_history
                    SET applied_at = ?
                    WHERE policy_version = 1
                    """,
                    ("2026-07-30T10:04:59Z",),
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute(
                    """
                    DELETE FROM trust_policy_history
                    WHERE policy_version = 1
                    """
                )
        finally:
            connection.close()

        self.assertEqual(
            history,
            [
                (
                    1,
                    canonical_json(first_policy.to_dict()),
                    "2026-07-30T10:05:00Z",
                ),
                (
                    2,
                    canonical_json(second_policy.to_dict()),
                    "2026-07-30T10:05:01Z",
                ),
            ],
        )

    def test_concurrent_root_enrollment_has_one_winner(self) -> None:
        other_root = Ed25519PrivateKey.generate()
        first_service = TrustProvisioningService(self.store)
        second_service = TrustProvisioningService(self.store)
        barrier = threading.Barrier(2)

        def enroll(
            service: TrustProvisioningService,
            private_key: Ed25519PrivateKey,
            key_id: str,
        ) -> StoreTrustStatus | Exception:
            barrier.wait()
            try:
                return self.pin(
                    service=service,
                    private_key=private_key,
                    root_key_id=key_id,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = (
                executor.submit(
                    enroll,
                    first_service,
                    self.root_private,
                    ROOT_KEY_ID,
                ),
                executor.submit(
                    enroll,
                    second_service,
                    other_root,
                    OTHER_ROOT_KEY_ID,
                ),
            )
            results = tuple(future.result(timeout=10) for future in futures)

        successes = [
            result
            for result in results
            if isinstance(result, StoreTrustStatus)
        ]
        failures = [
            result
            for result in results
            if isinstance(result, Exception)
        ]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], StoreConflictError)
        self.assertEqual(self.service.status(), successes[0])


if __name__ == "__main__":
    unittest.main()
