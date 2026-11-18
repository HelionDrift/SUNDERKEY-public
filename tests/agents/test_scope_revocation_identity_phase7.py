"""Tests for signed scope grant revocation credentials."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import (
    SCOPE_GRANT_SIGNING_DOMAIN,
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrant,
    ScopeGrantRevocation,
    TrustKeyUse,
    VerifiedScopeGrantRevocation,
    load_scope_grant_revocation,
    verify_scope_grant_revocation,
    verify_trust_policy,
)

NOW = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)
AUDIENCE = "sunderkey-runtime"
STORE_ID = "STR-0123456789ABCDEF0123456789ABCDEF"
MISSION_ID = "MISSION-PHASE7"
MISSION_CONTEXT_HASH = "sha256:" + "1" * 64
SCOPE_DOCUMENT_HASH = "sha256:" + "2" * 64
CONSTRAINTS_HASH = "sha256:" + "3" * 64
PROFILE_ID = "AOE-HQ-12"
SUBJECT = "operator:alice"
POLICY_ID = "POLICY-PHASE7"
ROOT_KEY_ID = "ROOT-PHASE7"
SCOPE_KEY_ID = "SCOPE-GRANT-PHASE7"
REVOCATION_KEY_ID = "SCOPE-REVOCATION-PHASE7"
GRANT_ID = "SGR-0123456789ABCDEF0123456789ABCDEF"
REVOCATION_ID = "SRV-0123456789ABCDEF0123456789ABCDEF"
ZERO_SIGNATURE = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class RevocationCredentialFactory:
    def __init__(self) -> None:
        self.root_private = Ed25519PrivateKey.generate()
        self.scope_private = Ed25519PrivateKey.generate()
        self.revocation_private = Ed25519PrivateKey.generate()

    @staticmethod
    def operations() -> list[str]:
        return sorted(
            [
                PrincipalOperation.APPROVAL_APPROVE.value,
                PrincipalOperation.MISSION_STOP.value,
            ]
        )

    def policy(
        self,
        *,
        policy_version: int = 8,
        revocation_key_use: str = TrustKeyUse.SCOPE_GRANT_REVOCATION.value,
        revocation_operations: list[str] | None = None,
        max_assertion_lifetime_seconds: int = 300,
    ) -> PrincipalTrustPolicy:
        operations = self.operations()
        raw: dict[str, Any] = {
            "schema_version": 1,
            "policy_id": POLICY_ID,
            "policy_version": policy_version,
            "issuer": "sunderkey-security",
            "audience": AUDIENCE,
            "store_id": STORE_ID,
            "issued_at": "2026-07-30T09:00:00Z",
            "not_before": "2026-07-30T09:00:00Z",
            "expires_at": "2026-07-30T12:00:00Z",
            "max_scope_lifetime_seconds": 3600,
            "max_assertion_lifetime_seconds": max_assertion_lifetime_seconds,
            "allowed_profiles": [PROFILE_ID],
            "allowed_subjects": [SUBJECT],
            "allowed_operations": operations,
            "keys": [
                {
                    "key_id": REVOCATION_KEY_ID,
                    "issuer": "scope-revocation-authority",
                    "public_key": b64url(public_bytes(self.revocation_private)),
                    "key_use": revocation_key_use,
                    "state": "active",
                    "not_before": "2026-07-30T09:00:00Z",
                    "not_after": "2026-07-30T12:00:00Z",
                    "retire_at": None,
                    "allowed_profiles": [PROFILE_ID],
                    "allowed_subjects": [SUBJECT],
                    "allowed_operations": sorted(
                        revocation_operations
                        if revocation_operations is not None
                        else operations
                    ),
                },
                {
                    "key_id": SCOPE_KEY_ID,
                    "issuer": "scope-authority",
                    "public_key": b64url(public_bytes(self.scope_private)),
                    "key_use": TrustKeyUse.SCOPE_GRANT.value,
                    "state": "active",
                    "not_before": "2026-07-30T09:00:00Z",
                    "not_after": "2026-07-30T12:00:00Z",
                    "retire_at": None,
                    "allowed_profiles": [PROFILE_ID],
                    "allowed_subjects": [SUBJECT],
                    "allowed_operations": operations,
                },
            ],
            "root_key_id": ROOT_KEY_ID,
            "signature": ZERO_SIGNATURE,
        }
        raw["keys"] = sorted(
            raw["keys"],
            key=lambda key: key["key_id"],
        )
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.root_private.sign(unsigned.signing_bytes())
            ),
        )

    def verified_policy(self, **changes: Any):
        policy = self.policy(**changes)
        return verify_trust_policy(
            policy,
            {ROOT_KEY_ID: public_bytes(self.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=STORE_ID,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=policy.policy_version,
            clock=lambda: NOW,
        )

    def grant(self, **changes: Any) -> ScopeGrant:
        raw: dict[str, Any] = {
            "schema_version": 1,
            "grant_id": GRANT_ID,
            "policy_id": POLICY_ID,
            "policy_version": 7,
            "issuer": "scope-authority",
            "key_id": SCOPE_KEY_ID,
            "subject": SUBJECT,
            "profile_id": PROFILE_ID,
            "audience": AUDIENCE,
            "store_id": STORE_ID,
            "mission_id": MISSION_ID,
            "mission_context_hash": MISSION_CONTEXT_HASH,
            "scope_reference": "SCOPE-PHASE7",
            "scope_document_hash": SCOPE_DOCUMENT_HASH,
            "environment": "test",
            "max_action_tier": "R3",
            "constraints_hash": CONSTRAINTS_HASH,
            "operations": self.operations(),
            "issued_at": "2026-07-30T10:00:00Z",
            "not_before": "2026-07-30T10:00:00Z",
            "expires_at": "2026-07-30T10:30:00Z",
            "signature": ZERO_SIGNATURE,
        }
        raw.update(changes)
        unsigned = ScopeGrant.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.scope_private.sign(unsigned.signing_bytes())
            ),
        )

    def revocation(
        self,
        target: ScopeGrant | None = None,
        **changes: Any,
    ) -> ScopeGrantRevocation:
        grant = target or self.grant()
        raw: dict[str, Any] = {
            "schema_version": 1,
            "revocation_id": REVOCATION_ID,
            "policy_id": POLICY_ID,
            "policy_version": 8,
            "issuer": "scope-revocation-authority",
            "key_id": REVOCATION_KEY_ID,
            "audience": AUDIENCE,
            "store_id": STORE_ID,
            "mission_id": MISSION_ID,
            "mission_context_hash": MISSION_CONTEXT_HASH,
            "scope_grant_issuer": grant.issuer,
            "scope_grant_id": grant.grant_id,
            "scope_grant_sha256": grant.content_sha256,
            "scope_grant_subject": grant.subject,
            "scope_grant_profile_id": grant.profile_id,
            "reason_code": "authorization_withdrawn",
            "reason": "The external scope authority withdrew this delegation",
            "issued_at": "2026-07-30T10:04:00Z",
            "not_before": "2026-07-30T10:04:00Z",
            "expires_at": "2026-07-30T10:09:00Z",
            "signature": ZERO_SIGNATURE,
        }
        raw.update(changes)
        unsigned = ScopeGrantRevocation.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.revocation_private.sign(unsigned.signing_bytes())
            ),
        )

    def verify(
        self,
        revocation: ScopeGrantRevocation,
        *,
        target: ScopeGrant | None = None,
        policy=None,
        clock=lambda: NOW,
        **expected: Any,
    ) -> VerifiedScopeGrantRevocation:
        return verify_scope_grant_revocation(
            revocation,
            policy or self.verified_policy(),
            target or self.grant(),
            expected_audience=expected.get("expected_audience", AUDIENCE),
            expected_store_id=expected.get("expected_store_id", STORE_ID),
            expected_mission_id=expected.get(
                "expected_mission_id",
                MISSION_ID,
            ),
            expected_mission_context_hash=expected.get(
                "expected_mission_context_hash",
                MISSION_CONTEXT_HASH,
            ),
            clock=clock,
        )


class ScopeGrantRevocationIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.factory = RevocationCredentialFactory()

    def test_valid_revocation_verifies_exact_target_and_policy(self) -> None:
        target = self.factory.grant()
        policy = self.factory.verified_policy()
        revocation = self.factory.revocation(target)

        verified = self.factory.verify(
            revocation,
            target=target,
            policy=policy,
        )

        self.assertEqual(verified.revocation, revocation)
        self.assertEqual(
            verified.revocation_sha256,
            revocation.content_sha256,
        )
        self.assertEqual(
            verified.target_grant_sha256,
            target.content_sha256,
        )
        self.assertEqual(
            verified.key_sha256,
            policy.policy.key(REVOCATION_KEY_ID).content_sha256,
        )
        self.assertEqual(verified.policy_sha256, policy.policy_sha256)
        self.assertEqual(verified.verified_at, "2026-07-30T10:05:00Z")

    def test_contract_is_closed_and_uses_strict_srv_id(self) -> None:
        raw = self.factory.revocation().to_dict()
        raw["unexpected"] = "value"
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "unknown fields",
        ):
            ScopeGrantRevocation.from_dict(raw)

        raw = self.factory.revocation().to_dict()
        raw["revocation_id"] = "SGV-0123456789ABCDEF0123456789ABCDEF"
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "must use SRV-",
        ):
            ScopeGrantRevocation.from_dict(raw)

        for invalid_version in (True, 1.0, "1"):
            raw = self.factory.revocation().to_dict()
            raw["schema_version"] = invalid_version
            with (
                self.subTest(schema_version=invalid_version),
                self.assertRaisesRegex(
                    PrincipalAuthenticationError,
                    "schema_version must be 1",
                ),
            ):
                ScopeGrantRevocation.from_dict(raw)

    def test_loader_rejects_duplicate_keys_and_utf8_bom(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "revocation.json"
            canonical = json.dumps(
                self.factory.revocation().to_dict(),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            duplicate = canonical.replace(
                '"schema_version":1',
                '"schema_version":1,"schema_version":1',
                1,
            )
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(
                PrincipalAuthenticationError,
                "Duplicate JSON object key",
            ):
                load_scope_grant_revocation(path)

            path.write_bytes(b"\xef\xbb\xbf" + canonical.encode("utf-8"))
            with self.assertRaisesRegex(
                PrincipalAuthenticationError,
                "must not contain a UTF-8 BOM",
            ):
                load_scope_grant_revocation(path)

    def test_exact_target_bindings_are_required(self) -> None:
        target = self.factory.grant()
        changed_targets = (
            self.factory.grant(
                grant_id="SGR-FEDCBA9876543210FEDCBA9876543210"
            ),
            self.factory.grant(issuer="other-scope-authority"),
            self.factory.grant(subject="operator:mallory"),
            self.factory.grant(profile_id="AOE-GA-D01-CMD"),
            self.factory.grant(
                mission_context_hash="sha256:" + "9" * 64
            ),
        )
        revocation = self.factory.revocation(target)
        for changed in changed_targets:
            with self.subTest(target=changed.to_dict()), self.assertRaises(
                PrincipalAuthenticationError
            ):
                self.factory.verify(revocation, target=changed)

    def test_expected_runtime_bindings_are_required(self) -> None:
        revocation = self.factory.revocation()
        invalid_expected = (
            {"expected_audience": "other-runtime"},
            {
                "expected_store_id":
                    "STR-FEDCBA9876543210FEDCBA9876543210"
            },
            {"expected_mission_id": "MISSION-OTHER"},
            {
                "expected_mission_context_hash":
                    "sha256:" + "9" * 64
            },
        )
        for expected in invalid_expected:
            with self.subTest(expected=expected), self.assertRaises(
                PrincipalAuthenticationError
            ):
                self.factory.verify(revocation, **expected)

    def test_current_policy_version_is_required(self) -> None:
        revocation = self.factory.revocation(policy_version=7)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "policy version",
        ):
            self.factory.verify(revocation)

    def test_dedicated_key_use_is_required(self) -> None:
        wrong_policy = self.factory.verified_policy(
            revocation_key_use=TrustKeyUse.SCOPE_GRANT.value
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "cannot verify a scope_grant_revocation",
        ):
            self.factory.verify(
                self.factory.revocation(),
                policy=wrong_policy,
            )

    def test_revocation_key_must_allow_every_target_operation(self) -> None:
        restricted_policy = self.factory.verified_policy(
            revocation_operations=[
                PrincipalOperation.MISSION_STOP.value
            ]
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "operation is not exactly allowed",
        ):
            self.factory.verify(
                self.factory.revocation(),
                policy=restricted_policy,
            )

    def test_revocation_uses_assertion_lifetime_limit(self) -> None:
        too_long = self.factory.revocation(
            expires_at="2026-07-30T10:10:00Z"
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "maximum lifetime",
        ):
            self.factory.verify(too_long)

    def test_revocation_expiry_boundary_is_exclusive(self) -> None:
        revocation = self.factory.revocation()
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "has expired",
        ):
            self.factory.verify(
                revocation,
                clock=lambda: datetime(
                    2026,
                    7,
                    30,
                    10,
                    9,
                    tzinfo=UTC,
                ),
            )

    def test_signature_is_domain_separated(self) -> None:
        revocation = self.factory.revocation()
        wrong_message = SCOPE_GRANT_SIGNING_DOMAIN + json.dumps(
            revocation.unsigned_dict(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        wrong_signature = b64url(
            self.factory.revocation_private.sign(wrong_message)
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "signature verification failed",
        ):
            self.factory.verify(
                replace(revocation, signature=wrong_signature)
            )

    def test_direct_dataclass_tampering_is_reparsed(self) -> None:
        tampered = replace(
            self.factory.revocation(),
            reason="contains\ncontrol",
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "printable ASCII",
        ):
            self.factory.verify(tampered)

    def test_verified_wrapper_cannot_be_forged(self) -> None:
        verified = self.factory.verify(self.factory.revocation())
        with self.assertRaisesRegex(
            TypeError,
            "verify_scope_grant_revocation",
        ):
            VerifiedScopeGrantRevocation(
                revocation=verified.revocation,
                revocation_sha256=verified.revocation_sha256,
                target_grant_sha256=verified.target_grant_sha256,
                key_sha256=verified.key_sha256,
                policy_sha256=verified.policy_sha256,
                verified_at=verified.verified_at,
                _proof=b"",
            )


if __name__ == "__main__":
    unittest.main()
