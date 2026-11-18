"""Offline root trust enrollment for a SUNDERKEY mission store."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)
from .identity import (
    PrincipalTrustPolicy,
    _strict_ed25519_public_key,
    verify_trust_policy,
)
from .store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    sha256_text,
)

_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_BASE64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


def _authentication_failure(message: str) -> PrincipalAuthenticationError:
    return PrincipalAuthenticationError(message)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise _authentication_failure(f"{label} must be a string")
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise _authentication_failure(f"{label} is not a valid identifier")
    return value


def _key_hash(value: Any) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise _authentication_failure(
            "expected_key_hash must use sha256 followed by "
            "64 lowercase hexadecimal characters"
        )
    return value


def _decode_public_key(value: Any) -> tuple[str, bytes]:
    if not isinstance(value, str) or _BASE64URL_PATTERN.fullmatch(value) is None:
        raise _authentication_failure(
            "public_key must be canonical unpadded base64url for 32 raw bytes"
        )
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error) as exc:
        raise _authentication_failure("public_key is not valid base64url") from exc
    if len(raw) != 32:
        raise _authentication_failure("public_key must decode to exactly 32 raw bytes")
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise _authentication_failure("public_key is not canonical unpadded base64url")
    _strict_ed25519_public_key(raw, "public_key")
    return value, raw


def _raw_key_hash(raw_public_key: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw_public_key).hexdigest()


@dataclass(frozen=True)
class StoreTrustStatus:
    """Public trust enrollment state for one mission store."""

    store_id: str
    created_at: str
    audience: str | None
    root_key_id: str | None
    root_public_key: str | None
    root_key_hash: str | None
    root_provisioned_at: str | None
    policy_id: str | None
    policy_version: int | None
    policy_hash: str | None
    policy_applied_at: str | None

    @property
    def root_pinned(self) -> bool:
        return self.root_key_id is not None

    @property
    def policy_applied(self) -> bool:
        return self.policy_id is not None

    def to_dict(self) -> dict[str, str | int | bool | None]:
        return {
            "store_id": self.store_id,
            "created_at": self.created_at,
            "root_pinned": self.root_pinned,
            "audience": self.audience,
            "root_key_id": self.root_key_id,
            "root_public_key": self.root_public_key,
            "root_key_hash": self.root_key_hash,
            "root_provisioned_at": self.root_provisioned_at,
            "policy_applied": self.policy_applied,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "policy_applied_at": self.policy_applied_at,
        }


class TrustProvisioningService:
    """Pin an out-of-band root and apply root-signed trust policies."""

    def __init__(self, store: MissionStore) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        self._store = store

    @staticmethod
    def _status_from_row(row: sqlite3.Row) -> StoreTrustStatus:
        policy_version = row["trust_policy_version"]
        return StoreTrustStatus(
            store_id=str(row["store_id"]),
            created_at=str(row["created_at"]),
            audience=(
                None if row["audience"] is None else str(row["audience"])
            ),
            root_key_id=(
                None
                if row["pinned_root_key_id"] is None
                else str(row["pinned_root_key_id"])
            ),
            root_public_key=(
                None
                if row["pinned_root_public_key"] is None
                else str(row["pinned_root_public_key"])
            ),
            root_key_hash=(
                None
                if row["pinned_root_key_hash"] is None
                else str(row["pinned_root_key_hash"])
            ),
            root_provisioned_at=(
                None
                if row["root_provisioned_at"] is None
                else str(row["root_provisioned_at"])
            ),
            policy_id=(
                None
                if row["trust_policy_id"] is None
                else str(row["trust_policy_id"])
            ),
            policy_version=(
                None if policy_version is None else int(policy_version)
            ),
            policy_hash=(
                None
                if row["trust_policy_hash"] is None
                else str(row["trust_policy_hash"])
            ),
            policy_applied_at=(
                None
                if row["policy_applied_at"] is None
                else str(row["policy_applied_at"])
            ),
        )

    def status(self) -> StoreTrustStatus:
        """Read the current root and policy high-water state."""

        connection = self._store._open_existing_connection()
        try:
            connection.execute("BEGIN")
            row = self._store._verify_store_identity(connection)
            return self._status_from_row(row)
        finally:
            connection.rollback()
            connection.close()

    def pin_root(
        self,
        root_key_id: str,
        audience: str,
        public_key: str,
        expected_key_hash: str,
    ) -> StoreTrustStatus:
        """Pin one root key only when its out-of-band hash matches."""

        parsed_key_id = _identifier(root_key_id, "root_key_id")
        parsed_audience = _identifier(audience, "audience")
        canonical_public_key, raw_public_key = _decode_public_key(public_key)
        parsed_expected_hash = _key_hash(expected_key_hash)
        actual_key_hash = _raw_key_hash(raw_public_key)
        if not hmac.compare_digest(parsed_expected_hash, actual_key_hash):
            raise _authentication_failure(
                "Root public key does not match expected_key_hash"
            )

        with self._store._write_connection() as connection:
            row = self._store._verify_store_identity(connection)
            current = self._status_from_row(row)
            if current.root_pinned:
                exact_replay = (
                    current.root_key_id == parsed_key_id
                    and current.audience == parsed_audience
                    and current.root_public_key == canonical_public_key
                    and current.root_key_hash == actual_key_hash
                )
                if exact_replay:
                    return current
                raise StoreConflictError(
                    "Store root trust is already pinned to different material"
                )

            provisioned_at = format_timestamp(self._store._clock())
            cursor = connection.execute(
                """
                UPDATE store_identity
                SET
                    audience = ?,
                    pinned_root_key_id = ?,
                    pinned_root_public_key = ?,
                    pinned_root_key_hash = ?,
                    root_provisioned_at = ?
                WHERE
                    singleton_id = 1
                    AND audience IS NULL
                    AND pinned_root_key_id IS NULL
                    AND pinned_root_public_key IS NULL
                    AND pinned_root_key_hash IS NULL
                    AND root_provisioned_at IS NULL
                """,
                (
                    parsed_audience,
                    parsed_key_id,
                    canonical_public_key,
                    actual_key_hash,
                    provisioned_at,
                ),
            )
            if cursor.rowcount != 1:
                raise StoreConflictError(
                    "Store root trust changed during enrollment"
                )
            updated = self._store._verify_store_identity(connection)
            return self._status_from_row(updated)

    def apply_policy(
        self,
        policy: PrincipalTrustPolicy,
    ) -> StoreTrustStatus:
        """Verify and persist an initial or strictly newer trust policy."""

        if not isinstance(policy, PrincipalTrustPolicy):
            raise _authentication_failure(
                "policy must be a PrincipalTrustPolicy"
            )
        policy = PrincipalTrustPolicy.from_dict(policy.to_dict())
        policy_json = canonical_json(policy.to_dict())
        policy_hash = sha256_text(policy_json)

        with self._store._write_connection() as connection:
            row = self._store._verify_store_identity(connection)
            current = self._status_from_row(row)
            if not current.root_pinned:
                raise StoreConflictError(
                    "A root key must be pinned before a trust policy can be applied"
                )

            stored_policy_json = row["trust_policy_json"]
            if current.policy_applied:
                exact_replay = (
                    current.policy_id == policy.policy_id
                    and current.policy_version == policy.policy_version
                    and current.policy_hash == policy_hash
                    and stored_policy_json == policy_json
                )
                if exact_replay:
                    return current
                if current.policy_id != policy.policy_id:
                    raise StoreConflictError(
                        "Trust policy replacement must retain the pinned policy ID"
                    )
                if (
                    current.policy_version is not None
                    and policy.policy_version <= current.policy_version
                ):
                    raise StoreConflictError(
                        "Trust policy version must strictly increase"
                    )

            if policy.root_key_id != current.root_key_id:
                raise PrincipalAuthenticationError(
                    "Trust policy root key does not match the pinned root key"
                )

            if (
                current.root_key_id is None
                or current.audience is None
                or current.root_public_key is None
            ):
                raise StoreIntegrityError(
                    "Pinned root trust state is incomplete"
                )
            try:
                _, raw_public_key = _decode_public_key(current.root_public_key)
            except PrincipalAuthenticationError as exc:
                raise StoreIntegrityError(
                    "Pinned root public key is not valid"
                ) from exc
            actual_stored_hash = _raw_key_hash(raw_public_key)
            if (
                current.root_key_hash is None
                or not hmac.compare_digest(
                    current.root_key_hash,
                    actual_stored_hash,
                )
            ):
                raise StoreIntegrityError(
                    "Pinned root public key hash does not match its key"
                )

            minimum_version = (
                1
                if current.policy_version is None
                else current.policy_version + 1
            )
            verified = verify_trust_policy(
                policy,
                {current.root_key_id: raw_public_key},
                expected_audience=current.audience,
                expected_store_id=current.store_id,
                expected_root_key_id=current.root_key_id,
                minimum_policy_version=minimum_version,
                clock=self._store._clock,
            )
            if verified.policy_sha256 != policy_hash:
                raise StoreIntegrityError(
                    "Verified trust policy hash does not match canonical storage"
                )
            if current.policy_applied:
                prior_timestamps = [
                    value
                    for value in (
                        current.policy_applied_at,
                        connection.execute(
                            "SELECT MAX(accepted_at) FROM mission_scope_grants"
                        ).fetchone()[0],
                        connection.execute(
                            "SELECT MAX(consumed_at) FROM principal_assertion_uses"
                        ).fetchone()[0],
                        connection.execute(
                            "SELECT MAX(accepted_at) "
                            "FROM mission_scope_grant_revocations"
                        ).fetchone()[0],
                    )
                    if value is not None
                ]
                latest_prior = max(
                    parse_timestamp(
                        str(value),
                        "trust policy high-water timestamp",
                    )
                    for value in prior_timestamps
                )
                applied_at = parse_timestamp(
                    verified.verified_at,
                    "trust policy applied_at",
                )
                if applied_at <= latest_prior:
                    raise StoreConflictError(
                        "Trust policy replacement time must be later than "
                        "all prior policy and credential records"
                    )
            else:
                self._store._verify_initial_authentication_readiness(
                    connection
                )

            connection.execute(
                """
                INSERT INTO trust_policy_history(
                    policy_hash,
                    policy_id,
                    policy_version,
                    policy_json,
                    audience,
                    store_id,
                    root_key_id,
                    applied_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy_hash,
                    policy.policy_id,
                    policy.policy_version,
                    policy_json,
                    policy.audience,
                    policy.store_id,
                    policy.root_key_id,
                    verified.verified_at,
                ),
            )
            cursor = connection.execute(
                """
                UPDATE store_identity
                SET
                    trust_policy_id = ?,
                    trust_policy_version = ?,
                    trust_policy_hash = ?,
                    trust_policy_json = ?,
                    policy_applied_at = ?
                WHERE singleton_id = 1
                """,
                (
                    policy.policy_id,
                    policy.policy_version,
                    policy_hash,
                    policy_json,
                    verified.verified_at,
                ),
            )
            if cursor.rowcount != 1:
                raise StoreConflictError(
                    "Store trust policy changed during enrollment"
                )
            updated = self._store._verify_store_identity(connection)
            return self._status_from_row(updated)


__all__ = [
    "StoreTrustStatus",
    "TrustProvisioningService",
]
