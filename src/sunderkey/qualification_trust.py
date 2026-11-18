"""Signed qualification trust-policy and reviewer credential contracts."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import PrincipalAuthenticationError, QualificationError
from .identity import (
    _base64url,
    _decode_base64url,
    _identifier,
    _strict_ed25519_public_key,
    _timestamp,
    _verify_ed25519,
)
from .qualification import (
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .validation import loads_json_without_duplicate_keys

TRUST_POLICY_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00QUALIFICATION-TRUST-POLICY\x00V1\x00"
)
REVIEWER_CREDENTIAL_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00QUALIFICATION-REVIEWER-CREDENTIAL\x00V1\x00"
)
MAX_REVIEWER_CREDENTIAL_LIFETIME_SECONDS = 2_592_000
MAX_TRUST_POLICY_LIFETIME_SECONDS = 31_622_400

_POLICY_ID_PATTERN = re.compile(r"QTP-[0-9A-F]{32}")
_CREDENTIAL_ID_PATTERN = re.compile(r"QRC-[0-9A-F]{32}")
_DECISION_RECORD_ID_PATTERN = re.compile(r"QDR-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_SPECIALIST_ID_PATTERN = re.compile(r"AOE-G[A-E]-D[0-9]{2}-S[0-9]{2}")
_VERIFICATION_PROOF_KEY = secrets.token_bytes(32)


class QualificationAuthorityKeyUse(StrEnum):
    """The one qualification contract family an authority key may sign."""

    REVIEWER_CREDENTIAL_ISSUER = "reviewer_credential_issuer"
    QUALIFICATION_DECISION = "qualification_decision"
    QUALIFICATION_REVOCATION = "qualification_revocation"


class QualificationAuthorityKeyState(StrEnum):
    """Lifecycle state for one qualification authority key."""

    ACTIVE = "active"
    RETIRING = "retiring"
    REVOKED = "revoked"


class QualificationReviewerRole(StrEnum):
    """Independent reviewer roles admitted by D008."""

    TECHNICAL_EVALUATOR = "technical_evaluator"
    INDEPENDENT_CONTROL = "independent_control"
    INDEPENDENT_ASSURANCE = "independent_assurance"


def _qualification_failure(message: str) -> QualificationError:
    return QualificationError(message)


def _auth_value(function: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return function(*args, **kwargs)
    except PrincipalAuthenticationError as exc:
        raise _qualification_failure(str(exc)) from exc


def _positive_integer(value: Any, label: str, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= maximum
    ):
        raise _qualification_failure(
            f"{label} must be an integer between 1 and {maximum}"
        )
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(
            f"{label} must be a canonical SHA-256 digest"
        )
    return value


def _policy_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _POLICY_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid policy ID")
    return value


def _credential_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _CREDENTIAL_ID_PATTERN.fullmatch(value) is None
    ):
        raise _qualification_failure(f"{label} is not a valid credential ID")
    return value


def _specialist_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _SPECIALIST_ID_PATTERN.fullmatch(value) is None
    ):
        raise _qualification_failure(f"{label} is not a specialist profile ID")
    return value


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise _qualification_failure(f"{label} is not a valid timestamp") from exc


def _timestamp_value(value: Any, label: str) -> str:
    parsed = _auth_value(_timestamp, value, label)
    _parse_timestamp(parsed, label)
    return parsed


def _public_key(value: Any, label: str) -> str:
    encoded = _auth_value(
        _base64url,
        value,
        label,
        decoded_length=32,
    )
    _auth_value(
        _strict_ed25519_public_key,
        _decode_base64url(encoded),
        label,
    )
    return encoded


def _signature(value: Any, label: str) -> str:
    return _auth_value(
        _base64url,
        value,
        label,
        decoded_length=64,
    )


def _sorted_specialist_ids(
    value: Any,
    label: str,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise _qualification_failure(f"{label} must be a non-empty list")
    items = tuple(
        _specialist_id(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    )
    if items != tuple(sorted(items)):
        raise _qualification_failure(f"{label} must use ascending order")
    if len(items) != len(set(items)):
        raise _qualification_failure(f"{label} must not contain duplicates")
    return items


def _sorted_roles(value: Any, label: str) -> tuple[QualificationReviewerRole, ...]:
    if not isinstance(value, list):
        raise _qualification_failure(f"{label} must be a list")
    try:
        roles = tuple(QualificationReviewerRole(item) for item in value)
    except (TypeError, ValueError) as exc:
        raise _qualification_failure(f"{label} contains an invalid role") from exc
    if roles != tuple(sorted(roles, key=lambda role: role.value)):
        raise _qualification_failure(f"{label} must use ascending order")
    if len(roles) != len(set(roles)):
        raise _qualification_failure(f"{label} must not contain duplicates")
    return roles


def _decision_record_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"record_id", "sha256"}, label)
    record_id = value.get("record_id")
    if (
        not isinstance(record_id, str)
        or _DECISION_RECORD_ID_PATTERN.fullmatch(record_id) is None
    ):
        raise _qualification_failure(f"{label}.record_id is invalid")
    return {
        "record_id": record_id,
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _standard_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"id", "version", "sha256"}, label)
    return {
        "id": _auth_value(_identifier, value.get("id"), f"{label}.id"),
        "version": _auth_value(
            _identifier,
            value.get("version"),
            f"{label}.version",
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


@dataclass(frozen=True)
class QualificationAuthorityKey:
    """Root-authorized Ed25519 key for exactly one qualification key use."""

    key_id: str
    issuer: str
    public_key: str
    key_use: QualificationAuthorityKeyUse
    state: QualificationAuthorityKeyState
    not_before: str
    not_after: str
    retire_at: str | None
    allowed_roles: tuple[QualificationReviewerRole, ...]
    allowed_profile_ids: tuple[str, ...]

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        label: str = "qualification authority key",
    ) -> QualificationAuthorityKey:
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "key_id",
                "issuer",
                "public_key",
                "algorithm",
                "key_use",
                "state",
                "not_before",
                "not_after",
                "retire_at",
                "allowed_roles",
                "allowed_profile_ids",
            },
            label,
        )
        if value.get("algorithm") != "Ed25519":
            raise _qualification_failure(f"{label}.algorithm must be Ed25519")
        try:
            key_use = QualificationAuthorityKeyUse(value.get("key_use"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(f"{label}.key_use is invalid") from exc
        try:
            state = QualificationAuthorityKeyState(value.get("state"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(f"{label}.state is invalid") from exc
        not_before = _timestamp_value(
            value.get("not_before"),
            f"{label}.not_before",
        )
        not_after = _timestamp_value(
            value.get("not_after"),
            f"{label}.not_after",
        )
        if _parse_timestamp(not_before, label) >= _parse_timestamp(
            not_after,
            label,
        ):
            raise _qualification_failure(
                f"{label}.not_before must be before not_after"
            )
        retire_raw = value.get("retire_at")
        retire_at = (
            None
            if retire_raw is None
            else _timestamp_value(retire_raw, f"{label}.retire_at")
        )
        if state is QualificationAuthorityKeyState.RETIRING:
            if retire_at is None:
                raise _qualification_failure(
                    f"{label}.retire_at is required for a retiring key"
                )
            retirement = _parse_timestamp(retire_at, label)
            if not (
                _parse_timestamp(not_before, label)
                <= retirement
                < _parse_timestamp(not_after, label)
            ):
                raise _qualification_failure(
                    f"{label}.retire_at must fall inside the key window"
                )
        elif retire_at is not None:
            raise _qualification_failure(
                f"{label}.retire_at is allowed only for a retiring key"
            )
        roles = _sorted_roles(value.get("allowed_roles"), f"{label}.allowed_roles")
        profile_ids = _sorted_specialist_ids(
            value.get("allowed_profile_ids"),
            f"{label}.allowed_profile_ids",
        )
        if key_use is QualificationAuthorityKeyUse.REVIEWER_CREDENTIAL_ISSUER:
            if not roles:
                raise _qualification_failure(
                    f"{label}.allowed_roles must not be empty for a credential issuer"
                )
        elif roles:
            raise _qualification_failure(
                f"{label}.allowed_roles must be empty for {key_use.value}"
            )
        return cls(
            key_id=_auth_value(_identifier, value.get("key_id"), f"{label}.key_id"),
            issuer=_auth_value(_identifier, value.get("issuer"), f"{label}.issuer"),
            public_key=_public_key(value.get("public_key"), f"{label}.public_key"),
            key_use=key_use,
            state=state,
            not_before=not_before,
            not_after=not_after,
            retire_at=retire_at,
            allowed_roles=roles,
            allowed_profile_ids=profile_ids,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "issuer": self.issuer,
            "public_key": self.public_key,
            "algorithm": "Ed25519",
            "key_use": self.key_use.value,
            "state": self.state.value,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "retire_at": self.retire_at,
            "allowed_roles": [role.value for role in self.allowed_roles],
            "allowed_profile_ids": list(self.allowed_profile_ids),
        }

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


@dataclass(frozen=True)
class QualificationTrustPolicy:
    """Offline-root-signed policy for qualification authority issuer keys."""

    schema_version: int
    policy_id: str
    policy_version: int
    decision_record: dict[str, str]
    qualification_standard: dict[str, str]
    issuer: str
    audience: str
    issued_at: str
    not_before: str
    expires_at: str
    max_reviewer_credential_lifetime_seconds: int
    allowed_profile_ids: tuple[str, ...]
    keys: tuple[QualificationAuthorityKey, ...]
    root_key_id: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationTrustPolicy:
        value = _mapping(raw, "qualification trust policy")
        _exact_fields(
            value,
            {
                "schema_version",
                "policy_id",
                "policy_version",
                "decision_record",
                "qualification_standard",
                "issuer",
                "audience",
                "issued_at",
                "not_before",
                "expires_at",
                "max_reviewer_credential_lifetime_seconds",
                "allowed_profile_ids",
                "keys",
                "root_key_id",
                "signature",
            },
            "qualification trust policy",
        )
        if value.get("schema_version") != 1:
            raise _qualification_failure(
                "Qualification trust policy schema_version must be 1"
            )
        issued_at = _timestamp_value(
            value.get("issued_at"),
            "qualification trust policy.issued_at",
        )
        not_before = _timestamp_value(
            value.get("not_before"),
            "qualification trust policy.not_before",
        )
        expires_at = _timestamp_value(
            value.get("expires_at"),
            "qualification trust policy.expires_at",
        )
        issued = _parse_timestamp(issued_at, "qualification trust policy")
        starts = _parse_timestamp(not_before, "qualification trust policy")
        expires = _parse_timestamp(expires_at, "qualification trust policy")
        if issued > starts or starts >= expires:
            raise _qualification_failure(
                "Qualification trust policy validity window is invalid"
            )
        if int((expires - issued).total_seconds()) > MAX_TRUST_POLICY_LIFETIME_SECONDS:
            raise _qualification_failure(
                "Qualification trust policy exceeds the maximum lifetime"
            )
        raw_keys = value.get("keys")
        if not isinstance(raw_keys, list) or not 3 <= len(raw_keys) <= 128:
            raise _qualification_failure(
                "Qualification trust policy keys must contain between 3 and 128 values"
            )
        keys = tuple(
            QualificationAuthorityKey.from_dict(
                item,
                label=f"qualification trust policy.keys[{index}]",
            )
            for index, item in enumerate(raw_keys)
        )
        if tuple(key.key_id for key in keys) != tuple(
            sorted(key.key_id for key in keys)
        ):
            raise _qualification_failure(
                "Qualification trust policy keys must use ascending key_id order"
            )
        if len({key.key_id for key in keys}) != len(keys):
            raise _qualification_failure(
                "Qualification trust policy keys must not repeat key IDs"
            )
        if len({key.public_key for key in keys}) != len(keys):
            raise _qualification_failure(
                "Qualification trust policy keys must use distinct public keys"
            )
        required_uses = set(QualificationAuthorityKeyUse)
        if {key.key_use for key in keys} != required_uses:
            raise _qualification_failure(
                "Qualification trust policy must provide every required key use"
            )
        root_key_id = _auth_value(
            _identifier,
            value.get("root_key_id"),
            "qualification trust policy.root_key_id",
        )
        if root_key_id in {key.key_id for key in keys}:
            raise _qualification_failure(
                "Qualification trust policy must not reuse the root key ID"
            )
        allowed_profile_ids = _sorted_specialist_ids(
            value.get("allowed_profile_ids"),
            "qualification trust policy.allowed_profile_ids",
        )
        allowed_set = set(allowed_profile_ids)
        for key in keys:
            if not set(key.allowed_profile_ids) <= allowed_set:
                raise _qualification_failure(
                    f"Qualification authority key {key.key_id} allows profiles "
                    "outside the policy"
                )
            key_start = _parse_timestamp(key.not_before, key.key_id)
            key_end = _parse_timestamp(key.not_after, key.key_id)
            if key_start < starts or key_end > expires:
                raise _qualification_failure(
                    f"Qualification authority key {key.key_id} exceeds the policy window"
                )
        return cls(
            schema_version=1,
            policy_id=_policy_id(
                value.get("policy_id"),
                "qualification trust policy.policy_id",
            ),
            policy_version=_positive_integer(
                value.get("policy_version"),
                "qualification trust policy.policy_version",
                2_147_483_647,
            ),
            decision_record=_decision_record_binding(
                value.get("decision_record"),
                "qualification trust policy.decision_record",
            ),
            qualification_standard=_standard_binding(
                value.get("qualification_standard"),
                "qualification trust policy.qualification_standard",
            ),
            issuer=_auth_value(
                _identifier,
                value.get("issuer"),
                "qualification trust policy.issuer",
            ),
            audience=_auth_value(
                _identifier,
                value.get("audience"),
                "qualification trust policy.audience",
            ),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            max_reviewer_credential_lifetime_seconds=_positive_integer(
                value.get("max_reviewer_credential_lifetime_seconds"),
                "qualification trust policy.max_reviewer_credential_lifetime_seconds",
                MAX_REVIEWER_CREDENTIAL_LIFETIME_SECONDS,
            ),
            allowed_profile_ids=allowed_profile_ids,
            keys=keys,
            root_key_id=root_key_id,
            signature=_signature(
                value.get("signature"),
                "qualification trust policy.signature",
            ),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "decision_record": dict(self.decision_record),
            "qualification_standard": dict(self.qualification_standard),
            "issuer": self.issuer,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "max_reviewer_credential_lifetime_seconds": (
                self.max_reviewer_credential_lifetime_seconds
            ),
            "allowed_profile_ids": list(self.allowed_profile_ids),
            "keys": [key.to_dict() for key in self.keys],
            "root_key_id": self.root_key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return TRUST_POLICY_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    def key(self, key_id: str) -> QualificationAuthorityKey:
        for key in self.keys:
            if key.key_id == key_id:
                return key
        raise _qualification_failure(
            f"Qualification trust policy does not contain key: {key_id}"
        )


@dataclass(frozen=True)
class QualificationReviewerCredential:
    """Issuer-signed short-lived Ed25519 credential for one reviewer role."""

    schema_version: int
    credential_id: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    issuer: str
    issuer_key_id: str
    reviewer_id: str
    reviewer_role: QualificationReviewerRole
    allowed_profile_ids: tuple[str, ...]
    issued_at: str
    not_before: str
    expires_at: str
    public_key: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationReviewerCredential:
        value = _mapping(raw, "qualification reviewer credential")
        _exact_fields(
            value,
            {
                "schema_version",
                "credential_id",
                "policy_id",
                "policy_version",
                "policy_sha256",
                "issuer",
                "issuer_key_id",
                "reviewer_id",
                "reviewer_role",
                "allowed_profile_ids",
                "issued_at",
                "not_before",
                "expires_at",
                "algorithm",
                "public_key",
                "signature",
            },
            "qualification reviewer credential",
        )
        if value.get("schema_version") != 1:
            raise _qualification_failure(
                "Qualification reviewer credential schema_version must be 1"
            )
        if value.get("algorithm") != "Ed25519":
            raise _qualification_failure(
                "Qualification reviewer credential algorithm must be Ed25519"
            )
        try:
            reviewer_role = QualificationReviewerRole(value.get("reviewer_role"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                "Qualification reviewer credential role is invalid"
            ) from exc
        issued_at = _timestamp_value(
            value.get("issued_at"),
            "qualification reviewer credential.issued_at",
        )
        not_before = _timestamp_value(
            value.get("not_before"),
            "qualification reviewer credential.not_before",
        )
        expires_at = _timestamp_value(
            value.get("expires_at"),
            "qualification reviewer credential.expires_at",
        )
        issued = _parse_timestamp(issued_at, "qualification reviewer credential")
        starts = _parse_timestamp(not_before, "qualification reviewer credential")
        expires = _parse_timestamp(expires_at, "qualification reviewer credential")
        if issued > starts or starts >= expires:
            raise _qualification_failure(
                "Qualification reviewer credential validity window is invalid"
            )
        if (
            int((expires - issued).total_seconds())
            > MAX_REVIEWER_CREDENTIAL_LIFETIME_SECONDS
        ):
            raise _qualification_failure(
                "Qualification reviewer credential exceeds the maximum lifetime"
            )
        return cls(
            schema_version=1,
            credential_id=_credential_id(
                value.get("credential_id"),
                "qualification reviewer credential.credential_id",
            ),
            policy_id=_policy_id(
                value.get("policy_id"),
                "qualification reviewer credential.policy_id",
            ),
            policy_version=_positive_integer(
                value.get("policy_version"),
                "qualification reviewer credential.policy_version",
                2_147_483_647,
            ),
            policy_sha256=_sha256(
                value.get("policy_sha256"),
                "qualification reviewer credential.policy_sha256",
            ),
            issuer=_auth_value(
                _identifier,
                value.get("issuer"),
                "qualification reviewer credential.issuer",
            ),
            issuer_key_id=_auth_value(
                _identifier,
                value.get("issuer_key_id"),
                "qualification reviewer credential.issuer_key_id",
            ),
            reviewer_id=_auth_value(
                _identifier,
                value.get("reviewer_id"),
                "qualification reviewer credential.reviewer_id",
            ),
            reviewer_role=reviewer_role,
            allowed_profile_ids=_sorted_specialist_ids(
                value.get("allowed_profile_ids"),
                "qualification reviewer credential.allowed_profile_ids",
            ),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            public_key=_public_key(
                value.get("public_key"),
                "qualification reviewer credential.public_key",
            ),
            signature=_signature(
                value.get("signature"),
                "qualification reviewer credential.signature",
            ),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "credential_id": self.credential_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "issuer": self.issuer,
            "issuer_key_id": self.issuer_key_id,
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role.value,
            "allowed_profile_ids": list(self.allowed_profile_ids),
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "algorithm": "Ed25519",
            "public_key": self.public_key,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return REVIEWER_CREDENTIAL_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise _qualification_failure("clock must be callable")
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _qualification_failure("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=0)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verification_proof(kind: str, material: dict[str, Any]) -> bytes:
    payload = _canonical_json(
        {
            "kind": kind,
            "material": material,
        }
    ).encode("ascii")
    return hmac.new(
        _VERIFICATION_PROOF_KEY,
        payload,
        hashlib.sha256,
    ).digest()


def _verified_policy_material(
    policy: QualificationTrustPolicy,
    policy_sha256: str,
    root_key_sha256: str,
    verified_at: str,
) -> dict[str, Any]:
    return {
        "policy": policy.to_dict(),
        "policy_sha256": policy_sha256,
        "root_key_sha256": root_key_sha256,
        "verified_at": verified_at,
    }


@dataclass(frozen=True)
class VerifiedQualificationTrustPolicy:
    """Qualification policy authenticated by a separately trusted root."""

    policy: QualificationTrustPolicy
    policy_sha256: str
    root_key_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        expected = _verification_proof(
            "verified_qualification_trust_policy",
            _verified_policy_material(
                self.policy,
                self.policy_sha256,
                self.root_key_sha256,
                self.verified_at,
            ),
        )
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedQualificationTrustPolicy can be created only by "
                "verify_qualification_trust_policy"
            )


def _verified_credential_material(
    credential: QualificationReviewerCredential,
    credential_sha256: str,
    policy_sha256: str,
    issuer_key_sha256: str,
    verified_profile_id: str,
    verified_at: str,
) -> dict[str, Any]:
    return {
        "credential": credential.to_dict(),
        "credential_sha256": credential_sha256,
        "policy_sha256": policy_sha256,
        "issuer_key_sha256": issuer_key_sha256,
        "verified_profile_id": verified_profile_id,
        "verified_at": verified_at,
    }


@dataclass(frozen=True)
class VerifiedQualificationReviewerCredential:
    """Reviewer credential authenticated against a verified policy."""

    credential: QualificationReviewerCredential
    credential_sha256: str
    policy_sha256: str
    issuer_key_sha256: str
    verified_profile_id: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        expected = _verification_proof(
            "verified_qualification_reviewer_credential",
            _verified_credential_material(
                self.credential,
                self.credential_sha256,
                self.policy_sha256,
                self.issuer_key_sha256,
                self.verified_profile_id,
                self.verified_at,
            ),
        )
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedQualificationReviewerCredential can be created only "
                "by verify_qualification_reviewer_credential"
            )

    @property
    def reviewer_id(self) -> str:
        return self.credential.reviewer_id

    @property
    def reviewer_role(self) -> QualificationReviewerRole:
        return self.credential.reviewer_role


def _trusted_root(
    trusted_root_keys: Mapping[str, bytes | Ed25519PublicKey],
    root_key_id: str,
) -> Ed25519PublicKey:
    if not isinstance(trusted_root_keys, Mapping):
        raise _qualification_failure("trusted_root_keys must be a mapping")
    try:
        candidate = trusted_root_keys[root_key_id]
    except KeyError as exc:
        raise _qualification_failure(
            f"Qualification root key is not trusted: {root_key_id}"
        ) from exc
    return _auth_value(
        _strict_ed25519_public_key,
        candidate,
        f"qualification root key {root_key_id}",
    )


def _raw_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def verify_qualification_trust_policy(
    policy: QualificationTrustPolicy,
    trusted_root_keys: Mapping[str, bytes | Ed25519PublicKey],
    *,
    decision_record: Any,
    qualification_standard: Any,
    expected_issuer: str,
    expected_audience: str,
    expected_root_key_id: str,
    minimum_policy_version: int,
    clock: Callable[[], datetime],
) -> VerifiedQualificationTrustPolicy:
    """Authenticate a policy against the approved decision and offline root."""

    from .qualification import QualificationStandard
    from .qualification_authority_decision import (
        QualificationAuthorityDecisionRecord,
    )

    if not isinstance(policy, QualificationTrustPolicy):
        raise _qualification_failure("policy must be a QualificationTrustPolicy")
    policy = QualificationTrustPolicy.from_dict(policy.to_dict())
    if not isinstance(decision_record, QualificationAuthorityDecisionRecord):
        raise _qualification_failure(
            "decision_record must be a QualificationAuthorityDecisionRecord"
        )
    decision_record = QualificationAuthorityDecisionRecord.from_dict(
        decision_record.to_dict()
    )
    if not isinstance(qualification_standard, QualificationStandard):
        raise _qualification_failure(
            "qualification_standard must be a QualificationStandard"
        )
    issuer = _auth_value(_identifier, expected_issuer, "expected_issuer")
    audience = _auth_value(_identifier, expected_audience, "expected_audience")
    root_key_id = _auth_value(
        _identifier,
        expected_root_key_id,
        "expected_root_key_id",
    )
    minimum_version = _positive_integer(
        minimum_policy_version,
        "minimum_policy_version",
        2_147_483_647,
    )
    if policy.issuer != issuer:
        raise _qualification_failure(
            "Qualification trust policy issuer does not match the expected issuer"
        )
    if policy.audience != audience:
        raise _qualification_failure(
            "Qualification trust policy audience does not match the expected audience"
        )
    if policy.root_key_id != root_key_id:
        raise _qualification_failure(
            "Qualification trust policy root key does not match the expected root"
        )
    if policy.policy_version < minimum_version:
        raise _qualification_failure(
            "Qualification trust policy version is older than the required minimum"
        )
    expected_decision_binding = {
        "record_id": decision_record.record_id,
        "sha256": decision_record.record_sha256,
    }
    if policy.decision_record != expected_decision_binding:
        raise _qualification_failure(
            "Qualification trust policy decision record binding is stale"
        )
    expected_standard_binding = {
        "id": qualification_standard.standard_id,
        "version": qualification_standard.standard_version,
        "sha256": qualification_standard.canonical_sha256,
    }
    if policy.qualification_standard != expected_standard_binding:
        raise _qualification_failure(
            "Qualification trust policy standard binding is stale"
        )
    now = _clock_value(clock)
    starts = _parse_timestamp(policy.not_before, "qualification trust policy")
    expires = _parse_timestamp(policy.expires_at, "qualification trust policy")
    if now < starts:
        raise _qualification_failure("Qualification trust policy is not active yet")
    if now >= expires:
        raise _qualification_failure("Qualification trust policy has expired")
    root = _trusted_root(trusted_root_keys, root_key_id)
    root_bytes = _raw_public_key(root)
    for key in policy.keys:
        if hmac.compare_digest(_decode_base64url(key.public_key), root_bytes):
            raise _qualification_failure(
                "Qualification issuer key must not reuse root key material"
            )
    _auth_value(
        _verify_ed25519,
        root,
        policy.signature,
        policy.signing_bytes(),
        "Qualification trust policy",
    )
    verified_at = _format_timestamp(now)
    policy_sha256 = policy.content_sha256
    root_key_sha256 = "sha256:" + hashlib.sha256(root_bytes).hexdigest()
    material = _verified_policy_material(
        policy,
        policy_sha256,
        root_key_sha256,
        verified_at,
    )
    return VerifiedQualificationTrustPolicy(
        policy=policy,
        policy_sha256=policy_sha256,
        root_key_sha256=root_key_sha256,
        verified_at=verified_at,
        _proof=_verification_proof(
            "verified_qualification_trust_policy",
            material,
        ),
    )


def verify_qualification_reviewer_credential(
    credential: QualificationReviewerCredential,
    verified_policy: VerifiedQualificationTrustPolicy,
    *,
    expected_reviewer_id: str,
    expected_role: QualificationReviewerRole | str,
    expected_profile_id: str,
    clock: Callable[[], datetime],
) -> VerifiedQualificationReviewerCredential:
    """Authenticate one role-scoped reviewer credential fail closed."""

    if not isinstance(credential, QualificationReviewerCredential):
        raise _qualification_failure(
            "credential must be a QualificationReviewerCredential"
        )
    credential = QualificationReviewerCredential.from_dict(credential.to_dict())
    if type(verified_policy) is not VerifiedQualificationTrustPolicy:
        raise _qualification_failure(
            "verified_policy must be a VerifiedQualificationTrustPolicy"
        )
    try:
        VerifiedQualificationTrustPolicy.__post_init__(verified_policy)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification trust policy proof is invalid"
        ) from exc
    reviewer_id = _auth_value(
        _identifier,
        expected_reviewer_id,
        "expected_reviewer_id",
    )
    try:
        role = QualificationReviewerRole(expected_role)
    except (TypeError, ValueError) as exc:
        raise _qualification_failure("expected_role is invalid") from exc
    profile_id = _specialist_id(expected_profile_id, "expected_profile_id")
    policy = QualificationTrustPolicy.from_dict(verified_policy.policy.to_dict())
    if policy.content_sha256 != verified_policy.policy_sha256:
        raise _qualification_failure(
            "Verified qualification trust policy digest is invalid"
        )
    if (
        credential.policy_id != policy.policy_id
        or credential.policy_version != policy.policy_version
        or credential.policy_sha256 != verified_policy.policy_sha256
    ):
        raise _qualification_failure(
            "Qualification reviewer credential policy binding is stale"
        )
    if credential.issuer != policy.issuer:
        raise _qualification_failure(
            "Qualification reviewer credential issuer does not match the policy"
        )
    if credential.reviewer_id != reviewer_id:
        raise _qualification_failure(
            "Qualification reviewer credential reviewer does not match the expected reviewer"
        )
    if credential.reviewer_role is not role:
        raise _qualification_failure(
            "Qualification reviewer credential role does not match the expected role"
        )
    if profile_id not in credential.allowed_profile_ids:
        raise _qualification_failure(
            "Qualification reviewer credential does not allow the expected profile"
        )
    if profile_id not in policy.allowed_profile_ids:
        raise _qualification_failure(
            "Qualification trust policy does not allow the expected profile"
        )
    issuer_key = policy.key(credential.issuer_key_id)
    if issuer_key.key_use is not QualificationAuthorityKeyUse.REVIEWER_CREDENTIAL_ISSUER:
        raise _qualification_failure(
            "Qualification reviewer credential key use is not authorized"
        )
    if issuer_key.state is QualificationAuthorityKeyState.REVOKED:
        raise _qualification_failure(
            "Qualification reviewer credential issuer key is revoked"
        )
    if role not in issuer_key.allowed_roles:
        raise _qualification_failure(
            "Qualification reviewer role is not allowed by the issuer key"
        )
    if not set(credential.allowed_profile_ids) <= set(
        issuer_key.allowed_profile_ids
    ):
        raise _qualification_failure(
            "Qualification reviewer credential profiles exceed the issuer key scope"
        )
    issued = _parse_timestamp(
        credential.issued_at,
        "qualification reviewer credential",
    )
    starts = _parse_timestamp(
        credential.not_before,
        "qualification reviewer credential",
    )
    expires = _parse_timestamp(
        credential.expires_at,
        "qualification reviewer credential",
    )
    policy_start = _parse_timestamp(policy.not_before, "qualification trust policy")
    policy_end = _parse_timestamp(policy.expires_at, "qualification trust policy")
    key_start = _parse_timestamp(issuer_key.not_before, issuer_key.key_id)
    key_end = _parse_timestamp(issuer_key.not_after, issuer_key.key_id)
    if starts < policy_start or expires > policy_end:
        raise _qualification_failure(
            "Qualification reviewer credential exceeds the policy window"
        )
    if issued < key_start or expires > key_end:
        raise _qualification_failure(
            "Qualification reviewer credential exceeds the issuer key window"
        )
    if (
        int((expires - issued).total_seconds())
        > policy.max_reviewer_credential_lifetime_seconds
    ):
        raise _qualification_failure(
            "Qualification reviewer credential exceeds the policy lifetime"
        )
    if (
        issuer_key.state is QualificationAuthorityKeyState.RETIRING
        and (
            issuer_key.retire_at is None
            or issued
            >= _parse_timestamp(
                issuer_key.retire_at,
                issuer_key.key_id,
            )
        )
    ):
        raise _qualification_failure(
            "Qualification reviewer credential was issued after key retirement"
        )
    now = _clock_value(clock)
    if now < starts:
        raise _qualification_failure(
            "Qualification reviewer credential is not active yet"
        )
    if now >= expires:
        raise _qualification_failure(
            "Qualification reviewer credential has expired"
        )
    credential_public_key = _decode_base64url(credential.public_key)
    for key in policy.keys:
        if hmac.compare_digest(
            credential_public_key,
            _decode_base64url(key.public_key),
        ):
            raise _qualification_failure(
                "Qualification reviewer credential must not reuse authority key material"
            )
    issuer_public_key = _auth_value(
        _strict_ed25519_public_key,
        _decode_base64url(issuer_key.public_key),
        f"qualification issuer key {issuer_key.key_id}",
    )
    _auth_value(
        _verify_ed25519,
        issuer_public_key,
        credential.signature,
        credential.signing_bytes(),
        "Qualification reviewer credential",
    )
    verified_at = _format_timestamp(now)
    credential_sha256 = credential.content_sha256
    issuer_key_sha256 = issuer_key.content_sha256
    material = _verified_credential_material(
        credential,
        credential_sha256,
        verified_policy.policy_sha256,
        issuer_key_sha256,
        profile_id,
        verified_at,
    )
    return VerifiedQualificationReviewerCredential(
        credential=credential,
        credential_sha256=credential_sha256,
        policy_sha256=verified_policy.policy_sha256,
        issuer_key_sha256=issuer_key_sha256,
        verified_profile_id=profile_id,
        verified_at=verified_at,
        _proof=_verification_proof(
            "verified_qualification_reviewer_credential",
            material,
        ),
    )


def _load_contract(path: str | Path, label: str) -> Any:
    resolved = Path(path)
    try:
        return loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise _qualification_failure(f"Could not load {label}: {resolved}") from exc


def load_qualification_trust_policy(
    path: str | Path,
) -> QualificationTrustPolicy:
    return QualificationTrustPolicy.from_dict(
        _load_contract(path, "qualification trust policy")
    )


def load_qualification_reviewer_credential(
    path: str | Path,
) -> QualificationReviewerCredential:
    return QualificationReviewerCredential.from_dict(
        _load_contract(path, "qualification reviewer credential")
    )


__all__ = [
    "MAX_REVIEWER_CREDENTIAL_LIFETIME_SECONDS",
    "QualificationAuthorityKey",
    "QualificationAuthorityKeyState",
    "QualificationAuthorityKeyUse",
    "QualificationReviewerCredential",
    "QualificationReviewerRole",
    "QualificationTrustPolicy",
    "VerifiedQualificationReviewerCredential",
    "VerifiedQualificationTrustPolicy",
    "load_qualification_reviewer_credential",
    "load_qualification_trust_policy",
    "verify_qualification_reviewer_credential",
    "verify_qualification_trust_policy",
]
