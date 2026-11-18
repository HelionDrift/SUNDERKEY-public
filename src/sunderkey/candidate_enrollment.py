"""Signed candidate enrollment authority and catalog contracts."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .identity import _decode_base64url, _identifier
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .qualification_trust import (
    QualificationReviewerRole,
    _auth_value,
    _parse_timestamp,
    _positive_integer,
    _public_key,
    _sha256,
    _signature,
    _specialist_id,
    _timestamp_value,
)
from .validation import loads_json_without_duplicate_keys

ENROLLMENT_SIGNER_AUTHORIZATION_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00CANDIDATE-ENROLLMENT-SIGNER-AUTHORIZATION\x00V1\x00"
)
ENROLLMENT_CATALOG_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00CANDIDATE-ENROLLMENT-CATALOG\x00V1\x00"
)
ENROLLMENT_RELEASE_REVIEW_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00CANDIDATE-ENROLLMENT-RELEASE-REVIEW\x00V1\x00"
)
ENROLLMENT_ENTRY_DOMAIN = "sunderkey.candidate-enrollment-entry.v1"
ENROLLMENT_RELEASE_BODY_DOMAIN = "sunderkey.candidate-enrollment-release-body.v1"

_AUTHORIZATION_ID_PATTERN = re.compile(r"CEA-[0-9A-F]{32}")
_CATALOG_ID_PATTERN = re.compile(r"CEC-[0-9A-F]{32}")
_ENROLLMENT_ID_PATTERN = re.compile(r"CEE-[0-9A-F]{32}")
_ROTATION_ID_PATTERN = re.compile(r"CRO-[0-9A-F]{32}")
_REVOCATION_ID_PATTERN = re.compile(r"CRV-[0-9A-F]{32}")
_D008_RECORD_ID_PATTERN = re.compile(r"QDR-[0-9A-F]{32}")
_D009_RECORD_ID_PATTERN = re.compile(r"CER-[0-9A-F]{32}")


class CandidateEnrollmentSignerKeyState(StrEnum):
    """Lifecycle state for a separated enrollment catalog signer."""

    ACTIVE = "active"
    RETIRING = "retiring"
    REVOKED = "revoked"


class CandidateEnrollmentRotationKind(StrEnum):
    """Identity surface changed by a reviewed overlap record."""

    OWNER_KEY = "owner_key"
    REPOSITORY_IDENTITY = "repository_identity"


class CandidateEnrollmentRevocationKind(StrEnum):
    """Catalog subject that can be revoked."""

    ENROLLMENT = "enrollment"
    OWNER_KEY = "owner_key"
    REPOSITORY_IDENTITY = "repository_identity"


def _pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise QualificationError(f"{label} is invalid")
    return value


def _decision_binding(
    raw: Any,
    label: str,
    pattern: re.Pattern[str],
) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"record_id", "sha256"}, label)
    return {
        "record_id": _pattern(value.get("record_id"), pattern, f"{label}.record_id"),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _authorization_binding(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(
        value,
        {"authorization_id", "authorization_version", "sha256"},
        label,
    )
    return {
        "authorization_id": _pattern(
            value.get("authorization_id"),
            _AUTHORIZATION_ID_PATTERN,
            f"{label}.authorization_id",
        ),
        "authorization_version": _positive_integer(
            value.get("authorization_version"),
            f"{label}.authorization_version",
            2_147_483_647,
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _policy_binding(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, {"policy_id", "policy_version", "sha256"}, label)
    policy_id = value.get("policy_id")
    if not isinstance(policy_id, str) or re.fullmatch(r"QTP-[0-9A-F]{32}", policy_id) is None:
        raise QualificationError(f"{label}.policy_id is invalid")
    return {
        "policy_id": policy_id,
        "policy_version": _positive_integer(
            value.get("policy_version"),
            f"{label}.policy_version",
            2_147_483_647,
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _credential_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"credential_id", "sha256"}, label)
    credential_id = value.get("credential_id")
    if (
        not isinstance(credential_id, str)
        or re.fullmatch(r"QRC-[0-9A-F]{32}", credential_id) is None
    ):
        raise QualificationError(f"{label}.credential_id is invalid")
    return {
        "credential_id": credential_id,
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _candidate_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(
        value,
        {"candidate_id", "candidate_version", "candidate_artifact_sha256"},
        label,
    )
    return {
        "candidate_id": _auth_value(
            _identifier,
            value.get("candidate_id"),
            f"{label}.candidate_id",
        ),
        "candidate_version": _auth_value(
            _identifier,
            value.get("candidate_version"),
            f"{label}.candidate_version",
        ),
        "candidate_artifact_sha256": _sha256(
            value.get("candidate_artifact_sha256"),
            f"{label}.candidate_artifact_sha256",
        ),
    }


def _entry_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"enrollment_id", "sha256"}, label)
    return {
        "enrollment_id": _pattern(
            value.get("enrollment_id"),
            _ENROLLMENT_ID_PATTERN,
            f"{label}.enrollment_id",
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


@dataclass(frozen=True)
class CandidateEnrollmentSignerKey:
    """Root-authorized public key for only enrollment catalog releases."""

    key_id: str
    issuer: str
    public_key: str
    state: CandidateEnrollmentSignerKeyState
    not_before: str
    not_after: str
    retire_at: str | None

    @classmethod
    def from_dict(cls, raw: Any, *, label: str) -> CandidateEnrollmentSignerKey:
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
            },
            label,
        )
        if value.get("algorithm") != "Ed25519":
            raise QualificationError(f"{label}.algorithm must be Ed25519")
        if value.get("key_use") != "candidate_enrollment_catalog":
            raise QualificationError(f"{label}.key_use is invalid")
        try:
            state = CandidateEnrollmentSignerKeyState(value.get("state"))
        except (TypeError, ValueError) as exc:
            raise QualificationError(f"{label}.state is invalid") from exc
        not_before = _timestamp_value(value.get("not_before"), f"{label}.not_before")
        not_after = _timestamp_value(value.get("not_after"), f"{label}.not_after")
        if _parse_timestamp(not_before, label) >= _parse_timestamp(not_after, label):
            raise QualificationError(f"{label} validity window is invalid")
        retire_raw = value.get("retire_at")
        retire_at = (
            None
            if retire_raw is None
            else _timestamp_value(retire_raw, f"{label}.retire_at")
        )
        if state is CandidateEnrollmentSignerKeyState.RETIRING:
            if retire_at is None:
                raise QualificationError(f"{label}.retire_at is required")
            retirement = _parse_timestamp(retire_at, label)
            if not (
                _parse_timestamp(not_before, label)
                <= retirement
                < _parse_timestamp(not_after, label)
            ):
                raise QualificationError(f"{label}.retire_at is outside the key window")
        elif retire_at is not None:
            raise QualificationError(f"{label}.retire_at requires retiring state")
        return cls(
            key_id=_auth_value(_identifier, value.get("key_id"), f"{label}.key_id"),
            issuer=_auth_value(_identifier, value.get("issuer"), f"{label}.issuer"),
            public_key=_public_key(value.get("public_key"), f"{label}.public_key"),
            state=state,
            not_before=not_before,
            not_after=not_after,
            retire_at=retire_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "issuer": self.issuer,
            "public_key": self.public_key,
            "algorithm": "Ed25519",
            "key_use": "candidate_enrollment_catalog",
            "state": self.state.value,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "retire_at": self.retire_at,
        }

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


@dataclass(frozen=True)
class CandidateEnrollmentSignerAuthorization:
    """Offline-root-signed authorization for separated catalog signers."""

    authorization_id: str
    authorization_version: int
    d008_decision: dict[str, str]
    d009_decision: dict[str, str]
    issuer: str
    audience: str
    issued_at: str
    not_before: str
    expires_at: str
    keys: tuple[CandidateEnrollmentSignerKey, ...]
    root_key_id: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentSignerAuthorization:
        value = _mapping(raw, "candidate enrollment signer authorization")
        _exact_fields(
            value,
            {
                "schema_version",
                "authorization_id",
                "authorization_version",
                "d008_decision",
                "d009_decision",
                "issuer",
                "audience",
                "issued_at",
                "not_before",
                "expires_at",
                "keys",
                "root_key_id",
                "algorithm",
                "signature",
            },
            "candidate enrollment signer authorization",
        )
        if value.get("schema_version") != 1:
            raise QualificationError("Candidate enrollment authorization schema is invalid")
        if value.get("algorithm") != "Ed25519":
            raise QualificationError("Candidate enrollment authorization algorithm is invalid")
        issued_at = _timestamp_value(value.get("issued_at"), "authorization.issued_at")
        not_before = _timestamp_value(value.get("not_before"), "authorization.not_before")
        expires_at = _timestamp_value(value.get("expires_at"), "authorization.expires_at")
        issued = _parse_timestamp(issued_at, "authorization")
        starts = _parse_timestamp(not_before, "authorization")
        expires = _parse_timestamp(expires_at, "authorization")
        if issued > starts or starts >= expires:
            raise QualificationError("Candidate enrollment authorization window is invalid")
        raw_keys = value.get("keys")
        if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= 64:
            raise QualificationError("Candidate enrollment authorization keys are invalid")
        keys = tuple(
            CandidateEnrollmentSignerKey.from_dict(item, label=f"authorization.keys[{index}]")
            for index, item in enumerate(raw_keys)
        )
        if tuple(key.key_id for key in keys) != tuple(sorted(key.key_id for key in keys)):
            raise QualificationError("Candidate enrollment signer keys must use ascending order")
        if len({key.key_id for key in keys}) != len(keys):
            raise QualificationError("Candidate enrollment signer key IDs must be unique")
        if len({key.public_key for key in keys}) != len(keys):
            raise QualificationError("Candidate enrollment signer public keys must be unique")
        issuer = _auth_value(_identifier, value.get("issuer"), "authorization.issuer")
        for key in keys:
            if key.issuer != issuer:
                raise QualificationError("Candidate enrollment signer issuer is inconsistent")
            if (
                _parse_timestamp(key.not_before, key.key_id) < starts
                or _parse_timestamp(key.not_after, key.key_id) > expires
            ):
                raise QualificationError("Candidate enrollment signer exceeds authorization window")
        return cls(
            authorization_id=_pattern(
                value.get("authorization_id"),
                _AUTHORIZATION_ID_PATTERN,
                "authorization.authorization_id",
            ),
            authorization_version=_positive_integer(
                value.get("authorization_version"),
                "authorization.authorization_version",
                2_147_483_647,
            ),
            d008_decision=_decision_binding(
                value.get("d008_decision"),
                "authorization.d008_decision",
                _D008_RECORD_ID_PATTERN,
            ),
            d009_decision=_decision_binding(
                value.get("d009_decision"),
                "authorization.d009_decision",
                _D009_RECORD_ID_PATTERN,
            ),
            issuer=issuer,
            audience=_auth_value(_identifier, value.get("audience"), "authorization.audience"),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            keys=keys,
            root_key_id=_auth_value(
                _identifier,
                value.get("root_key_id"),
                "authorization.root_key_id",
            ),
            signature=_signature(value.get("signature"), "authorization.signature"),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "authorization_id": self.authorization_id,
            "authorization_version": self.authorization_version,
            "d008_decision": self.d008_decision,
            "d009_decision": self.d009_decision,
            "issuer": self.issuer,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "keys": [key.to_dict() for key in self.keys],
            "root_key_id": self.root_key_id,
            "algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return ENROLLMENT_SIGNER_AUTHORIZATION_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    def key(self, key_id: str) -> CandidateEnrollmentSignerKey:
        for key in self.keys:
            if key.key_id == key_id:
                return key
        raise QualificationError(f"Candidate enrollment signer key is unknown: {key_id}")


@dataclass(frozen=True)
class CandidateEnrollmentEntry:
    """One exact candidate owner and logical evidence repository binding."""

    enrollment_id: str
    profile_id: str
    candidate: dict[str, str]
    owner: dict[str, str]
    repository: dict[str, str]
    not_before: str
    expires_at: str
    predecessor: dict[str, str] | None

    @classmethod
    def from_dict(cls, raw: Any, *, label: str) -> CandidateEnrollmentEntry:
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "enrollment_id",
                "profile_id",
                "candidate",
                "owner",
                "repository",
                "not_before",
                "expires_at",
                "predecessor",
            },
            label,
        )
        owner_raw = _mapping(value.get("owner"), f"{label}.owner")
        _exact_fields(
            owner_raw,
            {"owner_id", "key_id", "public_key", "public_key_sha256"},
            f"{label}.owner",
        )
        owner_public_key = _public_key(
            owner_raw.get("public_key"),
            f"{label}.owner.public_key",
        )
        owner_public_key_sha256 = _sha256(
            owner_raw.get("public_key_sha256"),
            f"{label}.owner.public_key_sha256",
        )
        expected_owner_digest = "sha256:" + hashlib.sha256(
            _decode_base64url(owner_public_key)
        ).hexdigest()
        if owner_public_key_sha256 != expected_owner_digest:
            raise QualificationError(f"{label}.owner public key digest is invalid")
        repository_raw = _mapping(value.get("repository"), f"{label}.repository")
        _exact_fields(
            repository_raw,
            {"repository_id", "content_address_scheme"},
            f"{label}.repository",
        )
        if repository_raw.get("content_address_scheme") != "sha256":
            raise QualificationError(f"{label}.repository content address scheme is invalid")
        not_before = _timestamp_value(value.get("not_before"), f"{label}.not_before")
        expires_at = _timestamp_value(value.get("expires_at"), f"{label}.expires_at")
        if _parse_timestamp(not_before, label) >= _parse_timestamp(expires_at, label):
            raise QualificationError(f"{label} validity window is invalid")
        predecessor_raw = value.get("predecessor")
        predecessor = (
            None
            if predecessor_raw is None
            else _entry_binding(predecessor_raw, f"{label}.predecessor")
        )
        return cls(
            enrollment_id=_pattern(
                value.get("enrollment_id"),
                _ENROLLMENT_ID_PATTERN,
                f"{label}.enrollment_id",
            ),
            profile_id=_specialist_id(value.get("profile_id"), f"{label}.profile_id"),
            candidate=_candidate_binding(value.get("candidate"), f"{label}.candidate"),
            owner={
                "owner_id": _auth_value(
                    _identifier,
                    owner_raw.get("owner_id"),
                    f"{label}.owner.owner_id",
                ),
                "key_id": _auth_value(
                    _identifier,
                    owner_raw.get("key_id"),
                    f"{label}.owner.key_id",
                ),
                "public_key": owner_public_key,
                "public_key_sha256": owner_public_key_sha256,
            },
            repository={
                "repository_id": _auth_value(
                    _identifier,
                    repository_raw.get("repository_id"),
                    f"{label}.repository.repository_id",
                ),
                "content_address_scheme": "sha256",
            },
            not_before=not_before,
            expires_at=expires_at,
            predecessor=predecessor,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enrollment_id": self.enrollment_id,
            "profile_id": self.profile_id,
            "candidate": self.candidate,
            "owner": self.owner,
            "repository": self.repository,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "predecessor": self.predecessor,
        }

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(
            {"domain": ENROLLMENT_ENTRY_DOMAIN, "enrollment": self.to_dict()}
        )


@dataclass(frozen=True)
class CandidateEnrollmentRotation:
    """Reviewed predecessor-successor overlap for one changed identity."""

    rotation_id: str
    rotation_kind: CandidateEnrollmentRotationKind
    predecessor: dict[str, str]
    successor: dict[str, str]
    overlap_not_before: str
    overlap_expires_at: str

    @classmethod
    def from_dict(cls, raw: Any, *, label: str) -> CandidateEnrollmentRotation:
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "rotation_id",
                "rotation_kind",
                "predecessor",
                "successor",
                "overlap_not_before",
                "overlap_expires_at",
            },
            label,
        )
        try:
            kind = CandidateEnrollmentRotationKind(value.get("rotation_kind"))
        except (TypeError, ValueError) as exc:
            raise QualificationError(f"{label}.rotation_kind is invalid") from exc
        overlap_not_before = _timestamp_value(
            value.get("overlap_not_before"),
            f"{label}.overlap_not_before",
        )
        overlap_expires_at = _timestamp_value(
            value.get("overlap_expires_at"),
            f"{label}.overlap_expires_at",
        )
        if _parse_timestamp(overlap_not_before, label) >= _parse_timestamp(
            overlap_expires_at,
            label,
        ):
            raise QualificationError(f"{label} overlap window is invalid")
        return cls(
            rotation_id=_pattern(
                value.get("rotation_id"),
                _ROTATION_ID_PATTERN,
                f"{label}.rotation_id",
            ),
            rotation_kind=kind,
            predecessor=_entry_binding(value.get("predecessor"), f"{label}.predecessor"),
            successor=_entry_binding(value.get("successor"), f"{label}.successor"),
            overlap_not_before=overlap_not_before,
            overlap_expires_at=overlap_expires_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rotation_id": self.rotation_id,
            "rotation_kind": self.rotation_kind.value,
            "predecessor": self.predecessor,
            "successor": self.successor,
            "overlap_not_before": self.overlap_not_before,
            "overlap_expires_at": self.overlap_expires_at,
        }


@dataclass(frozen=True)
class CandidateEnrollmentRevocation:
    """Signed-catalog revocation of one exact enrollment subject."""

    revocation_id: str
    revocation_kind: CandidateEnrollmentRevocationKind
    subject_id: str
    effective_at: str
    recorded_at: str
    reason_sha256: str

    @classmethod
    def from_dict(cls, raw: Any, *, label: str) -> CandidateEnrollmentRevocation:
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "revocation_id",
                "revocation_kind",
                "subject_id",
                "effective_at",
                "recorded_at",
                "reason_sha256",
            },
            label,
        )
        try:
            kind = CandidateEnrollmentRevocationKind(value.get("revocation_kind"))
        except (TypeError, ValueError) as exc:
            raise QualificationError(f"{label}.revocation_kind is invalid") from exc
        effective_at = _timestamp_value(value.get("effective_at"), f"{label}.effective_at")
        recorded_at = _timestamp_value(value.get("recorded_at"), f"{label}.recorded_at")
        if _parse_timestamp(recorded_at, label) > _parse_timestamp(effective_at, label):
            raise QualificationError(f"{label} must be recorded before it becomes effective")
        return cls(
            revocation_id=_pattern(
                value.get("revocation_id"),
                _REVOCATION_ID_PATTERN,
                f"{label}.revocation_id",
            ),
            revocation_kind=kind,
            subject_id=_auth_value(
                _identifier,
                value.get("subject_id"),
                f"{label}.subject_id",
            ),
            effective_at=effective_at,
            recorded_at=recorded_at,
            reason_sha256=_sha256(value.get("reason_sha256"), f"{label}.reason_sha256"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "revocation_id": self.revocation_id,
            "revocation_kind": self.revocation_kind.value,
            "subject_id": self.subject_id,
            "effective_at": self.effective_at,
            "recorded_at": self.recorded_at,
            "reason_sha256": self.reason_sha256,
        }


@dataclass(frozen=True)
class CandidateEnrollmentReleaseReview:
    """Independent approval binding for one exact catalog release body."""

    reviewer_id: str
    reviewer_role: QualificationReviewerRole
    credential: dict[str, str]
    reviewed_at: str
    release_body_sha256: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any, *, label: str) -> CandidateEnrollmentReleaseReview:
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "reviewer_id",
                "reviewer_role",
                "credential",
                "reviewed_at",
                "decision",
                "release_body_sha256",
                "algorithm",
                "signature",
            },
            label,
        )
        try:
            role = QualificationReviewerRole(value.get("reviewer_role"))
        except (TypeError, ValueError) as exc:
            raise QualificationError(f"{label}.reviewer_role is invalid") from exc
        if role not in {
            QualificationReviewerRole.INDEPENDENT_CONTROL,
            QualificationReviewerRole.INDEPENDENT_ASSURANCE,
        }:
            raise QualificationError(f"{label}.reviewer_role is not an enrollment review role")
        if value.get("decision") != "approved":
            raise QualificationError(f"{label}.decision must be approved")
        if value.get("algorithm") != "Ed25519":
            raise QualificationError(f"{label}.algorithm must be Ed25519")
        return cls(
            reviewer_id=_auth_value(
                _identifier,
                value.get("reviewer_id"),
                f"{label}.reviewer_id",
            ),
            reviewer_role=role,
            credential=_credential_binding(
                value.get("credential"),
                f"{label}.credential",
            ),
            reviewed_at=_timestamp_value(value.get("reviewed_at"), f"{label}.reviewed_at"),
            release_body_sha256=_sha256(
                value.get("release_body_sha256"),
                f"{label}.release_body_sha256",
            ),
            signature=_signature(value.get("signature"), f"{label}.signature"),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role.value,
            "credential": self.credential,
            "reviewed_at": self.reviewed_at,
            "decision": "approved",
            "release_body_sha256": self.release_body_sha256,
            "algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return ENROLLMENT_RELEASE_REVIEW_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


@dataclass(frozen=True)
class CandidateEnrollmentCatalog:
    """Versioned, reviewed, signer-authenticated enrollment release."""

    catalog_id: str
    catalog_version: int
    previous_catalog_sha256: str | None
    authorization: dict[str, Any]
    d009_decision: dict[str, str]
    qualification_policy: dict[str, Any]
    issuer: str
    audience: str
    issued_at: str
    not_before: str
    expires_at: str
    enrollments: tuple[CandidateEnrollmentEntry, ...]
    rotations: tuple[CandidateEnrollmentRotation, ...]
    revocations: tuple[CandidateEnrollmentRevocation, ...]
    release_body_sha256: str
    reviews: tuple[CandidateEnrollmentReleaseReview, ...]
    signer_key_id: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentCatalog:
        value = _mapping(raw, "candidate enrollment catalog")
        fields = {
            "schema_version",
            "catalog_id",
            "catalog_version",
            "previous_catalog_sha256",
            "authorization",
            "d009_decision",
            "qualification_policy",
            "issuer",
            "audience",
            "issued_at",
            "not_before",
            "expires_at",
            "enrollments",
            "rotations",
            "revocations",
            "release_body_sha256",
            "reviews",
            "signer_key_id",
            "algorithm",
            "signature",
        }
        _exact_fields(value, fields, "candidate enrollment catalog")
        if value.get("schema_version") != 1:
            raise QualificationError("Candidate enrollment catalog schema is invalid")
        if value.get("algorithm") != "Ed25519":
            raise QualificationError("Candidate enrollment catalog algorithm is invalid")
        catalog_version = _positive_integer(
            value.get("catalog_version"),
            "catalog.catalog_version",
            2_147_483_647,
        )
        previous_raw = value.get("previous_catalog_sha256")
        previous = (
            None
            if previous_raw is None
            else _sha256(previous_raw, "catalog.previous_catalog_sha256")
        )
        if (catalog_version == 1) != (previous is None):
            raise QualificationError("Candidate enrollment catalog predecessor is invalid")
        issued_at = _timestamp_value(value.get("issued_at"), "catalog.issued_at")
        not_before = _timestamp_value(value.get("not_before"), "catalog.not_before")
        expires_at = _timestamp_value(value.get("expires_at"), "catalog.expires_at")
        issued = _parse_timestamp(issued_at, "catalog")
        starts = _parse_timestamp(not_before, "catalog")
        expires = _parse_timestamp(expires_at, "catalog")
        if issued > starts or starts >= expires:
            raise QualificationError("Candidate enrollment catalog window is invalid")
        raw_enrollments = value.get("enrollments")
        if not isinstance(raw_enrollments, list) or not 1 <= len(raw_enrollments) <= 4096:
            raise QualificationError("Candidate enrollment catalog enrollments are invalid")
        enrollments = tuple(
            CandidateEnrollmentEntry.from_dict(item, label=f"catalog.enrollments[{index}]")
            for index, item in enumerate(raw_enrollments)
        )
        _require_sorted_unique(enrollments, "enrollment_id", "enrollments")
        for entry in enrollments:
            if (
                _parse_timestamp(entry.not_before, entry.enrollment_id) < starts
                or _parse_timestamp(entry.expires_at, entry.enrollment_id) > expires
            ):
                raise QualificationError("Candidate enrollment exceeds the catalog window")
        rotations = _record_list(
            value.get("rotations"),
            CandidateEnrollmentRotation,
            "rotations",
            "rotation_id",
        )
        revocations = _record_list(
            value.get("revocations"),
            CandidateEnrollmentRevocation,
            "revocations",
            "revocation_id",
        )
        _validate_entry_chain(enrollments, rotations)
        _validate_revocation_subjects(enrollments, revocations)
        body = {
            "schema_version": 1,
            "catalog_id": _pattern(
                value.get("catalog_id"),
                _CATALOG_ID_PATTERN,
                "catalog.catalog_id",
            ),
            "catalog_version": catalog_version,
            "previous_catalog_sha256": previous,
            "authorization": _authorization_binding(
                value.get("authorization"),
                "catalog.authorization",
            ),
            "d009_decision": _decision_binding(
                value.get("d009_decision"),
                "catalog.d009_decision",
                _D009_RECORD_ID_PATTERN,
            ),
            "qualification_policy": _policy_binding(
                value.get("qualification_policy"),
                "catalog.qualification_policy",
            ),
            "issuer": _auth_value(_identifier, value.get("issuer"), "catalog.issuer"),
            "audience": _auth_value(_identifier, value.get("audience"), "catalog.audience"),
            "issued_at": issued_at,
            "not_before": not_before,
            "expires_at": expires_at,
            "enrollments": [entry.to_dict() for entry in enrollments],
            "rotations": [rotation.to_dict() for rotation in rotations],
            "revocations": [revocation.to_dict() for revocation in revocations],
        }
        expected_release_hash = _canonical_sha256(
            {"domain": ENROLLMENT_RELEASE_BODY_DOMAIN, "release": body}
        )
        release_body_sha256 = _sha256(
            value.get("release_body_sha256"),
            "catalog.release_body_sha256",
        )
        if release_body_sha256 != expected_release_hash:
            raise QualificationError("Candidate enrollment release body digest is invalid")
        raw_reviews = value.get("reviews")
        if not isinstance(raw_reviews, list) or len(raw_reviews) != 2:
            raise QualificationError("Candidate enrollment catalog requires two reviews")
        reviews = tuple(
            CandidateEnrollmentReleaseReview.from_dict(item, label=f"catalog.reviews[{index}]")
            for index, item in enumerate(raw_reviews)
        )
        expected_roles = (
            QualificationReviewerRole.INDEPENDENT_ASSURANCE,
            QualificationReviewerRole.INDEPENDENT_CONTROL,
        )
        if tuple(review.reviewer_role for review in reviews) != expected_roles:
            raise QualificationError("Candidate enrollment reviews must use canonical role order")
        if len({review.reviewer_id for review in reviews}) != 2:
            raise QualificationError("Candidate enrollment reviewers must be distinct")
        if any(review.release_body_sha256 != release_body_sha256 for review in reviews):
            raise QualificationError("Candidate enrollment review binding is stale")
        if any(_parse_timestamp(review.reviewed_at, "review") > issued for review in reviews):
            raise QualificationError("Candidate enrollment review occurred after catalog issuance")
        return cls(
            catalog_id=body["catalog_id"],
            catalog_version=catalog_version,
            previous_catalog_sha256=previous,
            authorization=body["authorization"],
            d009_decision=body["d009_decision"],
            qualification_policy=body["qualification_policy"],
            issuer=body["issuer"],
            audience=body["audience"],
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            enrollments=enrollments,
            rotations=rotations,
            revocations=revocations,
            release_body_sha256=release_body_sha256,
            reviews=reviews,
            signer_key_id=_auth_value(
                _identifier,
                value.get("signer_key_id"),
                "catalog.signer_key_id",
            ),
            signature=_signature(value.get("signature"), "catalog.signature"),
        )

    def release_body_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "catalog_id": self.catalog_id,
            "catalog_version": self.catalog_version,
            "previous_catalog_sha256": self.previous_catalog_sha256,
            "authorization": self.authorization,
            "d009_decision": self.d009_decision,
            "qualification_policy": self.qualification_policy,
            "issuer": self.issuer,
            "audience": self.audience,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "enrollments": [entry.to_dict() for entry in self.enrollments],
            "rotations": [rotation.to_dict() for rotation in self.rotations],
            "revocations": [revocation.to_dict() for revocation in self.revocations],
        }

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            **self.release_body_dict(),
            "release_body_sha256": self.release_body_sha256,
            "reviews": [review.to_dict() for review in self.reviews],
            "signer_key_id": self.signer_key_id,
            "algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return ENROLLMENT_CATALOG_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    def enrollment(self, enrollment_id: str) -> CandidateEnrollmentEntry:
        for entry in self.enrollments:
            if entry.enrollment_id == enrollment_id:
                return entry
        raise QualificationError(f"Candidate enrollment is unknown: {enrollment_id}")


def _require_sorted_unique(records: tuple[Any, ...], field: str, label: str) -> None:
    values = tuple(getattr(record, field) for record in records)
    if values != tuple(sorted(values)):
        raise QualificationError(f"Candidate enrollment {label} must use ascending order")
    if len(values) != len(set(values)):
        raise QualificationError(f"Candidate enrollment {label} must be unique")


def _record_list(
    raw: Any,
    record_type: type[Any],
    label: str,
    identifier_field: str,
) -> tuple[Any, ...]:
    if not isinstance(raw, list) or len(raw) > 4096:
        raise QualificationError(f"Candidate enrollment catalog {label} are invalid")
    records = tuple(
        record_type.from_dict(item, label=f"catalog.{label}[{index}]")
        for index, item in enumerate(raw)
    )
    _require_sorted_unique(records, identifier_field, label)
    return records


def _validate_entry_chain(
    enrollments: tuple[CandidateEnrollmentEntry, ...],
    rotations: tuple[CandidateEnrollmentRotation, ...],
) -> None:
    by_id = {entry.enrollment_id: entry for entry in enrollments}
    for entry in enrollments:
        if entry.predecessor is None:
            continue
        predecessor = by_id.get(entry.predecessor["enrollment_id"])
        if predecessor is None or predecessor.content_sha256 != entry.predecessor["sha256"]:
            raise QualificationError("Candidate enrollment predecessor is unknown or stale")
        if (
            predecessor.profile_id != entry.profile_id
            or predecessor.candidate != entry.candidate
        ):
            raise QualificationError(
                "Candidate enrollment predecessor escapes exact candidate scope"
            )
    successor_ids: set[str] = set()
    for rotation in rotations:
        predecessor = by_id.get(rotation.predecessor["enrollment_id"])
        successor = by_id.get(rotation.successor["enrollment_id"])
        if (
            predecessor is None
            or successor is None
            or predecessor.content_sha256 != rotation.predecessor["sha256"]
            or successor.content_sha256 != rotation.successor["sha256"]
        ):
            raise QualificationError("Candidate enrollment rotation references stale entries")
        if successor.predecessor != rotation.predecessor:
            raise QualificationError("Candidate enrollment rotation predecessor is inconsistent")
        if successor.enrollment_id in successor_ids:
            raise QualificationError("Candidate enrollment successor has multiple rotations")
        successor_ids.add(successor.enrollment_id)
        if (
            predecessor.profile_id != successor.profile_id
            or predecessor.candidate != successor.candidate
        ):
            raise QualificationError("Candidate enrollment rotation escapes exact candidate scope")
        if rotation.rotation_kind is CandidateEnrollmentRotationKind.OWNER_KEY:
            if (
                predecessor.repository != successor.repository
                or predecessor.owner == successor.owner
            ):
                raise QualificationError("Candidate owner-key rotation scope is invalid")
        elif predecessor.owner != successor.owner or predecessor.repository == successor.repository:
            raise QualificationError("Candidate repository rotation scope is invalid")
        overlap_start = _parse_timestamp(rotation.overlap_not_before, rotation.rotation_id)
        overlap_end = _parse_timestamp(rotation.overlap_expires_at, rotation.rotation_id)
        if overlap_start < max(
            _parse_timestamp(predecessor.not_before, predecessor.enrollment_id),
            _parse_timestamp(successor.not_before, successor.enrollment_id),
        ) or overlap_end > min(
            _parse_timestamp(predecessor.expires_at, predecessor.enrollment_id),
            _parse_timestamp(successor.expires_at, successor.enrollment_id),
        ):
            raise QualificationError("Candidate enrollment rotation overlap exceeds entry windows")
    for entry in enrollments:
        if entry.predecessor is None or entry.enrollment_id in successor_ids:
            continue
        predecessor = by_id[entry.predecessor["enrollment_id"]]
        if predecessor.owner != entry.owner or predecessor.repository != entry.repository:
            raise QualificationError("Candidate enrollment identity change requires a rotation")


def _validate_revocation_subjects(
    enrollments: tuple[CandidateEnrollmentEntry, ...],
    revocations: tuple[CandidateEnrollmentRevocation, ...],
) -> None:
    subjects = {
        CandidateEnrollmentRevocationKind.ENROLLMENT: {
            entry.enrollment_id for entry in enrollments
        },
        CandidateEnrollmentRevocationKind.OWNER_KEY: {
            entry.owner["key_id"] for entry in enrollments
        },
        CandidateEnrollmentRevocationKind.REPOSITORY_IDENTITY: {
            entry.repository["repository_id"] for entry in enrollments
        },
    }
    seen: set[tuple[CandidateEnrollmentRevocationKind, str]] = set()
    for revocation in revocations:
        subject = (revocation.revocation_kind, revocation.subject_id)
        if revocation.subject_id not in subjects[revocation.revocation_kind]:
            raise QualificationError("Candidate enrollment revocation subject is unknown")
        if subject in seen:
            raise QualificationError("Candidate enrollment revocation subject is duplicated")
        seen.add(subject)


def _load_contract(path: str | Path, label: str) -> Any:
    resolved = Path(path)
    try:
        return loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load {label}: {resolved}") from exc


def load_candidate_enrollment_signer_authorization(
    path: str | Path,
) -> CandidateEnrollmentSignerAuthorization:
    return CandidateEnrollmentSignerAuthorization.from_dict(
        _load_contract(path, "candidate enrollment signer authorization")
    )


def load_candidate_enrollment_catalog(path: str | Path) -> CandidateEnrollmentCatalog:
    return CandidateEnrollmentCatalog.from_dict(
        _load_contract(path, "candidate enrollment catalog")
    )


__all__ = [
    "ENROLLMENT_CATALOG_SIGNING_DOMAIN",
    "ENROLLMENT_ENTRY_DOMAIN",
    "ENROLLMENT_RELEASE_BODY_DOMAIN",
    "ENROLLMENT_RELEASE_REVIEW_SIGNING_DOMAIN",
    "ENROLLMENT_SIGNER_AUTHORIZATION_SIGNING_DOMAIN",
    "CandidateEnrollmentCatalog",
    "CandidateEnrollmentEntry",
    "CandidateEnrollmentReleaseReview",
    "CandidateEnrollmentRevocation",
    "CandidateEnrollmentRevocationKind",
    "CandidateEnrollmentRotation",
    "CandidateEnrollmentRotationKind",
    "CandidateEnrollmentSignerAuthorization",
    "CandidateEnrollmentSignerKey",
    "CandidateEnrollmentSignerKeyState",
    "load_candidate_enrollment_catalog",
    "load_candidate_enrollment_signer_authorization",
]
