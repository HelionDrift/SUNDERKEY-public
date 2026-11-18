"""Reviewed qualification registry revision contracts."""

from __future__ import annotations

import copy
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import QualificationError, RegistryError
from .identity import (
    _decode_base64url,
    _identifier,
    _strict_ed25519_public_key,
    _timestamp,
    _verify_ed25519,
)
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .qualification_evaluation import QualificationCandidateBinding
from .qualification_lifecycle import (
    QualificationStatus,
    QualificationStatusBinding,
    VerifiedQualificationStatus,
)
from .qualification_trust import (
    QualificationAuthorityKeyState,
    QualificationAuthorityKeyUse,
    QualificationReviewerCredential,
    QualificationReviewerRole,
    QualificationTrustPolicy,
    VerifiedQualificationReviewerCredential,
    VerifiedQualificationTrustPolicy,
    _auth_value,
    _clock_value,
    _format_timestamp,
    _parse_timestamp,
    _positive_integer,
    _qualification_failure,
    _sha256,
    _signature,
    _specialist_id,
)
from .registry import ExpertRegistry, ProfileQualificationRecord
from .types import ProfileKind
from .validation import loads_json_without_duplicate_keys

QUALIFICATION_REGISTRY_REVIEW_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00QUALIFICATION-REGISTRY-REVIEW\x00V1\x00"
)
QUALIFICATION_REGISTRY_REVISION_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00QUALIFICATION-REGISTRY-REVISION\x00V1\x00"
)
_REVISION_ID_PATTERN = re.compile(r"QRR-[0-9A-F]{32}")
_REVIEW_ID_PATTERN = re.compile(r"QRV-[0-9A-F]{32}")
_CREDENTIAL_ID_PATTERN = re.compile(r"QRC-[0-9A-F]{32}")
_EVENT_ID_PATTERN = re.compile(r"(?:QKD|QST)-[0-9A-F]{32}")
_SEMVER_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_VERIFICATION_PROOF_KEY = secrets.token_bytes(32)
_REGISTRY_STATUS = {
    QualificationStatus.ACTIVE: "qualified",
    QualificationStatus.SUSPENDED: "suspended",
    QualificationStatus.REVOKED: "revoked",
}
_REVISION_REVIEW_ROLES = frozenset(
    {
        QualificationReviewerRole.INDEPENDENT_CONTROL,
        QualificationReviewerRole.INDEPENDENT_ASSURANCE,
    }
)


def _revision_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _REVISION_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid revision ID")
    return value


def _review_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _REVIEW_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid review ID")
    return value


def _credential_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CREDENTIAL_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid credential ID")
    return value


def _event_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _EVENT_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid status event ID")
    return value


def _policy_binding(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, {"policy_id", "policy_version", "sha256"}, label)
    policy_id = value.get("policy_id")
    if (
        not isinstance(policy_id, str)
        or re.fullmatch(r"QTP-[0-9A-F]{32}", policy_id) is None
    ):
        raise _qualification_failure(f"{label}.policy_id is invalid")
    return {
        "policy_id": policy_id,
        "policy_version": _positive_integer(
            value.get("policy_version"),
            f"{label}.policy_version",
            2_147_483_647,
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _registry_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"catalog_id", "catalog_version", "sha256"}, label)
    return {
        "catalog_id": _auth_value(
            _identifier,
            value.get("catalog_id"),
            f"{label}.catalog_id",
        ),
        "catalog_version": _semantic_version(
            value.get("catalog_version"),
            f"{label}.catalog_version",
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _credential_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"id", "sha256"}, label)
    return {
        "id": _credential_id(value.get("id"), f"{label}.id"),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _semantic_version(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SEMVER_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} must be a semantic version")
    return value


def _semantic_version_tuple(value: str) -> tuple[int, int, int]:
    matched = _SEMVER_PATTERN.fullmatch(value)
    if matched is None:
        raise _qualification_failure("Registry catalog version is invalid")
    return tuple(int(item) for item in matched.groups())


def _validated_policy(
    verified_policy: VerifiedQualificationTrustPolicy,
) -> QualificationTrustPolicy:
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
    policy = QualificationTrustPolicy.from_dict(verified_policy.policy.to_dict())
    if policy.content_sha256 != verified_policy.policy_sha256:
        raise _qualification_failure(
            "Verified qualification trust policy digest is invalid"
        )
    return policy


def _validated_credential(
    verified_credential: VerifiedQualificationReviewerCredential,
) -> QualificationReviewerCredential:
    if type(verified_credential) is not VerifiedQualificationReviewerCredential:
        raise _qualification_failure(
            "verified_credential must be a VerifiedQualificationReviewerCredential"
        )
    try:
        VerifiedQualificationReviewerCredential.__post_init__(verified_credential)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification reviewer credential proof is invalid"
        ) from exc
    credential = QualificationReviewerCredential.from_dict(
        verified_credential.credential.to_dict()
    )
    if credential.content_sha256 != verified_credential.credential_sha256:
        raise _qualification_failure(
            "Verified qualification reviewer credential digest is invalid"
        )
    return credential


def _validated_status(
    verified_status: VerifiedQualificationStatus,
) -> QualificationStatusBinding:
    if type(verified_status) is not VerifiedQualificationStatus:
        raise _qualification_failure(
            "verified_status must be a VerifiedQualificationStatus"
        )
    try:
        VerifiedQualificationStatus.__post_init__(verified_status)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification status proof is invalid"
        ) from exc
    binding = QualificationStatusBinding.from_dict(
        verified_status.binding.to_dict(),
        "verified qualification status",
    )
    if binding.content_sha256 != verified_status.binding_sha256:
        raise _qualification_failure(
            "Verified qualification status digest is invalid"
        )
    if binding.sequence == 1 and verified_status.previous_binding_sha256 is not None:
        raise _qualification_failure(
            "Initial qualification status cannot bind a predecessor"
        )
    if binding.sequence > 1:
        _sha256(
            verified_status.previous_binding_sha256,
            "verified qualification status previous binding",
        )
    return binding


def _registry_sha256(registry: ExpertRegistry) -> str:
    return _canonical_sha256(registry.to_dict())


def _qualification_record(
    binding: QualificationStatusBinding,
    binding_sha256: str,
) -> ProfileQualificationRecord:
    candidate = binding.candidate
    return ProfileQualificationRecord.from_dict(
        {
            "schema_version": 1,
            "candidate_id": candidate.candidate_id,
            "candidate_version": candidate.candidate_version,
            "candidate_artifact_sha256": candidate.candidate_artifact_sha256,
            "sequence": binding.sequence,
            "lifecycle_status": binding.status.value,
            "source_event_id": binding.source_event["id"],
            "source_event_sha256": binding.source_event["sha256"],
            "current_review_decision_id": binding.current_review_decision["id"],
            "current_review_decision_sha256": binding.current_review_decision[
                "sha256"
            ],
            "qualification_valid_until": binding.qualification_valid_until,
            "changed_at": binding.changed_at,
            "status_binding_sha256": binding_sha256,
        },
        "profile qualification record",
    )


def propose_qualification_registry(
    base_registry: ExpertRegistry,
    verified_status: VerifiedQualificationStatus,
    *,
    proposed_catalog_version: str,
) -> ExpertRegistry:
    """Build one deterministic proposed registry without writing it."""

    if not isinstance(base_registry, ExpertRegistry):
        raise _qualification_failure("base_registry must be an ExpertRegistry")
    try:
        base_registry.validate()
    except RegistryError as exc:
        raise _qualification_failure(
            "Base qualification registry is invalid"
        ) from exc
    status = _validated_status(verified_status)
    proposed_version = _semantic_version(
        proposed_catalog_version,
        "proposed_catalog_version",
    )
    base_version = _semantic_version(
        base_registry.catalog_version,
        "base registry catalog_version",
    )
    if _semantic_version_tuple(proposed_version) <= _semantic_version_tuple(
        base_version
    ):
        raise _qualification_failure(
            "Proposed registry catalog version must increase"
        )
    try:
        profile = base_registry.profile(status.profile_id)
    except RegistryError as exc:
        raise _qualification_failure(
            "Qualification registry profile does not exist"
        ) from exc
    if profile.kind is not ProfileKind.SPECIALIST:
        raise _qualification_failure(
            "Qualification registry revision can target only a specialist"
        )
    current = profile.qualification
    if status.sequence == 1:
        if current is not None or profile.status != "defined":
            raise _qualification_failure(
                "Initial qualification registry revision requires a defined profile"
            )
    else:
        if current is None:
            raise _qualification_failure(
                "Qualification registry revision predecessor is missing"
            )
        if (
            current.sequence + 1 != status.sequence
            or current.status_binding_sha256
            != verified_status.previous_binding_sha256
        ):
            raise _qualification_failure(
                "Qualification registry revision predecessor is stale"
            )
        candidate = status.candidate
        if (
            current.candidate_id != candidate.candidate_id
            or current.candidate_version != candidate.candidate_version
            or current.candidate_artifact_sha256
            != candidate.candidate_artifact_sha256
        ):
            raise _qualification_failure(
                "Qualification registry revision candidate is stale"
            )
    raw = copy.deepcopy(base_registry.to_dict())
    raw["catalog_version"] = proposed_version
    target = next(
        item for item in raw["profiles"] if item["id"] == status.profile_id
    )
    target["status"] = _REGISTRY_STATUS[status.status]
    target["qualification"] = _qualification_record(
        status,
        verified_status.binding_sha256,
    ).to_dict()
    try:
        return ExpertRegistry.from_dict(raw)
    except RegistryError as exc:
        raise _qualification_failure(
            "Proposed qualification registry is invalid"
        ) from exc


@dataclass(frozen=True)
class QualificationRegistryRevisionReview:
    """Credential-signed independent review of one exact proposed revision."""

    schema_version: int
    review_id: str
    revision_id: str
    policy: dict[str, Any]
    base_registry: dict[str, str]
    proposed_registry: dict[str, str]
    status_binding_sha256: str
    profile_id: str
    reviewer_credential: dict[str, str]
    reviewer_id: str
    reviewer_role: QualificationReviewerRole
    conclusion: str
    reason_sha256: str
    reviewed_at: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationRegistryRevisionReview:
        value = _mapping(raw, "qualification registry revision review")
        _exact_fields(
            value,
            {
                "schema_version",
                "review_id",
                "revision_id",
                "policy",
                "base_registry",
                "proposed_registry",
                "status_binding_sha256",
                "profile_id",
                "reviewer_credential",
                "reviewer_id",
                "reviewer_role",
                "conclusion",
                "reason_sha256",
                "reviewed_at",
                "algorithm",
                "signature",
            },
            "qualification registry revision review",
        )
        if value.get("schema_version") != 1:
            raise _qualification_failure(
                "Qualification registry revision review schema_version must be 1"
            )
        if value.get("algorithm") != "Ed25519":
            raise _qualification_failure(
                "Qualification registry revision review algorithm must be Ed25519"
            )
        if value.get("conclusion") != "approve_registry_revision":
            raise _qualification_failure(
                "Qualification registry revision review conclusion is invalid"
            )
        try:
            role = QualificationReviewerRole(value.get("reviewer_role"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                "Qualification registry revision review role is invalid"
            ) from exc
        if role not in _REVISION_REVIEW_ROLES:
            raise _qualification_failure(
                "Qualification registry revision review role is not independent"
            )
        return cls(
            schema_version=1,
            review_id=_review_id(
                value.get("review_id"),
                "qualification registry revision review.review_id",
            ),
            revision_id=_revision_id(
                value.get("revision_id"),
                "qualification registry revision review.revision_id",
            ),
            policy=_policy_binding(
                value.get("policy"),
                "qualification registry revision review.policy",
            ),
            base_registry=_registry_binding(
                value.get("base_registry"),
                "qualification registry revision review.base_registry",
            ),
            proposed_registry=_registry_binding(
                value.get("proposed_registry"),
                "qualification registry revision review.proposed_registry",
            ),
            status_binding_sha256=_sha256(
                value.get("status_binding_sha256"),
                "qualification registry revision review.status_binding_sha256",
            ),
            profile_id=_specialist_id(
                value.get("profile_id"),
                "qualification registry revision review.profile_id",
            ),
            reviewer_credential=_credential_binding(
                value.get("reviewer_credential"),
                "qualification registry revision review.reviewer_credential",
            ),
            reviewer_id=_auth_value(
                _identifier,
                value.get("reviewer_id"),
                "qualification registry revision review.reviewer_id",
            ),
            reviewer_role=role,
            conclusion="approve_registry_revision",
            reason_sha256=_sha256(
                value.get("reason_sha256"),
                "qualification registry revision review.reason_sha256",
            ),
            reviewed_at=_auth_value(
                _timestamp,
                value.get("reviewed_at"),
                "qualification registry revision review.reviewed_at",
            ),
            signature=_signature(
                value.get("signature"),
                "qualification registry revision review.signature",
            ),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "review_id": self.review_id,
            "revision_id": self.revision_id,
            "policy": dict(self.policy),
            "base_registry": dict(self.base_registry),
            "proposed_registry": dict(self.proposed_registry),
            "status_binding_sha256": self.status_binding_sha256,
            "profile_id": self.profile_id,
            "reviewer_credential": dict(self.reviewer_credential),
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role.value,
            "conclusion": self.conclusion,
            "reason_sha256": self.reason_sha256,
            "reviewed_at": self.reviewed_at,
            "algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return QUALIFICATION_REGISTRY_REVIEW_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


def _review_proof(material: dict[str, Any]) -> bytes:
    payload = _canonical_json(
        {"kind": "verified_qualification_registry_review", "material": material}
    ).encode("ascii")
    return hmac.new(_VERIFICATION_PROOF_KEY, payload, hashlib.sha256).digest()


@dataclass(frozen=True)
class VerifiedQualificationRegistryRevisionReview:
    review: QualificationRegistryRevisionReview
    review_sha256: str
    credential_sha256: str
    reviewer_key_sha256: str
    policy_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def _material(self) -> dict[str, Any]:
        return {
            "review": self.review.to_dict(),
            "review_sha256": self.review_sha256,
            "credential_sha256": self.credential_sha256,
            "reviewer_key_sha256": self.reviewer_key_sha256,
            "policy_sha256": self.policy_sha256,
            "verified_at": self.verified_at,
        }

    def __post_init__(self) -> None:
        expected = _review_proof(self._material())
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedQualificationRegistryRevisionReview can be created only "
                "by verify_qualification_registry_revision_review"
            )


def verify_qualification_registry_revision_review(
    review: QualificationRegistryRevisionReview,
    verified_credential: VerifiedQualificationReviewerCredential,
    verified_policy: VerifiedQualificationTrustPolicy,
    *,
    clock: Callable[[], datetime],
) -> VerifiedQualificationRegistryRevisionReview:
    """Authenticate one independent review of a proposed registry revision."""

    if not isinstance(review, QualificationRegistryRevisionReview):
        raise _qualification_failure(
            "review must be a QualificationRegistryRevisionReview"
        )
    review = QualificationRegistryRevisionReview.from_dict(review.to_dict())
    credential = _validated_credential(verified_credential)
    policy = _validated_policy(verified_policy)
    if review.policy != {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "sha256": verified_policy.policy_sha256,
    }:
        raise _qualification_failure(
            "Qualification registry revision review policy is stale"
        )
    if (
        verified_credential.policy_sha256 != verified_policy.policy_sha256
        or credential.policy_sha256 != verified_policy.policy_sha256
    ):
        raise _qualification_failure(
            "Qualification registry revision reviewer credential policy is stale"
        )
    if (
        review.reviewer_id != credential.reviewer_id
        or review.reviewer_role is not credential.reviewer_role
    ):
        raise _qualification_failure(
            "Qualification registry revision reviewer identity or role is stale"
        )
    if review.reviewer_role not in _REVISION_REVIEW_ROLES:
        raise _qualification_failure(
            "Qualification registry revision reviewer role is not independent"
        )
    if (
        verified_credential.verified_profile_id != review.profile_id
        or review.profile_id not in credential.allowed_profile_ids
    ):
        raise _qualification_failure(
            "Qualification registry revision reviewer profile scope is stale"
        )
    if review.reviewer_credential != {
        "id": credential.credential_id,
        "sha256": verified_credential.credential_sha256,
    }:
        raise _qualification_failure(
            "Qualification registry revision credential binding is stale"
        )
    reviewed = _parse_timestamp(review.reviewed_at, "registry revision review")
    starts = _parse_timestamp(credential.not_before, credential.credential_id)
    expires = _parse_timestamp(credential.expires_at, credential.credential_id)
    now = _clock_value(clock)
    if reviewed < starts or reviewed >= expires:
        raise _qualification_failure(
            "Qualification registry revision review is outside credential window"
        )
    if reviewed > now:
        raise _qualification_failure(
            "Qualification registry revision review is in the future"
        )
    reviewer_public_bytes = _decode_base64url(credential.public_key)
    reviewer_public_key = _auth_value(
        _strict_ed25519_public_key,
        reviewer_public_bytes,
        f"qualification registry reviewer {credential.reviewer_id}",
    )
    _auth_value(
        _verify_ed25519,
        reviewer_public_key,
        review.signature,
        review.signing_bytes(),
        "Qualification registry revision review",
    )
    reviewer_key_sha256 = (
        "sha256:" + hashlib.sha256(reviewer_public_bytes).hexdigest()
    )
    verified_at = _format_timestamp(now)
    material = {
        "review": review.to_dict(),
        "review_sha256": review.content_sha256,
        "credential_sha256": verified_credential.credential_sha256,
        "reviewer_key_sha256": reviewer_key_sha256,
        "policy_sha256": verified_policy.policy_sha256,
        "verified_at": verified_at,
    }
    return VerifiedQualificationRegistryRevisionReview(
        review=review,
        review_sha256=review.content_sha256,
        credential_sha256=verified_credential.credential_sha256,
        reviewer_key_sha256=reviewer_key_sha256,
        policy_sha256=verified_policy.policy_sha256,
        verified_at=verified_at,
        _proof=_review_proof(material),
    )


@dataclass(frozen=True)
class QualificationRegistryRevisionReviewBinding:
    review_id: str
    reviewer_id: str
    reviewer_role: QualificationReviewerRole
    review_sha256: str
    credential_sha256: str
    reviewer_key_sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
    ) -> QualificationRegistryRevisionReviewBinding:
        label = f"qualification registry revision.reviews[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "review_id",
                "reviewer_id",
                "reviewer_role",
                "review_sha256",
                "credential_sha256",
                "reviewer_key_sha256",
            },
            label,
        )
        try:
            role = QualificationReviewerRole(value.get("reviewer_role"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(f"{label}.reviewer_role is invalid") from exc
        if role not in _REVISION_REVIEW_ROLES:
            raise _qualification_failure(f"{label}.reviewer_role is invalid")
        return cls(
            review_id=_review_id(value.get("review_id"), f"{label}.review_id"),
            reviewer_id=_auth_value(
                _identifier,
                value.get("reviewer_id"),
                f"{label}.reviewer_id",
            ),
            reviewer_role=role,
            review_sha256=_sha256(
                value.get("review_sha256"),
                f"{label}.review_sha256",
            ),
            credential_sha256=_sha256(
                value.get("credential_sha256"),
                f"{label}.credential_sha256",
            ),
            reviewer_key_sha256=_sha256(
                value.get("reviewer_key_sha256"),
                f"{label}.reviewer_key_sha256",
            ),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "review_id": self.review_id,
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role.value,
            "review_sha256": self.review_sha256,
            "credential_sha256": self.credential_sha256,
            "reviewer_key_sha256": self.reviewer_key_sha256,
        }


@dataclass(frozen=True)
class QualificationRegistryRevision:
    """Authority-signed reviewed proposal for one registry status change."""

    schema_version: int
    revision_id: str
    revision_version: int
    policy: dict[str, Any]
    decision_record: dict[str, str]
    base_registry: dict[str, str]
    proposed_registry: dict[str, str]
    profile_id: str
    candidate: QualificationCandidateBinding
    qualification_status: dict[str, Any]
    profile_change: dict[str, str]
    reviews: tuple[QualificationRegistryRevisionReviewBinding, ...]
    issued_at: str
    signer_id: str
    signer_key_id: str
    application_effect: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationRegistryRevision:
        value = _mapping(raw, "qualification registry revision")
        _exact_fields(
            value,
            {
                "schema_version",
                "revision_id",
                "revision_version",
                "policy",
                "decision_record",
                "base_registry",
                "proposed_registry",
                "profile_id",
                "candidate",
                "qualification_status",
                "profile_change",
                "reviews",
                "issued_at",
                "signer_id",
                "signer_key_id",
                "application_effect",
                "algorithm",
                "signature",
            },
            "qualification registry revision",
        )
        if value.get("schema_version") != 1:
            raise _qualification_failure(
                "Qualification registry revision schema_version must be 1"
            )
        if value.get("algorithm") != "Ed25519":
            raise _qualification_failure(
                "Qualification registry revision algorithm must be Ed25519"
            )
        if value.get("application_effect") != "proposed_registry_only":
            raise _qualification_failure(
                "Qualification registry revision application effect is invalid"
            )
        decision_record = _mapping(
            value.get("decision_record"),
            "qualification registry revision.decision_record",
        )
        _exact_fields(
            decision_record,
            {"record_id", "sha256"},
            "qualification registry revision.decision_record",
        )
        record_id = decision_record.get("record_id")
        if (
            not isinstance(record_id, str)
            or re.fullmatch(r"QDR-[0-9A-F]{32}", record_id) is None
        ):
            raise _qualification_failure(
                "Qualification registry revision decision record ID is invalid"
            )
        status_raw = _mapping(
            value.get("qualification_status"),
            "qualification registry revision.qualification_status",
        )
        _exact_fields(
            status_raw,
            {
                "binding_sha256",
                "sequence",
                "lifecycle_status",
                "source_event_id",
                "source_event_sha256",
                "previous_binding_sha256",
            },
            "qualification registry revision.qualification_status",
        )
        try:
            lifecycle_status = QualificationStatus(
                status_raw.get("lifecycle_status")
            )
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                "Qualification registry revision lifecycle status is invalid"
            ) from exc
        previous_digest = status_raw.get("previous_binding_sha256")
        if previous_digest is not None:
            previous_digest = _sha256(
                previous_digest,
                "qualification registry revision previous binding",
            )
        status_binding = {
            "binding_sha256": _sha256(
                status_raw.get("binding_sha256"),
                "qualification registry revision status binding",
            ),
            "sequence": _positive_integer(
                status_raw.get("sequence"),
                "qualification registry revision status sequence",
                2_147_483_647,
            ),
            "lifecycle_status": lifecycle_status.value,
            "source_event_id": _event_id(
                status_raw.get("source_event_id"),
                "qualification registry revision source event",
            ),
            "source_event_sha256": _sha256(
                status_raw.get("source_event_sha256"),
                "qualification registry revision source event digest",
            ),
            "previous_binding_sha256": previous_digest,
        }
        profile_change = _mapping(
            value.get("profile_change"),
            "qualification registry revision.profile_change",
        )
        _exact_fields(
            profile_change,
            {"from_status", "to_status"},
            "qualification registry revision.profile_change",
        )
        allowed_registry_statuses = {
            "defined",
            "qualified",
            "suspended",
            "revoked",
        }
        from_status = profile_change.get("from_status")
        to_status = profile_change.get("to_status")
        if (
            from_status not in allowed_registry_statuses
            or to_status not in allowed_registry_statuses
        ):
            raise _qualification_failure(
                "Qualification registry revision profile status is invalid"
            )
        raw_reviews = value.get("reviews")
        if not isinstance(raw_reviews, list) or len(raw_reviews) != 2:
            raise _qualification_failure(
                "Qualification registry revision requires exactly two reviews"
            )
        reviews = tuple(
            QualificationRegistryRevisionReviewBinding.from_dict(item, index)
            for index, item in enumerate(raw_reviews)
        )
        canonical = tuple(
            sorted(reviews, key=lambda item: item.reviewer_role.value)
        )
        if (
            reviews != canonical
            or {item.reviewer_role for item in reviews} != _REVISION_REVIEW_ROLES
        ):
            raise _qualification_failure(
                "Qualification registry revision reviews must be canonical Control and Assurance"
            )
        return cls(
            schema_version=1,
            revision_id=_revision_id(
                value.get("revision_id"),
                "qualification registry revision.revision_id",
            ),
            revision_version=_positive_integer(
                value.get("revision_version"),
                "qualification registry revision.revision_version",
                2_147_483_647,
            ),
            policy=_policy_binding(
                value.get("policy"),
                "qualification registry revision.policy",
            ),
            decision_record={
                "record_id": record_id,
                "sha256": _sha256(
                    decision_record.get("sha256"),
                    "qualification registry revision decision record digest",
                ),
            },
            base_registry=_registry_binding(
                value.get("base_registry"),
                "qualification registry revision.base_registry",
            ),
            proposed_registry=_registry_binding(
                value.get("proposed_registry"),
                "qualification registry revision.proposed_registry",
            ),
            profile_id=_specialist_id(
                value.get("profile_id"),
                "qualification registry revision.profile_id",
            ),
            candidate=QualificationCandidateBinding.from_dict(
                value.get("candidate"),
                "qualification registry revision.candidate",
            ),
            qualification_status=status_binding,
            profile_change={
                "from_status": from_status,
                "to_status": to_status,
            },
            reviews=reviews,
            issued_at=_auth_value(
                _timestamp,
                value.get("issued_at"),
                "qualification registry revision.issued_at",
            ),
            signer_id=_auth_value(
                _identifier,
                value.get("signer_id"),
                "qualification registry revision.signer_id",
            ),
            signer_key_id=_auth_value(
                _identifier,
                value.get("signer_key_id"),
                "qualification registry revision.signer_key_id",
            ),
            application_effect="proposed_registry_only",
            signature=_signature(
                value.get("signature"),
                "qualification registry revision.signature",
            ),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "revision_id": self.revision_id,
            "revision_version": self.revision_version,
            "policy": dict(self.policy),
            "decision_record": dict(self.decision_record),
            "base_registry": dict(self.base_registry),
            "proposed_registry": dict(self.proposed_registry),
            "profile_id": self.profile_id,
            "candidate": self.candidate.to_dict(),
            "qualification_status": dict(self.qualification_status),
            "profile_change": dict(self.profile_change),
            "reviews": [item.to_dict() for item in self.reviews],
            "issued_at": self.issued_at,
            "signer_id": self.signer_id,
            "signer_key_id": self.signer_key_id,
            "application_effect": self.application_effect,
            "algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return QUALIFICATION_REGISTRY_REVISION_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


def _validated_review(
    verified: VerifiedQualificationRegistryRevisionReview,
) -> tuple[QualificationRegistryRevisionReview, QualificationRegistryRevisionReviewBinding]:
    if type(verified) is not VerifiedQualificationRegistryRevisionReview:
        raise _qualification_failure(
            "verified_reviews must contain verified registry revision reviews"
        )
    try:
        VerifiedQualificationRegistryRevisionReview.__post_init__(verified)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification registry revision review proof is invalid"
        ) from exc
    review = QualificationRegistryRevisionReview.from_dict(verified.review.to_dict())
    if review.content_sha256 != verified.review_sha256:
        raise _qualification_failure(
            "Verified qualification registry revision review digest is invalid"
        )
    return review, QualificationRegistryRevisionReviewBinding(
        review_id=review.review_id,
        reviewer_id=review.reviewer_id,
        reviewer_role=review.reviewer_role,
        review_sha256=verified.review_sha256,
        credential_sha256=verified.credential_sha256,
        reviewer_key_sha256=verified.reviewer_key_sha256,
    )


def _revision_proof(material: dict[str, Any]) -> bytes:
    payload = _canonical_json(
        {"kind": "verified_qualification_registry_revision", "material": material}
    ).encode("ascii")
    return hmac.new(_VERIFICATION_PROOF_KEY, payload, hashlib.sha256).digest()


@dataclass(frozen=True)
class VerifiedQualificationRegistryRevision:
    revision: QualificationRegistryRevision
    revision_sha256: str
    base_registry_sha256: str
    proposed_registry: ExpertRegistry
    proposed_registry_sha256: str
    status_binding_sha256: str
    reviewer_ids: tuple[str, str]
    signer_key_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def _material(self) -> dict[str, Any]:
        return {
            "revision": self.revision.to_dict(),
            "revision_sha256": self.revision_sha256,
            "base_registry_sha256": self.base_registry_sha256,
            "proposed_registry": self.proposed_registry.to_dict(),
            "proposed_registry_sha256": self.proposed_registry_sha256,
            "status_binding_sha256": self.status_binding_sha256,
            "reviewer_ids": list(self.reviewer_ids),
            "signer_key_sha256": self.signer_key_sha256,
            "verified_at": self.verified_at,
        }

    def __post_init__(self) -> None:
        expected = _revision_proof(self._material())
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedQualificationRegistryRevision can be created only by "
                "verify_qualification_registry_revision"
            )


def verify_qualification_registry_revision(
    revision: QualificationRegistryRevision,
    verified_status: VerifiedQualificationStatus,
    verified_policy: VerifiedQualificationTrustPolicy,
    verified_reviews: Sequence[VerifiedQualificationRegistryRevisionReview],
    *,
    base_registry: ExpertRegistry,
    proposed_registry: ExpertRegistry,
    clock: Callable[[], datetime],
) -> VerifiedQualificationRegistryRevision:
    """Authenticate a reviewed proposed registry without writing it."""

    if not isinstance(revision, QualificationRegistryRevision):
        raise _qualification_failure(
            "revision must be a QualificationRegistryRevision"
        )
    revision = QualificationRegistryRevision.from_dict(revision.to_dict())
    status = _validated_status(verified_status)
    policy = _validated_policy(verified_policy)
    if not isinstance(base_registry, ExpertRegistry):
        raise _qualification_failure("base_registry must be an ExpertRegistry")
    if not isinstance(proposed_registry, ExpertRegistry):
        raise _qualification_failure(
            "proposed_registry must be an ExpertRegistry"
        )
    base_registry.validate()
    proposed_registry.validate()
    expected_proposed = propose_qualification_registry(
        base_registry,
        verified_status,
        proposed_catalog_version=proposed_registry.catalog_version,
    )
    if expected_proposed.to_dict() != proposed_registry.to_dict():
        raise _qualification_failure(
            "Proposed qualification registry contains unrelated changes"
        )
    base_sha256 = _registry_sha256(base_registry)
    proposed_sha256 = _registry_sha256(proposed_registry)
    expected_base = {
        "catalog_id": base_registry.catalog_id,
        "catalog_version": base_registry.catalog_version,
        "sha256": base_sha256,
    }
    expected_proposed_binding = {
        "catalog_id": proposed_registry.catalog_id,
        "catalog_version": proposed_registry.catalog_version,
        "sha256": proposed_sha256,
    }
    if revision.base_registry != expected_base:
        raise _qualification_failure(
            "Qualification registry revision base binding is stale"
        )
    if revision.proposed_registry != expected_proposed_binding:
        raise _qualification_failure(
            "Qualification registry revision proposed binding is stale"
        )
    if revision.policy != {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "sha256": verified_policy.policy_sha256,
    }:
        raise _qualification_failure(
            "Qualification registry revision policy binding is stale"
        )
    if revision.decision_record != policy.decision_record:
        raise _qualification_failure(
            "Qualification registry revision D008 binding is stale"
        )
    expected_status = {
        "binding_sha256": verified_status.binding_sha256,
        "sequence": status.sequence,
        "lifecycle_status": status.status.value,
        "source_event_id": status.source_event["id"],
        "source_event_sha256": status.source_event["sha256"],
        "previous_binding_sha256": verified_status.previous_binding_sha256,
    }
    if revision.qualification_status != expected_status:
        raise _qualification_failure(
            "Qualification registry revision status binding is stale"
        )
    base_profile = base_registry.profile(status.profile_id)
    if (
        revision.profile_id != status.profile_id
        or revision.candidate != status.candidate
        or revision.profile_change
        != {
            "from_status": base_profile.status,
            "to_status": _REGISTRY_STATUS[status.status],
        }
    ):
        raise _qualification_failure(
            "Qualification registry revision profile change is stale"
        )
    if not isinstance(verified_reviews, Sequence) or isinstance(
        verified_reviews,
        (str, bytes),
    ):
        raise _qualification_failure("verified_reviews must be a sequence")
    validated = tuple(_validated_review(item) for item in verified_reviews)
    review_values = tuple(item[0] for item in validated)
    review_bindings = tuple(
        sorted(
            (item[1] for item in validated),
            key=lambda item: item.reviewer_role.value,
        )
    )
    if revision.reviews != review_bindings or len(review_values) != 2:
        raise _qualification_failure(
            "Qualification registry revision review binding is stale"
        )
    roles = {item.reviewer_role for item in review_bindings}
    if roles != _REVISION_REVIEW_ROLES:
        raise _qualification_failure(
            "Qualification registry revision requires Control and Assurance review"
        )
    reviewer_ids = tuple(item.reviewer_id for item in review_bindings)
    credential_hashes = tuple(item.credential_sha256 for item in review_bindings)
    reviewer_keys = tuple(item.reviewer_key_sha256 for item in review_bindings)
    review_ids = tuple(item.review_id for item in review_bindings)
    if (
        len(set(review_ids)) != 2
        or len(set(reviewer_ids)) != 2
        or len(set(credential_hashes)) != 2
        or len(set(reviewer_keys)) != 2
    ):
        raise _qualification_failure(
            "Qualification registry revision reviewers must be distinct"
        )
    for review in review_values:
        if (
            review.revision_id != revision.revision_id
            or review.policy != revision.policy
            or review.base_registry != revision.base_registry
            or review.proposed_registry != revision.proposed_registry
            or review.status_binding_sha256
            != revision.qualification_status["binding_sha256"]
            or review.profile_id != revision.profile_id
        ):
            raise _qualification_failure(
                "Qualification registry revision review content is stale"
            )
    changed = _parse_timestamp(status.changed_at, "qualification status")
    review_times = tuple(
        _parse_timestamp(item.reviewed_at, "qualification registry review")
        for item in review_values
    )
    if any(reviewed < changed for reviewed in review_times):
        raise _qualification_failure(
            "Qualification registry revision review predates qualification status"
        )
    issued = _parse_timestamp(revision.issued_at, "qualification registry revision")
    if any(
        reviewed > issued for reviewed in review_times
    ):
        raise _qualification_failure(
            "Qualification registry revision predates an independent review"
        )
    if issued < changed:
        raise _qualification_failure(
            "Qualification registry revision predates qualification status"
        )
    now = _clock_value(clock)
    if issued > now:
        raise _qualification_failure(
            "Qualification registry revision is in the future"
        )
    policy_start = _parse_timestamp(policy.not_before, "qualification trust policy")
    policy_end = _parse_timestamp(policy.expires_at, "qualification trust policy")
    if issued < policy_start or issued >= policy_end or now >= policy_end:
        raise _qualification_failure(
            "Qualification registry revision is outside policy window"
        )
    if status.status is QualificationStatus.ACTIVE and now >= _parse_timestamp(
        status.qualification_valid_until,
        "qualification status",
    ):
        raise _qualification_failure(
            "Active qualification registry revision has expired"
        )
    if revision.signer_id != policy.issuer:
        raise _qualification_failure(
            "Qualification registry revision signer does not match policy issuer"
        )
    signer = policy.key(revision.signer_key_id)
    expected_key_use = (
        QualificationAuthorityKeyUse.QUALIFICATION_DECISION
        if status.status is QualificationStatus.ACTIVE
        else QualificationAuthorityKeyUse.QUALIFICATION_REVOCATION
    )
    if signer.key_use is not expected_key_use:
        raise _qualification_failure(
            "Qualification registry revision signer key use is not authorized"
        )
    if (
        status.profile_id not in policy.allowed_profile_ids
        or status.profile_id not in signer.allowed_profile_ids
    ):
        raise _qualification_failure(
            "Qualification registry revision profile is outside signer scope"
        )
    if signer.state is QualificationAuthorityKeyState.REVOKED:
        raise _qualification_failure(
            "Qualification registry revision signer key is revoked"
        )
    key_start = _parse_timestamp(signer.not_before, signer.key_id)
    key_end = _parse_timestamp(signer.not_after, signer.key_id)
    if issued < key_start or issued >= key_end:
        raise _qualification_failure(
            "Qualification registry revision is outside signer key window"
        )
    if signer.state is QualificationAuthorityKeyState.RETIRING and (
        signer.retire_at is None
        or issued >= _parse_timestamp(signer.retire_at, signer.key_id)
    ):
        raise _qualification_failure(
            "Qualification registry revision was issued after key retirement"
        )
    signer_public_bytes = _decode_base64url(signer.public_key)
    signer_public_key = _auth_value(
        _strict_ed25519_public_key,
        signer_public_bytes,
        f"qualification registry revision key {signer.key_id}",
    )
    _auth_value(
        _verify_ed25519,
        signer_public_key,
        revision.signature,
        revision.signing_bytes(),
        "Qualification registry revision",
    )
    signer_key_sha256 = (
        "sha256:" + hashlib.sha256(signer_public_bytes).hexdigest()
    )
    verified_at = _format_timestamp(now)
    material = {
        "revision": revision.to_dict(),
        "revision_sha256": revision.content_sha256,
        "base_registry_sha256": base_sha256,
        "proposed_registry": proposed_registry.to_dict(),
        "proposed_registry_sha256": proposed_sha256,
        "status_binding_sha256": verified_status.binding_sha256,
        "reviewer_ids": list(reviewer_ids),
        "signer_key_sha256": signer_key_sha256,
        "verified_at": verified_at,
    }
    return VerifiedQualificationRegistryRevision(
        revision=revision,
        revision_sha256=revision.content_sha256,
        base_registry_sha256=base_sha256,
        proposed_registry=proposed_registry,
        proposed_registry_sha256=proposed_sha256,
        status_binding_sha256=verified_status.binding_sha256,
        reviewer_ids=(reviewer_ids[0], reviewer_ids[1]),
        signer_key_sha256=signer_key_sha256,
        verified_at=verified_at,
        _proof=_revision_proof(material),
    )


def load_qualification_registry_revision_review(
    path: str | Path,
) -> QualificationRegistryRevisionReview:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load qualification registry revision review: {resolved}"
        ) from exc
    return QualificationRegistryRevisionReview.from_dict(raw)


def load_qualification_registry_revision(
    path: str | Path,
) -> QualificationRegistryRevision:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load qualification registry revision: {resolved}"
        ) from exc
    return QualificationRegistryRevision.from_dict(raw)


__all__ = [
    "QUALIFICATION_REGISTRY_REVIEW_SIGNING_DOMAIN",
    "QUALIFICATION_REGISTRY_REVISION_SIGNING_DOMAIN",
    "QualificationRegistryRevision",
    "QualificationRegistryRevisionReview",
    "QualificationRegistryRevisionReviewBinding",
    "VerifiedQualificationRegistryRevision",
    "VerifiedQualificationRegistryRevisionReview",
    "load_qualification_registry_revision",
    "load_qualification_registry_revision_review",
    "propose_qualification_registry",
    "verify_qualification_registry_revision",
    "verify_qualification_registry_revision_review",
]
