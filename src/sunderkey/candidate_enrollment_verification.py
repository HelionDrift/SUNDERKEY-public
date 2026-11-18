"""Fail-closed verification for candidate enrollment authority and catalogs."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .candidate_enrollment import (
    CandidateEnrollmentCatalog,
    CandidateEnrollmentEntry,
    CandidateEnrollmentRevocationKind,
    CandidateEnrollmentSignerAuthorization,
    CandidateEnrollmentSignerKeyState,
)
from .candidate_enrollment_decision import CandidateEnrollmentDecisionRecord
from .errors import QualificationError
from .identity import (
    _decode_base64url,
    _identifier,
    _strict_ed25519_public_key,
    _verify_ed25519,
)
from .qualification import _canonical_json
from .qualification_authority_decision import QualificationAuthorityDecisionRecord
from .qualification_trust import (
    QualificationReviewerRole,
    VerifiedQualificationReviewerCredential,
    VerifiedQualificationTrustPolicy,
    _auth_value,
    _clock_value,
    _format_timestamp,
    _parse_timestamp,
    _positive_integer,
    _public_key,
    _raw_public_key,
    _sha256,
    _specialist_id,
    _trusted_root,
)

_VERIFICATION_PROOF_KEY = secrets.token_bytes(32)


def _proof(kind: str, material: dict[str, Any]) -> bytes:
    payload = _canonical_json({"kind": kind, "material": material}).encode("ascii")
    return hmac.new(_VERIFICATION_PROOF_KEY, payload, hashlib.sha256).digest()


def _check_proof(wrapper: Any, wrapper_type: type[Any], label: str) -> None:
    if type(wrapper) is not wrapper_type:
        raise QualificationError(f"{label} must be a {wrapper_type.__name__}")
    try:
        wrapper_type.__post_init__(wrapper)
    except TypeError as exc:
        raise QualificationError(f"{label} proof is invalid") from exc


@dataclass(frozen=True)
class CandidateEnrollmentCatalogCheckpoint:
    """Caller-retained last-seen state for rollback detection."""

    catalog_id: str
    catalog_version: int
    catalog_sha256: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentCatalogCheckpoint:
        if not isinstance(raw, Mapping) or set(raw) != {
            "catalog_id",
            "catalog_version",
            "catalog_sha256",
        }:
            raise QualificationError("Candidate enrollment checkpoint is invalid")
        catalog_id = raw.get("catalog_id")
        if (
            not isinstance(catalog_id, str)
            or re.fullmatch(r"CEC-[0-9A-F]{32}", catalog_id) is None
        ):
            raise QualificationError("Candidate enrollment checkpoint catalog ID is invalid")
        return cls(
            catalog_id=catalog_id,
            catalog_version=_positive_integer(
                raw.get("catalog_version"),
                "checkpoint.catalog_version",
                2_147_483_647,
            ),
            catalog_sha256=_sha256(
                raw.get("catalog_sha256"),
                "checkpoint.catalog_sha256",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_id": self.catalog_id,
            "catalog_version": self.catalog_version,
            "catalog_sha256": self.catalog_sha256,
        }


def _authorization_material(
    authorization: CandidateEnrollmentSignerAuthorization,
    authorization_sha256: str,
    root_key_sha256: str,
    policy_sha256: str,
    verified_at: str,
) -> dict[str, Any]:
    return {
        "authorization": authorization.to_dict(),
        "authorization_sha256": authorization_sha256,
        "root_key_sha256": root_key_sha256,
        "policy_sha256": policy_sha256,
        "verified_at": verified_at,
    }


@dataclass(frozen=True)
class VerifiedCandidateEnrollmentSignerAuthorization:
    """Enrollment signer authorization authenticated by the D008 root."""

    authorization: CandidateEnrollmentSignerAuthorization
    authorization_sha256: str
    root_key_sha256: str
    policy_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        expected = _proof(
            "verified_candidate_enrollment_signer_authorization",
            _authorization_material(
                self.authorization,
                self.authorization_sha256,
                self.root_key_sha256,
                self.policy_sha256,
                self.verified_at,
            ),
        )
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedCandidateEnrollmentSignerAuthorization can be created only "
                "by verify_candidate_enrollment_signer_authorization"
            )


def _catalog_material(
    catalog: CandidateEnrollmentCatalog,
    catalog_sha256: str,
    authorization_sha256: str,
    policy_sha256: str,
    reviewer_credential_sha256s: tuple[str, ...],
    verified_at: str,
    checkpoint: CandidateEnrollmentCatalogCheckpoint,
) -> dict[str, Any]:
    return {
        "catalog": catalog.to_dict(),
        "catalog_sha256": catalog_sha256,
        "authorization_sha256": authorization_sha256,
        "policy_sha256": policy_sha256,
        "reviewer_credential_sha256s": list(reviewer_credential_sha256s),
        "verified_at": verified_at,
        "checkpoint": checkpoint.to_dict(),
    }


@dataclass(frozen=True)
class VerifiedCandidateEnrollmentCatalog:
    """Authenticated, fresh, independently reviewed enrollment catalog."""

    catalog: CandidateEnrollmentCatalog
    catalog_sha256: str
    authorization_sha256: str
    policy_sha256: str
    reviewer_credential_sha256s: tuple[str, ...]
    verified_at: str
    checkpoint: CandidateEnrollmentCatalogCheckpoint
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        expected = _proof(
            "verified_candidate_enrollment_catalog",
            _catalog_material(
                self.catalog,
                self.catalog_sha256,
                self.authorization_sha256,
                self.policy_sha256,
                self.reviewer_credential_sha256s,
                self.verified_at,
                self.checkpoint,
            ),
        )
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedCandidateEnrollmentCatalog can be created only by "
                "verify_candidate_enrollment_catalog"
            )


def _entry_material(
    entry: CandidateEnrollmentEntry,
    catalog_sha256: str,
    verified_at: str,
) -> dict[str, Any]:
    return {
        "entry": entry.to_dict(),
        "entry_sha256": entry.content_sha256,
        "catalog_sha256": catalog_sha256,
        "verified_at": verified_at,
    }


@dataclass(frozen=True)
class VerifiedCandidateEnrollmentEntry:
    """One active non-revoked entry selected from a verified catalog."""

    entry: CandidateEnrollmentEntry
    entry_sha256: str
    catalog_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        expected = _proof(
            "verified_candidate_enrollment_entry",
            _entry_material(self.entry, self.catalog_sha256, self.verified_at),
        )
        if (
            self.entry_sha256 != self.entry.content_sha256
            or not isinstance(self._proof, bytes)
            or not hmac.compare_digest(self._proof, expected)
        ):
            raise TypeError(
                "VerifiedCandidateEnrollmentEntry can be created only by "
                "resolve_candidate_enrollment"
            )


def verify_candidate_enrollment_signer_authorization(
    authorization: CandidateEnrollmentSignerAuthorization,
    trusted_root_keys: Mapping[str, bytes | Ed25519PublicKey],
    *,
    d008_decision: QualificationAuthorityDecisionRecord,
    d009_decision: CandidateEnrollmentDecisionRecord,
    verified_qualification_policy: VerifiedQualificationTrustPolicy,
    expected_issuer: str,
    expected_audience: str,
    expected_root_key_id: str,
    minimum_authorization_version: int,
    clock: Callable[[], datetime],
) -> VerifiedCandidateEnrollmentSignerAuthorization:
    """Authenticate separated signer authorization against the D008 root."""

    if not isinstance(authorization, CandidateEnrollmentSignerAuthorization):
        raise QualificationError(
            "authorization must be a CandidateEnrollmentSignerAuthorization"
        )
    authorization = CandidateEnrollmentSignerAuthorization.from_dict(
        authorization.to_dict()
    )
    if not isinstance(d008_decision, QualificationAuthorityDecisionRecord):
        raise QualificationError("d008_decision is invalid")
    d008_decision = QualificationAuthorityDecisionRecord.from_dict(
        d008_decision.to_dict()
    )
    if not isinstance(d009_decision, CandidateEnrollmentDecisionRecord):
        raise QualificationError("d009_decision is invalid")
    d009_decision = CandidateEnrollmentDecisionRecord.from_dict(d009_decision.to_dict())
    _check_proof(
        verified_qualification_policy,
        VerifiedQualificationTrustPolicy,
        "verified_qualification_policy",
    )
    policy = verified_qualification_policy.policy
    if policy.content_sha256 != verified_qualification_policy.policy_sha256:
        raise QualificationError("Verified qualification policy digest is invalid")
    issuer = _auth_value(_identifier, expected_issuer, "expected_issuer")
    audience = _auth_value(_identifier, expected_audience, "expected_audience")
    root_key_id = _auth_value(
        _identifier,
        expected_root_key_id,
        "expected_root_key_id",
    )
    minimum_version = _positive_integer(
        minimum_authorization_version,
        "minimum_authorization_version",
        2_147_483_647,
    )
    if authorization.issuer != issuer:
        raise QualificationError("Candidate enrollment authorization issuer is unexpected")
    if authorization.audience != audience:
        raise QualificationError("Candidate enrollment authorization audience is unexpected")
    if authorization.root_key_id != root_key_id or policy.root_key_id != root_key_id:
        raise QualificationError("Candidate enrollment authorization root is unexpected")
    if authorization.authorization_version < minimum_version:
        raise QualificationError("Candidate enrollment authorization version is too old")
    if authorization.d008_decision != {
        "record_id": d008_decision.record_id,
        "sha256": d008_decision.record_sha256,
    }:
        raise QualificationError("Candidate enrollment D008 binding is stale")
    if authorization.d009_decision != {
        "record_id": d009_decision.record_id,
        "sha256": d009_decision.record_sha256,
    }:
        raise QualificationError("Candidate enrollment D009 binding is stale")
    now = _clock_value(clock)
    starts = _parse_timestamp(authorization.not_before, "authorization")
    expires = _parse_timestamp(authorization.expires_at, "authorization")
    if now < starts:
        raise QualificationError("Candidate enrollment authorization is not active yet")
    if now >= expires:
        raise QualificationError("Candidate enrollment authorization has expired")
    root = _trusted_root(trusted_root_keys, root_key_id)
    root_bytes = _raw_public_key(root)
    root_sha256 = "sha256:" + hashlib.sha256(root_bytes).hexdigest()
    if root_sha256 != verified_qualification_policy.root_key_sha256:
        raise QualificationError("Candidate enrollment root differs from the D008 policy root")
    qualification_key_bytes = {
        _decode_base64url(key.public_key) for key in policy.keys
    }
    for key in authorization.keys:
        raw = _decode_base64url(key.public_key)
        if hmac.compare_digest(raw, root_bytes) or raw in qualification_key_bytes:
            raise QualificationError(
                "Candidate enrollment signer reuses qualification authority key material"
            )
    _auth_value(
        _verify_ed25519,
        root,
        authorization.signature,
        authorization.signing_bytes(),
        "Candidate enrollment signer authorization",
    )
    verified_at = _format_timestamp(now)
    authorization_sha256 = authorization.content_sha256
    material = _authorization_material(
        authorization,
        authorization_sha256,
        root_sha256,
        verified_qualification_policy.policy_sha256,
        verified_at,
    )
    return VerifiedCandidateEnrollmentSignerAuthorization(
        authorization=authorization,
        authorization_sha256=authorization_sha256,
        root_key_sha256=root_sha256,
        policy_sha256=verified_qualification_policy.policy_sha256,
        verified_at=verified_at,
        _proof=_proof("verified_candidate_enrollment_signer_authorization", material),
    )


def _verified_reviewer_credentials(
    credentials: Sequence[VerifiedQualificationReviewerCredential],
    policy: VerifiedQualificationTrustPolicy,
) -> dict[QualificationReviewerRole, VerifiedQualificationReviewerCredential]:
    if not isinstance(credentials, Sequence) or isinstance(credentials, (str, bytes)):
        raise QualificationError("reviewer_credentials must be a sequence")
    if len(credentials) != 2:
        raise QualificationError("Candidate enrollment requires two reviewer credentials")
    result: dict[
        QualificationReviewerRole,
        VerifiedQualificationReviewerCredential,
    ] = {}
    for credential in credentials:
        _check_proof(
            credential,
            VerifiedQualificationReviewerCredential,
            "reviewer credential",
        )
        if credential.policy_sha256 != policy.policy_sha256:
            raise QualificationError("Candidate enrollment reviewer policy binding is stale")
        role = credential.reviewer_role
        if role not in {
            QualificationReviewerRole.INDEPENDENT_ASSURANCE,
            QualificationReviewerRole.INDEPENDENT_CONTROL,
        }:
            raise QualificationError("Candidate enrollment reviewer role is invalid")
        if role in result:
            raise QualificationError("Candidate enrollment reviewer roles are duplicated")
        result[role] = credential
    if set(result) != {
        QualificationReviewerRole.INDEPENDENT_ASSURANCE,
        QualificationReviewerRole.INDEPENDENT_CONTROL,
    }:
        raise QualificationError("Candidate enrollment reviewer roles are incomplete")
    if len({item.reviewer_id for item in result.values()}) != 2:
        raise QualificationError("Candidate enrollment reviewers must be distinct")
    return result


def _verify_release_reviews(
    catalog: CandidateEnrollmentCatalog,
    credentials: dict[
        QualificationReviewerRole,
        VerifiedQualificationReviewerCredential,
    ],
) -> tuple[str, ...]:
    required_profiles = {entry.profile_id for entry in catalog.enrollments}
    credential_sha256s: list[str] = []
    for review in catalog.reviews:
        verified = credentials[review.reviewer_role]
        credential = verified.credential
        if (
            review.reviewer_id != credential.reviewer_id
            or review.credential
            != {
                "credential_id": credential.credential_id,
                "sha256": verified.credential_sha256,
            }
        ):
            raise QualificationError("Candidate enrollment review credential binding is stale")
        if not required_profiles <= set(credential.allowed_profile_ids):
            raise QualificationError("Candidate enrollment review credential scope is too narrow")
        reviewed = _parse_timestamp(review.reviewed_at, "enrollment review")
        if reviewed < _parse_timestamp(credential.not_before, "review credential"):
            raise QualificationError("Candidate enrollment review predates its credential")
        if reviewed >= _parse_timestamp(credential.expires_at, "review credential"):
            raise QualificationError("Candidate enrollment review credential had expired")
        public_key = _auth_value(
            _strict_ed25519_public_key,
            _decode_base64url(credential.public_key),
            "candidate enrollment reviewer public key",
        )
        _auth_value(
            _verify_ed25519,
            public_key,
            review.signature,
            review.signing_bytes(),
            "Candidate enrollment release review",
        )
        credential_sha256s.append(verified.credential_sha256)
    return tuple(credential_sha256s)


def _verify_checkpoint(
    catalog: CandidateEnrollmentCatalog,
    catalog_sha256: str,
    last_seen_checkpoint: CandidateEnrollmentCatalogCheckpoint | None,
) -> CandidateEnrollmentCatalogCheckpoint:
    current = CandidateEnrollmentCatalogCheckpoint(
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.catalog_version,
        catalog_sha256=catalog_sha256,
    )
    if last_seen_checkpoint is None:
        if catalog.catalog_version != 1 or catalog.previous_catalog_sha256 is not None:
            raise QualificationError("Initial candidate enrollment catalog is not version 1")
        return current
    checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
        last_seen_checkpoint.to_dict()
        if isinstance(last_seen_checkpoint, CandidateEnrollmentCatalogCheckpoint)
        else last_seen_checkpoint
    )
    if checkpoint.catalog_id != catalog.catalog_id:
        raise QualificationError("Candidate enrollment catalog ID changed")
    if catalog.catalog_version == checkpoint.catalog_version:
        if catalog_sha256 != checkpoint.catalog_sha256:
            raise QualificationError("Candidate enrollment catalog version was replaced")
        return current
    if catalog.catalog_version != checkpoint.catalog_version + 1:
        raise QualificationError("Candidate enrollment catalog version is not monotonic")
    if catalog.previous_catalog_sha256 != checkpoint.catalog_sha256:
        raise QualificationError("Candidate enrollment catalog predecessor is stale")
    return current


def verify_candidate_enrollment_catalog(
    catalog: CandidateEnrollmentCatalog,
    verified_authorization: VerifiedCandidateEnrollmentSignerAuthorization,
    verified_qualification_policy: VerifiedQualificationTrustPolicy,
    reviewer_credentials: Sequence[VerifiedQualificationReviewerCredential],
    *,
    d009_decision: CandidateEnrollmentDecisionRecord,
    expected_catalog_id: str,
    expected_issuer: str,
    expected_audience: str,
    minimum_catalog_version: int,
    last_seen_checkpoint: CandidateEnrollmentCatalogCheckpoint | None,
    clock: Callable[[], datetime],
) -> VerifiedCandidateEnrollmentCatalog:
    """Authenticate catalog signature, reviews, scope, expiry, and freshness."""

    if not isinstance(catalog, CandidateEnrollmentCatalog):
        raise QualificationError("catalog must be a CandidateEnrollmentCatalog")
    catalog = CandidateEnrollmentCatalog.from_dict(catalog.to_dict())
    _check_proof(
        verified_authorization,
        VerifiedCandidateEnrollmentSignerAuthorization,
        "verified_authorization",
    )
    _check_proof(
        verified_qualification_policy,
        VerifiedQualificationTrustPolicy,
        "verified_qualification_policy",
    )
    if not isinstance(d009_decision, CandidateEnrollmentDecisionRecord):
        raise QualificationError("d009_decision is invalid")
    d009_decision = CandidateEnrollmentDecisionRecord.from_dict(d009_decision.to_dict())
    authorization = verified_authorization.authorization
    policy = verified_qualification_policy.policy
    if authorization.content_sha256 != verified_authorization.authorization_sha256:
        raise QualificationError("Verified enrollment authorization digest is invalid")
    if policy.content_sha256 != verified_qualification_policy.policy_sha256:
        raise QualificationError("Verified qualification policy digest is invalid")
    if verified_authorization.policy_sha256 != verified_qualification_policy.policy_sha256:
        raise QualificationError("Enrollment authorization policy binding is stale")
    expected_id = expected_catalog_id
    if (
        not isinstance(expected_id, str)
        or re.fullmatch(r"CEC-[0-9A-F]{32}", expected_id) is None
    ):
        raise QualificationError("expected_catalog_id is invalid")
    if catalog.catalog_id != expected_id:
        raise QualificationError("Candidate enrollment catalog ID is unexpected")
    issuer = _auth_value(_identifier, expected_issuer, "expected_issuer")
    audience = _auth_value(_identifier, expected_audience, "expected_audience")
    if catalog.issuer != issuer or catalog.issuer != authorization.issuer:
        raise QualificationError("Candidate enrollment catalog issuer is unexpected")
    if catalog.audience != audience:
        raise QualificationError("Candidate enrollment catalog audience is unexpected")
    minimum_version = _positive_integer(
        minimum_catalog_version,
        "minimum_catalog_version",
        2_147_483_647,
    )
    if catalog.catalog_version < minimum_version:
        raise QualificationError("Candidate enrollment catalog version is too old")
    if catalog.authorization != {
        "authorization_id": authorization.authorization_id,
        "authorization_version": authorization.authorization_version,
        "sha256": verified_authorization.authorization_sha256,
    }:
        raise QualificationError("Candidate enrollment authorization binding is stale")
    if catalog.d009_decision != {
        "record_id": d009_decision.record_id,
        "sha256": d009_decision.record_sha256,
    }:
        raise QualificationError("Candidate enrollment catalog D009 binding is stale")
    if catalog.qualification_policy != {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "sha256": verified_qualification_policy.policy_sha256,
    }:
        raise QualificationError("Candidate enrollment qualification policy binding is stale")
    now = _clock_value(clock)
    catalog_start = _parse_timestamp(catalog.not_before, "catalog")
    catalog_end = _parse_timestamp(catalog.expires_at, "catalog")
    if now < catalog_start:
        raise QualificationError("Candidate enrollment catalog is not active yet")
    if now >= catalog_end:
        raise QualificationError("Candidate enrollment catalog has expired")
    authorization_start = _parse_timestamp(authorization.not_before, "authorization")
    authorization_end = _parse_timestamp(authorization.expires_at, "authorization")
    if catalog_start < authorization_start or catalog_end > authorization_end:
        raise QualificationError("Candidate enrollment catalog exceeds authorization window")
    signer = authorization.key(catalog.signer_key_id)
    if signer.state is CandidateEnrollmentSignerKeyState.REVOKED:
        raise QualificationError("Candidate enrollment signer key is revoked")
    issued = _parse_timestamp(catalog.issued_at, "catalog")
    if (
        issued < _parse_timestamp(signer.not_before, signer.key_id)
        or catalog_end > _parse_timestamp(signer.not_after, signer.key_id)
    ):
        raise QualificationError("Candidate enrollment catalog exceeds signer key window")
    if (
        signer.state is CandidateEnrollmentSignerKeyState.RETIRING
        and (
            signer.retire_at is None
            or issued >= _parse_timestamp(signer.retire_at, signer.key_id)
        )
    ):
        raise QualificationError("Candidate enrollment catalog was issued after key retirement")
    signer_public_key = _auth_value(
        _strict_ed25519_public_key,
        _decode_base64url(signer.public_key),
        "candidate enrollment signer public key",
    )
    _auth_value(
        _verify_ed25519,
        signer_public_key,
        catalog.signature,
        catalog.signing_bytes(),
        "Candidate enrollment catalog",
    )
    credentials = _verified_reviewer_credentials(
        reviewer_credentials,
        verified_qualification_policy,
    )
    credential_sha256s = _verify_release_reviews(catalog, credentials)
    prohibited_owner_digests = {
        verified_authorization.root_key_sha256,
        *(
            "sha256:" + hashlib.sha256(_decode_base64url(key.public_key)).hexdigest()
            for key in authorization.keys
        ),
        *(
            "sha256:" + hashlib.sha256(_decode_base64url(key.public_key)).hexdigest()
            for key in policy.keys
        ),
        *(
            "sha256:"
            + hashlib.sha256(
                _decode_base64url(credential.credential.public_key)
            ).hexdigest()
            for credential in credentials.values()
        ),
    }
    if any(
        entry.owner["public_key_sha256"] in prohibited_owner_digests
        for entry in catalog.enrollments
    ):
        raise QualificationError("Candidate owner reuses authority or reviewer key material")
    catalog_sha256 = catalog.content_sha256
    checkpoint = _verify_checkpoint(catalog, catalog_sha256, last_seen_checkpoint)
    verified_at = _format_timestamp(now)
    material = _catalog_material(
        catalog,
        catalog_sha256,
        verified_authorization.authorization_sha256,
        verified_qualification_policy.policy_sha256,
        credential_sha256s,
        verified_at,
        checkpoint,
    )
    return VerifiedCandidateEnrollmentCatalog(
        catalog=catalog,
        catalog_sha256=catalog_sha256,
        authorization_sha256=verified_authorization.authorization_sha256,
        policy_sha256=verified_qualification_policy.policy_sha256,
        reviewer_credential_sha256s=credential_sha256s,
        verified_at=verified_at,
        checkpoint=checkpoint,
        _proof=_proof("verified_candidate_enrollment_catalog", material),
    )


def resolve_candidate_enrollment(
    verified_catalog: VerifiedCandidateEnrollmentCatalog,
    *,
    expected_profile_id: str,
    expected_candidate_id: str,
    expected_candidate_version: str,
    expected_candidate_artifact_sha256: str,
    expected_owner_id: str,
    expected_owner_public_key: str,
    expected_repository_id: str,
    clock: Callable[[], datetime],
) -> VerifiedCandidateEnrollmentEntry:
    """Resolve one exact active enrollment without trusting manifest declarations."""

    _check_proof(
        verified_catalog,
        VerifiedCandidateEnrollmentCatalog,
        "verified_catalog",
    )
    catalog = CandidateEnrollmentCatalog.from_dict(verified_catalog.catalog.to_dict())
    if catalog.content_sha256 != verified_catalog.catalog_sha256:
        raise QualificationError("Verified candidate enrollment catalog digest is invalid")
    profile_id = _specialist_id(expected_profile_id, "expected_profile_id")
    candidate_id = _auth_value(_identifier, expected_candidate_id, "expected_candidate_id")
    candidate_version = _auth_value(
        _identifier,
        expected_candidate_version,
        "expected_candidate_version",
    )
    artifact_sha256 = _sha256(
        expected_candidate_artifact_sha256,
        "expected_candidate_artifact_sha256",
    )
    owner_id = _auth_value(_identifier, expected_owner_id, "expected_owner_id")
    owner_public_key = _public_key(
        expected_owner_public_key,
        "expected_owner_public_key",
    )
    repository_id = _auth_value(
        _identifier,
        expected_repository_id,
        "expected_repository_id",
    )
    now = _clock_value(clock)
    matches = [
        entry
        for entry in catalog.enrollments
        if entry.profile_id == profile_id
        and entry.candidate
        == {
            "candidate_id": candidate_id,
            "candidate_version": candidate_version,
            "candidate_artifact_sha256": artifact_sha256,
        }
        and entry.owner["owner_id"] == owner_id
        and entry.owner["public_key"] == owner_public_key
        and entry.repository["repository_id"] == repository_id
        and _parse_timestamp(entry.not_before, entry.enrollment_id) <= now
        and now < _parse_timestamp(entry.expires_at, entry.enrollment_id)
    ]
    effective_revocations = {
        (revocation.revocation_kind, revocation.subject_id)
        for revocation in catalog.revocations
        if _parse_timestamp(revocation.effective_at, revocation.revocation_id) <= now
    }
    matches = [
        entry
        for entry in matches
        if (
            CandidateEnrollmentRevocationKind.ENROLLMENT,
            entry.enrollment_id,
        )
        not in effective_revocations
        and (CandidateEnrollmentRevocationKind.OWNER_KEY, entry.owner["key_id"])
        not in effective_revocations
        and (
            CandidateEnrollmentRevocationKind.REPOSITORY_IDENTITY,
            entry.repository["repository_id"],
        )
        not in effective_revocations
    ]
    if not matches:
        raise QualificationError("No active non-revoked candidate enrollment matches")
    entry = max(matches, key=lambda item: (item.not_before, item.enrollment_id))
    verified_at = _format_timestamp(now.astimezone(UTC))
    material = _entry_material(entry, verified_catalog.catalog_sha256, verified_at)
    return VerifiedCandidateEnrollmentEntry(
        entry=entry,
        entry_sha256=entry.content_sha256,
        catalog_sha256=verified_catalog.catalog_sha256,
        verified_at=verified_at,
        _proof=_proof("verified_candidate_enrollment_entry", material),
    )


__all__ = [
    "CandidateEnrollmentCatalogCheckpoint",
    "VerifiedCandidateEnrollmentCatalog",
    "VerifiedCandidateEnrollmentEntry",
    "VerifiedCandidateEnrollmentSignerAuthorization",
    "resolve_candidate_enrollment",
    "verify_candidate_enrollment_catalog",
    "verify_candidate_enrollment_signer_authorization",
]
