"""Enrollment-bound qualification evidence manifest verification."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .candidate_enrollment_verification import (
    VerifiedCandidateEnrollmentCatalog,
    VerifiedCandidateEnrollmentEntry,
    _check_proof,
    resolve_candidate_enrollment,
)
from .errors import QualificationError
from .identity import _decode_base64url
from .qualification import (
    QualificationPlanCatalog,
    QualificationStandard,
    _canonical_json,
)
from .qualification_evaluation import (
    QualificationEvaluationReport,
    QualificationEvaluationSuite,
    QualificationObservationSet,
)
from .qualification_evidence import (
    QualificationEvidenceManifest,
    VerifiedQualificationEvidenceManifest,
    verify_qualification_evidence_manifest,
)
from .qualification_trust import (
    VerifiedQualificationTrustPolicy,
    _clock_value,
    _format_timestamp,
    _parse_timestamp,
)
from .registry import ExpertRegistry
from .routing import CapabilityCatalog

_VERIFICATION_PROOF_KEY = secrets.token_bytes(32)


def _material(
    verified_manifest: VerifiedQualificationEvidenceManifest,
    verified_enrollment: VerifiedCandidateEnrollmentEntry,
    verified_at: str,
) -> dict[str, Any]:
    return {
        "manifest": verified_manifest.manifest.to_dict(),
        "manifest_sha256": verified_manifest.manifest_sha256,
        "owner_key_sha256": verified_manifest.owner_key_sha256,
        "policy_sha256": verified_manifest.policy_sha256,
        "enrollment": verified_enrollment.entry.to_dict(),
        "enrollment_sha256": verified_enrollment.entry_sha256,
        "catalog_sha256": verified_enrollment.catalog_sha256,
        "verified_at": verified_at,
    }


def _proof(material: dict[str, Any]) -> bytes:
    payload = _canonical_json(
        {
            "kind": "verified_enrolled_qualification_evidence_manifest",
            "material": material,
        }
    ).encode("ascii")
    return hmac.new(_VERIFICATION_PROOF_KEY, payload, "sha256").digest()


@dataclass(frozen=True)
class VerifiedEnrolledQualificationEvidenceManifest:
    """Evidence manifest authenticated through one verified D009 enrollment."""

    verified_manifest: VerifiedQualificationEvidenceManifest
    verified_enrollment: VerifiedCandidateEnrollmentEntry
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            VerifiedQualificationEvidenceManifest.__post_init__(
                self.verified_manifest
            )
            VerifiedCandidateEnrollmentEntry.__post_init__(
                self.verified_enrollment
            )
        except TypeError as exc:
            raise TypeError(
                "VerifiedEnrolledQualificationEvidenceManifest requires valid "
                "manifest and enrollment proofs"
            ) from exc
        expected = _proof(
            _material(
                self.verified_manifest,
                self.verified_enrollment,
                self.verified_at,
            )
        )
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedEnrolledQualificationEvidenceManifest can be created "
                "only by verify_enrolled_qualification_evidence_manifest"
            )

    @property
    def manifest(self) -> QualificationEvidenceManifest:
        return self.verified_manifest.manifest

    @property
    def manifest_sha256(self) -> str:
        return self.verified_manifest.manifest_sha256

    @property
    def enrollment_sha256(self) -> str:
        return self.verified_enrollment.entry_sha256

    @property
    def catalog_sha256(self) -> str:
        return self.verified_enrollment.catalog_sha256


def verify_enrolled_qualification_evidence_manifest(
    manifest: QualificationEvidenceManifest,
    verified_policy: VerifiedQualificationTrustPolicy,
    verified_catalog: VerifiedCandidateEnrollmentCatalog,
    *,
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    qualification_standard: QualificationStandard,
    qualification_plans: QualificationPlanCatalog,
    evaluation_suite: QualificationEvaluationSuite,
    observations: QualificationObservationSet,
    evaluation_report: QualificationEvaluationReport,
    clock: Callable[[], datetime],
) -> VerifiedEnrolledQualificationEvidenceManifest:
    """Verify evidence using only independently enrolled owner and repository values."""

    if not isinstance(manifest, QualificationEvidenceManifest):
        raise QualificationError("manifest must be a QualificationEvidenceManifest")
    manifest = QualificationEvidenceManifest.from_dict(manifest.to_dict())
    _check_proof(
        verified_catalog,
        VerifiedCandidateEnrollmentCatalog,
        "verified_catalog",
    )
    _check_proof(
        verified_policy,
        VerifiedQualificationTrustPolicy,
        "verified_policy",
    )
    if verified_catalog.policy_sha256 != verified_policy.policy_sha256:
        raise QualificationError("Candidate enrollment and evidence policy bindings differ")
    now = _clock_value(clock)
    enrollment = resolve_candidate_enrollment(
        verified_catalog,
        expected_profile_id=manifest.profile_id,
        expected_candidate_id=manifest.candidate.candidate_id,
        expected_candidate_version=manifest.candidate.candidate_version,
        expected_candidate_artifact_sha256=(
            manifest.candidate.candidate_artifact_sha256
        ),
        expected_owner_id=manifest.candidate_owner_id,
        expected_owner_public_key=manifest.public_key,
        expected_repository_id=manifest.repository_id,
        clock=lambda: now,
    )
    created = _parse_timestamp(manifest.created_at, "qualification evidence manifest")
    if created < _parse_timestamp(enrollment.entry.not_before, "enrollment"):
        raise QualificationError("Qualification evidence predates candidate enrollment")
    if created >= _parse_timestamp(enrollment.entry.expires_at, "enrollment"):
        raise QualificationError("Qualification evidence was created after enrollment expiry")
    verified_manifest = verify_qualification_evidence_manifest(
        manifest,
        verified_policy,
        registry=registry,
        capability_catalog=capability_catalog,
        qualification_standard=qualification_standard,
        qualification_plans=qualification_plans,
        evaluation_suite=evaluation_suite,
        observations=observations,
        evaluation_report=evaluation_report,
        expected_candidate_owner_id=enrollment.entry.owner["owner_id"],
        expected_candidate_owner_public_key=_decode_base64url(
            enrollment.entry.owner["public_key"]
        ),
        expected_repository_id=enrollment.entry.repository["repository_id"],
        clock=lambda: now,
    )
    verified_at = _format_timestamp(now)
    material = _material(verified_manifest, enrollment, verified_at)
    return VerifiedEnrolledQualificationEvidenceManifest(
        verified_manifest=verified_manifest,
        verified_enrollment=enrollment,
        verified_at=verified_at,
        _proof=_proof(material),
    )


__all__ = [
    "VerifiedEnrolledQualificationEvidenceManifest",
    "verify_enrolled_qualification_evidence_manifest",
]
