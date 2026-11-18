"""Signed initial specialist qualification decision contracts."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .identity import (
    _decode_base64url,
    _identifier,
    _strict_ed25519_public_key,
    _timestamp,
    _verify_ed25519,
)
from .qualification import (
    QualificationStandard,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .qualification_evaluation import QualificationCandidateBinding
from .qualification_evidence import (
    QualificationAttestationConclusion,
    QualificationEvidenceManifest,
    QualificationReviewerAttestation,
    VerifiedQualificationEvidenceManifest,
    VerifiedQualificationReviewerAttestation,
    _binding,
    _policy_binding,
)
from .qualification_trust import (
    QualificationAuthorityKeyState,
    QualificationAuthorityKeyUse,
    QualificationReviewerRole,
    QualificationTrustPolicy,
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
from .registry import ExpertRegistry
from .routing import CapabilityCatalog
from .validation import loads_json_without_duplicate_keys

QUALIFICATION_DECISION_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00QUALIFICATION-DECISION\x00V1\x00"
)
_DECISION_ID_PATTERN = re.compile(r"QKD-[0-9A-F]{32}")
_ATTESTATION_ID_PATTERN = re.compile(r"QRA-[0-9A-F]{32}")
_VERIFICATION_PROOF_KEY = secrets.token_bytes(32)


class QualificationDecisionKind(StrEnum):
    """Qualification decisions supported by this contract version."""

    INITIAL_APPROVAL = "initial_approval"


def _decision_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DECISION_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid decision ID")
    return value


def _attestation_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _ATTESTATION_ID_PATTERN.fullmatch(value) is None
    ):
        raise _qualification_failure(f"{label} is not a valid attestation ID")
    return value


@dataclass(frozen=True)
class QualificationDecisionAttestation:
    """One exact verified attestation bound into a decision."""

    attestation_id: str
    reviewer_id: str
    reviewer_role: QualificationReviewerRole
    attestation_sha256: str
    credential_sha256: str
    reviewer_key_sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
    ) -> QualificationDecisionAttestation:
        label = f"qualification decision.attestations[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "attestation_id",
                "reviewer_id",
                "reviewer_role",
                "attestation_sha256",
                "credential_sha256",
                "reviewer_key_sha256",
            },
            label,
        )
        try:
            role = QualificationReviewerRole(value.get("reviewer_role"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(f"{label}.reviewer_role is invalid") from exc
        return cls(
            attestation_id=_attestation_id(
                value.get("attestation_id"),
                f"{label}.attestation_id",
            ),
            reviewer_id=_auth_value(
                _identifier,
                value.get("reviewer_id"),
                f"{label}.reviewer_id",
            ),
            reviewer_role=role,
            attestation_sha256=_sha256(
                value.get("attestation_sha256"),
                f"{label}.attestation_sha256",
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
            "attestation_id": self.attestation_id,
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role.value,
            "attestation_sha256": self.attestation_sha256,
            "credential_sha256": self.credential_sha256,
            "reviewer_key_sha256": self.reviewer_key_sha256,
        }


@dataclass(frozen=True)
class QualificationDecision:
    """Authority-signed initial approval awaiting registry application."""

    schema_version: int
    decision_id: str
    decision_version: int
    decision_kind: QualificationDecisionKind
    policy: dict[str, Any]
    evidence_manifest: dict[str, str]
    profile_id: str
    candidate: QualificationCandidateBinding
    attestations: tuple[QualificationDecisionAttestation, ...]
    decision_status: str
    registry_effect: str
    issued_at: str
    valid_from: str
    valid_until: str
    issuer: str
    signer_key_id: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationDecision:
        value = _mapping(raw, "qualification decision")
        _exact_fields(
            value,
            {
                "schema_version",
                "decision_id",
                "decision_version",
                "decision_kind",
                "policy",
                "evidence_manifest",
                "profile_id",
                "candidate",
                "attestations",
                "decision_status",
                "registry_effect",
                "issued_at",
                "valid_from",
                "valid_until",
                "issuer",
                "signer_key_id",
                "algorithm",
                "signature",
            },
            "qualification decision",
        )
        if value.get("schema_version") != 1:
            raise _qualification_failure(
                "Qualification decision schema_version must be 1"
            )
        if value.get("algorithm") != "Ed25519":
            raise _qualification_failure(
                "Qualification decision algorithm must be Ed25519"
            )
        try:
            kind = QualificationDecisionKind(value.get("decision_kind"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                "Qualification decision kind is invalid"
            ) from exc
        if value.get("decision_status") != "approved":
            raise _qualification_failure(
                "Qualification decision status must be approved"
            )
        if value.get("registry_effect") != "none":
            raise _qualification_failure(
                "Qualification decision registry_effect must be none"
            )
        raw_attestations = value.get("attestations")
        if not isinstance(raw_attestations, list) or not 4 <= len(
            raw_attestations
        ) <= 32:
            raise _qualification_failure(
                "Qualification decision attestations must contain between "
                "4 and 32 values"
            )
        attestations = tuple(
            QualificationDecisionAttestation.from_dict(item, index)
            for index, item in enumerate(raw_attestations)
        )
        canonical = tuple(
            sorted(
                attestations,
                key=lambda item: (
                    item.reviewer_role.value,
                    item.reviewer_id,
                    item.attestation_id,
                ),
            )
        )
        if attestations != canonical:
            raise _qualification_failure(
                "Qualification decision attestations must use canonical order"
            )
        if len({item.attestation_id for item in attestations}) != len(
            attestations
        ):
            raise _qualification_failure(
                "Qualification decision attestation IDs must be unique"
            )
        issued_at = _auth_value(
            _timestamp,
            value.get("issued_at"),
            "qualification decision.issued_at",
        )
        valid_from = _auth_value(
            _timestamp,
            value.get("valid_from"),
            "qualification decision.valid_from",
        )
        valid_until = _auth_value(
            _timestamp,
            value.get("valid_until"),
            "qualification decision.valid_until",
        )
        if (
            _parse_timestamp(issued_at, "qualification decision")
            > _parse_timestamp(valid_from, "qualification decision")
            or _parse_timestamp(valid_from, "qualification decision")
            >= _parse_timestamp(valid_until, "qualification decision")
        ):
            raise _qualification_failure(
                "Qualification decision validity window is invalid"
            )
        return cls(
            schema_version=1,
            decision_id=_decision_id(
                value.get("decision_id"),
                "qualification decision.decision_id",
            ),
            decision_version=_positive_integer(
                value.get("decision_version"),
                "qualification decision.decision_version",
                2_147_483_647,
            ),
            decision_kind=kind,
            policy=_policy_binding(
                value.get("policy"),
                "qualification decision.policy",
            ),
            evidence_manifest=_binding(
                value.get("evidence_manifest"),
                "qualification decision.evidence_manifest",
                with_version=False,
            ),
            profile_id=_specialist_id(
                value.get("profile_id"),
                "qualification decision.profile_id",
            ),
            candidate=QualificationCandidateBinding.from_dict(
                value.get("candidate"),
                "qualification decision.candidate",
            ),
            attestations=attestations,
            decision_status="approved",
            registry_effect="none",
            issued_at=issued_at,
            valid_from=valid_from,
            valid_until=valid_until,
            issuer=_auth_value(
                _identifier,
                value.get("issuer"),
                "qualification decision.issuer",
            ),
            signer_key_id=_auth_value(
                _identifier,
                value.get("signer_key_id"),
                "qualification decision.signer_key_id",
            ),
            signature=_signature(
                value.get("signature"),
                "qualification decision.signature",
            ),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decision_id": self.decision_id,
            "decision_version": self.decision_version,
            "decision_kind": self.decision_kind.value,
            "policy": dict(self.policy),
            "evidence_manifest": dict(self.evidence_manifest),
            "profile_id": self.profile_id,
            "candidate": self.candidate.to_dict(),
            "attestations": [item.to_dict() for item in self.attestations],
            "decision_status": self.decision_status,
            "registry_effect": self.registry_effect,
            "issued_at": self.issued_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "issuer": self.issuer,
            "signer_key_id": self.signer_key_id,
            "algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return QUALIFICATION_DECISION_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


def _verification_proof(material: dict[str, Any]) -> bytes:
    payload = _canonical_json(
        {"kind": "verified_qualification_decision", "material": material}
    ).encode("ascii")
    return hmac.new(_VERIFICATION_PROOF_KEY, payload, hashlib.sha256).digest()


@dataclass(frozen=True)
class VerifiedQualificationDecision:
    """Authenticated qualification approval with no direct registry effect."""

    decision: QualificationDecision
    decision_sha256: str
    policy_sha256: str
    manifest_sha256: str
    signer_key_sha256: str
    reviewer_ids: tuple[str, ...]
    reviewer_key_sha256s: tuple[str, ...]
    manifest_created_at: str
    reviewer_reviewed_ats: tuple[str, ...]
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def _material(self) -> dict[str, Any]:
        return {
            "decision": self.decision.to_dict(),
            "decision_sha256": self.decision_sha256,
            "policy_sha256": self.policy_sha256,
            "manifest_sha256": self.manifest_sha256,
            "signer_key_sha256": self.signer_key_sha256,
            "reviewer_ids": list(self.reviewer_ids),
            "reviewer_key_sha256s": list(self.reviewer_key_sha256s),
            "manifest_created_at": self.manifest_created_at,
            "reviewer_reviewed_ats": list(self.reviewer_reviewed_ats),
            "verified_at": self.verified_at,
        }

    def __post_init__(self) -> None:
        expected = _verification_proof(self._material())
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedQualificationDecision can be created only by "
                "verify_qualification_decision"
            )


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


def _validated_manifest(
    verified_manifest: VerifiedQualificationEvidenceManifest,
) -> QualificationEvidenceManifest:
    if type(verified_manifest) is not VerifiedQualificationEvidenceManifest:
        raise _qualification_failure(
            "verified_manifest must be a VerifiedQualificationEvidenceManifest"
        )
    try:
        VerifiedQualificationEvidenceManifest.__post_init__(verified_manifest)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification evidence manifest proof is invalid"
        ) from exc
    manifest = QualificationEvidenceManifest.from_dict(
        verified_manifest.manifest.to_dict()
    )
    if manifest.content_sha256 != verified_manifest.manifest_sha256:
        raise _qualification_failure(
            "Verified qualification evidence manifest digest is invalid"
        )
    return manifest


def _validated_attestation(
    verified: VerifiedQualificationReviewerAttestation,
) -> tuple[QualificationReviewerAttestation, QualificationDecisionAttestation]:
    if type(verified) is not VerifiedQualificationReviewerAttestation:
        raise _qualification_failure(
            "verified attestations must be "
            "VerifiedQualificationReviewerAttestation values"
        )
    try:
        VerifiedQualificationReviewerAttestation.__post_init__(verified)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification reviewer attestation proof is invalid"
        ) from exc
    attestation = QualificationReviewerAttestation.from_dict(
        verified.attestation.to_dict()
    )
    if attestation.content_sha256 != verified.attestation_sha256:
        raise _qualification_failure(
            "Verified qualification reviewer attestation digest is invalid"
        )
    binding = QualificationDecisionAttestation(
        attestation_id=attestation.attestation_id,
        reviewer_id=attestation.reviewer_id,
        reviewer_role=attestation.reviewer_role,
        attestation_sha256=verified.attestation_sha256,
        credential_sha256=verified.credential_sha256,
        reviewer_key_sha256=verified.reviewer_key_sha256,
    )
    return attestation, binding


def verify_qualification_decision(
    decision: QualificationDecision,
    verified_policy: VerifiedQualificationTrustPolicy,
    verified_manifest: VerifiedQualificationEvidenceManifest,
    verified_attestations: Sequence[VerifiedQualificationReviewerAttestation],
    *,
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    qualification_standard: QualificationStandard,
    clock: Callable[[], datetime],
) -> VerifiedQualificationDecision:
    """Authenticate a complete initial approval without applying it."""

    if not isinstance(decision, QualificationDecision):
        raise _qualification_failure("decision must be a QualificationDecision")
    decision = QualificationDecision.from_dict(decision.to_dict())
    policy = _validated_policy(verified_policy)
    manifest = _validated_manifest(verified_manifest)
    if verified_manifest.policy_sha256 != verified_policy.policy_sha256:
        raise _qualification_failure(
            "Qualification evidence manifest policy does not match"
        )
    if not isinstance(registry, ExpertRegistry):
        raise _qualification_failure("registry must be an ExpertRegistry")
    if not isinstance(capability_catalog, CapabilityCatalog):
        raise _qualification_failure(
            "capability_catalog must be a CapabilityCatalog"
        )
    if not isinstance(qualification_standard, QualificationStandard):
        raise _qualification_failure(
            "qualification_standard must be a QualificationStandard"
        )
    registry.validate()
    catalog = capability_catalog.revalidated(registry)
    standard = qualification_standard.revalidated(registry, catalog)
    if manifest.qualification_standard != {
        "id": standard.standard_id,
        "version": standard.standard_version,
        "sha256": standard.canonical_sha256,
    }:
        raise _qualification_failure(
            "Qualification decision standard binding is stale"
        )
    if not isinstance(verified_attestations, Sequence) or isinstance(
        verified_attestations,
        (str, bytes),
    ):
        raise _qualification_failure("verified_attestations must be a sequence")
    validated = tuple(
        _validated_attestation(item) for item in verified_attestations
    )
    attestations = tuple(item[0] for item in validated)
    bindings = tuple(item[1] for item in validated)
    canonical_bindings = tuple(
        sorted(
            bindings,
            key=lambda item: (
                item.reviewer_role.value,
                item.reviewer_id,
                item.attestation_id,
            ),
        )
    )
    if decision.attestations != canonical_bindings:
        raise _qualification_failure(
            "Qualification decision attestation binding is stale"
        )
    bindings = canonical_bindings
    if len(attestations) != len(decision.attestations):
        raise _qualification_failure(
            "Qualification decision attestation count is invalid"
        )
    if any(
        item.policy_sha256 != verified_policy.policy_sha256
        or item.manifest_sha256 != verified_manifest.manifest_sha256
        for item in verified_attestations
    ):
        raise _qualification_failure(
            "Qualification decision attestation policy or manifest is stale"
        )
    if any(
        item.conclusion
        is not QualificationAttestationConclusion.SUPPORTS_QUALIFICATION
        for item in attestations
    ):
        raise _qualification_failure(
            "Qualification decision requires supporting attestations"
        )
    reviewer_ids = tuple(item.reviewer_id for item in bindings)
    reviewer_keys = tuple(item.reviewer_key_sha256 for item in bindings)
    credential_hashes = tuple(item.credential_sha256 for item in bindings)
    attestations_by_id = {
        item.attestation_id: item for item in attestations
    }
    reviewer_reviewed_ats = tuple(
        attestations_by_id[item.attestation_id].reviewed_at
        for item in bindings
    )
    if (
        len(set(reviewer_ids)) != len(reviewer_ids)
        or len(set(reviewer_keys)) != len(reviewer_keys)
        or len(set(credential_hashes)) != len(credential_hashes)
    ):
        raise _qualification_failure(
            "Qualification decision reviewers, keys, and credentials must be distinct"
        )
    role_counts = {
        role: sum(item.reviewer_role is role for item in bindings)
        for role in QualificationReviewerRole
    }
    if standard.decision_policy.allow_self_attestation:
        raise _qualification_failure(
            "Qualification decision standard must prohibit self-attestation"
        )
    if (
        role_counts[QualificationReviewerRole.TECHNICAL_EVALUATOR]
        < standard.decision_policy.minimum_distinct_evaluators
    ):
        raise _qualification_failure(
            "Qualification decision has too few distinct technical evaluators"
        )
    if (
        standard.decision_policy.require_independent_control_review
        and role_counts[QualificationReviewerRole.INDEPENDENT_CONTROL] < 1
    ):
        raise _qualification_failure(
            "Qualification decision requires independent Control review"
        )
    if (
        standard.decision_policy.require_independent_assurance_review
        and role_counts[QualificationReviewerRole.INDEPENDENT_ASSURANCE] < 1
    ):
        raise _qualification_failure(
            "Qualification decision requires independent Assurance review"
        )
    if decision.policy != {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "sha256": verified_policy.policy_sha256,
    }:
        raise _qualification_failure(
            "Qualification decision policy binding is stale"
        )
    if decision.evidence_manifest != {
        "id": manifest.manifest_id,
        "sha256": manifest.content_sha256,
    }:
        raise _qualification_failure(
            "Qualification decision evidence binding is stale"
        )
    if (
        decision.profile_id != manifest.profile_id
        or decision.candidate != manifest.candidate
    ):
        raise _qualification_failure(
            "Qualification decision candidate binding is stale"
        )
    if decision.issuer != policy.issuer:
        raise _qualification_failure(
            "Qualification decision issuer does not match policy"
        )
    if decision.profile_id not in policy.allowed_profile_ids:
        raise _qualification_failure(
            "Qualification decision profile is outside policy scope"
        )
    signer = policy.key(decision.signer_key_id)
    if signer.key_use is not QualificationAuthorityKeyUse.QUALIFICATION_DECISION:
        raise _qualification_failure(
            "Qualification decision signer key use is not authorized"
        )
    if decision.profile_id not in signer.allowed_profile_ids:
        raise _qualification_failure(
            "Qualification decision signer profile scope is stale"
        )
    if signer.state is QualificationAuthorityKeyState.REVOKED:
        raise _qualification_failure(
            "Qualification decision signer key is revoked"
        )
    issued = _parse_timestamp(decision.issued_at, "qualification decision")
    starts = _parse_timestamp(decision.valid_from, "qualification decision")
    expires = _parse_timestamp(decision.valid_until, "qualification decision")
    key_start = _parse_timestamp(signer.not_before, signer.key_id)
    key_end = _parse_timestamp(signer.not_after, signer.key_id)
    policy_start = _parse_timestamp(policy.not_before, "qualification trust policy")
    policy_end = _parse_timestamp(policy.expires_at, "qualification trust policy")
    if issued < key_start or issued >= key_end:
        raise _qualification_failure(
            "Qualification decision issuance is outside the signer key window"
        )
    if starts < policy_start or expires > policy_end:
        raise _qualification_failure(
            "Qualification decision exceeds the policy window"
        )
    if signer.state is QualificationAuthorityKeyState.RETIRING and (
        signer.retire_at is None
        or issued >= _parse_timestamp(signer.retire_at, signer.key_id)
    ):
        raise _qualification_failure(
            "Qualification decision was issued after key retirement"
        )
    maximum_seconds = standard.decision_policy.qualification_validity_days * 86_400
    if int((expires - starts).total_seconds()) > maximum_seconds:
        raise _qualification_failure(
            "Qualification decision exceeds the standard validity window"
        )
    if any(
        _parse_timestamp(item.reviewed_at, "qualification reviewer attestation")
        > issued
        for item in attestations
    ):
        raise _qualification_failure(
            "Qualification decision predates a required attestation"
        )
    now = _clock_value(clock)
    if now < starts:
        raise _qualification_failure("Qualification decision is not active yet")
    if now >= expires:
        raise _qualification_failure("Qualification decision has expired")
    signer_public_bytes = _decode_base64url(signer.public_key)
    signer_public_key = _auth_value(
        _strict_ed25519_public_key,
        signer_public_bytes,
        f"qualification decision key {signer.key_id}",
    )
    _auth_value(
        _verify_ed25519,
        signer_public_key,
        decision.signature,
        decision.signing_bytes(),
        "Qualification decision",
    )
    signer_key_sha256 = (
        "sha256:" + hashlib.sha256(signer_public_bytes).hexdigest()
    )
    verified_at = _format_timestamp(now)
    material = {
        "decision": decision.to_dict(),
        "decision_sha256": decision.content_sha256,
        "policy_sha256": verified_policy.policy_sha256,
        "manifest_sha256": verified_manifest.manifest_sha256,
        "signer_key_sha256": signer_key_sha256,
        "reviewer_ids": list(reviewer_ids),
        "reviewer_key_sha256s": list(reviewer_keys),
        "manifest_created_at": manifest.created_at,
        "reviewer_reviewed_ats": list(reviewer_reviewed_ats),
        "verified_at": verified_at,
    }
    return VerifiedQualificationDecision(
        decision=decision,
        decision_sha256=decision.content_sha256,
        policy_sha256=verified_policy.policy_sha256,
        manifest_sha256=verified_manifest.manifest_sha256,
        signer_key_sha256=signer_key_sha256,
        reviewer_ids=reviewer_ids,
        reviewer_key_sha256s=reviewer_keys,
        manifest_created_at=manifest.created_at,
        reviewer_reviewed_ats=reviewer_reviewed_ats,
        verified_at=verified_at,
        _proof=_verification_proof(material),
    )


def load_qualification_decision(path: str | Path) -> QualificationDecision:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load qualification decision: {resolved}"
        ) from exc
    return QualificationDecision.from_dict(raw)


__all__ = [
    "QUALIFICATION_DECISION_SIGNING_DOMAIN",
    "QualificationDecision",
    "QualificationDecisionAttestation",
    "QualificationDecisionKind",
    "VerifiedQualificationDecision",
    "load_qualification_decision",
    "verify_qualification_decision",
]
