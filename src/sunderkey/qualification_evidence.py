"""Signed qualification evidence and reviewer attestation contracts."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import QualificationError
from .identity import (
    _decode_base64url,
    _identifier,
    _strict_ed25519_public_key,
    _timestamp,
    _verify_ed25519,
)
from .qualification import (
    QualificationPlanCatalog,
    QualificationStandard,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .qualification_evaluation import (
    CASE_ID_PATTERN,
    QualificationCandidateBinding,
    QualificationEvaluationReport,
    QualificationEvaluationSuite,
    QualificationObservationSet,
    evaluate_qualification_observations,
)
from .qualification_trust import (
    QualificationReviewerCredential,
    QualificationReviewerRole,
    QualificationTrustPolicy,
    VerifiedQualificationReviewerCredential,
    VerifiedQualificationTrustPolicy,
    _auth_value,
    _clock_value,
    _credential_id,
    _format_timestamp,
    _parse_timestamp,
    _positive_integer,
    _public_key,
    _qualification_failure,
    _sha256,
    _signature,
    _specialist_id,
)
from .registry import ExpertRegistry
from .routing import CapabilityCatalog
from .validation import loads_json_without_duplicate_keys

EVIDENCE_MANIFEST_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00QUALIFICATION-EVIDENCE-MANIFEST\x00V1\x00"
)
REVIEWER_ATTESTATION_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00QUALIFICATION-REVIEWER-ATTESTATION\x00V1\x00"
)
CASE_EVIDENCE_DOMAIN = "sunderkey.qualification-case-evidence.v1"

_MANIFEST_ID_PATTERN = re.compile(r"QEM-[0-9A-F]{32}")
_ATTESTATION_ID_PATTERN = re.compile(r"QRA-[0-9A-F]{32}")
_MEDIA_TYPE_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9.+-]{0,62}/[a-z0-9][a-z0-9.+-]{0,62}"
)
_VERIFICATION_PROOF_KEY = secrets.token_bytes(32)


class QualificationEvidenceArtifactType(StrEnum):
    """Portable evidence object types retained by the organization."""

    CANDIDATE_RESULT = "candidate_result"
    SUPPORTING_EVIDENCE = "supporting_evidence"
    REPRODUCTION_MATERIAL = "reproduction_material"
    SCENARIO_INPUT = "scenario_input"
    EXPECTED_RESULT = "expected_result"


class QualificationAttestationConclusion(StrEnum):
    """A reviewer's conclusion about one exact evidence manifest."""

    SUPPORTS_QUALIFICATION = "supports_qualification"
    DOES_NOT_SUPPORT_QUALIFICATION = "does_not_support_qualification"


def _manifest_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _MANIFEST_ID_PATTERN.fullmatch(value) is None
    ):
        raise _qualification_failure(f"{label} is not a valid manifest ID")
    return value


def _attestation_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _ATTESTATION_ID_PATTERN.fullmatch(value) is None
    ):
        raise _qualification_failure(f"{label} is not a valid attestation ID")
    return value


def _case_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or CASE_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid case ID")
    return value


def _media_type(value: Any, label: str) -> str:
    if not isinstance(value, str) or _MEDIA_TYPE_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a canonical media type")
    return value


def _binding(
    raw: Any,
    label: str,
    *,
    id_label: str = "id",
    with_version: bool = True,
) -> dict[str, str]:
    value = _mapping(raw, label)
    fields = {id_label, "sha256"}
    if with_version:
        fields.add("version")
    _exact_fields(value, fields, label)
    result = {
        id_label: _auth_value(
            _identifier,
            value.get(id_label),
            f"{label}.{id_label}",
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }
    if with_version:
        result["version"] = _auth_value(
            _identifier,
            value.get("version"),
            f"{label}.version",
        )
    return result


def _policy_binding(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, {"policy_id", "policy_version", "sha256"}, label)
    return {
        "policy_id": _auth_value(
            _identifier,
            value.get("policy_id"),
            f"{label}.policy_id",
        ),
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
    return {
        "credential_id": _credential_id(
            value.get("credential_id"),
            f"{label}.credential_id",
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


@dataclass(frozen=True)
class QualificationEvidenceArtifact:
    """One immutable object in the content-addressed evidence repository."""

    artifact_id: str
    case_id: str
    artifact_type: QualificationEvidenceArtifactType
    media_type: str
    size_bytes: int
    sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
    ) -> QualificationEvidenceArtifact:
        label = f"qualification evidence manifest.artifacts[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "artifact_id",
                "case_id",
                "artifact_type",
                "media_type",
                "size_bytes",
                "sha256",
            },
            label,
        )
        try:
            artifact_type = QualificationEvidenceArtifactType(
                value.get("artifact_type")
            )
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                f"{label}.artifact_type is invalid"
            ) from exc
        return cls(
            artifact_id=_auth_value(
                _identifier,
                value.get("artifact_id"),
                f"{label}.artifact_id",
            ),
            case_id=_case_id(value.get("case_id"), f"{label}.case_id"),
            artifact_type=artifact_type,
            media_type=_media_type(
                value.get("media_type"),
                f"{label}.media_type",
            ),
            size_bytes=_positive_integer(
                value.get("size_bytes"),
                f"{label}.size_bytes",
                9_223_372_036_854_775_807,
            ),
            sha256=_sha256(value.get("sha256"), f"{label}.sha256"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "case_id": self.case_id,
            "artifact_type": self.artifact_type.value,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


def compute_qualification_case_evidence_sha256(
    case_body: dict[str, Any],
    artifacts: tuple[QualificationEvidenceArtifact, ...],
) -> str:
    """Hash one case record and its exact content-addressed objects."""

    return _canonical_sha256(
        {
            "domain": CASE_EVIDENCE_DOMAIN,
            "case": dict(case_body),
            "artifacts": [artifact.to_dict() for artifact in artifacts],
        }
    )


@dataclass(frozen=True)
class QualificationEvidenceCase:
    """Evidence and observed outcome for one exact qualification case."""

    case_id: str
    gate_id: str
    scenario_sha256: str
    expected_result_sha256: str
    critical_failure_definition_sha256: str
    outcome: str
    critical_failure: bool
    result_sha256: str
    artifact_ids: tuple[str, ...]
    case_evidence_sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
        artifacts_by_id: dict[str, QualificationEvidenceArtifact],
    ) -> QualificationEvidenceCase:
        label = f"qualification evidence manifest.cases[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "case_id",
                "gate_id",
                "scenario_sha256",
                "expected_result_sha256",
                "critical_failure_definition_sha256",
                "outcome",
                "critical_failure",
                "result_sha256",
                "artifact_ids",
                "case_evidence_sha256",
            },
            label,
        )
        outcome = value.get("outcome")
        if outcome not in {"pass", "fail"}:
            raise _qualification_failure(f"{label}.outcome must be pass or fail")
        critical_failure = value.get("critical_failure")
        if not isinstance(critical_failure, bool):
            raise _qualification_failure(
                f"{label}.critical_failure must be a boolean"
            )
        if outcome == "pass" and critical_failure:
            raise _qualification_failure(
                f"{label} cannot pass with a critical failure"
            )
        raw_artifact_ids = value.get("artifact_ids")
        if not isinstance(raw_artifact_ids, list) or not 3 <= len(
            raw_artifact_ids
        ) <= 256:
            raise _qualification_failure(
                f"{label}.artifact_ids must contain between 3 and 256 values"
            )
        artifact_ids = tuple(
            _auth_value(
                _identifier,
                item,
                f"{label}.artifact_ids[{artifact_index}]",
            )
            for artifact_index, item in enumerate(raw_artifact_ids)
        )
        if artifact_ids != tuple(sorted(artifact_ids)) or len(
            set(artifact_ids)
        ) != len(artifact_ids):
            raise _qualification_failure(
                f"{label}.artifact_ids must be unique and in ascending order"
            )
        case_id = _case_id(value.get("case_id"), f"{label}.case_id")
        try:
            artifacts = tuple(artifacts_by_id[item] for item in artifact_ids)
        except KeyError as exc:
            raise _qualification_failure(
                f"{label} references an unknown evidence artifact"
            ) from exc
        if any(artifact.case_id != case_id for artifact in artifacts):
            raise _qualification_failure(
                f"{label} references evidence from another case"
            )
        types = tuple(artifact.artifact_type for artifact in artifacts)
        if types.count(QualificationEvidenceArtifactType.CANDIDATE_RESULT) != 1:
            raise _qualification_failure(
                f"{label} must reference exactly one candidate result"
            )
        if QualificationEvidenceArtifactType.SUPPORTING_EVIDENCE not in types:
            raise _qualification_failure(
                f"{label} must reference supporting evidence"
            )
        if QualificationEvidenceArtifactType.REPRODUCTION_MATERIAL not in types:
            raise _qualification_failure(
                f"{label} must reference reproduction material"
            )
        result_sha256 = _sha256(
            value.get("result_sha256"),
            f"{label}.result_sha256",
        )
        result_artifact = next(
            artifact
            for artifact in artifacts
            if artifact.artifact_type
            is QualificationEvidenceArtifactType.CANDIDATE_RESULT
        )
        if result_artifact.sha256 != result_sha256:
            raise _qualification_failure(
                f"{label} candidate result artifact digest does not match"
            )
        case = cls(
            case_id=case_id,
            gate_id=_auth_value(
                _identifier,
                value.get("gate_id"),
                f"{label}.gate_id",
            ),
            scenario_sha256=_sha256(
                value.get("scenario_sha256"),
                f"{label}.scenario_sha256",
            ),
            expected_result_sha256=_sha256(
                value.get("expected_result_sha256"),
                f"{label}.expected_result_sha256",
            ),
            critical_failure_definition_sha256=_sha256(
                value.get("critical_failure_definition_sha256"),
                f"{label}.critical_failure_definition_sha256",
            ),
            outcome=outcome,
            critical_failure=critical_failure,
            result_sha256=result_sha256,
            artifact_ids=artifact_ids,
            case_evidence_sha256=_sha256(
                value.get("case_evidence_sha256"),
                f"{label}.case_evidence_sha256",
            ),
        )
        if case.case_evidence_sha256 != compute_qualification_case_evidence_sha256(
            case.unsigned_dict(),
            artifacts,
        ):
            raise _qualification_failure(
                f"{label}.case_evidence_sha256 is invalid"
            )
        return case

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "gate_id": self.gate_id,
            "scenario_sha256": self.scenario_sha256,
            "expected_result_sha256": self.expected_result_sha256,
            "critical_failure_definition_sha256": (
                self.critical_failure_definition_sha256
            ),
            "outcome": self.outcome,
            "critical_failure": self.critical_failure,
            "result_sha256": self.result_sha256,
            "artifact_ids": list(self.artifact_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.unsigned_dict(),
            "case_evidence_sha256": self.case_evidence_sha256,
        }


@dataclass(frozen=True)
class QualificationEvidenceManifest:
    """Candidate-owner-signed content-addressed qualification evidence."""

    schema_version: int
    manifest_id: str
    manifest_version: int
    policy: dict[str, Any]
    qualification_standard: dict[str, str]
    evaluation_suite: dict[str, str]
    observation_set: dict[str, str]
    evaluation_report: dict[str, str]
    repository_id: str
    profile_id: str
    candidate: QualificationCandidateBinding
    candidate_owner_id: str
    created_at: str
    artifacts: tuple[QualificationEvidenceArtifact, ...]
    cases: tuple[QualificationEvidenceCase, ...]
    public_key: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationEvidenceManifest:
        value = _mapping(raw, "qualification evidence manifest")
        _exact_fields(
            value,
            {
                "schema_version",
                "manifest_id",
                "manifest_version",
                "policy",
                "qualification_standard",
                "evaluation_suite",
                "observation_set",
                "evaluation_report",
                "repository_id",
                "profile_id",
                "candidate",
                "candidate_owner_id",
                "created_at",
                "artifacts",
                "cases",
                "algorithm",
                "public_key",
                "signature",
            },
            "qualification evidence manifest",
        )
        if value.get("schema_version") != 1:
            raise _qualification_failure(
                "Qualification evidence manifest schema_version must be 1"
            )
        if value.get("algorithm") != "Ed25519":
            raise _qualification_failure(
                "Qualification evidence manifest algorithm must be Ed25519"
            )
        raw_artifacts = value.get("artifacts")
        if not isinstance(raw_artifacts, list) or not 3 <= len(
            raw_artifacts
        ) <= 65_536:
            raise _qualification_failure(
                "Qualification evidence manifest artifacts must contain "
                "between 3 and 65536 values"
            )
        artifacts = tuple(
            QualificationEvidenceArtifact.from_dict(item, index)
            for index, item in enumerate(raw_artifacts)
        )
        if artifacts != tuple(
            sorted(artifacts, key=lambda item: (item.case_id, item.artifact_id))
        ):
            raise _qualification_failure(
                "Qualification evidence manifest artifacts must use canonical order"
            )
        artifact_ids = tuple(item.artifact_id for item in artifacts)
        if len(set(artifact_ids)) != len(artifact_ids):
            raise _qualification_failure(
                "Qualification evidence manifest artifact IDs must be unique"
            )
        artifacts_by_id = {item.artifact_id: item for item in artifacts}
        raw_cases = value.get("cases")
        if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= 4_096:
            raise _qualification_failure(
                "Qualification evidence manifest cases must contain between "
                "1 and 4096 values"
            )
        cases = tuple(
            QualificationEvidenceCase.from_dict(
                item,
                index,
                artifacts_by_id,
            )
            for index, item in enumerate(raw_cases)
        )
        case_ids = tuple(item.case_id for item in cases)
        if case_ids != tuple(sorted(case_ids)) or len(set(case_ids)) != len(
            case_ids
        ):
            raise _qualification_failure(
                "Qualification evidence manifest cases must be unique and in "
                "ascending order"
            )
        referenced_artifacts = tuple(
            artifact_id for case in cases for artifact_id in case.artifact_ids
        )
        if len(set(referenced_artifacts)) != len(referenced_artifacts) or set(
            referenced_artifacts
        ) != set(artifact_ids):
            raise _qualification_failure(
                "Qualification evidence manifest cases must partition every artifact"
            )
        return cls(
            schema_version=1,
            manifest_id=_manifest_id(
                value.get("manifest_id"),
                "qualification evidence manifest.manifest_id",
            ),
            manifest_version=_positive_integer(
                value.get("manifest_version"),
                "qualification evidence manifest.manifest_version",
                2_147_483_647,
            ),
            policy=_policy_binding(
                value.get("policy"),
                "qualification evidence manifest.policy",
            ),
            qualification_standard=_binding(
                value.get("qualification_standard"),
                "qualification evidence manifest.qualification_standard",
            ),
            evaluation_suite=_binding(
                value.get("evaluation_suite"),
                "qualification evidence manifest.evaluation_suite",
            ),
            observation_set=_binding(
                value.get("observation_set"),
                "qualification evidence manifest.observation_set",
            ),
            evaluation_report=_binding(
                value.get("evaluation_report"),
                "qualification evidence manifest.evaluation_report",
                with_version=False,
            ),
            repository_id=_auth_value(
                _identifier,
                value.get("repository_id"),
                "qualification evidence manifest.repository_id",
            ),
            profile_id=_specialist_id(
                value.get("profile_id"),
                "qualification evidence manifest.profile_id",
            ),
            candidate=QualificationCandidateBinding.from_dict(
                value.get("candidate"),
                "qualification evidence manifest.candidate",
            ),
            candidate_owner_id=_auth_value(
                _identifier,
                value.get("candidate_owner_id"),
                "qualification evidence manifest.candidate_owner_id",
            ),
            created_at=_auth_value(
                _timestamp,
                value.get("created_at"),
                "qualification evidence manifest.created_at",
            ),
            artifacts=artifacts,
            cases=cases,
            public_key=_public_key(
                value.get("public_key"),
                "qualification evidence manifest.public_key",
            ),
            signature=_signature(
                value.get("signature"),
                "qualification evidence manifest.signature",
            ),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "policy": dict(self.policy),
            "qualification_standard": dict(self.qualification_standard),
            "evaluation_suite": dict(self.evaluation_suite),
            "observation_set": dict(self.observation_set),
            "evaluation_report": dict(self.evaluation_report),
            "repository_id": self.repository_id,
            "profile_id": self.profile_id,
            "candidate": self.candidate.to_dict(),
            "candidate_owner_id": self.candidate_owner_id,
            "created_at": self.created_at,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "cases": [case.to_dict() for case in self.cases],
            "algorithm": "Ed25519",
            "public_key": self.public_key,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return EVIDENCE_MANIFEST_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


@dataclass(frozen=True)
class QualificationReviewerAttestation:
    """Reviewer-signed conclusion over one exact evidence manifest."""

    schema_version: int
    attestation_id: str
    policy: dict[str, Any]
    reviewer_credential: dict[str, str]
    evidence_manifest: dict[str, str]
    reviewer_id: str
    reviewer_role: QualificationReviewerRole
    profile_id: str
    candidate: QualificationCandidateBinding
    conclusion: QualificationAttestationConclusion
    reason_sha256: str
    reviewed_at: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationReviewerAttestation:
        value = _mapping(raw, "qualification reviewer attestation")
        _exact_fields(
            value,
            {
                "schema_version",
                "attestation_id",
                "policy",
                "reviewer_credential",
                "evidence_manifest",
                "reviewer_id",
                "reviewer_role",
                "profile_id",
                "candidate",
                "conclusion",
                "reason_sha256",
                "reviewed_at",
                "algorithm",
                "signature",
            },
            "qualification reviewer attestation",
        )
        if value.get("schema_version") != 1:
            raise _qualification_failure(
                "Qualification reviewer attestation schema_version must be 1"
            )
        if value.get("algorithm") != "Ed25519":
            raise _qualification_failure(
                "Qualification reviewer attestation algorithm must be Ed25519"
            )
        try:
            role = QualificationReviewerRole(value.get("reviewer_role"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                "Qualification reviewer attestation role is invalid"
            ) from exc
        try:
            conclusion = QualificationAttestationConclusion(
                value.get("conclusion")
            )
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                "Qualification reviewer attestation conclusion is invalid"
            ) from exc
        return cls(
            schema_version=1,
            attestation_id=_attestation_id(
                value.get("attestation_id"),
                "qualification reviewer attestation.attestation_id",
            ),
            policy=_policy_binding(
                value.get("policy"),
                "qualification reviewer attestation.policy",
            ),
            reviewer_credential=_credential_binding(
                value.get("reviewer_credential"),
                "qualification reviewer attestation.reviewer_credential",
            ),
            evidence_manifest=_binding(
                value.get("evidence_manifest"),
                "qualification reviewer attestation.evidence_manifest",
                with_version=False,
            ),
            reviewer_id=_auth_value(
                _identifier,
                value.get("reviewer_id"),
                "qualification reviewer attestation.reviewer_id",
            ),
            reviewer_role=role,
            profile_id=_specialist_id(
                value.get("profile_id"),
                "qualification reviewer attestation.profile_id",
            ),
            candidate=QualificationCandidateBinding.from_dict(
                value.get("candidate"),
                "qualification reviewer attestation.candidate",
            ),
            conclusion=conclusion,
            reason_sha256=_sha256(
                value.get("reason_sha256"),
                "qualification reviewer attestation.reason_sha256",
            ),
            reviewed_at=_auth_value(
                _timestamp,
                value.get("reviewed_at"),
                "qualification reviewer attestation.reviewed_at",
            ),
            signature=_signature(
                value.get("signature"),
                "qualification reviewer attestation.signature",
            ),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attestation_id": self.attestation_id,
            "policy": dict(self.policy),
            "reviewer_credential": dict(self.reviewer_credential),
            "evidence_manifest": dict(self.evidence_manifest),
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role.value,
            "profile_id": self.profile_id,
            "candidate": self.candidate.to_dict(),
            "conclusion": self.conclusion.value,
            "reason_sha256": self.reason_sha256,
            "reviewed_at": self.reviewed_at,
            "algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return REVIEWER_ATTESTATION_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


def _verification_proof(kind: str, material: dict[str, Any]) -> bytes:
    payload = _canonical_json({"kind": kind, "material": material}).encode(
        "ascii"
    )
    return hmac.new(_VERIFICATION_PROOF_KEY, payload, hashlib.sha256).digest()


@dataclass(frozen=True)
class VerifiedQualificationEvidenceManifest:
    """Evidence manifest with authenticated owner and artifact bindings."""

    manifest: QualificationEvidenceManifest
    manifest_sha256: str
    owner_key_sha256: str
    policy_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def _material(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "manifest_sha256": self.manifest_sha256,
            "owner_key_sha256": self.owner_key_sha256,
            "policy_sha256": self.policy_sha256,
            "verified_at": self.verified_at,
        }

    def __post_init__(self) -> None:
        expected = _verification_proof(
            "verified_qualification_evidence_manifest",
            self._material(),
        )
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedQualificationEvidenceManifest can be created only "
                "by verify_qualification_evidence_manifest"
            )


@dataclass(frozen=True)
class VerifiedQualificationReviewerAttestation:
    """Reviewer attestation authenticated against one verified credential."""

    attestation: QualificationReviewerAttestation
    attestation_sha256: str
    credential_sha256: str
    reviewer_key_sha256: str
    manifest_sha256: str
    policy_sha256: str
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def _material(self) -> dict[str, Any]:
        return {
            "attestation": self.attestation.to_dict(),
            "attestation_sha256": self.attestation_sha256,
            "credential_sha256": self.credential_sha256,
            "reviewer_key_sha256": self.reviewer_key_sha256,
            "manifest_sha256": self.manifest_sha256,
            "policy_sha256": self.policy_sha256,
            "verified_at": self.verified_at,
        }

    def __post_init__(self) -> None:
        expected = _verification_proof(
            "verified_qualification_reviewer_attestation",
            self._material(),
        )
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedQualificationReviewerAttestation can be created only "
                "by verify_qualification_reviewer_attestation"
            )

    @property
    def reviewer_id(self) -> str:
        return self.attestation.reviewer_id

    @property
    def reviewer_role(self) -> QualificationReviewerRole:
        return self.attestation.reviewer_role

    @property
    def conclusion(self) -> QualificationAttestationConclusion:
        return self.attestation.conclusion


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
            "verified_credential must be a "
            "VerifiedQualificationReviewerCredential"
        )
    try:
        VerifiedQualificationReviewerCredential.__post_init__(
            verified_credential
        )
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


def verify_qualification_evidence_manifest(
    manifest: QualificationEvidenceManifest,
    verified_policy: VerifiedQualificationTrustPolicy,
    *,
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    qualification_standard: QualificationStandard,
    qualification_plans: QualificationPlanCatalog,
    evaluation_suite: QualificationEvaluationSuite,
    observations: QualificationObservationSet,
    evaluation_report: QualificationEvaluationReport,
    expected_candidate_owner_id: str,
    expected_candidate_owner_public_key: bytes | Ed25519PublicKey,
    expected_repository_id: str,
    clock: Callable[[], datetime],
) -> VerifiedQualificationEvidenceManifest:
    """Authenticate a content-addressed manifest and its exact evidence."""

    if not isinstance(manifest, QualificationEvidenceManifest):
        raise _qualification_failure(
            "manifest must be a QualificationEvidenceManifest"
        )
    manifest = QualificationEvidenceManifest.from_dict(manifest.to_dict())
    policy = _validated_policy(verified_policy)
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
    if not isinstance(qualification_plans, QualificationPlanCatalog):
        raise _qualification_failure(
            "qualification_plans must be a QualificationPlanCatalog"
        )
    if not isinstance(evaluation_suite, QualificationEvaluationSuite):
        raise _qualification_failure(
            "evaluation_suite must be a QualificationEvaluationSuite"
        )
    if not isinstance(observations, QualificationObservationSet):
        raise _qualification_failure(
            "observations must be a QualificationObservationSet"
        )
    if not isinstance(evaluation_report, QualificationEvaluationReport):
        raise _qualification_failure(
            "evaluation_report must be a QualificationEvaluationReport"
        )
    registry.validate()
    catalog = capability_catalog.revalidated(registry)
    standard = qualification_standard.revalidated(registry, catalog)
    plans = qualification_plans.revalidated(registry, catalog, standard)
    suite = evaluation_suite.revalidated(registry, catalog, standard, plans)
    observation_set = observations.revalidated(suite)
    report = QualificationEvaluationReport.from_dict(evaluation_report.to_dict())
    expected_report = evaluate_qualification_observations(
        registry,
        catalog,
        standard,
        plans,
        suite,
        observation_set,
    )
    if report != expected_report:
        raise _qualification_failure(
            "Qualification evidence manifest evaluation report is stale"
        )
    expected_policy = {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "sha256": verified_policy.policy_sha256,
    }
    if manifest.policy != expected_policy:
        raise _qualification_failure(
            "Qualification evidence manifest policy binding is stale"
        )
    expected_standard = {
        "id": standard.standard_id,
        "version": standard.standard_version,
        "sha256": standard.canonical_sha256,
    }
    if manifest.qualification_standard != expected_standard:
        raise _qualification_failure(
            "Qualification evidence manifest standard binding is stale"
        )
    if manifest.evaluation_suite != {
        "id": suite.suite_id,
        "version": suite.suite_version,
        "sha256": suite.canonical_sha256,
    }:
        raise _qualification_failure(
            "Qualification evidence manifest suite binding is stale"
        )
    if manifest.observation_set != {
        "id": observation_set.observation_set_id,
        "version": observation_set.observation_set_version,
        "sha256": observation_set.canonical_sha256,
    }:
        raise _qualification_failure(
            "Qualification evidence manifest observation binding is stale"
        )
    if manifest.evaluation_report != {
        "id": report.report_id,
        "sha256": report.report_sha256,
    }:
        raise _qualification_failure(
            "Qualification evidence manifest report binding is stale"
        )
    if manifest.profile_id != suite.profile_id or manifest.candidate != suite.candidate:
        raise _qualification_failure(
            "Qualification evidence manifest candidate binding is stale"
        )
    if manifest.profile_id not in policy.allowed_profile_ids:
        raise _qualification_failure(
            "Qualification evidence manifest profile is not allowed by policy"
        )
    expected_cases: dict[str, tuple[Any, Any]] = {
        case.case_id: (case, observation_set.observations_by_case_id[case.case_id])
        for case in suite.cases
    }
    if {case.case_id for case in manifest.cases} != set(expected_cases):
        raise _qualification_failure(
            "Qualification evidence manifest must cover every suite case"
        )
    for case in manifest.cases:
        suite_case, observation = expected_cases[case.case_id]
        if (
            case.gate_id != suite_case.gate_id
            or case.scenario_sha256 != suite_case.scenario_sha256
            or case.expected_result_sha256 != suite_case.expected_result_sha256
            or case.critical_failure_definition_sha256
            != suite_case.critical_failure_definition_sha256
            or case.outcome != observation.outcome
            or case.critical_failure != observation.critical_failure
            or case.result_sha256 != observation.result_sha256
            or case.case_evidence_sha256
            != observation.evidence_manifest_sha256
        ):
            raise _qualification_failure(
                f"Qualification evidence case binding is stale: {case.case_id}"
            )
    owner_id = _auth_value(
        _identifier,
        expected_candidate_owner_id,
        "expected_candidate_owner_id",
    )
    repository_id = _auth_value(
        _identifier,
        expected_repository_id,
        "expected_repository_id",
    )
    if manifest.candidate_owner_id != owner_id:
        raise _qualification_failure(
            "Qualification evidence manifest candidate owner is unexpected"
        )
    if manifest.repository_id != repository_id:
        raise _qualification_failure(
            "Qualification evidence repository is unexpected"
        )
    owner_public_key = _auth_value(
        _strict_ed25519_public_key,
        expected_candidate_owner_public_key,
        "candidate owner public key",
    )
    owner_bytes = owner_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(
        owner_bytes,
        _decode_base64url(manifest.public_key),
    ):
        raise _qualification_failure(
            "Qualification evidence manifest owner key is unexpected"
        )
    owner_key_sha256 = "sha256:" + hashlib.sha256(owner_bytes).hexdigest()
    if owner_key_sha256 == verified_policy.root_key_sha256 or any(
        hmac.compare_digest(
            owner_bytes,
            _decode_base64url(key.public_key),
        )
        for key in policy.keys
    ):
        raise _qualification_failure(
            "Qualification evidence owner key must not reuse authority key material"
        )
    created = _parse_timestamp(
        manifest.created_at,
        "qualification evidence manifest",
    )
    policy_start = _parse_timestamp(policy.not_before, "qualification trust policy")
    policy_end = _parse_timestamp(policy.expires_at, "qualification trust policy")
    now = _clock_value(clock)
    if created < policy_start or created >= policy_end:
        raise _qualification_failure(
            "Qualification evidence manifest creation is outside the policy window"
        )
    if created > now:
        raise _qualification_failure(
            "Qualification evidence manifest creation is in the future"
        )
    _auth_value(
        _verify_ed25519,
        owner_public_key,
        manifest.signature,
        manifest.signing_bytes(),
        "Qualification evidence manifest",
    )
    verified_at = _format_timestamp(now)
    material = {
        "manifest": manifest.to_dict(),
        "manifest_sha256": manifest.content_sha256,
        "owner_key_sha256": owner_key_sha256,
        "policy_sha256": verified_policy.policy_sha256,
        "verified_at": verified_at,
    }
    return VerifiedQualificationEvidenceManifest(
        manifest=manifest,
        manifest_sha256=manifest.content_sha256,
        owner_key_sha256=owner_key_sha256,
        policy_sha256=verified_policy.policy_sha256,
        verified_at=verified_at,
        _proof=_verification_proof(
            "verified_qualification_evidence_manifest",
            material,
        ),
    )


def verify_qualification_reviewer_attestation(
    attestation: QualificationReviewerAttestation,
    verified_policy: VerifiedQualificationTrustPolicy,
    verified_credential: VerifiedQualificationReviewerCredential,
    verified_manifest: VerifiedQualificationEvidenceManifest,
    *,
    expected_conclusion: QualificationAttestationConclusion | str,
    clock: Callable[[], datetime],
) -> VerifiedQualificationReviewerAttestation:
    """Authenticate a reviewer conclusion without granting qualification."""

    if not isinstance(attestation, QualificationReviewerAttestation):
        raise _qualification_failure(
            "attestation must be a QualificationReviewerAttestation"
        )
    attestation = QualificationReviewerAttestation.from_dict(
        attestation.to_dict()
    )
    policy = _validated_policy(verified_policy)
    credential = _validated_credential(verified_credential)
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
    try:
        conclusion = QualificationAttestationConclusion(expected_conclusion)
    except (TypeError, ValueError) as exc:
        raise _qualification_failure("expected_conclusion is invalid") from exc
    if verified_credential.policy_sha256 != verified_policy.policy_sha256:
        raise _qualification_failure(
            "Qualification reviewer credential policy does not match"
        )
    if verified_credential.verified_profile_id != manifest.profile_id:
        raise _qualification_failure(
            "Qualification reviewer credential was not verified for the "
            "manifest profile"
        )
    if verified_manifest.policy_sha256 != verified_policy.policy_sha256:
        raise _qualification_failure(
            "Qualification evidence manifest policy does not match"
        )
    if attestation.policy != {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "sha256": verified_policy.policy_sha256,
    }:
        raise _qualification_failure(
            "Qualification reviewer attestation policy binding is stale"
        )
    if attestation.reviewer_credential != {
        "credential_id": credential.credential_id,
        "sha256": credential.content_sha256,
    }:
        raise _qualification_failure(
            "Qualification reviewer attestation credential binding is stale"
        )
    if attestation.evidence_manifest != {
        "id": manifest.manifest_id,
        "sha256": manifest.content_sha256,
    }:
        raise _qualification_failure(
            "Qualification reviewer attestation manifest binding is stale"
        )
    if (
        attestation.reviewer_id != credential.reviewer_id
        or attestation.reviewer_role is not credential.reviewer_role
    ):
        raise _qualification_failure(
            "Qualification reviewer attestation reviewer binding is stale"
        )
    if (
        attestation.profile_id != manifest.profile_id
        or attestation.candidate != manifest.candidate
    ):
        raise _qualification_failure(
            "Qualification reviewer attestation candidate binding is stale"
        )
    if attestation.conclusion is not conclusion:
        raise _qualification_failure(
            "Qualification reviewer attestation conclusion is unexpected"
        )
    if attestation.reviewer_id == manifest.candidate_owner_id:
        raise _qualification_failure(
            "Candidate owner cannot attest to their own qualification evidence"
        )
    reviewer_public_bytes = _decode_base64url(credential.public_key)
    if hmac.compare_digest(
        reviewer_public_bytes,
        _decode_base64url(manifest.public_key),
    ):
        raise _qualification_failure(
            "Candidate owner and reviewer must use distinct key material"
        )
    reviewed = _parse_timestamp(
        attestation.reviewed_at,
        "qualification reviewer attestation",
    )
    if attestation.reviewed_at != verified_credential.verified_at:
        raise _qualification_failure(
            "Reviewer credential must be verified at the attestation time"
        )
    if reviewed < _parse_timestamp(
        manifest.created_at,
        "qualification evidence manifest",
    ):
        raise _qualification_failure(
            "Qualification reviewer attestation predates the evidence manifest"
        )
    now = _clock_value(clock)
    if reviewed > now:
        raise _qualification_failure(
            "Qualification reviewer attestation time is in the future"
        )
    reviewer_public_key = _auth_value(
        _strict_ed25519_public_key,
        reviewer_public_bytes,
        "qualification reviewer public key",
    )
    _auth_value(
        _verify_ed25519,
        reviewer_public_key,
        attestation.signature,
        attestation.signing_bytes(),
        "Qualification reviewer attestation",
    )
    verified_at = _format_timestamp(now)
    reviewer_key_sha256 = (
        "sha256:" + hashlib.sha256(reviewer_public_bytes).hexdigest()
    )
    material = {
        "attestation": attestation.to_dict(),
        "attestation_sha256": attestation.content_sha256,
        "credential_sha256": credential.content_sha256,
        "reviewer_key_sha256": reviewer_key_sha256,
        "manifest_sha256": manifest.content_sha256,
        "policy_sha256": verified_policy.policy_sha256,
        "verified_at": verified_at,
    }
    return VerifiedQualificationReviewerAttestation(
        attestation=attestation,
        attestation_sha256=attestation.content_sha256,
        credential_sha256=credential.content_sha256,
        reviewer_key_sha256=reviewer_key_sha256,
        manifest_sha256=manifest.content_sha256,
        policy_sha256=verified_policy.policy_sha256,
        verified_at=verified_at,
        _proof=_verification_proof(
            "verified_qualification_reviewer_attestation",
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
        raise QualificationError(f"Could not load {label}: {resolved}") from exc


def load_qualification_evidence_manifest(
    path: str | Path,
) -> QualificationEvidenceManifest:
    return QualificationEvidenceManifest.from_dict(
        _load_contract(path, "qualification evidence manifest")
    )


def load_qualification_reviewer_attestation(
    path: str | Path,
) -> QualificationReviewerAttestation:
    return QualificationReviewerAttestation.from_dict(
        _load_contract(path, "qualification reviewer attestation")
    )


__all__ = [
    "CASE_EVIDENCE_DOMAIN",
    "EVIDENCE_MANIFEST_SIGNING_DOMAIN",
    "REVIEWER_ATTESTATION_SIGNING_DOMAIN",
    "QualificationAttestationConclusion",
    "QualificationEvidenceArtifact",
    "QualificationEvidenceArtifactType",
    "QualificationEvidenceCase",
    "QualificationEvidenceManifest",
    "QualificationReviewerAttestation",
    "VerifiedQualificationEvidenceManifest",
    "VerifiedQualificationReviewerAttestation",
    "compute_qualification_case_evidence_sha256",
    "load_qualification_evidence_manifest",
    "load_qualification_reviewer_attestation",
    "verify_qualification_evidence_manifest",
    "verify_qualification_reviewer_attestation",
]
