"""Offline cryptographic preflight for deployment-specific enrollment artifacts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_enrollment import (
    CandidateEnrollmentCatalog,
    CandidateEnrollmentSignerAuthorization,
)
from .candidate_enrollment_decision import CandidateEnrollmentDecisionRecord
from .candidate_enrollment_deployment import (
    CandidateEnrollmentDeploymentPreparationPacket,
)
from .candidate_enrollment_deployment_inputs import (
    CandidateEnrollmentDeploymentPreflightReport,
    CandidateEnrollmentDeploymentWorksheet,
    assess_candidate_enrollment_deployment_inputs,
)
from .candidate_enrollment_verification import (
    CandidateEnrollmentCatalogCheckpoint,
    verify_candidate_enrollment_catalog,
    verify_candidate_enrollment_signer_authorization,
)
from .errors import QualificationError
from .identity import _decode_base64url, _identifier
from .qualification import (
    QualificationStandard,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .qualification_authority_decision import QualificationAuthorityDecisionRecord
from .qualification_trust import (
    QualificationReviewerCredential,
    QualificationReviewerRole,
    QualificationTrustPolicy,
    _auth_value,
    _parse_timestamp,
    _positive_integer,
    _public_key,
    _specialist_id,
    verify_qualification_reviewer_credential,
    verify_qualification_trust_policy,
)
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
RECEIPT_DOMAIN = "sunderkey.candidate-enrollment-deployment-verification.v1"
_RECEIPT_ID_PATTERN = re.compile(r"CVR-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

VERIFICATION_GATES = (
    "worksheet_documentation_complete",
    "d008_policy_root_signature_and_scope_verified",
    "control_reviewer_credential_verified",
    "assurance_reviewer_credential_verified",
    "d009_signer_authorization_root_signature_and_scope_verified",
    "catalog_control_and_assurance_reviews_verified",
    "catalog_signature_scope_expiry_and_freshness_verified",
    "next_catalog_checkpoint_derived",
)

PROHIBITED_EFFECTS = (
    "does_not_persist_or_distribute_the_verified_checkpoint",
    "does_not_publish_or_distribute_the_verified_catalog",
    "does_not_enroll_a_live_owner_candidate_or_repository",
    "does_not_accept_or_retrieve_live_evidence",
    "does_not_qualify_a_candidate_or_specialist",
    "does_not_change_registry_status_or_routing_eligibility",
    "does_not_make_network_provider_tool_retrieval_or_target_requests",
    "does_not_mutate_runtime_or_sqlite_state",
)


def _binding(raw: Any, label: str, id_field: str, pattern: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {id_field, "sha256"}, label)
    identifier = value.get(id_field)
    digest = value.get("sha256")
    if (
        not isinstance(identifier, str)
        or re.fullmatch(pattern, identifier) is None
        or not isinstance(digest, str)
        or _SHA256_PATTERN.fullmatch(digest) is None
    ):
        raise QualificationError(f"{label} is invalid")
    return {id_field: identifier, "sha256": digest}


@dataclass(frozen=True)
class CandidateEnrollmentDeploymentVerificationContext:
    """Public expectations supplied out of band by the deployment owner."""

    qualification_issuer: str
    qualification_audience: str
    root_key_id: str
    root_public_key: str
    minimum_policy_version: int
    authorization_issuer: str
    authorization_audience: str
    minimum_authorization_version: int
    catalog_id: str
    catalog_issuer: str
    catalog_audience: str
    minimum_catalog_version: int
    profile_id: str
    control_reviewer_id: str
    assurance_reviewer_id: str
    verification_time: str
    last_seen_checkpoint: CandidateEnrollmentCatalogCheckpoint | None
    document_json: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> CandidateEnrollmentDeploymentVerificationContext:
        value = _mapping(raw, "candidate enrollment deployment verification context")
        fields = {
            "schema_version",
            "qualification_policy",
            "signer_authorization",
            "catalog",
            "profile_id",
            "reviewers",
            "verification_time",
            "last_seen_checkpoint",
            "context_effect",
        }
        _exact_fields(value, fields, "candidate enrollment deployment verification context")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment verification context schema is invalid")
        qualification = _mapping(
            value.get("qualification_policy"),
            "verification context qualification policy",
        )
        _exact_fields(
            qualification,
            {
                "expected_issuer",
                "expected_audience",
                "root_key_id",
                "root_public_key",
                "minimum_version",
            },
            "verification context qualification policy",
        )
        authorization = _mapping(
            value.get("signer_authorization"),
            "verification context signer authorization",
        )
        _exact_fields(
            authorization,
            {"expected_issuer", "expected_audience", "minimum_version"},
            "verification context signer authorization",
        )
        catalog = _mapping(value.get("catalog"), "verification context catalog")
        _exact_fields(
            catalog,
            {"expected_catalog_id", "expected_issuer", "expected_audience", "minimum_version"},
            "verification context catalog",
        )
        catalog_id = catalog.get("expected_catalog_id")
        if (
            not isinstance(catalog_id, str)
            or re.fullmatch(r"CEC-[0-9A-F]{32}", catalog_id) is None
        ):
            raise QualificationError("Verification context catalog ID is invalid")
        reviewers = _mapping(value.get("reviewers"), "verification context reviewers")
        _exact_fields(
            reviewers,
            {"independent_control", "independent_assurance"},
            "verification context reviewers",
        )
        control = _mapping(
            reviewers.get("independent_control"),
            "verification context Control reviewer",
        )
        assurance = _mapping(
            reviewers.get("independent_assurance"),
            "verification context Assurance reviewer",
        )
        _exact_fields(control, {"reviewer_id"}, "verification context Control reviewer")
        _exact_fields(
            assurance,
            {"reviewer_id"},
            "verification context Assurance reviewer",
        )
        checkpoint_raw = value.get("last_seen_checkpoint")
        checkpoint = (
            None
            if checkpoint_raw is None
            else CandidateEnrollmentCatalogCheckpoint.from_dict(checkpoint_raw)
        )
        verification_time = value.get("verification_time")
        if not isinstance(verification_time, str):
            raise QualificationError("Verification context time is invalid")
        _parse_timestamp(verification_time, "verification_time")
        if value.get("context_effect") != "verification_inputs_only":
            raise QualificationError("Candidate enrollment verification context effect is invalid")
        normalized = {
            "schema_version": SCHEMA_VERSION,
            "qualification_policy": {
                "expected_issuer": _auth_value(
                    _identifier,
                    qualification.get("expected_issuer"),
                    "qualification_policy.expected_issuer",
                ),
                "expected_audience": _auth_value(
                    _identifier,
                    qualification.get("expected_audience"),
                    "qualification_policy.expected_audience",
                ),
                "root_key_id": _auth_value(
                    _identifier,
                    qualification.get("root_key_id"),
                    "qualification_policy.root_key_id",
                ),
                "root_public_key": _public_key(
                    qualification.get("root_public_key"),
                    "qualification_policy.root_public_key",
                ),
                "minimum_version": _positive_integer(
                    qualification.get("minimum_version"),
                    "qualification_policy.minimum_version",
                    2_147_483_647,
                ),
            },
            "signer_authorization": {
                "expected_issuer": _auth_value(
                    _identifier,
                    authorization.get("expected_issuer"),
                    "signer_authorization.expected_issuer",
                ),
                "expected_audience": _auth_value(
                    _identifier,
                    authorization.get("expected_audience"),
                    "signer_authorization.expected_audience",
                ),
                "minimum_version": _positive_integer(
                    authorization.get("minimum_version"),
                    "signer_authorization.minimum_version",
                    2_147_483_647,
                ),
            },
            "catalog": {
                "expected_catalog_id": catalog_id,
                "expected_issuer": _auth_value(
                    _identifier,
                    catalog.get("expected_issuer"),
                    "catalog.expected_issuer",
                ),
                "expected_audience": _auth_value(
                    _identifier,
                    catalog.get("expected_audience"),
                    "catalog.expected_audience",
                ),
                "minimum_version": _positive_integer(
                    catalog.get("minimum_version"),
                    "catalog.minimum_version",
                    2_147_483_647,
                ),
            },
            "profile_id": _specialist_id(value.get("profile_id"), "profile_id"),
            "reviewers": {
                "independent_control": {
                    "reviewer_id": _auth_value(
                        _identifier,
                        control.get("reviewer_id"),
                        "reviewers.independent_control.reviewer_id",
                    )
                },
                "independent_assurance": {
                    "reviewer_id": _auth_value(
                        _identifier,
                        assurance.get("reviewer_id"),
                        "reviewers.independent_assurance.reviewer_id",
                    )
                },
            },
            "verification_time": verification_time,
            "last_seen_checkpoint": None if checkpoint is None else checkpoint.to_dict(),
            "context_effect": "verification_inputs_only",
        }
        return cls(
            qualification_issuer=normalized["qualification_policy"]["expected_issuer"],
            qualification_audience=normalized["qualification_policy"]["expected_audience"],
            root_key_id=normalized["qualification_policy"]["root_key_id"],
            root_public_key=normalized["qualification_policy"]["root_public_key"],
            minimum_policy_version=normalized["qualification_policy"]["minimum_version"],
            authorization_issuer=normalized["signer_authorization"]["expected_issuer"],
            authorization_audience=normalized["signer_authorization"]["expected_audience"],
            minimum_authorization_version=normalized["signer_authorization"]["minimum_version"],
            catalog_id=normalized["catalog"]["expected_catalog_id"],
            catalog_issuer=normalized["catalog"]["expected_issuer"],
            catalog_audience=normalized["catalog"]["expected_audience"],
            minimum_catalog_version=normalized["catalog"]["minimum_version"],
            profile_id=normalized["profile_id"],
            control_reviewer_id=normalized["reviewers"]["independent_control"]["reviewer_id"],
            assurance_reviewer_id=normalized["reviewers"]["independent_assurance"]["reviewer_id"],
            verification_time=verification_time,
            last_seen_checkpoint=checkpoint,
            document_json=_canonical_json(normalized),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment verification context is invalid")
        return value

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


@dataclass(frozen=True)
class CandidateEnrollmentDeploymentVerificationReceipt:
    """Portable record that the complete external artifact chain verified."""

    receipt_id: str
    receipt_sha256: str
    document_json: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> CandidateEnrollmentDeploymentVerificationReceipt:
        value = _mapping(raw, "candidate enrollment deployment verification receipt")
        fields = {
            "schema_version",
            "receipt_id",
            "receipt_sha256",
            "context_sha256",
            "sources",
            "verification_status",
            "verification_gates",
            "verified_at",
            "next_checkpoint",
            "readiness",
            "prohibited_effects",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment deployment verification receipt")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment verification receipt schema is invalid")
        receipt_id = value.get("receipt_id")
        receipt_sha256 = value.get("receipt_sha256")
        context_sha256 = value.get("context_sha256")
        if (
            not isinstance(receipt_id, str)
            or _RECEIPT_ID_PATTERN.fullmatch(receipt_id) is None
            or not isinstance(receipt_sha256, str)
            or _SHA256_PATTERN.fullmatch(receipt_sha256) is None
            or not isinstance(context_sha256, str)
            or _SHA256_PATTERN.fullmatch(context_sha256) is None
        ):
            raise QualificationError(
                "Candidate enrollment verification receipt identity is invalid"
            )
        sources = _mapping(value.get("sources"), "verification receipt sources")
        source_fields = {
            "preparation_packet",
            "worksheet",
            "documentation_preflight",
            "d008_decision",
            "d009_decision",
            "qualification_standard",
            "qualification_policy",
            "signer_authorization",
            "control_reviewer_credential",
            "assurance_reviewer_credential",
            "catalog",
        }
        _exact_fields(sources, source_fields, "verification receipt sources")
        patterns = {
            "preparation_packet": ("packet_id", r"CDP-[0-9A-F]{32}"),
            "documentation_preflight": ("report_id", r"CDR-[0-9A-F]{32}"),
            "d008_decision": ("record_id", r"QDR-[0-9A-F]{32}"),
            "d009_decision": ("record_id", r"CER-[0-9A-F]{32}"),
            "qualification_standard": ("standard_id", r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"),
            "qualification_policy": ("policy_id", r"QTP-[0-9A-F]{32}"),
            "signer_authorization": ("authorization_id", r"CEA-[0-9A-F]{32}"),
            "control_reviewer_credential": ("credential_id", r"QRC-[0-9A-F]{32}"),
            "assurance_reviewer_credential": ("credential_id", r"QRC-[0-9A-F]{32}"),
            "catalog": ("catalog_id", r"CEC-[0-9A-F]{32}"),
        }
        for source_name, (id_field, pattern) in patterns.items():
            _binding(sources.get(source_name), source_name, id_field, pattern)
        worksheet = _mapping(sources.get("worksheet"), "verification receipt worksheet")
        _exact_fields(
            worksheet,
            {"template_id", "worksheet_sha256"},
            "verification receipt worksheet",
        )
        if (
            not isinstance(worksheet.get("template_id"), str)
            or re.fullmatch(r"CDT-[0-9A-F]{32}", str(worksheet["template_id"])) is None
            or not isinstance(worksheet.get("worksheet_sha256"), str)
            or _SHA256_PATTERN.fullmatch(str(worksheet["worksheet_sha256"])) is None
        ):
            raise QualificationError("Candidate enrollment receipt worksheet is invalid")
        if value.get("verification_status") != "cryptographic_artifacts_verified":
            raise QualificationError("Candidate enrollment verification status is invalid")
        if value.get("verification_gates") != list(VERIFICATION_GATES):
            raise QualificationError("Candidate enrollment verification gates are invalid")
        verified_at = value.get("verified_at")
        if not isinstance(verified_at, str):
            raise QualificationError("Candidate enrollment verification time is invalid")
        _parse_timestamp(verified_at, "verified_at")
        CandidateEnrollmentCatalogCheckpoint.from_dict(value.get("next_checkpoint"))
        readiness = _mapping(value.get("readiness"), "verification receipt readiness")
        expected_readiness = {
            "ready_for_checkpoint_commit": True,
            "ready_for_controlled_catalog_release": False,
            "ready_for_live_enrollment": False,
            "next_action": "persist_checkpoint_and_complete_controlled_catalog_release",
        }
        if readiness != expected_readiness:
            raise QualificationError("Candidate enrollment verification readiness is invalid")
        if value.get("prohibited_effects") != list(PROHIBITED_EFFECTS):
            raise QualificationError("Candidate enrollment verification effects are invalid")
        if (
            value.get("network_call_performed") is not False
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Candidate enrollment verification boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_hash = _canonical_sha256({"domain": RECEIPT_DOMAIN, "receipt": body})
        expected_id = "CVR-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if receipt_sha256 != expected_hash or receipt_id != expected_id:
            raise QualificationError("Candidate enrollment verification receipt hash is invalid")
        return cls(
            receipt_id=receipt_id,
            receipt_sha256=receipt_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment verification receipt is invalid")
        return value


def verify_candidate_enrollment_deployment_artifacts(
    preparation_packet: CandidateEnrollmentDeploymentPreparationPacket,
    worksheet: CandidateEnrollmentDeploymentWorksheet,
    documentation_preflight: CandidateEnrollmentDeploymentPreflightReport,
    context: CandidateEnrollmentDeploymentVerificationContext,
    qualification_standard: QualificationStandard,
    d008_decision: QualificationAuthorityDecisionRecord,
    d009_decision: CandidateEnrollmentDecisionRecord,
    qualification_policy: QualificationTrustPolicy,
    signer_authorization: CandidateEnrollmentSignerAuthorization,
    control_credential: QualificationReviewerCredential,
    assurance_credential: QualificationReviewerCredential,
    catalog: CandidateEnrollmentCatalog,
) -> CandidateEnrollmentDeploymentVerificationReceipt:
    """Verify the complete chain and derive the checkpoint that must be persisted."""

    if not isinstance(context, CandidateEnrollmentDeploymentVerificationContext):
        raise QualificationError(
            "context must be a CandidateEnrollmentDeploymentVerificationContext"
        )
    context = CandidateEnrollmentDeploymentVerificationContext.from_dict(context.to_dict())
    expected_preflight = assess_candidate_enrollment_deployment_inputs(
        preparation_packet,
        worksheet,
    )
    if not isinstance(
        documentation_preflight,
        CandidateEnrollmentDeploymentPreflightReport,
    ) or documentation_preflight != expected_preflight:
        raise QualificationError("Candidate enrollment documentation preflight is stale")
    if not documentation_preflight.to_dict()["readiness"][
        "ready_for_cryptographic_artifact_verification"
    ]:
        raise QualificationError("Candidate enrollment documentation is incomplete")
    now = _parse_timestamp(context.verification_time, "verification_time")
    root_bytes = _decode_base64url(context.root_public_key)
    trusted_roots = {context.root_key_id: root_bytes}
    verified_policy = verify_qualification_trust_policy(
        qualification_policy,
        trusted_roots,
        decision_record=d008_decision,
        qualification_standard=qualification_standard,
        expected_issuer=context.qualification_issuer,
        expected_audience=context.qualification_audience,
        expected_root_key_id=context.root_key_id,
        minimum_policy_version=context.minimum_policy_version,
        clock=lambda: now,
    )
    verified_control = verify_qualification_reviewer_credential(
        control_credential,
        verified_policy,
        expected_reviewer_id=context.control_reviewer_id,
        expected_role=QualificationReviewerRole.INDEPENDENT_CONTROL,
        expected_profile_id=context.profile_id,
        clock=lambda: now,
    )
    verified_assurance = verify_qualification_reviewer_credential(
        assurance_credential,
        verified_policy,
        expected_reviewer_id=context.assurance_reviewer_id,
        expected_role=QualificationReviewerRole.INDEPENDENT_ASSURANCE,
        expected_profile_id=context.profile_id,
        clock=lambda: now,
    )
    verified_authorization = verify_candidate_enrollment_signer_authorization(
        signer_authorization,
        trusted_roots,
        d008_decision=d008_decision,
        d009_decision=d009_decision,
        verified_qualification_policy=verified_policy,
        expected_issuer=context.authorization_issuer,
        expected_audience=context.authorization_audience,
        expected_root_key_id=context.root_key_id,
        minimum_authorization_version=context.minimum_authorization_version,
        clock=lambda: now,
    )
    verified_catalog = verify_candidate_enrollment_catalog(
        catalog,
        verified_authorization,
        verified_policy,
        (verified_control, verified_assurance),
        d009_decision=d009_decision,
        expected_catalog_id=context.catalog_id,
        expected_issuer=context.catalog_issuer,
        expected_audience=context.catalog_audience,
        minimum_catalog_version=context.minimum_catalog_version,
        last_seen_checkpoint=context.last_seen_checkpoint,
        clock=lambda: now,
    )
    worksheet_sha256 = _canonical_sha256(worksheet.to_dict())
    sources = {
        "preparation_packet": {
            "packet_id": preparation_packet.packet_id,
            "sha256": preparation_packet.packet_sha256,
        },
        "worksheet": {
            "template_id": worksheet.template_id,
            "worksheet_sha256": worksheet_sha256,
        },
        "documentation_preflight": {
            "report_id": documentation_preflight.report_id,
            "sha256": documentation_preflight.report_sha256,
        },
        "d008_decision": {
            "record_id": d008_decision.record_id,
            "sha256": d008_decision.record_sha256,
        },
        "d009_decision": {
            "record_id": d009_decision.record_id,
            "sha256": d009_decision.record_sha256,
        },
        "qualification_standard": {
            "standard_id": qualification_standard.standard_id,
            "sha256": qualification_standard.canonical_sha256,
        },
        "qualification_policy": {
            "policy_id": qualification_policy.policy_id,
            "sha256": verified_policy.policy_sha256,
        },
        "signer_authorization": {
            "authorization_id": signer_authorization.authorization_id,
            "sha256": verified_authorization.authorization_sha256,
        },
        "control_reviewer_credential": {
            "credential_id": control_credential.credential_id,
            "sha256": verified_control.credential_sha256,
        },
        "assurance_reviewer_credential": {
            "credential_id": assurance_credential.credential_id,
            "sha256": verified_assurance.credential_sha256,
        },
        "catalog": {
            "catalog_id": catalog.catalog_id,
            "sha256": verified_catalog.catalog_sha256,
        },
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "context_sha256": context.content_sha256,
        "sources": sources,
        "verification_status": "cryptographic_artifacts_verified",
        "verification_gates": list(VERIFICATION_GATES),
        "verified_at": verified_catalog.verified_at,
        "next_checkpoint": verified_catalog.checkpoint.to_dict(),
        "readiness": {
            "ready_for_checkpoint_commit": True,
            "ready_for_controlled_catalog_release": False,
            "ready_for_live_enrollment": False,
            "next_action": "persist_checkpoint_and_complete_controlled_catalog_release",
        },
        "prohibited_effects": list(PROHIBITED_EFFECTS),
        "network_call_performed": False,
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    receipt_sha256 = _canonical_sha256({"domain": RECEIPT_DOMAIN, "receipt": body})
    return CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        {
            **body,
            "receipt_id": "CVR-" + receipt_sha256.removeprefix("sha256:")[:32].upper(),
            "receipt_sha256": receipt_sha256,
        }
    )


def _load_json(path: str | Path, label: str) -> Any:
    resolved = Path(path)
    try:
        return loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load {label}: {resolved}") from exc


def load_candidate_enrollment_deployment_verification_context(
    path: str | Path,
) -> CandidateEnrollmentDeploymentVerificationContext:
    return CandidateEnrollmentDeploymentVerificationContext.from_dict(
        _load_json(path, "candidate enrollment deployment verification context")
    )


def load_candidate_enrollment_deployment_verification_receipt(
    path: str | Path,
) -> CandidateEnrollmentDeploymentVerificationReceipt:
    return CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        _load_json(path, "candidate enrollment deployment verification receipt")
    )


def verify_candidate_enrollment_deployment_verification_receipt(
    receipt: CandidateEnrollmentDeploymentVerificationReceipt,
    preparation_packet: CandidateEnrollmentDeploymentPreparationPacket,
    worksheet: CandidateEnrollmentDeploymentWorksheet,
    documentation_preflight: CandidateEnrollmentDeploymentPreflightReport,
    context: CandidateEnrollmentDeploymentVerificationContext,
    qualification_standard: QualificationStandard,
    d008_decision: QualificationAuthorityDecisionRecord,
    d009_decision: CandidateEnrollmentDecisionRecord,
    qualification_policy: QualificationTrustPolicy,
    signer_authorization: CandidateEnrollmentSignerAuthorization,
    control_credential: QualificationReviewerCredential,
    assurance_credential: QualificationReviewerCredential,
    catalog: CandidateEnrollmentCatalog,
) -> CandidateEnrollmentDeploymentVerificationReceipt:
    """Re-run every source verification and require the exact same receipt."""

    if not isinstance(receipt, CandidateEnrollmentDeploymentVerificationReceipt):
        raise QualificationError(
            "receipt must be a CandidateEnrollmentDeploymentVerificationReceipt"
        )
    receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        receipt.to_dict()
    )
    expected = verify_candidate_enrollment_deployment_artifacts(
        preparation_packet,
        worksheet,
        documentation_preflight,
        context,
        qualification_standard,
        d008_decision,
        d009_decision,
        qualification_policy,
        signer_authorization,
        control_credential,
        assurance_credential,
        catalog,
    )
    if receipt != expected:
        raise QualificationError(
            "Candidate enrollment verification receipt does not match its sources"
        )
    return receipt


__all__ = [
    "CandidateEnrollmentDeploymentVerificationContext",
    "CandidateEnrollmentDeploymentVerificationReceipt",
    "load_candidate_enrollment_deployment_verification_context",
    "load_candidate_enrollment_deployment_verification_receipt",
    "verify_candidate_enrollment_deployment_artifacts",
    "verify_candidate_enrollment_deployment_verification_receipt",
]
