"""Provider-neutral contracts for quarantined evidence repository ingest."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol

from .collaboration_executor_provider_evidence import (
    MAXIMUM_EVIDENCE_BYTES,
    validate_collaboration_executor_provider_evidence_digest_document,
)
from .collaboration_executor_provider_evidence_service import (
    CollaborationExecutorProviderEvidenceVerificationReceipt,
)
from .errors import CollaborationPlanError, QualificationError
from .provider_evidence_custody_decision import (
    ProviderEvidenceCustodyDecisionRecord,
)
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .store import parse_timestamp

SCHEMA_VERSION = 1
INGEST_REQUEST_DOMAIN = "sunderkey.provider-evidence-repository-ingest-request.v1"
INGEST_RECEIPT_DOMAIN = "sunderkey.provider-evidence-repository-ingest-receipt.v1"
MAXIMUM_INGEST_WINDOW_SECONDS = 300
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
INGEST_OUTCOMES = (
    "accepted",
    "already_exists_same_digest",
    "rejected",
    "failed",
)

REPOSITORY_POLICY = {
    "artifact_repository": "immutable_content_addressed_object_repository",
    "control_data_separation": ("metadata_receipts_in_control_plane_bytes_in_repository"),
    "encryption_key_custody": ("envelope_encryption_organization_kms_separate_key_scope"),
    "access_identity_scope": ("dedicated_service_identity_mission_scoped_time_bounded_access"),
    "retention_legal_hold": ("mission_policy_retention_with_independent_legal_hold_override"),
    "integrity_immutability": ("conditional_create_version_lock_and_digest_reverification"),
    "repository_provenance": ("signed_repository_receipt_bound_to_object_version_and_identity"),
    "content_safety": "quarantine_passive_detection_and_sandboxed_derivation",
    "classification_redaction": (
        "restricted_raw_and_separately_addressed_provenance_linked_derivatives"
    ),
    "residency_resilience": ("mission_allowed_regions_replication_and_integrity_drills"),
}

_SATISFIED_ASSERTIONS = {
    "conditional_create": "provider_asserted_satisfied",
    "immutable_version": "provider_asserted_satisfied",
    "envelope_encryption": "provider_asserted_satisfied",
    "quarantine": "provider_asserted_satisfied",
    "retention_policy": "provider_asserted_satisfied",
    "residency_policy": "provider_asserted_satisfied",
}
_UNCLAIMED_ASSERTIONS = {key: "not_claimed" for key in _SATISFIED_ASSERTIONS}


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _binding(raw: Any, label: str, fields: set[str]) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, fields, label)
    return dict(value)


def _validate_decision_binding(raw: Any) -> dict[str, str]:
    value = _binding(
        raw,
        "evidence custody decision binding",
        {"record_id", "record_sha256"},
    )
    if (
        not isinstance(value.get("record_id"), str)
        or re.fullmatch(r"ECR-[0-9A-F]{32}", value["record_id"]) is None
    ):
        raise CollaborationPlanError("Evidence custody decision identity is invalid")
    return {
        "record_id": value["record_id"],
        "record_sha256": _sha256(value.get("record_sha256"), "record_sha256"),
    }


def _validate_lifecycle_bindings(raw: Any) -> dict[str, Any]:
    value = _binding(
        raw,
        "evidence lifecycle bindings",
        {
            "retention_policy_id",
            "retention_policy_sha256",
            "residency_policy_id",
            "residency_policy_sha256",
            "encryption_profile_id",
            "encryption_profile_sha256",
            "access_policy_id",
            "access_policy_sha256",
        },
    )
    for field in (
        "retention_policy_id",
        "residency_policy_id",
        "encryption_profile_id",
        "access_policy_id",
    ):
        _identifier(value.get(field), f"lifecycle_bindings.{field}")
    for field in (
        "retention_policy_sha256",
        "residency_policy_sha256",
        "encryption_profile_sha256",
        "access_policy_sha256",
    ):
        _sha256(value.get(field), f"lifecycle_bindings.{field}")
    return value


@dataclass(frozen=True)
class ProviderEvidenceRepositoryIngestRequest:
    """Content-addressed request for conditional quarantined evidence ingest."""

    request_id: str
    request_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProviderEvidenceRepositoryIngestRequest:
        value = _mapping(raw, "provider evidence repository ingest request")
        fields = {
            "schema_version",
            "request_id",
            "request_sha256",
            "custody_decision",
            "evidence_verification",
            "repository_policy",
            "lifecycle_bindings",
            "content_address",
            "requested_at",
            "expires_at",
            "request_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "provider evidence repository ingest request")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Evidence ingest request schema is invalid")
        request_id = value.get("request_id")
        request_sha256 = value.get("request_sha256")
        if not isinstance(request_id, str) or re.fullmatch(r"EIR-[0-9A-F]{32}", request_id) is None:
            raise CollaborationPlanError("Evidence ingest request identity is invalid")
        _sha256(request_sha256, "request_sha256")
        _validate_decision_binding(value.get("custody_decision"))
        verification = validate_collaboration_executor_provider_evidence_digest_document(
            value.get("evidence_verification")
        )
        if value.get("repository_policy") != REPOSITORY_POLICY:
            raise CollaborationPlanError("Evidence repository policy is invalid")
        _validate_lifecycle_bindings(value.get("lifecycle_bindings"))
        expected_address = verification["provider_evidence_sha256"]
        if value.get("content_address") != expected_address:
            raise CollaborationPlanError("Evidence content address is invalid")
        requested = parse_timestamp(value.get("requested_at"), "requested_at")
        expires = parse_timestamp(value.get("expires_at"), "expires_at")
        verified = parse_timestamp(verification["verified_at"], "verified_at")
        if (
            requested < verified
            or expires <= requested
            or expires - requested > timedelta(seconds=MAXIMUM_INGEST_WINDOW_SECONDS)
        ):
            raise CollaborationPlanError("Evidence ingest request time window is invalid")
        if (
            value.get("request_status") != "prepared_quarantined_repository_ingest"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Evidence ingest request boundary is invalid")
        body = {
            key: item for key, item in value.items() if key not in {"request_id", "request_sha256"}
        }
        digest = _canonical_sha256({"domain": INGEST_REQUEST_DOMAIN, "ingest_request": body})
        expected_id = "EIR-" + digest.removeprefix("sha256:")[:32].upper()
        if request_sha256 != digest or request_id != expected_id:
            raise CollaborationPlanError("Evidence ingest request hash is invalid")
        return cls(request_id, request_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Evidence ingest request is invalid")
        return value


@dataclass(frozen=True)
class ProviderEvidenceRepositoryIngestReceipt:
    """Unauthenticated provider result for one exact evidence ingest request."""

    receipt_id: str
    receipt_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProviderEvidenceRepositoryIngestReceipt:
        value = _mapping(raw, "provider evidence repository ingest receipt")
        fields = {
            "schema_version",
            "receipt_id",
            "receipt_sha256",
            "ingest_request",
            "provider",
            "repository_object",
            "outcome",
            "provider_assertions",
            "responded_at",
            "authentication_status",
            "custody_status",
            "raw_evidence_in_contract",
            "runtime_effect",
        }
        _exact_fields(value, fields, "provider evidence repository ingest receipt")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Evidence ingest receipt schema is invalid")
        receipt_id = value.get("receipt_id")
        receipt_sha256 = value.get("receipt_sha256")
        if not isinstance(receipt_id, str) or re.fullmatch(r"ERR-[0-9A-F]{32}", receipt_id) is None:
            raise CollaborationPlanError("Evidence ingest receipt identity is invalid")
        _sha256(receipt_sha256, "receipt_sha256")
        request = _binding(
            value.get("ingest_request"),
            "ingest request binding",
            {
                "request_id",
                "request_sha256",
                "content_address",
                "evidence_size_bytes",
            },
        )
        if (
            not isinstance(request.get("request_id"), str)
            or re.fullmatch(r"EIR-[0-9A-F]{32}", request["request_id"]) is None
            or not isinstance(request.get("evidence_size_bytes"), int)
            or isinstance(request.get("evidence_size_bytes"), bool)
            or not 1 <= request["evidence_size_bytes"] <= MAXIMUM_EVIDENCE_BYTES
        ):
            raise CollaborationPlanError("Evidence ingest receipt request is invalid")
        _sha256(request.get("request_sha256"), "request.request_sha256")
        _sha256(request.get("content_address"), "request.content_address")
        provider = _binding(
            value.get("provider"),
            "repository provider binding",
            {"adapter_id", "adapter_version", "adapter_build_sha256"},
        )
        _identifier(provider.get("adapter_id"), "provider.adapter_id")
        _identifier(provider.get("adapter_version"), "provider.adapter_version")
        _sha256(provider.get("adapter_build_sha256"), "provider.adapter_build_sha256")
        repository_object = _binding(
            value.get("repository_object"),
            "repository object binding",
            {"repository_id", "object_version_id", "content_address"},
        )
        _identifier(repository_object.get("repository_id"), "repository.repository_id")
        _identifier(
            repository_object.get("object_version_id"),
            "repository.object_version_id",
        )
        _sha256(repository_object.get("content_address"), "repository.content_address")
        if repository_object["content_address"] != request["content_address"]:
            raise CollaborationPlanError("Evidence repository object digest is invalid")
        outcome = value.get("outcome")
        if outcome not in INGEST_OUTCOMES:
            raise CollaborationPlanError("Evidence ingest outcome is invalid")
        expected_assertions = (
            _SATISFIED_ASSERTIONS
            if outcome in {"accepted", "already_exists_same_digest"}
            else _UNCLAIMED_ASSERTIONS
        )
        if value.get("provider_assertions") != expected_assertions:
            raise CollaborationPlanError("Evidence provider assertions are invalid")
        parse_timestamp(value.get("responded_at"), "responded_at")
        if (
            value.get("authentication_status") != "repository_provider_assertion_unverified"
            or value.get("custody_status") != "provider_report_only"
            or value.get("raw_evidence_in_contract") is not False
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Evidence ingest receipt boundary is invalid")
        body = {
            key: item for key, item in value.items() if key not in {"receipt_id", "receipt_sha256"}
        }
        digest = _canonical_sha256({"domain": INGEST_RECEIPT_DOMAIN, "ingest_receipt": body})
        expected_id = "ERR-" + digest.removeprefix("sha256:")[:32].upper()
        if receipt_sha256 != digest or receipt_id != expected_id:
            raise CollaborationPlanError("Evidence ingest receipt hash is invalid")
        return cls(receipt_id, receipt_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Evidence ingest receipt is invalid")
        return value


class ProviderEvidenceRepositoryAdapter(Protocol):
    """External evidence repository interface. No implementation is selected."""

    def put_quarantined(
        self,
        request: ProviderEvidenceRepositoryIngestRequest,
        evidence: bytes,
    ) -> ProviderEvidenceRepositoryIngestReceipt: ...


def build_provider_evidence_repository_ingest_request(
    decision: ProviderEvidenceCustodyDecisionRecord,
    verification_receipt: CollaborationExecutorProviderEvidenceVerificationReceipt,
    *,
    retention_policy_id: str,
    retention_policy_sha256: str,
    residency_policy_id: str,
    residency_policy_sha256: str,
    encryption_profile_id: str,
    encryption_profile_sha256: str,
    access_policy_id: str,
    access_policy_sha256: str,
    requested_at: str,
    expires_at: str,
) -> ProviderEvidenceRepositoryIngestRequest:
    """Build a no-effect request from approved policy and transient verification."""

    parsed_decision = ProviderEvidenceCustodyDecisionRecord.from_dict(decision.to_dict())
    decision_document = parsed_decision.to_dict()
    if (
        decision_document["decision_effect"]
        != "provider_evidence_custody_contract_implementation_authorized"
        or not decision_document["recommendation_alignment"]["all_recommended_options_selected"]
    ):
        raise QualificationError("Evidence custody decision is not authorized")
    receipt = verification_receipt.to_dict()
    if (
        receipt["verification_custody_status"] != "transient_not_retained"
        or receipt["evidence_retention_status"] != "not_retained"
        or receipt["runtime_effect"] != "none"
    ):
        raise CollaborationPlanError("Evidence verification boundary is invalid")
    verification = receipt["evidence_verification"]
    lifecycle = _validate_lifecycle_bindings(
        {
            "retention_policy_id": retention_policy_id,
            "retention_policy_sha256": retention_policy_sha256,
            "residency_policy_id": residency_policy_id,
            "residency_policy_sha256": residency_policy_sha256,
            "encryption_profile_id": encryption_profile_id,
            "encryption_profile_sha256": encryption_profile_sha256,
            "access_policy_id": access_policy_id,
            "access_policy_sha256": access_policy_sha256,
        }
    )
    body = {
        "schema_version": SCHEMA_VERSION,
        "custody_decision": {
            "record_id": parsed_decision.record_id,
            "record_sha256": parsed_decision.record_sha256,
        },
        "evidence_verification": verification,
        "repository_policy": REPOSITORY_POLICY,
        "lifecycle_bindings": lifecycle,
        "content_address": verification["provider_evidence_sha256"],
        "requested_at": requested_at,
        "expires_at": expires_at,
        "request_status": "prepared_quarantined_repository_ingest",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": INGEST_REQUEST_DOMAIN, "ingest_request": body})
    return ProviderEvidenceRepositoryIngestRequest.from_dict(
        {
            **body,
            "request_id": "EIR-" + digest.removeprefix("sha256:")[:32].upper(),
            "request_sha256": digest,
        }
    )


def validate_provider_evidence_repository_ingest_bytes(
    request: ProviderEvidenceRepositoryIngestRequest,
    evidence: bytes,
) -> None:
    """Verify out-of-band evidence against the request without retaining it."""

    parsed = ProviderEvidenceRepositoryIngestRequest.from_dict(request.to_dict())
    if not isinstance(evidence, bytes):
        raise TypeError("evidence must be bytes")
    document = parsed.to_dict()
    verification = document["evidence_verification"]
    if len(evidence) != verification["evidence_size_bytes"]:
        raise CollaborationPlanError("Evidence ingest size does not match request")
    actual = "sha256:" + hashlib.sha256(evidence).hexdigest()
    if not hmac.compare_digest(actual, document["content_address"]):
        raise CollaborationPlanError("Evidence ingest bytes do not match request")


def build_provider_evidence_repository_ingest_receipt(
    request: ProviderEvidenceRepositoryIngestRequest,
    *,
    adapter_id: str,
    adapter_version: str,
    adapter_build_sha256: str,
    repository_id: str,
    object_version_id: str,
    outcome: str,
    responded_at: str,
) -> ProviderEvidenceRepositoryIngestReceipt:
    """Build an explicitly unauthenticated provider report for repository ingest."""

    request = ProviderEvidenceRepositoryIngestRequest.from_dict(request.to_dict())
    document = request.to_dict()
    verification = document["evidence_verification"]
    assertions = (
        _SATISFIED_ASSERTIONS
        if outcome in {"accepted", "already_exists_same_digest"}
        else _UNCLAIMED_ASSERTIONS
    )
    body = {
        "schema_version": SCHEMA_VERSION,
        "ingest_request": {
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "content_address": document["content_address"],
            "evidence_size_bytes": verification["evidence_size_bytes"],
        },
        "provider": {
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "adapter_build_sha256": adapter_build_sha256,
        },
        "repository_object": {
            "repository_id": repository_id,
            "object_version_id": object_version_id,
            "content_address": document["content_address"],
        },
        "outcome": outcome,
        "provider_assertions": assertions,
        "responded_at": responded_at,
        "authentication_status": "repository_provider_assertion_unverified",
        "custody_status": "provider_report_only",
        "raw_evidence_in_contract": False,
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": INGEST_RECEIPT_DOMAIN, "ingest_receipt": body})
    return ProviderEvidenceRepositoryIngestReceipt.from_dict(
        {
            **body,
            "receipt_id": "ERR-" + digest.removeprefix("sha256:")[:32].upper(),
            "receipt_sha256": digest,
        }
    )


def validate_provider_evidence_repository_ingest_receipt(
    request: ProviderEvidenceRepositoryIngestRequest,
    receipt: ProviderEvidenceRepositoryIngestReceipt,
) -> ProviderEvidenceRepositoryIngestReceipt:
    """Require an exact receipt-to-request binding without trusting its claims."""

    request = ProviderEvidenceRepositoryIngestRequest.from_dict(request.to_dict())
    receipt = ProviderEvidenceRepositoryIngestReceipt.from_dict(receipt.to_dict())
    request_document = request.to_dict()
    binding = receipt.to_dict()["ingest_request"]
    expected = {
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "content_address": request_document["content_address"],
        "evidence_size_bytes": request_document["evidence_verification"]["evidence_size_bytes"],
    }
    if binding != expected:
        raise CollaborationPlanError("Evidence ingest receipt request binding is invalid")
    return receipt


__all__ = [
    "INGEST_OUTCOMES",
    "MAXIMUM_INGEST_WINDOW_SECONDS",
    "ProviderEvidenceRepositoryAdapter",
    "ProviderEvidenceRepositoryIngestReceipt",
    "ProviderEvidenceRepositoryIngestRequest",
    "REPOSITORY_POLICY",
    "build_provider_evidence_repository_ingest_receipt",
    "build_provider_evidence_repository_ingest_request",
    "validate_provider_evidence_repository_ingest_bytes",
    "validate_provider_evidence_repository_ingest_receipt",
]
