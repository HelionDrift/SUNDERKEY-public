"""Provider-neutral invocation attempt and uncertain-outcome contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .collaboration_executor import CollaborationExecutorAcknowledgement
from .collaboration_executor_delivery_claim_store import (
    CollaborationExecutorDeliveryClaimCommitReceipt,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .store import parse_timestamp
from .validation import is_ascii_text

SCHEMA_VERSION = 1
PREPARATION_DOMAIN = "sunderkey.collaboration-executor-invocation-preparation.v1"
RESOLUTION_DOMAIN = "sunderkey.collaboration-executor-invocation-resolution.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
IDEMPOTENCY_STATUSES = (
    "absent",
    "declared_unverified",
    "verified",
)
INVOCATION_OUTCOMES = (
    "failed_before_invocation",
    "provider_report_received",
    "outcome_uncertain",
)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or IDENTIFIER_PATTERN.fullmatch(value) is None
        or not is_ascii_text(value)
    ):
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _binding(raw: Any, label: str, *, fields: set[str]) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, fields, label)
    return dict(value)


@dataclass(frozen=True)
class CollaborationExecutorInvocationPreparation:
    """Durable-before-call material for one adapter invocation attempt."""

    attempt_id: str
    attempt_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutorInvocationPreparation:
        value = _mapping(raw, "collaboration executor invocation preparation")
        fields = {
            "schema_version",
            "attempt_id",
            "attempt_sha256",
            "delivery_claim",
            "reservation",
            "session",
            "operation",
            "adapter",
            "idempotency",
            "prepared_at",
            "attempt_status",
            "external_effect_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration executor invocation preparation")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Invocation preparation schema is invalid")
        attempt_id = value.get("attempt_id")
        attempt_sha256 = value.get("attempt_sha256")
        if (
            not isinstance(attempt_id, str)
            or re.fullmatch(r"EIP-[0-9A-F]{32}", attempt_id) is None
        ):
            raise CollaborationPlanError("Invocation preparation identity is invalid")
        _sha256(attempt_sha256, "attempt_sha256")
        claim = _binding(
            value.get("delivery_claim"),
            "delivery_claim",
            fields={
                "claim_id",
                "claim_sha256",
                "claim_generation",
                "claimant_instance_id",
                "claimed_at",
                "lease_expires_at",
            },
        )
        if re.fullmatch(r"DCL-[0-9A-F]{32}", claim["claim_id"]) is None:
            raise CollaborationPlanError("Invocation delivery claim identity is invalid")
        _sha256(claim["claim_sha256"], "delivery_claim.claim_sha256")
        if (
            not isinstance(claim["claim_generation"], int)
            or isinstance(claim["claim_generation"], bool)
            or claim["claim_generation"] < 1
        ):
            raise CollaborationPlanError("Invocation claim generation is invalid")
        _identifier(
            claim["claimant_instance_id"],
            "delivery_claim.claimant_instance_id",
        )
        claimed_at = parse_timestamp(claim["claimed_at"], "delivery_claim.claimed_at")
        lease_expires = parse_timestamp(
            claim["lease_expires_at"],
            "delivery_claim.lease_expires_at",
        )
        reservation = _binding(
            value.get("reservation"),
            "reservation",
            fields={
                "authentication_id",
                "authentication_sha256",
                "dispatch_id",
                "dispatch_sha256",
                "dispatch_expires_at",
            },
        )
        if re.fullmatch(r"EDA-[0-9A-F]{32}", reservation["authentication_id"]) is None:
            raise CollaborationPlanError("Invocation reservation identity is invalid")
        if re.fullmatch(r"EXD-[0-9A-F]{32}", reservation["dispatch_id"]) is None:
            raise CollaborationPlanError("Invocation dispatch identity is invalid")
        _sha256(reservation["authentication_sha256"], "reservation.authentication_sha256")
        _sha256(reservation["dispatch_sha256"], "reservation.dispatch_sha256")
        dispatch_expires = parse_timestamp(
            reservation["dispatch_expires_at"],
            "reservation.dispatch_expires_at",
        )
        session = _binding(
            value.get("session"),
            "session",
            fields={"session_id", "session_sha256", "fence_generation"},
        )
        _identifier(session["session_id"], "session.session_id")
        _sha256(session["session_sha256"], "session.session_sha256")
        if (
            not isinstance(session["fence_generation"], int)
            or isinstance(session["fence_generation"], bool)
            or session["fence_generation"] < 1
        ):
            raise CollaborationPlanError("Invocation fence generation is invalid")
        operation = _binding(
            value.get("operation"),
            "operation",
            fields={"name", "sequence", "operation_input_sha256"},
        )
        if operation["name"] not in {
            "start",
            "action",
            "evidence",
            "heartbeat",
            "pause",
            "resume",
            "stop",
            "destroy",
        }:
            raise CollaborationPlanError("Invocation operation is invalid")
        if (
            not isinstance(operation["sequence"], int)
            or isinstance(operation["sequence"], bool)
            or operation["sequence"] < 1
        ):
            raise CollaborationPlanError("Invocation operation sequence is invalid")
        _sha256(
            operation["operation_input_sha256"],
            "operation.operation_input_sha256",
        )
        adapter = _binding(
            value.get("adapter"),
            "adapter",
            fields={
                "adapter_id",
                "adapter_version",
                "adapter_build_sha256",
                "deployment_binding_sha256",
            },
        )
        _identifier(adapter["adapter_id"], "adapter.adapter_id")
        _identifier(adapter["adapter_version"], "adapter.adapter_version")
        _sha256(adapter["adapter_build_sha256"], "adapter.adapter_build_sha256")
        _sha256(
            adapter["deployment_binding_sha256"],
            "adapter.deployment_binding_sha256",
        )
        idempotency = _binding(
            value.get("idempotency"),
            "idempotency",
            fields={"status", "key_sha256"},
        )
        if idempotency["status"] not in IDEMPOTENCY_STATUSES:
            raise CollaborationPlanError("Invocation idempotency status is invalid")
        if idempotency["status"] == "absent":
            if idempotency["key_sha256"] is not None:
                raise CollaborationPlanError("Absent idempotency has a key")
        else:
            _sha256(idempotency["key_sha256"], "idempotency.key_sha256")
        prepared_at = parse_timestamp(value.get("prepared_at"), "prepared_at")
        if (
            prepared_at < claimed_at
            or prepared_at >= lease_expires
            or prepared_at >= dispatch_expires
        ):
            raise CollaborationPlanError("Invocation preparation window is invalid")
        if (
            value.get("attempt_status") != "prepared_before_invocation"
            or value.get("external_effect_status") != "not_started"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Invocation preparation boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"attempt_id", "attempt_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": PREPARATION_DOMAIN, "invocation_preparation": body}
        )
        expected_id = "EIP-" + digest.removeprefix("sha256:")[:32].upper()
        if attempt_sha256 != digest or attempt_id != expected_id:
            raise CollaborationPlanError("Invocation preparation hash is invalid")
        return cls(attempt_id, attempt_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Invocation preparation is invalid")
        return value


@dataclass(frozen=True)
class CollaborationExecutorInvocationResolution:
    """Terminal local knowledge about one prepared invocation attempt."""

    resolution_id: str
    resolution_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutorInvocationResolution:
        value = _mapping(raw, "collaboration executor invocation resolution")
        fields = {
            "schema_version",
            "resolution_id",
            "resolution_sha256",
            "invocation_preparation",
            "outcome",
            "provider_acknowledgement",
            "failure_code",
            "resolved_at",
            "retry_disposition",
            "external_effect_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration executor invocation resolution")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Invocation resolution schema is invalid")
        resolution_id = value.get("resolution_id")
        resolution_sha256 = value.get("resolution_sha256")
        if (
            not isinstance(resolution_id, str)
            or re.fullmatch(r"EIR-[0-9A-F]{32}", resolution_id) is None
        ):
            raise CollaborationPlanError("Invocation resolution identity is invalid")
        _sha256(resolution_sha256, "resolution_sha256")
        preparation = _binding(
            value.get("invocation_preparation"),
            "invocation_preparation",
            fields={
                "attempt_id",
                "attempt_sha256",
                "prepared_at",
                "idempotency_status",
            },
        )
        if re.fullmatch(r"EIP-[0-9A-F]{32}", preparation["attempt_id"]) is None:
            raise CollaborationPlanError("Invocation resolution attempt is invalid")
        _sha256(preparation["attempt_sha256"], "invocation_preparation.attempt_sha256")
        prepared_at = parse_timestamp(
            preparation["prepared_at"],
            "invocation_preparation.prepared_at",
        )
        if preparation["idempotency_status"] not in IDEMPOTENCY_STATUSES:
            raise CollaborationPlanError(
                "Invocation resolution idempotency status is invalid"
            )
        outcome = value.get("outcome")
        if outcome not in INVOCATION_OUTCOMES:
            raise CollaborationPlanError("Invocation outcome is invalid")
        acknowledgement = value.get("provider_acknowledgement")
        failure_code = value.get("failure_code")
        if outcome == "provider_report_received":
            report = _binding(
                acknowledgement,
                "provider_acknowledgement",
                fields={"acknowledgement_id", "acknowledgement_sha256"},
            )
            if re.fullmatch(r"EXA-[0-9A-F]{32}", report["acknowledgement_id"]) is None:
                raise CollaborationPlanError("Invocation acknowledgement identity is invalid")
            _sha256(
                report["acknowledgement_sha256"],
                "provider_acknowledgement.acknowledgement_sha256",
            )
            if failure_code is not None:
                raise CollaborationPlanError("Reported invocation has a failure code")
        else:
            if acknowledgement is not None:
                raise CollaborationPlanError("Invocation failure has an acknowledgement")
            _identifier(failure_code, "failure_code")
        resolved_at = parse_timestamp(value.get("resolved_at"), "resolved_at")
        if resolved_at < prepared_at:
            raise CollaborationPlanError("Invocation resolution precedes preparation")
        expected = {
            "failed_before_invocation": (
                "retry_allowed_no_external_effect",
                "not_started",
            ),
            "provider_report_received": (
                "complete_provider_report_pending_authentication",
                "provider_report_pending_authentication",
            ),
            "outcome_uncertain": (
                "retry_allowed_verified_idempotency"
                if preparation["idempotency_status"] == "verified"
                else "retry_forbidden_uncertain_effect",
                "outcome_uncertain",
            ),
        }
        retry_disposition, external_effect_status = expected[outcome]
        if (
            value.get("retry_disposition") != retry_disposition
            or value.get("external_effect_status") != external_effect_status
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Invocation resolution boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"resolution_id", "resolution_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": RESOLUTION_DOMAIN, "invocation_resolution": body}
        )
        expected_id = "EIR-" + digest.removeprefix("sha256:")[:32].upper()
        if resolution_sha256 != digest or resolution_id != expected_id:
            raise CollaborationPlanError("Invocation resolution hash is invalid")
        return cls(resolution_id, resolution_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Invocation resolution is invalid")
        return value


def build_collaboration_executor_invocation_preparation(
    claim_receipt: CollaborationExecutorDeliveryClaimCommitReceipt,
    operation_input: bytes,
    *,
    adapter_id: str,
    adapter_version: str,
    adapter_build_sha256: str,
    deployment_binding_sha256: str,
    idempotency_status: str,
    idempotency_key_sha256: str | None,
    prepared_at: str,
) -> CollaborationExecutorInvocationPreparation:
    """Validate exact bytes and prepare durable-before-call attempt material."""

    if not isinstance(
        claim_receipt,
        CollaborationExecutorDeliveryClaimCommitReceipt,
    ):
        raise TypeError("claim_receipt must be a durable delivery claim receipt")
    if not isinstance(operation_input, bytes):
        raise TypeError("operation_input must be bytes")
    claim = claim_receipt.claim.to_dict()
    actual_input_sha256 = "sha256:" + hashlib.sha256(operation_input).hexdigest()
    if actual_input_sha256 != claim["operation"]["operation_input_sha256"]:
        raise CollaborationPlanError("Invocation operation input hash is invalid")
    body = {
        "schema_version": SCHEMA_VERSION,
        "delivery_claim": {
            "claim_id": claim["claim_id"],
            "claim_sha256": claim["claim_sha256"],
            "claim_generation": claim["claim_generation"],
            "claimant_instance_id": claim["claimant"]["instance_id"],
            "claimed_at": claim["claimed_at"],
            "lease_expires_at": claim["lease_expires_at"],
        },
        "reservation": {
            "authentication_id": claim["reservation"]["authentication_id"],
            "authentication_sha256": claim["reservation"]["authentication_sha256"],
            "dispatch_id": claim["reservation"]["dispatch_id"],
            "dispatch_sha256": claim["reservation"]["dispatch_sha256"],
            "dispatch_expires_at": claim["reservation"]["dispatch_expires_at"],
        },
        "session": dict(claim["session"]),
        "operation": dict(claim["operation"]),
        "adapter": {
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "adapter_build_sha256": adapter_build_sha256,
            "deployment_binding_sha256": deployment_binding_sha256,
        },
        "idempotency": {
            "status": idempotency_status,
            "key_sha256": idempotency_key_sha256,
        },
        "prepared_at": prepared_at,
        "attempt_status": "prepared_before_invocation",
        "external_effect_status": "not_started",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": PREPARATION_DOMAIN, "invocation_preparation": body}
    )
    return CollaborationExecutorInvocationPreparation.from_dict(
        {
            **body,
            "attempt_id": "EIP-" + digest.removeprefix("sha256:")[:32].upper(),
            "attempt_sha256": digest,
        }
    )


def build_collaboration_executor_invocation_resolution(
    preparation: CollaborationExecutorInvocationPreparation,
    *,
    outcome: str,
    resolved_at: str,
    provider_acknowledgement: CollaborationExecutorAcknowledgement | None = None,
    failure_code: str | None = None,
) -> CollaborationExecutorInvocationResolution:
    """Record terminal local knowledge without asserting an external effect."""

    if not isinstance(preparation, CollaborationExecutorInvocationPreparation):
        raise TypeError("preparation must be an invocation preparation")
    attempt = preparation.to_dict()
    report_binding = None
    if provider_acknowledgement is not None:
        if not isinstance(provider_acknowledgement, CollaborationExecutorAcknowledgement):
            raise TypeError("provider_acknowledgement must be an executor acknowledgement")
        report = provider_acknowledgement.to_dict()
        if (
            report["dispatch"]["dispatch_id"]
            != attempt["reservation"]["dispatch_id"]
            or report["dispatch"]["dispatch_sha256"]
            != attempt["reservation"]["dispatch_sha256"]
            or report["session"]["session_id"] != attempt["session"]["session_id"]
            or report["session"]["session_sha256"]
            != attempt["session"]["session_sha256"]
            or report["worker"]["fence_generation"]
            != attempt["session"]["fence_generation"]
            or report["provider"]["adapter_id"]
            != attempt["adapter"]["adapter_id"]
            or report["provider"]["adapter_version"]
            != attempt["adapter"]["adapter_version"]
            or report["provider"]["adapter_build_sha256"]
            != attempt["adapter"]["adapter_build_sha256"]
        ):
            raise CollaborationPlanError("Invocation provider report is stale")
        acknowledged_at = parse_timestamp(
            report["acknowledged_at"],
            "provider_acknowledgement.acknowledged_at",
        )
        if (
            acknowledged_at < parse_timestamp(attempt["prepared_at"], "prepared_at")
            or acknowledged_at > parse_timestamp(resolved_at, "resolved_at")
        ):
            raise CollaborationPlanError("Invocation provider report time is invalid")
        report_binding = {
            "acknowledgement_id": report["acknowledgement_id"],
            "acknowledgement_sha256": report["acknowledgement_sha256"],
        }
    retry_disposition = {
        "failed_before_invocation": "retry_allowed_no_external_effect",
        "provider_report_received": (
            "complete_provider_report_pending_authentication"
        ),
        "outcome_uncertain": (
            "retry_allowed_verified_idempotency"
            if attempt["idempotency"]["status"] == "verified"
            else "retry_forbidden_uncertain_effect"
        ),
    }.get(outcome)
    external_effect_status = {
        "failed_before_invocation": "not_started",
        "provider_report_received": "provider_report_pending_authentication",
        "outcome_uncertain": "outcome_uncertain",
    }.get(outcome)
    body = {
        "schema_version": SCHEMA_VERSION,
        "invocation_preparation": {
            "attempt_id": preparation.attempt_id,
            "attempt_sha256": preparation.attempt_sha256,
            "prepared_at": attempt["prepared_at"],
            "idempotency_status": attempt["idempotency"]["status"],
        },
        "outcome": outcome,
        "provider_acknowledgement": report_binding,
        "failure_code": failure_code,
        "resolved_at": resolved_at,
        "retry_disposition": retry_disposition,
        "external_effect_status": external_effect_status,
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": RESOLUTION_DOMAIN, "invocation_resolution": body}
    )
    return CollaborationExecutorInvocationResolution.from_dict(
        {
            **body,
            "resolution_id": "EIR-"
            + digest.removeprefix("sha256:")[:32].upper(),
            "resolution_sha256": digest,
        }
    )


__all__ = [
    "CollaborationExecutorInvocationPreparation",
    "CollaborationExecutorInvocationResolution",
    "IDEMPOTENCY_STATUSES",
    "INVOCATION_OUTCOMES",
    "build_collaboration_executor_invocation_preparation",
    "build_collaboration_executor_invocation_resolution",
]
