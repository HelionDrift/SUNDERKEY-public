"""Provider-neutral delivery claim contracts for reserved executor dispatches."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .authenticated_collaboration_executor_dispatch import (
    AuthenticatedCollaborationExecutorDispatchReservationReceipt,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .store import parse_timestamp
from .validation import is_ascii_text

SCHEMA_VERSION = 1
DELIVERY_CLAIM_DOMAIN = "sunderkey.collaboration-executor-delivery-claim.v1"
MAXIMUM_DELIVERY_CLAIM_LEASE_SECONDS = 60
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


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


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _binding(raw: Any, label: str, *, fields: set[str]) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, fields, label)
    return dict(value)


@dataclass(frozen=True)
class CollaborationExecutorDeliveryClaim:
    """One exclusive, time-bounded claim to attempt a reserved dispatch."""

    claim_id: str
    claim_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutorDeliveryClaim:
        value = _mapping(raw, "collaboration executor delivery claim")
        fields = {
            "schema_version",
            "claim_id",
            "claim_sha256",
            "reservation",
            "mission",
            "session",
            "operation",
            "claimant",
            "claim_generation",
            "predecessor",
            "claimed_at",
            "lease_expires_at",
            "claim_status",
            "claimant_identity_status",
            "external_effect_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration executor delivery claim")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Executor delivery claim schema is invalid")
        claim_id = value.get("claim_id")
        claim_sha256 = value.get("claim_sha256")
        if (
            not isinstance(claim_id, str)
            or re.fullmatch(r"DCL-[0-9A-F]{32}", claim_id) is None
        ):
            raise CollaborationPlanError("Executor delivery claim identity is invalid")
        _sha256(claim_sha256, "claim_sha256")
        reservation = _binding(
            value.get("reservation"),
            "reservation",
            fields={
                "authentication_id",
                "authentication_sha256",
                "dispatch_id",
                "dispatch_sha256",
                "reserved_at",
                "dispatch_expires_at",
            },
        )
        if re.fullmatch(r"EDA-[0-9A-F]{32}", reservation["authentication_id"]) is None:
            raise CollaborationPlanError("Executor delivery reservation identity is invalid")
        if re.fullmatch(r"EXD-[0-9A-F]{32}", reservation["dispatch_id"]) is None:
            raise CollaborationPlanError("Executor delivery dispatch identity is invalid")
        _sha256(reservation["authentication_sha256"], "reservation.authentication_sha256")
        _sha256(reservation["dispatch_sha256"], "reservation.dispatch_sha256")
        reserved_at = parse_timestamp(reservation["reserved_at"], "reservation.reserved_at")
        dispatch_expires = parse_timestamp(
            reservation["dispatch_expires_at"],
            "reservation.dispatch_expires_at",
        )
        mission = _binding(
            value.get("mission"),
            "mission",
            fields={"mission_id", "collaboration_plan_id"},
        )
        _identifier(mission["mission_id"], "mission.mission_id")
        _identifier(mission["collaboration_plan_id"], "mission.collaboration_plan_id")
        session = _binding(
            value.get("session"),
            "session",
            fields={"session_id", "session_sha256", "fence_generation"},
        )
        _identifier(session["session_id"], "session.session_id")
        _sha256(session["session_sha256"], "session.session_sha256")
        _positive_integer(session["fence_generation"], "session.fence_generation")
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
            raise CollaborationPlanError("Executor delivery operation is invalid")
        _positive_integer(operation["sequence"], "operation.sequence")
        _sha256(
            operation["operation_input_sha256"],
            "operation.operation_input_sha256",
        )
        claimant = _binding(
            value.get("claimant"),
            "claimant",
            fields={"instance_id"},
        )
        _identifier(claimant["instance_id"], "claimant.instance_id")
        generation = _positive_integer(value.get("claim_generation"), "claim_generation")
        predecessor = value.get("predecessor")
        predecessor_expiry = None
        if generation == 1:
            if predecessor is not None:
                raise CollaborationPlanError("Initial delivery claim has a predecessor")
        else:
            previous = _binding(
                predecessor,
                "predecessor",
                fields={
                    "claim_id",
                    "claim_sha256",
                    "claim_generation",
                    "lease_expires_at",
                },
            )
            if re.fullmatch(r"DCL-[0-9A-F]{32}", previous["claim_id"]) is None:
                raise CollaborationPlanError("Delivery predecessor identity is invalid")
            _sha256(previous["claim_sha256"], "predecessor.claim_sha256")
            if (
                _positive_integer(
                    previous["claim_generation"],
                    "predecessor.claim_generation",
                )
                != generation - 1
            ):
                raise CollaborationPlanError("Delivery predecessor generation is invalid")
            predecessor_expiry = parse_timestamp(
                previous["lease_expires_at"],
                "predecessor.lease_expires_at",
            )
        claimed_at = parse_timestamp(value.get("claimed_at"), "claimed_at")
        lease_expires_at = parse_timestamp(
            value.get("lease_expires_at"),
            "lease_expires_at",
        )
        if (
            claimed_at < reserved_at
            or claimed_at >= dispatch_expires
            or lease_expires_at <= claimed_at
            or lease_expires_at > dispatch_expires
            or lease_expires_at - claimed_at
            > timedelta(seconds=MAXIMUM_DELIVERY_CLAIM_LEASE_SECONDS)
            or (
                predecessor_expiry is not None
                and claimed_at < predecessor_expiry
            )
        ):
            raise CollaborationPlanError("Executor delivery claim window is invalid")
        if (
            value.get("claim_status") != "claimed_pending_invocation"
            or value.get("claimant_identity_status")
            != "deployment_instance_unverified"
            or value.get("external_effect_status") != "not_started"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Executor delivery claim boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"claim_id", "claim_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": DELIVERY_CLAIM_DOMAIN, "delivery_claim": body}
        )
        expected_id = "DCL-" + digest.removeprefix("sha256:")[:32].upper()
        if claim_sha256 != digest or claim_id != expected_id:
            raise CollaborationPlanError("Executor delivery claim hash is invalid")
        return cls(claim_id, claim_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Executor delivery claim is invalid")
        return value


def build_collaboration_executor_delivery_claim(
    reservation: AuthenticatedCollaborationExecutorDispatchReservationReceipt,
    *,
    claimant_instance_id: str,
    claimed_at: str,
    lease_expires_at: str,
    previous_claim: CollaborationExecutorDeliveryClaim | None = None,
) -> CollaborationExecutorDeliveryClaim:
    """Build an initial or expired-lease takeover claim without invoking an adapter."""

    if not isinstance(
        reservation,
        AuthenticatedCollaborationExecutorDispatchReservationReceipt,
    ):
        raise TypeError("reservation must be a durable dispatch reservation receipt")
    receipt = reservation.to_dict()
    authentication = receipt["dispatch_authentication"]
    dispatch = authentication["dispatch"]
    predecessor = None
    generation = 1
    if previous_claim is not None:
        if not isinstance(previous_claim, CollaborationExecutorDeliveryClaim):
            raise TypeError("previous_claim must be a delivery claim")
        previous = previous_claim.to_dict()
        expected_reservation = {
            "authentication_id": authentication["authentication_id"],
            "authentication_sha256": authentication["authentication_sha256"],
            "dispatch_id": dispatch["dispatch_id"],
            "dispatch_sha256": dispatch["dispatch_sha256"],
            "reserved_at": receipt["reserved_at"],
            "dispatch_expires_at": dispatch["expires_at"],
        }
        if previous["reservation"] != expected_reservation:
            raise CollaborationPlanError("Delivery predecessor reservation changed")
        generation = int(previous["claim_generation"]) + 1
        predecessor = {
            "claim_id": previous["claim_id"],
            "claim_sha256": previous["claim_sha256"],
            "claim_generation": previous["claim_generation"],
            "lease_expires_at": previous["lease_expires_at"],
        }
    body = {
        "schema_version": SCHEMA_VERSION,
        "reservation": {
            "authentication_id": authentication["authentication_id"],
            "authentication_sha256": authentication["authentication_sha256"],
            "dispatch_id": dispatch["dispatch_id"],
            "dispatch_sha256": dispatch["dispatch_sha256"],
            "reserved_at": receipt["reserved_at"],
            "dispatch_expires_at": dispatch["expires_at"],
        },
        "mission": {
            "mission_id": dispatch["mission"]["mission_id"],
            "collaboration_plan_id": dispatch["mission"]["collaboration_plan_id"],
        },
        "session": {
            "session_id": dispatch["session"]["session_id"],
            "session_sha256": dispatch["session"]["session_sha256"],
            "fence_generation": dispatch["worker"]["fence_generation"],
        },
        "operation": {
            "name": dispatch["operation"],
            "sequence": dispatch["operation_sequence"],
            "operation_input_sha256": dispatch["policy"][
                "operation_input_sha256"
            ],
        },
        "claimant": {"instance_id": claimant_instance_id},
        "claim_generation": generation,
        "predecessor": predecessor,
        "claimed_at": claimed_at,
        "lease_expires_at": lease_expires_at,
        "claim_status": "claimed_pending_invocation",
        "claimant_identity_status": "deployment_instance_unverified",
        "external_effect_status": "not_started",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": DELIVERY_CLAIM_DOMAIN, "delivery_claim": body}
    )
    return CollaborationExecutorDeliveryClaim.from_dict(
        {
            **body,
            "claim_id": "DCL-" + digest.removeprefix("sha256:")[:32].upper(),
            "claim_sha256": digest,
        }
    )


__all__ = [
    "CollaborationExecutorDeliveryClaim",
    "MAXIMUM_DELIVERY_CLAIM_LEASE_SECONDS",
    "build_collaboration_executor_delivery_claim",
]
