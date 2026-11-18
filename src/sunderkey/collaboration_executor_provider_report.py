"""Lossless provider-report custody contract for an invocation attempt."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .collaboration_executor import CollaborationExecutorAcknowledgement
from .collaboration_executor_invocation_attempt import (
    CollaborationExecutorInvocationPreparation,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .store import parse_timestamp

SCHEMA_VERSION = 1
PROVIDER_REPORT_DOMAIN = "sunderkey.collaboration-executor-provider-report.v1"


@dataclass(frozen=True)
class CollaborationExecutorProviderReport:
    """Complete untrusted provider report bound to one prepared attempt."""

    report_custody_id: str
    report_custody_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationExecutorProviderReport:
        value = _mapping(raw, "collaboration executor provider report")
        fields = {
            "schema_version",
            "report_custody_id",
            "report_custody_sha256",
            "invocation_preparation",
            "provider_acknowledgement",
            "received_at",
            "report_status",
            "authentication_status",
            "external_effect_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration executor provider report")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Provider report custody schema is invalid")
        report_custody_id = value.get("report_custody_id")
        report_custody_sha256 = value.get("report_custody_sha256")
        if (
            not isinstance(report_custody_id, str)
            or re.fullmatch(r"EPR-[0-9A-F]{32}", report_custody_id) is None
            or not isinstance(report_custody_sha256, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", report_custody_sha256) is None
        ):
            raise CollaborationPlanError("Provider report custody identity is invalid")
        preparation = _mapping(
            value.get("invocation_preparation"),
            "invocation_preparation",
        )
        _exact_fields(
            preparation,
            {
                "attempt_id",
                "attempt_sha256",
                "prepared_at",
                "dispatch_id",
                "dispatch_sha256",
                "operation",
                "operation_sequence",
                "session_id",
                "session_sha256",
                "fence_generation",
                "adapter_id",
                "adapter_version",
                "adapter_build_sha256",
            },
            "invocation_preparation",
        )
        if (
            not isinstance(preparation["attempt_id"], str)
            or re.fullmatch(r"EIP-[0-9A-F]{32}", preparation["attempt_id"])
            is None
            or not isinstance(preparation["attempt_sha256"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", preparation["attempt_sha256"])
            is None
        ):
            raise CollaborationPlanError("Provider report preparation is invalid")
        prepared_at = parse_timestamp(
            preparation["prepared_at"],
            "invocation_preparation.prepared_at",
        )
        acknowledgement = CollaborationExecutorAcknowledgement.from_dict(
            value.get("provider_acknowledgement")
        )
        report = acknowledgement.to_dict()
        if (
            report["dispatch"]["dispatch_id"] != preparation["dispatch_id"]
            or report["dispatch"]["dispatch_sha256"]
            != preparation["dispatch_sha256"]
            or report["dispatch"]["operation"] != preparation["operation"]
            or report["dispatch"]["operation_sequence"]
            != preparation["operation_sequence"]
            or report["provider"]["adapter_id"] != preparation["adapter_id"]
            or report["provider"]["adapter_version"]
            != preparation["adapter_version"]
            or report["provider"]["adapter_build_sha256"]
            != preparation["adapter_build_sha256"]
            or report["session"]["session_id"] != preparation["session_id"]
            or report["session"]["session_sha256"]
            != preparation["session_sha256"]
            or report["worker"]["fence_generation"]
            != preparation["fence_generation"]
        ):
            raise CollaborationPlanError(
                "Provider report does not bind invocation preparation"
            )
        acknowledged_at = parse_timestamp(
            report["acknowledged_at"],
            "provider_acknowledgement.acknowledged_at",
        )
        received_at = parse_timestamp(value.get("received_at"), "received_at")
        if acknowledged_at < prepared_at or received_at < acknowledged_at:
            raise CollaborationPlanError("Provider report custody time is invalid")
        if (
            value.get("report_status")
            != "complete_report_captured_pending_authentication"
            or value.get("authentication_status") != "not_authenticated"
            or value.get("external_effect_status")
            != "provider_report_pending_authentication"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Provider report custody boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_custody_id", "report_custody_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": PROVIDER_REPORT_DOMAIN, "provider_report": body}
        )
        expected_id = "EPR-" + digest.removeprefix("sha256:")[:32].upper()
        if (
            report_custody_sha256 != digest
            or report_custody_id != expected_id
        ):
            raise CollaborationPlanError("Provider report custody hash is invalid")
        return cls(report_custody_id, report_custody_sha256, _canonical_json(value))

    @property
    def provider_acknowledgement(self) -> CollaborationExecutorAcknowledgement:
        return CollaborationExecutorAcknowledgement.from_dict(
            self.to_dict()["provider_acknowledgement"]
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Provider report custody is invalid")
        return value


def build_collaboration_executor_provider_report(
    preparation: CollaborationExecutorInvocationPreparation,
    provider_acknowledgement: CollaborationExecutorAcknowledgement,
    *,
    received_at: str,
) -> CollaborationExecutorProviderReport:
    """Capture one complete untrusted report without authenticating it."""

    if not isinstance(preparation, CollaborationExecutorInvocationPreparation):
        raise TypeError("preparation must be an invocation preparation")
    if not isinstance(provider_acknowledgement, CollaborationExecutorAcknowledgement):
        raise TypeError("provider_acknowledgement must be an executor acknowledgement")
    attempt = preparation.to_dict()
    body = {
        "schema_version": SCHEMA_VERSION,
        "invocation_preparation": {
            "attempt_id": preparation.attempt_id,
            "attempt_sha256": preparation.attempt_sha256,
            "prepared_at": attempt["prepared_at"],
            "dispatch_id": attempt["reservation"]["dispatch_id"],
            "dispatch_sha256": attempt["reservation"]["dispatch_sha256"],
            "operation": attempt["operation"]["name"],
            "operation_sequence": attempt["operation"]["sequence"],
            "session_id": attempt["session"]["session_id"],
            "session_sha256": attempt["session"]["session_sha256"],
            "fence_generation": attempt["session"]["fence_generation"],
            "adapter_id": attempt["adapter"]["adapter_id"],
            "adapter_version": attempt["adapter"]["adapter_version"],
            "adapter_build_sha256": attempt["adapter"]["adapter_build_sha256"],
        },
        "provider_acknowledgement": provider_acknowledgement.to_dict(),
        "received_at": received_at,
        "report_status": "complete_report_captured_pending_authentication",
        "authentication_status": "not_authenticated",
        "external_effect_status": "provider_report_pending_authentication",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": PROVIDER_REPORT_DOMAIN, "provider_report": body}
    )
    return CollaborationExecutorProviderReport.from_dict(
        {
            **body,
            "report_custody_id": "EPR-"
            + digest.removeprefix("sha256:")[:32].upper(),
            "report_custody_sha256": digest,
        }
    )


__all__ = [
    "CollaborationExecutorProviderReport",
    "build_collaboration_executor_provider_report",
]
