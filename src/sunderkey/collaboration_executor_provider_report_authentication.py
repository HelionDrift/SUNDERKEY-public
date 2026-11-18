"""Bind worker-principal authentication to durable provider-report custody."""

from __future__ import annotations

import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from .collaboration_executor import (
    SAFETY_REDUCING_OPERATIONS,
    CollaborationExecutorAcknowledgement,
)
from .collaboration_executor_authentication import (
    AUTHENTICATION_DOMAIN as ACKNOWLEDGEMENT_AUTHENTICATION_DOMAIN,
    AuthenticatedCollaborationExecutorAcknowledgement,
)
from .collaboration_executor_provider_report import (
    CollaborationExecutorProviderReport,
)
from .errors import CollaborationPlanError
from .identity import PrincipalOperation
from .qualification import (
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .store import parse_timestamp

SCHEMA_VERSION = 1
AUTHENTICATION_DOMAIN = (
    "sunderkey.collaboration-executor-provider-report-authentication.v1"
)
_PROOF_KEY = secrets.token_bytes(32)


def _authentication_body(
    provider_report: CollaborationExecutorProviderReport,
    acknowledgement_authentication: (
        AuthenticatedCollaborationExecutorAcknowledgement
    ),
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "provider_report": provider_report.to_dict(),
        "acknowledgement_authentication": (
            acknowledgement_authentication.to_dict()
        ),
        "authentication_status": "authenticated_worker_principal",
        "evidence_verification_status": (
            "provider_evidence_digest_unverified"
        ),
        "external_effect_status": "authenticated_report_unverified_effect",
        "runtime_effect": "none",
    }


def _proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        (AUTHENTICATION_DOMAIN + "\x00" + _canonical_json(document)).encode(),
        "sha256",
    ).digest()


def validate_authenticated_collaboration_executor_provider_report_document(
    raw: Any,
) -> dict[str, Any]:
    """Validate the serialized contract without recreating its trusted wrapper."""

    value = _mapping(raw, "authenticated executor provider report")
    fields = {
        "schema_version",
        "report_authentication_id",
        "report_authentication_sha256",
        "provider_report",
        "acknowledgement_authentication",
        "authentication_status",
        "evidence_verification_status",
        "external_effect_status",
        "runtime_effect",
    }
    _exact_fields(value, fields, "authenticated executor provider report")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise CollaborationPlanError(
            "Provider report authentication schema is invalid"
        )
    report = CollaborationExecutorProviderReport.from_dict(
        value.get("provider_report")
    )
    authentication = _mapping(
        value.get("acknowledgement_authentication"),
        "acknowledgement_authentication",
    )
    authentication_fields = {
        "schema_version",
        "authentication_id",
        "authentication_sha256",
        "acknowledgement",
        "worker_attestor",
        "authenticated_at",
        "authentication_status",
        "external_effect_status",
        "runtime_effect",
    }
    _exact_fields(
        authentication,
        authentication_fields,
        "acknowledgement_authentication",
    )
    if authentication.get("schema_version") != 1:
        raise CollaborationPlanError(
            "Provider report acknowledgement authentication schema is invalid"
        )
    acknowledgement = CollaborationExecutorAcknowledgement.from_dict(
        authentication.get("acknowledgement")
    )
    if acknowledgement != report.provider_acknowledgement:
        raise CollaborationPlanError(
            "Provider report authentication does not bind the retained report"
        )
    worker = _mapping(authentication.get("worker_attestor"), "worker_attestor")
    worker_fields = {
        "assertion_id",
        "assertion_sha256",
        "subject",
        "profile_id",
        "issuer",
        "key_id",
        "key_sha256",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "scope_grant_id",
        "scope_grant_sha256",
        "audience",
        "store_id",
        "mission_id",
        "operation",
        "operation_intent_sha256",
        "authenticated_at",
        "expires_at",
    }
    _exact_fields(worker, worker_fields, "worker_attestor")
    if (
        not isinstance(worker.get("policy_version"), int)
        or isinstance(worker.get("policy_version"), bool)
        or worker["policy_version"] < 1
    ):
        raise CollaborationPlanError(
            "Provider report worker policy version is invalid"
        )
    hashes = {
        "assertion_sha256",
        "key_sha256",
        "policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
    }
    if any(
        not isinstance(worker.get(field), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", worker[field]) is None
        for field in hashes
    ):
        raise CollaborationPlanError("Provider report worker digest is invalid")
    strings = worker_fields - hashes - {"policy_version"}
    if any(
        not isinstance(worker.get(field), str) or not worker[field]
        for field in strings
    ):
        raise CollaborationPlanError("Provider report worker identity is invalid")
    acknowledgement_document = acknowledgement.to_dict()
    report_worker = acknowledgement_document["worker"]
    if worker["profile_id"] != report_worker["worker_principal_id"]:
        raise CollaborationPlanError(
            "Provider report authentication worker does not match"
        )
    expected_operation = (
        PrincipalOperation.EXECUTOR_ACKNOWLEDGE_SAFETY.value
        if acknowledgement_document["dispatch"]["operation"]
        in SAFETY_REDUCING_OPERATIONS
        else PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value
    )
    if worker["operation"] != expected_operation:
        raise CollaborationPlanError(
            "Provider report authentication operation does not match"
        )
    if worker["authenticated_at"] != authentication.get("authenticated_at"):
        raise CollaborationPlanError(
            "Provider report authentication time does not reconcile"
        )
    authenticated_at = parse_timestamp(
        authentication.get("authenticated_at"),
        "authenticated_at",
    )
    if authenticated_at < parse_timestamp(
        report.to_dict()["received_at"],
        "received_at",
    ):
        raise CollaborationPlanError(
            "Provider report authentication precedes durable custody"
        )
    if (
        authentication.get("authentication_status")
        != "authenticated_worker_principal"
        or authentication.get("external_effect_status")
        != "authenticated_report_unverified_effect"
        or authentication.get("runtime_effect") != "none"
    ):
        raise CollaborationPlanError(
            "Provider report acknowledgement authentication boundary is invalid"
        )
    acknowledgement_body = {
        key: item
        for key, item in authentication.items()
        if key not in {"authentication_id", "authentication_sha256"}
    }
    acknowledgement_digest = _canonical_sha256(
        {
            "domain": ACKNOWLEDGEMENT_AUTHENTICATION_DOMAIN,
            "authentication": acknowledgement_body,
        }
    )
    expected_acknowledgement_id = (
        "EAX-" + acknowledgement_digest.removeprefix("sha256:")[:32].upper()
    )
    if (
        authentication.get("authentication_sha256")
        != acknowledgement_digest
        or authentication.get("authentication_id")
        != expected_acknowledgement_id
    ):
        raise CollaborationPlanError(
            "Provider report acknowledgement authentication hash is invalid"
        )
    if (
        value.get("authentication_status")
        != "authenticated_worker_principal"
        or value.get("evidence_verification_status")
        != "provider_evidence_digest_unverified"
        or value.get("external_effect_status")
        != "authenticated_report_unverified_effect"
        or value.get("runtime_effect") != "none"
    ):
        raise CollaborationPlanError(
            "Provider report authentication boundary is invalid"
        )
    body = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "report_authentication_id",
            "report_authentication_sha256",
        }
    }
    digest = _canonical_sha256(
        {
            "domain": AUTHENTICATION_DOMAIN,
            "provider_report_authentication": body,
        }
    )
    expected_id = "EPA-" + digest.removeprefix("sha256:")[:32].upper()
    if (
        value.get("report_authentication_sha256") != digest
        or value.get("report_authentication_id") != expected_id
    ):
        raise CollaborationPlanError(
            "Provider report authentication hash is invalid"
        )
    return json.loads(_canonical_json(value))


def collaboration_executor_provider_report_authentication_effect_payload(
    authenticated: (
        AuthenticatedCollaborationExecutorProviderReport | dict[str, Any]
    ),
) -> dict[str, Any]:
    """Build the exact protected effect payload for durable authentication."""

    raw = (
        authenticated.to_dict()
        if isinstance(
            authenticated,
            AuthenticatedCollaborationExecutorProviderReport,
        )
        else authenticated
    )
    document = validate_authenticated_collaboration_executor_provider_report_document(
        raw
    )
    report = document["provider_report"]
    acknowledgement = report["provider_acknowledgement"]
    authentication = document["acknowledgement_authentication"]
    return {
        "report_authentication_id": document["report_authentication_id"],
        "report_authentication_sha256": document[
            "report_authentication_sha256"
        ],
        "report_custody_id": report["report_custody_id"],
        "report_custody_sha256": report["report_custody_sha256"],
        "attempt_id": report["invocation_preparation"]["attempt_id"],
        "acknowledgement_authentication_id": authentication[
            "authentication_id"
        ],
        "acknowledgement_authentication_sha256": authentication[
            "authentication_sha256"
        ],
        "acknowledgement_id": acknowledgement["acknowledgement_id"],
        "acknowledgement_sha256": acknowledgement[
            "acknowledgement_sha256"
        ],
        "mission_id": authentication["worker_attestor"]["mission_id"],
        "authentication_status": document["authentication_status"],
        "evidence_verification_status": document[
            "evidence_verification_status"
        ],
        "external_effect_status": document["external_effect_status"],
        "runtime_effect": document["runtime_effect"],
    }


@dataclass(frozen=True)
class AuthenticatedCollaborationExecutorProviderReport:
    """A durable report bound to exact worker-principal authentication."""

    report_authentication_id: str
    report_authentication_sha256: str
    provider_report: CollaborationExecutorProviderReport
    acknowledgement_authentication: (
        AuthenticatedCollaborationExecutorAcknowledgement
    )
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        report = CollaborationExecutorProviderReport.from_dict(
            self.provider_report.to_dict()
        )
        authentication = self.acknowledgement_authentication
        if (
            not isinstance(
                authentication,
                AuthenticatedCollaborationExecutorAcknowledgement,
            )
            or not authentication._proof_is_valid()
        ):
            raise TypeError(
                "acknowledgement_authentication must be produced by executor "
                "acknowledgement authentication"
            )
        if (
            authentication.acknowledgement.to_dict()
            != report.provider_acknowledgement.to_dict()
        ):
            raise CollaborationPlanError(
                "Provider report authentication does not bind the retained report"
            )
        report_document = report.to_dict()
        acknowledgement = report_document["provider_acknowledgement"]
        if (
            authentication.worker_attestor.to_dict()["profile_id"]
            != acknowledgement["worker"]["worker_principal_id"]
        ):
            raise CollaborationPlanError(
                "Provider report authentication worker does not match"
            )
        if parse_timestamp(
            authentication.authenticated_at,
            "authenticated_at",
        ) < parse_timestamp(report_document["received_at"], "received_at"):
            raise CollaborationPlanError(
                "Provider report authentication precedes durable custody"
            )
        body = _authentication_body(report, authentication)
        digest = _canonical_sha256(
            {
                "domain": AUTHENTICATION_DOMAIN,
                "provider_report_authentication": body,
            }
        )
        expected_id = "EPA-" + digest.removeprefix("sha256:")[:32].upper()
        document = {
            **body,
            "report_authentication_id": self.report_authentication_id,
            "report_authentication_sha256": self.report_authentication_sha256,
        }
        if (
            self.report_authentication_sha256 != digest
            or self.report_authentication_id != expected_id
        ):
            raise TypeError("Provider report authentication identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _proof(document),
        ):
            raise TypeError(
                "AuthenticatedCollaborationExecutorProviderReport can be created "
                "only by bind_authenticated_collaboration_executor_provider_report"
            )

    def to_dict(self) -> dict[str, Any]:
        body = _authentication_body(
            self.provider_report,
            self.acknowledgement_authentication,
        )
        return {
            **body,
            "report_authentication_id": self.report_authentication_id,
            "report_authentication_sha256": self.report_authentication_sha256,
        }

    def _proof_is_valid(self) -> bool:
        return isinstance(self._proof, bytes) and hmac.compare_digest(
            self._proof,
            _proof(self.to_dict()),
        )


def bind_authenticated_collaboration_executor_provider_report(
    provider_report: CollaborationExecutorProviderReport,
    acknowledgement_authentication: (
        AuthenticatedCollaborationExecutorAcknowledgement
    ),
) -> AuthenticatedCollaborationExecutorProviderReport:
    """Bind a retained report to exact worker authentication without execution."""

    if not isinstance(provider_report, CollaborationExecutorProviderReport):
        raise TypeError("provider_report must be a provider report")
    if not isinstance(
        acknowledgement_authentication,
        AuthenticatedCollaborationExecutorAcknowledgement,
    ):
        raise TypeError(
            "acknowledgement_authentication must be authenticated"
        )
    report = CollaborationExecutorProviderReport.from_dict(
        provider_report.to_dict()
    )
    body = _authentication_body(report, acknowledgement_authentication)
    digest = _canonical_sha256(
        {
            "domain": AUTHENTICATION_DOMAIN,
            "provider_report_authentication": body,
        }
    )
    authentication_id = "EPA-" + digest.removeprefix("sha256:")[:32].upper()
    document = {
        **body,
        "report_authentication_id": authentication_id,
        "report_authentication_sha256": digest,
    }
    return AuthenticatedCollaborationExecutorProviderReport(
        report_authentication_id=authentication_id,
        report_authentication_sha256=digest,
        provider_report=report,
        acknowledgement_authentication=acknowledgement_authentication,
        _proof=_proof(document),
    )


__all__ = [
    "AuthenticatedCollaborationExecutorProviderReport",
    "bind_authenticated_collaboration_executor_provider_report",
    "collaboration_executor_provider_report_authentication_effect_payload",
    "validate_authenticated_collaboration_executor_provider_report_document",
]
