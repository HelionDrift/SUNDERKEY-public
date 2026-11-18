"""Digest verification for authenticated executor provider evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from .collaboration_executor_provider_report_authentication import (
    AuthenticatedCollaborationExecutorProviderReport,
    validate_authenticated_collaboration_executor_provider_report_document,
)
from .errors import CollaborationPlanError
from .qualification import (
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .store import parse_timestamp

SCHEMA_VERSION = 1
VERIFICATION_DOMAIN = "sunderkey.collaboration-executor-provider-evidence.v1"
MAXIMUM_EVIDENCE_BYTES = 16 * 1024 * 1024
_MEDIA_TYPE_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*"
)
_PROOF_KEY = secrets.token_bytes(32)


def _proof(document: dict[str, Any]) -> bytes:
    return hmac.new(
        _PROOF_KEY,
        (VERIFICATION_DOMAIN + "\x00" + _canonical_json(document)).encode(),
        "sha256",
    ).digest()


def _body(
    authentication: dict[str, Any],
    *,
    evidence_size_bytes: int,
    evidence_media_type: str,
    verified_at: str,
) -> dict[str, Any]:
    report = authentication["provider_report"]
    acknowledgement = report["provider_acknowledgement"]
    return {
        "schema_version": SCHEMA_VERSION,
        "report_authentication_id": authentication[
            "report_authentication_id"
        ],
        "report_authentication_sha256": authentication[
            "report_authentication_sha256"
        ],
        "report_custody_id": report["report_custody_id"],
        "report_custody_sha256": report["report_custody_sha256"],
        "attempt_id": report["invocation_preparation"]["attempt_id"],
        "acknowledgement_id": acknowledgement["acknowledgement_id"],
        "acknowledgement_sha256": acknowledgement[
            "acknowledgement_sha256"
        ],
        "provider_evidence_sha256": acknowledgement[
            "provider_evidence_sha256"
        ],
        "evidence_size_bytes": evidence_size_bytes,
        "evidence_media_type": evidence_media_type,
        "verified_at": verified_at,
        "evidence_verification_status": (
            "provider_evidence_digest_verified"
        ),
        "media_type_status": "caller_declared_unverified",
        "semantic_verification_status": "not_performed",
        "external_effect_status": (
            "authenticated_report_evidence_digest_verified_effect_unverified"
        ),
        "runtime_effect": "none",
    }


def validate_collaboration_executor_provider_evidence_digest_document(
    raw: Any,
) -> dict[str, Any]:
    """Validate serialized digest-verification material."""

    value = _mapping(raw, "executor provider evidence verification")
    fields = {
        "schema_version",
        "verification_id",
        "verification_sha256",
        "report_authentication_id",
        "report_authentication_sha256",
        "report_custody_id",
        "report_custody_sha256",
        "attempt_id",
        "acknowledgement_id",
        "acknowledgement_sha256",
        "provider_evidence_sha256",
        "evidence_size_bytes",
        "evidence_media_type",
        "verified_at",
        "evidence_verification_status",
        "media_type_status",
        "semantic_verification_status",
        "external_effect_status",
        "runtime_effect",
    }
    _exact_fields(value, fields, "executor provider evidence verification")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise CollaborationPlanError(
            "Provider evidence verification schema is invalid"
        )
    hashes = {
        "verification_sha256",
        "report_authentication_sha256",
        "report_custody_sha256",
        "acknowledgement_sha256",
        "provider_evidence_sha256",
    }
    if any(
        not isinstance(value.get(name), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value[name]) is None
        for name in hashes
    ):
        raise CollaborationPlanError(
            "Provider evidence verification digest is invalid"
        )
    identifiers = {
        "report_authentication_id": r"EPA-[0-9A-F]{32}",
        "report_custody_id": r"EPR-[0-9A-F]{32}",
        "attempt_id": r"EIP-[0-9A-F]{32}",
        "acknowledgement_id": r"EXA-[0-9A-F]{32}",
    }
    if any(
        not isinstance(value.get(name), str)
        or re.fullmatch(pattern, value[name]) is None
        for name, pattern in identifiers.items()
    ):
        raise CollaborationPlanError(
            "Provider evidence verification identity is invalid"
        )
    if (
        not isinstance(value.get("evidence_size_bytes"), int)
        or isinstance(value.get("evidence_size_bytes"), bool)
        or not 1
        <= value["evidence_size_bytes"]
        <= MAXIMUM_EVIDENCE_BYTES
    ):
        raise CollaborationPlanError(
            "Provider evidence verification size is invalid"
        )
    if (
        not isinstance(value.get("evidence_media_type"), str)
        or _MEDIA_TYPE_PATTERN.fullmatch(value["evidence_media_type"]) is None
    ):
        raise CollaborationPlanError(
            "Provider evidence media type is invalid"
        )
    parse_timestamp(value.get("verified_at"), "verified_at")
    if (
        value.get("evidence_verification_status")
        != "provider_evidence_digest_verified"
        or value.get("media_type_status")
        != "caller_declared_unverified"
        or value.get("semantic_verification_status") != "not_performed"
        or value.get("external_effect_status")
        != (
            "authenticated_report_evidence_digest_verified_"
            "effect_unverified"
        )
        or value.get("runtime_effect") != "none"
    ):
        raise CollaborationPlanError(
            "Provider evidence verification boundary is invalid"
        )
    body = {
        key: item
        for key, item in value.items()
        if key not in {"verification_id", "verification_sha256"}
    }
    digest = _canonical_sha256(
        {
            "domain": VERIFICATION_DOMAIN,
            "provider_evidence_verification": body,
        }
    )
    expected_id = "EPV-" + digest.removeprefix("sha256:")[:32].upper()
    if (
        value.get("verification_sha256") != digest
        or value.get("verification_id") != expected_id
    ):
        raise CollaborationPlanError(
            "Provider evidence verification hash is invalid"
        )
    return json.loads(_canonical_json(value))


@dataclass(frozen=True)
class VerifiedCollaborationExecutorProviderEvidenceDigest:
    """Exact provider evidence bytes matched to an authenticated report."""

    verification_id: str
    verification_sha256: str
    document: dict[str, Any]
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        parsed = validate_collaboration_executor_provider_evidence_digest_document(
            self.document
        )
        if (
            parsed["verification_id"] != self.verification_id
            or parsed["verification_sha256"] != self.verification_sha256
        ):
            raise TypeError("Provider evidence verification identity is invalid")
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            _proof(parsed),
        ):
            raise TypeError(
                "VerifiedCollaborationExecutorProviderEvidenceDigest can be "
                "created only by verify_collaboration_executor_provider_evidence_digest"
            )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(_canonical_json(self.document))

    def _proof_is_valid(self) -> bool:
        return isinstance(self._proof, bytes) and hmac.compare_digest(
            self._proof,
            _proof(self.to_dict()),
        )


def verify_collaboration_executor_provider_evidence_digest(
    authenticated_report: (
        AuthenticatedCollaborationExecutorProviderReport | dict[str, Any]
    ),
    evidence: bytes,
    *,
    evidence_media_type: str,
    verified_at: str,
) -> VerifiedCollaborationExecutorProviderEvidenceDigest:
    """Match exact evidence bytes while leaving meaning and effect unverified."""

    authentication_raw = (
        authenticated_report.to_dict()
        if isinstance(
            authenticated_report,
            AuthenticatedCollaborationExecutorProviderReport,
        )
        else authenticated_report
    )
    authentication = (
        validate_authenticated_collaboration_executor_provider_report_document(
            authentication_raw
        )
    )
    if not isinstance(evidence, bytes):
        raise TypeError("evidence must be bytes")
    if not 1 <= len(evidence) <= MAXIMUM_EVIDENCE_BYTES:
        raise CollaborationPlanError("Provider evidence size is invalid")
    if (
        not isinstance(evidence_media_type, str)
        or _MEDIA_TYPE_PATTERN.fullmatch(evidence_media_type) is None
    ):
        raise CollaborationPlanError("Provider evidence media type is invalid")
    verified_time = parse_timestamp(verified_at, "verified_at")
    authenticated_at = parse_timestamp(
        authentication["acknowledgement_authentication"]["authenticated_at"],
        "authenticated_at",
    )
    if verified_time < authenticated_at:
        raise CollaborationPlanError(
            "Provider evidence verification precedes report authentication"
        )
    evidence_sha256 = "sha256:" + hashlib.sha256(evidence).hexdigest()
    expected_sha256 = authentication["provider_report"][
        "provider_acknowledgement"
    ]["provider_evidence_sha256"]
    if not hmac.compare_digest(evidence_sha256, expected_sha256):
        raise CollaborationPlanError(
            "Provider evidence bytes do not match the retained digest"
        )
    body = _body(
        authentication,
        evidence_size_bytes=len(evidence),
        evidence_media_type=evidence_media_type,
        verified_at=verified_at,
    )
    digest = _canonical_sha256(
        {
            "domain": VERIFICATION_DOMAIN,
            "provider_evidence_verification": body,
        }
    )
    verification_id = "EPV-" + digest.removeprefix("sha256:")[:32].upper()
    document = {
        **body,
        "verification_id": verification_id,
        "verification_sha256": digest,
    }
    return VerifiedCollaborationExecutorProviderEvidenceDigest(
        verification_id=verification_id,
        verification_sha256=digest,
        document=document,
        _proof=_proof(document),
    )


__all__ = [
    "MAXIMUM_EVIDENCE_BYTES",
    "VerifiedCollaborationExecutorProviderEvidenceDigest",
    "validate_collaboration_executor_provider_evidence_digest_document",
    "verify_collaboration_executor_provider_evidence_digest",
]
