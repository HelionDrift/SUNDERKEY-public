"""Bind supplied HTTP response bytes to an existing exchange receipt offline.

The receipt is content-addressed but not an origin attestation. This module
performs no HTTP request and grants no target, finding, or execution authority.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

from .authorized_http_runtime import AuthorizedHttpRuntimeError, verify_exchange_receipt
from .finding_validators import EvidenceRecord, FindingValidationError


class OfflineApiReceiptEvidenceError(ValueError):
    """Raised when response bytes cannot be bound to an exact receipt context."""


def bind_http_response_evidence(
    *,
    receipt: bytes | str | Mapping[str, Any],
    response_body: bytes,
    evidence_id: str,
    principal_id: str,
    object_id: str,
    action: str,
    expected_access: bool,
    expected_scope_id: str,
    expected_scope_sha256: str,
    expected_target_id: str,
    expected_target_sha256: str,
    expected_session_id: str,
) -> EvidenceRecord:
    """Create typed response evidence only after exact receipt and body checks.

    Principal identity and expected access are caller assertions. A valid
    content address does not authenticate the backend, target, or principal.
    """

    if not isinstance(response_body, bytes):
        raise OfflineApiReceiptEvidenceError("response body must be bytes")
    if type(expected_access) is not bool:
        raise OfflineApiReceiptEvidenceError("expected access must be boolean")
    try:
        checked = verify_exchange_receipt(
            dict(receipt) if isinstance(receipt, Mapping) else receipt
        )
    except (AuthorizedHttpRuntimeError, TypeError, ValueError) as exc:
        raise OfflineApiReceiptEvidenceError("HTTP receipt verification failed") from exc
    if (
        type(checked["schema_version"]) is not int
        or type(checked["transport_called"]) is not bool
        or type(checked["network_call_performed"]) is not bool
    ):
        raise OfflineApiReceiptEvidenceError("HTTP receipt wire types are invalid")
    if checked["status"] != "completed" or not checked["transport_called"]:
        raise OfflineApiReceiptEvidenceError("completed HTTP response receipt is required")
    binding = checked["binding"]
    if (
        checked["scope_id"] != expected_scope_id
        or checked["scope_sha256"] != expected_scope_sha256
        or binding["scope_id"] != expected_scope_id
        or binding["scope_sha256"] != expected_scope_sha256
        or binding["target_id"] != expected_target_id
        or binding["target_sha256"] != expected_target_sha256
        or binding["session_id"] != expected_session_id
    ):
        raise OfflineApiReceiptEvidenceError("HTTP receipt context does not match")
    actual_digest = "sha256:" + hashlib.sha256(response_body).hexdigest()
    if (
        not hmac.compare_digest(actual_digest, checked["response_body_sha256"])
        or len(response_body) != checked["response_size_bytes"]
    ):
        raise OfflineApiReceiptEvidenceError("response bytes do not match HTTP receipt")
    try:
        return EvidenceRecord.from_bytes(
            evidence_id,
            response_body,
            media_type=checked["response_mime_type"],
            role="response",
            status_code=checked["response_status_code"],
            attributes={
                "principal_id": principal_id,
                "object_id": object_id,
                "action": action,
                "expected_access": expected_access,
                "source_receipt_sha256": checked["receipt_sha256"],
                "source_session_id": expected_session_id,
                "source_scope_id": expected_scope_id,
                "source_scope_sha256": expected_scope_sha256,
                "source_target_id": expected_target_id,
                "source_target_sha256": expected_target_sha256,
            },
        )
    except FindingValidationError as exc:
        raise OfflineApiReceiptEvidenceError("typed HTTP response evidence is invalid") from exc


__all__ = ["OfflineApiReceiptEvidenceError", "bind_http_response_evidence"]
