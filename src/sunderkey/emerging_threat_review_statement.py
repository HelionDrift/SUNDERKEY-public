"""Externally signed historical opinions about offline threat reviews."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .emerging_threat_review import (
    EmergingThreatReviewError,
    _utc,
    verify_emerging_threat_review,
)

DOMAIN = "sunderkey.emerging-threat-review-statement.v1"
SIGNATURE_DOMAIN = "sunderkey.emerging-threat-review-statement.signature.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
ROLES = frozenset({"independent_control", "independent_assurance"})
DISPOSITIONS = frozenset({"supports", "challenges", "insufficient_evidence"})
EFFECTS = {
    "admission": "none",
    "authorization": "none",
    "content_release": "none",
    "qualification": "none",
    "review_approval": "none",
    "target_interaction": "none",
    "test_execution": "none",
}


class EmergingThreatReviewStatementError(ValueError):
    """The historical opinion or its exact source binding is invalid."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise EmergingThreatReviewStatementError("statement is not JSON") from exc


def _key_id(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise EmergingThreatReviewStatementError("pinned Ed25519 public key is invalid")
    return "ETK-" + hashlib.sha256(public_key).hexdigest()[:32].upper()


def _statement_body(unsigned: Any) -> dict[str, Any]:
    if (
        type(unsigned) is not dict
        or any(type(key) is not str for key in unsigned)
        or set(unsigned) != {
            "statement_id", "statement_sha256", "schema_version", "review_sha256",
            "advisory_sha256", "inventory_sha256", "reviewer_id", "claimed_role",
            "disposition", "rationale_sha256", "signed_at", "signer_key_id",
            "qualification_effect", "effects",
        }
    ):
        raise EmergingThreatReviewStatementError("unsigned statement fields are invalid")
    body = {
        key: value for key, value in unsigned.items()
        if key not in {"statement_id", "statement_sha256"}
    }
    if type(body["schema_version"]) is not int or body["schema_version"] != 1:
        raise EmergingThreatReviewStatementError("statement version is invalid")
    for key in ("review_sha256", "advisory_sha256", "inventory_sha256", "rationale_sha256"):
        if type(body[key]) is not str or SHA256_RE.fullmatch(body[key]) is None:
            raise EmergingThreatReviewStatementError("statement digest is invalid")
    if (
        type(body["reviewer_id"]) is not str
        or IDENTIFIER_RE.fullmatch(body["reviewer_id"]) is None
        or type(body["claimed_role"]) is not str
        or body["claimed_role"] not in ROLES
        or type(body["disposition"]) is not str
        or body["disposition"] not in DISPOSITIONS
        or type(body["signer_key_id"]) is not str
        or re.fullmatch(r"ETK-[0-9A-F]{32}", body["signer_key_id"]) is None
        or type(body["qualification_effect"]) is not str
        or body["qualification_effect"] != "none"
        or type(body["effects"]) is not dict
        or _canonical(body["effects"]) != _canonical(EFFECTS)
    ):
        raise EmergingThreatReviewStatementError("statement semantics are invalid")
    try:
        _utc(body["signed_at"], "signed_at")
    except EmergingThreatReviewError as exc:
        raise EmergingThreatReviewStatementError("statement time is invalid") from exc
    digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
    if (
        unsigned["statement_id"] != "ETS-" + digest[:32].upper()
        or unsigned["statement_sha256"] != "sha256:" + digest
    ):
        raise EmergingThreatReviewStatementError("statement content address is invalid")
    return body


def build_emerging_threat_review_statement(
    advisory: Any,
    inventory: Any,
    review_at: str,
    review: Any,
    *,
    reviewer_id: str,
    claimed_role: str,
    disposition: str,
    rationale_sha256: str,
    signed_at: str,
    pinned_public_key: bytes,
    maximum_inventory_age_seconds: int = 604_800,
) -> dict[str, Any]:
    """Prepare a source-replayed unsigned historical opinion for an external signer."""

    try:
        verify_emerging_threat_review(
            advisory, inventory, review_at, review,
            maximum_inventory_age_seconds=maximum_inventory_age_seconds,
        )
        review_time = _utc(review_at, "review_at")
        signing_time = _utc(signed_at, "signed_at")
    except EmergingThreatReviewError as exc:
        raise EmergingThreatReviewStatementError("threat review source does not replay") from exc
    if not timedelta(0) <= signing_time - review_time <= timedelta(days=7):
        raise EmergingThreatReviewStatementError("signing time is outside review window")
    key_id = _key_id(pinned_public_key)
    body = {
        "schema_version": 1,
        "review_sha256": review["review_sha256"],
        "advisory_sha256": review["advisory_sha256"],
        "inventory_sha256": review["inventory_sha256"],
        "reviewer_id": reviewer_id,
        "claimed_role": claimed_role,
        "disposition": disposition,
        "rationale_sha256": rationale_sha256,
        "signed_at": signed_at,
        "signer_key_id": key_id,
        "qualification_effect": "none",
        "effects": dict(EFFECTS),
    }
    digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
    unsigned = {
        **body,
        "statement_id": "ETS-" + digest[:32].upper(),
        "statement_sha256": "sha256:" + digest,
    }
    _statement_body(unsigned)
    return unsigned


def emerging_threat_review_statement_signing_bytes(unsigned: Any) -> bytes:
    """Return exact domain-separated bytes without using a private key."""

    _statement_body(unsigned)
    return SIGNATURE_DOMAIN.encode() + b"\0" + _canonical(unsigned)


def verify_emerging_threat_review_statement(
    signed: Any,
    advisory: Any,
    inventory: Any,
    review_at: str,
    review: Any,
    *,
    pinned_public_key: bytes,
    maximum_inventory_age_seconds: int = 604_800,
) -> dict[str, str]:
    """Verify signature and exact historical sources without approving any use."""

    if type(signed) is not dict or any(type(key) is not str for key in signed) or set(signed) != {
        "statement_id", "statement_sha256", "schema_version", "review_sha256",
        "advisory_sha256", "inventory_sha256", "reviewer_id", "claimed_role",
        "disposition", "rationale_sha256", "signed_at", "signer_key_id",
        "qualification_effect", "effects", "signature_b64url",
    }:
        raise EmergingThreatReviewStatementError("signed statement fields are invalid")
    signature = signed["signature_b64url"]
    if type(signature) is not str or SIGNATURE_RE.fullmatch(signature) is None:
        raise EmergingThreatReviewStatementError("signature encoding is invalid")
    unsigned = {key: value for key, value in signed.items() if key != "signature_b64url"}
    expected = build_emerging_threat_review_statement(
        advisory, inventory, review_at, review,
        reviewer_id=signed["reviewer_id"],
        claimed_role=signed["claimed_role"],
        disposition=signed["disposition"],
        rationale_sha256=signed["rationale_sha256"],
        signed_at=signed["signed_at"],
        pinned_public_key=pinned_public_key,
        maximum_inventory_age_seconds=maximum_inventory_age_seconds,
    )
    if _canonical(unsigned) != _canonical(expected):
        raise EmergingThreatReviewStatementError("statement source binding differs")
    try:
        signature_bytes = base64.urlsafe_b64decode(signature + "==")
        if len(signature_bytes) != 64:
            raise ValueError("signature length")
        if base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode() != signature:
            raise ValueError("noncanonical signature encoding")
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(
            signature_bytes, emerging_threat_review_statement_signing_bytes(unsigned)
        )
    except (InvalidSignature, ValueError) as exc:
        raise EmergingThreatReviewStatementError("statement signature is invalid") from exc
    return {
        "status": "valid_historical_opinion_only",
        "statement_id": expected["statement_id"],
        "statement_sha256": expected["statement_sha256"],
        "qualification_effect": "none",
    }
