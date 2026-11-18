"""Independent, non-authorizing signature check for one offline event-history head."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sunderkey.event_assessment_history import (
    MAX_HISTORY_ENTRIES,
    OfflineEventAssessmentHistoryStore,
)

DOMAIN = "sunderkey.event-history-checkpoint.v1"
SIGNATURE_DOMAIN = "sunderkey.event-history-checkpoint.signature.v1"
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
KEY_ID_RE = re.compile(r"EHK-[0-9A-F]{32}\Z")
NO_EFFECTS = {
    "admission": "none",
    "authority": "none",
    "network": "none",
    "qualification": "none",
    "scheduling": "none",
    "target_interaction": "none",
}


class EventHistoryCheckpointError(ValueError):
    """A checkpoint, pinned key, signature, or local head is invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _key_id(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise EventHistoryCheckpointError("pinned Ed25519 public key must be 32 bytes")
    return "EHK-" + hashlib.sha256(public_key).hexdigest()[:32].upper()


def _time(value: str) -> None:
    if type(value) is not str or TIMESTAMP_RE.fullmatch(value) is None:
        raise EventHistoryCheckpointError("observed_at must be canonical UTC seconds")
    try:
        instant = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise EventHistoryCheckpointError("observed_at is invalid") from exc
    if instant.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise EventHistoryCheckpointError("observed_at is not canonical")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise EventHistoryCheckpointError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def build_event_history_checkpoint(
    store: OfflineEventAssessmentHistoryStore,
    *,
    pinned_public_key: bytes,
    custody_domain: str,
    observed_at: str,
) -> dict[str, Any]:
    """Build an unsigned exact-head checkpoint for an external signer."""

    if type(store) is not OfflineEventAssessmentHistoryStore:
        raise EventHistoryCheckpointError("history store must be the exact local reference type")
    key_id = _key_id(pinned_public_key)
    if type(custody_domain) is not str or IDENTIFIER_RE.fullmatch(custody_domain) is None:
        raise EventHistoryCheckpointError("custody_domain is invalid")
    _time(observed_at)
    try:
        verified = store.verify()
    except Exception as exc:
        raise EventHistoryCheckpointError("local history did not verify") from exc
    body = {
        "schema_version": 1,
        "custody_domain": custody_domain,
        "scope_sha256": verified.scope_sha256,
        "head_sequence": verified.head_sequence,
        "head_sha256": verified.head_sha256,
        "observed_at": observed_at,
        "signer_key_id": key_id,
        "effects": dict(NO_EFFECTS),
    }
    digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
    return {
        "checkpoint_id": "EHC-" + digest[:32].upper(),
        "checkpoint_sha256": "sha256:" + digest,
        **body,
    }


def event_history_checkpoint_signing_bytes(checkpoint: dict[str, Any]) -> bytes:
    """Return domain-separated bytes for an external Ed25519 signer."""

    if type(checkpoint) is not dict or set(checkpoint) != {
        "checkpoint_id", "checkpoint_sha256", "schema_version", "custody_domain",
        "scope_sha256", "head_sequence", "head_sha256", "observed_at",
        "signer_key_id", "effects",
    }:
        raise EventHistoryCheckpointError("unsigned checkpoint fields are invalid")
    body = {
        key: value for key, value in checkpoint.items()
        if key not in {"checkpoint_id", "checkpoint_sha256"}
    }
    if (
        type(body["schema_version"]) is not int
        or body["schema_version"] != 1
        or type(body["custody_domain"]) is not str
        or IDENTIFIER_RE.fullmatch(body["custody_domain"]) is None
        or type(body["scope_sha256"]) is not str
        or SHA256_RE.fullmatch(body["scope_sha256"]) is None
        or type(body["head_sequence"]) is not int
        or not 0 <= body["head_sequence"] <= MAX_HISTORY_ENTRIES
        or type(body["head_sha256"]) is not str
        or SHA256_RE.fullmatch(body["head_sha256"]) is None
        or type(body["signer_key_id"]) is not str
        or KEY_ID_RE.fullmatch(body["signer_key_id"]) is None
        or body["effects"] != NO_EFFECTS
    ):
        raise EventHistoryCheckpointError("unsigned checkpoint fields are invalid")
    _time(body["observed_at"])
    try:
        digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
        if (
            checkpoint["checkpoint_id"] != "EHC-" + digest[:32].upper()
            or checkpoint["checkpoint_sha256"] != "sha256:" + digest
        ):
            raise EventHistoryCheckpointError("checkpoint content address is invalid")
        return SIGNATURE_DOMAIN.encode() + b"\0" + _canonical(checkpoint)
    except (TypeError, ValueError) as exc:
        raise EventHistoryCheckpointError("checkpoint is not canonical JSON") from exc


def verify_event_history_checkpoint(
    raw: Any,
    store: OfflineEventAssessmentHistoryStore,
    *,
    pinned_public_key: bytes,
    expected_custody_domain: str,
) -> dict[str, Any]:
    """Verify signature and exact current replayed head, with no authority effect."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EventHistoryCheckpointError("checkpoint is not UTF-8") from exc
    if isinstance(raw, str):
        try:
            raw = json.loads(raw, object_pairs_hook=_unique_pairs)
        except (TypeError, ValueError) as exc:
            raise EventHistoryCheckpointError("checkpoint is not valid JSON") from exc
    if type(raw) is not dict or set(raw) != {
        "checkpoint_id", "checkpoint_sha256", "schema_version", "custody_domain",
        "scope_sha256", "head_sequence", "head_sha256", "observed_at",
        "signer_key_id", "effects", "signature_b64url",
    }:
        raise EventHistoryCheckpointError("signed checkpoint fields are invalid")
    signature_text = raw["signature_b64url"]
    if (
        type(signature_text) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{86}", signature_text) is None
    ):
        raise EventHistoryCheckpointError("signature encoding is invalid")
    unsigned = {key: value for key, value in raw.items() if key != "signature_b64url"}
    expected = build_event_history_checkpoint(
        store,
        pinned_public_key=pinned_public_key,
        custody_domain=expected_custody_domain,
        observed_at=unsigned["observed_at"],
    )
    try:
        if _canonical(unsigned) != _canonical(expected):
            raise EventHistoryCheckpointError("checkpoint does not match the current local head")
        signature = base64.urlsafe_b64decode(signature_text + "==")
        if (
            len(signature) != 64
            or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
            != signature_text
        ):
            raise EventHistoryCheckpointError("signature length is invalid")
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(
            signature, event_history_checkpoint_signing_bytes(expected)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise EventHistoryCheckpointError("checkpoint signature or head is invalid") from exc
    return {**expected, "signature_b64url": signature_text}
