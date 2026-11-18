"""Pure, bounded D012 V1 release-head signing-byte reconstruction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime

from .candidate_enrollment_production_custody_contract import (
    LedgerHeadDescriptor,
    ReleaseHeadSigningRequest,
    SignedReleaseHeadDescriptor,
)

SCHEMA_VERSION = 1
SIGNING_DOMAIN = b"SUNDERKEY\x00PRODUCTION-CUSTODY-RELEASE-HEAD\x00D012\x00V1\x00"
SIGNING_ALGORITHM = "Ed25519"
MAX_SIGNING_BYTES = 4096
MAX_LEDGER_SEQUENCE = (1 << 63) - 1

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEAD_FIELDS = (
    "deployment_id",
    "ledger_sequence",
    "entry_id",
    "entry_sha256",
    "previous_head_sha256",
)
_REQUEST_FIELDS = (
    "request_id",
    "head",
    "signer_key_id",
    "offline_root_authorization_sha256",
    "signing_algorithm",
    "requested_at",
)
_SIGNED_FIELDS = (
    "head",
    "signer_key_id",
    "offline_root_authorization_sha256",
    "signing_algorithm",
    "signature",
    "signed_at",
)


class ReleaseHeadSigningProfileError(ValueError):
    """An input is outside the finite, non-authorizing V1 byte profile."""


@dataclass(frozen=True, slots=True)
class _SourceSnapshot:
    storage: dict[str, object]
    head: LedgerHeadDescriptor
    head_storage: dict[str, object]
    values: tuple[object, ...]
    head_values: tuple[object, ...]


def _fields(value: object, family: type, names: tuple[str, ...]) -> dict[str, object]:
    if type(value) is not family:
        raise ReleaseHeadSigningProfileError(f"input must be an exact {family.__name__}")
    try:
        storage = object.__getattribute__(value, "__dict__")
    except AttributeError as exc:
        raise ReleaseHeadSigningProfileError("input has no native field storage") from exc
    if (
        type(storage) is not dict
        or len(storage) != len(names)
        or any(type(key) is not str or key not in names for key in storage)
    ):
        raise ReleaseHeadSigningProfileError("input fields are missing, unknown or non-native")
    return storage


def _text(value: object, label: str, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or not value.isascii():
        raise ReleaseHeadSigningProfileError(f"{label} must be bounded native ASCII text")
    return value


def _identifier(value: object, label: str) -> str:
    text = _text(value, label, 256)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ReleaseHeadSigningProfileError(f"{label} is not a supported identifier")
    return text


def _digest(value: object, label: str) -> str:
    text = _text(value, label, 71)
    if _SHA256.fullmatch(text) is None:
        raise ReleaseHeadSigningProfileError(f"{label} must be a canonical SHA-256 digest")
    return text


def _timestamp(value: object) -> str:
    text = _text(value, "signed_at", 20)
    if _TIMESTAMP.fullmatch(text) is None:
        raise ReleaseHeadSigningProfileError("signed_at must use exact UTC-second spelling")
    try:
        datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ReleaseHeadSigningProfileError("signed_at is not a valid UTC instant") from exc
    return text


def _capture(
    value: object, family: type, names: tuple[str, ...]
) -> tuple[dict[str, object], _SourceSnapshot]:
    storage = _fields(value, family, names)
    values = tuple(storage[name] for name in names)
    head = storage["head"]
    head_storage = _fields(head, LedgerHeadDescriptor, _HEAD_FIELDS)
    head_values = tuple(head_storage[name] for name in _HEAD_FIELDS)
    deployment = _identifier(head_storage["deployment_id"], "deployment_id")
    sequence = head_storage["ledger_sequence"]
    if type(sequence) is not int or not 1 <= sequence <= MAX_LEDGER_SEQUENCE:
        raise ReleaseHeadSigningProfileError("ledger_sequence exceeds the V1 supported subset")
    entry = _identifier(head_storage["entry_id"], "entry_id")
    entry_digest = _digest(head_storage["entry_sha256"], "entry_sha256")
    predecessor = head_storage["previous_head_sha256"]
    if predecessor is not None:
        predecessor = _digest(predecessor, "previous_head_sha256")
    if (sequence == 1) != (predecessor is None):
        raise ReleaseHeadSigningProfileError("head sequence and predecessor are inconsistent")
    owned_head = LedgerHeadDescriptor(deployment, sequence, entry, entry_digest, predecessor)
    signer = _identifier(storage["signer_key_id"], "signer_key_id")
    root = _digest(storage["offline_root_authorization_sha256"], "root authorization")
    algorithm = _text(storage["signing_algorithm"], "signing_algorithm", 7)
    if algorithm != SIGNING_ALGORITHM:
        raise ReleaseHeadSigningProfileError("V1 supports only the Ed25519 signing algorithm")
    time_field = "requested_at" if family is ReleaseHeadSigningRequest else "signed_at"
    signed_at = _timestamp(storage[time_field])
    if family is ReleaseHeadSigningRequest:
        request_id = _identifier(storage["request_id"], "request_id")
        ReleaseHeadSigningRequest(request_id, owned_head, signer, root, algorithm, signed_at)
    else:
        signature = storage["signature"]
        if type(signature) is not bytes or len(signature) != 64:
            raise ReleaseHeadSigningProfileError("signature must be 64 native bytes")
        SignedReleaseHeadDescriptor(owned_head, signer, root, algorithm, signature, signed_at)
    document = {
        "schema_version": SCHEMA_VERSION,
        "head": {
            "deployment_id": deployment,
            "ledger_sequence": sequence,
            "entry_id": entry,
            "entry_sha256": entry_digest,
            "previous_head_sha256": predecessor,
        },
        "signer_key_id": signer,
        "offline_root_authorization_sha256": root,
        "signing_algorithm": algorithm,
        "signed_at": signed_at,
    }
    return document, _SourceSnapshot(storage, head, head_storage, values, head_values)


def _signing_bytes(value: object, family: type, names: tuple[str, ...]) -> bytes:
    document, original = _capture(value, family, names)
    encoded = json.dumps(
        document, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    if (
        type(encoded) is not str
        or len(SIGNING_DOMAIN) + len(encoded) > MAX_SIGNING_BYTES
        or not encoded.isascii()
    ):
        raise ReleaseHeadSigningProfileError("canonical bytes exceed the V1 supported profile")
    current_document, current = _capture(value, family, names)
    if (
        current.storage is not original.storage
        or current.head is not original.head
        or current.head_storage is not original.head_storage
        or current.values != original.values
        or current.head_values != original.head_values
        or current_document != document
    ):
        raise ReleaseHeadSigningProfileError("source changed during byte construction")
    return SIGNING_DOMAIN + encoded.encode("ascii")


def release_head_signing_bytes(request: ReleaseHeadSigningRequest) -> bytes:
    """Project a native request to V1 bytes without signing or granting authority."""
    return _signing_bytes(request, ReleaseHeadSigningRequest, _REQUEST_FIELDS)


def signed_release_head_signing_bytes(signed_head: SignedReleaseHeadDescriptor) -> bytes:
    """Reconstruct V1 bytes; a 64-byte signature shape is not signature verification."""
    return _signing_bytes(signed_head, SignedReleaseHeadDescriptor, _SIGNED_FIELDS)


__all__ = [
    "MAX_LEDGER_SEQUENCE",
    "MAX_SIGNING_BYTES",
    "SCHEMA_VERSION",
    "SIGNING_ALGORITHM",
    "SIGNING_DOMAIN",
    "ReleaseHeadSigningProfileError",
    "release_head_signing_bytes",
    "signed_release_head_signing_bytes",
]
