"""Offline, non-authorizing D012 release-head Ed25519 verification preview."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .candidate_enrollment_production_custody_contract import (
    LedgerHeadDescriptor,
    SignedReleaseHeadDescriptor,
    provider_subject_sha256,
)
from .release_head_signing_profile import (
    MAX_LEDGER_SEQUENCE,
    ReleaseHeadSigningProfileError,
    signed_release_head_signing_bytes,
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_HEAD_FIELDS = (
    "deployment_id",
    "ledger_sequence",
    "entry_id",
    "entry_sha256",
    "previous_head_sha256",
)
_SIGNED_FIELDS = (
    "head",
    "signer_key_id",
    "offline_root_authorization_sha256",
    "signing_algorithm",
    "signature",
    "signed_at",
)


class ReleaseHeadVerificationError(ValueError):
    """The offline preview cannot verify the supplied signature or trust binding."""


def _native_fields(value: object, family: type, names: tuple[str, ...]) -> dict[str, object]:
    if type(value) is not family:
        raise ReleaseHeadVerificationError(f"expected exact {family.__name__}")
    try:
        storage = object.__getattribute__(value, "__dict__")
    except AttributeError as exc:
        raise ReleaseHeadVerificationError("source has no native field storage") from exc
    if (
        type(storage) is not dict
        or len(storage) != len(names)
        or any(type(name) is not str or name not in names for name in storage)
    ):
        raise ReleaseHeadVerificationError("source fields are not native and exact")
    return storage


def _head_copy(value: object) -> tuple[LedgerHeadDescriptor, dict[str, object], tuple[object, ...]]:
    storage = _native_fields(value, LedgerHeadDescriptor, _HEAD_FIELDS)
    values = tuple(storage[name] for name in _HEAD_FIELDS)
    try:
        copy = LedgerHeadDescriptor(*values)
    except (TypeError, ValueError) as exc:
        raise ReleaseHeadVerificationError("trusted head is invalid") from exc
    if (
        type(copy.ledger_sequence) is not int
        or copy.ledger_sequence > MAX_LEDGER_SEQUENCE
        or type(copy.deployment_id) is not str
        or type(copy.entry_id) is not str
        or type(copy.entry_sha256) is not str
        or (copy.previous_head_sha256 is not None and type(copy.previous_head_sha256) is not str)
    ):
        raise ReleaseHeadVerificationError("trusted head is outside the V1 profile")
    return copy, storage, values


@dataclass(frozen=True, slots=True)
class ReleaseHeadTrustAnchor:
    """Caller-asserted public key, root and immediate predecessor context."""

    deployment_id: str
    signer_key_id: str
    public_key_sha256: str
    offline_root_authorization_sha256: str
    previous_head: LedgerHeadDescriptor | None

    def __post_init__(self) -> None:
        for label in ("deployment_id", "signer_key_id"):
            value = object.__getattribute__(self, label)
            if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
                raise ReleaseHeadVerificationError(f"{label} is invalid")
        for label in ("public_key_sha256", "offline_root_authorization_sha256"):
            value = object.__getattribute__(self, label)
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ReleaseHeadVerificationError(f"{label} must be a canonical SHA-256 digest")
        predecessor = object.__getattribute__(self, "previous_head")
        if predecessor is not None:
            copied, _, _ = _head_copy(predecessor)
            if copied.deployment_id != self.deployment_id:
                raise ReleaseHeadVerificationError("trusted predecessor deployment differs")


@dataclass(frozen=True, slots=True)
class OfflineReleaseHeadVerificationPreview:
    """A successful local check, not a production provider receipt."""

    deployment_id: str
    ledger_sequence: int
    head_sha256: str
    signing_input_sha256: str
    signer_key_id: str
    signature_verified: bool = True
    predecessor_verified: bool = True
    rollback_checked: bool = True
    qualification_effect: str = "none"
    authority_effect: str = "none"
    network_call_performed: bool = False
    provider_call_performed: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.deployment_id) is not str
            or _IDENTIFIER.fullmatch(self.deployment_id) is None
            or type(self.signer_key_id) is not str
            or _IDENTIFIER.fullmatch(self.signer_key_id) is None
            or type(self.ledger_sequence) is not int
            or not 1 <= self.ledger_sequence <= MAX_LEDGER_SEQUENCE
            or type(self.head_sha256) is not str
            or _SHA256.fullmatch(self.head_sha256) is None
            or type(self.signing_input_sha256) is not str
            or _SHA256.fullmatch(self.signing_input_sha256) is None
            or self.signature_verified is not True
            or self.predecessor_verified is not True
            or self.rollback_checked is not True
            or self.qualification_effect != "none"
            or self.authority_effect != "none"
            or self.network_call_performed is not False
            or self.provider_call_performed is not False
        ):
            raise ReleaseHeadVerificationError("offline preview fields are invalid")


def _verify_signature(public_key_bytes: bytes, signature: bytes, signing_bytes: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, signing_bytes)
    except (InvalidSignature, ValueError) as exc:
        raise ReleaseHeadVerificationError("Ed25519 signature is invalid") from exc


def verify_release_head_offline(
    signed_head: SignedReleaseHeadDescriptor,
    public_key_bytes: bytes,
    trust_anchor: ReleaseHeadTrustAnchor,
) -> OfflineReleaseHeadVerificationPreview:
    """Check V1 bytes and exact caller-supplied trust anchors without granting authority."""

    if type(trust_anchor) is not ReleaseHeadTrustAnchor:
        raise ReleaseHeadVerificationError("trust anchor must be exact")
    anchor_values = (
        trust_anchor.deployment_id,
        trust_anchor.signer_key_id,
        trust_anchor.public_key_sha256,
        trust_anchor.offline_root_authorization_sha256,
        trust_anchor.previous_head,
    )
    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise ReleaseHeadVerificationError("public key must be 32 native bytes")
    if "sha256:" + hashlib.sha256(public_key_bytes).hexdigest() != trust_anchor.public_key_sha256:
        raise ReleaseHeadVerificationError("public key digest differs from trusted anchor")

    signed_storage = _native_fields(signed_head, SignedReleaseHeadDescriptor, _SIGNED_FIELDS)
    signed_values = tuple(signed_storage[name] for name in _SIGNED_FIELDS)
    source_head = signed_storage["head"]
    head, head_storage, head_values = _head_copy(source_head)
    predecessor_source = trust_anchor.previous_head
    if predecessor_source is None:
        predecessor = None
        predecessor_storage = None
        predecessor_values = None
    else:
        predecessor, predecessor_storage, predecessor_values = _head_copy(predecessor_source)

    try:
        signing_bytes = signed_release_head_signing_bytes(signed_head)
    except ReleaseHeadSigningProfileError as exc:
        raise ReleaseHeadVerificationError("signed head is outside the V1 byte profile") from exc
    if signed_storage["signer_key_id"] != trust_anchor.signer_key_id:
        raise ReleaseHeadVerificationError("signer key ID differs from trusted anchor")
    if (
        signed_storage["offline_root_authorization_sha256"]
        != trust_anchor.offline_root_authorization_sha256
    ):
        raise ReleaseHeadVerificationError("offline root differs from trusted anchor")
    if head.deployment_id != trust_anchor.deployment_id:
        raise ReleaseHeadVerificationError("deployment differs from trusted anchor")
    expected_sequence = 1 if predecessor is None else predecessor.ledger_sequence + 1
    expected_digest = None if predecessor is None else provider_subject_sha256(predecessor)
    if expected_sequence > MAX_LEDGER_SEQUENCE or head.ledger_sequence != expected_sequence:
        raise ReleaseHeadVerificationError("head sequence is stale, skipped or rolled back")
    if head.previous_head_sha256 != expected_digest:
        raise ReleaseHeadVerificationError("head predecessor differs from trusted anchor")

    _verify_signature(public_key_bytes, signed_storage["signature"], signing_bytes)
    verified_head_sha256 = provider_subject_sha256(head)
    verified_signing_input_sha256 = "sha256:" + hashlib.sha256(signing_bytes).hexdigest()
    if (
        _native_fields(signed_head, SignedReleaseHeadDescriptor, _SIGNED_FIELDS)
        is not signed_storage
        or tuple(signed_storage[name] for name in _SIGNED_FIELDS) != signed_values
        or signed_storage["head"] is not source_head
        or _native_fields(source_head, LedgerHeadDescriptor, _HEAD_FIELDS) is not head_storage
        or tuple(head_storage[name] for name in _HEAD_FIELDS) != head_values
        or (
            trust_anchor.deployment_id,
            trust_anchor.signer_key_id,
            trust_anchor.public_key_sha256,
            trust_anchor.offline_root_authorization_sha256,
            trust_anchor.previous_head,
        )
        != anchor_values
        or trust_anchor.previous_head is not predecessor_source
        or (
            predecessor_source is not None
            and (
                _native_fields(predecessor_source, LedgerHeadDescriptor, _HEAD_FIELDS)
                is not predecessor_storage
                or tuple(predecessor_storage[name] for name in _HEAD_FIELDS) != predecessor_values
            )
        )
    ):
        raise ReleaseHeadVerificationError("source changed during offline verification")
    return OfflineReleaseHeadVerificationPreview(
        head.deployment_id,
        head.ledger_sequence,
        verified_head_sha256,
        verified_signing_input_sha256,
        anchor_values[1],
    )


__all__ = [
    "OfflineReleaseHeadVerificationPreview",
    "ReleaseHeadTrustAnchor",
    "ReleaseHeadVerificationError",
    "verify_release_head_offline",
]
