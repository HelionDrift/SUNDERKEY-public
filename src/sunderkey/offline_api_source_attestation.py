"""Local signature and time-window rehearsal for receipt-sourced API lineage."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .offline_api_source_ledger import (
    OfflineApiSourceLedgerError,
    verify_offline_api_source_ledger,
)

ATTESTATION_DOMAIN = "sunderkey.offline-api-source-attestation.v1"
FRESHNESS_DOMAIN = "sunderkey.offline-api-source-freshness-rehearsal.v1"
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authority": "none",
    "network": "none",
    "positive_use": "none",
    "qualification": "none",
    "source_authentication": "caller_provided_key_only",
    "target_execution": "none",
}
BODY_FIELDS = {
    "schema_version",
    "ledger_id",
    "ledger_sha256",
    "mission_id",
    "scope_id",
    "source_scope_sha256",
    "producer_id",
    "key_id",
    "issued_at",
    "expires_at",
    "custody_assurance",
    "positive_use_approved",
    "effects",
}


class OfflineApiSourceAttestationError(ValueError):
    """Raised when synthetic source custody or local freshness is invalid."""


@dataclass(frozen=True, slots=True)
class OfflineSourceKeyBinding:
    key_id: str
    producer_id: str
    public_key: Ed25519PublicKey

    def __post_init__(self) -> None:
        _binding(self)


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise OfflineApiSourceAttestationError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if (
        type(value) is not str
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None
    ):
        raise OfflineApiSourceAttestationError(f"{label} is invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise OfflineApiSourceAttestationError(f"{label} is invalid") from exc


def _native_keys(value: Any) -> bool:
    return isinstance(value, Mapping) and all(type(key) is str for key in value)


def _binding(value: Any) -> tuple[str, str, Ed25519PublicKey]:
    if type(value) is not OfflineSourceKeyBinding:
        raise OfflineApiSourceAttestationError("source key binding is invalid")
    key_id, producer_id, public_key = value.key_id, value.producer_id, value.public_key
    _identifier(key_id, "key_id")
    _identifier(producer_id, "producer_id")
    if not isinstance(public_key, Ed25519PublicKey):
        raise OfflineApiSourceAttestationError("Ed25519 public key is required")
    return key_id, producer_id, public_key


def _window(issued_at: Any, expires_at: Any) -> None:
    issued = _timestamp(issued_at, "issued_at")
    expires = _timestamp(expires_at, "expires_at")
    if not issued < expires <= issued + timedelta(hours=24):
        raise OfflineApiSourceAttestationError("source attestation window is invalid")


def _ledger(value: Mapping[str, Any]) -> dict[str, Any]:
    if not _native_keys(value) or any(
        type(value.get(field)) is not str
        for field in ("source_mode", "ledger_id", "ledger_sha256", "mission_id", "scope_id")
    ):
        raise OfflineApiSourceAttestationError("source ledger context is invalid")
    if (
        value["source_mode"] == "receipt_sourced"
        and type(value.get("source_scope_sha256")) is not str
    ):
        raise OfflineApiSourceAttestationError("source ledger context is invalid")
    try:
        checked = verify_offline_api_source_ledger(value)
    except OfflineApiSourceLedgerError as exc:
        raise OfflineApiSourceAttestationError("source ledger is invalid") from exc
    if checked["source_mode"] != "receipt_sourced":
        raise OfflineApiSourceAttestationError("receipt-sourced ledger is required")
    return checked


def sign_offline_api_source_attestation(
    *,
    ledger: Mapping[str, Any],
    producer_id: str,
    key_id: str,
    issued_at: str,
    expires_at: str,
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Sign a local ledger digest, not the underlying receipt producer identity."""

    checked = _ledger(ledger)
    _identifier(producer_id, "producer_id")
    _identifier(key_id, "key_id")
    _window(issued_at, expires_at)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise OfflineApiSourceAttestationError("Ed25519 private key is required")
    body = {
        "schema_version": 1,
        "ledger_id": checked["ledger_id"],
        "ledger_sha256": checked["ledger_sha256"],
        "mission_id": checked["mission_id"],
        "scope_id": checked["scope_id"],
        "source_scope_sha256": checked["source_scope_sha256"],
        "producer_id": producer_id,
        "key_id": key_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "custody_assurance": "local_signature_only",
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    signature = private_key.sign(
        _canonical({"domain": ATTESTATION_DOMAIN, "body": body}).encode("ascii")
    )
    signed = {**body, "signature_base64": base64.b64encode(signature).decode("ascii")}
    return {
        **signed,
        "attestation_sha256": _digest({"domain": ATTESTATION_DOMAIN, "signed": signed}),
    }


def verify_offline_api_source_attestation_historical(
    *,
    document: Mapping[str, Any],
    ledger: Mapping[str, Any],
    key_binding: OfflineSourceKeyBinding,
) -> dict[str, Any]:
    """Verify immutable local signature and ledger identity after expiry too."""

    checked = _ledger(ledger)
    key_id, producer_id, public_key = _binding(key_binding)
    if not _native_keys(document):
        raise OfflineApiSourceAttestationError("attestation inputs are invalid")
    if set(document) != BODY_FIELDS | {"signature_base64", "attestation_sha256"}:
        raise OfflineApiSourceAttestationError("attestation fields are invalid")
    try:
        value = dict(document)
        if any(
            type(value[field]) is not str
            for field in BODY_FIELDS - {"schema_version", "positive_use_approved", "effects"}
        ):
            raise OfflineApiSourceAttestationError("attestation context strings are invalid")
        if (
            type(value["effects"]) is not dict
            or not _native_keys(value["effects"])
            or set(value["effects"]) != set(NO_EFFECTS)
            or any(type(item) is not str for item in value["effects"].values())
        ):
            raise OfflineApiSourceAttestationError("attestation effects are invalid")
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["custody_assurance"] != "local_signature_only"
            or value["positive_use_approved"] is not False
            or value["effects"] != NO_EFFECTS
            or value["ledger_id"] != checked["ledger_id"]
            or value["ledger_sha256"] != checked["ledger_sha256"]
            or value["mission_id"] != checked["mission_id"]
            or value["scope_id"] != checked["scope_id"]
            or value["source_scope_sha256"] != checked["source_scope_sha256"]
            or value["producer_id"] != producer_id
            or value["key_id"] != key_id
        ):
            raise OfflineApiSourceAttestationError("attestation context differs")
        _window(value["issued_at"], value["expires_at"])
        if (
            type(value["source_scope_sha256"]) is not str
            or SHA256_RE.fullmatch(value["source_scope_sha256"]) is None
        ):
            raise OfflineApiSourceAttestationError("source scope digest is invalid")
        if (
            type(value["signature_base64"]) is not str
            or len(value["signature_base64"]) != 88
            or type(value["attestation_sha256"]) is not str
            or SHA256_RE.fullmatch(value["attestation_sha256"]) is None
        ):
            raise OfflineApiSourceAttestationError("attestation signature fields are invalid")
        signed = {key: item for key, item in value.items() if key != "attestation_sha256"}
        if value["attestation_sha256"] != _digest({"domain": ATTESTATION_DOMAIN, "signed": signed}):
            raise OfflineApiSourceAttestationError("attestation content identity is invalid")
        signature = base64.b64decode(value["signature_base64"], validate=True)
        if len(signature) != 64:
            raise OfflineApiSourceAttestationError("attestation signature length is invalid")
        body = {key: value[key] for key in BODY_FIELDS}
        public_key.verify(
            signature,
            _canonical({"domain": ATTESTATION_DOMAIN, "body": body}).encode("ascii"),
        )
        return json.loads(_canonical(value))
    except (
        InvalidSignature,
        binascii.Error,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        if isinstance(exc, OfflineApiSourceAttestationError):
            raise
        raise OfflineApiSourceAttestationError(
            "attestation signature or binding is invalid"
        ) from exc


def rehearse_offline_api_source_freshness(
    *,
    document: Mapping[str, Any],
    ledger: Mapping[str, Any],
    key_binding: OfflineSourceKeyBinding,
    as_of: str,
    expected_mission_id: str,
    expected_scope_id: str,
    expected_scope_sha256: str,
) -> dict[str, Any]:
    """Check a local time window without claiming live source currentness."""

    checked = verify_offline_api_source_attestation_historical(
        document=document, ledger=ledger, key_binding=key_binding
    )
    now = _timestamp(as_of, "as_of")
    _identifier(expected_mission_id, "expected_mission_id")
    _identifier(expected_scope_id, "expected_scope_id")
    if type(expected_scope_sha256) is not str or SHA256_RE.fullmatch(expected_scope_sha256) is None:
        raise OfflineApiSourceAttestationError("expected_scope_sha256 is invalid")
    if (
        checked["mission_id"] != expected_mission_id
        or checked["scope_id"] != expected_scope_id
        or checked["source_scope_sha256"] != expected_scope_sha256
        or not _timestamp(checked["issued_at"], "issued_at")
        <= now
        < _timestamp(checked["expires_at"], "expires_at")
    ):
        raise OfflineApiSourceAttestationError("source freshness rehearsal is invalid")
    body = {
        "schema_version": 1,
        "attestation_sha256": checked["attestation_sha256"],
        "ledger_sha256": checked["ledger_sha256"],
        "as_of": as_of,
        "mission_id": expected_mission_id,
        "scope_id": expected_scope_id,
        "source_scope_sha256": expected_scope_sha256,
        "freshness_status": "within_local_signed_window_only",
        "live_currentness_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "rehearsal_sha256": _digest({"domain": FRESHNESS_DOMAIN, "body": body}),
    }


__all__ = [
    "OfflineApiSourceAttestationError",
    "OfflineSourceKeyBinding",
    "rehearse_offline_api_source_freshness",
    "sign_offline_api_source_attestation",
    "verify_offline_api_source_attestation_historical",
]
