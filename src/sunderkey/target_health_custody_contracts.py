"""Signed, local-only custody contracts for target-health receipts.

The contracts in this module verify already-produced evidence. They perform no
collection, network access, target action, qualification, or execution control.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authorized_target_health_runtime import (
    TargetHealthReceipt,
    parse_target_health_receipt,
)
from .execution_control_runtime import ExecutionBinding, canonical_json

SCHEMA_VERSION = 1
MAX_DOCUMENT_BYTES = 1_048_576
MAX_STRING_BYTES = 32_768
SIGNATURE_ALGORITHM = "Ed25519"
MAX_SEQUENCE = 2**63 - 1

CUSTODY_STORE_APPLICATION_ID = 0x53544843
CUSTODY_STORE_SCHEMA_VERSION = 1
CUSTODY_STORE_MIGRATION_VERSION = 1
CUSTODY_STORE_MIGRATION_ID = "sunderkey.target-health-custody.sqlite.v1"
CUSTODY_STORE_MIGRATION_SHA256 = (
    "sha256:6e63e569b2f5a35050964e81721124540a46b3f04a832ecb2c7adf247ea20335"
)
CUSTODY_STORE_SCHEMA_MANIFEST_SHA256 = (
    "sha256:2c2ed03b3aac3a772e8318cb8ed8077ffde88f27033d8e51abd2cf078fe0fde3"
)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
_RECORD_ID_RE = re.compile(r"[A-Z]{4}-[0-9A-F]{32}\Z")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")

_BINDING_FIELDS = {
    "context_id",
    "context_sha256",
    "fence_epoch",
    "lease_id",
    "scope_id",
    "scope_sha256",
    "session_id",
    "target_id",
    "target_sha256",
    "tenant_id",
}
_NO_EFFECTS = {
    "authority_effect": "none",
    "collection_effect": "none",
    "network_call_performed": False,
    "pause_effect": "none",
    "qualification_effect": "none",
    "resume_effect": "none",
    "target_effect_performed": False,
}
_NO_EFFECT_FIELDS = set(_NO_EFFECTS)
_INSPECTION_EFFECTS = {
    **_NO_EFFECTS,
    "control_effect": "none",
    "reservation_effect": "none",
}
_INSPECTION_EFFECT_FIELDS = set(_INSPECTION_EFFECTS)


class TargetHealthCustodyContractError(ValueError):
    """Raised when a custody record or verification boundary is invalid."""


class TargetHealthVerificationMode(StrEnum):
    """Whether verification proves historical integrity or current usability."""

    HISTORICAL = "historical"
    CURRENT = "current"


def _canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = _canonical_sha256({"body": dict(body), "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise TargetHealthCustodyContractError(f"{label} fields are invalid")
    return value


def _type_or_version_is_invalid(
    value: Mapping[str, Any],
    expected_kind: str,
) -> bool:
    return (
        value["kind"] != expected_kind
        or type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TargetHealthCustodyContractError("document contains a duplicate key")
        result[key] = value
    return result


def _validate_tree(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        raise TargetHealthCustodyContractError("document nesting is too deep")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise TargetHealthCustodyContractError("document strings must be ASCII") from exc
        if len(encoded) > MAX_STRING_BYTES:
            raise TargetHealthCustodyContractError("document string exceeds the size limit")
        if any(ord(character) < 0x20 for character in value):
            raise TargetHealthCustodyContractError("document strings contain control characters")
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise TargetHealthCustodyContractError("floating-point values are forbidden")
    if isinstance(value, list):
        for item in value:
            _validate_tree(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TargetHealthCustodyContractError("document keys must be strings")
            _validate_tree(key, depth=depth + 1)
            _validate_tree(item, depth=depth + 1)
        return
    raise TargetHealthCustodyContractError("document contains an unsupported value")


def _load_document(raw: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, bytes):
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise TargetHealthCustodyContractError("document exceeds the size limit")
        try:
            return _load_document(raw.decode("ascii"))
        except UnicodeDecodeError as exc:
            raise TargetHealthCustodyContractError("document must be ASCII") from exc
    if isinstance(raw, str):
        try:
            encoded = raw.encode("ascii")
        except UnicodeEncodeError as exc:
            raise TargetHealthCustodyContractError("document must be ASCII") from exc
        if len(encoded) > MAX_DOCUMENT_BYTES:
            raise TargetHealthCustodyContractError("document exceeds the size limit")
        try:
            value = json.loads(
                raw,
                object_pairs_hook=_pairs,
                parse_float=lambda _: (_ for _ in ()).throw(
                    TargetHealthCustodyContractError("floating-point values are forbidden")
                ),
                parse_constant=lambda _: (_ for _ in ()).throw(
                    TargetHealthCustodyContractError("non-finite values are forbidden")
                ),
            )
        except TargetHealthCustodyContractError:
            raise
        except json.JSONDecodeError as exc:
            raise TargetHealthCustodyContractError("document JSON is invalid") from exc
        if not isinstance(value, dict):
            raise TargetHealthCustodyContractError("document root must be an object")
        if raw != canonical_json(value):
            raise TargetHealthCustodyContractError("document JSON is not canonical")
    elif isinstance(raw, dict):
        value = raw
        _validate_tree(value)
        if len(canonical_json(value).encode("ascii")) > MAX_DOCUMENT_BYTES:
            raise TargetHealthCustodyContractError("document exceeds the size limit")
    else:
        raise TargetHealthCustodyContractError("document input is invalid")
    _validate_tree(value)
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise TargetHealthCustodyContractError(f"{label} is invalid")
    _validate_tree(value)
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise TargetHealthCustodyContractError(f"{label} is invalid")
    return value


def _record_id(value: Any, prefix: str, label: str) -> str:
    if not isinstance(value, str) or _RECORD_ID_RE.fullmatch(value) is None:
        raise TargetHealthCustodyContractError(f"{label} is invalid")
    if not value.startswith(prefix + "-"):
        raise TargetHealthCustodyContractError(f"{label} has the wrong prefix")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise TargetHealthCustodyContractError(f"{label} must be a sha256 digest")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int = MAX_SEQUENCE) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise TargetHealthCustodyContractError(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise TargetHealthCustodyContractError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise TargetHealthCustodyContractError(f"{label} must be canonical UTC") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise TargetHealthCustodyContractError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _decode_base64url(value: Any, length: int, label: str) -> bytes:
    if not isinstance(value, str) or _BASE64URL_RE.fullmatch(value) is None or "=" in value:
        raise TargetHealthCustodyContractError(f"{label} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise TargetHealthCustodyContractError(f"{label} must be unpadded base64url") from exc
    if len(decoded) != length or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise TargetHealthCustodyContractError(f"{label} has an invalid length or encoding")
    return decoded


def _public_key(value: Any, fingerprint: Any, label: str) -> bytes:
    raw = _decode_base64url(value, 32, label)
    expected = "sha256:" + hashlib.sha256(raw).hexdigest()
    _digest(fingerprint, f"{label}_sha256")
    if not hmac.compare_digest(expected, fingerprint):
        raise TargetHealthCustodyContractError(f"{label} fingerprint does not match")
    return raw


def _signature(value: Any, label: str) -> bytes:
    return _decode_base64url(value, 64, label)


def _binding_from_dict(value: Any) -> ExecutionBinding:
    try:
        return ExecutionBinding(**_exact(value, _BINDING_FIELDS, "execution binding"))
    except TargetHealthCustodyContractError:
        raise
    except ValueError as exc:
        raise TargetHealthCustodyContractError("execution binding is invalid") from exc


def _receipt_from_dict(value: Any) -> TargetHealthReceipt:
    try:
        return parse_target_health_receipt(value)
    except ValueError as exc:
        raise TargetHealthCustodyContractError("target-health receipt is invalid") from exc


def execution_binding_sha256(binding: ExecutionBinding) -> str:
    """Return the exact digest of the complete execution binding."""

    if not isinstance(binding, ExecutionBinding):
        raise TargetHealthCustodyContractError("execution binding is invalid")
    return _canonical_sha256(binding.to_dict())


def target_health_chain_id(
    collector_id: str,
    mission_id: str,
    binding_sha256: str,
) -> str:
    """Derive a mission-separated chain from collector and exact binding digest."""

    _identifier(collector_id, "collector_id")
    _identifier(mission_id, "mission_id")
    _digest(binding_sha256, "binding_sha256")
    digest = _canonical_sha256(
        {
            "binding_sha256": binding_sha256,
            "collector_id": collector_id,
            "domain": "sunderkey.target-health-custody-chain.v2",
            "mission_id": mission_id,
        }
    )
    return "THCH-" + digest[7:39].upper()


def _check_effects(value: Mapping[str, Any]) -> None:
    if any(
        (value.get(key) is not expected)
        if isinstance(expected, bool)
        else (value.get(key) != expected)
        for key, expected in _NO_EFFECTS.items()
    ):
        raise TargetHealthCustodyContractError("record effects are invalid")


def _check_inspection_effects(value: Mapping[str, Any]) -> None:
    if any(
        (value.get(key) is not expected)
        if isinstance(expected, bool)
        else (value.get(key) != expected)
        for key, expected in _INSPECTION_EFFECTS.items()
    ):
        raise TargetHealthCustodyContractError("inspection effects are invalid")


def _verify_signature(public_key: str, signature: str, payload: bytes, label: str) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(_decode_base64url(public_key, 32, label)).verify(
            _signature(signature, f"{label} signature"), payload
        )
    except InvalidSignature as exc:
        raise TargetHealthCustodyContractError(f"{label} signature is invalid") from exc


@dataclass(frozen=True, slots=True)
class TargetHealthTrustRoot:
    """Pinned tenant and mission trust root for collector policy verification."""

    tenant_id: str
    mission_id: str
    trust_root_revision: int
    root_key_id: str
    root_public_key: str
    root_public_key_sha256: str
    deployment_attestation_id: str
    deployment_attestation_sha256: str
    effective_at: str
    expires_at: str
    trust_root_id: str = ""
    trust_root_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-trust-root.v2"
    PREFIX: ClassVar[str] = "THRT"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _integer(self.trust_root_revision, "trust_root_revision", 1)
        _identifier(self.root_key_id, "root_key_id")
        _public_key(self.root_public_key, self.root_public_key_sha256, "root_public_key")
        _identifier(self.deployment_attestation_id, "deployment_attestation_id")
        _digest(self.deployment_attestation_sha256, "deployment_attestation_sha256")
        _utc(self.effective_at, "effective_at")
        _utc(self.expires_at, "expires_at")
        if _instant(self.effective_at) >= _instant(self.expires_at):
            raise TargetHealthCustodyContractError("trust root validity window is invalid")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.trust_root_id and not hmac.compare_digest(self.trust_root_id, identifier):
            raise TargetHealthCustodyContractError("trust_root_id does not match content")
        if self.trust_root_sha256 and not hmac.compare_digest(self.trust_root_sha256, digest):
            raise TargetHealthCustodyContractError("trust_root_sha256 does not match content")
        object.__setattr__(self, "trust_root_id", identifier)
        object.__setattr__(self, "trust_root_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "deployment_attestation_id": self.deployment_attestation_id,
            "deployment_attestation_sha256": self.deployment_attestation_sha256,
            "effective_at": self.effective_at,
            "expires_at": self.expires_at,
            "mission_id": self.mission_id,
            "root_key_id": self.root_key_id,
            "root_public_key": self.root_public_key,
            "root_public_key_sha256": self.root_public_key_sha256,
            "tenant_id": self.tenant_id,
            "trust_root_revision": self.trust_root_revision,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "trust_root_id": self.trust_root_id,
            "trust_root_sha256": self.trust_root_sha256,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthTrustRoot:
        fields = {
            "deployment_attestation_id",
            "deployment_attestation_sha256",
            "effective_at",
            "expires_at",
            "kind",
            "mission_id",
            "root_key_id",
            "root_public_key",
            "root_public_key_sha256",
            "schema_version",
            "tenant_id",
            "trust_root_id",
            "trust_root_revision",
            "trust_root_sha256",
            *_NO_EFFECT_FIELDS,
        }
        data = _exact(value, fields, "trust root")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError("trust root type or version is invalid")
        _check_effects(data)
        return cls(
            tenant_id=data["tenant_id"],
            mission_id=data["mission_id"],
            trust_root_revision=data["trust_root_revision"],
            root_key_id=data["root_key_id"],
            root_public_key=data["root_public_key"],
            root_public_key_sha256=data["root_public_key_sha256"],
            deployment_attestation_id=data["deployment_attestation_id"],
            deployment_attestation_sha256=data["deployment_attestation_sha256"],
            effective_at=data["effective_at"],
            expires_at=data["expires_at"],
            trust_root_id=data["trust_root_id"],
            trust_root_sha256=data["trust_root_sha256"],
        )


_POLICY_UNSIGNED_FIELDS = {
    "binding",
    "binding_sha256",
    "chain_id",
    "collector_epoch",
    "collector_id",
    "collector_key_id",
    "collector_public_key",
    "collector_public_key_sha256",
    "deployment_attestation_id",
    "deployment_attestation_sha256",
    "effective_at",
    "expires_at",
    "issued_at",
    "maximum_future_skew_seconds",
    "maximum_observation_age_seconds",
    "mission_id",
    "policy_revision",
    "policy_status",
    "predecessor_policy_id",
    "predecessor_policy_sha256",
    "prior_epoch_head_envelope_id",
    "prior_epoch_head_envelope_sha256",
    "revoked",
    "runtime_policy_id",
    "runtime_policy_sha256",
    "signature_algorithm",
    "tenant_id",
    "trust_root_id",
    "trust_root_revision",
    "trust_root_sha256",
    *_NO_EFFECT_FIELDS,
}


@dataclass(frozen=True, slots=True)
class TargetHealthCollectorPolicyRevision:
    """Root-signed immutable authorization for one collector epoch and binding."""

    tenant_id: str
    mission_id: str
    trust_root_id: str
    trust_root_sha256: str
    trust_root_revision: int
    binding: ExecutionBinding
    binding_sha256: str
    runtime_policy_id: str
    runtime_policy_sha256: str
    collector_id: str
    collector_epoch: int
    chain_id: str
    collector_key_id: str
    collector_public_key: str
    collector_public_key_sha256: str
    deployment_attestation_id: str
    deployment_attestation_sha256: str
    policy_revision: int
    predecessor_policy_id: str | None
    predecessor_policy_sha256: str | None
    prior_epoch_head_envelope_id: str | None
    prior_epoch_head_envelope_sha256: str | None
    issued_at: str
    effective_at: str
    expires_at: str
    maximum_observation_age_seconds: int
    maximum_future_skew_seconds: int
    root_signature: str
    policy_status: str = "active"
    revoked: bool = False
    signature_algorithm: str = SIGNATURE_ALGORITHM
    policy_id: str = ""
    policy_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-collector-policy-revision.v2"
    PREFIX: ClassVar[str] = "THCP"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _record_id(self.trust_root_id, "THRT", "trust_root_id")
        _digest(self.trust_root_sha256, "trust_root_sha256")
        _integer(self.trust_root_revision, "trust_root_revision", 1)
        if not isinstance(self.binding, ExecutionBinding):
            raise TargetHealthCustodyContractError("binding is invalid")
        if self.binding.tenant_id != self.tenant_id:
            raise TargetHealthCustodyContractError("policy tenant does not match binding")
        expected_binding = execution_binding_sha256(self.binding)
        if not hmac.compare_digest(self.binding_sha256, expected_binding):
            raise TargetHealthCustodyContractError("binding_sha256 does not match binding")
        _identifier(self.runtime_policy_id, "runtime_policy_id")
        _digest(self.runtime_policy_sha256, "runtime_policy_sha256")
        _identifier(self.collector_id, "collector_id")
        _integer(self.collector_epoch, "collector_epoch", 1)
        if self.chain_id != target_health_chain_id(
            self.collector_id, self.mission_id, self.binding_sha256
        ):
            raise TargetHealthCustodyContractError("chain_id is not deterministic")
        _identifier(self.collector_key_id, "collector_key_id")
        _public_key(
            self.collector_public_key,
            self.collector_public_key_sha256,
            "collector_public_key",
        )
        _identifier(self.deployment_attestation_id, "deployment_attestation_id")
        _digest(self.deployment_attestation_sha256, "deployment_attestation_sha256")
        _integer(self.policy_revision, "policy_revision", 1)
        if self.policy_revision == 1:
            if self.predecessor_policy_id is not None or self.predecessor_policy_sha256 is not None:
                raise TargetHealthCustodyContractError("first policy revision has a predecessor")
        else:
            _record_id(self.predecessor_policy_id, self.PREFIX, "predecessor_policy_id")
            _digest(self.predecessor_policy_sha256, "predecessor_policy_sha256")
        if self.collector_epoch == 1:
            if (
                self.prior_epoch_head_envelope_id is not None
                or self.prior_epoch_head_envelope_sha256 is not None
            ):
                raise TargetHealthCustodyContractError("first collector epoch has a prior head")
        else:
            _record_id(
                self.prior_epoch_head_envelope_id,
                "THCE",
                "prior_epoch_head_envelope_id",
            )
            _digest(
                self.prior_epoch_head_envelope_sha256,
                "prior_epoch_head_envelope_sha256",
            )
        _utc(self.issued_at, "issued_at")
        _utc(self.effective_at, "effective_at")
        _utc(self.expires_at, "expires_at")
        if not (
            _instant(self.issued_at) <= _instant(self.effective_at) < _instant(self.expires_at)
        ):
            raise TargetHealthCustodyContractError("policy time window is invalid")
        _integer(
            self.maximum_observation_age_seconds,
            "maximum_observation_age_seconds",
            1,
            86_400,
        )
        _integer(
            self.maximum_future_skew_seconds,
            "maximum_future_skew_seconds",
            0,
            300,
        )
        if self.policy_status != "active" or self.revoked is not False:
            raise TargetHealthCustodyContractError("collector policy must be active and unrevoked")
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise TargetHealthCustodyContractError("collector policy requires Ed25519")
        _signature(self.root_signature, "root_signature")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.policy_id and not hmac.compare_digest(self.policy_id, identifier):
            raise TargetHealthCustodyContractError("policy_id does not match content")
        if self.policy_sha256 and not hmac.compare_digest(self.policy_sha256, digest):
            raise TargetHealthCustodyContractError("policy_sha256 does not match content")
        object.__setattr__(self, "policy_id", identifier)
        object.__setattr__(self, "policy_sha256", digest)

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": self.chain_id,
            "collector_epoch": self.collector_epoch,
            "collector_id": self.collector_id,
            "collector_key_id": self.collector_key_id,
            "collector_public_key": self.collector_public_key,
            "collector_public_key_sha256": self.collector_public_key_sha256,
            "deployment_attestation_id": self.deployment_attestation_id,
            "deployment_attestation_sha256": self.deployment_attestation_sha256,
            "effective_at": self.effective_at,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "maximum_future_skew_seconds": self.maximum_future_skew_seconds,
            "maximum_observation_age_seconds": self.maximum_observation_age_seconds,
            "mission_id": self.mission_id,
            "policy_revision": self.policy_revision,
            "policy_status": self.policy_status,
            "predecessor_policy_id": self.predecessor_policy_id,
            "predecessor_policy_sha256": self.predecessor_policy_sha256,
            "prior_epoch_head_envelope_id": self.prior_epoch_head_envelope_id,
            "prior_epoch_head_envelope_sha256": self.prior_epoch_head_envelope_sha256,
            "revoked": self.revoked,
            "runtime_policy_id": self.runtime_policy_id,
            "runtime_policy_sha256": self.runtime_policy_sha256,
            "signature_algorithm": self.signature_algorithm,
            "tenant_id": self.tenant_id,
            "trust_root_id": self.trust_root_id,
            "trust_root_revision": self.trust_root_revision,
            "trust_root_sha256": self.trust_root_sha256,
            **_NO_EFFECTS,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json(
            {
                "domain": "sunderkey.target-health-collector-policy-signature.v2",
                "policy": self.unsigned_body(),
            }
        ).encode("ascii")

    @classmethod
    def signing_bytes_for(cls, unsigned_fields: dict[str, Any]) -> bytes:
        data = _exact(unsigned_fields, _POLICY_UNSIGNED_FIELDS, "policy signing fields")
        placeholder = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
        candidate = cls(
            **{
                key: value
                for key, value in data.items()
                if key not in _NO_EFFECT_FIELDS | {"binding"}
            },
            binding=_binding_from_dict(data["binding"]),
            root_signature=placeholder,
        )
        _check_effects(data)
        return candidate.signing_bytes()

    def body(self) -> dict[str, Any]:
        return {**self.unsigned_body(), "root_signature": self.root_signature}

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthCollectorPolicyRevision:
        fields = _POLICY_UNSIGNED_FIELDS | {
            "kind",
            "policy_id",
            "policy_sha256",
            "root_signature",
            "schema_version",
        }
        data = _exact(value, fields, "collector policy")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError("collector policy type or version is invalid")
        _check_effects(data)
        return cls(
            **{
                key: item
                for key, item in data.items()
                if key
                not in _NO_EFFECT_FIELDS
                | {"binding", "kind", "schema_version"}
            },
            binding=_binding_from_dict(data["binding"]),
        )


_REVOCATION_UNSIGNED_FIELDS = {
    "binding",
    "binding_sha256",
    "chain_id",
    "collector_epoch",
    "collector_id",
    "mission_id",
    "policy_id",
    "policy_revision",
    "policy_sha256",
    "revocation_reason",
    "revoked",
    "revoked_at",
    "signature_algorithm",
    "tenant_id",
    "terminal",
    "trust_root_id",
    "trust_root_revision",
    "trust_root_sha256",
    *_NO_EFFECT_FIELDS,
}


@dataclass(frozen=True, slots=True)
class TargetHealthCollectorPolicyRevocation:
    """Root-signed terminal revocation of one exact collector policy revision."""

    tenant_id: str
    mission_id: str
    trust_root_id: str
    trust_root_sha256: str
    trust_root_revision: int
    policy_id: str
    policy_sha256: str
    policy_revision: int
    binding: ExecutionBinding
    binding_sha256: str
    collector_id: str
    collector_epoch: int
    chain_id: str
    revoked_at: str
    revocation_reason: str
    root_signature: str
    revoked: bool = True
    terminal: bool = True
    signature_algorithm: str = SIGNATURE_ALGORITHM
    revocation_id: str = ""
    revocation_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-collector-policy-revocation.v2"
    PREFIX: ClassVar[str] = "THRV"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _record_id(self.trust_root_id, "THRT", "trust_root_id")
        _digest(self.trust_root_sha256, "trust_root_sha256")
        _integer(self.trust_root_revision, "trust_root_revision", 1)
        _record_id(self.policy_id, "THCP", "policy_id")
        _digest(self.policy_sha256, "policy_sha256")
        _integer(self.policy_revision, "policy_revision", 1)
        if not isinstance(self.binding, ExecutionBinding):
            raise TargetHealthCustodyContractError("revocation binding is invalid")
        if self.binding.tenant_id != self.tenant_id or not hmac.compare_digest(
            self.binding_sha256, execution_binding_sha256(self.binding)
        ):
            raise TargetHealthCustodyContractError("revocation binding does not match")
        _identifier(self.collector_id, "collector_id")
        _integer(self.collector_epoch, "collector_epoch", 1)
        if self.chain_id != target_health_chain_id(
            self.collector_id, self.mission_id, self.binding_sha256
        ):
            raise TargetHealthCustodyContractError("revocation chain_id is invalid")
        _utc(self.revoked_at, "revoked_at")
        _identifier(self.revocation_reason, "revocation_reason")
        if self.revoked is not True or self.terminal is not True:
            raise TargetHealthCustodyContractError("policy revocation must be terminal")
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise TargetHealthCustodyContractError("policy revocation requires Ed25519")
        _signature(self.root_signature, "root_signature")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.revocation_id and not hmac.compare_digest(self.revocation_id, identifier):
            raise TargetHealthCustodyContractError("revocation_id does not match content")
        if self.revocation_sha256 and not hmac.compare_digest(
            self.revocation_sha256, digest
        ):
            raise TargetHealthCustodyContractError("revocation_sha256 does not match content")
        object.__setattr__(self, "revocation_id", identifier)
        object.__setattr__(self, "revocation_sha256", digest)

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": self.chain_id,
            "collector_epoch": self.collector_epoch,
            "collector_id": self.collector_id,
            "mission_id": self.mission_id,
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "policy_sha256": self.policy_sha256,
            "revocation_reason": self.revocation_reason,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
            "signature_algorithm": self.signature_algorithm,
            "tenant_id": self.tenant_id,
            "terminal": self.terminal,
            "trust_root_id": self.trust_root_id,
            "trust_root_revision": self.trust_root_revision,
            "trust_root_sha256": self.trust_root_sha256,
            **_NO_EFFECTS,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json(
            {
                "domain": "sunderkey.target-health-policy-revocation-signature.v2",
                "revocation": self.unsigned_body(),
            }
        ).encode("ascii")

    @classmethod
    def signing_bytes_for(cls, unsigned_fields: dict[str, Any]) -> bytes:
        data = _exact(
            unsigned_fields,
            _REVOCATION_UNSIGNED_FIELDS,
            "policy revocation signing fields",
        )
        _check_effects(data)
        placeholder = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
        candidate = cls(
            **{
                key: item
                for key, item in data.items()
                if key not in _NO_EFFECT_FIELDS | {"binding"}
            },
            binding=_binding_from_dict(data["binding"]),
            root_signature=placeholder,
        )
        return candidate.signing_bytes()

    def body(self) -> dict[str, Any]:
        return {**self.unsigned_body(), "root_signature": self.root_signature}

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "revocation_id": self.revocation_id,
            "revocation_sha256": self.revocation_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthCollectorPolicyRevocation:
        fields = _REVOCATION_UNSIGNED_FIELDS | {
            "kind",
            "revocation_id",
            "revocation_sha256",
            "root_signature",
            "schema_version",
        }
        data = _exact(value, fields, "collector policy revocation")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError(
                "collector policy revocation type or version is invalid"
            )
        _check_effects(data)
        return cls(
            **{
                key: item
                for key, item in data.items()
                if key
                not in _NO_EFFECT_FIELDS
                | {"binding", "kind", "schema_version"}
            },
            binding=_binding_from_dict(data["binding"]),
        )


_ENVELOPE_UNSIGNED_FIELDS = {
    "binding",
    "binding_sha256",
    "chain_id",
    "collector_epoch",
    "collector_id",
    "collector_key_id",
    "collector_public_key",
    "collector_public_key_sha256",
    "deployment_attestation_id",
    "deployment_attestation_sha256",
    "mission_id",
    "observed_at",
    "policy_id",
    "policy_revision",
    "policy_sha256",
    "predecessor_envelope_id",
    "predecessor_envelope_sha256",
    "receipt",
    "receipt_id",
    "receipt_sha256",
    "runtime_policy_id",
    "runtime_policy_sha256",
    "sequence",
    "signature_algorithm",
    "tenant_id",
    *_NO_EFFECT_FIELDS,
}


@dataclass(frozen=True, slots=True)
class SignedTargetHealthCustodyEnvelopeV2:
    """Collector-signed envelope over one exact target-health receipt."""

    tenant_id: str
    mission_id: str
    binding: ExecutionBinding
    binding_sha256: str
    runtime_policy_id: str
    runtime_policy_sha256: str
    policy_id: str
    policy_sha256: str
    policy_revision: int
    collector_id: str
    collector_epoch: int
    chain_id: str
    collector_key_id: str
    collector_public_key: str
    collector_public_key_sha256: str
    deployment_attestation_id: str
    deployment_attestation_sha256: str
    sequence: int
    predecessor_envelope_id: str | None
    predecessor_envelope_sha256: str | None
    receipt: TargetHealthReceipt
    receipt_id: str
    receipt_sha256: str
    observed_at: str
    collector_signature: str
    signature_algorithm: str = SIGNATURE_ALGORITHM
    envelope_id: str = ""
    envelope_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.signed-target-health-custody-envelope.v2"
    PREFIX: ClassVar[str] = "THCE"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        if not isinstance(self.binding, ExecutionBinding):
            raise TargetHealthCustodyContractError("binding is invalid")
        if self.binding.tenant_id != self.tenant_id:
            raise TargetHealthCustodyContractError("envelope tenant does not match binding")
        if not hmac.compare_digest(self.binding_sha256, execution_binding_sha256(self.binding)):
            raise TargetHealthCustodyContractError("binding_sha256 does not match binding")
        _identifier(self.runtime_policy_id, "runtime_policy_id")
        _digest(self.runtime_policy_sha256, "runtime_policy_sha256")
        _record_id(self.policy_id, "THCP", "policy_id")
        _digest(self.policy_sha256, "policy_sha256")
        _integer(self.policy_revision, "policy_revision", 1)
        _identifier(self.collector_id, "collector_id")
        _integer(self.collector_epoch, "collector_epoch", 1)
        if self.chain_id != target_health_chain_id(
            self.collector_id, self.mission_id, self.binding_sha256
        ):
            raise TargetHealthCustodyContractError("chain_id is not deterministic")
        _identifier(self.collector_key_id, "collector_key_id")
        _public_key(
            self.collector_public_key,
            self.collector_public_key_sha256,
            "collector_public_key",
        )
        _identifier(self.deployment_attestation_id, "deployment_attestation_id")
        _digest(self.deployment_attestation_sha256, "deployment_attestation_sha256")
        _integer(self.sequence, "sequence", 1)
        if (self.predecessor_envelope_id is None) != (
            self.predecessor_envelope_sha256 is None
        ):
            raise TargetHealthCustodyContractError("envelope predecessor is incomplete")
        if self.predecessor_envelope_id is not None:
            _record_id(self.predecessor_envelope_id, self.PREFIX, "predecessor_envelope_id")
            _digest(self.predecessor_envelope_sha256, "predecessor_envelope_sha256")
        if self.sequence > 1 and self.predecessor_envelope_id is None:
            raise TargetHealthCustodyContractError("later envelope requires a predecessor")
        if not isinstance(self.receipt, TargetHealthReceipt):
            raise TargetHealthCustodyContractError("receipt is invalid")
        _validate_tree(self.receipt.to_dict())
        if self.receipt.binding != self.binding:
            raise TargetHealthCustodyContractError("receipt binding does not match envelope")
        if not hmac.compare_digest(self.receipt_id, self.receipt.receipt_id):
            raise TargetHealthCustodyContractError("receipt_id does not match receipt")
        if not hmac.compare_digest(self.receipt_sha256, self.receipt.receipt_sha256):
            raise TargetHealthCustodyContractError("receipt_sha256 does not match receipt")
        if self.receipt.runtime_policy_id != self.runtime_policy_id or not hmac.compare_digest(
            self.receipt.runtime_policy_sha256, self.runtime_policy_sha256
        ):
            raise TargetHealthCustodyContractError("receipt runtime policy does not match")
        _utc(self.observed_at, "observed_at")
        if self.receipt.observed_at != self.observed_at:
            raise TargetHealthCustodyContractError("receipt observed_at does not match envelope")
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise TargetHealthCustodyContractError("custody envelope requires Ed25519")
        _signature(self.collector_signature, "collector_signature")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.envelope_id and not hmac.compare_digest(self.envelope_id, identifier):
            raise TargetHealthCustodyContractError("envelope_id does not match content")
        if self.envelope_sha256 and not hmac.compare_digest(self.envelope_sha256, digest):
            raise TargetHealthCustodyContractError("envelope_sha256 does not match content")
        object.__setattr__(self, "envelope_id", identifier)
        object.__setattr__(self, "envelope_sha256", digest)

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": self.chain_id,
            "collector_epoch": self.collector_epoch,
            "collector_id": self.collector_id,
            "collector_key_id": self.collector_key_id,
            "collector_public_key": self.collector_public_key,
            "collector_public_key_sha256": self.collector_public_key_sha256,
            "deployment_attestation_id": self.deployment_attestation_id,
            "deployment_attestation_sha256": self.deployment_attestation_sha256,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "policy_sha256": self.policy_sha256,
            "predecessor_envelope_id": self.predecessor_envelope_id,
            "predecessor_envelope_sha256": self.predecessor_envelope_sha256,
            "receipt": self.receipt.to_dict(),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "runtime_policy_id": self.runtime_policy_id,
            "runtime_policy_sha256": self.runtime_policy_sha256,
            "sequence": self.sequence,
            "signature_algorithm": self.signature_algorithm,
            "tenant_id": self.tenant_id,
            **_NO_EFFECTS,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json(
            {
                "domain": "sunderkey.target-health-custody-envelope-signature.v2",
                "envelope": self.unsigned_body(),
            }
        ).encode("ascii")

    @classmethod
    def signing_bytes_for(cls, unsigned_fields: dict[str, Any]) -> bytes:
        data = _exact(unsigned_fields, _ENVELOPE_UNSIGNED_FIELDS, "envelope signing fields")
        _check_effects(data)
        placeholder = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
        candidate = cls(
            **{
                key: item
                for key, item in data.items()
                if key not in _NO_EFFECT_FIELDS | {"binding", "receipt"}
            },
            binding=_binding_from_dict(data["binding"]),
            receipt=_receipt_from_dict(data["receipt"]),
            collector_signature=placeholder,
        )
        return candidate.signing_bytes()

    def body(self) -> dict[str, Any]:
        return {**self.unsigned_body(), "collector_signature": self.collector_signature}

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "envelope_id": self.envelope_id,
            "envelope_sha256": self.envelope_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SignedTargetHealthCustodyEnvelopeV2:
        fields = _ENVELOPE_UNSIGNED_FIELDS | {
            "collector_signature",
            "envelope_id",
            "envelope_sha256",
            "kind",
            "schema_version",
        }
        data = _exact(value, fields, "custody envelope")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError("custody envelope type or version is invalid")
        _check_effects(data)
        return cls(
            **{
                key: item
                for key, item in data.items()
                if key
                not in _NO_EFFECT_FIELDS
                | {"binding", "kind", "receipt", "schema_version"}
            },
            binding=_binding_from_dict(data["binding"]),
            receipt=_receipt_from_dict(data["receipt"]),
        )


@dataclass(frozen=True, slots=True)
class TargetHealthSigningContext:
    """Restart-safe chain context that grants no sequence reservation or authority."""

    tenant_id: str
    mission_id: str
    binding_sha256: str
    policy_id: str
    policy_sha256: str
    policy_revision: int
    collector_id: str
    collector_epoch: int
    chain_id: str
    next_sequence: int
    previous_envelope_id: str | None
    previous_envelope_sha256: str | None
    current_head_sequence: int
    current_head_envelope_id: str | None
    current_head_envelope_sha256: str | None
    prepared_at: str
    reservation_effect: str = "none"
    authority_effect: str = "none"

    KIND: ClassVar[str] = "sunderkey.target-health-signing-context.v2"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _digest(self.binding_sha256, "binding_sha256")
        _record_id(self.policy_id, "THCP", "policy_id")
        _digest(self.policy_sha256, "policy_sha256")
        _integer(self.policy_revision, "policy_revision", 1)
        _identifier(self.collector_id, "collector_id")
        _integer(self.collector_epoch, "collector_epoch", 1)
        if self.chain_id != target_health_chain_id(
            self.collector_id, self.mission_id, self.binding_sha256
        ):
            raise TargetHealthCustodyContractError("signing context chain_id is invalid")
        _integer(self.next_sequence, "next_sequence", 1)
        _integer(self.current_head_sequence, "current_head_sequence", 0)
        if self.next_sequence != self.current_head_sequence + 1:
            raise TargetHealthCustodyContractError("signing context sequence is invalid")
        pairs = (
            (self.previous_envelope_id, self.previous_envelope_sha256, "previous envelope"),
            (
                self.current_head_envelope_id,
                self.current_head_envelope_sha256,
                "current head",
            ),
        )
        for identifier, digest, label in pairs:
            if (identifier is None) != (digest is None):
                raise TargetHealthCustodyContractError(f"{label} is incomplete")
            if identifier is not None:
                _record_id(identifier, "THCE", f"{label} id")
                _digest(digest, f"{label} sha256")
        if self.current_head_sequence == 0:
            if self.current_head_envelope_id is not None:
                raise TargetHealthCustodyContractError("empty chain has a current head")
        elif (
            self.previous_envelope_id != self.current_head_envelope_id
            or self.previous_envelope_sha256 != self.current_head_envelope_sha256
        ):
            raise TargetHealthCustodyContractError("previous envelope is not the current head")
        _utc(self.prepared_at, "prepared_at")
        if self.reservation_effect != "none" or self.authority_effect != "none":
            raise TargetHealthCustodyContractError("signing context cannot reserve or authorize")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_effect": self.authority_effect,
            "binding_sha256": self.binding_sha256,
            "chain_id": self.chain_id,
            "collector_epoch": self.collector_epoch,
            "collector_id": self.collector_id,
            "current_head_envelope_id": self.current_head_envelope_id,
            "current_head_envelope_sha256": self.current_head_envelope_sha256,
            "current_head_sequence": self.current_head_sequence,
            "kind": self.KIND,
            "mission_id": self.mission_id,
            "next_sequence": self.next_sequence,
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "policy_sha256": self.policy_sha256,
            "prepared_at": self.prepared_at,
            "previous_envelope_id": self.previous_envelope_id,
            "previous_envelope_sha256": self.previous_envelope_sha256,
            "reservation_effect": self.reservation_effect,
            "schema_version": SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthSigningContext:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        fields |= {"kind", "schema_version"}
        data = _exact(value, fields, "signing context")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError("signing context type or version is invalid")
        return cls(
            **{
                key: item
                for key, item in data.items()
                if key not in {"kind", "schema_version"}
            }
        )


@dataclass(frozen=True, slots=True)
class TargetHealthCustodyVerificationResult:
    """Content-addressed proof of historical or current local verification."""

    mode: TargetHealthVerificationMode
    verified_at: str
    tenant_id: str
    mission_id: str
    binding: ExecutionBinding
    binding_sha256: str
    trust_root_id: str
    trust_root_sha256: str
    trust_root_revision: int
    policy_id: str
    policy_sha256: str
    policy_revision: int
    policy_revocation_id: str | None
    policy_revocation_sha256: str | None
    collector_id: str
    collector_epoch: int
    chain_id: str
    envelope_id: str
    envelope_sha256: str
    envelope_observed_at: str
    sequence: int
    predecessor_envelope_id: str | None
    predecessor_envelope_sha256: str | None
    receipt_id: str
    receipt_sha256: str
    signatures_verified: bool
    current_policy_verified: bool
    current_head_verified: bool
    evidence_current_verified: bool
    verification_id: str = ""
    verification_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-custody-verification-result.v2"
    PREFIX: ClassVar[str] = "THVR"

    def __post_init__(self) -> None:
        if not isinstance(self.mode, TargetHealthVerificationMode):
            raise TargetHealthCustodyContractError("verification mode is invalid")
        _utc(self.verified_at, "verified_at")
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        if not isinstance(self.binding, ExecutionBinding):
            raise TargetHealthCustodyContractError("verification binding is invalid")
        if self.binding.tenant_id != self.tenant_id or not hmac.compare_digest(
            self.binding_sha256, execution_binding_sha256(self.binding)
        ):
            raise TargetHealthCustodyContractError("verification binding does not match")
        for value, prefix, label in (
            (self.trust_root_id, "THRT", "trust_root_id"),
            (self.policy_id, "THCP", "policy_id"),
            (self.envelope_id, "THCE", "envelope_id"),
            (self.receipt_id, "THR", "receipt_id"),
        ):
            if prefix == "THR":
                _identifier(value, label)
            else:
                _record_id(value, prefix, label)
        for value, label in (
            (self.trust_root_sha256, "trust_root_sha256"),
            (self.policy_sha256, "policy_sha256"),
            (self.envelope_sha256, "envelope_sha256"),
            (self.receipt_sha256, "receipt_sha256"),
        ):
            _digest(value, label)
        _utc(self.envelope_observed_at, "envelope_observed_at")
        _integer(self.trust_root_revision, "trust_root_revision", 1)
        _integer(self.policy_revision, "policy_revision", 1)
        if (self.policy_revocation_id is None) != (
            self.policy_revocation_sha256 is None
        ):
            raise TargetHealthCustodyContractError("verification revocation is incomplete")
        if self.policy_revocation_id is not None:
            _record_id(self.policy_revocation_id, "THRV", "policy_revocation_id")
            _digest(self.policy_revocation_sha256, "policy_revocation_sha256")
        _identifier(self.collector_id, "collector_id")
        _integer(self.collector_epoch, "collector_epoch", 1)
        if self.chain_id != target_health_chain_id(
            self.collector_id, self.mission_id, self.binding_sha256
        ):
            raise TargetHealthCustodyContractError("verification chain_id is invalid")
        _integer(self.sequence, "sequence", 1)
        if (self.predecessor_envelope_id is None) != (
            self.predecessor_envelope_sha256 is None
        ):
            raise TargetHealthCustodyContractError("verification predecessor is incomplete")
        if self.predecessor_envelope_id is not None:
            _record_id(self.predecessor_envelope_id, "THCE", "predecessor_envelope_id")
            _digest(self.predecessor_envelope_sha256, "predecessor_envelope_sha256")
        for name in (
            "signatures_verified",
            "current_policy_verified",
            "current_head_verified",
            "evidence_current_verified",
        ):
            if not isinstance(getattr(self, name), bool):
                raise TargetHealthCustodyContractError(f"{name} is invalid")
        if not self.signatures_verified:
            raise TargetHealthCustodyContractError("verification result must verify signatures")
        current_flags = (
            self.current_policy_verified,
            self.current_head_verified,
            self.evidence_current_verified,
        )
        if self.mode is TargetHealthVerificationMode.CURRENT and not all(current_flags):
            raise TargetHealthCustodyContractError("current verification is incomplete")
        if self.mode is TargetHealthVerificationMode.HISTORICAL and any(current_flags):
            raise TargetHealthCustodyContractError("historical verification overclaims currentness")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.verification_id and not hmac.compare_digest(self.verification_id, identifier):
            raise TargetHealthCustodyContractError("verification_id does not match content")
        if self.verification_sha256 and not hmac.compare_digest(
            self.verification_sha256, digest
        ):
            raise TargetHealthCustodyContractError("verification_sha256 does not match content")
        object.__setattr__(self, "verification_id", identifier)
        object.__setattr__(self, "verification_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": self.chain_id,
            "collector_epoch": self.collector_epoch,
            "collector_id": self.collector_id,
            "current_head_verified": self.current_head_verified,
            "current_policy_verified": self.current_policy_verified,
            "envelope_id": self.envelope_id,
            "envelope_observed_at": self.envelope_observed_at,
            "envelope_sha256": self.envelope_sha256,
            "evidence_current_verified": self.evidence_current_verified,
            "mission_id": self.mission_id,
            "mode": self.mode.value,
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "policy_revocation_id": self.policy_revocation_id,
            "policy_revocation_sha256": self.policy_revocation_sha256,
            "policy_sha256": self.policy_sha256,
            "predecessor_envelope_id": self.predecessor_envelope_id,
            "predecessor_envelope_sha256": self.predecessor_envelope_sha256,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "sequence": self.sequence,
            "signatures_verified": self.signatures_verified,
            "tenant_id": self.tenant_id,
            "trust_root_id": self.trust_root_id,
            "trust_root_revision": self.trust_root_revision,
            "trust_root_sha256": self.trust_root_sha256,
            "verified_at": self.verified_at,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "verification_id": self.verification_id,
            "verification_sha256": self.verification_sha256,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthCustodyVerificationResult:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        fields |= {"kind", "schema_version", *_NO_EFFECT_FIELDS}
        data = _exact(value, fields, "verification result")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError("verification result type or version is invalid")
        _check_effects(data)
        return cls(
            **{
                key: item
                for key, item in data.items()
                if key
                not in _NO_EFFECT_FIELDS
                | {"binding", "kind", "mode", "schema_version"}
            },
            binding=_binding_from_dict(data["binding"]),
            mode=TargetHealthVerificationMode(data["mode"]),
        )


@dataclass(frozen=True, slots=True)
class TargetHealthCustodyReceipt:
    """Durable current-verification acceptance record with complete lineage."""

    verification: TargetHealthCustodyVerificationResult
    recorded_at: str
    custody_receipt_id: str = ""
    custody_receipt_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-custody-receipt.v2"
    PREFIX: ClassVar[str] = "THCR"

    def __post_init__(self) -> None:
        if not isinstance(self.verification, TargetHealthCustodyVerificationResult):
            raise TargetHealthCustodyContractError("custody verification is invalid")
        if self.verification.mode is not TargetHealthVerificationMode.CURRENT:
            raise TargetHealthCustodyContractError("custody requires current verification")
        _utc(self.recorded_at, "recorded_at")
        if _instant(self.recorded_at) < max(
            _instant(self.verification.verified_at),
            _instant(self.verification.envelope_observed_at),
        ):
            raise TargetHealthCustodyContractError("custody predates verification")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.custody_receipt_id and not hmac.compare_digest(
            self.custody_receipt_id, identifier
        ):
            raise TargetHealthCustodyContractError("custody_receipt_id does not match content")
        if self.custody_receipt_sha256 and not hmac.compare_digest(
            self.custody_receipt_sha256, digest
        ):
            raise TargetHealthCustodyContractError("custody receipt digest does not match content")
        object.__setattr__(self, "custody_receipt_id", identifier)
        object.__setattr__(self, "custody_receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        verification = self.verification
        return {
            "binding": verification.binding.to_dict(),
            "binding_sha256": verification.binding_sha256,
            "chain_id": verification.chain_id,
            "collector_epoch": verification.collector_epoch,
            "collector_id": verification.collector_id,
            "envelope_id": verification.envelope_id,
            "envelope_observed_at": verification.envelope_observed_at,
            "envelope_sha256": verification.envelope_sha256,
            "mission_id": verification.mission_id,
            "policy_id": verification.policy_id,
            "policy_revision": verification.policy_revision,
            "policy_revocation_id": verification.policy_revocation_id,
            "policy_revocation_sha256": verification.policy_revocation_sha256,
            "policy_sha256": verification.policy_sha256,
            "predecessor_envelope_id": verification.predecessor_envelope_id,
            "predecessor_envelope_sha256": verification.predecessor_envelope_sha256,
            "receipt_id": verification.receipt_id,
            "receipt_sha256": verification.receipt_sha256,
            "recorded_at": self.recorded_at,
            "sequence": verification.sequence,
            "tenant_id": verification.tenant_id,
            "trust_root_id": verification.trust_root_id,
            "trust_root_revision": verification.trust_root_revision,
            "trust_root_sha256": verification.trust_root_sha256,
            "verification_id": verification.verification_id,
            "verification_mode": verification.mode.value,
            "verification_sha256": verification.verification_sha256,
            "verified_at": verification.verified_at,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "custody_receipt_id": self.custody_receipt_id,
            "custody_receipt_sha256": self.custody_receipt_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthCustodyReceipt:
        body_fields = {
            "binding",
            "binding_sha256",
            "chain_id",
            "collector_epoch",
            "collector_id",
            "envelope_id",
            "envelope_observed_at",
            "envelope_sha256",
            "mission_id",
            "policy_id",
            "policy_revision",
            "policy_revocation_id",
            "policy_revocation_sha256",
            "policy_sha256",
            "predecessor_envelope_id",
            "predecessor_envelope_sha256",
            "receipt_id",
            "receipt_sha256",
            "recorded_at",
            "sequence",
            "tenant_id",
            "trust_root_id",
            "trust_root_revision",
            "trust_root_sha256",
            "verification_id",
            "verification_mode",
            "verification_sha256",
            "verified_at",
            *_NO_EFFECT_FIELDS,
        }
        data = _exact(
            value,
            body_fields
            | {
                "custody_receipt_id",
                "custody_receipt_sha256",
                "kind",
                "schema_version",
            },
            "custody receipt",
        )
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError("custody receipt type or version is invalid")
        _check_effects(data)
        if data["verification_mode"] != TargetHealthVerificationMode.CURRENT.value:
            raise TargetHealthCustodyContractError("custody receipt verification mode is invalid")
        verification = TargetHealthCustodyVerificationResult(
            mode=TargetHealthVerificationMode.CURRENT,
            verified_at=data["verified_at"],
            tenant_id=data["tenant_id"],
            mission_id=data["mission_id"],
            binding=_binding_from_dict(data["binding"]),
            binding_sha256=data["binding_sha256"],
            trust_root_id=data["trust_root_id"],
            trust_root_sha256=data["trust_root_sha256"],
            trust_root_revision=data["trust_root_revision"],
            policy_id=data["policy_id"],
            policy_sha256=data["policy_sha256"],
            policy_revision=data["policy_revision"],
            policy_revocation_id=data["policy_revocation_id"],
            policy_revocation_sha256=data["policy_revocation_sha256"],
            collector_id=data["collector_id"],
            collector_epoch=data["collector_epoch"],
            chain_id=data["chain_id"],
            envelope_id=data["envelope_id"],
            envelope_sha256=data["envelope_sha256"],
            envelope_observed_at=data["envelope_observed_at"],
            sequence=data["sequence"],
            predecessor_envelope_id=data["predecessor_envelope_id"],
            predecessor_envelope_sha256=data["predecessor_envelope_sha256"],
            receipt_id=data["receipt_id"],
            receipt_sha256=data["receipt_sha256"],
            signatures_verified=True,
            current_policy_verified=True,
            current_head_verified=True,
            evidence_current_verified=True,
            verification_id=data["verification_id"],
            verification_sha256=data["verification_sha256"],
        )
        return cls(
            verification=verification,
            recorded_at=data["recorded_at"],
            custody_receipt_id=data["custody_receipt_id"],
            custody_receipt_sha256=data["custody_receipt_sha256"],
        )


@dataclass(frozen=True, slots=True)
class TargetHealthCustodyEvent:
    """Chain-local immutable event for a stored custody receipt."""

    tenant_id: str
    mission_id: str
    chain_id: str
    event_kind: str
    event_sequence: int
    predecessor_event_id: str | None
    predecessor_event_sha256: str | None
    custody_receipt_id: str
    custody_receipt_sha256: str
    envelope_id: str
    envelope_sha256: str
    recorded_at: str
    event_id: str = ""
    event_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-custody-event.v2"
    PREFIX: ClassVar[str] = "THCV"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _record_id(self.chain_id, "THCH", "chain_id")
        if self.event_kind != "target_health_custody_recorded":
            raise TargetHealthCustodyContractError("event_kind is invalid")
        _integer(self.event_sequence, "event_sequence", 1)
        if (self.predecessor_event_id is None) != (self.predecessor_event_sha256 is None):
            raise TargetHealthCustodyContractError("event predecessor is incomplete")
        if self.event_sequence == 1:
            if self.predecessor_event_id is not None:
                raise TargetHealthCustodyContractError("first event has a predecessor")
        else:
            _record_id(self.predecessor_event_id, self.PREFIX, "predecessor_event_id")
            _digest(self.predecessor_event_sha256, "predecessor_event_sha256")
        _record_id(self.custody_receipt_id, "THCR", "custody_receipt_id")
        _digest(self.custody_receipt_sha256, "custody_receipt_sha256")
        _record_id(self.envelope_id, "THCE", "envelope_id")
        _digest(self.envelope_sha256, "envelope_sha256")
        _utc(self.recorded_at, "recorded_at")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.event_id and not hmac.compare_digest(self.event_id, identifier):
            raise TargetHealthCustodyContractError("event_id does not match content")
        if self.event_sha256 and not hmac.compare_digest(self.event_sha256, digest):
            raise TargetHealthCustodyContractError("event_sha256 does not match content")
        object.__setattr__(self, "event_id", identifier)
        object.__setattr__(self, "event_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "custody_receipt_id": self.custody_receipt_id,
            "custody_receipt_sha256": self.custody_receipt_sha256,
            "envelope_id": self.envelope_id,
            "envelope_sha256": self.envelope_sha256,
            "event_kind": self.event_kind,
            "event_sequence": self.event_sequence,
            "mission_id": self.mission_id,
            "predecessor_event_id": self.predecessor_event_id,
            "predecessor_event_sha256": self.predecessor_event_sha256,
            "recorded_at": self.recorded_at,
            "tenant_id": self.tenant_id,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "event_id": self.event_id,
            "event_sha256": self.event_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthCustodyEvent:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        fields |= {"kind", "schema_version", *_NO_EFFECT_FIELDS}
        data = _exact(value, fields, "custody event")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError("custody event type or version is invalid")
        _check_effects(data)
        return cls(
            **{
                key: item
                for key, item in data.items()
                if key not in _NO_EFFECT_FIELDS | {"kind", "schema_version"}
            }
        )


@dataclass(frozen=True, slots=True)
class TargetHealthCustodyHeadBinding:
    """Content-addressed identity of one inspected durable custody head."""

    tenant_id: str
    mission_id: str
    chain_id: str
    store_application_id: int
    store_schema_version: int
    store_migration_version: int
    store_migration_id: str
    store_migration_sha256: str
    store_schema_manifest_sha256: str
    global_transition_sequence: int
    trust_root_id: str
    trust_root_sha256: str
    trust_root_revision: int
    policy_id: str
    policy_sha256: str
    policy_revision: int
    policy_collector_epoch: int
    policy_head_transition_sequence: int
    policy_revocation_id: str | None
    policy_revocation_sha256: str | None
    policy_revoked_at: str | None
    policy_revocation_transition_sequence: int | None
    binding_sha256: str
    collector_id: str
    collector_epoch: int
    chain_head_sequence: int
    chain_head_envelope_id: str
    chain_head_envelope_sha256: str
    chain_head_custody_receipt_id: str
    chain_head_custody_receipt_sha256: str
    chain_head_policy_id: str
    chain_head_policy_sha256: str
    chain_head_transition_sequence: int
    event_head_sequence: int
    event_head_event_id: str
    event_head_event_sha256: str
    head_binding_id: str = ""
    head_binding_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-custody-head-binding.v1"
    PREFIX: ClassVar[str] = "THHB"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _record_id(self.chain_id, "THCH", "chain_id")
        _integer(
            self.store_application_id,
            "store_application_id",
            CUSTODY_STORE_APPLICATION_ID,
            CUSTODY_STORE_APPLICATION_ID,
        )
        _integer(
            self.store_schema_version,
            "store_schema_version",
            CUSTODY_STORE_SCHEMA_VERSION,
            CUSTODY_STORE_SCHEMA_VERSION,
        )
        _integer(
            self.store_migration_version,
            "store_migration_version",
            CUSTODY_STORE_MIGRATION_VERSION,
            CUSTODY_STORE_MIGRATION_VERSION,
        )
        if self.store_migration_id != CUSTODY_STORE_MIGRATION_ID:
            raise TargetHealthCustodyContractError("store migration identity is invalid")
        if not hmac.compare_digest(
            self.store_migration_sha256,
            CUSTODY_STORE_MIGRATION_SHA256,
        ):
            raise TargetHealthCustodyContractError("store migration digest is invalid")
        if not hmac.compare_digest(
            self.store_schema_manifest_sha256,
            CUSTODY_STORE_SCHEMA_MANIFEST_SHA256,
        ):
            raise TargetHealthCustodyContractError("store schema manifest is invalid")
        _integer(self.global_transition_sequence, "global_transition_sequence", 1)
        _record_id(self.trust_root_id, "THRT", "trust_root_id")
        _digest(self.trust_root_sha256, "trust_root_sha256")
        _integer(self.trust_root_revision, "trust_root_revision", 1)
        _record_id(self.policy_id, "THCP", "policy_id")
        _digest(self.policy_sha256, "policy_sha256")
        _integer(self.policy_revision, "policy_revision", 1)
        _integer(self.policy_collector_epoch, "policy_collector_epoch", 1)
        _integer(
            self.policy_head_transition_sequence,
            "policy_head_transition_sequence",
            1,
        )
        revocation_values = (
            self.policy_revocation_id,
            self.policy_revocation_sha256,
            self.policy_revoked_at,
            self.policy_revocation_transition_sequence,
        )
        if any(value is None for value in revocation_values) and not all(
            value is None for value in revocation_values
        ):
            raise TargetHealthCustodyContractError(
                "policy revocation head binding is incomplete"
            )
        if self.policy_revocation_id is not None:
            _record_id(self.policy_revocation_id, "THRV", "policy_revocation_id")
            _digest(self.policy_revocation_sha256, "policy_revocation_sha256")
            _utc(self.policy_revoked_at, "policy_revoked_at")
            _integer(
                self.policy_revocation_transition_sequence,
                "policy_revocation_transition_sequence",
                1,
            )
        _digest(self.binding_sha256, "binding_sha256")
        _identifier(self.collector_id, "collector_id")
        _integer(self.collector_epoch, "collector_epoch", 1)
        _integer(self.chain_head_sequence, "chain_head_sequence", 1)
        _record_id(self.chain_head_envelope_id, "THCE", "chain_head_envelope_id")
        _digest(self.chain_head_envelope_sha256, "chain_head_envelope_sha256")
        _record_id(
            self.chain_head_custody_receipt_id,
            "THCR",
            "chain_head_custody_receipt_id",
        )
        _digest(
            self.chain_head_custody_receipt_sha256,
            "chain_head_custody_receipt_sha256",
        )
        _record_id(self.chain_head_policy_id, "THCP", "chain_head_policy_id")
        _digest(self.chain_head_policy_sha256, "chain_head_policy_sha256")
        _integer(
            self.chain_head_transition_sequence,
            "chain_head_transition_sequence",
            1,
        )
        _integer(self.event_head_sequence, "event_head_sequence", 1)
        _record_id(self.event_head_event_id, "THCV", "event_head_event_id")
        _digest(self.event_head_event_sha256, "event_head_event_sha256")
        transition_sequences = [
            self.policy_head_transition_sequence,
            self.chain_head_transition_sequence,
        ]
        if self.policy_revocation_transition_sequence is not None:
            transition_sequences.append(self.policy_revocation_transition_sequence)
        if self.global_transition_sequence < max(transition_sequences):
            raise TargetHealthCustodyContractError(
                "global transition sequence does not cover bound heads"
            )
        if self.policy_head_transition_sequence >= self.chain_head_transition_sequence:
            raise TargetHealthCustodyContractError(
                "policy head transition must precede chain head transition"
            )
        if (
            self.policy_revocation_transition_sequence is not None
            and self.policy_head_transition_sequence
            >= self.policy_revocation_transition_sequence
        ):
            raise TargetHealthCustodyContractError(
                "policy head transition must precede revocation head transition"
            )
        if self.chain_head_sequence != self.event_head_sequence:
            raise TargetHealthCustodyContractError(
                "chain and event head sequences disagree"
            )
        if (
            self.chain_head_policy_id != self.policy_id
            or not hmac.compare_digest(self.chain_head_policy_sha256, self.policy_sha256)
            or self.collector_epoch != self.policy_collector_epoch
        ):
            raise TargetHealthCustodyContractError(
                "policy and chain head bindings disagree"
            )
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.head_binding_id and not hmac.compare_digest(
            self.head_binding_id, identifier
        ):
            raise TargetHealthCustodyContractError(
                "head_binding_id does not match content"
            )
        if self.head_binding_sha256 and not hmac.compare_digest(
            self.head_binding_sha256, digest
        ):
            raise TargetHealthCustodyContractError(
                "head_binding_sha256 does not match content"
            )
        object.__setattr__(self, "head_binding_id", identifier)
        object.__setattr__(self, "head_binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding_sha256": self.binding_sha256,
            "chain_head_custody_receipt_id": self.chain_head_custody_receipt_id,
            "chain_head_custody_receipt_sha256": self.chain_head_custody_receipt_sha256,
            "chain_head_envelope_id": self.chain_head_envelope_id,
            "chain_head_envelope_sha256": self.chain_head_envelope_sha256,
            "chain_head_policy_id": self.chain_head_policy_id,
            "chain_head_policy_sha256": self.chain_head_policy_sha256,
            "chain_head_sequence": self.chain_head_sequence,
            "chain_head_transition_sequence": self.chain_head_transition_sequence,
            "chain_id": self.chain_id,
            "collector_epoch": self.collector_epoch,
            "collector_id": self.collector_id,
            "event_head_event_id": self.event_head_event_id,
            "event_head_event_sha256": self.event_head_event_sha256,
            "event_head_sequence": self.event_head_sequence,
            "global_transition_sequence": self.global_transition_sequence,
            "mission_id": self.mission_id,
            "policy_collector_epoch": self.policy_collector_epoch,
            "policy_head_transition_sequence": self.policy_head_transition_sequence,
            "policy_id": self.policy_id,
            "policy_revocation_id": self.policy_revocation_id,
            "policy_revocation_sha256": self.policy_revocation_sha256,
            "policy_revocation_transition_sequence": (
                self.policy_revocation_transition_sequence
            ),
            "policy_revoked_at": self.policy_revoked_at,
            "policy_revision": self.policy_revision,
            "policy_sha256": self.policy_sha256,
            "store_application_id": self.store_application_id,
            "store_migration_id": self.store_migration_id,
            "store_migration_sha256": self.store_migration_sha256,
            "store_migration_version": self.store_migration_version,
            "store_schema_manifest_sha256": self.store_schema_manifest_sha256,
            "store_schema_version": self.store_schema_version,
            "tenant_id": self.tenant_id,
            "trust_root_id": self.trust_root_id,
            "trust_root_revision": self.trust_root_revision,
            "trust_root_sha256": self.trust_root_sha256,
            **_INSPECTION_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "head_binding_id": self.head_binding_id,
            "head_binding_sha256": self.head_binding_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthCustodyHeadBinding:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        fields |= {"kind", "schema_version", *_INSPECTION_EFFECT_FIELDS}
        data = _exact(value, fields, "custody head binding")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError(
                "custody head binding type or version is invalid"
            )
        _check_inspection_effects(data)
        return cls(
            **{
                key: item
                for key, item in data.items()
                if key
                not in _INSPECTION_EFFECT_FIELDS | {"kind", "schema_version"}
            }
        )


@dataclass(frozen=True, slots=True)
class TargetHealthCurrentHeadInspection:
    """Closed current-head inspection with no authority or control effect.

    Current means the embedded signatures, policy, durable head, and evidence
    freshness passed verification at ``inspected_at``. It does not mean the
    embedded receipt reports healthy status or is eligible for an action.
    """

    tenant_id: str
    mission_id: str
    chain_id: str
    head_binding: TargetHealthCustodyHeadBinding
    trust_root: TargetHealthTrustRoot
    current_policy: TargetHealthCollectorPolicyRevision
    policy_revocation: TargetHealthCollectorPolicyRevocation | None
    envelope: SignedTargetHealthCustodyEnvelopeV2
    custody_receipt: TargetHealthCustodyReceipt
    custody_event: TargetHealthCustodyEvent
    verification: TargetHealthCustodyVerificationResult
    inspected_at: str
    inspection_context_sha256: str | None = None
    current_material_sha256: str = ""
    inspection_id: str = ""
    inspection_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-current-head-inspection.v1"
    PREFIX: ClassVar[str] = "THCI"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _record_id(self.chain_id, "THCH", "chain_id")
        if not isinstance(self.head_binding, TargetHealthCustodyHeadBinding):
            raise TargetHealthCustodyContractError("head_binding is invalid")
        if not isinstance(self.trust_root, TargetHealthTrustRoot):
            raise TargetHealthCustodyContractError("trust_root is invalid")
        if not isinstance(self.current_policy, TargetHealthCollectorPolicyRevision):
            raise TargetHealthCustodyContractError("current_policy is invalid")
        if self.policy_revocation is not None and not isinstance(
            self.policy_revocation,
            TargetHealthCollectorPolicyRevocation,
        ):
            raise TargetHealthCustodyContractError("policy_revocation is invalid")
        if not isinstance(self.envelope, SignedTargetHealthCustodyEnvelopeV2):
            raise TargetHealthCustodyContractError("envelope is invalid")
        if not isinstance(self.custody_receipt, TargetHealthCustodyReceipt):
            raise TargetHealthCustodyContractError("custody_receipt is invalid")
        if not isinstance(self.custody_event, TargetHealthCustodyEvent):
            raise TargetHealthCustodyContractError("custody_event is invalid")
        if not isinstance(self.verification, TargetHealthCustodyVerificationResult):
            raise TargetHealthCustodyContractError("verification is invalid")
        _utc(self.inspected_at, "inspected_at")
        if self.inspection_context_sha256 is not None:
            _digest(self.inspection_context_sha256, "inspection_context_sha256")
        contextual = (
            (self.head_binding.tenant_id, self.tenant_id),
            (self.trust_root.tenant_id, self.tenant_id),
            (self.current_policy.tenant_id, self.tenant_id),
            (self.envelope.tenant_id, self.tenant_id),
            (self.verification.tenant_id, self.tenant_id),
            (self.head_binding.mission_id, self.mission_id),
            (self.trust_root.mission_id, self.mission_id),
            (self.current_policy.mission_id, self.mission_id),
            (self.envelope.mission_id, self.mission_id),
            (self.verification.mission_id, self.mission_id),
            (self.head_binding.chain_id, self.chain_id),
            (self.current_policy.chain_id, self.chain_id),
            (self.envelope.chain_id, self.chain_id),
            (self.custody_receipt.verification.chain_id, self.chain_id),
            (self.custody_event.chain_id, self.chain_id),
            (self.verification.chain_id, self.chain_id),
            (self.custody_receipt.verification.tenant_id, self.tenant_id),
            (self.custody_event.tenant_id, self.tenant_id),
            (self.custody_receipt.verification.mission_id, self.mission_id),
            (self.custody_event.mission_id, self.mission_id),
        )
        if any(actual != expected for actual, expected in contextual):
            raise TargetHealthCustodyContractError(
                "inspection crosses a tenant, mission, or chain boundary"
            )
        head = self.head_binding
        if (
            head.trust_root_id != self.trust_root.trust_root_id
            or not hmac.compare_digest(
                head.trust_root_sha256,
                self.trust_root.trust_root_sha256,
            )
            or head.trust_root_revision != self.trust_root.trust_root_revision
        ):
            raise TargetHealthCustodyContractError("inspection trust root is substituted")
        if (
            head.policy_id != self.current_policy.policy_id
            or not hmac.compare_digest(head.policy_sha256, self.current_policy.policy_sha256)
            or head.policy_revision != self.current_policy.policy_revision
            or head.policy_collector_epoch != self.current_policy.collector_epoch
        ):
            raise TargetHealthCustodyContractError("inspection policy head is substituted")
        expected_revocation = (
            None
            if self.policy_revocation is None
            else (
                self.policy_revocation.revocation_id,
                self.policy_revocation.revocation_sha256,
                self.policy_revocation.revoked_at,
            )
        )
        bound_revocation = (
            None
            if head.policy_revocation_id is None
            else (
                head.policy_revocation_id,
                head.policy_revocation_sha256,
                head.policy_revoked_at,
            )
        )
        if expected_revocation != bound_revocation:
            raise TargetHealthCustodyContractError(
                "inspection policy revocation is omitted or substituted"
            )
        if self.policy_revocation is not None and (
            self.policy_revocation.policy_id != self.current_policy.policy_id
            or not hmac.compare_digest(
                self.policy_revocation.policy_sha256,
                self.current_policy.policy_sha256,
            )
        ):
            raise TargetHealthCustodyContractError(
                "inspection revocation does not bind the current policy"
            )
        if (
            head.binding_sha256 != self.envelope.binding_sha256
            or head.collector_id != self.envelope.collector_id
            or head.collector_epoch != self.envelope.collector_epoch
            or head.chain_head_sequence != self.envelope.sequence
            or head.chain_head_envelope_id != self.envelope.envelope_id
            or not hmac.compare_digest(
                head.chain_head_envelope_sha256,
                self.envelope.envelope_sha256,
            )
            or head.chain_head_policy_id != self.envelope.policy_id
            or not hmac.compare_digest(
                head.chain_head_policy_sha256,
                self.envelope.policy_sha256,
            )
        ):
            raise TargetHealthCustodyContractError("inspection chain head is substituted")
        custody_verification = self.custody_receipt.verification
        acceptance_source = custody_verification.body()
        current_source = self.verification.body()
        for field_name in (
            "policy_revocation_id",
            "policy_revocation_sha256",
            "verified_at",
        ):
            acceptance_source.pop(field_name)
            current_source.pop(field_name)
        if acceptance_source != current_source:
            raise TargetHealthCustodyContractError(
                "inspection custody receipt source material is substituted"
            )
        revocation_existed_at_acceptance = (
            head.policy_revocation_transition_sequence is not None
            and head.policy_revocation_transition_sequence
            <= head.chain_head_transition_sequence
        )
        expected_acceptance_revocation = (
            (head.policy_revocation_id, head.policy_revocation_sha256)
            if revocation_existed_at_acceptance
            else (None, None)
        )
        if (
            custody_verification.policy_revocation_id,
            custody_verification.policy_revocation_sha256,
        ) != expected_acceptance_revocation:
            raise TargetHealthCustodyContractError(
                "inspection custody receipt revocation lineage is invalid"
            )
        if custody_verification.verified_at != self.custody_receipt.recorded_at:
            raise TargetHealthCustodyContractError(
                "inspection custody receipt acceptance chronology is invalid"
            )
        if (
            head.chain_head_custody_receipt_id
            != self.custody_receipt.custody_receipt_id
            or not hmac.compare_digest(
                head.chain_head_custody_receipt_sha256,
                self.custody_receipt.custody_receipt_sha256,
            )
        ):
            raise TargetHealthCustodyContractError(
                "inspection custody receipt head is substituted"
            )
        event = self.custody_event
        if (
            event.event_id != head.event_head_event_id
            or not hmac.compare_digest(
                event.event_sha256,
                head.event_head_event_sha256,
            )
            or event.event_sequence != head.event_head_sequence
            or event.event_sequence != head.chain_head_sequence
            or event.event_sequence != self.envelope.sequence
            or event.custody_receipt_id != self.custody_receipt.custody_receipt_id
            or not hmac.compare_digest(
                event.custody_receipt_sha256,
                self.custody_receipt.custody_receipt_sha256,
            )
            or event.envelope_id != self.envelope.envelope_id
            or not hmac.compare_digest(
                event.envelope_sha256,
                self.envelope.envelope_sha256,
            )
        ):
            raise TargetHealthCustodyContractError(
                "inspection custody event head is substituted"
            )
        if event.recorded_at != self.custody_receipt.recorded_at:
            raise TargetHealthCustodyContractError(
                "inspection custody event chronology is invalid"
            )
        event_has_predecessor = event.predecessor_event_id is not None
        envelope_has_predecessor = self.envelope.predecessor_envelope_id is not None
        if event_has_predecessor != envelope_has_predecessor:
            raise TargetHealthCustodyContractError(
                "inspection custody predecessor presence is invalid"
            )
        if self.inspected_at != self.verification.verified_at:
            raise TargetHealthCustodyContractError(
                "inspection time does not match current verification"
            )
        if self.verification.mode is not TargetHealthVerificationMode.CURRENT:
            raise TargetHealthCustodyContractError(
                "inspection requires current verification"
            )
        expected_verification = verify_target_health_custody_envelope_current(
            self.trust_root,
            self.current_policy,
            self.envelope,
            verified_at=self.inspected_at,
            expected_policy_id=head.policy_id,
            expected_policy_sha256=head.policy_sha256,
            expected_head_envelope_id=head.chain_head_envelope_id,
            expected_head_envelope_sha256=head.chain_head_envelope_sha256,
            expected_head_sequence=head.chain_head_sequence,
            policy_revocation=self.policy_revocation,
        )
        if expected_verification != self.verification:
            raise TargetHealthCustodyContractError(
                "inspection verification does not match current material"
            )
        if (
            self.envelope.receipt_id != self.verification.receipt_id
            or not hmac.compare_digest(
                self.envelope.receipt_sha256,
                self.verification.receipt_sha256,
            )
        ):
            raise TargetHealthCustodyContractError(
                "inspection health receipt does not match verification"
            )
        expected_material = self.material_sha256(
            head_binding=self.head_binding,
            trust_root=self.trust_root,
            current_policy=self.current_policy,
            policy_revocation=self.policy_revocation,
            envelope=self.envelope,
            custody_receipt=self.custody_receipt,
            custody_event=self.custody_event,
            verification=self.verification,
        )
        if self.current_material_sha256 and not hmac.compare_digest(
            self.current_material_sha256,
            expected_material,
        ):
            raise TargetHealthCustodyContractError(
                "current_material_sha256 does not match current material"
            )
        object.__setattr__(self, "current_material_sha256", expected_material)
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.inspection_id and not hmac.compare_digest(self.inspection_id, identifier):
            raise TargetHealthCustodyContractError(
                "inspection_id does not match content"
            )
        if self.inspection_sha256 and not hmac.compare_digest(
            self.inspection_sha256,
            digest,
        ):
            raise TargetHealthCustodyContractError(
                "inspection_sha256 does not match content"
            )
        object.__setattr__(self, "inspection_id", identifier)
        object.__setattr__(self, "inspection_sha256", digest)

    @staticmethod
    def material_sha256(
        *,
        head_binding: TargetHealthCustodyHeadBinding,
        trust_root: TargetHealthTrustRoot,
        current_policy: TargetHealthCollectorPolicyRevision,
        policy_revocation: TargetHealthCollectorPolicyRevocation | None,
        envelope: SignedTargetHealthCustodyEnvelopeV2,
        custody_receipt: TargetHealthCustodyReceipt,
        custody_event: TargetHealthCustodyEvent,
        verification: TargetHealthCustodyVerificationResult,
    ) -> str:
        return _canonical_sha256(
            {
                "chain_id": head_binding.chain_id,
                "custody_event_id": custody_event.event_id,
                "custody_event_sha256": custody_event.event_sha256,
                "custody_receipt_id": custody_receipt.custody_receipt_id,
                "custody_receipt_sha256": custody_receipt.custody_receipt_sha256,
                "domain": "sunderkey.target-health-current-material.v1",
                "envelope_id": envelope.envelope_id,
                "envelope_sha256": envelope.envelope_sha256,
                "head_binding_id": head_binding.head_binding_id,
                "head_binding_sha256": head_binding.head_binding_sha256,
                "mission_id": head_binding.mission_id,
                "policy_id": current_policy.policy_id,
                "policy_revocation_id": (
                    None if policy_revocation is None else policy_revocation.revocation_id
                ),
                "policy_revocation_sha256": (
                    None
                    if policy_revocation is None
                    else policy_revocation.revocation_sha256
                ),
                "policy_sha256": current_policy.policy_sha256,
                "receipt_id": envelope.receipt.receipt_id,
                "receipt_sha256": envelope.receipt.receipt_sha256,
                "tenant_id": head_binding.tenant_id,
                "trust_root_id": trust_root.trust_root_id,
                "trust_root_sha256": trust_root.trust_root_sha256,
                "verification_id": verification.verification_id,
                "verification_sha256": verification.verification_sha256,
            }
        )

    def body(self) -> dict[str, Any]:
        body = {
            "chain_id": self.chain_id,
            "current_material_sha256": self.current_material_sha256,
            "current_policy": self.current_policy.to_dict(),
            "custody_event": self.custody_event.to_dict(),
            "custody_receipt": self.custody_receipt.to_dict(),
            "envelope": self.envelope.to_dict(),
            "head_binding": self.head_binding.to_dict(),
            "inspected_at": self.inspected_at,
            "mission_id": self.mission_id,
            "policy_revocation": (
                None if self.policy_revocation is None else self.policy_revocation.to_dict()
            ),
            "tenant_id": self.tenant_id,
            "trust_root": self.trust_root.to_dict(),
            "verification": self.verification.to_dict(),
            **_INSPECTION_EFFECTS,
        }
        if self.inspection_context_sha256 is not None:
            body["inspection_context_sha256"] = self.inspection_context_sha256
        return body

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "inspection_id": self.inspection_id,
            "inspection_sha256": self.inspection_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetHealthCurrentHeadInspection:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        required_fields = fields - {"inspection_context_sha256"}
        document_fields = required_fields | {
            "kind",
            "schema_version",
            *_INSPECTION_EFFECT_FIELDS,
        }
        if "inspection_context_sha256" in value:
            document_fields.add("inspection_context_sha256")
        data = _exact(value, document_fields, "current head inspection")
        if _type_or_version_is_invalid(data, cls.KIND):
            raise TargetHealthCustodyContractError(
                "current head inspection type or version is invalid"
            )
        _check_inspection_effects(data)
        revocation = data["policy_revocation"]
        if revocation is not None and not isinstance(revocation, dict):
            raise TargetHealthCustodyContractError("policy_revocation is invalid")
        return cls(
            tenant_id=data["tenant_id"],
            mission_id=data["mission_id"],
            chain_id=data["chain_id"],
            head_binding=TargetHealthCustodyHeadBinding.from_dict(data["head_binding"]),
            trust_root=TargetHealthTrustRoot.from_dict(data["trust_root"]),
            current_policy=TargetHealthCollectorPolicyRevision.from_dict(
                data["current_policy"]
            ),
            policy_revocation=(
                None
                if revocation is None
                else TargetHealthCollectorPolicyRevocation.from_dict(revocation)
            ),
            custody_receipt=TargetHealthCustodyReceipt.from_dict(
                data["custody_receipt"]
            ),
            custody_event=TargetHealthCustodyEvent.from_dict(data["custody_event"]),
            envelope=SignedTargetHealthCustodyEnvelopeV2.from_dict(data["envelope"]),
            verification=TargetHealthCustodyVerificationResult.from_dict(
                data["verification"]
            ),
            inspected_at=data["inspected_at"],
            inspection_context_sha256=data.get("inspection_context_sha256"),
            current_material_sha256=data["current_material_sha256"],
            inspection_id=data["inspection_id"],
            inspection_sha256=data["inspection_sha256"],
        )


def verify_target_health_collector_policy(
    trust_root: TargetHealthTrustRoot,
    policy: TargetHealthCollectorPolicyRevision,
    *,
    verified_at: str,
    current: bool,
) -> TargetHealthCollectorPolicyRevision:
    """Verify one exact policy revision against its pinned trust root."""

    if not isinstance(trust_root, TargetHealthTrustRoot) or not isinstance(
        policy, TargetHealthCollectorPolicyRevision
    ):
        raise TargetHealthCustodyContractError("trust root or collector policy is invalid")
    _utc(verified_at, "verified_at")
    if (
        policy.tenant_id != trust_root.tenant_id
        or policy.mission_id != trust_root.mission_id
        or policy.trust_root_id != trust_root.trust_root_id
        or not hmac.compare_digest(policy.trust_root_sha256, trust_root.trust_root_sha256)
        or policy.trust_root_revision != trust_root.trust_root_revision
    ):
        raise TargetHealthCustodyContractError("collector policy trust root binding is invalid")
    if (
        policy.deployment_attestation_id != trust_root.deployment_attestation_id
        or not hmac.compare_digest(
            policy.deployment_attestation_sha256,
            trust_root.deployment_attestation_sha256,
        )
    ):
        raise TargetHealthCustodyContractError("collector deployment attestation is invalid")
    issued = _instant(policy.issued_at)
    if not (_instant(trust_root.effective_at) <= issued < _instant(trust_root.expires_at)):
        raise TargetHealthCustodyContractError("collector policy was issued outside root validity")
    if (
        _instant(policy.effective_at) < _instant(trust_root.effective_at)
        or _instant(policy.expires_at) > _instant(trust_root.expires_at)
    ):
        raise TargetHealthCustodyContractError(
            "collector policy validity is not contained by trust root validity"
        )
    if current:
        checked = _instant(verified_at)
        if not (_instant(trust_root.effective_at) <= checked < _instant(trust_root.expires_at)):
            raise TargetHealthCustodyContractError("trust root is not current")
        if not (_instant(policy.effective_at) <= checked < _instant(policy.expires_at)):
            raise TargetHealthCustodyContractError("collector policy is not current")
    _verify_signature(
        trust_root.root_public_key,
        policy.root_signature,
        policy.signing_bytes(),
        "collector policy",
    )
    return policy


def verify_target_health_collector_policy_revocation(
    trust_root: TargetHealthTrustRoot,
    policy: TargetHealthCollectorPolicyRevision,
    revocation: TargetHealthCollectorPolicyRevocation,
) -> TargetHealthCollectorPolicyRevocation:
    """Verify one terminal root-signed revocation against its exact policy."""

    if not isinstance(revocation, TargetHealthCollectorPolicyRevocation):
        raise TargetHealthCustodyContractError("collector policy revocation is invalid")
    verify_target_health_collector_policy(
        trust_root,
        policy,
        verified_at=revocation.revoked_at,
        current=False,
    )
    comparisons = (
        (revocation.tenant_id, policy.tenant_id),
        (revocation.mission_id, policy.mission_id),
        (revocation.trust_root_id, trust_root.trust_root_id),
        (revocation.trust_root_sha256, trust_root.trust_root_sha256),
        (revocation.trust_root_revision, trust_root.trust_root_revision),
        (revocation.policy_id, policy.policy_id),
        (revocation.policy_sha256, policy.policy_sha256),
        (revocation.policy_revision, policy.policy_revision),
        (revocation.binding, policy.binding),
        (revocation.binding_sha256, policy.binding_sha256),
        (revocation.collector_id, policy.collector_id),
        (revocation.collector_epoch, policy.collector_epoch),
        (revocation.chain_id, policy.chain_id),
    )
    if any(left != right for left, right in comparisons):
        raise TargetHealthCustodyContractError("policy revocation binding is invalid")
    revoked = _instant(revocation.revoked_at)
    if not (
        _instant(policy.issued_at) <= revoked < _instant(trust_root.expires_at)
        and revoked >= _instant(trust_root.effective_at)
    ):
        raise TargetHealthCustodyContractError("policy revocation time is invalid")
    _verify_signature(
        trust_root.root_public_key,
        revocation.root_signature,
        revocation.signing_bytes(),
        "collector policy revocation",
    )
    return revocation


def _verify_envelope_common(
    trust_root: TargetHealthTrustRoot,
    policy: TargetHealthCollectorPolicyRevision,
    envelope: SignedTargetHealthCustodyEnvelopeV2,
    *,
    verified_at: str,
    current: bool,
) -> None:
    verify_target_health_collector_policy(
        trust_root,
        policy,
        verified_at=verified_at,
        current=current,
    )
    if not isinstance(envelope, SignedTargetHealthCustodyEnvelopeV2):
        raise TargetHealthCustodyContractError("custody envelope is invalid")
    comparisons = (
        (envelope.tenant_id, policy.tenant_id),
        (envelope.mission_id, policy.mission_id),
        (envelope.binding, policy.binding),
        (envelope.binding_sha256, policy.binding_sha256),
        (envelope.runtime_policy_id, policy.runtime_policy_id),
        (envelope.runtime_policy_sha256, policy.runtime_policy_sha256),
        (envelope.policy_id, policy.policy_id),
        (envelope.policy_sha256, policy.policy_sha256),
        (envelope.policy_revision, policy.policy_revision),
        (envelope.collector_id, policy.collector_id),
        (envelope.collector_epoch, policy.collector_epoch),
        (envelope.chain_id, policy.chain_id),
        (envelope.collector_key_id, policy.collector_key_id),
        (envelope.collector_public_key, policy.collector_public_key),
        (envelope.collector_public_key_sha256, policy.collector_public_key_sha256),
        (envelope.deployment_attestation_id, policy.deployment_attestation_id),
        (
            envelope.deployment_attestation_sha256,
            policy.deployment_attestation_sha256,
        ),
    )
    if any(left != right for left, right in comparisons):
        raise TargetHealthCustodyContractError("custody envelope does not match collector policy")
    observed = _instant(envelope.observed_at)
    if not (_instant(policy.effective_at) <= observed < _instant(policy.expires_at)):
        raise TargetHealthCustodyContractError("envelope observation is outside policy validity")
    if envelope.sequence == 1:
        if policy.collector_epoch == 1:
            if envelope.predecessor_envelope_id is not None:
                raise TargetHealthCustodyContractError("first epoch envelope has a predecessor")
        elif (
            envelope.predecessor_envelope_id != policy.prior_epoch_head_envelope_id
            or envelope.predecessor_envelope_sha256
            != policy.prior_epoch_head_envelope_sha256
        ):
            raise TargetHealthCustodyContractError("epoch envelope does not link prior epoch head")
    _verify_signature(
        policy.collector_public_key,
        envelope.collector_signature,
        envelope.signing_bytes(),
        "custody envelope",
    )


def _verification_result(
    mode: TargetHealthVerificationMode,
    verified_at: str,
    trust_root: TargetHealthTrustRoot,
    policy: TargetHealthCollectorPolicyRevision,
    envelope: SignedTargetHealthCustodyEnvelopeV2,
    policy_revocation: TargetHealthCollectorPolicyRevocation | None,
) -> TargetHealthCustodyVerificationResult:
    current = mode is TargetHealthVerificationMode.CURRENT
    return TargetHealthCustodyVerificationResult(
        mode=mode,
        verified_at=verified_at,
        tenant_id=envelope.tenant_id,
        mission_id=envelope.mission_id,
        binding=envelope.binding,
        binding_sha256=envelope.binding_sha256,
        trust_root_id=trust_root.trust_root_id,
        trust_root_sha256=trust_root.trust_root_sha256,
        trust_root_revision=trust_root.trust_root_revision,
        policy_id=policy.policy_id,
        policy_sha256=policy.policy_sha256,
        policy_revision=policy.policy_revision,
        policy_revocation_id=(
            None if policy_revocation is None else policy_revocation.revocation_id
        ),
        policy_revocation_sha256=(
            None if policy_revocation is None else policy_revocation.revocation_sha256
        ),
        collector_id=envelope.collector_id,
        collector_epoch=envelope.collector_epoch,
        chain_id=envelope.chain_id,
        envelope_id=envelope.envelope_id,
        envelope_sha256=envelope.envelope_sha256,
        envelope_observed_at=envelope.observed_at,
        sequence=envelope.sequence,
        predecessor_envelope_id=envelope.predecessor_envelope_id,
        predecessor_envelope_sha256=envelope.predecessor_envelope_sha256,
        receipt_id=envelope.receipt_id,
        receipt_sha256=envelope.receipt_sha256,
        signatures_verified=True,
        current_policy_verified=current,
        current_head_verified=current,
        evidence_current_verified=current,
    )


def verify_target_health_custody_envelope_historical(
    trust_root: TargetHealthTrustRoot,
    policy: TargetHealthCollectorPolicyRevision,
    envelope: SignedTargetHealthCustodyEnvelopeV2,
    *,
    verified_at: str,
    policy_revocation: TargetHealthCollectorPolicyRevocation | None = None,
) -> TargetHealthCustodyVerificationResult:
    """Verify persisted root, policy, and envelope without claiming currentness."""

    _utc(verified_at, "verified_at")
    checked = _instant(verified_at)
    if checked < _instant(policy.issued_at) or checked < _instant(envelope.observed_at):
        raise TargetHealthCustodyContractError(
            "historical verification predates policy or envelope"
        )
    _verify_envelope_common(
        trust_root,
        policy,
        envelope,
        verified_at=verified_at,
        current=False,
    )
    if policy_revocation is not None:
        verify_target_health_collector_policy_revocation(
            trust_root,
            policy,
            policy_revocation,
        )
        if _instant(envelope.observed_at) >= _instant(policy_revocation.revoked_at):
            raise TargetHealthCustodyContractError(
                "revoked collector policy cannot sign this envelope"
            )
    return _verification_result(
        TargetHealthVerificationMode.HISTORICAL,
        verified_at,
        trust_root,
        policy,
        envelope,
        policy_revocation,
    )


def _verify_evidence_current(
    policy: TargetHealthCollectorPolicyRevision,
    receipt: TargetHealthReceipt,
    verified_at: str,
) -> None:
    now = _instant(verified_at)
    observed = _instant(receipt.observed_at)
    age = (now - observed).total_seconds()
    if age > policy.maximum_observation_age_seconds:
        raise TargetHealthCustodyContractError("target-health receipt is too old")
    if age < -policy.maximum_future_skew_seconds:
        raise TargetHealthCustodyContractError("target-health receipt is too far in the future")
    expiries = [item.expires_at for item in receipt.observations]
    if receipt.safety_attestation is not None:
        expiries.append(receipt.safety_attestation.expires_at)
    if receipt.budget_state is not None:
        expiries.append(receipt.budget_state.expires_at)
    if any(now >= _instant(value) for value in expiries):
        raise TargetHealthCustodyContractError("target-health embedded evidence is not current")


def verify_target_health_custody_envelope_current(
    trust_root: TargetHealthTrustRoot,
    policy: TargetHealthCollectorPolicyRevision,
    envelope: SignedTargetHealthCustodyEnvelopeV2,
    *,
    verified_at: str,
    expected_policy_id: str,
    expected_policy_sha256: str,
    expected_head_envelope_id: str,
    expected_head_envelope_sha256: str,
    expected_head_sequence: int,
    policy_revocation: TargetHealthCollectorPolicyRevocation | None,
) -> TargetHealthCustodyVerificationResult:
    """Verify signatures, current policy, evidence freshness, and exact chain head."""

    _utc(verified_at, "verified_at")
    _record_id(expected_policy_id, "THCP", "expected_policy_id")
    _digest(expected_policy_sha256, "expected_policy_sha256")
    _record_id(expected_head_envelope_id, "THCE", "expected_head_envelope_id")
    _digest(expected_head_envelope_sha256, "expected_head_envelope_sha256")
    _integer(expected_head_sequence, "expected_head_sequence", 1)
    if expected_policy_id != policy.policy_id or not hmac.compare_digest(
        expected_policy_sha256, policy.policy_sha256
    ):
        raise TargetHealthCustodyContractError(
            "collector policy is not the expected current policy"
        )
    if (
        expected_head_envelope_id != envelope.envelope_id
        or not hmac.compare_digest(expected_head_envelope_sha256, envelope.envelope_sha256)
        or expected_head_sequence != envelope.sequence
    ):
        raise TargetHealthCustodyContractError("custody envelope is not the expected current head")
    _verify_envelope_common(
        trust_root,
        policy,
        envelope,
        verified_at=verified_at,
        current=True,
    )
    if policy_revocation is not None:
        verify_target_health_collector_policy_revocation(
            trust_root,
            policy,
            policy_revocation,
        )
        if (
            _instant(envelope.observed_at) >= _instant(policy_revocation.revoked_at)
            or _instant(verified_at) >= _instant(policy_revocation.revoked_at)
        ):
            raise TargetHealthCustodyContractError(
                "revoked collector policy cannot verify current"
            )
    _verify_evidence_current(policy, envelope.receipt, verified_at)
    return _verification_result(
        TargetHealthVerificationMode.CURRENT,
        verified_at,
        trust_root,
        policy,
        envelope,
        policy_revocation,
    )


def build_target_health_custody_receipt(
    verification: TargetHealthCustodyVerificationResult,
    *,
    recorded_at: str,
) -> TargetHealthCustodyReceipt:
    """Build one deterministic receipt from a successful current verification."""

    return TargetHealthCustodyReceipt(verification=verification, recorded_at=recorded_at)


def build_target_health_custody_event(
    receipt: TargetHealthCustodyReceipt,
    *,
    event_sequence: int,
    predecessor_event_id: str | None,
    predecessor_event_sha256: str | None,
    recorded_at: str,
) -> TargetHealthCustodyEvent:
    """Build one deterministic chain-local event for a custody receipt."""

    if not isinstance(receipt, TargetHealthCustodyReceipt):
        raise TargetHealthCustodyContractError("custody receipt is invalid")
    body = receipt.body()
    _utc(recorded_at, "recorded_at")
    if _instant(recorded_at) < _instant(receipt.recorded_at):
        raise TargetHealthCustodyContractError("custody event predates its receipt")
    return TargetHealthCustodyEvent(
        tenant_id=body["tenant_id"],
        mission_id=body["mission_id"],
        chain_id=body["chain_id"],
        event_kind="target_health_custody_recorded",
        event_sequence=event_sequence,
        predecessor_event_id=predecessor_event_id,
        predecessor_event_sha256=predecessor_event_sha256,
        custody_receipt_id=receipt.custody_receipt_id,
        custody_receipt_sha256=receipt.custody_receipt_sha256,
        envelope_id=body["envelope_id"],
        envelope_sha256=body["envelope_sha256"],
        recorded_at=recorded_at,
    )


def parse_target_health_custody_document(
    raw: bytes | str | dict[str, Any],
) -> (
    TargetHealthTrustRoot
    | TargetHealthCollectorPolicyRevision
    | TargetHealthCollectorPolicyRevocation
    | SignedTargetHealthCustodyEnvelopeV2
    | TargetHealthSigningContext
    | TargetHealthCustodyVerificationResult
    | TargetHealthCustodyReceipt
    | TargetHealthCustodyEvent
    | TargetHealthCustodyHeadBinding
    | TargetHealthCurrentHeadInspection
):
    """Parse one canonical closed custody document into its exact record type."""

    value = _load_document(raw)
    kind = value.get("kind")
    parsers = {
        TargetHealthTrustRoot.KIND: TargetHealthTrustRoot.from_dict,
        TargetHealthCollectorPolicyRevision.KIND: TargetHealthCollectorPolicyRevision.from_dict,
        TargetHealthCollectorPolicyRevocation.KIND: (
            TargetHealthCollectorPolicyRevocation.from_dict
        ),
        SignedTargetHealthCustodyEnvelopeV2.KIND: SignedTargetHealthCustodyEnvelopeV2.from_dict,
        TargetHealthSigningContext.KIND: TargetHealthSigningContext.from_dict,
        TargetHealthCustodyVerificationResult.KIND: (
            TargetHealthCustodyVerificationResult.from_dict
        ),
        TargetHealthCustodyReceipt.KIND: TargetHealthCustodyReceipt.from_dict,
        TargetHealthCustodyEvent.KIND: TargetHealthCustodyEvent.from_dict,
        TargetHealthCustodyHeadBinding.KIND: TargetHealthCustodyHeadBinding.from_dict,
        TargetHealthCurrentHeadInspection.KIND: TargetHealthCurrentHeadInspection.from_dict,
    }
    parser = parsers.get(kind)
    if parser is None:
        raise TargetHealthCustodyContractError("document kind is invalid")
    return parser(value)


__all__ = [
    "CUSTODY_STORE_APPLICATION_ID",
    "CUSTODY_STORE_MIGRATION_ID",
    "CUSTODY_STORE_MIGRATION_SHA256",
    "CUSTODY_STORE_MIGRATION_VERSION",
    "CUSTODY_STORE_SCHEMA_MANIFEST_SHA256",
    "CUSTODY_STORE_SCHEMA_VERSION",
    "MAX_DOCUMENT_BYTES",
    "MAX_STRING_BYTES",
    "SCHEMA_VERSION",
    "SIGNATURE_ALGORITHM",
    "SignedTargetHealthCustodyEnvelopeV2",
    "TargetHealthCollectorPolicyRevision",
    "TargetHealthCollectorPolicyRevocation",
    "TargetHealthCustodyContractError",
    "TargetHealthCustodyEvent",
    "TargetHealthCustodyHeadBinding",
    "TargetHealthCustodyReceipt",
    "TargetHealthCustodyVerificationResult",
    "TargetHealthCurrentHeadInspection",
    "TargetHealthSigningContext",
    "TargetHealthTrustRoot",
    "TargetHealthVerificationMode",
    "build_target_health_custody_event",
    "build_target_health_custody_receipt",
    "execution_binding_sha256",
    "parse_target_health_custody_document",
    "target_health_chain_id",
    "verify_target_health_collector_policy",
    "verify_target_health_collector_policy_revocation",
    "verify_target_health_custody_envelope_current",
    "verify_target_health_custody_envelope_historical",
]
