"""Deterministic, passive-only multi-source asset reconciliation.

The module reconciles caller-supplied observations. It performs no collection,
network access, target interaction, authorization, routing, or deployment.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any

SCHEMA_VERSION = 1
SNAPSHOT_DOMAIN = "sunderkey.asset-reconciliation.snapshot.v1"
ASSET_DOMAIN = "sunderkey.asset-reconciliation.asset.v1"
CONFLICT_DOMAIN = "sunderkey.asset-reconciliation.conflict.v1"
POLICY_DOMAIN = "sunderkey.asset-reconciliation.policy.v1"

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SNAPSHOT_ID_RE = re.compile(r"ARS-[0-9A-F]{32}\Z")
ASSET_ID_RE = re.compile(r"AST-[0-9A-F]{32}\Z")
CONFLICT_ID_RE = re.compile(r"ARC-[0-9A-F]{32}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,})",
    re.IGNORECASE,
)

NO_EFFECTS = MappingProxyType({
    "active_probing": False,
    "authority": "none",
    "deployment": "none",
    "qualification": "none",
    "routing": "none",
    "target_interaction": False,
})

MAX_OBSERVATIONS = 10000
MAX_IDENTIFIERS_PER_OBSERVATION = 64
MAX_CLAIMS_PER_OBSERVATION = 64
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024


class AssetReconciliationError(ValueError):
    """Raised when reconciliation input or output is invalid."""


class SourceKind(StrEnum):
    """Supported caller-supplied passive source classes."""

    CMDB = "cmdb"
    CLOUD = "cloud"
    DIRECTORY = "directory"
    ENDPOINT = "endpoint"
    VULNERABILITY = "vulnerability"
    EXTERNAL = "external"


class IdentifierKind(StrEnum):
    """Closed identifier vocabulary used for identity resolution."""

    CMDB_CI_ID = "cmdb_ci_id"
    CLOUD_RESOURCE_ID = "cloud_resource_id"
    DIRECTORY_OBJECT_ID = "directory_object_id"
    ENDPOINT_DEVICE_ID = "endpoint_device_id"
    VULNERABILITY_ASSET_ID = "vulnerability_asset_id"
    EXTERNAL_ASSET_ID = "external_asset_id"
    SERIAL_NUMBER = "serial_number"
    MAC_ADDRESS = "mac_address"
    FQDN = "fqdn"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"


class FreshnessState(StrEnum):
    CURRENT = "current"
    STALE = "stale"


class ConfidenceBand(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


LINKING_IDENTIFIER_KINDS = frozenset(
    {
        IdentifierKind.CMDB_CI_ID,
        IdentifierKind.CLOUD_RESOURCE_ID,
        IdentifierKind.DIRECTORY_OBJECT_ID,
        IdentifierKind.ENDPOINT_DEVICE_ID,
        IdentifierKind.VULNERABILITY_ASSET_ID,
        IdentifierKind.EXTERNAL_ASSET_ID,
        IdentifierKind.SERIAL_NUMBER,
        IdentifierKind.MAC_ADDRESS,
        IdentifierKind.FQDN,
    }
)
CORROBORATING_IDENTIFIER_KINDS = frozenset({IdentifierKind.HOSTNAME, IdentifierKind.IP_ADDRESS})
NATIVE_IDENTIFIER_BY_SOURCE = {
    SourceKind.CMDB: IdentifierKind.CMDB_CI_ID,
    SourceKind.CLOUD: IdentifierKind.CLOUD_RESOURCE_ID,
    SourceKind.DIRECTORY: IdentifierKind.DIRECTORY_OBJECT_ID,
    SourceKind.ENDPOINT: IdentifierKind.ENDPOINT_DEVICE_ID,
    SourceKind.VULNERABILITY: IdentifierKind.VULNERABILITY_ASSET_ID,
    SourceKind.EXTERNAL: IdentifierKind.EXTERNAL_ASSET_ID,
}
IDENTITY_PRIORITY = {
    IdentifierKind.CLOUD_RESOURCE_ID: 0,
    IdentifierKind.CMDB_CI_ID: 1,
    IdentifierKind.DIRECTORY_OBJECT_ID: 2,
    IdentifierKind.ENDPOINT_DEVICE_ID: 3,
    IdentifierKind.SERIAL_NUMBER: 4,
    IdentifierKind.MAC_ADDRESS: 5,
    IdentifierKind.FQDN: 6,
    IdentifierKind.VULNERABILITY_ASSET_ID: 7,
    IdentifierKind.EXTERNAL_ASSET_ID: 8,
}
SOURCE_CONFIDENCE_CAP_BPS = {
    SourceKind.CMDB: 9800,
    SourceKind.CLOUD: 9800,
    SourceKind.DIRECTORY: 9500,
    SourceKind.ENDPOINT: 9500,
    SourceKind.VULNERABILITY: 8500,
    SourceKind.EXTERNAL: 7000,
}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(domain: str, value: Any) -> str:
    return (
        "sha256:" + hashlib.sha256(domain.encode() + b"\x00" + _canonical_json(value)).hexdigest()
    )


def _derived_id(prefix: str, digest: str) -> str:
    return f"{prefix}-{digest.removeprefix('sha256:')[:32].upper()}"


def _exact_fields(
    raw: Any, required: set[str], label: str, *, optional: set[str] = frozenset()
) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise AssetReconciliationError(f"{label} must be an object")
    keys = set(raw)
    missing = required - keys
    extra = keys - required - optional
    if missing or extra:
        raise AssetReconciliationError(
            f"{label} fields are invalid: missing={sorted(missing)}, extra={sorted(extra)}"
        )
    return raw


def _safe_text(value: Any, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise AssetReconciliationError(f"{label} must be nonempty canonical text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AssetReconciliationError(f"{label} contains a control character")
    if SECRET_RE.search(value):
        raise AssetReconciliationError(f"{label} appears to contain secret material")
    return value


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise AssetReconciliationError(f"{label} must be a lowercase token")
    return value


def _identifier_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise AssetReconciliationError(f"{label} is invalid")
    if SECRET_RE.search(value):
        raise AssetReconciliationError(f"{label} appears to contain secret material")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise AssetReconciliationError(f"{label} must be second-precision UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AssetReconciliationError(f"{label} is not a valid UTC instant") from exc
    return parsed


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise AssetReconciliationError(f"{label} must be a lowercase sha256 digest")
    return value


def _bps(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10000:
        raise AssetReconciliationError(f"{label} must be an integer from 0 through 10000")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssetReconciliationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_path(path: str | Path, label: str) -> Any:
    document = Path(path)
    try:
        before = document.stat()
        if not stat.S_ISREG(before.st_mode):
            raise AssetReconciliationError(f"{label} must be a regular file")
        if before.st_size > MAX_DOCUMENT_BYTES:
            raise AssetReconciliationError(f"{label} exceeds its byte limit")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(document, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise AssetReconciliationError(f"{label} must be a regular file")
            if opened.st_size > MAX_DOCUMENT_BYTES:
                raise AssetReconciliationError(f"{label} exceeds its byte limit")
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
            ):
                raise AssetReconciliationError(f"{label} changed while opening")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(MAX_DOCUMENT_BYTES + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if len(content) > MAX_DOCUMENT_BYTES:
            raise AssetReconciliationError(f"{label} exceeds its byte limit")
        if (
            len(content) != opened.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise AssetReconciliationError(f"{label} changed while reading")
        text = content.decode("utf-8")
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except AssetReconciliationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AssetReconciliationError(f"{label} is not valid UTF-8 JSON") from exc


def _normalize_identifier(kind: IdentifierKind, value: str) -> str:
    canonical = _identifier_text(value, "identifier value")
    if kind in {IdentifierKind.FQDN, IdentifierKind.HOSTNAME}:
        normalized = canonical.rstrip(".").lower()
        if not normalized or len(normalized) > 253:
            raise AssetReconciliationError("DNS identifier is invalid")
        return normalized
    if kind is IdentifierKind.MAC_ADDRESS:
        compact = re.sub(r"[:-]", "", canonical).lower()
        if re.fullmatch(r"[0-9a-f]{12}", compact) is None:
            raise AssetReconciliationError("MAC address is invalid")
        return ":".join(compact[index : index + 2] for index in range(0, 12, 2))
    if kind is IdentifierKind.IP_ADDRESS:
        try:
            return ipaddress.ip_address(canonical).compressed.lower()
        except ValueError as exc:
            raise AssetReconciliationError("IP address is invalid") from exc
    if kind is IdentifierKind.SERIAL_NUMBER:
        return canonical.upper()
    return canonical


@dataclass(frozen=True, order=True)
class AssetIdentifier:
    """One normalized, namespace-scoped identifier."""

    kind: IdentifierKind | str
    namespace: str
    value: str

    def __post_init__(self) -> None:
        try:
            kind = IdentifierKind(self.kind)
        except (TypeError, ValueError) as exc:
            raise AssetReconciliationError("identifier kind is invalid") from exc
        namespace = _token(self.namespace, "identifier namespace")
        value = _normalize_identifier(kind, self.value)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "namespace", namespace)
        object.__setattr__(self, "value", value)

    @property
    def key(self) -> str:
        return f"{self.kind.value}|{self.namespace}|{self.value}"

    @property
    def links_identity(self) -> bool:
        return self.kind in LINKING_IDENTIFIER_KINDS

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind.value, "namespace": self.namespace, "value": self.value}

    @classmethod
    def from_dict(cls, raw: Any) -> AssetIdentifier:
        value = _exact_fields(raw, {"kind", "namespace", "value"}, "asset identifier")
        return cls(kind=value["kind"], namespace=value["namespace"], value=value["value"])


@dataclass(frozen=True, order=True)
class AttributeClaim:
    """One non-secret descriptive claim."""

    name: str
    value: str

    def __post_init__(self) -> None:
        _token(self.name, "claim name")
        if any(term in self.name for term in ("credential", "password", "secret", "token")):
            raise AssetReconciliationError("claim name may not describe secret material")
        _safe_text(self.value, "claim value")

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}

    @classmethod
    def from_dict(cls, raw: Any) -> AttributeClaim:
        value = _exact_fields(raw, {"name", "value"}, "attribute claim")
        return cls(name=value["name"], value=value["value"])


@dataclass(frozen=True, order=True)
class OwnershipClaim:
    """One bounded owner assertion from a passive observation."""

    owner_ref: str
    effective_from: str
    effective_until: str | None = None

    def __post_init__(self) -> None:
        _identifier_text(self.owner_ref, "owner_ref")
        start = _utc(self.effective_from, "ownership effective_from")
        if self.effective_until is not None:
            end = _utc(self.effective_until, "ownership effective_until")
            if end <= start:
                raise AssetReconciliationError(
                    "ownership effective_until must follow effective_from"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "effective_from": self.effective_from,
            "effective_until": self.effective_until,
            "owner_ref": self.owner_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OwnershipClaim:
        value = _exact_fields(
            raw, {"effective_from", "effective_until", "owner_ref"}, "ownership claim"
        )
        return cls(**value)


@dataclass(frozen=True)
class AssetObservation:
    """Caller-supplied passive observation from one inventory source."""

    tenant_id: str
    source_kind: SourceKind | str
    source_system: str
    source_record_id: str
    observed_at: str
    expires_at: str
    confidence_bps: int
    provenance_sha256: str
    identifiers: tuple[AssetIdentifier, ...]
    claims: tuple[AttributeClaim, ...] = ()
    ownership: tuple[OwnershipClaim, ...] = ()

    def __post_init__(self) -> None:
        _identifier_text(self.tenant_id, "tenant_id")
        try:
            source_kind = SourceKind(self.source_kind)
        except (TypeError, ValueError) as exc:
            raise AssetReconciliationError("source_kind is invalid") from exc
        object.__setattr__(self, "source_kind", source_kind)
        _token(self.source_system, "source_system")
        _identifier_text(self.source_record_id, "source_record_id")
        observed = _utc(self.observed_at, "observation observed_at")
        expires = _utc(self.expires_at, "observation expires_at")
        if expires <= observed:
            raise AssetReconciliationError("observation expires_at must follow observed_at")
        confidence = _bps(self.confidence_bps, "observation confidence_bps")
        if confidence > SOURCE_CONFIDENCE_CAP_BPS[source_kind]:
            raise AssetReconciliationError("observation confidence exceeds its source-kind cap")
        _sha256(self.provenance_sha256, "observation provenance_sha256")
        if not self.identifiers or len(self.identifiers) > MAX_IDENTIFIERS_PER_OBSERVATION:
            raise AssetReconciliationError("observation identifier count is invalid")
        if any(type(item) is not AssetIdentifier for item in self.identifiers):
            raise AssetReconciliationError("observation identifiers must be exact records")
        if any(type(item) is not AttributeClaim for item in self.claims):
            raise AssetReconciliationError("observation claims must be exact records")
        if any(type(item) is not OwnershipClaim for item in self.ownership):
            raise AssetReconciliationError("observation ownership must be exact records")
        identifiers = tuple(sorted(self.identifiers, key=lambda item: item.key))
        if len({item.key for item in identifiers}) != len(identifiers):
            raise AssetReconciliationError("observation identifiers must be unique")
        native = NATIVE_IDENTIFIER_BY_SOURCE[source_kind]
        if not any(item.kind is native for item in identifiers):
            raise AssetReconciliationError(
                f"{source_kind.value} observations require a {native.value} identifier"
            )
        claims = tuple(sorted(self.claims))
        ownership = tuple(sorted(self.ownership))
        if len(claims) > MAX_CLAIMS_PER_OBSERVATION:
            raise AssetReconciliationError("observation claim count exceeds its limit")
        if len({(item.name, item.value) for item in claims}) != len(claims):
            raise AssetReconciliationError("observation claims must be unique")
        if len(
            {(item.owner_ref, item.effective_from, item.effective_until) for item in ownership}
        ) != len(ownership):
            raise AssetReconciliationError("observation ownership claims must be unique")
        object.__setattr__(self, "identifiers", identifiers)
        object.__setattr__(self, "claims", claims)
        object.__setattr__(self, "ownership", ownership)

    @property
    def provenance_key(self) -> str:
        return f"{self.source_kind.value}|{self.source_system}|{self.source_record_id}"

    def is_current(self, as_of: str) -> bool:
        instant = _utc(as_of, "reconciliation as_of")
        if _utc(self.observed_at, "observation observed_at") > instant:
            raise AssetReconciliationError("observation occurs after reconciliation as_of")
        return _utc(self.expires_at, "observation expires_at") > instant

    def to_dict(self) -> dict[str, Any]:
        return {
            "claims": [item.to_dict() for item in self.claims],
            "confidence_bps": self.confidence_bps,
            "expires_at": self.expires_at,
            "identifiers": [item.to_dict() for item in self.identifiers],
            "observed_at": self.observed_at,
            "ownership": [item.to_dict() for item in self.ownership],
            "provenance_sha256": self.provenance_sha256,
            "source_kind": self.source_kind.value,
            "source_record_id": self.source_record_id,
            "source_system": self.source_system,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AssetObservation:
        value = _exact_fields(
            raw,
            {
                "claims",
                "confidence_bps",
                "expires_at",
                "identifiers",
                "observed_at",
                "ownership",
                "provenance_sha256",
                "source_kind",
                "source_record_id",
                "source_system",
                "tenant_id",
            },
            "asset observation",
        )
        for field in ("claims", "identifiers", "ownership"):
            if not isinstance(value[field], list):
                raise AssetReconciliationError(f"observation {field} must be an array")
        return cls(
            tenant_id=value["tenant_id"],
            source_kind=value["source_kind"],
            source_system=value["source_system"],
            source_record_id=value["source_record_id"],
            observed_at=value["observed_at"],
            expires_at=value["expires_at"],
            confidence_bps=value["confidence_bps"],
            provenance_sha256=value["provenance_sha256"],
            identifiers=tuple(AssetIdentifier.from_dict(item) for item in value["identifiers"]),
            claims=tuple(AttributeClaim.from_dict(item) for item in value["claims"]),
            ownership=tuple(OwnershipClaim.from_dict(item) for item in value["ownership"]),
        )


@dataclass(frozen=True, order=True)
class ProvenanceRecord:
    source_kind: SourceKind | str
    source_system: str
    source_record_id: str
    provenance_sha256: str
    observed_at: str
    expires_at: str
    confidence_bps: int
    freshness: FreshnessState | str

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "source_kind", SourceKind(self.source_kind))
            object.__setattr__(self, "freshness", FreshnessState(self.freshness))
        except (TypeError, ValueError) as exc:
            raise AssetReconciliationError("provenance enum value is invalid") from exc
        _token(self.source_system, "provenance source_system")
        _identifier_text(self.source_record_id, "provenance source_record_id")
        _sha256(self.provenance_sha256, "provenance digest")
        if _utc(self.expires_at, "provenance expires_at") <= _utc(
            self.observed_at, "provenance observed_at"
        ):
            raise AssetReconciliationError("provenance expiry must follow observation")
        _bps(self.confidence_bps, "provenance confidence_bps")

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence_bps": self.confidence_bps,
            "expires_at": self.expires_at,
            "freshness": self.freshness.value,
            "observed_at": self.observed_at,
            "provenance_sha256": self.provenance_sha256,
            "source_kind": self.source_kind.value,
            "source_record_id": self.source_record_id,
            "source_system": self.source_system,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ProvenanceRecord:
        value = _exact_fields(
            raw,
            {
                "confidence_bps",
                "expires_at",
                "freshness",
                "observed_at",
                "provenance_sha256",
                "source_kind",
                "source_record_id",
                "source_system",
            },
            "provenance record",
        )
        return cls(**value)


@dataclass(frozen=True, order=True)
class OwnershipHistoryEntry:
    owner_ref: str
    effective_from: str
    effective_until: str | None
    observation_sha256: str

    def __post_init__(self) -> None:
        _identifier_text(self.owner_ref, "ownership history owner_ref")
        start = _utc(self.effective_from, "ownership history effective_from")
        if (
            self.effective_until is not None
            and _utc(self.effective_until, "ownership history effective_until") <= start
        ):
            raise AssetReconciliationError("ownership history interval is invalid")
        _sha256(self.observation_sha256, "ownership history observation_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "effective_from": self.effective_from,
            "effective_until": self.effective_until,
            "observation_sha256": self.observation_sha256,
            "owner_ref": self.owner_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OwnershipHistoryEntry:
        value = _exact_fields(
            raw,
            {"effective_from", "effective_until", "observation_sha256", "owner_ref"},
            "ownership history entry",
        )
        return cls(**value)


@dataclass(frozen=True, order=True)
class ConflictClaim:
    value: str
    confidence_bps: int
    provenance_sha256: str

    def __post_init__(self) -> None:
        _safe_text(self.value, "conflict claim value")
        _bps(self.confidence_bps, "conflict claim confidence_bps")
        _sha256(self.provenance_sha256, "conflict claim provenance_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence_bps": self.confidence_bps,
            "provenance_sha256": self.provenance_sha256,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ConflictClaim:
        value = _exact_fields(
            raw, {"confidence_bps", "provenance_sha256", "value"}, "conflict claim"
        )
        return cls(**value)


@dataclass(frozen=True)
class AssetConflict:
    conflict_id: str
    asset_id: str
    kind: str
    field: str
    status: str
    claims: tuple[ConflictClaim, ...]

    def __post_init__(self) -> None:
        if CONFLICT_ID_RE.fullmatch(self.conflict_id) is None:
            raise AssetReconciliationError("conflict_id is invalid")
        if ASSET_ID_RE.fullmatch(self.asset_id) is None:
            raise AssetReconciliationError("conflict asset_id is invalid")
        _token(self.kind, "conflict kind")
        _safe_text(self.field, "conflict field", maximum=256)
        if self.status != "unresolved":
            raise AssetReconciliationError("conflict status must be unresolved")
        claims = tuple(sorted(self.claims))
        if len(claims) < 2 or len({item.value for item in claims}) < 2:
            raise AssetReconciliationError("conflict requires at least two distinct claims")
        core = {
            "asset_id": self.asset_id,
            "claims": [item.to_dict() for item in claims],
            "field": self.field,
            "kind": self.kind,
            "status": self.status,
        }
        if self.conflict_id != _derived_id("ARC", _digest(CONFLICT_DOMAIN, core)):
            raise AssetReconciliationError("conflict_id does not match conflict content")
        object.__setattr__(self, "claims", claims)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "claims": [item.to_dict() for item in self.claims],
            "conflict_id": self.conflict_id,
            "field": self.field,
            "kind": self.kind,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AssetConflict:
        value = _exact_fields(
            raw, {"asset_id", "claims", "conflict_id", "field", "kind", "status"}, "asset conflict"
        )
        if not isinstance(value["claims"], list):
            raise AssetReconciliationError("conflict claims must be an array")
        return cls(
            conflict_id=value["conflict_id"],
            asset_id=value["asset_id"],
            kind=value["kind"],
            field=value["field"],
            status=value["status"],
            claims=tuple(ConflictClaim.from_dict(item) for item in value["claims"]),
        )


@dataclass(frozen=True)
class ReconciledAsset:
    asset_id: str
    tenant_id: str
    identity_anchor: AssetIdentifier
    prior_asset_ids: tuple[str, ...]
    identifiers: tuple[AssetIdentifier, ...]
    confidence_bps: int
    confidence_band: ConfidenceBand | str
    freshness: FreshnessState | str
    first_seen_at: str
    last_seen_at: str
    claims: tuple[AttributeClaim, ...]
    ownership_history: tuple[OwnershipHistoryEntry, ...]
    provenance: tuple[ProvenanceRecord, ...]

    def __post_init__(self) -> None:
        if ASSET_ID_RE.fullmatch(self.asset_id) is None:
            raise AssetReconciliationError("asset_id is invalid")
        _identifier_text(self.tenant_id, "asset tenant_id")
        if not self.identity_anchor.links_identity:
            raise AssetReconciliationError("identity anchor must be identity-linking")
        prior_ids = tuple(sorted(self.prior_asset_ids))
        if len(set(prior_ids)) != len(prior_ids) or any(
            ASSET_ID_RE.fullmatch(item) is None for item in prior_ids
        ):
            raise AssetReconciliationError("prior_asset_ids are invalid")
        identifiers = tuple(sorted(self.identifiers, key=lambda item: item.key))
        if len({item.key for item in identifiers}) != len(identifiers):
            raise AssetReconciliationError("asset identifiers must be unique")
        if self.identity_anchor not in identifiers:
            raise AssetReconciliationError("identity anchor must be present in identifiers")
        confidence = _bps(self.confidence_bps, "asset confidence_bps")
        expected_band = (
            ConfidenceBand.HIGH
            if confidence >= 8000
            else ConfidenceBand.MEDIUM
            if confidence >= 5000
            else ConfidenceBand.LOW
        )
        try:
            band = ConfidenceBand(self.confidence_band)
            freshness = FreshnessState(self.freshness)
        except (TypeError, ValueError) as exc:
            raise AssetReconciliationError("asset enum value is invalid") from exc
        if band is not expected_band:
            raise AssetReconciliationError("confidence_band does not match confidence_bps")
        first = _utc(self.first_seen_at, "asset first_seen_at")
        last = _utc(self.last_seen_at, "asset last_seen_at")
        if last < first:
            raise AssetReconciliationError("asset last_seen_at precedes first_seen_at")
        object.__setattr__(self, "prior_asset_ids", prior_ids)
        object.__setattr__(self, "identifiers", identifiers)
        object.__setattr__(self, "confidence_band", band)
        object.__setattr__(self, "freshness", freshness)
        object.__setattr__(self, "claims", tuple(sorted(self.claims)))
        object.__setattr__(self, "ownership_history", tuple(sorted(self.ownership_history)))
        object.__setattr__(self, "provenance", tuple(sorted(self.provenance)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "claims": [item.to_dict() for item in self.claims],
            "confidence_band": self.confidence_band.value,
            "confidence_bps": self.confidence_bps,
            "first_seen_at": self.first_seen_at,
            "freshness": self.freshness.value,
            "identifiers": [item.to_dict() for item in self.identifiers],
            "identity_anchor": self.identity_anchor.to_dict(),
            "last_seen_at": self.last_seen_at,
            "ownership_history": [item.to_dict() for item in self.ownership_history],
            "prior_asset_ids": list(self.prior_asset_ids),
            "provenance": [item.to_dict() for item in self.provenance],
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ReconciledAsset:
        value = _exact_fields(
            raw,
            {
                "asset_id",
                "claims",
                "confidence_band",
                "confidence_bps",
                "first_seen_at",
                "freshness",
                "identifiers",
                "identity_anchor",
                "last_seen_at",
                "ownership_history",
                "prior_asset_ids",
                "provenance",
                "tenant_id",
            },
            "reconciled asset",
        )
        for field in (
            "claims",
            "identifiers",
            "ownership_history",
            "prior_asset_ids",
            "provenance",
        ):
            if not isinstance(value[field], list):
                raise AssetReconciliationError(f"asset {field} must be an array")
        return cls(
            asset_id=value["asset_id"],
            tenant_id=value["tenant_id"],
            identity_anchor=AssetIdentifier.from_dict(value["identity_anchor"]),
            prior_asset_ids=tuple(value["prior_asset_ids"]),
            identifiers=tuple(AssetIdentifier.from_dict(item) for item in value["identifiers"]),
            confidence_bps=value["confidence_bps"],
            confidence_band=value["confidence_band"],
            freshness=value["freshness"],
            first_seen_at=value["first_seen_at"],
            last_seen_at=value["last_seen_at"],
            claims=tuple(AttributeClaim.from_dict(item) for item in value["claims"]),
            ownership_history=tuple(
                OwnershipHistoryEntry.from_dict(item) for item in value["ownership_history"]
            ),
            provenance=tuple(ProvenanceRecord.from_dict(item) for item in value["provenance"]),
        )


@dataclass(frozen=True)
class AssetReconciliationSnapshot:
    snapshot_id: str
    snapshot_sha256: str
    tenant_id: str
    as_of: str
    assets: tuple[ReconciledAsset, ...]
    conflicts: tuple[AssetConflict, ...]
    observation_count: int
    source_counts: tuple[tuple[str, int], ...]
    prior_snapshot_sha256: str | None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != SCHEMA_VERSION
        ):
            raise AssetReconciliationError("snapshot schema_version is unsupported")
        if SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None:
            raise AssetReconciliationError("snapshot_id is invalid")
        _sha256(self.snapshot_sha256, "snapshot_sha256")
        _identifier_text(self.tenant_id, "snapshot tenant_id")
        _utc(self.as_of, "snapshot as_of")
        if self.prior_snapshot_sha256 is not None:
            _sha256(self.prior_snapshot_sha256, "prior_snapshot_sha256")
        assets = tuple(sorted(self.assets, key=lambda item: item.asset_id))
        conflicts = tuple(sorted(self.conflicts, key=lambda item: item.conflict_id))
        if len({item.asset_id for item in assets}) != len(assets):
            raise AssetReconciliationError("snapshot asset IDs must be unique")
        if len({item.conflict_id for item in conflicts}) != len(conflicts):
            raise AssetReconciliationError("snapshot conflict IDs must be unique")
        if any(item.tenant_id != self.tenant_id for item in assets):
            raise AssetReconciliationError("snapshot assets cross tenant boundaries")
        if isinstance(self.observation_count, bool) or not isinstance(self.observation_count, int):
            raise AssetReconciliationError("snapshot observation_count must be an integer")
        if not 1 <= self.observation_count <= MAX_OBSERVATIONS:
            raise AssetReconciliationError("snapshot observation_count is outside its limit")
        source_counts = tuple(sorted(self.source_counts))
        if len({name for name, _ in source_counts}) != len(source_counts):
            raise AssetReconciliationError("snapshot source_counts names must be unique")
        if sum(count for _, count in source_counts) != self.observation_count:
            raise AssetReconciliationError("source_counts do not match observation_count")
        if any(
            name not in {item.value for item in SourceKind}
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 1
            for name, count in source_counts
        ):
            raise AssetReconciliationError("snapshot source_counts are invalid")
        asset_ids = {item.asset_id for item in assets}
        if any(item.asset_id not in asset_ids for item in conflicts):
            raise AssetReconciliationError("conflict references an unknown asset")
        object.__setattr__(self, "assets", assets)
        object.__setattr__(self, "conflicts", conflicts)
        object.__setattr__(self, "source_counts", source_counts)
        _verify_snapshot_semantics(self)
        core = self._core_dict()
        expected_sha256 = _digest(SNAPSHOT_DOMAIN, core)
        if self.snapshot_sha256 != expected_sha256:
            raise AssetReconciliationError("snapshot_sha256 does not match snapshot content")
        if self.snapshot_id != _derived_id("ARS", expected_sha256):
            raise AssetReconciliationError("snapshot_id does not match snapshot content")

    def _core_dict(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "assets": [item.to_dict() for item in self.assets],
            "conflicts": [item.to_dict() for item in self.conflicts],
            "effects": dict(NO_EFFECTS),
            "observation_count": self.observation_count,
            "prior_snapshot_sha256": self.prior_snapshot_sha256,
            "schema_version": self.schema_version,
            "source_counts": {name: count for name, count in self.source_counts},
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._core_dict(),
            "snapshot_id": self.snapshot_id,
            "snapshot_sha256": self.snapshot_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AssetReconciliationSnapshot:
        value = _exact_fields(
            raw,
            {
                "as_of",
                "assets",
                "conflicts",
                "effects",
                "observation_count",
                "prior_snapshot_sha256",
                "schema_version",
                "snapshot_id",
                "snapshot_sha256",
                "source_counts",
                "tenant_id",
            },
            "asset reconciliation snapshot",
        )
        if value["effects"] != NO_EFFECTS:
            raise AssetReconciliationError(
                "snapshot effects must preserve the passive-only boundary"
            )
        if not isinstance(value["assets"], list) or not isinstance(value["conflicts"], list):
            raise AssetReconciliationError("snapshot assets and conflicts must be arrays")
        if not isinstance(value["source_counts"], Mapping):
            raise AssetReconciliationError("snapshot source_counts must be an object")
        instance = cls(
            snapshot_id=value["snapshot_id"],
            snapshot_sha256=value["snapshot_sha256"],
            tenant_id=value["tenant_id"],
            as_of=value["as_of"],
            assets=tuple(ReconciledAsset.from_dict(item) for item in value["assets"]),
            conflicts=tuple(AssetConflict.from_dict(item) for item in value["conflicts"]),
            observation_count=value["observation_count"],
            source_counts=tuple(value["source_counts"].items()),
            prior_snapshot_sha256=value["prior_snapshot_sha256"],
            schema_version=value["schema_version"],
        )
        if instance.to_dict() != raw:
            raise AssetReconciliationError("snapshot document is not canonical")
        return instance


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[max(left_root, right_root)] = min(left_root, right_root)


def _asset_id(tenant_id: str, anchor: AssetIdentifier) -> str:
    return _derived_id(
        "AST", _digest(ASSET_DOMAIN, {"anchor": anchor.to_dict(), "tenant_id": tenant_id})
    )


def _ambiguous_asset_id(
    tenant_id: str,
    identifiers: Sequence[AssetIdentifier],
    prior_asset_ids: Sequence[str],
) -> str:
    return _derived_id(
        "AST",
        _digest(
            "sunderkey.asset-reconciliation.ambiguous-asset.v1",
            {
                "identifiers": [item.to_dict() for item in identifiers],
                "prior_asset_ids": list(prior_asset_ids),
                "tenant_id": tenant_id,
            },
        ),
    )


def _verify_snapshot_semantics(snapshot: AssetReconciliationSnapshot) -> None:
    conflicts_by_asset: dict[str, list[AssetConflict]] = defaultdict(list)
    for conflict in snapshot.conflicts:
        conflicts_by_asset[conflict.asset_id].append(conflict)

    all_provenance = [record for asset in snapshot.assets for record in asset.provenance]
    if len(all_provenance) != snapshot.observation_count:
        raise AssetReconciliationError("snapshot observation_count does not match asset provenance")
    provenance_keys = {
        (record.source_kind.value, record.source_system, record.source_record_id)
        for record in all_provenance
    }
    if len(provenance_keys) != len(all_provenance):
        raise AssetReconciliationError("snapshot provenance records must be unique")
    actual_source_counts = Counter(record.source_kind.value for record in all_provenance)
    if dict(snapshot.source_counts) != dict(sorted(actual_source_counts.items())):
        raise AssetReconciliationError("snapshot source_counts do not match asset provenance")

    as_of = _utc(snapshot.as_of, "snapshot as_of")
    for asset in snapshot.assets:
        if not asset.provenance:
            raise AssetReconciliationError("asset provenance may not be empty")
        current_records: list[ProvenanceRecord] = []
        for record in asset.provenance:
            observed = _utc(record.observed_at, "provenance observed_at")
            if observed > as_of:
                raise AssetReconciliationError("asset provenance occurs after snapshot as_of")
            expected_freshness = (
                FreshnessState.CURRENT
                if _utc(record.expires_at, "provenance expires_at") > as_of
                else FreshnessState.STALE
            )
            if record.freshness is not expected_freshness:
                raise AssetReconciliationError("provenance freshness does not match snapshot as_of")
            if expected_freshness is FreshnessState.CURRENT:
                current_records.append(record)
        expected_asset_freshness = (
            FreshnessState.CURRENT if current_records else FreshnessState.STALE
        )
        if asset.freshness is not expected_asset_freshness:
            raise AssetReconciliationError("asset freshness does not match its provenance")
        observed_times = [record.observed_at for record in asset.provenance]
        if asset.last_seen_at != max(observed_times):
            raise AssetReconciliationError("asset last_seen_at does not match provenance")
        if asset.prior_asset_ids:
            if asset.first_seen_at > min(observed_times):
                raise AssetReconciliationError(
                    "continued asset first_seen_at exceeds current provenance"
                )
        elif asset.first_seen_at != min(observed_times):
            raise AssetReconciliationError("new asset first_seen_at does not match provenance")

        asset_conflicts = conflicts_by_asset.get(asset.asset_id, [])
        expected_confidence = max(
            record.confidence_bps for record in (current_records or list(asset.provenance))
        )
        if expected_asset_freshness is FreshnessState.STALE:
            expected_confidence = min(expected_confidence, 5000)
        if asset_conflicts:
            expected_confidence = max(0, expected_confidence - 1000)
        if asset.confidence_bps != expected_confidence:
            raise AssetReconciliationError(
                "asset confidence does not match provenance and conflicts"
            )

        conflict_kinds = {item.kind for item in asset_conflicts}
        if not asset.prior_asset_ids:
            if asset.asset_id != _asset_id(snapshot.tenant_id, asset.identity_anchor):
                raise AssetReconciliationError("new asset_id does not match its identity anchor")
        elif "prior_identity_merge" in conflict_kinds or "prior_identity_split" in conflict_kinds:
            expected_id = _ambiguous_asset_id(
                snapshot.tenant_id, asset.identifiers, asset.prior_asset_ids
            )
            if asset.asset_id != expected_id:
                raise AssetReconciliationError(
                    "ambiguous asset_id does not match its identity evidence"
                )
        elif len(asset.prior_asset_ids) == 1:
            if asset.asset_id != asset.prior_asset_ids[0]:
                raise AssetReconciliationError("continued asset did not retain its prior asset_id")
        else:
            raise AssetReconciliationError(
                "multiple prior asset IDs require an identity merge conflict"
            )

        permitted_conflict_provenance = {record.provenance_sha256 for record in asset.provenance}
        if snapshot.prior_snapshot_sha256 is not None:
            permitted_conflict_provenance.add(snapshot.prior_snapshot_sha256)
        if any(
            claim.provenance_sha256 not in permitted_conflict_provenance
            for conflict in asset_conflicts
            for claim in conflict.claims
        ):
            raise AssetReconciliationError("conflict claim is not bound to asset provenance")


def _conflict(
    asset_id: str, kind: str, field: str, claims: Iterable[ConflictClaim]
) -> AssetConflict:
    canonical = tuple(sorted(set(claims)))
    core = {
        "asset_id": asset_id,
        "claims": [item.to_dict() for item in canonical],
        "field": field,
        "kind": kind,
        "status": "unresolved",
    }
    return AssetConflict(
        conflict_id=_derived_id("ARC", _digest(CONFLICT_DOMAIN, core)),
        asset_id=asset_id,
        kind=kind,
        field=field,
        status="unresolved",
        claims=canonical,
    )


def _observation_digest(observation: AssetObservation) -> str:
    return _digest("sunderkey.asset-reconciliation.observation.v1", observation.to_dict())


def reconcile_asset_observations(
    tenant_id: str,
    as_of: str,
    observations: Sequence[AssetObservation],
    *,
    prior_snapshot: AssetReconciliationSnapshot | None = None,
) -> AssetReconciliationSnapshot:
    """Reconcile a closed caller-supplied observation set without side effects."""

    _identifier_text(tenant_id, "tenant_id")
    instant = _utc(as_of, "reconciliation as_of")
    if not observations or len(observations) > MAX_OBSERVATIONS:
        raise AssetReconciliationError("observation count is invalid")
    canonical = tuple(sorted(observations, key=lambda item: item.provenance_key))
    if len({item.provenance_key for item in canonical}) != len(canonical):
        raise AssetReconciliationError("source records must be unique")
    if any(item.tenant_id != tenant_id for item in canonical):
        raise AssetReconciliationError("observations may not cross tenant boundaries")
    for observation in canonical:
        observation.is_current(as_of)
    if prior_snapshot is not None:
        AssetReconciliationSnapshot.from_dict(prior_snapshot.to_dict())
        if prior_snapshot.tenant_id != tenant_id:
            raise AssetReconciliationError("prior snapshot may not cross tenant boundaries")
        if _utc(prior_snapshot.as_of, "prior snapshot as_of") >= instant:
            raise AssetReconciliationError("prior snapshot must precede reconciliation as_of")

    union = _UnionFind(len(canonical))
    seen_identifiers: dict[str, int] = {}
    for index, observation in enumerate(canonical):
        for identifier in observation.identifiers:
            if not identifier.links_identity:
                continue
            prior_index = seen_identifiers.setdefault(identifier.key, index)
            union.union(index, prior_index)
    components: dict[int, list[AssetObservation]] = defaultdict(list)
    for index, observation in enumerate(canonical):
        components[union.find(index)].append(observation)

    prior_assets = prior_snapshot.assets if prior_snapshot is not None else ()
    prior_assets_by_identifier: dict[str, set[str]] = defaultdict(set)
    for asset in prior_assets:
        for identifier in asset.identifiers:
            if identifier.links_identity:
                prior_assets_by_identifier[identifier.key].add(asset.asset_id)
    prepared: list[tuple[list[AssetObservation], tuple[AssetIdentifier, ...], tuple[str, ...]]] = []
    for group in components.values():
        identifiers = tuple(
            sorted(
                {item for observation in group for item in observation.identifiers},
                key=lambda x: x.key,
            )
        )
        keys = {item.key for item in identifiers if item.links_identity}
        matches = tuple(
            sorted(
                {asset_id for key in keys for asset_id in prior_assets_by_identifier.get(key, ())}
            )
        )
        prepared.append((group, identifiers, matches))

    match_use = Counter(asset_id for _, _, matches in prepared for asset_id in matches)
    assets: list[ReconciledAsset] = []
    conflicts: list[AssetConflict] = []
    prior_by_id = {item.asset_id: item for item in prior_assets}

    for group, identifiers, matches in prepared:
        linking = [item for item in identifiers if item.links_identity]
        if not linking:
            raise AssetReconciliationError(
                "every component requires an identity-linking identifier"
            )
        anchor = min(linking, key=lambda item: (IDENTITY_PRIORITY[item.kind], item.key))
        clean_reuse = len(matches) == 1 and match_use[matches[0]] == 1
        if clean_reuse:
            asset_id = matches[0]
        elif matches:
            asset_id = _ambiguous_asset_id(tenant_id, identifiers, matches)
        else:
            asset_id = _asset_id(tenant_id, anchor)
        current = [item for item in group if item.is_current(as_of)]
        freshness = FreshnessState.CURRENT if current else FreshnessState.STALE
        confidence = max(item.confidence_bps for item in (current or group))
        if freshness is FreshnessState.STALE:
            confidence = min(confidence, 5000)
        provenance = tuple(
            ProvenanceRecord(
                source_kind=item.source_kind,
                source_system=item.source_system,
                source_record_id=item.source_record_id,
                provenance_sha256=item.provenance_sha256,
                observed_at=item.observed_at,
                expires_at=item.expires_at,
                confidence_bps=item.confidence_bps,
                freshness=(
                    FreshnessState.CURRENT if item.is_current(as_of) else FreshnessState.STALE
                ),
            )
            for item in group
        )
        ownership_entries = {
            OwnershipHistoryEntry(
                owner_ref=claim.owner_ref,
                effective_from=claim.effective_from,
                effective_until=claim.effective_until,
                observation_sha256=_observation_digest(observation),
            )
            for observation in group
            for claim in observation.ownership
        }
        for match in matches:
            ownership_entries.update(prior_by_id[match].ownership_history)
        claim_observations = current or group
        all_claims = tuple(
            sorted({claim for observation in claim_observations for claim in observation.claims})
        )
        asset_conflicts: list[AssetConflict] = []
        if len(matches) > 1:
            asset_conflicts.append(
                _conflict(
                    asset_id,
                    "prior_identity_merge",
                    "prior_asset_ids",
                    (
                        ConflictClaim(
                            value=item,
                            confidence_bps=10000,
                            provenance_sha256=prior_snapshot.snapshot_sha256,
                        )
                        for item in matches
                    ),
                )
            )
        elif matches and match_use[matches[0]] > 1:
            competing_anchors = sorted(
                item.key
                for _, component_identifiers, component_matches in prepared
                if matches[0] in component_matches
                for item in component_identifiers
                if item.links_identity
            )
            asset_conflicts.append(
                _conflict(
                    asset_id,
                    "prior_identity_split",
                    matches[0],
                    (
                        ConflictClaim(
                            value=value,
                            confidence_bps=10000,
                            provenance_sha256=prior_snapshot.snapshot_sha256,
                        )
                        for value in competing_anchors
                    ),
                )
            )
        claim_sources: dict[str, list[tuple[AttributeClaim, AssetObservation]]] = defaultdict(list)
        for observation in current:
            for claim in observation.claims:
                claim_sources[claim.name].append((claim, observation))
        for name, entries in claim_sources.items():
            if len({claim.value for claim, _ in entries}) > 1:
                asset_conflicts.append(
                    _conflict(
                        asset_id,
                        "attribute_disagreement",
                        name,
                        (
                            ConflictClaim(
                                value=claim.value,
                                confidence_bps=observation.confidence_bps,
                                provenance_sha256=observation.provenance_sha256,
                            )
                            for claim, observation in entries
                        ),
                    )
                )
        active_owners: list[tuple[OwnershipClaim, AssetObservation]] = []
        for observation in current:
            for claim in observation.ownership:
                if _utc(claim.effective_from, "ownership effective_from") <= instant and (
                    claim.effective_until is None
                    or _utc(claim.effective_until, "ownership effective_until") > instant
                ):
                    active_owners.append((claim, observation))
        if len({claim.owner_ref for claim, _ in active_owners}) > 1:
            asset_conflicts.append(
                _conflict(
                    asset_id,
                    "ownership_disagreement",
                    "current_owner",
                    (
                        ConflictClaim(
                            value=claim.owner_ref,
                            confidence_bps=observation.confidence_bps,
                            provenance_sha256=observation.provenance_sha256,
                        )
                        for claim, observation in active_owners
                    ),
                )
            )
        if asset_conflicts:
            confidence = max(0, confidence - 1000)
        band = (
            ConfidenceBand.HIGH
            if confidence >= 8000
            else ConfidenceBand.MEDIUM
            if confidence >= 5000
            else ConfidenceBand.LOW
        )
        asset = ReconciledAsset(
            asset_id=asset_id,
            tenant_id=tenant_id,
            identity_anchor=anchor,
            prior_asset_ids=matches,
            identifiers=identifiers,
            confidence_bps=confidence,
            confidence_band=band,
            freshness=freshness,
            first_seen_at=min(
                [item.observed_at for item in group]
                + [prior_by_id[item].first_seen_at for item in matches]
            ),
            last_seen_at=max(item.observed_at for item in group),
            claims=all_claims,
            ownership_history=tuple(ownership_entries),
            provenance=provenance,
        )
        assets.append(asset)
        conflicts.extend(asset_conflicts)

    source_counts = tuple(sorted(Counter(item.source_kind.value for item in canonical).items()))
    core = {
        "as_of": as_of,
        "assets": [item.to_dict() for item in sorted(assets, key=lambda item: item.asset_id)],
        "conflicts": [
            item.to_dict() for item in sorted(conflicts, key=lambda item: item.conflict_id)
        ],
        "effects": dict(NO_EFFECTS),
        "observation_count": len(canonical),
        "prior_snapshot_sha256": prior_snapshot.snapshot_sha256 if prior_snapshot else None,
        "schema_version": SCHEMA_VERSION,
        "source_counts": dict(source_counts),
        "tenant_id": tenant_id,
    }
    digest = _digest(SNAPSHOT_DOMAIN, core)
    return AssetReconciliationSnapshot(
        snapshot_id=_derived_id("ARS", digest),
        snapshot_sha256=digest,
        tenant_id=tenant_id,
        as_of=as_of,
        assets=tuple(assets),
        conflicts=tuple(conflicts),
        observation_count=len(canonical),
        source_counts=source_counts,
        prior_snapshot_sha256=prior_snapshot.snapshot_sha256 if prior_snapshot else None,
    )


def verify_asset_reconciliation_snapshot_from_sources(
    snapshot: AssetReconciliationSnapshot,
    observations: Sequence[AssetObservation],
    *,
    prior_snapshot: AssetReconciliationSnapshot | None = None,
) -> AssetReconciliationSnapshot:
    """Replay a stored snapshot from its complete caller-supplied observation set."""

    if not isinstance(snapshot, AssetReconciliationSnapshot):
        raise AssetReconciliationError("asset snapshot has the wrong type")
    AssetReconciliationSnapshot.from_dict(snapshot.to_dict())
    expected = reconcile_asset_observations(
        snapshot.tenant_id,
        snapshot.as_of,
        observations,
        prior_snapshot=prior_snapshot,
    )
    if expected != snapshot:
        raise AssetReconciliationError("asset snapshot does not match source replay")
    return snapshot


def load_asset_observations(path: str | Path) -> tuple[AssetObservation, ...]:
    """Load a strict local JSON observation array without performing I/O beyond the file."""

    raw = _load_json_path(path, "asset observation file")
    if not isinstance(raw, list):
        raise AssetReconciliationError("asset observation document must be an array")
    return tuple(AssetObservation.from_dict(item) for item in raw)


def load_asset_reconciliation_snapshot(path: str | Path) -> AssetReconciliationSnapshot:
    """Load and verify a local content-addressed snapshot."""

    raw = _load_json_path(path, "asset snapshot file")
    return AssetReconciliationSnapshot.from_dict(raw)
