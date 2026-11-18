"""Deterministic, import-only defender telemetry adapter contracts.

This module normalizes caller-supplied telemetry references. It has no source
client, network transport, credential resolver, collection loop, persistence,
target effect, or qualification effect.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

SCHEMA_VERSION = 1
NO_BUILTIN_NETWORK = True
MAX_EVENTS = 512
MAX_SECONDS = 31_536_000
NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "collection": "none",
        "network": "none",
        "persistence": "none",
        "qualification": "none",
        "source_write": "none",
        "target_action": "none",
    }
)

_REF_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}:[A-Za-z0-9][A-Za-z0-9._~:/+-]{0,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?$")
_REGION_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:authorization|cookie|password|passwd|secret|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|client[_-]?secret)\b\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)


class DefenderTelemetryAdapterError(ValueError):
    """Raised when telemetry import or normalization fails closed."""


class TelemetryDomain(StrEnum):
    NETWORK = "network"
    IDENTITY = "identity"
    CLOUD = "cloud"
    APPLICATION_API = "application_api"
    ENDPOINT = "endpoint"
    SIEM = "siem"


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    DATA_ACCESS = "data_access"
    EXECUTION = "execution"
    NETWORK_FLOW = "network_flow"
    RESOURCE_CHANGE = "resource_change"
    SECURITY_ALERT = "security_alert"


class EventOutcome(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FAILURE = "failure"
    SUCCESS = "success"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise DefenderTelemetryAdapterError("value is not canonical JSON") from exc
    if _SECRET_RE.search(encoded):
        raise DefenderTelemetryAdapterError("secret-like material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": dict(body), "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Mapping[str, Any], fields: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise DefenderTelemetryAdapterError(f"{label} fields are invalid")


def _ref(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None or _SECRET_RE.search(value):
        raise DefenderTelemetryAdapterError(f"{label} must be a safe opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise DefenderTelemetryAdapterError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise DefenderTelemetryAdapterError(f"{label} must be a sha256 digest")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        raise DefenderTelemetryAdapterError(f"{label} must be a canonical code")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
        raise DefenderTelemetryAdapterError(f"{label} must be an exact version")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DefenderTelemetryAdapterError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DefenderTelemetryAdapterError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise DefenderTelemetryAdapterError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _plus_seconds(value: str, seconds: int) -> str:
    return (_instant(value) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _bounded_seconds(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= MAX_SECONDS:
        raise DefenderTelemetryAdapterError(f"{label} is outside the supported range")
    return value


def _enum(value: Any, enum_type: type[StrEnum], label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise DefenderTelemetryAdapterError(f"{label} is invalid") from exc


def _bounded_unique(
    values: Sequence[Any], label: str, maximum: int = MAX_EVENTS
) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes)):
        raise DefenderTelemetryAdapterError(f"{label} must be a sequence")
    result = tuple(values)
    try:
        unique_count = len(set(result))
    except TypeError as exc:
        raise DefenderTelemetryAdapterError(f"{label} contains an invalid item") from exc
    if not result or len(result) > maximum or unique_count != len(result):
        raise DefenderTelemetryAdapterError(f"{label} must be a bounded unique sequence")
    return result


def _metadata(raw: Mapping[str, Any], kind: str) -> None:
    if raw.get("kind") != kind or raw.get("schema_version") != SCHEMA_VERSION:
        raise DefenderTelemetryAdapterError("contract metadata is invalid")
    if "effects" in raw and raw.get("effects") != dict(NO_EFFECTS):
        raise DefenderTelemetryAdapterError("contract attempts effect escalation")


@dataclass(frozen=True, slots=True)
class FreshnessPolicy:
    maximum_event_age_seconds: int
    maximum_ingest_delay_seconds: int
    maximum_future_skew_seconds: int
    replay_window_seconds: int

    def __post_init__(self) -> None:
        _bounded_seconds(self.maximum_event_age_seconds, "maximum_event_age_seconds")
        _bounded_seconds(self.maximum_ingest_delay_seconds, "maximum_ingest_delay_seconds")
        _bounded_seconds(
            self.maximum_future_skew_seconds,
            "maximum_future_skew_seconds",
            allow_zero=True,
        )
        _bounded_seconds(self.replay_window_seconds, "replay_window_seconds")
        if self.replay_window_seconds < self.maximum_event_age_seconds:
            raise DefenderTelemetryAdapterError("replay window must cover maximum event age")

    def to_dict(self) -> dict[str, int]:
        return {
            "maximum_event_age_seconds": self.maximum_event_age_seconds,
            "maximum_future_skew_seconds": self.maximum_future_skew_seconds,
            "maximum_ingest_delay_seconds": self.maximum_ingest_delay_seconds,
            "replay_window_seconds": self.replay_window_seconds,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> FreshnessPolicy:
        fields = {
            "maximum_event_age_seconds",
            "maximum_future_skew_seconds",
            "maximum_ingest_delay_seconds",
            "replay_window_seconds",
        }
        _exact(raw, fields, "freshness policy")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class TelemetrySourceBinding:
    tenant_ref: str
    engagement_ref: str
    scope_sha256: str
    source_ref: str
    telemetry_domain: TelemetryDomain | str
    adapter_ref: str
    adapter_version: str
    source_schema_sha256: str
    mapping_sha256: str
    custody_policy_sha256: str
    processing_region: str
    freshness_policy: FreshnessPolicy
    effective_at: str
    expires_at: str
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.telemetry-source-binding.v1"

    def __post_init__(self) -> None:
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        _digest(self.scope_sha256, "scope_sha256")
        _ref(self.source_ref, "source_ref", "sourceref")
        object.__setattr__(
            self,
            "telemetry_domain",
            _enum(self.telemetry_domain, TelemetryDomain, "telemetry_domain"),
        )
        _ref(self.adapter_ref, "adapter_ref", "adapterref")
        _version(self.adapter_version, "adapter_version")
        for name in ("source_schema_sha256", "mapping_sha256", "custody_policy_sha256"):
            _digest(getattr(self, name), name)
        if (
            not isinstance(self.processing_region, str)
            or _REGION_RE.fullmatch(self.processing_region) is None
        ):
            raise DefenderTelemetryAdapterError("processing_region is invalid")
        if not isinstance(self.freshness_policy, FreshnessPolicy):
            raise DefenderTelemetryAdapterError("freshness_policy is invalid")
        _time(self.effective_at, "effective_at")
        _time(self.expires_at, "expires_at")
        if _instant(self.expires_at) <= _instant(self.effective_at):
            raise DefenderTelemetryAdapterError("expires_at must follow effective_at")
        binding_id, digest = _identity("TSB", self.KIND, self.body())
        object.__setattr__(self, "binding_id", binding_id)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "adapter_ref": self.adapter_ref,
            "adapter_version": self.adapter_version,
            "custody_policy_sha256": self.custody_policy_sha256,
            "effective_at": self.effective_at,
            "engagement_ref": self.engagement_ref,
            "expires_at": self.expires_at,
            "freshness_policy": self.freshness_policy.to_dict(),
            "mapping_sha256": self.mapping_sha256,
            "processing_region": self.processing_region,
            "scope_sha256": self.scope_sha256,
            "source_ref": self.source_ref,
            "source_schema_sha256": self.source_schema_sha256,
            "telemetry_domain": self.telemetry_domain.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TelemetrySourceBinding:
        fields = {
            "adapter_ref",
            "adapter_version",
            "binding_id",
            "binding_sha256",
            "custody_policy_sha256",
            "effective_at",
            "engagement_ref",
            "expires_at",
            "freshness_policy",
            "kind",
            "mapping_sha256",
            "processing_region",
            "schema_version",
            "scope_sha256",
            "source_ref",
            "source_schema_sha256",
            "telemetry_domain",
            "tenant_ref",
        }
        _exact(raw, fields, "telemetry source binding")
        _metadata(raw, cls.KIND)
        candidate = cls(
            tenant_ref=raw["tenant_ref"],
            engagement_ref=raw["engagement_ref"],
            scope_sha256=raw["scope_sha256"],
            source_ref=raw["source_ref"],
            telemetry_domain=raw["telemetry_domain"],
            adapter_ref=raw["adapter_ref"],
            adapter_version=raw["adapter_version"],
            source_schema_sha256=raw["source_schema_sha256"],
            mapping_sha256=raw["mapping_sha256"],
            custody_policy_sha256=raw["custody_policy_sha256"],
            processing_region=raw["processing_region"],
            freshness_policy=FreshnessPolicy.from_dict(raw["freshness_policy"]),
            effective_at=raw["effective_at"],
            expires_at=raw["expires_at"],
        )
        if candidate.to_dict() != dict(raw):
            raise DefenderTelemetryAdapterError("binding identity does not match content")
        return candidate


@dataclass(frozen=True, slots=True)
class TelemetryEnvelopeReference:
    binding_id: str
    binding_sha256: str
    tenant_ref: str
    engagement_ref: str
    scope_sha256: str
    source_ref: str
    telemetry_domain: TelemetryDomain | str
    source_event_ref: str
    source_sequence: int
    occurred_at: str
    received_at: str
    raw_event_sha256: str
    artifact_ref: str
    custody_sha256: str
    custody_status: str = "durable_verified"
    redacted: bool = True
    envelope_id: str = field(init=False)
    envelope_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.telemetry-envelope-reference.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.binding_id, str) or not self.binding_id.startswith("TSB-"):
            raise DefenderTelemetryAdapterError("binding_id is invalid")
        _digest(self.binding_sha256, "binding_sha256")
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        _digest(self.scope_sha256, "scope_sha256")
        _ref(self.source_ref, "source_ref", "sourceref")
        object.__setattr__(
            self,
            "telemetry_domain",
            _enum(self.telemetry_domain, TelemetryDomain, "telemetry_domain"),
        )
        _ref(self.source_event_ref, "source_event_ref", "eventref")
        if (
            isinstance(self.source_sequence, bool)
            or not isinstance(self.source_sequence, int)
            or self.source_sequence < 0
            or self.source_sequence > 2**63 - 1
        ):
            raise DefenderTelemetryAdapterError("source_sequence is invalid")
        _time(self.occurred_at, "occurred_at")
        _time(self.received_at, "received_at")
        _digest(self.raw_event_sha256, "raw_event_sha256")
        _ref(self.artifact_ref, "artifact_ref", "artifactref")
        _digest(self.custody_sha256, "custody_sha256")
        if self.custody_status != "durable_verified":
            raise DefenderTelemetryAdapterError("telemetry custody must be durable_verified")
        if self.redacted is not True:
            raise DefenderTelemetryAdapterError("telemetry envelope must be redacted")
        envelope_id, digest = _identity("TER", self.KIND, self.body())
        object.__setattr__(self, "envelope_id", envelope_id)
        object.__setattr__(self, "envelope_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "custody_sha256": self.custody_sha256,
            "custody_status": self.custody_status,
            "engagement_ref": self.engagement_ref,
            "occurred_at": self.occurred_at,
            "raw_event_sha256": self.raw_event_sha256,
            "received_at": self.received_at,
            "redacted": self.redacted,
            "scope_sha256": self.scope_sha256,
            "source_event_ref": self.source_event_ref,
            "source_ref": self.source_ref,
            "source_sequence": self.source_sequence,
            "telemetry_domain": self.telemetry_domain.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "envelope_sha256": self.envelope_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TelemetryEnvelopeReference:
        fields = {
            "artifact_ref",
            "binding_id",
            "binding_sha256",
            "custody_sha256",
            "custody_status",
            "engagement_ref",
            "envelope_id",
            "envelope_sha256",
            "kind",
            "occurred_at",
            "raw_event_sha256",
            "received_at",
            "redacted",
            "schema_version",
            "scope_sha256",
            "source_event_ref",
            "source_ref",
            "source_sequence",
            "telemetry_domain",
            "tenant_ref",
        }
        _exact(raw, fields, "telemetry envelope reference")
        _metadata(raw, cls.KIND)
        values = {
            key: raw[key]
            for key in fields - {"envelope_id", "envelope_sha256", "kind", "schema_version"}
        }
        candidate = cls(**values)
        if candidate.to_dict() != dict(raw):
            raise DefenderTelemetryAdapterError("envelope identity does not match content")
        return candidate


@dataclass(frozen=True, slots=True)
class NormalizedAttribute:
    name: str
    value_ref: str

    def __post_init__(self) -> None:
        _code(self.name, "attribute name")
        _ref(self.value_ref, "attribute value_ref")

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value_ref": self.value_ref}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> NormalizedAttribute:
        _exact(raw, {"name", "value_ref"}, "normalized attribute")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class NormalizationProjection:
    source_event_ref: str
    raw_event_sha256: str
    mapping_sha256: str
    event_category: EventCategory | str
    operation_code: str
    outcome: EventOutcome | str
    severity: Severity | str
    actor_ref: str
    subject_ref: str
    resource_ref: str
    attributes: tuple[NormalizedAttribute, ...] = ()

    def __post_init__(self) -> None:
        _ref(self.source_event_ref, "source_event_ref", "eventref")
        _digest(self.raw_event_sha256, "raw_event_sha256")
        _digest(self.mapping_sha256, "mapping_sha256")
        object.__setattr__(
            self,
            "event_category",
            _enum(self.event_category, EventCategory, "event_category"),
        )
        _code(self.operation_code, "operation_code")
        object.__setattr__(self, "outcome", _enum(self.outcome, EventOutcome, "outcome"))
        object.__setattr__(self, "severity", _enum(self.severity, Severity, "severity"))
        for name in ("actor_ref", "subject_ref", "resource_ref"):
            _ref(getattr(self, name), name, "entityref")
        attributes = tuple(self.attributes)
        if any(not isinstance(item, NormalizedAttribute) for item in attributes):
            raise DefenderTelemetryAdapterError("normalized attributes are invalid")
        attributes = tuple(sorted(attributes, key=lambda item: item.name))
        if len(attributes) > 64 or len({item.name for item in attributes}) != len(attributes):
            raise DefenderTelemetryAdapterError("normalized attributes are invalid")
        object.__setattr__(self, "attributes", attributes)


class TelemetryNormalizer(Protocol):
    """Caller-supplied pure normalizer. Implementations receive references only."""

    def normalize(
        self,
        *,
        binding: TelemetrySourceBinding,
        envelope: TelemetryEnvelopeReference,
    ) -> NormalizationProjection: ...


@dataclass(frozen=True, slots=True)
class NormalizedTelemetryEvent:
    binding_id: str
    binding_sha256: str
    tenant_ref: str
    engagement_ref: str
    scope_sha256: str
    source_ref: str
    telemetry_domain: TelemetryDomain | str
    envelope_id: str
    envelope_sha256: str
    source_event_ref: str
    source_sequence: int
    occurred_at: str
    received_at: str
    raw_event_sha256: str
    mapping_sha256: str
    event_category: EventCategory | str
    operation_code: str
    outcome: EventOutcome | str
    severity: Severity | str
    actor_ref: str
    subject_ref: str
    resource_ref: str
    attributes: tuple[NormalizedAttribute, ...]
    normalized_at: str
    event_id: str = field(init=False)
    event_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.normalized-telemetry-event.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.binding_id, str) or not self.binding_id.startswith("TSB-"):
            raise DefenderTelemetryAdapterError("binding_id is invalid")
        _digest(self.binding_sha256, "binding_sha256")
        _ref(self.tenant_ref, "tenant_ref", "tenantref")
        _ref(self.engagement_ref, "engagement_ref", "engagementref")
        _digest(self.scope_sha256, "scope_sha256")
        _ref(self.source_ref, "source_ref", "sourceref")
        object.__setattr__(
            self,
            "telemetry_domain",
            _enum(self.telemetry_domain, TelemetryDomain, "telemetry_domain"),
        )
        if not isinstance(self.envelope_id, str) or not self.envelope_id.startswith("TER-"):
            raise DefenderTelemetryAdapterError("envelope_id is invalid")
        _digest(self.envelope_sha256, "envelope_sha256")
        _ref(self.source_event_ref, "source_event_ref", "eventref")
        if (
            isinstance(self.source_sequence, bool)
            or not isinstance(self.source_sequence, int)
            or self.source_sequence < 0
            or self.source_sequence > 2**63 - 1
        ):
            raise DefenderTelemetryAdapterError("source_sequence is invalid")
        _time(self.occurred_at, "occurred_at")
        _time(self.received_at, "received_at")
        _digest(self.raw_event_sha256, "raw_event_sha256")
        _digest(self.mapping_sha256, "mapping_sha256")
        object.__setattr__(
            self,
            "event_category",
            _enum(self.event_category, EventCategory, "event_category"),
        )
        _code(self.operation_code, "operation_code")
        object.__setattr__(self, "outcome", _enum(self.outcome, EventOutcome, "outcome"))
        object.__setattr__(self, "severity", _enum(self.severity, Severity, "severity"))
        for name in ("actor_ref", "subject_ref", "resource_ref"):
            _ref(getattr(self, name), name, "entityref")
        attributes = tuple(self.attributes)
        if any(not isinstance(item, NormalizedAttribute) for item in attributes):
            raise DefenderTelemetryAdapterError("normalized attributes are invalid")
        attributes = tuple(sorted(attributes, key=lambda item: item.name))
        if len(attributes) > 64 or len({item.name for item in attributes}) != len(attributes):
            raise DefenderTelemetryAdapterError("normalized attributes are invalid")
        object.__setattr__(self, "attributes", attributes)
        _time(self.normalized_at, "normalized_at")
        event_id, digest = _identity("NTE", self.KIND, self.body())
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "actor_ref": self.actor_ref,
            "attributes": [item.to_dict() for item in self.attributes],
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "engagement_ref": self.engagement_ref,
            "envelope_id": self.envelope_id,
            "envelope_sha256": self.envelope_sha256,
            "event_category": self.event_category.value,
            "mapping_sha256": self.mapping_sha256,
            "normalized_at": self.normalized_at,
            "occurred_at": self.occurred_at,
            "operation_code": self.operation_code,
            "outcome": self.outcome.value,
            "raw_event_sha256": self.raw_event_sha256,
            "received_at": self.received_at,
            "resource_ref": self.resource_ref,
            "scope_sha256": self.scope_sha256,
            "severity": self.severity.value,
            "source_event_ref": self.source_event_ref,
            "source_ref": self.source_ref,
            "source_sequence": self.source_sequence,
            "subject_ref": self.subject_ref,
            "telemetry_domain": self.telemetry_domain.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_sha256": self.event_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> NormalizedTelemetryEvent:
        fields = {
            "actor_ref",
            "attributes",
            "binding_id",
            "binding_sha256",
            "engagement_ref",
            "envelope_id",
            "envelope_sha256",
            "event_category",
            "event_id",
            "event_sha256",
            "kind",
            "mapping_sha256",
            "normalized_at",
            "occurred_at",
            "operation_code",
            "outcome",
            "raw_event_sha256",
            "received_at",
            "resource_ref",
            "schema_version",
            "scope_sha256",
            "severity",
            "source_event_ref",
            "source_ref",
            "source_sequence",
            "subject_ref",
            "telemetry_domain",
            "tenant_ref",
        }
        _exact(raw, fields, "normalized telemetry event")
        _metadata(raw, cls.KIND)
        values = {
            key: raw[key]
            for key in fields - {"event_id", "event_sha256", "kind", "schema_version", "attributes"}
        }
        candidate = cls(
            **values,
            attributes=tuple(NormalizedAttribute.from_dict(item) for item in raw["attributes"]),
        )
        if candidate.to_dict() != dict(raw):
            raise DefenderTelemetryAdapterError("normalized event identity does not match content")
        return candidate


@dataclass(frozen=True, slots=True)
class ReplayMarker:
    binding_id: str
    binding_sha256: str
    tenant_ref: str
    engagement_ref: str
    scope_sha256: str
    source_event_ref: str
    raw_event_sha256: str
    accepted_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.binding_id, str) or not self.binding_id.startswith("TSB-"):
            raise DefenderTelemetryAdapterError("replay binding_id is invalid")
        _digest(self.binding_sha256, "replay binding_sha256")
        _ref(self.tenant_ref, "replay tenant_ref", "tenantref")
        _ref(self.engagement_ref, "replay engagement_ref", "engagementref")
        _digest(self.scope_sha256, "replay scope_sha256")
        _ref(self.source_event_ref, "replay source_event_ref", "eventref")
        _digest(self.raw_event_sha256, "replay raw_event_sha256")
        _time(self.accepted_at, "replay accepted_at")
        _time(self.expires_at, "replay expires_at")
        if _instant(self.expires_at) <= _instant(self.accepted_at):
            raise DefenderTelemetryAdapterError("replay marker expiry is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted_at": self.accepted_at,
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "engagement_ref": self.engagement_ref,
            "expires_at": self.expires_at,
            "raw_event_sha256": self.raw_event_sha256,
            "scope_sha256": self.scope_sha256,
            "source_event_ref": self.source_event_ref,
            "tenant_ref": self.tenant_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ReplayMarker:
        fields = {
            "accepted_at",
            "binding_id",
            "binding_sha256",
            "engagement_ref",
            "expires_at",
            "raw_event_sha256",
            "scope_sha256",
            "source_event_ref",
            "tenant_ref",
        }
        _exact(raw, fields, "replay marker")
        return cls(**raw)


def _validate_context(
    binding: TelemetrySourceBinding,
    envelope: TelemetryEnvelopeReference,
) -> None:
    expected = (
        binding.binding_id,
        binding.binding_sha256,
        binding.tenant_ref,
        binding.engagement_ref,
        binding.scope_sha256,
        binding.source_ref,
        binding.telemetry_domain,
    )
    actual = (
        envelope.binding_id,
        envelope.binding_sha256,
        envelope.tenant_ref,
        envelope.engagement_ref,
        envelope.scope_sha256,
        envelope.source_ref,
        envelope.telemetry_domain,
    )
    if actual != expected:
        raise DefenderTelemetryAdapterError("telemetry envelope crosses its bound context")


def _validate_freshness(
    binding: TelemetrySourceBinding,
    envelope: TelemetryEnvelopeReference,
    imported_at: str,
) -> None:
    imported = _instant(imported_at)
    occurred = _instant(envelope.occurred_at)
    received = _instant(envelope.received_at)
    policy = binding.freshness_policy
    if not _instant(binding.effective_at) <= imported < _instant(binding.expires_at):
        raise DefenderTelemetryAdapterError("source binding is not active at import time")
    if (
        occurred > received
        and int((occurred - received).total_seconds()) > policy.maximum_future_skew_seconds
    ):
        raise DefenderTelemetryAdapterError("event exceeds allowed source clock skew")
    if (
        received > imported
        and int((received - imported).total_seconds()) > policy.maximum_future_skew_seconds
    ):
        raise DefenderTelemetryAdapterError("receipt exceeds allowed import clock skew")
    if int((imported - occurred).total_seconds()) > policy.maximum_event_age_seconds:
        raise DefenderTelemetryAdapterError("telemetry event is stale")
    if int((imported - received).total_seconds()) > policy.maximum_ingest_delay_seconds:
        raise DefenderTelemetryAdapterError("telemetry import is stale")


@dataclass(frozen=True, slots=True)
class TelemetryIngestBatch:
    binding: TelemetrySourceBinding
    imported_at: str
    envelopes: tuple[TelemetryEnvelopeReference, ...]
    events: tuple[NormalizedTelemetryEvent, ...]
    replay_markers: tuple[ReplayMarker, ...]
    batch_id: str = field(init=False)
    batch_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.telemetry-ingest-batch.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.binding, TelemetrySourceBinding):
            raise DefenderTelemetryAdapterError("binding is invalid")
        _time(self.imported_at, "imported_at")
        envelopes = tuple(self.envelopes)
        events = tuple(self.events)
        markers = tuple(self.replay_markers)
        if (
            any(not isinstance(item, TelemetryEnvelopeReference) for item in envelopes)
            or any(not isinstance(item, NormalizedTelemetryEvent) for item in events)
            or any(not isinstance(item, ReplayMarker) for item in markers)
        ):
            raise DefenderTelemetryAdapterError("batch component type is invalid")
        envelopes = tuple(sorted(envelopes, key=lambda item: item.source_sequence))
        events = tuple(sorted(events, key=lambda item: item.source_sequence))
        markers = tuple(sorted(markers, key=lambda item: item.source_event_ref))
        if not envelopes or len(envelopes) > MAX_EVENTS:
            raise DefenderTelemetryAdapterError("batch event count is invalid")
        if len(events) != len(envelopes) or len(markers) != len(envelopes):
            raise DefenderTelemetryAdapterError("batch components are incomplete")
        if len({item.source_event_ref for item in envelopes}) != len(envelopes):
            raise DefenderTelemetryAdapterError("source event reference is duplicated")
        if len({item.raw_event_sha256 for item in envelopes}) != len(envelopes):
            raise DefenderTelemetryAdapterError("raw telemetry digest is duplicated")
        if len({item.source_sequence for item in envelopes}) != len(envelopes):
            raise DefenderTelemetryAdapterError("source sequence is duplicated")
        event_by_source = {item.source_event_ref: item for item in events}
        marker_by_source = {item.source_event_ref: item for item in markers}
        if len(event_by_source) != len(events) or len(marker_by_source) != len(markers):
            raise DefenderTelemetryAdapterError("batch contains duplicated normalized records")
        for envelope in envelopes:
            _validate_context(self.binding, envelope)
            _validate_freshness(self.binding, envelope, self.imported_at)
            event = event_by_source.get(envelope.source_event_ref)
            marker = marker_by_source.get(envelope.source_event_ref)
            if event is None or marker is None:
                raise DefenderTelemetryAdapterError("batch record mapping is incomplete")
            expected_event = (
                self.binding.binding_id,
                self.binding.binding_sha256,
                self.binding.tenant_ref,
                self.binding.engagement_ref,
                self.binding.scope_sha256,
                self.binding.source_ref,
                self.binding.telemetry_domain,
                envelope.envelope_id,
                envelope.envelope_sha256,
                envelope.source_sequence,
                envelope.source_event_ref,
                envelope.occurred_at,
                envelope.received_at,
                envelope.raw_event_sha256,
                self.binding.mapping_sha256,
                self.imported_at,
            )
            actual_event = (
                event.binding_id,
                event.binding_sha256,
                event.tenant_ref,
                event.engagement_ref,
                event.scope_sha256,
                event.source_ref,
                event.telemetry_domain,
                event.envelope_id,
                event.envelope_sha256,
                event.source_sequence,
                event.source_event_ref,
                event.occurred_at,
                event.received_at,
                event.raw_event_sha256,
                event.mapping_sha256,
                event.normalized_at,
            )
            if actual_event != expected_event:
                raise DefenderTelemetryAdapterError("normalized event crosses its bound context")
            expected_marker = (
                self.binding.binding_id,
                self.binding.binding_sha256,
                self.binding.tenant_ref,
                self.binding.engagement_ref,
                self.binding.scope_sha256,
                envelope.raw_event_sha256,
                self.imported_at,
                _plus_seconds(
                    self.imported_at,
                    self.binding.freshness_policy.replay_window_seconds,
                ),
            )
            actual_marker = (
                marker.binding_id,
                marker.binding_sha256,
                marker.tenant_ref,
                marker.engagement_ref,
                marker.scope_sha256,
                marker.raw_event_sha256,
                marker.accepted_at,
                marker.expires_at,
            )
            if actual_marker != expected_marker:
                raise DefenderTelemetryAdapterError("replay marker crosses its bound context")
        object.__setattr__(self, "envelopes", envelopes)
        object.__setattr__(self, "events", events)
        object.__setattr__(self, "replay_markers", markers)
        batch_id, digest = _identity("TIB", self.KIND, self.body())
        object.__setattr__(self, "batch_id", batch_id)
        object.__setattr__(self, "batch_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "effects": dict(NO_EFFECTS),
            "envelopes": [item.to_dict() for item in self.envelopes],
            "events": [item.to_dict() for item in self.events],
            "imported_at": self.imported_at,
            "replay_markers": [item.to_dict() for item in self.replay_markers],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "batch_sha256": self.batch_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> TelemetryIngestBatch:
        fields = {
            "batch_id",
            "batch_sha256",
            "binding",
            "effects",
            "envelopes",
            "events",
            "imported_at",
            "kind",
            "replay_markers",
            "schema_version",
        }
        _exact(raw, fields, "telemetry ingest batch")
        _metadata(raw, cls.KIND)
        candidate = cls(
            binding=TelemetrySourceBinding.from_dict(raw["binding"]),
            imported_at=raw["imported_at"],
            envelopes=tuple(
                TelemetryEnvelopeReference.from_dict(item) for item in raw["envelopes"]
            ),
            events=tuple(NormalizedTelemetryEvent.from_dict(item) for item in raw["events"]),
            replay_markers=tuple(ReplayMarker.from_dict(item) for item in raw["replay_markers"]),
        )
        if candidate.to_dict() != dict(raw):
            raise DefenderTelemetryAdapterError("batch identity does not match content")
        return candidate


def normalize_import_batch(
    binding: TelemetrySourceBinding,
    envelopes: Sequence[TelemetryEnvelopeReference],
    normalizer: TelemetryNormalizer,
    *,
    imported_at: str,
    prior_replay_markers: Sequence[ReplayMarker] = (),
) -> TelemetryIngestBatch:
    """Normalize one bounded import after context, freshness, and replay checks."""

    _time(imported_at, "imported_at")
    items = _bounded_unique(tuple(envelopes), "envelopes")
    prior = tuple(prior_replay_markers)
    active_refs: set[str] = set()
    active_digests: set[str] = set()
    for marker in prior:
        if not isinstance(marker, ReplayMarker):
            raise DefenderTelemetryAdapterError("replay marker type is invalid")
        expected = (
            binding.binding_id,
            binding.binding_sha256,
            binding.tenant_ref,
            binding.engagement_ref,
            binding.scope_sha256,
        )
        actual = (
            marker.binding_id,
            marker.binding_sha256,
            marker.tenant_ref,
            marker.engagement_ref,
            marker.scope_sha256,
        )
        if actual != expected:
            raise DefenderTelemetryAdapterError("replay state crosses its bound context")
        if _instant(marker.expires_at) > _instant(imported_at):
            active_refs.add(marker.source_event_ref)
            active_digests.add(marker.raw_event_sha256)

    events: list[NormalizedTelemetryEvent] = []
    markers: list[ReplayMarker] = []
    seen_refs: set[str] = set()
    seen_digests: set[str] = set()
    for envelope in items:
        if not isinstance(envelope, TelemetryEnvelopeReference):
            raise DefenderTelemetryAdapterError("telemetry envelope type is invalid")
        _validate_context(binding, envelope)
        _validate_freshness(binding, envelope, imported_at)
        if (
            envelope.source_event_ref in seen_refs
            or envelope.raw_event_sha256 in seen_digests
            or envelope.source_event_ref in active_refs
            or envelope.raw_event_sha256 in active_digests
        ):
            raise DefenderTelemetryAdapterError("telemetry replay was detected")
        projection = normalizer.normalize(binding=binding, envelope=envelope)
        if not isinstance(projection, NormalizationProjection):
            raise DefenderTelemetryAdapterError("normalizer returned an invalid projection")
        if (
            projection.source_event_ref != envelope.source_event_ref
            or projection.raw_event_sha256 != envelope.raw_event_sha256
            or projection.mapping_sha256 != binding.mapping_sha256
        ):
            raise DefenderTelemetryAdapterError("normalizer projection crosses its input binding")
        event = NormalizedTelemetryEvent(
            binding_id=binding.binding_id,
            binding_sha256=binding.binding_sha256,
            tenant_ref=binding.tenant_ref,
            engagement_ref=binding.engagement_ref,
            scope_sha256=binding.scope_sha256,
            source_ref=binding.source_ref,
            telemetry_domain=binding.telemetry_domain,
            envelope_id=envelope.envelope_id,
            envelope_sha256=envelope.envelope_sha256,
            source_event_ref=envelope.source_event_ref,
            source_sequence=envelope.source_sequence,
            occurred_at=envelope.occurred_at,
            received_at=envelope.received_at,
            raw_event_sha256=envelope.raw_event_sha256,
            mapping_sha256=binding.mapping_sha256,
            event_category=projection.event_category,
            operation_code=projection.operation_code,
            outcome=projection.outcome,
            severity=projection.severity,
            actor_ref=projection.actor_ref,
            subject_ref=projection.subject_ref,
            resource_ref=projection.resource_ref,
            attributes=projection.attributes,
            normalized_at=imported_at,
        )
        markers.append(
            ReplayMarker(
                binding_id=binding.binding_id,
                binding_sha256=binding.binding_sha256,
                tenant_ref=binding.tenant_ref,
                engagement_ref=binding.engagement_ref,
                scope_sha256=binding.scope_sha256,
                source_event_ref=envelope.source_event_ref,
                raw_event_sha256=envelope.raw_event_sha256,
                accepted_at=imported_at,
                expires_at=_plus_seconds(
                    imported_at,
                    binding.freshness_policy.replay_window_seconds,
                ),
            )
        )
        events.append(event)
        seen_refs.add(envelope.source_event_ref)
        seen_digests.add(envelope.raw_event_sha256)
    return TelemetryIngestBatch(binding, imported_at, items, tuple(events), tuple(markers))


def parse_contract(
    value: str | Mapping[str, Any],
) -> (
    TelemetrySourceBinding
    | TelemetryEnvelopeReference
    | NormalizedTelemetryEvent
    | TelemetryIngestBatch
):
    """Parse one supported telemetry contract and recompute its identity."""

    if isinstance(value, str):
        try:
            raw = json.loads(value)
        except json.JSONDecodeError as exc:
            raise DefenderTelemetryAdapterError("contract JSON is invalid") from exc
        if not isinstance(raw, Mapping) or canonical_json(raw) != value:
            raise DefenderTelemetryAdapterError("contract JSON must be canonical")
    elif isinstance(value, Mapping):
        raw = value
    else:
        raise DefenderTelemetryAdapterError("contract must be JSON or a mapping")
    parsers = {
        TelemetrySourceBinding.KIND: TelemetrySourceBinding.from_dict,
        TelemetryEnvelopeReference.KIND: TelemetryEnvelopeReference.from_dict,
        NormalizedTelemetryEvent.KIND: NormalizedTelemetryEvent.from_dict,
        TelemetryIngestBatch.KIND: TelemetryIngestBatch.from_dict,
    }
    parser = parsers.get(raw.get("kind"))
    if parser is None:
        raise DefenderTelemetryAdapterError("contract kind is unsupported")
    return parser(raw)
