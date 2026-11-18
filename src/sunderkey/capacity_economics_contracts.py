"""Deterministic capacity and economics evidence with no runtime effects.

This module validates caller-supplied measurement evidence, quota declarations,
forecasts, attribution, and advisory admission recommendations. It does not
collect metrics, call a provider, bill a tenant, persist data, schedule work,
authorize an action, scale infrastructure, or qualify a deployment.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar

SCHEMA_VERSION = 1

NO_EFFECTS = {
    "authorization": "none",
    "billing": "none",
    "metric_collection": "none",
    "network": "none",
    "persistence": "none",
    "provider_calls": "none",
    "qualification": "none",
    "scaling": "none",
    "scheduling": "none",
}

UNIT_BY_QUOTA = {
    "concurrent_requests": "requests",
    "cost_per_day": "microusd",
    "input_tokens_per_minute": "tokens",
    "output_tokens_per_minute": "tokens",
    "requests_per_minute": "requests",
}
REQUIRED_QUOTAS = tuple(sorted(UNIT_BY_QUOTA))
MEASUREMENT_UNITS = {
    "cost": "microusd",
    "queue_time": "milliseconds",
    "requests": "requests",
    "storage": "bytes",
    "tokens": "tokens",
    "worker_time": "milliseconds",
}

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:custodyref|assessmentref|tenantref|providerref|workerpoolref):"
    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}\Z"
)


class CapacityEconomicsError(ValueError):
    """Raised when capacity or economics evidence fails closed."""


class EvidenceProvenance(StrEnum):
    SYNTHETIC = "synthetic"
    MEASURED_TEST = "measured_test"
    MEASURED_PRODUCTION = "measured_production"


class AdmissionDisposition(StrEnum):
    ADMIT = "admit"
    DENY = "deny"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    _validate_json(value, "value")
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise CapacityEconomicsError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 14:
        raise CapacityEconomicsError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CapacityEconomicsError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise CapacityEconomicsError(f"{label} contains an unsupported value")


def _exact(raw: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise CapacityEconomicsError(f"{label} fields are invalid")
    return raw


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise CapacityEconomicsError(f"{label} must be a safe identifier")
    return value


def _reference(value: Any, label: str, namespace: str) -> str:
    if (
        not isinstance(value, str)
        or REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise CapacityEconomicsError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CapacityEconomicsError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise CapacityEconomicsError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CapacityEconomicsError(f"{label} must be valid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise CapacityEconomicsError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    _timestamp(value, "timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _nonnegative(value: Any, label: str, maximum: int = 9_223_372_036_854_775_807) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise CapacityEconomicsError(f"{label} must be a non-negative integer")
    return value


def _positive(value: Any, label: str, maximum: int = 9_223_372_036_854_775_807) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise CapacityEconomicsError(f"{label} must be a positive integer")
    return value


def _basis_points(value: Any, label: str, *, allow_zero: bool = True) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 10_000:
        raise CapacityEconomicsError(f"{label} must be between {minimum} and 10000")
    return value


def _ordered_unique(
    values: Sequence[Any], label: str, validator: Any, *, allow_empty: bool = False
) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise CapacityEconomicsError(f"{label} must be a sequence")
    normalized = tuple(validator(item, f"{label} item") for item in values)
    if not allow_empty and not normalized:
        raise CapacityEconomicsError(f"{label} must not be empty")
    if len(normalized) != len(set(normalized)):
        raise CapacityEconomicsError(f"{label} must not contain duplicates")
    return tuple(sorted(normalized))


def _digests(values: Sequence[Any], label: str) -> tuple[str, ...]:
    return _ordered_unique(values, label, _digest)


def _references(
    values: Sequence[Any], label: str, namespace: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    return _ordered_unique(
        values,
        label,
        lambda item, item_label: _reference(item, item_label, namespace),
        allow_empty=allow_empty,
    )


def _ids(values: Sequence[Any], label: str) -> tuple[str, ...]:
    return _ordered_unique(values, label, _identifier)


def _nearest_rank(values: Sequence[int], percentile: int) -> int:
    ordered = sorted(values)
    rank = (percentile * len(ordered) + 99) // 100
    return ordered[max(rank, 1) - 1]


@dataclass(frozen=True, slots=True)
class MeasurementDimensions:
    tenant_ref: str
    assessment_ref: str
    provider_ref: str
    region: str
    worker_pool_ref: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "tenant_ref",
            _reference(self.tenant_ref, "tenant_ref", "tenantref"),
        )
        object.__setattr__(
            self,
            "assessment_ref",
            _reference(self.assessment_ref, "assessment_ref", "assessmentref"),
        )
        object.__setattr__(
            self,
            "provider_ref",
            _reference(self.provider_ref, "provider_ref", "providerref"),
        )
        object.__setattr__(self, "region", _identifier(self.region, "region"))
        object.__setattr__(
            self,
            "worker_pool_ref",
            _reference(self.worker_pool_ref, "worker_pool_ref", "workerpoolref"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "assessment_ref": self.assessment_ref,
            "provider_ref": self.provider_ref,
            "region": self.region,
            "tenant_ref": self.tenant_ref,
            "worker_pool_ref": self.worker_pool_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> MeasurementDimensions:
        fields = {"assessment_ref", "provider_ref", "region", "tenant_ref", "worker_pool_ref"}
        value = _exact(raw, fields, "measurement dimensions")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class MeasurementWindow:
    dimensions: MeasurementDimensions
    window_start: str
    window_end: str
    observed_at: str
    provenance: EvidenceProvenance | str
    source_sha256s: tuple[str, ...]
    custody_refs: tuple[str, ...]
    worker_capacity_milliseconds: int
    worker_busy_milliseconds: int
    queue_time_samples_milliseconds: tuple[int, ...]
    requests: int
    input_tokens: int
    output_tokens: int
    model_cost_micros: int
    tool_cost_micros: int
    storage_cost_micros: int
    storage_start_bytes: int
    storage_end_bytes: int
    validated_findings: int
    window_id: str = field(init=False)
    window_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.capacity-measurement-window.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.dimensions, MeasurementDimensions):
            raise CapacityEconomicsError("dimensions must be MeasurementDimensions")
        for name in ("window_start", "window_end", "observed_at"):
            object.__setattr__(self, name, _timestamp(getattr(self, name), name))
        if _instant(self.window_end) <= _instant(self.window_start):
            raise CapacityEconomicsError("measurement window must have positive duration")
        if _instant(self.observed_at) < _instant(self.window_end):
            raise CapacityEconomicsError("measurement observed_at precedes window_end")
        try:
            provenance = EvidenceProvenance(self.provenance)
        except ValueError as exc:
            raise CapacityEconomicsError("measurement provenance is invalid") from exc
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "source_sha256s", _digests(self.source_sha256s, "source_sha256s"))
        object.__setattr__(
            self,
            "custody_refs",
            _references(self.custody_refs, "custody_refs", "custodyref", allow_empty=True),
        )
        if provenance is EvidenceProvenance.MEASURED_PRODUCTION and not self.custody_refs:
            raise CapacityEconomicsError("measured production data requires custody references")
        for name in (
            "worker_capacity_milliseconds",
            "worker_busy_milliseconds",
            "requests",
            "input_tokens",
            "output_tokens",
            "model_cost_micros",
            "tool_cost_micros",
            "storage_cost_micros",
            "storage_start_bytes",
            "storage_end_bytes",
            "validated_findings",
        ):
            _nonnegative(getattr(self, name), name)
        if self.worker_capacity_milliseconds == 0 and self.worker_busy_milliseconds != 0:
            raise CapacityEconomicsError("worker busy time requires worker capacity")
        if self.worker_busy_milliseconds > self.worker_capacity_milliseconds:
            raise CapacityEconomicsError("worker busy time exceeds capacity")
        if self.storage_end_bytes < self.storage_start_bytes:
            raise CapacityEconomicsError("storage end bytes precede storage start bytes")
        if isinstance(self.queue_time_samples_milliseconds, (str, bytes)) or not isinstance(
            self.queue_time_samples_milliseconds, Sequence
        ):
            raise CapacityEconomicsError("queue time samples must be a sequence")
        samples = tuple(
            _nonnegative(item, "queue time sample") for item in self.queue_time_samples_milliseconds
        )
        if len(samples) != self.requests:
            raise CapacityEconomicsError("queue samples must cover every request")
        object.__setattr__(self, "queue_time_samples_milliseconds", samples)
        body = self._body()
        identity, digest = _identity("CMW", self.KIND, body)
        object.__setattr__(self, "window_id", identity)
        object.__setattr__(self, "window_sha256", digest)

    @property
    def duration_seconds(self) -> int:
        return int((_instant(self.window_end) - _instant(self.window_start)).total_seconds())

    @property
    def worker_utilization_basis_points(self) -> int:
        if self.worker_capacity_milliseconds == 0:
            return 0
        return (self.worker_busy_milliseconds * 10_000) // self.worker_capacity_milliseconds

    @property
    def queue_p50_milliseconds(self) -> int:
        if not self.queue_time_samples_milliseconds:
            return 0
        return _nearest_rank(self.queue_time_samples_milliseconds, 50)

    @property
    def queue_p95_milliseconds(self) -> int:
        if not self.queue_time_samples_milliseconds:
            return 0
        return _nearest_rank(self.queue_time_samples_milliseconds, 95)

    @property
    def storage_growth_bytes(self) -> int:
        return self.storage_end_bytes - self.storage_start_bytes

    @property
    def total_cost_micros(self) -> int:
        return self.model_cost_micros + self.tool_cost_micros + self.storage_cost_micros

    def _body(self) -> dict[str, Any]:
        return {
            "custody_refs": list(self.custody_refs),
            "dimensions": self.dimensions.to_dict(),
            "input_tokens": self.input_tokens,
            "model_cost_micros": self.model_cost_micros,
            "observed_at": self.observed_at,
            "output_tokens": self.output_tokens,
            "provenance": self.provenance.value,
            "queue_time_samples_milliseconds": list(self.queue_time_samples_milliseconds),
            "requests": self.requests,
            "source_sha256s": list(self.source_sha256s),
            "storage_cost_micros": self.storage_cost_micros,
            "storage_end_bytes": self.storage_end_bytes,
            "storage_start_bytes": self.storage_start_bytes,
            "tool_cost_micros": self.tool_cost_micros,
            "validated_findings": self.validated_findings,
            "window_end": self.window_end,
            "window_start": self.window_start,
            "worker_busy_milliseconds": self.worker_busy_milliseconds,
            "worker_capacity_milliseconds": self.worker_capacity_milliseconds,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "derived": {
                "duration_seconds": self.duration_seconds,
                "queue_p50_milliseconds": self.queue_p50_milliseconds,
                "queue_p95_milliseconds": self.queue_p95_milliseconds,
                "storage_growth_bytes": self.storage_growth_bytes,
                "total_cost_micros": self.total_cost_micros,
                "worker_utilization_basis_points": self.worker_utilization_basis_points,
            },
            "kind": self.KIND,
            **self._body(),
            "units": dict(MEASUREMENT_UNITS),
            "window_id": self.window_id,
            "window_sha256": self.window_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> MeasurementWindow:
        fields = set(cls.__dataclass_fields__) - {"KIND", "window_id", "window_sha256"}
        expected = fields | {"derived", "kind", "units", "window_id", "window_sha256"}
        value = _exact(raw, expected, "measurement window")
        if value["kind"] != cls.KIND or value["units"] != MEASUREMENT_UNITS:
            raise CapacityEconomicsError("measurement kind or units are invalid")
        kwargs = {name: value[name] for name in fields}
        kwargs["dimensions"] = MeasurementDimensions.from_dict(value["dimensions"])
        kwargs["source_sha256s"] = tuple(value["source_sha256s"])
        kwargs["custody_refs"] = tuple(value["custody_refs"])
        kwargs["queue_time_samples_milliseconds"] = tuple(value["queue_time_samples_milliseconds"])
        result = cls(**kwargs)
        if value["window_id"] != result.window_id or value["window_sha256"] != result.window_sha256:
            raise CapacityEconomicsError("measurement content address is invalid")
        expected_derived = result.to_dict()["derived"]
        if value["derived"] != expected_derived:
            raise CapacityEconomicsError("measurement derived values are invalid")
        return result


@dataclass(frozen=True, slots=True)
class CostAttribution:
    tenant_ref: str
    assessment_ref: str
    source_window_ids: tuple[str, ...]
    requests: int
    input_tokens: int
    output_tokens: int
    storage_growth_bytes: int
    validated_findings: int
    model_cost_micros: int
    tool_cost_micros: int
    storage_cost_micros: int
    attribution_id: str = field(init=False)
    attribution_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.capacity-cost-attribution.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "tenant_ref",
            _reference(self.tenant_ref, "tenant_ref", "tenantref"),
        )
        object.__setattr__(
            self,
            "assessment_ref",
            _reference(self.assessment_ref, "assessment_ref", "assessmentref"),
        )
        object.__setattr__(
            self,
            "source_window_ids",
            _ids(self.source_window_ids, "source_window_ids"),
        )
        for name in (
            "requests",
            "input_tokens",
            "output_tokens",
            "storage_growth_bytes",
            "validated_findings",
            "model_cost_micros",
            "tool_cost_micros",
            "storage_cost_micros",
        ):
            _nonnegative(getattr(self, name), name)
        identity, digest = _identity("CAT", self.KIND, self._body())
        object.__setattr__(self, "attribution_id", identity)
        object.__setattr__(self, "attribution_sha256", digest)

    @property
    def total_cost_micros(self) -> int:
        return self.model_cost_micros + self.tool_cost_micros + self.storage_cost_micros

    @property
    def cost_per_validated_finding_micros(self) -> int | None:
        if self.validated_findings == 0:
            return None
        return self.total_cost_micros // self.validated_findings

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "input_tokens": self.input_tokens,
            "model_cost_micros": self.model_cost_micros,
            "output_tokens": self.output_tokens,
            "requests": self.requests,
            "source_window_ids": list(self.source_window_ids),
            "storage_cost_micros": self.storage_cost_micros,
            "storage_growth_bytes": self.storage_growth_bytes,
            "tenant_ref": self.tenant_ref,
            "tool_cost_micros": self.tool_cost_micros,
            "validated_findings": self.validated_findings,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "attribution_id": self.attribution_id,
            "attribution_sha256": self.attribution_sha256,
            "cost_per_validated_finding_micros": self.cost_per_validated_finding_micros,
            "kind": self.KIND,
            **self._body(),
            "total_cost_micros": self.total_cost_micros,
            "units": {"cost": "microusd", "storage": "bytes", "tokens": "tokens"},
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CostAttribution:
        fields = set(cls.__dataclass_fields__) - {
            "KIND",
            "attribution_id",
            "attribution_sha256",
        }
        expected = fields | {
            "attribution_id",
            "attribution_sha256",
            "cost_per_validated_finding_micros",
            "kind",
            "total_cost_micros",
            "units",
        }
        value = _exact(raw, expected, "cost attribution")
        if value["kind"] != cls.KIND or value["units"] != {
            "cost": "microusd",
            "storage": "bytes",
            "tokens": "tokens",
        }:
            raise CapacityEconomicsError("attribution kind or units are invalid")
        kwargs = {name: value[name] for name in fields}
        kwargs["source_window_ids"] = tuple(value["source_window_ids"])
        result = cls(**kwargs)
        if (
            value["attribution_id"] != result.attribution_id
            or value["attribution_sha256"] != result.attribution_sha256
            or value["total_cost_micros"] != result.total_cost_micros
            or value["cost_per_validated_finding_micros"]
            != result.cost_per_validated_finding_micros
        ):
            raise CapacityEconomicsError("attribution derivation or content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class QuotaCounter:
    name: str
    unit: str
    limit: int
    used: int
    reserved: int

    def __post_init__(self) -> None:
        if self.name not in UNIT_BY_QUOTA:
            raise CapacityEconomicsError("quota name is invalid")
        if self.unit != UNIT_BY_QUOTA[self.name]:
            raise CapacityEconomicsError("quota unit does not match its name")
        _positive(self.limit, "quota limit")
        _nonnegative(self.used, "quota used")
        _nonnegative(self.reserved, "quota reserved")
        if self.used + self.reserved > self.limit:
            raise CapacityEconomicsError("quota is oversubscribed")

    @property
    def headroom(self) -> int:
        return self.limit - self.used - self.reserved

    @property
    def headroom_basis_points(self) -> int:
        return (self.headroom * 10_000) // self.limit

    def to_dict(self) -> dict[str, Any]:
        return {
            "headroom": self.headroom,
            "headroom_basis_points": self.headroom_basis_points,
            "limit": self.limit,
            "name": self.name,
            "reserved": self.reserved,
            "unit": self.unit,
            "used": self.used,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> QuotaCounter:
        value = _exact(
            raw,
            {"headroom", "headroom_basis_points", "limit", "name", "reserved", "unit", "used"},
            "quota counter",
        )
        result = cls(
            value["name"],
            value["unit"],
            value["limit"],
            value["used"],
            value["reserved"],
        )
        if (
            value["headroom"] != result.headroom
            or value["headroom_basis_points"] != result.headroom_basis_points
        ):
            raise CapacityEconomicsError("quota headroom is not derived")
        return result


@dataclass(frozen=True, slots=True)
class ProviderQuotaSnapshot:
    provider_ref: str
    region: str
    observed_at: str
    expires_at: str
    provenance: EvidenceProvenance | str
    source_sha256s: tuple[str, ...]
    custody_refs: tuple[str, ...]
    quotas: tuple[QuotaCounter, ...]
    snapshot_id: str = field(init=False)
    snapshot_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.provider-quota-snapshot.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider_ref",
            _reference(self.provider_ref, "provider_ref", "providerref"),
        )
        object.__setattr__(self, "region", _identifier(self.region, "region"))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at, "expires_at"))
        if _instant(self.expires_at) <= _instant(self.observed_at):
            raise CapacityEconomicsError("quota expiration must follow observation")
        try:
            provenance = EvidenceProvenance(self.provenance)
        except ValueError as exc:
            raise CapacityEconomicsError("quota provenance is invalid") from exc
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "source_sha256s", _digests(self.source_sha256s, "source_sha256s"))
        object.__setattr__(
            self,
            "custody_refs",
            _references(self.custody_refs, "custody_refs", "custodyref", allow_empty=True),
        )
        if provenance is EvidenceProvenance.MEASURED_PRODUCTION and not self.custody_refs:
            raise CapacityEconomicsError("measured production quota requires custody references")
        if isinstance(self.quotas, (str, bytes)) or not isinstance(self.quotas, Sequence):
            raise CapacityEconomicsError("quotas must be a sequence")
        if any(not isinstance(item, QuotaCounter) for item in self.quotas):
            raise CapacityEconomicsError("quotas must contain QuotaCounter values")
        quotas = tuple(sorted(self.quotas, key=lambda item: item.name))
        if tuple(item.name for item in quotas) != REQUIRED_QUOTAS:
            raise CapacityEconomicsError(
                "quota snapshot must contain every required quota exactly once"
            )
        object.__setattr__(self, "quotas", quotas)
        identity, digest = _identity("PQS", self.KIND, self._body())
        object.__setattr__(self, "snapshot_id", identity)
        object.__setattr__(self, "snapshot_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "custody_refs": list(self.custody_refs),
            "expires_at": self.expires_at,
            "observed_at": self.observed_at,
            "provenance": self.provenance.value,
            "provider_ref": self.provider_ref,
            "quotas": [item.to_dict() for item in self.quotas],
            "region": self.region,
            "source_sha256s": list(self.source_sha256s),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            **self._body(),
            "snapshot_id": self.snapshot_id,
            "snapshot_sha256": self.snapshot_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ProviderQuotaSnapshot:
        fields = set(cls.__dataclass_fields__) - {"KIND", "snapshot_id", "snapshot_sha256"}
        expected = fields | {"kind", "snapshot_id", "snapshot_sha256"}
        value = _exact(raw, expected, "provider quota snapshot")
        if value["kind"] != cls.KIND:
            raise CapacityEconomicsError("quota snapshot kind is invalid")
        kwargs = {name: value[name] for name in fields}
        kwargs["source_sha256s"] = tuple(value["source_sha256s"])
        kwargs["custody_refs"] = tuple(value["custody_refs"])
        kwargs["quotas"] = tuple(QuotaCounter.from_dict(item) for item in value["quotas"])
        result = cls(**kwargs)
        if (
            value["snapshot_id"] != result.snapshot_id
            or value["snapshot_sha256"] != result.snapshot_sha256
        ):
            raise CapacityEconomicsError("quota snapshot content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class ForecastMetric:
    name: str
    unit: str
    lower: int
    expected: int
    upper: int

    def __post_init__(self) -> None:
        if self.name not in UNIT_BY_QUOTA:
            raise CapacityEconomicsError("forecast metric name is invalid")
        if self.unit != UNIT_BY_QUOTA[self.name]:
            raise CapacityEconomicsError("forecast metric unit does not match its name")
        for name in ("lower", "expected", "upper"):
            _nonnegative(getattr(self, name), f"forecast {name}")
        if not self.lower <= self.expected <= self.upper:
            raise CapacityEconomicsError("forecast bounds do not contain expected demand")

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected": self.expected,
            "lower": self.lower,
            "name": self.name,
            "unit": self.unit,
            "upper": self.upper,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ForecastMetric:
        value = _exact(raw, {"expected", "lower", "name", "unit", "upper"}, "forecast metric")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class DemandForecast:
    provider_ref: str
    region: str
    created_at: str
    horizon_start: str
    horizon_end: str
    confidence_basis_points: int
    source_window_ids: tuple[str, ...]
    source_sha256s: tuple[str, ...]
    metrics: tuple[ForecastMetric, ...]
    forecast_id: str = field(init=False)
    forecast_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.capacity-demand-forecast.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider_ref",
            _reference(self.provider_ref, "provider_ref", "providerref"),
        )
        object.__setattr__(self, "region", _identifier(self.region, "region"))
        for name in ("created_at", "horizon_start", "horizon_end"):
            object.__setattr__(self, name, _timestamp(getattr(self, name), name))
        if _instant(self.horizon_start) < _instant(self.created_at):
            raise CapacityEconomicsError("forecast horizon starts before creation")
        if _instant(self.horizon_end) <= _instant(self.horizon_start):
            raise CapacityEconomicsError("forecast horizon must have positive duration")
        _basis_points(self.confidence_basis_points, "confidence_basis_points", allow_zero=False)
        object.__setattr__(
            self,
            "source_window_ids",
            _ids(self.source_window_ids, "source_window_ids"),
        )
        object.__setattr__(self, "source_sha256s", _digests(self.source_sha256s, "source_sha256s"))
        if isinstance(self.metrics, (str, bytes)) or not isinstance(self.metrics, Sequence):
            raise CapacityEconomicsError("forecast metrics must be a sequence")
        if any(not isinstance(item, ForecastMetric) for item in self.metrics):
            raise CapacityEconomicsError("metrics must contain ForecastMetric values")
        metrics = tuple(sorted(self.metrics, key=lambda item: item.name))
        if tuple(item.name for item in metrics) != REQUIRED_QUOTAS:
            raise CapacityEconomicsError("forecast must contain every required metric exactly once")
        object.__setattr__(self, "metrics", metrics)
        identity, digest = _identity("CDF", self.KIND, self._body())
        object.__setattr__(self, "forecast_id", identity)
        object.__setattr__(self, "forecast_sha256", digest)

    @property
    def horizon_seconds(self) -> int:
        return int((_instant(self.horizon_end) - _instant(self.horizon_start)).total_seconds())

    def _body(self) -> dict[str, Any]:
        return {
            "confidence_basis_points": self.confidence_basis_points,
            "created_at": self.created_at,
            "horizon_end": self.horizon_end,
            "horizon_start": self.horizon_start,
            "metrics": [item.to_dict() for item in self.metrics],
            "provider_ref": self.provider_ref,
            "region": self.region,
            "source_sha256s": list(self.source_sha256s),
            "source_window_ids": list(self.source_window_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "forecast_id": self.forecast_id,
            "forecast_sha256": self.forecast_sha256,
            "horizon_seconds": self.horizon_seconds,
            "kind": self.KIND,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DemandForecast:
        fields = set(cls.__dataclass_fields__) - {"KIND", "forecast_id", "forecast_sha256"}
        expected = fields | {"forecast_id", "forecast_sha256", "horizon_seconds", "kind"}
        value = _exact(raw, expected, "demand forecast")
        if value["kind"] != cls.KIND:
            raise CapacityEconomicsError("forecast kind is invalid")
        kwargs = {name: value[name] for name in fields}
        kwargs["source_window_ids"] = tuple(value["source_window_ids"])
        kwargs["source_sha256s"] = tuple(value["source_sha256s"])
        kwargs["metrics"] = tuple(ForecastMetric.from_dict(item) for item in value["metrics"])
        result = cls(**kwargs)
        if (
            value["forecast_id"] != result.forecast_id
            or value["forecast_sha256"] != result.forecast_sha256
            or value["horizon_seconds"] != result.horizon_seconds
        ):
            raise CapacityEconomicsError("forecast derivation or content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class CapacityPolicy:
    policy_version: str
    maximum_measurement_age_seconds: int
    maximum_quota_age_seconds: int
    maximum_forecast_age_seconds: int
    maximum_forecast_horizon_seconds: int
    minimum_forecast_confidence_basis_points: int
    minimum_quota_headroom_basis_points: int
    maximum_worker_utilization_basis_points: int
    maximum_queue_p95_milliseconds: int
    maximum_assessment_cost_micros: int
    maximum_cost_per_validated_finding_micros: int
    policy_id: str = field(init=False)
    policy_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.capacity-economics-policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "policy_version",
            _identifier(self.policy_version, "policy_version"),
        )
        for name in (
            "maximum_measurement_age_seconds",
            "maximum_quota_age_seconds",
            "maximum_forecast_age_seconds",
            "maximum_forecast_horizon_seconds",
            "maximum_queue_p95_milliseconds",
            "maximum_assessment_cost_micros",
            "maximum_cost_per_validated_finding_micros",
        ):
            _positive(getattr(self, name), name)
        _basis_points(
            self.minimum_forecast_confidence_basis_points,
            "minimum_forecast_confidence_basis_points",
            allow_zero=False,
        )
        _basis_points(
            self.minimum_quota_headroom_basis_points,
            "minimum_quota_headroom_basis_points",
            allow_zero=False,
        )
        _basis_points(
            self.maximum_worker_utilization_basis_points,
            "maximum_worker_utilization_basis_points",
            allow_zero=False,
        )
        identity, digest = _identity("CEP", self.KIND, self._body())
        object.__setattr__(self, "policy_id", identity)
        object.__setattr__(self, "policy_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "maximum_assessment_cost_micros": self.maximum_assessment_cost_micros,
            "maximum_cost_per_validated_finding_micros": (
                self.maximum_cost_per_validated_finding_micros
            ),
            "maximum_forecast_age_seconds": self.maximum_forecast_age_seconds,
            "maximum_forecast_horizon_seconds": self.maximum_forecast_horizon_seconds,
            "maximum_measurement_age_seconds": self.maximum_measurement_age_seconds,
            "maximum_queue_p95_milliseconds": self.maximum_queue_p95_milliseconds,
            "maximum_quota_age_seconds": self.maximum_quota_age_seconds,
            "maximum_worker_utilization_basis_points": self.maximum_worker_utilization_basis_points,
            "minimum_forecast_confidence_basis_points": (
                self.minimum_forecast_confidence_basis_points
            ),
            "minimum_quota_headroom_basis_points": self.minimum_quota_headroom_basis_points,
            "policy_version": self.policy_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            **self._body(),
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CapacityPolicy:
        fields = set(cls.__dataclass_fields__) - {"KIND", "policy_id", "policy_sha256"}
        expected = fields | {"kind", "policy_id", "policy_sha256"}
        value = _exact(raw, expected, "capacity policy")
        if value["kind"] != cls.KIND:
            raise CapacityEconomicsError("capacity policy kind is invalid")
        result = cls(**{name: value[name] for name in fields})
        if value["policy_id"] != result.policy_id or value["policy_sha256"] != result.policy_sha256:
            raise CapacityEconomicsError("capacity policy content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class AdmissionRecommendation:
    as_of: str
    tenant_ref: str
    assessment_ref: str
    provider_ref: str
    region: str
    disposition: AdmissionDisposition | str
    blockers: tuple[str, ...]
    measurement_window_ids: tuple[str, ...]
    attribution_id: str
    quota_snapshot_id: str
    forecast_id: str
    policy_id: str
    projected_cost_micros: int
    recommendation_id: str = field(init=False)
    recommendation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.capacity-admission-recommendation.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "as_of", _timestamp(self.as_of, "as_of"))
        object.__setattr__(
            self,
            "tenant_ref",
            _reference(self.tenant_ref, "tenant_ref", "tenantref"),
        )
        object.__setattr__(
            self,
            "assessment_ref",
            _reference(self.assessment_ref, "assessment_ref", "assessmentref"),
        )
        object.__setattr__(
            self,
            "provider_ref",
            _reference(self.provider_ref, "provider_ref", "providerref"),
        )
        object.__setattr__(self, "region", _identifier(self.region, "region"))
        try:
            disposition = AdmissionDisposition(self.disposition)
        except ValueError as exc:
            raise CapacityEconomicsError("admission disposition is invalid") from exc
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(
            self,
            "blockers",
            _ordered_unique(self.blockers, "blockers", _identifier, allow_empty=True),
        )
        if (disposition is AdmissionDisposition.ADMIT) != (not self.blockers):
            raise CapacityEconomicsError("admission disposition does not match blockers")
        object.__setattr__(
            self,
            "measurement_window_ids",
            _ids(self.measurement_window_ids, "measurement_window_ids"),
        )
        for name in ("attribution_id", "quota_snapshot_id", "forecast_id", "policy_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        _nonnegative(self.projected_cost_micros, "projected_cost_micros")
        identity, digest = _identity("CAR", self.KIND, self._body())
        object.__setattr__(self, "recommendation_id", identity)
        object.__setattr__(self, "recommendation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "assessment_ref": self.assessment_ref,
            "attribution_id": self.attribution_id,
            "blockers": list(self.blockers),
            "disposition": self.disposition.value,
            "forecast_id": self.forecast_id,
            "measurement_window_ids": list(self.measurement_window_ids),
            "policy_id": self.policy_id,
            "projected_cost_micros": self.projected_cost_micros,
            "provider_ref": self.provider_ref,
            "quota_snapshot_id": self.quota_snapshot_id,
            "region": self.region,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            **self._body(),
            "recommendation_id": self.recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AdmissionRecommendation:
        fields = set(cls.__dataclass_fields__) - {
            "KIND",
            "recommendation_id",
            "recommendation_sha256",
        }
        expected = fields | {"kind", "recommendation_id", "recommendation_sha256"}
        value = _exact(raw, expected, "admission recommendation")
        if value["kind"] != cls.KIND:
            raise CapacityEconomicsError("admission recommendation kind is invalid")
        kwargs = {name: value[name] for name in fields}
        kwargs["blockers"] = tuple(value["blockers"])
        kwargs["measurement_window_ids"] = tuple(value["measurement_window_ids"])
        result = cls(**kwargs)
        if (
            value["recommendation_id"] != result.recommendation_id
            or value["recommendation_sha256"] != result.recommendation_sha256
        ):
            raise CapacityEconomicsError("admission recommendation content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class CapacityEconomicsContract:
    measurement_windows: tuple[MeasurementWindow, ...]
    attributions: tuple[CostAttribution, ...]
    quota_snapshots: tuple[ProviderQuotaSnapshot, ...]
    forecasts: tuple[DemandForecast, ...]
    policy: CapacityPolicy
    recommendation: AdmissionRecommendation
    contract_id: str = field(init=False)
    contract_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.capacity-economics-contract.v1"

    def __post_init__(self) -> None:
        for values, expected_type, label in (
            (self.measurement_windows, MeasurementWindow, "measurement windows"),
            (self.attributions, CostAttribution, "attributions"),
            (self.quota_snapshots, ProviderQuotaSnapshot, "quota snapshots"),
            (self.forecasts, DemandForecast, "forecasts"),
        ):
            if (
                isinstance(values, (str, bytes))
                or not isinstance(values, Sequence)
                or not values
                or any(not isinstance(item, expected_type) for item in values)
            ):
                raise CapacityEconomicsError(f"{label} must contain valid records")
        windows = tuple(sorted(self.measurement_windows, key=lambda item: item.window_id))
        attributions = tuple(sorted(self.attributions, key=lambda item: item.attribution_id))
        snapshots = tuple(sorted(self.quota_snapshots, key=lambda item: item.snapshot_id))
        forecasts = tuple(sorted(self.forecasts, key=lambda item: item.forecast_id))
        if not isinstance(self.policy, CapacityPolicy):
            raise CapacityEconomicsError("policy must be CapacityPolicy")
        if not isinstance(self.recommendation, AdmissionRecommendation):
            raise CapacityEconomicsError("recommendation must be AdmissionRecommendation")
        object.__setattr__(self, "measurement_windows", windows)
        object.__setattr__(self, "attributions", attributions)
        object.__setattr__(self, "quota_snapshots", snapshots)
        object.__setattr__(self, "forecasts", forecasts)
        _validate_contract_records(self)
        identity, digest = _identity("CEC", self.KIND, self._body())
        object.__setattr__(self, "contract_id", identity)
        object.__setattr__(self, "contract_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "attributions": [item.to_dict() for item in self.attributions],
            "forecasts": [item.to_dict() for item in self.forecasts],
            "measurement_windows": [item.to_dict() for item in self.measurement_windows],
            "policy": self.policy.to_dict(),
            "quota_snapshots": [item.to_dict() for item in self.quota_snapshots],
            "recommendation": self.recommendation.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CapacityEconomicsContract:
        expected = {
            "attributions",
            "contract_id",
            "contract_sha256",
            "effects",
            "forecasts",
            "kind",
            "measurement_windows",
            "policy",
            "quota_snapshots",
            "recommendation",
            "schema_version",
        }
        value = _exact(raw, expected, "capacity economics contract")
        if (
            value["kind"] != cls.KIND
            or value["schema_version"] != SCHEMA_VERSION
            or value["effects"] != NO_EFFECTS
        ):
            raise CapacityEconomicsError("contract metadata or effects are invalid")
        result = cls(
            measurement_windows=tuple(
                MeasurementWindow.from_dict(item) for item in value["measurement_windows"]
            ),
            attributions=tuple(CostAttribution.from_dict(item) for item in value["attributions"]),
            quota_snapshots=tuple(
                ProviderQuotaSnapshot.from_dict(item) for item in value["quota_snapshots"]
            ),
            forecasts=tuple(DemandForecast.from_dict(item) for item in value["forecasts"]),
            policy=CapacityPolicy.from_dict(value["policy"]),
            recommendation=AdmissionRecommendation.from_dict(value["recommendation"]),
        )
        if (
            value["contract_id"] != result.contract_id
            or value["contract_sha256"] != result.contract_sha256
        ):
            raise CapacityEconomicsError("contract content address is invalid")
        return result


def _derive_admission_blockers(
    *,
    as_of: str,
    windows: Sequence[MeasurementWindow],
    attribution: CostAttribution,
    snapshot: ProviderQuotaSnapshot,
    forecast: DemandForecast,
    policy: CapacityPolicy,
) -> tuple[str, ...]:
    now = _instant(as_of)
    blockers: set[str] = set()
    for window in windows:
        age = int((now - _instant(window.observed_at)).total_seconds())
        if age < 0 or age > policy.maximum_measurement_age_seconds:
            blockers.add("measurement_stale_or_future")
        if window.worker_utilization_basis_points > policy.maximum_worker_utilization_basis_points:
            blockers.add("worker_utilization_exceeded")
        if window.queue_p95_milliseconds > policy.maximum_queue_p95_milliseconds:
            blockers.add("queue_p95_exceeded")

    quota_age = int((now - _instant(snapshot.observed_at)).total_seconds())
    if (
        quota_age < 0
        or quota_age > policy.maximum_quota_age_seconds
        or now >= _instant(snapshot.expires_at)
    ):
        blockers.add("quota_snapshot_stale_or_expired")
    forecast_age = int((now - _instant(forecast.created_at)).total_seconds())
    if forecast_age < 0 or forecast_age > policy.maximum_forecast_age_seconds:
        blockers.add("forecast_stale_or_future")
    if forecast.horizon_seconds > policy.maximum_forecast_horizon_seconds:
        blockers.add("forecast_horizon_exceeded")
    if not _instant(forecast.horizon_start) <= now < _instant(forecast.horizon_end):
        blockers.add("forecast_does_not_cover_admission_time")
    if forecast.confidence_basis_points < policy.minimum_forecast_confidence_basis_points:
        blockers.add("forecast_confidence_insufficient")

    quota_by_name = {item.name: item for item in snapshot.quotas}
    for metric in forecast.metrics:
        quota = quota_by_name[metric.name]
        if metric.upper > quota.headroom:
            blockers.add("forecast_exceeds_quota_headroom")
        if quota.headroom_basis_points < policy.minimum_quota_headroom_basis_points:
            blockers.add("quota_headroom_below_policy")
    if attribution.total_cost_micros > policy.maximum_assessment_cost_micros:
        blockers.add("assessment_cost_exceeded")
    cost_per_finding = attribution.cost_per_validated_finding_micros
    if cost_per_finding is None:
        if attribution.total_cost_micros > 0:
            blockers.add("cost_per_validated_finding_unavailable")
    elif cost_per_finding > policy.maximum_cost_per_validated_finding_micros:
        blockers.add("cost_per_validated_finding_exceeded")
    return tuple(sorted(blockers))


def _validate_contract_records(contract: CapacityEconomicsContract) -> None:
    windows_by_id = {item.window_id: item for item in contract.measurement_windows}
    if len(windows_by_id) != len(contract.measurement_windows):
        raise CapacityEconomicsError("measurement windows contain duplicate content")
    for left_index, left in enumerate(contract.measurement_windows):
        for right in contract.measurement_windows[left_index + 1 :]:
            if left.dimensions == right.dimensions and (
                _instant(left.window_start) < _instant(right.window_end)
                and _instant(right.window_start) < _instant(left.window_end)
            ):
                raise CapacityEconomicsError("measurement windows overlap for the same dimensions")

    expected_groups: dict[tuple[str, str], list[MeasurementWindow]] = {}
    for window in contract.measurement_windows:
        key = (window.dimensions.tenant_ref, window.dimensions.assessment_ref)
        expected_groups.setdefault(key, []).append(window)
    attribution_groups: dict[tuple[str, str], CostAttribution] = {}
    attributed_window_ids: set[str] = set()
    for attribution in contract.attributions:
        key = (attribution.tenant_ref, attribution.assessment_ref)
        if key in attribution_groups:
            raise CapacityEconomicsError("tenant and assessment are attributed more than once")
        if attributed_window_ids.intersection(attribution.source_window_ids):
            raise CapacityEconomicsError("measurement window is attributed more than once")
        attributed_window_ids.update(attribution.source_window_ids)
        attribution_groups[key] = attribution
        source = [
            windows_by_id[item]
            for item in attribution.source_window_ids
            if item in windows_by_id
        ]
        if len(source) != len(attribution.source_window_ids):
            raise CapacityEconomicsError("attribution references an unknown measurement window")
        if any(
            (item.dimensions.tenant_ref, item.dimensions.assessment_ref) != key for item in source
        ):
            raise CapacityEconomicsError("attribution crosses tenant or assessment dimensions")
        derived = {
            "requests": sum(item.requests for item in source),
            "input_tokens": sum(item.input_tokens for item in source),
            "output_tokens": sum(item.output_tokens for item in source),
            "storage_growth_bytes": sum(item.storage_growth_bytes for item in source),
            "validated_findings": sum(item.validated_findings for item in source),
            "model_cost_micros": sum(item.model_cost_micros for item in source),
            "tool_cost_micros": sum(item.tool_cost_micros for item in source),
            "storage_cost_micros": sum(item.storage_cost_micros for item in source),
        }
        if any(getattr(attribution, name) != value for name, value in derived.items()):
            raise CapacityEconomicsError("attribution totals are not derived from source windows")
    if set(expected_groups) != set(attribution_groups) or attributed_window_ids != set(
        windows_by_id
    ):
        raise CapacityEconomicsError("every measurement window must be attributed exactly once")
    for key, windows in expected_groups.items():
        if set(attribution_groups[key].source_window_ids) != {item.window_id for item in windows}:
            raise CapacityEconomicsError("attribution source windows are incomplete")

    snapshot_keys = {(item.provider_ref, item.region): item for item in contract.quota_snapshots}
    forecast_keys = {(item.provider_ref, item.region): item for item in contract.forecasts}
    if len(snapshot_keys) != len(contract.quota_snapshots):
        raise CapacityEconomicsError("provider quota dimensions are duplicated")
    if len(forecast_keys) != len(contract.forecasts):
        raise CapacityEconomicsError("provider forecast dimensions are duplicated")
    if set(snapshot_keys) != set(forecast_keys):
        raise CapacityEconomicsError("provider quota and forecast dimensions do not match")
    for key, forecast in forecast_keys.items():
        source_windows = [
            windows_by_id[item]
            for item in forecast.source_window_ids
            if item in windows_by_id
        ]
        if len(source_windows) != len(forecast.source_window_ids):
            raise CapacityEconomicsError("forecast references an unknown measurement window")
        if any(
            (item.dimensions.provider_ref, item.dimensions.region) != key for item in source_windows
        ):
            raise CapacityEconomicsError("forecast source dimensions do not match provider quota")
        if any(
            _instant(item.observed_at) > _instant(forecast.created_at)
            for item in source_windows
        ):
            raise CapacityEconomicsError("forecast predates its measurement evidence")

    recommendation = contract.recommendation
    target_windows = tuple(
        item
        for item in contract.measurement_windows
        if item.dimensions.tenant_ref == recommendation.tenant_ref
        and item.dimensions.assessment_ref == recommendation.assessment_ref
        and item.dimensions.provider_ref == recommendation.provider_ref
        and item.dimensions.region == recommendation.region
    )
    target_attributions = tuple(
        item
        for item in contract.attributions
        if item.tenant_ref == recommendation.tenant_ref
        and item.assessment_ref == recommendation.assessment_ref
    )
    target_snapshots = tuple(
        item
        for item in contract.quota_snapshots
        if item.provider_ref == recommendation.provider_ref
        and item.region == recommendation.region
    )
    target_forecasts = tuple(
        item
        for item in contract.forecasts
        if item.provider_ref == recommendation.provider_ref
        and item.region == recommendation.region
    )
    if (
        not target_windows
        or len(target_attributions) != 1
        or len(target_snapshots) != 1
        or len(target_forecasts) != 1
    ):
        raise CapacityEconomicsError("recommendation target dimensions are incomplete")
    attribution = target_attributions[0]
    snapshot = target_snapshots[0]
    forecast = target_forecasts[0]
    expected_blockers = _derive_admission_blockers(
        as_of=recommendation.as_of,
        windows=target_windows,
        attribution=attribution,
        snapshot=snapshot,
        forecast=forecast,
        policy=contract.policy,
    )
    expected_disposition = (
        AdmissionDisposition.ADMIT if not expected_blockers else AdmissionDisposition.DENY
    )
    if (
        set(recommendation.measurement_window_ids)
        != {item.window_id for item in target_windows}
        or recommendation.attribution_id != attribution.attribution_id
        or recommendation.quota_snapshot_id != snapshot.snapshot_id
        or recommendation.forecast_id != forecast.forecast_id
        or recommendation.policy_id != contract.policy.policy_id
        or recommendation.projected_cost_micros != attribution.total_cost_micros
        or recommendation.blockers != expected_blockers
        or recommendation.disposition is not expected_disposition
    ):
        raise CapacityEconomicsError(
            "admission recommendation is not derived from contract evidence"
        )


def build_contract(
    *,
    as_of: str,
    target_tenant_ref: str,
    target_assessment_ref: str,
    target_provider_ref: str,
    target_region: str,
    measurement_windows: Sequence[MeasurementWindow],
    attributions: Sequence[CostAttribution],
    quota_snapshots: Sequence[ProviderQuotaSnapshot],
    forecasts: Sequence[DemandForecast],
    policy: CapacityPolicy,
) -> CapacityEconomicsContract:
    """Build one advisory contract and derive a fail-closed recommendation."""

    as_of = _timestamp(as_of, "as_of")
    tenant_ref = _reference(target_tenant_ref, "target_tenant_ref", "tenantref")
    assessment_ref = _reference(
        target_assessment_ref, "target_assessment_ref", "assessmentref"
    )
    provider_ref = _reference(target_provider_ref, "target_provider_ref", "providerref")
    region = _identifier(target_region, "target_region")
    windows = tuple(measurement_windows)
    attributions_tuple = tuple(attributions)
    snapshots = tuple(quota_snapshots)
    forecasts_tuple = tuple(forecasts)

    target_windows = tuple(
        item
        for item in windows
        if item.dimensions.tenant_ref == tenant_ref
        and item.dimensions.assessment_ref == assessment_ref
        and item.dimensions.provider_ref == provider_ref
        and item.dimensions.region == region
    )
    target_attributions = tuple(
        item
        for item in attributions_tuple
        if item.tenant_ref == tenant_ref and item.assessment_ref == assessment_ref
    )
    target_snapshots = tuple(
        item for item in snapshots if item.provider_ref == provider_ref and item.region == region
    )
    target_forecasts = tuple(
        item
        for item in forecasts_tuple
        if item.provider_ref == provider_ref and item.region == region
    )
    if (
        not target_windows
        or len(target_attributions) != 1
        or len(target_snapshots) != 1
        or len(target_forecasts) != 1
    ):
        raise CapacityEconomicsError(
            "target dimensions require windows, attribution, quota, and forecast"
        )
    attribution = target_attributions[0]
    snapshot = target_snapshots[0]
    forecast = target_forecasts[0]
    blockers_tuple = _derive_admission_blockers(
        as_of=as_of,
        windows=target_windows,
        attribution=attribution,
        snapshot=snapshot,
        forecast=forecast,
        policy=policy,
    )
    recommendation = AdmissionRecommendation(
        as_of=as_of,
        tenant_ref=tenant_ref,
        assessment_ref=assessment_ref,
        provider_ref=provider_ref,
        region=region,
        disposition=(
            AdmissionDisposition.ADMIT
            if not blockers_tuple
            else AdmissionDisposition.DENY
        ),
        blockers=blockers_tuple,
        measurement_window_ids=tuple(item.window_id for item in target_windows),
        attribution_id=attribution.attribution_id,
        quota_snapshot_id=snapshot.snapshot_id,
        forecast_id=forecast.forecast_id,
        policy_id=policy.policy_id,
        projected_cost_micros=attribution.total_cost_micros,
    )
    return CapacityEconomicsContract(
        measurement_windows=windows,
        attributions=attributions_tuple,
        quota_snapshots=snapshots,
        forecasts=forecasts_tuple,
        policy=policy,
        recommendation=recommendation,
    )


def parse_contract(raw: str | bytes | Mapping[str, Any]) -> CapacityEconomicsContract:
    """Parse and revalidate a serialized capacity economics contract."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CapacityEconomicsError("contract bytes must be UTF-8") from exc
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CapacityEconomicsError("contract JSON is invalid") from exc
    else:
        value = raw
    return CapacityEconomicsContract.from_dict(value)
