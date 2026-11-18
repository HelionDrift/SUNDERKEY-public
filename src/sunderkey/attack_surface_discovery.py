"""Deterministic attack surface discovery and correlation contracts.

The module admits observations from injected collectors. It contains no active
scanner, network client, DNS resolver, cloud client, credential reader, or
scheduler. Collector attestations and every tenant, context, scope, request,
and lineage binding are validated before evidence is correlated.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol

SCHEMA_VERSION = 1

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

NO_EFFECTS = {
    "active_scan": "none",
    "authority": "none",
    "cloud": "none",
    "credential_access": "none",
    "dns": "none",
    "execution": "none",
    "network": "none",
    "scheduler": "none",
}

HARD_LIMITS = {
    "max_assets": 20000,
    "max_collectors": 128,
    "max_conflicts": 20000,
    "max_endpoints": 50000,
    "max_gaps": 50000,
    "max_observations": 100000,
    "max_revalidation_plans": 50000,
    "max_services": 50000,
}


class AttackSurfaceDiscoveryError(ValueError):
    """Raised when discovery evidence or correlation fails closed."""


class SurfaceKind(StrEnum):
    """Supported attack surface families."""

    WEB = "web"
    API = "api"
    CLOUD = "cloud"
    IDENTITY = "identity"
    NETWORK = "network"
    CODE = "code"
    THIRD_PARTY = "third_party"


class EntityState(StrEnum):
    """Conservative state of a correlated entity."""

    CURRENT = "current"
    STALE = "stale"
    CONFLICTED = "conflicted"


class TemporalChange(StrEnum):
    """Relationship to an immediately supplied prior report."""

    ADDED = "added"
    CHANGED = "changed"
    UNCHANGED = "unchanged"
    MISSING = "missing"


class GapKind(StrEnum):
    """Reasons more evidence is required."""

    COVERAGE = "coverage"
    IDENTITY_CONFLICT = "identity_conflict"
    LOW_CONFIDENCE = "low_confidence"
    MISSING_OWNERSHIP = "missing_ownership"
    MISSING_SCOPE = "missing_scope"
    STALE_EVIDENCE = "stale_evidence"
    TEMPORAL_MISSING = "temporal_missing"
    UNCORRELATED_SERVICE = "uncorrelated_service"


@dataclass(frozen=True)
class DiscoveryLimits:
    """Fail-closed ceilings for import and correlation."""

    max_assets: int = 5000
    max_collectors: int = 32
    max_conflicts: int = 5000
    max_endpoints: int = 10000
    max_gaps: int = 10000
    max_observations: int = 25000
    max_revalidation_plans: int = 10000
    max_services: int = 10000

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise AttackSurfaceDiscoveryError(f"{name} must be a positive integer")
            if value > HARD_LIMITS[name]:
                raise AttackSurfaceDiscoveryError(f"{name} exceeds its hard limit")

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in sorted(HARD_LIMITS)}

    @classmethod
    def from_dict(cls, raw: Any) -> DiscoveryLimits:
        _exact_fields(raw, set(HARD_LIMITS), "discovery limits")
        return cls(**raw)


@dataclass(frozen=True)
class DiscoveryContext:
    """Tenant-isolated discovery context and governed associations."""

    tenant_id: str
    context_id: str
    scope_binding_sha256: str
    owner_refs: tuple[str, ...]
    scope_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.context_id, "context_id")
        _sha256(self.scope_binding_sha256, "scope_binding_sha256")
        object.__setattr__(self, "owner_refs", _refs(self.owner_refs, "owner_refs"))
        object.__setattr__(self, "scope_refs", _refs(self.scope_refs, "scope_refs"))
        if not self.owner_refs or not self.scope_refs:
            raise AttackSurfaceDiscoveryError("context requires owner and scope references")

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "owner_refs": list(self.owner_refs),
            "scope_binding_sha256": self.scope_binding_sha256,
            "scope_refs": list(self.scope_refs),
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DiscoveryContext:
        _exact_fields(
            raw,
            {"context_id", "owner_refs", "scope_binding_sha256", "scope_refs", "tenant_id"},
            "discovery context",
        )
        return cls(
            tenant_id=raw["tenant_id"],
            context_id=raw["context_id"],
            scope_binding_sha256=raw["scope_binding_sha256"],
            owner_refs=tuple(raw["owner_refs"]),
            scope_refs=tuple(raw["scope_refs"]),
        )


@dataclass(frozen=True)
class CollectorSpec:
    """One passive or existing-evidence collector declaration."""

    collector_id: str
    collector_version: str
    evidence_source_ref: str
    surface_kinds: tuple[SurfaceKind | str, ...]
    record_limit: int
    passive_only: bool = True

    def __post_init__(self) -> None:
        _identifier(self.collector_id, "collector_id")
        _identifier(self.collector_version, "collector_version")
        _identifier(self.evidence_source_ref, "evidence_source_ref")
        try:
            kinds = tuple(sorted({SurfaceKind(value) for value in self.surface_kinds}, key=str))
        except (TypeError, ValueError) as exc:
            raise AttackSurfaceDiscoveryError("collector surface_kinds are invalid") from exc
        if not kinds:
            raise AttackSurfaceDiscoveryError("collector requires at least one surface kind")
        object.__setattr__(self, "surface_kinds", kinds)
        if (
            isinstance(self.record_limit, bool)
            or not isinstance(self.record_limit, int)
            or not 1 <= self.record_limit <= HARD_LIMITS["max_observations"]
        ):
            raise AttackSurfaceDiscoveryError("collector record_limit is invalid")
        if self.passive_only is not True:
            raise AttackSurfaceDiscoveryError("collectors must be passive_only")

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector_id": self.collector_id,
            "collector_version": self.collector_version,
            "evidence_source_ref": self.evidence_source_ref,
            "passive_only": self.passive_only,
            "record_limit": self.record_limit,
            "surface_kinds": [item.value for item in self.surface_kinds],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CollectorSpec:
        _exact_fields(
            raw,
            {
                "collector_id",
                "collector_version",
                "evidence_source_ref",
                "passive_only",
                "record_limit",
                "surface_kinds",
            },
            "collector spec",
        )
        return cls(
            collector_id=raw["collector_id"],
            collector_version=raw["collector_version"],
            evidence_source_ref=raw["evidence_source_ref"],
            surface_kinds=tuple(raw["surface_kinds"]),
            record_limit=raw["record_limit"],
            passive_only=raw["passive_only"],
        )


@dataclass(frozen=True)
class DiscoveryPlan:
    """Content-addressed, bounded, effect-free discovery plan."""

    schema_version: int
    plan_id: str
    plan_sha256: str
    planned_at: str
    valid_until: str
    run_nonce_sha256: str
    context: DiscoveryContext
    collectors: tuple[CollectorSpec, ...]
    limits: DiscoveryLimits
    no_effects: Mapping[str, str]
    qualification_effect: str = "none"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise AttackSurfaceDiscoveryError("plan schema_version is unsupported")
        if not re.fullmatch(r"ADP-[0-9A-F]{32}", self.plan_id):
            raise AttackSurfaceDiscoveryError("plan_id is invalid")
        _sha256(self.plan_sha256, "plan_sha256")
        planned = _utc(self.planned_at, "planned_at")
        if _utc(self.valid_until, "valid_until") <= planned:
            raise AttackSurfaceDiscoveryError("valid_until must follow planned_at")
        _sha256(self.run_nonce_sha256, "run_nonce_sha256")
        if not isinstance(self.context, DiscoveryContext):
            raise AttackSurfaceDiscoveryError("context must be DiscoveryContext")
        if not isinstance(self.limits, DiscoveryLimits):
            raise AttackSurfaceDiscoveryError("limits must be DiscoveryLimits")
        collectors = tuple(self.collectors)
        if not collectors or len(collectors) > self.limits.max_collectors:
            raise AttackSurfaceDiscoveryError("collector count is outside plan limits")
        if any(not isinstance(item, CollectorSpec) for item in collectors):
            raise AttackSurfaceDiscoveryError("collectors contain an invalid value")
        if collectors != tuple(sorted(collectors, key=lambda item: item.collector_id)):
            raise AttackSurfaceDiscoveryError("collectors are not canonically ordered")
        if len({item.collector_id for item in collectors}) != len(collectors):
            raise AttackSurfaceDiscoveryError("collector_id values must be unique")
        if sum(item.record_limit for item in collectors) > self.limits.max_observations:
            raise AttackSurfaceDiscoveryError("collector limits exceed max_observations")
        object.__setattr__(self, "no_effects", _no_effects(self.no_effects))
        if self.qualification_effect != "none":
            raise AttackSurfaceDiscoveryError("plan cannot create a qualification effect")
        expected_sha = _digest("sunderkey.attack-surface-plan.v1", self._identity_payload())
        if self.plan_sha256 != expected_sha or self.plan_id != _derived_id("ADP", expected_sha):
            raise AttackSurfaceDiscoveryError("plan identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "collectors": [item.to_dict() for item in self.collectors],
            "context": self.context.to_dict(),
            "limits": self.limits.to_dict(),
            "no_effects": dict(self.no_effects),
            "planned_at": self.planned_at,
            "qualification_effect": self.qualification_effect,
            "run_nonce_sha256": self.run_nonce_sha256,
            "schema_version": self.schema_version,
            "valid_until": self.valid_until,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
        }

    def request_for(self, collector_id: str) -> CollectorRequest:
        matches = [item for item in self.collectors if item.collector_id == collector_id]
        if not matches:
            raise AttackSurfaceDiscoveryError("collector is not present in plan")
        payload = {
            "collector": matches[0].to_dict(),
            "context": self.context.to_dict(),
            "plan_sha256": self.plan_sha256,
            "run_nonce_sha256": self.run_nonce_sha256,
        }
        request_sha = _digest("sunderkey.attack-surface-request.v1", payload)
        return CollectorRequest(
            request_id=_derived_id("ADR", request_sha),
            request_sha256=request_sha,
            plan_sha256=self.plan_sha256,
            run_nonce_sha256=self.run_nonce_sha256,
            context=self.context,
            collector=matches[0],
        )


@dataclass(frozen=True)
class CollectorRequest:
    """Exact request passed to an injected collector."""

    request_id: str
    request_sha256: str
    plan_sha256: str
    run_nonce_sha256: str
    context: DiscoveryContext
    collector: CollectorSpec

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ADR-[0-9A-F]{32}", self.request_id):
            raise AttackSurfaceDiscoveryError("request_id is invalid")
        for name in ("request_sha256", "plan_sha256", "run_nonce_sha256"):
            _sha256(getattr(self, name), name)
        payload = {
            "collector": self.collector.to_dict(),
            "context": self.context.to_dict(),
            "plan_sha256": self.plan_sha256,
            "run_nonce_sha256": self.run_nonce_sha256,
        }
        expected_sha = _digest("sunderkey.attack-surface-request.v1", payload)
        if self.request_sha256 != expected_sha or self.request_id != _derived_id(
            "ADR", expected_sha
        ):
            raise AttackSurfaceDiscoveryError("request identity does not match canonical content")


@dataclass(frozen=True)
class CollectorObservation:
    """Content-addressed observation containing digests and safe references only."""

    observation_id: str
    observation_sha256: str
    request_sha256: str
    tenant_id: str
    context_id: str
    collector_id: str
    sequence: int
    surface_kind: SurfaceKind | str
    native_key_sha256: str
    asset_key_sha256: str
    service_key_sha256: str | None
    endpoint_key_sha256: str | None
    content_sha256: str
    provenance_sha256: str
    observed_at: str
    freshness_expires_at: str
    confidence: int
    owner_refs: tuple[str, ...]
    scope_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ADO-[0-9A-F]{32}", self.observation_id):
            raise AttackSurfaceDiscoveryError("observation_id is invalid")
        for name in (
            "observation_sha256",
            "request_sha256",
            "native_key_sha256",
            "asset_key_sha256",
            "content_sha256",
            "provenance_sha256",
        ):
            _sha256(getattr(self, name), name)
        for name in ("service_key_sha256", "endpoint_key_sha256"):
            value = getattr(self, name)
            if value is not None:
                _sha256(value, name)
        _identifier(self.tenant_id, "observation tenant_id")
        _identifier(self.context_id, "observation context_id")
        _identifier(self.collector_id, "observation collector_id")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            raise AttackSurfaceDiscoveryError("observation sequence is invalid")
        try:
            kind = SurfaceKind(self.surface_kind)
        except (TypeError, ValueError) as exc:
            raise AttackSurfaceDiscoveryError("observation surface_kind is invalid") from exc
        object.__setattr__(self, "surface_kind", kind)
        observed = _utc(self.observed_at, "observed_at")
        if _utc(self.freshness_expires_at, "freshness_expires_at") <= observed:
            raise AttackSurfaceDiscoveryError("freshness_expires_at must follow observed_at")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, int)
            or not 0 <= self.confidence <= 100
        ):
            raise AttackSurfaceDiscoveryError("confidence must be from 0 through 100")
        object.__setattr__(self, "owner_refs", _refs(self.owner_refs, "observation owner_refs"))
        object.__setattr__(self, "scope_refs", _refs(self.scope_refs, "observation scope_refs"))
        if self.endpoint_key_sha256 is not None and self.service_key_sha256 is None:
            raise AttackSurfaceDiscoveryError("endpoint evidence requires a service key")
        expected_sha = _digest("sunderkey.attack-surface-observation.v1", self._identity_payload())
        if self.observation_sha256 != expected_sha or self.observation_id != _derived_id(
            "ADO", expected_sha
        ):
            raise AttackSurfaceDiscoveryError(
                "observation identity does not match canonical content"
            )

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "asset_key_sha256": self.asset_key_sha256,
            "collector_id": self.collector_id,
            "confidence": self.confidence,
            "content_sha256": self.content_sha256,
            "context_id": self.context_id,
            "endpoint_key_sha256": self.endpoint_key_sha256,
            "freshness_expires_at": self.freshness_expires_at,
            "native_key_sha256": self.native_key_sha256,
            "observed_at": self.observed_at,
            "owner_refs": list(self.owner_refs),
            "provenance_sha256": self.provenance_sha256,
            "request_sha256": self.request_sha256,
            "scope_refs": list(self.scope_refs),
            "sequence": self.sequence,
            "service_key_sha256": self.service_key_sha256,
            "surface_kind": self.surface_kind.value,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CollectorObservation:
        fields = {
            "asset_key_sha256",
            "collector_id",
            "confidence",
            "content_sha256",
            "context_id",
            "endpoint_key_sha256",
            "freshness_expires_at",
            "native_key_sha256",
            "observation_id",
            "observation_sha256",
            "observed_at",
            "owner_refs",
            "provenance_sha256",
            "request_sha256",
            "scope_refs",
            "sequence",
            "service_key_sha256",
            "surface_kind",
            "tenant_id",
        }
        _exact_fields(raw, fields, "collector observation")
        return cls(
            **{key: raw[key] for key in fields - {"owner_refs", "scope_refs"}},
            owner_refs=tuple(raw["owner_refs"]),
            scope_refs=tuple(raw["scope_refs"]),
        )


@dataclass(frozen=True)
class CollectorResult:
    """Attested result returned by one injected collector."""

    result_id: str
    result_sha256: str
    plan_sha256: str
    request_sha256: str
    tenant_id: str
    context_id: str
    collector_id: str
    observations: tuple[CollectorObservation, ...]
    network_call_performed: bool
    active_scan_performed: bool
    credential_material_returned: bool

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ADC-[0-9A-F]{32}", self.result_id):
            raise AttackSurfaceDiscoveryError("result_id is invalid")
        _sha256(self.result_sha256, "result_sha256")
        _sha256(self.plan_sha256, "result plan_sha256")
        _sha256(self.request_sha256, "result request_sha256")
        for name in ("tenant_id", "context_id", "collector_id"):
            _identifier(getattr(self, name), f"result {name}")
        observations = tuple(self.observations)
        if any(not isinstance(item, CollectorObservation) for item in observations):
            raise AttackSurfaceDiscoveryError("result observations contain an invalid value")
        if observations != tuple(sorted(observations, key=lambda item: item.sequence)):
            raise AttackSurfaceDiscoveryError("result observations are not ordered by sequence")
        if len({item.sequence for item in observations}) != len(observations):
            raise AttackSurfaceDiscoveryError("observation sequences must be unique")
        if len({item.observation_sha256 for item in observations}) != len(observations):
            raise AttackSurfaceDiscoveryError("replayed observation detected in collector result")
        for item in observations:
            if (
                item.request_sha256 != self.request_sha256
                or item.tenant_id != self.tenant_id
                or item.context_id != self.context_id
                or item.collector_id != self.collector_id
            ):
                raise AttackSurfaceDiscoveryError("observation result binding mismatch")
        for name in (
            "network_call_performed",
            "active_scan_performed",
            "credential_material_returned",
        ):
            if getattr(self, name) is not False:
                raise AttackSurfaceDiscoveryError(f"{name} must be false")
        expected_sha = _digest(
            "sunderkey.attack-surface-collector-result.v1", self._identity_payload()
        )
        if self.result_sha256 != expected_sha or self.result_id != _derived_id("ADC", expected_sha):
            raise AttackSurfaceDiscoveryError("result identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "active_scan_performed": self.active_scan_performed,
            "collector_id": self.collector_id,
            "context_id": self.context_id,
            "credential_material_returned": self.credential_material_returned,
            "network_call_performed": self.network_call_performed,
            "observations": [item.to_dict() for item in self.observations],
            "plan_sha256": self.plan_sha256,
            "request_sha256": self.request_sha256,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "result_id": self.result_id,
            "result_sha256": self.result_sha256,
        }


class InjectedCollector(Protocol):
    """Trusted, externally supplied passive observation collector."""

    def collect(self, request: CollectorRequest) -> CollectorResult:
        """Return a request-bound, passive collector result."""


@dataclass(frozen=True)
class ObservationBatch:
    """Content-addressed imported evidence from a single discovery plan."""

    batch_id: str
    batch_sha256: str
    collected_at: str
    plan_sha256: str
    run_nonce_sha256: str
    context: DiscoveryContext
    planned_surface_kinds: tuple[SurfaceKind | str, ...]
    collector_ids: tuple[str, ...]
    collector_result_sha256s: tuple[str, ...]
    observations: tuple[CollectorObservation, ...]
    limits: DiscoveryLimits
    no_effects: Mapping[str, str]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ADB-[0-9A-F]{32}", self.batch_id):
            raise AttackSurfaceDiscoveryError("batch_id is invalid")
        for name in ("batch_sha256", "plan_sha256", "run_nonce_sha256"):
            _sha256(getattr(self, name), name)
        _utc(self.collected_at, "collected_at")
        kinds = tuple(sorted({SurfaceKind(value) for value in self.planned_surface_kinds}, key=str))
        object.__setattr__(self, "planned_surface_kinds", kinds)
        object.__setattr__(self, "collector_ids", _refs(self.collector_ids, "collector_ids"))
        digests = tuple(sorted(self.collector_result_sha256s))
        if len(set(digests)) != len(digests):
            raise AttackSurfaceDiscoveryError("collector result replay detected")
        for digest in digests:
            _sha256(digest, "collector_result_sha256")
        object.__setattr__(self, "collector_result_sha256s", digests)
        observations = tuple(sorted(self.observations, key=lambda item: item.observation_sha256))
        if tuple(self.observations) != observations:
            raise AttackSurfaceDiscoveryError("batch observations are not canonically ordered")
        if len(observations) > self.limits.max_observations:
            raise AttackSurfaceDiscoveryError("batch exceeds max_observations")
        if len({item.observation_sha256 for item in observations}) != len(observations):
            raise AttackSurfaceDiscoveryError("observation replay detected in batch")
        if any(
            item.tenant_id != self.context.tenant_id or item.context_id != self.context.context_id
            for item in observations
        ):
            raise AttackSurfaceDiscoveryError("batch contains cross-context evidence")
        object.__setattr__(self, "no_effects", _no_effects(self.no_effects))
        expected_sha = _digest("sunderkey.attack-surface-batch.v1", self._identity_payload())
        if self.batch_sha256 != expected_sha or self.batch_id != _derived_id("ADB", expected_sha):
            raise AttackSurfaceDiscoveryError("batch identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "collected_at": self.collected_at,
            "collector_ids": list(self.collector_ids),
            "collector_result_sha256s": list(self.collector_result_sha256s),
            "context": self.context.to_dict(),
            "limits": self.limits.to_dict(),
            "no_effects": dict(self.no_effects),
            "observations": [item.to_dict() for item in self.observations],
            "plan_sha256": self.plan_sha256,
            "planned_surface_kinds": [item.value for item in self.planned_surface_kinds],
            "run_nonce_sha256": self.run_nonce_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "batch_id": self.batch_id,
            "batch_sha256": self.batch_sha256,
        }


@dataclass(frozen=True)
class DiscoveryConflict:
    """Deterministic evidence contradiction retained for review."""

    conflict_id: str
    conflict_sha256: str
    conflict_kind: str
    key_sha256: str
    observation_sha256s: tuple[str, ...]
    claim_values: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ADF-[0-9A-F]{32}", self.conflict_id):
            raise AttackSurfaceDiscoveryError("conflict_id is invalid")
        _sha256(self.conflict_sha256, "conflict_sha256")
        _identifier(self.conflict_kind, "conflict_kind")
        _sha256(self.key_sha256, "conflict key_sha256")
        values = _refs(self.claim_values, "claim_values")
        object.__setattr__(self, "claim_values", values)
        observations = tuple(sorted(self.observation_sha256s))
        for digest in observations:
            _sha256(digest, "conflict observation_sha256")
        if not observations or not values:
            raise AttackSurfaceDiscoveryError("conflict requires observations and claims")
        object.__setattr__(self, "observation_sha256s", observations)
        expected_sha = _digest("sunderkey.attack-surface-conflict.v1", self._identity_payload())
        if self.conflict_sha256 != expected_sha or self.conflict_id != _derived_id(
            "ADF", expected_sha
        ):
            raise AttackSurfaceDiscoveryError("conflict identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "claim_values": list(self.claim_values),
            "conflict_kind": self.conflict_kind,
            "key_sha256": self.key_sha256,
            "observation_sha256s": list(self.observation_sha256s),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "conflict_id": self.conflict_id,
            "conflict_sha256": self.conflict_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DiscoveryConflict:
        _exact_fields(
            raw,
            {
                "claim_values",
                "conflict_id",
                "conflict_kind",
                "conflict_sha256",
                "key_sha256",
                "observation_sha256s",
            },
            "discovery conflict",
        )
        return cls(
            conflict_id=raw["conflict_id"],
            conflict_sha256=raw["conflict_sha256"],
            conflict_kind=raw["conflict_kind"],
            key_sha256=raw["key_sha256"],
            observation_sha256s=tuple(raw["observation_sha256s"]),
            claim_values=tuple(raw["claim_values"]),
        )


@dataclass(frozen=True)
class CorrelatedEntity:
    """Resolved asset, service, or endpoint projection."""

    entity_id: str
    entity_sha256: str
    entity_kind: str
    stable_key_sha256: str
    parent_entity_id: str | None
    state: EntityState | str
    surface_kinds: tuple[SurfaceKind | str, ...]
    confidence: int
    owner_refs: tuple[str, ...]
    scope_refs: tuple[str, ...]
    provenance_sha256s: tuple[str, ...]
    observation_sha256s: tuple[str, ...]
    conflict_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"(ASA|ASS|ASE)-[0-9A-F]{32}", self.entity_id):
            raise AttackSurfaceDiscoveryError("entity_id is invalid")
        _sha256(self.entity_sha256, "entity_sha256")
        if self.entity_kind not in {"asset", "service", "endpoint"}:
            raise AttackSurfaceDiscoveryError("entity_kind is invalid")
        _sha256(self.stable_key_sha256, "stable_key_sha256")
        if self.entity_kind == "asset" and self.parent_entity_id is not None:
            raise AttackSurfaceDiscoveryError("asset cannot have a parent entity")
        if self.entity_kind != "asset" and self.parent_entity_id is None:
            raise AttackSurfaceDiscoveryError("service and endpoint require a parent entity")
        if self.parent_entity_id is not None:
            _identifier(self.parent_entity_id, "parent_entity_id")
        try:
            state = EntityState(self.state)
            kinds = tuple(sorted({SurfaceKind(value) for value in self.surface_kinds}, key=str))
        except (TypeError, ValueError) as exc:
            raise AttackSurfaceDiscoveryError("entity state or surface kind is invalid") from exc
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "surface_kinds", kinds)
        if not kinds:
            raise AttackSurfaceDiscoveryError("entity requires surface kinds")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, int)
            or not 0 <= self.confidence <= 100
        ):
            raise AttackSurfaceDiscoveryError("entity confidence is invalid")
        object.__setattr__(self, "owner_refs", _refs(self.owner_refs, "entity owner_refs"))
        object.__setattr__(self, "scope_refs", _refs(self.scope_refs, "entity scope_refs"))
        for name in ("provenance_sha256s", "observation_sha256s"):
            values = tuple(sorted(set(getattr(self, name))))
            if not values:
                raise AttackSurfaceDiscoveryError(f"{name} cannot be empty")
            for digest in values:
                _sha256(digest, name)
            object.__setattr__(self, name, values)
        object.__setattr__(self, "conflict_ids", _refs(self.conflict_ids, "conflict_ids"))
        expected_sha = _digest("sunderkey.attack-surface-entity.v1", self._identity_payload())
        prefix = {"asset": "ASA", "service": "ASS", "endpoint": "ASE"}[self.entity_kind]
        stable_id = _derived_id(
            prefix,
            _digest(
                f"sunderkey.{self.entity_kind}-identity.v1",
                {
                    "parent_entity_id": self.parent_entity_id,
                    "stable_key_sha256": self.stable_key_sha256,
                },
            ),
        )
        if self.entity_sha256 != expected_sha or self.entity_id != stable_id:
            raise AttackSurfaceDiscoveryError("entity identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "conflict_ids": list(self.conflict_ids),
            "entity_kind": self.entity_kind,
            "observation_sha256s": list(self.observation_sha256s),
            "owner_refs": list(self.owner_refs),
            "parent_entity_id": self.parent_entity_id,
            "provenance_sha256s": list(self.provenance_sha256s),
            "scope_refs": list(self.scope_refs),
            "stable_key_sha256": self.stable_key_sha256,
            "state": self.state.value,
            "surface_kinds": [item.value for item in self.surface_kinds],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "entity_id": self.entity_id,
            "entity_sha256": self.entity_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CorrelatedEntity:
        fields = {
            "confidence",
            "conflict_ids",
            "entity_id",
            "entity_kind",
            "entity_sha256",
            "observation_sha256s",
            "owner_refs",
            "parent_entity_id",
            "provenance_sha256s",
            "scope_refs",
            "stable_key_sha256",
            "state",
            "surface_kinds",
        }
        _exact_fields(raw, fields, "correlated entity")
        return cls(
            **{
                key: raw[key]
                for key in fields
                - {
                    "conflict_ids",
                    "observation_sha256s",
                    "owner_refs",
                    "provenance_sha256s",
                    "scope_refs",
                    "surface_kinds",
                }
            },
            conflict_ids=tuple(raw["conflict_ids"]),
            observation_sha256s=tuple(raw["observation_sha256s"]),
            owner_refs=tuple(raw["owner_refs"]),
            provenance_sha256s=tuple(raw["provenance_sha256s"]),
            scope_refs=tuple(raw["scope_refs"]),
            surface_kinds=tuple(raw["surface_kinds"]),
        )


@dataclass(frozen=True)
class TemporalLink:
    """Stable entity relationship between adjacent reports."""

    link_id: str
    link_sha256: str
    entity_id: str
    entity_kind: str
    surface_kind: SurfaceKind | str
    change: TemporalChange | str
    prior_entity_sha256: str | None
    current_entity_sha256: str | None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ADT-[0-9A-F]{32}", self.link_id):
            raise AttackSurfaceDiscoveryError("link_id is invalid")
        _sha256(self.link_sha256, "link_sha256")
        _identifier(self.entity_id, "temporal entity_id")
        if self.entity_kind not in {"asset", "service", "endpoint"}:
            raise AttackSurfaceDiscoveryError("temporal entity_kind is invalid")
        try:
            surface_kind = SurfaceKind(self.surface_kind)
            change = TemporalChange(self.change)
        except (TypeError, ValueError) as exc:
            raise AttackSurfaceDiscoveryError("temporal change or surface kind is invalid") from exc
        object.__setattr__(self, "surface_kind", surface_kind)
        object.__setattr__(self, "change", change)
        for name in ("prior_entity_sha256", "current_entity_sha256"):
            value = getattr(self, name)
            if value is not None:
                _sha256(value, name)
        if change is TemporalChange.ADDED and (
            self.prior_entity_sha256 is not None or self.current_entity_sha256 is None
        ):
            raise AttackSurfaceDiscoveryError("added link requires only a current entity")
        if change is TemporalChange.MISSING and (
            self.prior_entity_sha256 is None or self.current_entity_sha256 is not None
        ):
            raise AttackSurfaceDiscoveryError("missing link requires only a prior entity")
        if change in {TemporalChange.CHANGED, TemporalChange.UNCHANGED} and (
            self.prior_entity_sha256 is None or self.current_entity_sha256 is None
        ):
            raise AttackSurfaceDiscoveryError("linked entities require prior and current digests")
        expected_sha = _digest(
            "sunderkey.attack-surface-temporal-link.v1", self._identity_payload()
        )
        if self.link_sha256 != expected_sha or self.link_id != _derived_id("ADT", expected_sha):
            raise AttackSurfaceDiscoveryError("temporal link identity does not match content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "change": self.change.value,
            "current_entity_sha256": self.current_entity_sha256,
            "entity_id": self.entity_id,
            "entity_kind": self.entity_kind,
            "prior_entity_sha256": self.prior_entity_sha256,
            "surface_kind": self.surface_kind.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "link_id": self.link_id,
            "link_sha256": self.link_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TemporalLink:
        _exact_fields(
            raw,
            {
                "change",
                "current_entity_sha256",
                "entity_id",
                "entity_kind",
                "link_id",
                "link_sha256",
                "prior_entity_sha256",
                "surface_kind",
            },
            "temporal link",
        )
        return cls(**raw)


@dataclass(frozen=True)
class DiscoveryGap:
    """Prioritized deficiency in discovery evidence."""

    gap_id: str
    gap_sha256: str
    gap_kind: GapKind | str
    priority: int
    entity_id: str | None
    surface_kind: SurfaceKind | str
    reason_code: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ADG-[0-9A-F]{32}", self.gap_id):
            raise AttackSurfaceDiscoveryError("gap_id is invalid")
        _sha256(self.gap_sha256, "gap_sha256")
        try:
            gap_kind = GapKind(self.gap_kind)
            surface_kind = SurfaceKind(self.surface_kind)
        except (TypeError, ValueError) as exc:
            raise AttackSurfaceDiscoveryError("gap enum value is invalid") from exc
        object.__setattr__(self, "gap_kind", gap_kind)
        object.__setattr__(self, "surface_kind", surface_kind)
        if (
            not isinstance(self.priority, int)
            or isinstance(self.priority, bool)
            or not 1 <= self.priority <= 5
        ):
            raise AttackSurfaceDiscoveryError("gap priority must be from 1 through 5")
        if self.entity_id is not None:
            _identifier(self.entity_id, "gap entity_id")
        _identifier(self.reason_code, "gap reason_code")
        object.__setattr__(self, "evidence_refs", _refs(self.evidence_refs, "gap evidence_refs"))
        expected_sha = _digest("sunderkey.attack-surface-gap.v1", self._identity_payload())
        if self.gap_sha256 != expected_sha or self.gap_id != _derived_id("ADG", expected_sha):
            raise AttackSurfaceDiscoveryError("gap identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "evidence_refs": list(self.evidence_refs),
            "gap_kind": self.gap_kind.value,
            "priority": self.priority,
            "reason_code": self.reason_code,
            "surface_kind": self.surface_kind.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._identity_payload(), "gap_id": self.gap_id, "gap_sha256": self.gap_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> DiscoveryGap:
        _exact_fields(
            raw,
            {
                "entity_id",
                "evidence_refs",
                "gap_id",
                "gap_kind",
                "gap_sha256",
                "priority",
                "reason_code",
                "surface_kind",
            },
            "discovery gap",
        )
        return cls(
            **{key: raw[key] for key in raw if key != "evidence_refs"},
            evidence_refs=tuple(raw["evidence_refs"]),
        )


@dataclass(frozen=True)
class RevalidationPlan:
    """Bounded, proposal-only response to one discovery gap."""

    revalidation_id: str
    revalidation_sha256: str
    gap_id: str
    priority: int
    requested_collector_ids: tuple[str, ...]
    record_limit: int
    active_scan_permitted: bool
    network_access_permitted: bool
    status: str = "proposal_only"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ADV-[0-9A-F]{32}", self.revalidation_id):
            raise AttackSurfaceDiscoveryError("revalidation_id is invalid")
        _sha256(self.revalidation_sha256, "revalidation_sha256")
        _identifier(self.gap_id, "revalidation gap_id")
        if (
            not isinstance(self.priority, int)
            or isinstance(self.priority, bool)
            or not 1 <= self.priority <= 5
        ):
            raise AttackSurfaceDiscoveryError("revalidation priority is invalid")
        object.__setattr__(
            self,
            "requested_collector_ids",
            _refs(self.requested_collector_ids, "requested_collector_ids"),
        )
        if not self.requested_collector_ids:
            raise AttackSurfaceDiscoveryError("revalidation requires a collector")
        if (
            isinstance(self.record_limit, bool)
            or not isinstance(self.record_limit, int)
            or self.record_limit < 1
        ):
            raise AttackSurfaceDiscoveryError("revalidation record_limit is invalid")
        if self.active_scan_permitted is not False or self.network_access_permitted is not False:
            raise AttackSurfaceDiscoveryError(
                "revalidation cannot permit active or network effects"
            )
        if self.status != "proposal_only":
            raise AttackSurfaceDiscoveryError("revalidation status must be proposal_only")
        expected_sha = _digest("sunderkey.attack-surface-revalidation.v1", self._identity_payload())
        if self.revalidation_sha256 != expected_sha or self.revalidation_id != _derived_id(
            "ADV", expected_sha
        ):
            raise AttackSurfaceDiscoveryError("revalidation identity does not match content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "active_scan_permitted": self.active_scan_permitted,
            "gap_id": self.gap_id,
            "network_access_permitted": self.network_access_permitted,
            "priority": self.priority,
            "record_limit": self.record_limit,
            "requested_collector_ids": list(self.requested_collector_ids),
            "status": self.status,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "revalidation_id": self.revalidation_id,
            "revalidation_sha256": self.revalidation_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RevalidationPlan:
        _exact_fields(
            raw,
            {
                "active_scan_permitted",
                "gap_id",
                "network_access_permitted",
                "priority",
                "record_limit",
                "requested_collector_ids",
                "revalidation_id",
                "revalidation_sha256",
                "status",
            },
            "revalidation plan",
        )
        return cls(
            **{key: raw[key] for key in raw if key != "requested_collector_ids"},
            requested_collector_ids=tuple(raw["requested_collector_ids"]),
        )


@dataclass(frozen=True)
class DiscoveryReport:
    """Content-addressed attack surface correlation report."""

    schema_version: int
    report_id: str
    report_sha256: str
    generated_at: str
    context: DiscoveryContext
    observation_batch_sha256: str
    parent_report_sha256: str | None
    assets: tuple[CorrelatedEntity, ...]
    services: tuple[CorrelatedEntity, ...]
    endpoints: tuple[CorrelatedEntity, ...]
    conflicts: tuple[DiscoveryConflict, ...]
    temporal_links: tuple[TemporalLink, ...]
    gaps: tuple[DiscoveryGap, ...]
    revalidation_plans: tuple[RevalidationPlan, ...]
    limits: DiscoveryLimits
    no_effects: Mapping[str, str]
    evidence_level: str = "repository_only"
    operational_status: str = "nonqualified"
    qualification_effect: str = "none"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise AttackSurfaceDiscoveryError("report schema_version is unsupported")
        if not re.fullmatch(r"ADS-[0-9A-F]{32}", self.report_id):
            raise AttackSurfaceDiscoveryError("report_id is invalid")
        _sha256(self.report_sha256, "report_sha256")
        _utc(self.generated_at, "generated_at")
        _sha256(self.observation_batch_sha256, "observation_batch_sha256")
        if self.parent_report_sha256 is not None:
            _sha256(self.parent_report_sha256, "parent_report_sha256")
        groups = (
            ("assets", self.assets, "asset", self.limits.max_assets),
            ("services", self.services, "service", self.limits.max_services),
            ("endpoints", self.endpoints, "endpoint", self.limits.max_endpoints),
        )
        for name, values, kind, limit in groups:
            if len(values) > limit:
                raise AttackSurfaceDiscoveryError(f"{name} exceed report limits")
            if any(item.entity_kind != kind for item in values):
                raise AttackSurfaceDiscoveryError(f"{name} contain the wrong entity kind")
            if tuple(values) != tuple(sorted(values, key=lambda item: item.entity_id)):
                raise AttackSurfaceDiscoveryError(f"{name} are not canonically ordered")
        for name, values, limit in (
            ("conflicts", self.conflicts, self.limits.max_conflicts),
            ("gaps", self.gaps, self.limits.max_gaps),
            ("revalidation_plans", self.revalidation_plans, self.limits.max_revalidation_plans),
        ):
            if len(values) > limit:
                raise AttackSurfaceDiscoveryError(f"{name} exceed report limits")
        if tuple(self.gaps) != tuple(
            sorted(self.gaps, key=lambda item: (item.priority, item.gap_id))
        ):
            raise AttackSurfaceDiscoveryError("gaps are not priority ordered")
        if tuple(self.revalidation_plans) != tuple(
            sorted(self.revalidation_plans, key=lambda item: (item.priority, item.revalidation_id))
        ):
            raise AttackSurfaceDiscoveryError("revalidation plans are not priority ordered")
        object.__setattr__(self, "no_effects", _no_effects(self.no_effects))
        if (
            self.evidence_level != "repository_only"
            or self.operational_status != "nonqualified"
            or self.qualification_effect != "none"
        ):
            raise AttackSurfaceDiscoveryError("report assurance declarations are invalid")
        expected_sha = _digest("sunderkey.attack-surface-report.v1", self._identity_payload())
        if self.report_sha256 != expected_sha or self.report_id != _derived_id("ADS", expected_sha):
            raise AttackSurfaceDiscoveryError("report identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "assets": [item.to_dict() for item in self.assets],
            "conflicts": [item.to_dict() for item in self.conflicts],
            "context": self.context.to_dict(),
            "endpoints": [item.to_dict() for item in self.endpoints],
            "evidence_level": self.evidence_level,
            "gaps": [item.to_dict() for item in self.gaps],
            "generated_at": self.generated_at,
            "limits": self.limits.to_dict(),
            "no_effects": dict(self.no_effects),
            "observation_batch_sha256": self.observation_batch_sha256,
            "operational_status": self.operational_status,
            "parent_report_sha256": self.parent_report_sha256,
            "qualification_effect": self.qualification_effect,
            "revalidation_plans": [item.to_dict() for item in self.revalidation_plans],
            "schema_version": self.schema_version,
            "services": [item.to_dict() for item in self.services],
            "temporal_links": [item.to_dict() for item in self.temporal_links],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DiscoveryReport:
        fields = {
            "assets",
            "conflicts",
            "context",
            "endpoints",
            "evidence_level",
            "gaps",
            "generated_at",
            "limits",
            "no_effects",
            "observation_batch_sha256",
            "operational_status",
            "parent_report_sha256",
            "qualification_effect",
            "report_id",
            "report_sha256",
            "revalidation_plans",
            "schema_version",
            "services",
            "temporal_links",
        }
        _exact_fields(raw, fields, "discovery report")
        result = cls(
            schema_version=raw["schema_version"],
            report_id=raw["report_id"],
            report_sha256=raw["report_sha256"],
            generated_at=raw["generated_at"],
            context=DiscoveryContext.from_dict(raw["context"]),
            observation_batch_sha256=raw["observation_batch_sha256"],
            parent_report_sha256=raw["parent_report_sha256"],
            assets=tuple(CorrelatedEntity.from_dict(item) for item in raw["assets"]),
            services=tuple(CorrelatedEntity.from_dict(item) for item in raw["services"]),
            endpoints=tuple(CorrelatedEntity.from_dict(item) for item in raw["endpoints"]),
            conflicts=tuple(DiscoveryConflict.from_dict(item) for item in raw["conflicts"]),
            temporal_links=tuple(TemporalLink.from_dict(item) for item in raw["temporal_links"]),
            gaps=tuple(DiscoveryGap.from_dict(item) for item in raw["gaps"]),
            revalidation_plans=tuple(
                RevalidationPlan.from_dict(item) for item in raw["revalidation_plans"]
            ),
            limits=DiscoveryLimits.from_dict(raw["limits"]),
            no_effects=raw["no_effects"],
            evidence_level=raw["evidence_level"],
            operational_status=raw["operational_status"],
            qualification_effect=raw["qualification_effect"],
        )
        if result.to_dict() != dict(raw):
            raise AttackSurfaceDiscoveryError("discovery report is not canonical")
        return result


def build_discovery_plan(
    context: DiscoveryContext,
    collectors: Sequence[CollectorSpec],
    *,
    planned_at: str,
    valid_until: str,
    run_nonce_sha256: str,
    limits: DiscoveryLimits | None = None,
) -> DiscoveryPlan:
    """Build a bounded plan that permits only passive evidence collection."""

    selected_limits = limits or DiscoveryLimits()
    ordered = tuple(sorted(collectors, key=lambda item: item.collector_id))
    payload = {
        "collectors": [item.to_dict() for item in ordered],
        "context": context.to_dict(),
        "limits": selected_limits.to_dict(),
        "no_effects": dict(NO_EFFECTS),
        "planned_at": planned_at,
        "qualification_effect": "none",
        "run_nonce_sha256": run_nonce_sha256,
        "schema_version": SCHEMA_VERSION,
        "valid_until": valid_until,
    }
    digest = _digest("sunderkey.attack-surface-plan.v1", payload)
    return DiscoveryPlan(
        schema_version=SCHEMA_VERSION,
        plan_id=_derived_id("ADP", digest),
        plan_sha256=digest,
        planned_at=planned_at,
        valid_until=valid_until,
        run_nonce_sha256=run_nonce_sha256,
        context=context,
        collectors=ordered,
        limits=selected_limits,
        no_effects=NO_EFFECTS,
    )


def build_collector_observation(
    request: CollectorRequest,
    *,
    sequence: int,
    surface_kind: SurfaceKind | str,
    native_key_sha256: str,
    asset_key_sha256: str,
    content_sha256: str,
    provenance_sha256: str,
    observed_at: str,
    freshness_expires_at: str,
    confidence: int,
    service_key_sha256: str | None = None,
    endpoint_key_sha256: str | None = None,
    owner_refs: Sequence[str] = (),
    scope_refs: Sequence[str] = (),
) -> CollectorObservation:
    """Build one request-bound digest-only observation."""

    kind = SurfaceKind(surface_kind)
    payload = {
        "asset_key_sha256": asset_key_sha256,
        "collector_id": request.collector.collector_id,
        "confidence": confidence,
        "content_sha256": content_sha256,
        "context_id": request.context.context_id,
        "endpoint_key_sha256": endpoint_key_sha256,
        "freshness_expires_at": freshness_expires_at,
        "native_key_sha256": native_key_sha256,
        "observed_at": observed_at,
        "owner_refs": list(_refs(tuple(owner_refs), "observation owner_refs")),
        "provenance_sha256": provenance_sha256,
        "request_sha256": request.request_sha256,
        "scope_refs": list(_refs(tuple(scope_refs), "observation scope_refs")),
        "sequence": sequence,
        "service_key_sha256": service_key_sha256,
        "surface_kind": kind.value,
        "tenant_id": request.context.tenant_id,
    }
    digest = _digest("sunderkey.attack-surface-observation.v1", payload)
    return CollectorObservation(
        observation_id=_derived_id("ADO", digest),
        observation_sha256=digest,
        request_sha256=request.request_sha256,
        tenant_id=request.context.tenant_id,
        context_id=request.context.context_id,
        collector_id=request.collector.collector_id,
        sequence=sequence,
        surface_kind=kind,
        native_key_sha256=native_key_sha256,
        asset_key_sha256=asset_key_sha256,
        service_key_sha256=service_key_sha256,
        endpoint_key_sha256=endpoint_key_sha256,
        content_sha256=content_sha256,
        provenance_sha256=provenance_sha256,
        observed_at=observed_at,
        freshness_expires_at=freshness_expires_at,
        confidence=confidence,
        owner_refs=tuple(owner_refs),
        scope_refs=tuple(scope_refs),
    )


def build_collector_result(
    request: CollectorRequest,
    observations: Sequence[CollectorObservation],
) -> CollectorResult:
    """Build an attested passive result for an injected collector."""

    ordered = tuple(sorted(observations, key=lambda item: item.sequence))
    payload = {
        "active_scan_performed": False,
        "collector_id": request.collector.collector_id,
        "context_id": request.context.context_id,
        "credential_material_returned": False,
        "network_call_performed": False,
        "observations": [item.to_dict() for item in ordered],
        "plan_sha256": request.plan_sha256,
        "request_sha256": request.request_sha256,
        "tenant_id": request.context.tenant_id,
    }
    digest = _digest("sunderkey.attack-surface-collector-result.v1", payload)
    return CollectorResult(
        result_id=_derived_id("ADC", digest),
        result_sha256=digest,
        plan_sha256=request.plan_sha256,
        request_sha256=request.request_sha256,
        tenant_id=request.context.tenant_id,
        context_id=request.context.context_id,
        collector_id=request.collector.collector_id,
        observations=ordered,
        network_call_performed=False,
        active_scan_performed=False,
        credential_material_returned=False,
    )


def execute_discovery_plan(
    plan: DiscoveryPlan,
    collectors: Mapping[str, InjectedCollector],
    *,
    collected_at: str,
    seen_observation_sha256s: Sequence[str] = (),
) -> ObservationBatch:
    """Call exact injected collectors once and import their passive results."""

    instant = _utc(collected_at, "collected_at")
    if not (_utc(plan.planned_at, "planned_at") <= instant < _utc(plan.valid_until, "valid_until")):
        raise AttackSurfaceDiscoveryError("collection time is outside the plan validity window")
    expected_ids = {item.collector_id for item in plan.collectors}
    if set(collectors) != expected_ids:
        raise AttackSurfaceDiscoveryError("injected collector set does not exactly match plan")
    seen = set(seen_observation_sha256s)
    for digest in seen:
        _sha256(digest, "seen observation digest")
    results: list[CollectorResult] = []
    observations: list[CollectorObservation] = []
    kinds: set[SurfaceKind] = set()
    for spec in plan.collectors:
        request = plan.request_for(spec.collector_id)
        result = collectors[spec.collector_id].collect(request)
        if not isinstance(result, CollectorResult):
            raise AttackSurfaceDiscoveryError("injected collector returned an invalid result")
        if (
            result.plan_sha256 != plan.plan_sha256
            or result.request_sha256 != request.request_sha256
            or result.collector_id != spec.collector_id
            or result.tenant_id != plan.context.tenant_id
            or result.context_id != plan.context.context_id
        ):
            raise AttackSurfaceDiscoveryError("collector result binding mismatch")
        if len(result.observations) > spec.record_limit:
            raise AttackSurfaceDiscoveryError("collector result exceeds its record limit")
        if any(item.surface_kind not in spec.surface_kinds for item in result.observations):
            raise AttackSurfaceDiscoveryError("collector returned an undeclared surface kind")
        for item in result.observations:
            if item.observation_sha256 in seen:
                raise AttackSurfaceDiscoveryError("replayed observation was rejected")
            seen.add(item.observation_sha256)
            observations.append(item)
        kinds.update(spec.surface_kinds)
        results.append(result)
    ordered_observations = tuple(sorted(observations, key=lambda item: item.observation_sha256))
    payload = {
        "collected_at": collected_at,
        "collector_ids": sorted(expected_ids),
        "collector_result_sha256s": sorted(item.result_sha256 for item in results),
        "context": plan.context.to_dict(),
        "limits": plan.limits.to_dict(),
        "no_effects": dict(NO_EFFECTS),
        "observations": [item.to_dict() for item in ordered_observations],
        "plan_sha256": plan.plan_sha256,
        "planned_surface_kinds": [item.value for item in sorted(kinds, key=str)],
        "run_nonce_sha256": plan.run_nonce_sha256,
    }
    digest = _digest("sunderkey.attack-surface-batch.v1", payload)
    return ObservationBatch(
        batch_id=_derived_id("ADB", digest),
        batch_sha256=digest,
        collected_at=collected_at,
        plan_sha256=plan.plan_sha256,
        run_nonce_sha256=plan.run_nonce_sha256,
        context=plan.context,
        planned_surface_kinds=tuple(sorted(kinds, key=str)),
        collector_ids=tuple(sorted(expected_ids)),
        collector_result_sha256s=tuple(sorted(item.result_sha256 for item in results)),
        observations=ordered_observations,
        limits=plan.limits,
        no_effects=NO_EFFECTS,
    )


def correlate_attack_surface(
    batch: ObservationBatch,
    *,
    generated_at: str,
    prior_report: DiscoveryReport | None = None,
    low_confidence_threshold: int = 60,
) -> DiscoveryReport:
    """Resolve evidence into isolated assets, services, endpoints, gaps, and plans."""

    instant = _utc(generated_at, "generated_at")
    if instant < _utc(batch.collected_at, "collected_at"):
        raise AttackSurfaceDiscoveryError("generated_at cannot precede collected_at")
    if not 1 <= low_confidence_threshold <= 100:
        raise AttackSurfaceDiscoveryError("low_confidence_threshold must be from 1 through 100")
    if prior_report is not None:
        if prior_report.context != batch.context:
            raise AttackSurfaceDiscoveryError("prior report tenant or context does not match")
        if _utc(prior_report.generated_at, "prior generated_at") >= instant:
            raise AttackSurfaceDiscoveryError("prior report must precede the current report")
        if prior_report.observation_batch_sha256 == batch.batch_sha256:
            raise AttackSurfaceDiscoveryError("observation batch replay was rejected")

    conflicts = _build_conflicts(batch.observations, generated_at)
    if len(conflicts) > batch.limits.max_conflicts:
        raise AttackSurfaceDiscoveryError("conflicts exceed max_conflicts")
    conflict_ids_by_observation: dict[str, set[str]] = defaultdict(set)
    for conflict in conflicts:
        for digest in conflict.observation_sha256s:
            conflict_ids_by_observation[digest].add(conflict.conflict_id)

    assets = _build_entities(
        "asset",
        _group(batch.observations, lambda item: (item.asset_key_sha256,)),
        generated_at,
        conflict_ids_by_observation,
    )
    asset_id_by_key = {item.stable_key_sha256: item.entity_id for item in assets}
    service_groups = _group(
        tuple(item for item in batch.observations if item.service_key_sha256 is not None),
        lambda item: (item.asset_key_sha256, item.service_key_sha256 or ""),
    )
    services = _build_entities(
        "service",
        service_groups,
        generated_at,
        conflict_ids_by_observation,
        parent_lookup=lambda key: asset_id_by_key[key[0]],
    )
    asset_key_by_id = {value: key for key, value in asset_id_by_key.items()}
    service_id_by_key = {
        (asset_key_by_id[item.parent_entity_id], item.stable_key_sha256): item.entity_id
        for item in services
        if item.parent_entity_id is not None
    }
    endpoint_groups = _group(
        tuple(item for item in batch.observations if item.endpoint_key_sha256 is not None),
        lambda item: (
            item.asset_key_sha256,
            item.service_key_sha256 or "",
            item.endpoint_key_sha256 or "",
        ),
    )
    endpoints = _build_entities(
        "endpoint",
        endpoint_groups,
        generated_at,
        conflict_ids_by_observation,
        parent_lookup=lambda key: service_id_by_key[(key[0], key[1])],
    )
    if len(assets) > batch.limits.max_assets:
        raise AttackSurfaceDiscoveryError("assets exceed max_assets")
    if len(services) > batch.limits.max_services:
        raise AttackSurfaceDiscoveryError("services exceed max_services")
    if len(endpoints) > batch.limits.max_endpoints:
        raise AttackSurfaceDiscoveryError("endpoints exceed max_endpoints")

    temporal_links = _build_temporal_links(assets, services, endpoints, prior_report)
    gaps = _build_gaps(
        batch,
        assets,
        services,
        conflicts,
        temporal_links,
        low_confidence_threshold,
    )
    if len(gaps) > batch.limits.max_gaps:
        raise AttackSurfaceDiscoveryError("gaps exceed max_gaps")
    revalidations = _build_revalidations(gaps, batch)
    if len(revalidations) > batch.limits.max_revalidation_plans:
        raise AttackSurfaceDiscoveryError("revalidation plans exceed limit")
    payload = {
        "assets": [item.to_dict() for item in assets],
        "conflicts": [item.to_dict() for item in conflicts],
        "context": batch.context.to_dict(),
        "endpoints": [item.to_dict() for item in endpoints],
        "evidence_level": "repository_only",
        "gaps": [item.to_dict() for item in gaps],
        "generated_at": generated_at,
        "limits": batch.limits.to_dict(),
        "no_effects": dict(NO_EFFECTS),
        "observation_batch_sha256": batch.batch_sha256,
        "operational_status": "nonqualified",
        "parent_report_sha256": None if prior_report is None else prior_report.report_sha256,
        "qualification_effect": "none",
        "revalidation_plans": [item.to_dict() for item in revalidations],
        "schema_version": SCHEMA_VERSION,
        "services": [item.to_dict() for item in services],
        "temporal_links": [item.to_dict() for item in temporal_links],
    }
    digest = _digest("sunderkey.attack-surface-report.v1", payload)
    return DiscoveryReport(
        schema_version=SCHEMA_VERSION,
        report_id=_derived_id("ADS", digest),
        report_sha256=digest,
        generated_at=generated_at,
        context=batch.context,
        observation_batch_sha256=batch.batch_sha256,
        parent_report_sha256=None if prior_report is None else prior_report.report_sha256,
        assets=assets,
        services=services,
        endpoints=endpoints,
        conflicts=conflicts,
        temporal_links=temporal_links,
        gaps=gaps,
        revalidation_plans=revalidations,
        limits=batch.limits,
        no_effects=NO_EFFECTS,
    )


def parse_discovery_report(raw: Mapping[str, Any]) -> DiscoveryReport:
    """Parse and verify one closed, canonical report document."""

    return DiscoveryReport.from_dict(raw)


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation used for identities."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise AttackSurfaceDiscoveryError("value is not canonical JSON") from exc


def _build_conflicts(
    observations: Sequence[CollectorObservation],
    generated_at: str,
) -> tuple[DiscoveryConflict, ...]:
    current = tuple(
        item
        for item in observations
        if _utc(item.freshness_expires_at, "freshness_expires_at")
        > _utc(generated_at, "generated_at")
    )
    candidates: list[tuple[str, str, tuple[CollectorObservation, ...], tuple[str, ...]]] = []
    for kind, key_fn, value_fn in (
        (
            "native_key_multiple_assets",
            lambda item: item.native_key_sha256,
            lambda item: item.asset_key_sha256,
        ),
        (
            "service_key_multiple_assets",
            lambda item: item.service_key_sha256,
            lambda item: item.asset_key_sha256,
        ),
        (
            "endpoint_key_multiple_services",
            lambda item: item.endpoint_key_sha256,
            lambda item: item.service_key_sha256,
        ),
    ):
        grouped: dict[str, list[CollectorObservation]] = defaultdict(list)
        for item in current:
            key = key_fn(item)
            if key is not None:
                grouped[key].append(item)
        for key, members in grouped.items():
            values = tuple(
                sorted({value_fn(item) for item in members if value_fn(item) is not None})
            )
            if len(values) > 1:
                candidates.append((kind, key, tuple(members), values))
    for key, members in _group(current, lambda item: (item.asset_key_sha256,)).items():
        for kind, getter in (
            ("ownership_claim_conflict", lambda item: set(item.owner_refs)),
            ("scope_claim_conflict", lambda item: set(item.scope_refs)),
        ):
            claims = [getter(item) for item in members if getter(item)]
            if len(claims) > 1 and not set.intersection(*claims):
                candidates.append((kind, key[0], members, tuple(sorted(set().union(*claims)))))
    conflicts = []
    for kind, key, members, claims in candidates:
        payload = {
            "claim_values": list(claims),
            "conflict_kind": kind,
            "key_sha256": key,
            "observation_sha256s": sorted(item.observation_sha256 for item in members),
        }
        digest = _digest("sunderkey.attack-surface-conflict.v1", payload)
        conflicts.append(
            DiscoveryConflict(
                conflict_id=_derived_id("ADF", digest),
                conflict_sha256=digest,
                conflict_kind=kind,
                key_sha256=key,
                observation_sha256s=tuple(payload["observation_sha256s"]),
                claim_values=claims,
            )
        )
    return tuple(sorted(conflicts, key=lambda item: item.conflict_id))


def _build_entities(
    entity_kind: str,
    groups: Mapping[tuple[str, ...], tuple[CollectorObservation, ...]],
    generated_at: str,
    conflicts_by_observation: Mapping[str, set[str]],
    parent_lookup: Any = None,
) -> tuple[CorrelatedEntity, ...]:
    entities = []
    for key in sorted(groups):
        members = groups[key]
        current = tuple(
            item
            for item in members
            if _utc(item.freshness_expires_at, "freshness_expires_at")
            > _utc(generated_at, "generated_at")
        )
        selected = current or members
        conflict_ids = tuple(
            sorted(
                set().union(
                    *(
                        conflicts_by_observation.get(item.observation_sha256, set())
                        for item in members
                    )
                )
            )
        )
        state = (
            EntityState.CONFLICTED
            if conflict_ids
            else (EntityState.CURRENT if current else EntityState.STALE)
        )
        confidence = (
            min(item.confidence for item in selected)
            if conflict_ids
            else max(item.confidence for item in selected)
        )
        stable_key = key[-1]
        parent_id = None if parent_lookup is None else parent_lookup(key)
        prefix = {"asset": "ASA", "service": "ASS", "endpoint": "ASE"}[entity_kind]
        entity_id = _derived_id(
            prefix,
            _digest(
                f"sunderkey.{entity_kind}-identity.v1",
                {
                    "parent_entity_id": parent_id,
                    "stable_key_sha256": stable_key,
                },
            ),
        )
        payload = {
            "confidence": confidence,
            "conflict_ids": list(conflict_ids),
            "entity_kind": entity_kind,
            "observation_sha256s": sorted(item.observation_sha256 for item in members),
            "owner_refs": sorted(set().union(*(set(item.owner_refs) for item in members))),
            "parent_entity_id": parent_id,
            "provenance_sha256s": sorted({item.provenance_sha256 for item in members}),
            "scope_refs": sorted(set().union(*(set(item.scope_refs) for item in members))),
            "stable_key_sha256": stable_key,
            "state": state.value,
            "surface_kinds": sorted({item.surface_kind.value for item in members}),
        }
        digest = _digest("sunderkey.attack-surface-entity.v1", payload)
        entities.append(
            CorrelatedEntity(
                entity_id=entity_id,
                entity_sha256=digest,
                entity_kind=entity_kind,
                stable_key_sha256=stable_key,
                parent_entity_id=parent_id,
                state=state,
                surface_kinds=tuple(payload["surface_kinds"]),
                confidence=confidence,
                owner_refs=tuple(payload["owner_refs"]),
                scope_refs=tuple(payload["scope_refs"]),
                provenance_sha256s=tuple(payload["provenance_sha256s"]),
                observation_sha256s=tuple(payload["observation_sha256s"]),
                conflict_ids=conflict_ids,
            )
        )
    return tuple(sorted(entities, key=lambda item: item.entity_id))


def _build_temporal_links(
    assets: Sequence[CorrelatedEntity],
    services: Sequence[CorrelatedEntity],
    endpoints: Sequence[CorrelatedEntity],
    prior: DiscoveryReport | None,
) -> tuple[TemporalLink, ...]:
    current = {item.entity_id: item for item in (*assets, *services, *endpoints)}
    previous = (
        {}
        if prior is None
        else {item.entity_id: item for item in (*prior.assets, *prior.services, *prior.endpoints)}
    )
    links = []
    for entity_id in sorted(set(current) | set(previous)):
        old = previous.get(entity_id)
        new = current.get(entity_id)
        if old is None:
            change = TemporalChange.ADDED
        elif new is None:
            change = TemporalChange.MISSING
        elif old.entity_sha256 == new.entity_sha256:
            change = TemporalChange.UNCHANGED
        else:
            change = TemporalChange.CHANGED
        entity = new or old
        assert entity is not None
        payload = {
            "change": change.value,
            "current_entity_sha256": None if new is None else new.entity_sha256,
            "entity_id": entity_id,
            "entity_kind": entity.entity_kind,
            "prior_entity_sha256": None if old is None else old.entity_sha256,
            "surface_kind": entity.surface_kinds[0].value,
        }
        digest = _digest("sunderkey.attack-surface-temporal-link.v1", payload)
        links.append(
            TemporalLink(
                link_id=_derived_id("ADT", digest),
                link_sha256=digest,
                entity_id=entity_id,
                entity_kind=entity.entity_kind,
                surface_kind=entity.surface_kinds[0],
                change=change,
                prior_entity_sha256=payload["prior_entity_sha256"],
                current_entity_sha256=payload["current_entity_sha256"],
            )
        )
    return tuple(sorted(links, key=lambda item: item.entity_id))


def _build_gaps(
    batch: ObservationBatch,
    assets: Sequence[CorrelatedEntity],
    services: Sequence[CorrelatedEntity],
    conflicts: Sequence[DiscoveryConflict],
    temporal_links: Sequence[TemporalLink],
    threshold: int,
) -> tuple[DiscoveryGap, ...]:
    candidates: list[tuple[GapKind, int, str | None, SurfaceKind, str, tuple[str, ...]]] = []
    observed_kinds = {item.surface_kind for item in batch.observations}
    for kind in batch.planned_surface_kinds:
        if kind not in observed_kinds:
            candidates.append((GapKind.COVERAGE, 2, None, kind, "no_admitted_observations", ()))
    observations_by_sha = {item.observation_sha256: item for item in batch.observations}
    for asset in assets:
        surface = asset.surface_kinds[0]
        if asset.state is EntityState.STALE:
            candidates.append(
                (
                    GapKind.STALE_EVIDENCE,
                    1,
                    asset.entity_id,
                    surface,
                    "all_evidence_stale",
                    asset.observation_sha256s,
                )
            )
        if asset.confidence < threshold:
            candidates.append(
                (
                    GapKind.LOW_CONFIDENCE,
                    3,
                    asset.entity_id,
                    surface,
                    "below_confidence_threshold",
                    asset.observation_sha256s,
                )
            )
        if not asset.owner_refs:
            candidates.append(
                (
                    GapKind.MISSING_OWNERSHIP,
                    2,
                    asset.entity_id,
                    surface,
                    "no_owner_association",
                    asset.observation_sha256s,
                )
            )
        if not asset.scope_refs:
            candidates.append(
                (
                    GapKind.MISSING_SCOPE,
                    1,
                    asset.entity_id,
                    surface,
                    "no_scope_association",
                    asset.observation_sha256s,
                )
            )
        if surface in {SurfaceKind.WEB, SurfaceKind.API, SurfaceKind.NETWORK} and not any(
            item.parent_entity_id == asset.entity_id for item in services
        ):
            candidates.append(
                (
                    GapKind.UNCORRELATED_SERVICE,
                    3,
                    asset.entity_id,
                    surface,
                    "no_service_correlation",
                    asset.observation_sha256s,
                )
            )
    for conflict in conflicts:
        member = observations_by_sha[conflict.observation_sha256s[0]]
        candidates.append(
            (
                GapKind.IDENTITY_CONFLICT,
                1,
                None,
                member.surface_kind,
                conflict.conflict_kind,
                (conflict.conflict_id,),
            )
        )
    prior_missing = [item for item in temporal_links if item.change is TemporalChange.MISSING]
    for link in prior_missing:
        candidates.append(
            (
                GapKind.TEMPORAL_MISSING,
                2,
                link.entity_id,
                link.surface_kind,
                "prior_entity_not_observed",
                (link.link_id,),
            )
        )
    gaps = []
    for kind, priority, entity_id, surface, reason, refs in candidates:
        payload = {
            "entity_id": entity_id,
            "evidence_refs": list(sorted(refs)),
            "gap_kind": kind.value,
            "priority": priority,
            "reason_code": reason,
            "surface_kind": surface.value,
        }
        digest = _digest("sunderkey.attack-surface-gap.v1", payload)
        gaps.append(
            DiscoveryGap(
                gap_id=_derived_id("ADG", digest),
                gap_sha256=digest,
                gap_kind=kind,
                priority=priority,
                entity_id=entity_id,
                surface_kind=surface,
                reason_code=reason,
                evidence_refs=tuple(payload["evidence_refs"]),
            )
        )
    return tuple(sorted(gaps, key=lambda item: (item.priority, item.gap_id)))


def _build_revalidations(
    gaps: Sequence[DiscoveryGap],
    batch: ObservationBatch,
) -> tuple[RevalidationPlan, ...]:
    collector_kinds: dict[str, set[SurfaceKind]] = defaultdict(set)
    for observation in batch.observations:
        collector_kinds[observation.collector_id].add(observation.surface_kind)
    plans = []
    for gap in gaps:
        selected = tuple(
            sorted(
                collector_id
                for collector_id in batch.collector_ids
                if not collector_kinds[collector_id]
                or gap.surface_kind in collector_kinds[collector_id]
            )
        )
        if not selected:
            selected = batch.collector_ids
        payload = {
            "active_scan_permitted": False,
            "gap_id": gap.gap_id,
            "network_access_permitted": False,
            "priority": gap.priority,
            "record_limit": min(100, batch.limits.max_observations),
            "requested_collector_ids": list(selected),
            "status": "proposal_only",
        }
        digest = _digest("sunderkey.attack-surface-revalidation.v1", payload)
        plans.append(
            RevalidationPlan(
                revalidation_id=_derived_id("ADV", digest),
                revalidation_sha256=digest,
                gap_id=gap.gap_id,
                priority=gap.priority,
                requested_collector_ids=selected,
                record_limit=payload["record_limit"],
                active_scan_permitted=False,
                network_access_permitted=False,
            )
        )
    return tuple(sorted(plans, key=lambda item: (item.priority, item.revalidation_id)))


def _group(
    observations: Sequence[CollectorObservation], key_fn: Any
) -> dict[tuple[str, ...], tuple[CollectorObservation, ...]]:
    grouped: dict[tuple[str, ...], list[CollectorObservation]] = defaultdict(list)
    for item in observations:
        grouped[key_fn(item)].append(item)
    return {
        key: tuple(sorted(values, key=lambda item: item.observation_sha256))
        for key, values in grouped.items()
    }


def _digest(domain: str, payload: Any) -> str:
    data = f"{domain}\n{canonical_json(payload)}".encode()
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _derived_id(prefix: str, digest: str) -> str:
    _sha256(digest, "derived digest")
    return f"{prefix}-{digest[7:39].upper()}"


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise AttackSurfaceDiscoveryError(f"{name} is invalid")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise AttackSurfaceDiscoveryError(f"{name} must be a lowercase sha256 digest")
    return value


def _utc(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise AttackSurfaceDiscoveryError(f"{name} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AttackSurfaceDiscoveryError(f"{name} is not a valid instant") from exc


def _refs(values: Sequence[str], name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise AttackSurfaceDiscoveryError(f"{name} must be a sequence")
    result = tuple(sorted(set(values)))
    for value in result:
        _identifier(value, name)
    return result


def _exact_fields(raw: Any, expected: set[str], name: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise AttackSurfaceDiscoveryError(f"{name} fields are invalid")


def _no_effects(value: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise AttackSurfaceDiscoveryError("no_effects declaration is invalid")
    snapshot = dict(value)
    if snapshot != NO_EFFECTS:
        raise AttackSurfaceDiscoveryError("no_effects declaration is invalid")
    return MappingProxyType(snapshot)
