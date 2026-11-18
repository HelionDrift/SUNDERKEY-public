"""Deterministic model routing and budget planning contracts.

This module evaluates immutable provider and model declarations. It performs no
network access, provider calls, credential handling, pricing lookup, authority
change, budget spend, or tool execution.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

SCHEMA_VERSION = 1
DECISION_KIND = "sunderkey.model-routing-decision.v1"
ROUTING_POLICY_VERSION = "cost_latency_availability_v1"

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

DATA_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
TOOL_POLICIES = ("forbidden", "allowed", "required")
HOSTING_MODES = ("provider_managed", "dedicated", "private_cloud", "on_premises")
MODALITIES = ("audio", "image", "text", "video")
DECISION_STATUSES = ("selected", "abstained")

PLANNING_EFFECTS = {
    "authority": "none",
    "budget_reservation": "planning_only",
    "budget_spend": "none",
    "credential_values": "none",
    "execution": "none",
    "model_calls": "none",
    "network": "none",
    "pricing_lookup": "none",
    "provider_clients": "none",
    "provider_state": "none",
    "qualification": "none",
    "requests": "none",
    "secrets": "none",
    "tools": "none",
}


class ModelRoutingError(ValueError):
    """Raised when routing input or a serialized routing record is invalid."""


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
        raise ModelRoutingError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise ModelRoutingError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelRoutingError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise ModelRoutingError(f"{label} contains an unsupported value")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise ModelRoutingError(f"{label} must be a safe identifier")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ModelRoutingError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ModelRoutingError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ModelRoutingError(f"{label} must be a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _exact_version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise ModelRoutingError(f"{label} must be an exact version token")
    if value.lower() in {"default", "latest", "stable", "current", "auto"}:
        raise ModelRoutingError(f"{label} must not be a moving alias")
    if not any(character.isdigit() for character in value):
        raise ModelRoutingError(f"{label} must contain a version number")
    return value


def _positive(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ModelRoutingError(f"{label} must be an integer of at least {minimum}")
    return value


def _ordered_unique(
    values: Sequence[str], label: str, validator: Any, *, allow_empty: bool = False
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ModelRoutingError(f"{label} must be a sequence")
    normalized = tuple(validator(item, f"{label} item") for item in values)
    if not allow_empty and not normalized:
        raise ModelRoutingError(f"{label} must not be empty")
    if len(normalized) != len(set(normalized)):
        raise ModelRoutingError(f"{label} must not contain duplicates")
    return tuple(sorted(normalized))


def _tokens(values: Sequence[str], label: str, allowed: Sequence[str]) -> tuple[str, ...]:
    allowed_set = frozenset(allowed)

    def validate(value: Any, item_label: str) -> str:
        if not isinstance(value, str) or value not in allowed_set:
            raise ModelRoutingError(f"{item_label} is invalid")
        return value

    return _ordered_unique(values, label, validate)


def _digests(values: Sequence[str], label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    return _ordered_unique(values, label, _digest, allow_empty=allow_empty)


def _identifiers(
    values: Sequence[str], label: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    return _ordered_unique(values, label, _identifier, allow_empty=allow_empty)


def _exact_fields(raw: Any, expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise ModelRoutingError(f"{label} fields are invalid")


def _list(raw: Any, label: str) -> list[Any]:
    if not isinstance(raw, list):
        raise ModelRoutingError(f"{label} must be a JSON array")
    return raw


@dataclass(frozen=True, slots=True)
class ModelCapabilityDeclaration:
    """Pinned provider and model behavior supplied by a trusted registry."""

    provider_id: str
    provider_api_version: str
    model_id: str
    model_version: str
    pricing_revision: str
    modalities: tuple[str, ...]
    maximum_context_tokens: int
    maximum_output_tokens: int
    data_classifications: tuple[str, ...]
    hosting_mode: str
    region: str
    retention_days: int
    inputs_used_for_training: bool
    tool_policy: str
    safety_profile_refs: tuple[str, ...]
    qualification_refs: tuple[str, ...]
    latency_p95_ms: int
    availability_basis_points: int
    input_micros_per_million_tokens: int
    output_micros_per_million_tokens: int
    quality_tier: int
    available: bool
    capability_id: str = field(init=False)
    capability_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.model-capability-declaration.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _identifier(self.provider_id, "provider_id"))
        object.__setattr__(
            self,
            "provider_api_version",
            _exact_version(self.provider_api_version, "provider_api_version"),
        )
        object.__setattr__(self, "model_id", _identifier(self.model_id, "model_id"))
        object.__setattr__(
            self, "model_version", _exact_version(self.model_version, "model_version")
        )
        object.__setattr__(
            self,
            "pricing_revision",
            _exact_version(self.pricing_revision, "pricing_revision"),
        )
        object.__setattr__(self, "modalities", _tokens(self.modalities, "modalities", MODALITIES))
        _positive(self.maximum_context_tokens, "maximum_context_tokens")
        _positive(self.maximum_output_tokens, "maximum_output_tokens")
        if self.maximum_output_tokens > self.maximum_context_tokens:
            raise ModelRoutingError("maximum_output_tokens exceeds maximum_context_tokens")
        object.__setattr__(
            self,
            "data_classifications",
            _tokens(self.data_classifications, "data_classifications", DATA_CLASSIFICATIONS),
        )
        if self.hosting_mode not in HOSTING_MODES:
            raise ModelRoutingError("hosting_mode is invalid")
        _identifier(self.region, "region")
        _positive(self.retention_days, "retention_days", allow_zero=True)
        if not isinstance(self.inputs_used_for_training, bool):
            raise ModelRoutingError("inputs_used_for_training must be boolean")
        if self.tool_policy not in TOOL_POLICIES:
            raise ModelRoutingError("tool_policy is invalid")
        object.__setattr__(
            self,
            "safety_profile_refs",
            _digests(self.safety_profile_refs, "safety_profile_refs", allow_empty=True),
        )
        object.__setattr__(
            self,
            "qualification_refs",
            _digests(self.qualification_refs, "qualification_refs", allow_empty=True),
        )
        _positive(self.latency_p95_ms, "latency_p95_ms")
        if not 0 <= self.availability_basis_points <= 10_000:
            raise ModelRoutingError("availability_basis_points must be between 0 and 10000")
        _positive(
            self.input_micros_per_million_tokens,
            "input_micros_per_million_tokens",
            allow_zero=True,
        )
        _positive(
            self.output_micros_per_million_tokens,
            "output_micros_per_million_tokens",
            allow_zero=True,
        )
        if not 1 <= self.quality_tier <= 100:
            raise ModelRoutingError("quality_tier must be between 1 and 100")
        if not isinstance(self.available, bool):
            raise ModelRoutingError("available must be boolean")
        body = self._body()
        record_id, digest = _identity("MCD", self.KIND, body)
        object.__setattr__(self, "capability_id", record_id)
        object.__setattr__(self, "capability_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "availability_basis_points": self.availability_basis_points,
            "data_classifications": list(self.data_classifications),
            "hosting_mode": self.hosting_mode,
            "input_micros_per_million_tokens": self.input_micros_per_million_tokens,
            "inputs_used_for_training": self.inputs_used_for_training,
            "latency_p95_ms": self.latency_p95_ms,
            "maximum_context_tokens": self.maximum_context_tokens,
            "maximum_output_tokens": self.maximum_output_tokens,
            "modalities": list(self.modalities),
            "model_id": self.model_id,
            "model_version": self.model_version,
            "output_micros_per_million_tokens": self.output_micros_per_million_tokens,
            "pricing_revision": self.pricing_revision,
            "provider_api_version": self.provider_api_version,
            "provider_id": self.provider_id,
            "qualification_refs": list(self.qualification_refs),
            "quality_tier": self.quality_tier,
            "region": self.region,
            "retention_days": self.retention_days,
            "safety_profile_refs": list(self.safety_profile_refs),
            "tool_policy": self.tool_policy,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "capability_id": self.capability_id,
            "capability_sha256": self.capability_sha256,
            **self._body(),
            "effects": dict(PLANNING_EFFECTS),
        }


@dataclass(frozen=True, slots=True)
class TaskRoutingRequirements:
    """Deny-by-default requirements for one tenant and assessment task."""

    tenant_id: str
    assessment_id: str
    task_id: str
    requester_id: str
    required_modalities: tuple[str, ...]
    input_token_ceiling: int
    output_token_ceiling: int
    data_classification: str
    allowed_hosting_modes: tuple[str, ...]
    allowed_regions: tuple[str, ...]
    maximum_retention_days: int
    training_use_allowed: bool
    tool_policy: str
    required_safety_profile_refs: tuple[str, ...]
    required_qualification_refs: tuple[str, ...]
    maximum_latency_p95_ms: int
    minimum_availability_basis_points: int
    minimum_quality_tier: int
    maximum_request_cost_micros: int
    requirements_id: str = field(init=False)
    requirements_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.task-routing-requirements.v1"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "assessment_id", "task_id", "requester_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(
            self,
            "required_modalities",
            _tokens(self.required_modalities, "required_modalities", MODALITIES),
        )
        _positive(self.input_token_ceiling, "input_token_ceiling")
        _positive(self.output_token_ceiling, "output_token_ceiling")
        if self.data_classification not in DATA_CLASSIFICATIONS:
            raise ModelRoutingError("data_classification is invalid")
        object.__setattr__(
            self,
            "allowed_hosting_modes",
            _tokens(self.allowed_hosting_modes, "allowed_hosting_modes", HOSTING_MODES),
        )
        object.__setattr__(
            self,
            "allowed_regions",
            _identifiers(self.allowed_regions, "allowed_regions"),
        )
        _positive(self.maximum_retention_days, "maximum_retention_days", allow_zero=True)
        if not isinstance(self.training_use_allowed, bool):
            raise ModelRoutingError("training_use_allowed must be boolean")
        if self.tool_policy not in TOOL_POLICIES:
            raise ModelRoutingError("tool_policy is invalid")
        object.__setattr__(
            self,
            "required_safety_profile_refs",
            _digests(
                self.required_safety_profile_refs,
                "required_safety_profile_refs",
                allow_empty=True,
            ),
        )
        object.__setattr__(
            self,
            "required_qualification_refs",
            _digests(
                self.required_qualification_refs,
                "required_qualification_refs",
                allow_empty=True,
            ),
        )
        _positive(self.maximum_latency_p95_ms, "maximum_latency_p95_ms")
        if not 0 <= self.minimum_availability_basis_points <= 10_000:
            raise ModelRoutingError("minimum_availability_basis_points must be between 0 and 10000")
        if not 1 <= self.minimum_quality_tier <= 100:
            raise ModelRoutingError("minimum_quality_tier must be between 1 and 100")
        _positive(self.maximum_request_cost_micros, "maximum_request_cost_micros")
        record_id, digest = _identity("MTR", self.KIND, self._body())
        object.__setattr__(self, "requirements_id", record_id)
        object.__setattr__(self, "requirements_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "allowed_hosting_modes": list(self.allowed_hosting_modes),
            "allowed_regions": list(self.allowed_regions),
            "assessment_id": self.assessment_id,
            "data_classification": self.data_classification,
            "input_token_ceiling": self.input_token_ceiling,
            "maximum_latency_p95_ms": self.maximum_latency_p95_ms,
            "maximum_request_cost_micros": self.maximum_request_cost_micros,
            "maximum_retention_days": self.maximum_retention_days,
            "minimum_availability_basis_points": self.minimum_availability_basis_points,
            "minimum_quality_tier": self.minimum_quality_tier,
            "output_token_ceiling": self.output_token_ceiling,
            "requester_id": self.requester_id,
            "required_modalities": list(self.required_modalities),
            "required_qualification_refs": list(self.required_qualification_refs),
            "required_safety_profile_refs": list(self.required_safety_profile_refs),
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
            "tool_policy": self.tool_policy,
            "training_use_allowed": self.training_use_allowed,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "requirements_id": self.requirements_id,
            "requirements_sha256": self.requirements_sha256,
            **self._body(),
            "effects": dict(PLANNING_EFFECTS),
        }


@dataclass(frozen=True, slots=True)
class RoutingAuthorityBinding:
    """External authority binding. Routing never creates or expands this grant."""

    tenant_id: str
    assessment_id: str
    task_id: str
    requester_id: str
    authorizer_id: str
    allowed_capability_sha256s: tuple[str, ...]
    valid_from: str
    expires_at: str
    authority_ref: str
    binding_id: str = field(init=False)
    binding_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.routing-authority-binding.v1"

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "assessment_id",
            "task_id",
            "requester_id",
            "authorizer_id",
        ):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        if self.authorizer_id == self.requester_id:
            raise ModelRoutingError("requester cannot authorize its own routing")
        object.__setattr__(
            self,
            "allowed_capability_sha256s",
            _digests(self.allowed_capability_sha256s, "allowed_capability_sha256s"),
        )
        _timestamp(self.valid_from, "valid_from")
        _timestamp(self.expires_at, "expires_at")
        if _instant(self.valid_from) >= _instant(self.expires_at):
            raise ModelRoutingError("authority validity interval is empty")
        _digest(self.authority_ref, "authority_ref")
        record_id, digest = _identity("RAB", self.KIND, self._body())
        object.__setattr__(self, "binding_id", record_id)
        object.__setattr__(self, "binding_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "allowed_capability_sha256s": list(self.allowed_capability_sha256s),
            "assessment_id": self.assessment_id,
            "authority_ref": self.authority_ref,
            "authorizer_id": self.authorizer_id,
            "expires_at": self.expires_at,
            "requester_id": self.requester_id,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
            "valid_from": self.valid_from,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            **self._body(),
            "effects": dict(PLANNING_EFFECTS),
        }


@dataclass(frozen=True, slots=True)
class BudgetEnvelope:
    """Immutable budget snapshot used to propose, but not commit, a reservation."""

    tenant_id: str
    assessment_id: str
    currency: str
    request_input_token_limit: int
    request_output_token_limit: int
    request_cost_limit_micros: int
    aggregate_input_token_limit: int
    aggregate_output_token_limit: int
    aggregate_cost_limit_micros: int
    aggregate_input_tokens_reserved: int
    aggregate_output_tokens_reserved: int
    aggregate_cost_reserved_micros: int
    budget_revision: str
    budget_id: str = field(init=False)
    budget_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.routing-budget-envelope.v1"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "assessment_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        if self.currency != "USD":
            raise ModelRoutingError("currency must be USD")
        for name in (
            "request_input_token_limit",
            "request_output_token_limit",
            "request_cost_limit_micros",
            "aggregate_input_token_limit",
            "aggregate_output_token_limit",
            "aggregate_cost_limit_micros",
        ):
            _positive(getattr(self, name), name)
        for name in (
            "aggregate_input_tokens_reserved",
            "aggregate_output_tokens_reserved",
            "aggregate_cost_reserved_micros",
        ):
            _positive(getattr(self, name), name, allow_zero=True)
        if self.aggregate_input_tokens_reserved > self.aggregate_input_token_limit:
            raise ModelRoutingError("reserved input tokens exceed aggregate limit")
        if self.aggregate_output_tokens_reserved > self.aggregate_output_token_limit:
            raise ModelRoutingError("reserved output tokens exceed aggregate limit")
        if self.aggregate_cost_reserved_micros > self.aggregate_cost_limit_micros:
            raise ModelRoutingError("reserved cost exceeds aggregate limit")
        object.__setattr__(
            self, "budget_revision", _exact_version(self.budget_revision, "budget_revision")
        )
        record_id, digest = _identity("RBE", self.KIND, self._body())
        object.__setattr__(self, "budget_id", record_id)
        object.__setattr__(self, "budget_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "aggregate_cost_limit_micros": self.aggregate_cost_limit_micros,
            "aggregate_cost_reserved_micros": self.aggregate_cost_reserved_micros,
            "aggregate_input_token_limit": self.aggregate_input_token_limit,
            "aggregate_input_tokens_reserved": self.aggregate_input_tokens_reserved,
            "aggregate_output_token_limit": self.aggregate_output_token_limit,
            "aggregate_output_tokens_reserved": self.aggregate_output_tokens_reserved,
            "assessment_id": self.assessment_id,
            "budget_revision": self.budget_revision,
            "currency": self.currency,
            "request_cost_limit_micros": self.request_cost_limit_micros,
            "request_input_token_limit": self.request_input_token_limit,
            "request_output_token_limit": self.request_output_token_limit,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "budget_id": self.budget_id,
            "budget_sha256": self.budget_sha256,
            **self._body(),
            "effects": dict(PLANNING_EFFECTS),
        }


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    capability_sha256: str
    eligible: bool
    score: int | None
    estimated_cost_micros: int
    blockers: tuple[str, ...]

    def __post_init__(self) -> None:
        _digest(self.capability_sha256, "capability_sha256")
        if not isinstance(self.eligible, bool):
            raise ModelRoutingError("eligible must be boolean")
        if self.score is not None:
            _positive(self.score, "score", allow_zero=True)
        _positive(self.estimated_cost_micros, "estimated_cost_micros", allow_zero=True)
        object.__setattr__(
            self,
            "blockers",
            _identifiers(self.blockers, "blockers", allow_empty=True),
        )
        if self.eligible != (not self.blockers):
            raise ModelRoutingError("candidate eligibility and blockers are inconsistent")
        if self.eligible != (self.score is not None):
            raise ModelRoutingError("eligible candidates require a score")

    def to_dict(self) -> dict[str, Any]:
        return {
            "blockers": list(self.blockers),
            "capability_sha256": self.capability_sha256,
            "eligible": self.eligible,
            "estimated_cost_micros": self.estimated_cost_micros,
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEvaluation:
        fields = {
            "blockers",
            "capability_sha256",
            "eligible",
            "estimated_cost_micros",
            "score",
        }
        _exact_fields(raw, fields, "candidate evaluation")
        return cls(
            capability_sha256=raw["capability_sha256"],
            eligible=raw["eligible"],
            score=raw["score"],
            estimated_cost_micros=raw["estimated_cost_micros"],
            blockers=tuple(_list(raw["blockers"], "blockers")),
        )


@dataclass(frozen=True, slots=True)
class RouteSelection:
    capability_sha256: str
    provider_id: str
    provider_api_version: str
    model_id: str
    model_version: str
    pricing_revision: str
    score: int

    def __post_init__(self) -> None:
        _digest(self.capability_sha256, "capability_sha256")
        _identifier(self.provider_id, "provider_id")
        _exact_version(self.provider_api_version, "provider_api_version")
        _identifier(self.model_id, "model_id")
        _exact_version(self.model_version, "model_version")
        _exact_version(self.pricing_revision, "pricing_revision")
        _positive(self.score, "score", allow_zero=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_sha256": self.capability_sha256,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "pricing_revision": self.pricing_revision,
            "provider_api_version": self.provider_api_version,
            "provider_id": self.provider_id,
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RouteSelection:
        fields = {
            "capability_sha256",
            "model_id",
            "model_version",
            "pricing_revision",
            "provider_api_version",
            "provider_id",
            "score",
        }
        _exact_fields(raw, fields, "route selection")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    """Proposed reservation. It has no effect until another subsystem commits it."""

    tenant_id: str
    assessment_id: str
    task_id: str
    budget_sha256: str
    capability_sha256: str
    input_tokens: int
    output_tokens: int
    estimated_cost_micros: int
    aggregate_input_tokens_after: int
    aggregate_output_tokens_after: int
    aggregate_cost_micros_after: int
    reservation_state: str = "proposed"
    planning_only: bool = True
    reservation_id: str = field(init=False)
    reservation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.model-budget-reservation.v1"

    def __post_init__(self) -> None:
        for name in ("tenant_id", "assessment_id", "task_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        _digest(self.budget_sha256, "budget_sha256")
        _digest(self.capability_sha256, "capability_sha256")
        for name in (
            "input_tokens",
            "output_tokens",
            "estimated_cost_micros",
            "aggregate_input_tokens_after",
            "aggregate_output_tokens_after",
            "aggregate_cost_micros_after",
        ):
            _positive(getattr(self, name), name, allow_zero=True)
        if self.reservation_state != "proposed" or self.planning_only is not True:
            raise ModelRoutingError("budget reservation must remain proposed and planning-only")
        record_id, digest = _identity("MBR", self.KIND, self._body())
        object.__setattr__(self, "reservation_id", record_id)
        object.__setattr__(self, "reservation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "aggregate_cost_micros_after": self.aggregate_cost_micros_after,
            "aggregate_input_tokens_after": self.aggregate_input_tokens_after,
            "aggregate_output_tokens_after": self.aggregate_output_tokens_after,
            "assessment_id": self.assessment_id,
            "budget_sha256": self.budget_sha256,
            "capability_sha256": self.capability_sha256,
            "estimated_cost_micros": self.estimated_cost_micros,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "planning_only": self.planning_only,
            "reservation_state": self.reservation_state,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "reservation_id": self.reservation_id,
            "reservation_sha256": self.reservation_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> BudgetReservation:
        computed = {"reservation_id", "reservation_sha256", "schema_version", "kind"}
        expected = computed | {
            "aggregate_cost_micros_after",
            "aggregate_input_tokens_after",
            "aggregate_output_tokens_after",
            "assessment_id",
            "budget_sha256",
            "capability_sha256",
            "estimated_cost_micros",
            "input_tokens",
            "output_tokens",
            "planning_only",
            "reservation_state",
            "task_id",
            "tenant_id",
        }
        _exact_fields(raw, expected, "budget reservation")
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != cls.KIND:
            raise ModelRoutingError("budget reservation type is invalid")
        instance = cls(**{key: value for key, value in raw.items() if key not in computed})
        if (
            instance.reservation_id != raw["reservation_id"]
            or instance.reservation_sha256 != raw["reservation_sha256"]
        ):
            raise ModelRoutingError("budget reservation content address mismatch")
        return instance


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    tenant_id: str
    assessment_id: str
    task_id: str
    decided_at: str
    requirements_sha256: str
    authority_binding_sha256: str
    budget_sha256: str
    routing_policy_version: str
    status: str
    evaluations: tuple[CandidateEvaluation, ...]
    selection: RouteSelection | None
    fallback_plan: tuple[RouteSelection, ...]
    substitution_requires_new_decision: bool
    blockers: tuple[str, ...]
    budget_reservation: BudgetReservation | None
    decision_id: str = field(init=False)
    decision_sha256: str = field(init=False)

    KIND: ClassVar[str] = DECISION_KIND

    def __post_init__(self) -> None:
        for name in ("tenant_id", "assessment_id", "task_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        _timestamp(self.decided_at, "decided_at")
        for name in ("requirements_sha256", "authority_binding_sha256", "budget_sha256"):
            _digest(getattr(self, name), name)
        if self.routing_policy_version != ROUTING_POLICY_VERSION:
            raise ModelRoutingError("routing_policy_version is invalid")
        if self.status not in DECISION_STATUSES:
            raise ModelRoutingError("status is invalid")
        if not self.evaluations:
            raise ModelRoutingError("evaluations must not be empty")
        evaluation_refs = tuple(item.capability_sha256 for item in self.evaluations)
        if evaluation_refs != tuple(sorted(evaluation_refs)) or len(evaluation_refs) != len(
            set(evaluation_refs)
        ):
            raise ModelRoutingError("evaluations must be unique and sorted")
        fallback_refs = tuple(item.capability_sha256 for item in self.fallback_plan)
        if len(fallback_refs) != len(set(fallback_refs)):
            raise ModelRoutingError("fallback_plan must not contain duplicates")
        if self.substitution_requires_new_decision is not True:
            raise ModelRoutingError("fallback substitution must require a new decision")
        object.__setattr__(
            self, "blockers", _identifiers(self.blockers, "blockers", allow_empty=True)
        )
        eligible_refs = {item.capability_sha256 for item in self.evaluations if item.eligible}
        evaluation_by_ref = {item.capability_sha256: item for item in self.evaluations}
        if self.status == "selected":
            if self.selection is None or self.budget_reservation is None or self.blockers:
                raise ModelRoutingError("selected decision fields are inconsistent")
            if self.selection.capability_sha256 not in eligible_refs:
                raise ModelRoutingError("selection is not eligible")
            if self.selection.capability_sha256 in fallback_refs:
                raise ModelRoutingError("selection cannot also be a fallback")
            if not set(fallback_refs).issubset(eligible_refs):
                raise ModelRoutingError("fallback_plan contains an ineligible route")
            routes = (self.selection, *self.fallback_plan)
            if {item.capability_sha256 for item in routes} != eligible_refs:
                raise ModelRoutingError("route plan must contain every eligible candidate")
            for route in routes:
                if evaluation_by_ref[route.capability_sha256].score != route.score:
                    raise ModelRoutingError("route score does not match candidate evaluation")
            if routes != tuple(
                sorted(
                    routes,
                    key=lambda item: (
                        item.score,
                        item.provider_id,
                        item.model_id,
                        item.model_version,
                        item.capability_sha256,
                    ),
                )
            ):
                raise ModelRoutingError("route plan is not in deterministic rank order")
            if self.budget_reservation.capability_sha256 != self.selection.capability_sha256:
                raise ModelRoutingError("reservation is not bound to the selection")
            if self.budget_reservation.budget_sha256 != self.budget_sha256:
                raise ModelRoutingError("reservation is not bound to the budget")
            if (
                self.budget_reservation.tenant_id,
                self.budget_reservation.assessment_id,
                self.budget_reservation.task_id,
            ) != (self.tenant_id, self.assessment_id, self.task_id):
                raise ModelRoutingError("reservation task binding is invalid")
            if (
                self.budget_reservation.estimated_cost_micros
                != evaluation_by_ref[self.selection.capability_sha256].estimated_cost_micros
            ):
                raise ModelRoutingError("reservation cost does not match candidate evaluation")
        else:
            if (
                self.selection is not None
                or self.fallback_plan
                or self.budget_reservation is not None
            ):
                raise ModelRoutingError("abstained decisions cannot contain routes or reservations")
            if not self.blockers:
                raise ModelRoutingError("abstained decisions require blockers")
        record_id, digest = _identity("MRD", self.KIND, self._body())
        object.__setattr__(self, "decision_id", record_id)
        object.__setattr__(self, "decision_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "authority_binding_sha256": self.authority_binding_sha256,
            "blockers": list(self.blockers),
            "budget_reservation": (
                self.budget_reservation.to_dict() if self.budget_reservation else None
            ),
            "budget_sha256": self.budget_sha256,
            "decided_at": self.decided_at,
            "evaluations": [item.to_dict() for item in self.evaluations],
            "fallback_plan": [item.to_dict() for item in self.fallback_plan],
            "requirements_sha256": self.requirements_sha256,
            "routing_policy_version": self.routing_policy_version,
            "selection": self.selection.to_dict() if self.selection else None,
            "status": self.status,
            "substitution_requires_new_decision": self.substitution_requires_new_decision,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "decision_id": self.decision_id,
            "decision_sha256": self.decision_sha256,
            **self._body(),
            "effects": dict(PLANNING_EFFECTS),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> RoutingDecision:
        computed = {"schema_version", "kind", "decision_id", "decision_sha256", "effects"}
        body_fields = {
            "assessment_id",
            "authority_binding_sha256",
            "blockers",
            "budget_reservation",
            "budget_sha256",
            "decided_at",
            "evaluations",
            "fallback_plan",
            "requirements_sha256",
            "routing_policy_version",
            "selection",
            "status",
            "substitution_requires_new_decision",
            "task_id",
            "tenant_id",
        }
        _exact_fields(raw, computed | body_fields, "routing decision")
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != cls.KIND:
            raise ModelRoutingError("routing decision type is invalid")
        if raw["effects"] != PLANNING_EFFECTS:
            raise ModelRoutingError("routing decision effects are invalid")
        kwargs = {key: raw[key] for key in body_fields}
        kwargs["evaluations"] = tuple(
            CandidateEvaluation.from_dict(item) for item in _list(raw["evaluations"], "evaluations")
        )
        kwargs["fallback_plan"] = tuple(
            RouteSelection.from_dict(item) for item in _list(raw["fallback_plan"], "fallback_plan")
        )
        kwargs["selection"] = (
            RouteSelection.from_dict(raw["selection"]) if raw["selection"] is not None else None
        )
        kwargs["budget_reservation"] = (
            BudgetReservation.from_dict(raw["budget_reservation"])
            if raw["budget_reservation"] is not None
            else None
        )
        kwargs["blockers"] = tuple(_list(raw["blockers"], "blockers"))
        instance = cls(**kwargs)
        if (
            instance.decision_id != raw["decision_id"]
            or instance.decision_sha256 != raw["decision_sha256"]
        ):
            raise ModelRoutingError("routing decision content address mismatch")
        return instance

    @classmethod
    def from_json(cls, payload: str) -> RoutingDecision:
        try:
            raw = json.loads(payload)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ModelRoutingError("routing decision JSON is invalid") from exc
        return cls.from_dict(raw)


def _estimated_cost(
    capability: ModelCapabilityDeclaration, requirements: TaskRoutingRequirements
) -> int:
    input_cost = (
        requirements.input_token_ceiling * capability.input_micros_per_million_tokens + 999_999
    ) // 1_000_000
    output_cost = (
        requirements.output_token_ceiling * capability.output_micros_per_million_tokens + 999_999
    ) // 1_000_000
    return input_cost + output_cost


def _evaluate(
    capability: ModelCapabilityDeclaration,
    requirements: TaskRoutingRequirements,
    authority: RoutingAuthorityBinding,
    budget: BudgetEnvelope,
) -> CandidateEvaluation:
    blockers: set[str] = set()
    estimated_cost = _estimated_cost(capability, requirements)
    if not capability.available:
        blockers.add("provider_unavailable")
    if capability.capability_sha256 not in authority.allowed_capability_sha256s:
        blockers.add("authority_not_granted")
    if not set(requirements.required_modalities).issubset(capability.modalities):
        blockers.add("modality_unsupported")
    if (
        requirements.input_token_ceiling + requirements.output_token_ceiling
        > capability.maximum_context_tokens
    ):
        blockers.add("context_capacity_insufficient")
    if requirements.output_token_ceiling > capability.maximum_output_tokens:
        blockers.add("output_capacity_insufficient")
    if requirements.data_classification not in capability.data_classifications:
        blockers.add("data_classification_denied")
    if capability.hosting_mode not in requirements.allowed_hosting_modes:
        blockers.add("hosting_mode_denied")
    if capability.region not in requirements.allowed_regions:
        blockers.add("region_denied")
    if capability.retention_days > requirements.maximum_retention_days:
        blockers.add("retention_exceeds_policy")
    if capability.inputs_used_for_training and not requirements.training_use_allowed:
        blockers.add("training_use_denied")
    if requirements.tool_policy != capability.tool_policy:
        blockers.add("tool_policy_incompatible")
    if not set(requirements.required_safety_profile_refs).issubset(capability.safety_profile_refs):
        blockers.add("safety_profile_missing")
    if not set(requirements.required_qualification_refs).issubset(capability.qualification_refs):
        blockers.add("qualification_missing")
    if capability.latency_p95_ms > requirements.maximum_latency_p95_ms:
        blockers.add("latency_exceeds_ceiling")
    if capability.availability_basis_points < requirements.minimum_availability_basis_points:
        blockers.add("availability_below_minimum")
    if capability.quality_tier < requirements.minimum_quality_tier:
        blockers.add("quality_tier_below_minimum")
    if estimated_cost > requirements.maximum_request_cost_micros:
        blockers.add("task_cost_ceiling_exceeded")
    if requirements.input_token_ceiling > budget.request_input_token_limit:
        blockers.add("request_input_token_budget_exceeded")
    if requirements.output_token_ceiling > budget.request_output_token_limit:
        blockers.add("request_output_token_budget_exceeded")
    if estimated_cost > budget.request_cost_limit_micros:
        blockers.add("request_cost_budget_exceeded")
    if (
        budget.aggregate_input_tokens_reserved + requirements.input_token_ceiling
        > budget.aggregate_input_token_limit
    ):
        blockers.add("aggregate_input_token_budget_exceeded")
    if (
        budget.aggregate_output_tokens_reserved + requirements.output_token_ceiling
        > budget.aggregate_output_token_limit
    ):
        blockers.add("aggregate_output_token_budget_exceeded")
    if budget.aggregate_cost_reserved_micros + estimated_cost > budget.aggregate_cost_limit_micros:
        blockers.add("aggregate_cost_budget_exceeded")
    score = None
    if not blockers:
        score = (
            estimated_cost * 1_000_000
            + capability.latency_p95_ms * 1_000
            + (10_000 - capability.availability_basis_points) * 10
            + (100 - capability.quality_tier)
        )
    return CandidateEvaluation(
        capability_sha256=capability.capability_sha256,
        eligible=not blockers,
        score=score,
        estimated_cost_micros=estimated_cost,
        blockers=tuple(blockers),
    )


def _selection(
    capability: ModelCapabilityDeclaration, evaluation: CandidateEvaluation
) -> RouteSelection:
    if evaluation.score is None:
        raise ModelRoutingError("ineligible capability cannot be selected")
    return RouteSelection(
        capability_sha256=capability.capability_sha256,
        provider_id=capability.provider_id,
        provider_api_version=capability.provider_api_version,
        model_id=capability.model_id,
        model_version=capability.model_version,
        pricing_revision=capability.pricing_revision,
        score=evaluation.score,
    )


def route_model(
    requirements: TaskRoutingRequirements,
    capabilities: Sequence[ModelCapabilityDeclaration],
    authority: RoutingAuthorityBinding,
    budget: BudgetEnvelope,
    *,
    decided_at: str,
) -> RoutingDecision:
    """Create a deterministic route plan without calling or reserving a provider."""

    _timestamp(decided_at, "decided_at")
    if isinstance(capabilities, (str, bytes)) or not capabilities:
        raise ModelRoutingError("capabilities must not be empty")
    refs = tuple(item.capability_sha256 for item in capabilities)
    if len(refs) != len(set(refs)):
        raise ModelRoutingError("capabilities must not contain duplicate declarations")
    binding = (requirements.tenant_id, requirements.assessment_id, requirements.task_id)
    if binding != (authority.tenant_id, authority.assessment_id, authority.task_id):
        raise ModelRoutingError("authority is not bound to the routing task")
    if requirements.requester_id != authority.requester_id:
        raise ModelRoutingError("authority requester binding is invalid")
    if binding[:2] != (budget.tenant_id, budget.assessment_id):
        raise ModelRoutingError("budget is not bound to the tenant and assessment")
    instant = _instant(decided_at)
    if not (_instant(authority.valid_from) <= instant < _instant(authority.expires_at)):
        raise ModelRoutingError("authority is not valid at the decision time")

    by_ref = {item.capability_sha256: item for item in capabilities}
    evaluations = tuple(
        sorted(
            (_evaluate(item, requirements, authority, budget) for item in capabilities),
            key=lambda item: item.capability_sha256,
        )
    )
    eligible = [item for item in evaluations if item.eligible]
    ranked = sorted(
        eligible,
        key=lambda item: (
            item.score,
            by_ref[item.capability_sha256].provider_id,
            by_ref[item.capability_sha256].model_id,
            by_ref[item.capability_sha256].model_version,
            item.capability_sha256,
        ),
    )
    if not ranked:
        blockers = tuple(sorted({blocker for item in evaluations for blocker in item.blockers}))
        return RoutingDecision(
            tenant_id=requirements.tenant_id,
            assessment_id=requirements.assessment_id,
            task_id=requirements.task_id,
            decided_at=decided_at,
            requirements_sha256=requirements.requirements_sha256,
            authority_binding_sha256=authority.binding_sha256,
            budget_sha256=budget.budget_sha256,
            routing_policy_version=ROUTING_POLICY_VERSION,
            status="abstained",
            evaluations=evaluations,
            selection=None,
            fallback_plan=(),
            substitution_requires_new_decision=True,
            blockers=blockers or ("no_eligible_candidate",),
            budget_reservation=None,
        )

    primary_evaluation = ranked[0]
    primary_capability = by_ref[primary_evaluation.capability_sha256]
    primary = _selection(primary_capability, primary_evaluation)
    fallbacks = tuple(_selection(by_ref[item.capability_sha256], item) for item in ranked[1:])
    reservation = BudgetReservation(
        tenant_id=requirements.tenant_id,
        assessment_id=requirements.assessment_id,
        task_id=requirements.task_id,
        budget_sha256=budget.budget_sha256,
        capability_sha256=primary.capability_sha256,
        input_tokens=requirements.input_token_ceiling,
        output_tokens=requirements.output_token_ceiling,
        estimated_cost_micros=primary_evaluation.estimated_cost_micros,
        aggregate_input_tokens_after=(
            budget.aggregate_input_tokens_reserved + requirements.input_token_ceiling
        ),
        aggregate_output_tokens_after=(
            budget.aggregate_output_tokens_reserved + requirements.output_token_ceiling
        ),
        aggregate_cost_micros_after=(
            budget.aggregate_cost_reserved_micros + primary_evaluation.estimated_cost_micros
        ),
    )
    return RoutingDecision(
        tenant_id=requirements.tenant_id,
        assessment_id=requirements.assessment_id,
        task_id=requirements.task_id,
        decided_at=decided_at,
        requirements_sha256=requirements.requirements_sha256,
        authority_binding_sha256=authority.binding_sha256,
        budget_sha256=budget.budget_sha256,
        routing_policy_version=ROUTING_POLICY_VERSION,
        status="selected",
        evaluations=evaluations,
        selection=primary,
        fallback_plan=fallbacks,
        substitution_requires_new_decision=True,
        blockers=(),
        budget_reservation=reservation,
    )
