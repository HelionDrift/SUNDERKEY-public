"""Offline remediation planning, retest, and closure decision contracts.

The contracts in this module are repository-only and nonqualifying. They plan
and evaluate caller-supplied records. They do not change a target, create a
ticket, contact an integration, grant authority, or execute a retest.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MAX_ITEMS = 2048
MAX_EXCEPTION_DAYS = 90

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "integration": "none",
        "network": "none",
        "persistence": "none",
        "qualification": "none",
        "target_execution": "none",
        "ticketing": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|assessmentref|findingref|pathref|evidenceref|itemref|"
    r"controlref|principalref|handoffref|actionref|cleanupref|rollbackref|"
    r"gateref|exceptionref|idemref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class RemediationValidationError(ValueError):
    """Raised when a remediation or validation contract fails closed."""


class GateDisposition(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    NOT_OBSERVED = "not_observed"


class ClosureDisposition(StrEnum):
    CLOSED_NONQUALIFIED = "closed_nonqualified"
    OPEN = "open"
    EXCEPTION_ACTIVE_NONQUALIFIED = "exception_active_nonqualified"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise RemediationValidationError("value cannot be serialized") from exc


def canonical_sha256(value: Any) -> str:
    """Return a prefixed SHA-256 over canonical JSON."""

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise RemediationValidationError(f"{label} fields are invalid")
    return raw


def _field_names(record_type: type[Any]) -> set[str]:
    return {item.name for item in fields(record_type)}


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise RemediationValidationError(f"{label} must be a SHA-256 digest")
    return value


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise RemediationValidationError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise RemediationValidationError(f"{label} must use {namespace}")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or CODE_RE.fullmatch(value) is None:
        raise RemediationValidationError(f"{label} must be a code")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise RemediationValidationError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RemediationValidationError(f"{label} must be valid") from exc


def _bounded(value: Any, label: str, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RemediationValidationError(f"{label} must be between {minimum} and {maximum}")
    return value


def _tuple(
    values: Sequence[str],
    label: str,
    *,
    namespace: str | None = None,
    minimum: int = 1,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RemediationValidationError(f"{label} must be a sequence")
    result = tuple(values)
    if not minimum <= len(result) <= MAX_ITEMS or len(set(result)) != len(result):
        raise RemediationValidationError(f"{label} must be bounded and unique")
    for value in result:
        _reference(value, label, namespace)
    return tuple(sorted(result))


def _digest_tuple(values: Sequence[str], label: str, minimum: int = 1) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RemediationValidationError(f"{label} must be a sequence")
    result = tuple(values)
    if not minimum <= len(result) <= MAX_ITEMS or len(set(result)) != len(result):
        raise RemediationValidationError(f"{label} must be bounded and unique")
    for value in result:
        _digest(value, label)
    return tuple(sorted(result))


def _verify_effects(value: Any) -> None:
    if not isinstance(value, Mapping) or dict(value) != dict(NO_EFFECTS):
        raise RemediationValidationError("effects must preserve the no-effect boundary")


def _verify_address(
    raw: Mapping[str, Any], id_field: str, digest_field: str, prefix: str, domain: str
) -> None:
    body = {key: value for key, value in raw.items() if key not in {id_field, digest_field}}
    expected_id, expected_digest = _identity(prefix, domain, body)
    if raw[id_field] != expected_id or raw[digest_field] != expected_digest:
        raise RemediationValidationError("record content address does not match content")


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise RemediationValidationError(f"{label} is invalid") from exc


@dataclass(frozen=True, slots=True)
class ContextBinding:
    """Tenant, assessment, scope, graph, and evidence state for a plan."""

    tenant_ref: str
    tenant_sha256: str
    assessment_ref: str
    assessment_sha256: str
    scope_sha256: str
    world_sha256: str
    findings_sha256: str
    attack_paths_sha256: str
    evidence_bundle_sha256: str
    observed_at: str
    expires_at: str
    context_id: str = ""
    context_sha256: str = ""

    DOMAIN: ClassVar[str] = "sunderkey.remediation-context.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.assessment_ref, "assessment_ref", "assessmentref")
        for name in (
            "tenant_sha256",
            "assessment_sha256",
            "scope_sha256",
            "world_sha256",
            "findings_sha256",
            "attack_paths_sha256",
            "evidence_bundle_sha256",
        ):
            _digest(getattr(self, name), name)
        observed = _timestamp(self.observed_at, "observed_at")
        if _timestamp(self.expires_at, "expires_at") <= observed:
            raise RemediationValidationError("context expires_at must follow observed_at")
        body = self._body()
        identity, digest = _identity("RMC", self.DOMAIN, body)
        if self.context_id not in {"", identity} or self.context_sha256 not in {"", digest}:
            raise RemediationValidationError("context content address does not match content")
        object.__setattr__(self, "context_id", identity)
        object.__setattr__(self, "context_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "assessment_sha256": self.assessment_sha256,
            "attack_paths_sha256": self.attack_paths_sha256,
            "evidence_bundle_sha256": self.evidence_bundle_sha256,
            "expires_at": self.expires_at,
            "findings_sha256": self.findings_sha256,
            "kind": self.DOMAIN,
            "observed_at": self.observed_at,
            "schema_version": SCHEMA_VERSION,
            "scope_sha256": self.scope_sha256,
            "tenant_ref": self.tenant_ref,
            "tenant_sha256": self.tenant_sha256,
            "world_sha256": self.world_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ContextBinding:
        _exact(raw, _field_names(cls) | {"kind", "schema_version"}, "context")
        if raw["kind"] != cls.DOMAIN or raw["schema_version"] != SCHEMA_VERSION:
            raise RemediationValidationError("context kind or schema version is invalid")
        values = {key: raw[key] for key in _field_names(cls)}
        return cls(**values)


@dataclass(frozen=True, slots=True)
class RemediationItem:
    """One bounded remediation proposal with risk and dependency inputs."""

    item_ref: str
    action_sha256: str
    finding_refs: tuple[str, ...]
    attack_path_refs: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    dependency_refs: tuple[str, ...]
    owner_ref: str
    inherent_risk_points: int
    residual_risk_points: int
    effort_points: int
    rollback_ref: str
    rollback_sha256: str
    cleanup_ref: str
    cleanup_sha256: str

    def __post_init__(self) -> None:
        _reference(self.item_ref, "item_ref", "itemref")
        _digest(self.action_sha256, "action_sha256")
        object.__setattr__(
            self, "finding_refs", _tuple(self.finding_refs, "finding_refs", namespace="findingref")
        )
        object.__setattr__(
            self,
            "attack_path_refs",
            _tuple(self.attack_path_refs, "attack_path_refs", namespace="pathref"),
        )
        object.__setattr__(
            self, "evidence_digests", _digest_tuple(self.evidence_digests, "evidence_digests")
        )
        object.__setattr__(
            self,
            "dependency_refs",
            _tuple(self.dependency_refs, "dependency_refs", namespace="itemref", minimum=0),
        )
        if self.item_ref in self.dependency_refs:
            raise RemediationValidationError("an item cannot depend on itself")
        _reference(self.owner_ref, "owner_ref", "principalref")
        inherent = _bounded(self.inherent_risk_points, "inherent_risk_points", 1)
        residual = _bounded(self.residual_risk_points, "residual_risk_points")
        _bounded(self.effort_points, "effort_points", 1, 10000)
        if residual >= inherent:
            raise RemediationValidationError("residual risk must be lower than inherent risk")
        _reference(self.rollback_ref, "rollback_ref", "rollbackref")
        _digest(self.rollback_sha256, "rollback_sha256")
        _reference(self.cleanup_ref, "cleanup_ref", "cleanupref")
        _digest(self.cleanup_sha256, "cleanup_sha256")

    @property
    def risk_reduction_points(self) -> int:
        return self.inherent_risk_points - self.residual_risk_points

    @property
    def priority_score(self) -> int:
        return (self.risk_reduction_points * 1_000_000) // self.effort_points

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "attack_path_refs": list(self.attack_path_refs),
            "cleanup_ref": self.cleanup_ref,
            "cleanup_sha256": self.cleanup_sha256,
            "dependency_refs": list(self.dependency_refs),
            "effort_points": self.effort_points,
            "evidence_digests": list(self.evidence_digests),
            "finding_refs": list(self.finding_refs),
            "inherent_risk_points": self.inherent_risk_points,
            "item_ref": self.item_ref,
            "owner_ref": self.owner_ref,
            "priority_score": self.priority_score,
            "residual_risk_points": self.residual_risk_points,
            "risk_reduction_points": self.risk_reduction_points,
            "rollback_ref": self.rollback_ref,
            "rollback_sha256": self.rollback_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RemediationItem:
        computed = {"priority_score", "risk_reduction_points"}
        _exact(raw, _field_names(cls) | computed, "remediation item")
        values = {key: raw[key] for key in _field_names(cls)}
        for name in ("finding_refs", "attack_path_refs", "evidence_digests", "dependency_refs"):
            values[name] = tuple(values[name])
        result = cls(**values)
        if (
            raw["priority_score"] != result.priority_score
            or raw["risk_reduction_points"] != result.risk_reduction_points
        ):
            raise RemediationValidationError("remediation item derived risk values are invalid")
        return result


@dataclass(frozen=True, slots=True)
class CompensatingControl:
    control_ref: str
    control_sha256: str
    item_refs: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    expected_risk_reduction_points: int
    owner_ref: str
    expires_at: str

    def __post_init__(self) -> None:
        _reference(self.control_ref, "control_ref", "controlref")
        _digest(self.control_sha256, "control_sha256")
        object.__setattr__(
            self, "item_refs", _tuple(self.item_refs, "item_refs", namespace="itemref")
        )
        object.__setattr__(
            self, "evidence_digests", _digest_tuple(self.evidence_digests, "evidence_digests")
        )
        _bounded(self.expected_risk_reduction_points, "expected_risk_reduction_points", 1)
        _reference(self.owner_ref, "owner_ref", "principalref")
        _timestamp(self.expires_at, "expires_at")

    def to_dict(self) -> dict[str, Any]:
        result = {name: getattr(self, name) for name in _field_names(type(self))}
        result["item_refs"] = list(self.item_refs)
        result["evidence_digests"] = list(self.evidence_digests)
        return result

    @classmethod
    def from_dict(cls, raw: Any) -> CompensatingControl:
        _exact(raw, _field_names(cls), "compensating control")
        return cls(
            **{
                **raw,
                "item_refs": tuple(raw["item_refs"]),
                "evidence_digests": tuple(raw["evidence_digests"]),
            }
        )


@dataclass(frozen=True, slots=True)
class OwnershipHandoff:
    handoff_ref: str
    item_refs: tuple[str, ...]
    from_owner_ref: str
    to_owner_ref: str
    acceptance_evidence_sha256: str
    accepted_at: str

    def __post_init__(self) -> None:
        _reference(self.handoff_ref, "handoff_ref", "handoffref")
        object.__setattr__(
            self, "item_refs", _tuple(self.item_refs, "item_refs", namespace="itemref")
        )
        _reference(self.from_owner_ref, "from_owner_ref", "principalref")
        _reference(self.to_owner_ref, "to_owner_ref", "principalref")
        if self.from_owner_ref == self.to_owner_ref:
            raise RemediationValidationError("ownership handoff must change owner")
        _digest(self.acceptance_evidence_sha256, "acceptance_evidence_sha256")
        _timestamp(self.accepted_at, "accepted_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            **{name: getattr(self, name) for name in _field_names(type(self))},
            "item_refs": list(self.item_refs),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OwnershipHandoff:
        _exact(raw, _field_names(cls), "ownership handoff")
        return cls(**{**raw, "item_refs": tuple(raw["item_refs"])})


@dataclass(frozen=True, slots=True)
class RemediationBatch:
    sequence: int
    item_refs: tuple[str, ...]
    dependency_refs: tuple[str, ...]
    owner_refs: tuple[str, ...]
    risk_reduction_points: int
    priority_score: int

    def __post_init__(self) -> None:
        _bounded(self.sequence, "sequence", 1, MAX_ITEMS)
        item_refs = tuple(self.item_refs)
        if not 1 <= len(item_refs) <= MAX_ITEMS or len(set(item_refs)) != len(item_refs):
            raise RemediationValidationError("item_refs must be bounded and unique")
        for item_ref in item_refs:
            _reference(item_ref, "item_refs", "itemref")
        object.__setattr__(self, "item_refs", item_refs)
        object.__setattr__(
            self,
            "dependency_refs",
            _tuple(self.dependency_refs, "dependency_refs", namespace="itemref", minimum=0),
        )
        object.__setattr__(
            self, "owner_refs", _tuple(self.owner_refs, "owner_refs", namespace="principalref")
        )
        _bounded(self.risk_reduction_points, "risk_reduction_points", 1)
        _bounded(self.priority_score, "priority_score", 1, 10**12)

    def to_dict(self) -> dict[str, Any]:
        result = {name: getattr(self, name) for name in _field_names(type(self))}
        for name in ("item_refs", "dependency_refs", "owner_refs"):
            result[name] = list(result[name])
        return result

    @classmethod
    def from_dict(cls, raw: Any) -> RemediationBatch:
        _exact(raw, _field_names(cls), "remediation batch")
        values = dict(raw)
        for name in ("item_refs", "dependency_refs", "owner_refs"):
            values[name] = tuple(values[name])
        return cls(**values)


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    context_id: str
    context_sha256: str
    idempotency_key: str
    proposed_by: str
    created_at: str
    expires_at: str
    items: tuple[RemediationItem, ...]
    compensating_controls: tuple[CompensatingControl, ...]
    ownership_handoffs: tuple[OwnershipHandoff, ...]
    batches: tuple[RemediationBatch, ...]
    plan_id: str = ""
    plan_sha256: str = ""
    effects: Mapping[str, str] = field(default_factory=lambda: dict(NO_EFFECTS))

    DOMAIN: ClassVar[str] = "sunderkey.remediation-plan.v1"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"RMC-[0-9A-F]{32}", self.context_id):
            raise RemediationValidationError("context_id is invalid")
        _digest(self.context_sha256, "context_sha256")
        _reference(self.idempotency_key, "idempotency_key", "idemref")
        _reference(self.proposed_by, "proposed_by", "principalref")
        created = _timestamp(self.created_at, "created_at")
        if _timestamp(self.expires_at, "expires_at") <= created:
            raise RemediationValidationError("plan expires_at must follow created_at")
        for name in ("items", "compensating_controls", "ownership_handoffs", "batches"):
            value = tuple(getattr(self, name))
            if not 1 <= len(value) <= MAX_ITEMS:
                raise RemediationValidationError(f"{name} must be bounded and nonempty")
            object.__setattr__(self, name, value)
        object.__setattr__(self, "items", tuple(sorted(self.items, key=lambda item: item.item_ref)))
        object.__setattr__(
            self,
            "compensating_controls",
            tuple(sorted(self.compensating_controls, key=lambda value: value.control_ref)),
        )
        object.__setattr__(
            self,
            "ownership_handoffs",
            tuple(sorted(self.ownership_handoffs, key=lambda value: value.handoff_ref)),
        )
        item_refs = {item.item_ref for item in self.items}
        if len(item_refs) != len(self.items):
            raise RemediationValidationError("item references must be unique")
        for control in self.compensating_controls:
            if not set(control.item_refs) <= item_refs:
                raise RemediationValidationError("control references an item outside the plan")
            if _timestamp(control.expires_at, "control expires_at") <= created:
                raise RemediationValidationError("control is stale at plan creation")
        handoff_items: list[str] = []
        items_by_ref = {item.item_ref: item for item in self.items}
        for handoff in self.ownership_handoffs:
            if not set(handoff.item_refs) <= item_refs:
                raise RemediationValidationError("handoff references an item outside the plan")
            if _timestamp(handoff.accepted_at, "handoff accepted_at") > created:
                raise RemediationValidationError("handoff acceptance is after plan creation")
            for item_ref in handoff.item_refs:
                if items_by_ref[item_ref].owner_ref != handoff.to_owner_ref:
                    raise RemediationValidationError("handoff destination does not own its item")
                handoff_items.append(item_ref)
        if sorted(handoff_items) != sorted(item_refs):
            raise RemediationValidationError(
                "every remediation item needs exactly one accepted ownership handoff"
            )
        if self.batches != _build_batches(self.items):
            raise RemediationValidationError(
                "remediation batches do not match deterministic ordering"
            )
        _verify_effects(self.effects)
        object.__setattr__(self, "effects", NO_EFFECTS)
        identity, digest = _identity("RMP", self.DOMAIN, self._body())
        if self.plan_id not in {"", identity} or self.plan_sha256 not in {"", digest}:
            raise RemediationValidationError("plan content address does not match content")
        object.__setattr__(self, "plan_id", identity)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "batches": [value.to_dict() for value in self.batches],
            "compensating_controls": [value.to_dict() for value in self.compensating_controls],
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "created_at": self.created_at,
            "effects": dict(NO_EFFECTS),
            "expires_at": self.expires_at,
            "idempotency_key": self.idempotency_key,
            "items": [value.to_dict() for value in self.items],
            "kind": self.DOMAIN,
            "ownership_handoffs": [value.to_dict() for value in self.ownership_handoffs],
            "proposed_by": self.proposed_by,
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_id": self.plan_id, "plan_sha256": self.plan_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> RemediationPlan:
        expected = set(cls.__dataclass_fields__) - {"DOMAIN"} | {"kind", "schema_version"}
        _exact(raw, expected, "remediation plan")
        if raw["kind"] != cls.DOMAIN or raw["schema_version"] != SCHEMA_VERSION:
            raise RemediationValidationError("plan kind or schema version is invalid")
        _verify_address(raw, "plan_id", "plan_sha256", "RMP", cls.DOMAIN)
        return cls(
            context_id=raw["context_id"],
            context_sha256=raw["context_sha256"],
            idempotency_key=raw["idempotency_key"],
            proposed_by=raw["proposed_by"],
            created_at=raw["created_at"],
            expires_at=raw["expires_at"],
            items=tuple(RemediationItem.from_dict(value) for value in raw["items"]),
            compensating_controls=tuple(
                CompensatingControl.from_dict(value) for value in raw["compensating_controls"]
            ),
            ownership_handoffs=tuple(
                OwnershipHandoff.from_dict(value) for value in raw["ownership_handoffs"]
            ),
            batches=tuple(RemediationBatch.from_dict(value) for value in raw["batches"]),
            plan_id=raw["plan_id"],
            plan_sha256=raw["plan_sha256"],
            effects=raw["effects"],
        )


def _build_batches(items: tuple[RemediationItem, ...]) -> tuple[RemediationBatch, ...]:
    by_ref = {item.item_ref: item for item in items}
    if len(by_ref) != len(items):
        raise RemediationValidationError("item references must be unique")
    for item in items:
        if not set(item.dependency_refs) <= set(by_ref):
            raise RemediationValidationError("item dependency is not in the plan")
    remaining = set(by_ref)
    completed: set[str] = set()
    batches: list[RemediationBatch] = []
    while remaining:
        ready = [by_ref[ref] for ref in remaining if set(by_ref[ref].dependency_refs) <= completed]
        if not ready:
            raise RemediationValidationError("item dependency graph contains a cycle")
        ready.sort(key=lambda item: (-item.priority_score, item.item_ref))
        refs = tuple(item.item_ref for item in ready)
        dependencies = tuple(sorted({ref for item in ready for ref in item.dependency_refs}))
        owners = tuple(sorted({item.owner_ref for item in ready}))
        batches.append(
            RemediationBatch(
                sequence=len(batches) + 1,
                item_refs=refs,
                dependency_refs=dependencies,
                owner_refs=owners,
                risk_reduction_points=sum(item.risk_reduction_points for item in ready),
                priority_score=sum(item.priority_score for item in ready),
            )
        )
        completed.update(refs)
        remaining.difference_update(refs)
    return tuple(batches)


def build_remediation_plan(
    context: ContextBinding,
    items: Sequence[RemediationItem],
    controls: Sequence[CompensatingControl],
    handoffs: Sequence[OwnershipHandoff],
    *,
    idempotency_key: str,
    proposed_by: str,
    created_at: str,
    expires_at: str,
) -> RemediationPlan:
    """Build deterministic, dependency-ordered remediation batches."""

    if not isinstance(context, ContextBinding):
        raise RemediationValidationError("context must be a typed remediation context")
    context = ContextBinding.from_dict(context.to_dict())
    checked_sources = []
    for values, record_type, label in (
        (items, RemediationItem, "items"),
        (controls, CompensatingControl, "controls"),
        (handoffs, OwnershipHandoff, "handoffs"),
    ):
        if (
            not isinstance(values, Sequence)
            or isinstance(values, (str, bytes))
            or len(values) > MAX_ITEMS
            or any(not isinstance(value, record_type) for value in values)
        ):
            raise RemediationValidationError(f"{label} must be a bounded typed sequence")
        checked_sources.append(tuple(record_type.from_dict(value.to_dict()) for value in values))
    items, controls, handoffs = checked_sources
    created = _timestamp(created_at, "created_at")
    if created < _timestamp(context.observed_at, "context observed_at"):
        raise RemediationValidationError("plan predates its context")
    if _timestamp(expires_at, "expires_at") > _timestamp(context.expires_at, "context expires_at"):
        raise RemediationValidationError("plan outlives its context")
    item_values = tuple(sorted(items, key=lambda item: item.item_ref))
    control_values = tuple(sorted(controls, key=lambda control: control.control_ref))
    handoff_values = tuple(sorted(handoffs, key=lambda handoff: handoff.handoff_ref))
    item_refs = {item.item_ref for item in item_values}
    for control in control_values:
        if not set(control.item_refs) <= item_refs:
            raise RemediationValidationError("control references an item outside the plan")
        if _timestamp(control.expires_at, "control expires_at") <= created:
            raise RemediationValidationError("control is stale at plan creation")
    handoff_items: list[str] = []
    for handoff in handoff_values:
        if not set(handoff.item_refs) <= item_refs:
            raise RemediationValidationError("handoff references an item outside the plan")
        if _timestamp(handoff.accepted_at, "handoff accepted_at") > created:
            raise RemediationValidationError("handoff acceptance is after plan creation")
        for item_ref in handoff.item_refs:
            by_item = next((item for item in item_values if item.item_ref == item_ref), None)
            if by_item is not None and by_item.owner_ref != handoff.to_owner_ref:
                raise RemediationValidationError("handoff destination does not own its item")
            handoff_items.append(item_ref)
    if sorted(handoff_items) != sorted(item_refs):
        raise RemediationValidationError(
            "every remediation item needs exactly one accepted ownership handoff"
        )
    return RemediationPlan(
        context_id=context.context_id,
        context_sha256=context.context_sha256,
        idempotency_key=idempotency_key,
        proposed_by=proposed_by,
        created_at=created_at,
        expires_at=expires_at,
        items=item_values,
        compensating_controls=control_values,
        ownership_handoffs=handoff_values,
        batches=_build_batches(item_values),
    )


def verify_remediation_plan(context: ContextBinding, plan: RemediationPlan) -> None:
    """Replay the entire plan from its exact context and bound source records."""

    if not isinstance(plan, RemediationPlan):
        raise RemediationValidationError("plan must be a typed remediation plan")
    plan = RemediationPlan.from_dict(plan.to_dict())
    expected = build_remediation_plan(
        context,
        plan.items,
        plan.compensating_controls,
        plan.ownership_handoffs,
        idempotency_key=plan.idempotency_key,
        proposed_by=plan.proposed_by,
        created_at=plan.created_at,
        expires_at=plan.expires_at,
    )
    if plan.to_dict() != expected.to_dict():
        raise RemediationValidationError("remediation plan does not replay from its context")


@dataclass(frozen=True, slots=True)
class RegressionGate:
    gate_ref: str
    gate_sha256: str
    item_refs: tuple[str, ...]
    required_evidence_digests: tuple[str, ...]
    failure_code: str

    def __post_init__(self) -> None:
        _reference(self.gate_ref, "gate_ref", "gateref")
        _digest(self.gate_sha256, "gate_sha256")
        object.__setattr__(
            self, "item_refs", _tuple(self.item_refs, "item_refs", namespace="itemref")
        )
        object.__setattr__(
            self,
            "required_evidence_digests",
            _digest_tuple(self.required_evidence_digests, "required_evidence_digests"),
        )
        _code(self.failure_code, "failure_code")

    def to_dict(self) -> dict[str, Any]:
        result = {name: getattr(self, name) for name in _field_names(type(self))}
        result["item_refs"] = list(self.item_refs)
        result["required_evidence_digests"] = list(self.required_evidence_digests)
        return result

    @classmethod
    def from_dict(cls, raw: Any) -> RegressionGate:
        _exact(raw, _field_names(cls), "regression gate")
        return cls(
            **{
                **raw,
                "item_refs": tuple(raw["item_refs"]),
                "required_evidence_digests": tuple(raw["required_evidence_digests"]),
            }
        )


@dataclass(frozen=True, slots=True)
class RetestPlan:
    context_id: str
    context_sha256: str
    remediation_plan_id: str
    remediation_plan_sha256: str
    idempotency_key: str
    item_refs: tuple[str, ...]
    gates: tuple[RegressionGate, ...]
    rollback_evidence_digests: tuple[str, ...]
    cleanup_evidence_digests: tuple[str, ...]
    proposed_by: str
    created_at: str
    expires_at: str
    retest_plan_id: str = ""
    retest_plan_sha256: str = ""
    effects: Mapping[str, str] = field(default_factory=lambda: dict(NO_EFFECTS))

    DOMAIN: ClassVar[str] = "sunderkey.remediation-retest-plan.v1"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"RMC-[0-9A-F]{32}", self.context_id):
            raise RemediationValidationError("context_id is invalid")
        _digest(self.context_sha256, "context_sha256")
        if not re.fullmatch(r"RMP-[0-9A-F]{32}", self.remediation_plan_id):
            raise RemediationValidationError("remediation_plan_id is invalid")
        _digest(self.remediation_plan_sha256, "remediation_plan_sha256")
        _reference(self.idempotency_key, "idempotency_key", "idemref")
        object.__setattr__(
            self, "item_refs", _tuple(self.item_refs, "item_refs", namespace="itemref")
        )
        gates = tuple(self.gates)
        if not 1 <= len(gates) <= MAX_ITEMS or len({gate.gate_ref for gate in gates}) != len(gates):
            raise RemediationValidationError("gates must be bounded and unique")
        object.__setattr__(self, "gates", tuple(sorted(gates, key=lambda gate: gate.gate_ref)))
        object.__setattr__(
            self,
            "rollback_evidence_digests",
            _digest_tuple(self.rollback_evidence_digests, "rollback_evidence_digests"),
        )
        object.__setattr__(
            self,
            "cleanup_evidence_digests",
            _digest_tuple(self.cleanup_evidence_digests, "cleanup_evidence_digests"),
        )
        if {item_ref for gate in self.gates for item_ref in gate.item_refs} != set(self.item_refs):
            raise RemediationValidationError(
                "regression gates must cover exactly all remediation items"
            )
        _reference(self.proposed_by, "proposed_by", "principalref")
        created = _timestamp(self.created_at, "created_at")
        if _timestamp(self.expires_at, "expires_at") <= created:
            raise RemediationValidationError("retest plan expires_at must follow created_at")
        _verify_effects(self.effects)
        object.__setattr__(self, "effects", NO_EFFECTS)
        identity, digest = _identity("RTP", self.DOMAIN, self._body())
        if self.retest_plan_id not in {"", identity} or self.retest_plan_sha256 not in {"", digest}:
            raise RemediationValidationError("retest plan content address does not match content")
        object.__setattr__(self, "retest_plan_id", identity)
        object.__setattr__(self, "retest_plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cleanup_evidence_digests": list(self.cleanup_evidence_digests),
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "created_at": self.created_at,
            "effects": dict(NO_EFFECTS),
            "expires_at": self.expires_at,
            "gates": [gate.to_dict() for gate in self.gates],
            "idempotency_key": self.idempotency_key,
            "item_refs": list(self.item_refs),
            "kind": self.DOMAIN,
            "proposed_by": self.proposed_by,
            "remediation_plan_id": self.remediation_plan_id,
            "remediation_plan_sha256": self.remediation_plan_sha256,
            "rollback_evidence_digests": list(self.rollback_evidence_digests),
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "retest_plan_id": self.retest_plan_id,
            "retest_plan_sha256": self.retest_plan_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetestPlan:
        expected = set(cls.__dataclass_fields__) - {"DOMAIN"} | {"kind", "schema_version"}
        _exact(raw, expected, "retest plan")
        if raw["kind"] != cls.DOMAIN or raw["schema_version"] != SCHEMA_VERSION:
            raise RemediationValidationError("retest plan kind or schema version is invalid")
        _verify_address(raw, "retest_plan_id", "retest_plan_sha256", "RTP", cls.DOMAIN)
        return cls(
            context_id=raw["context_id"],
            context_sha256=raw["context_sha256"],
            remediation_plan_id=raw["remediation_plan_id"],
            remediation_plan_sha256=raw["remediation_plan_sha256"],
            idempotency_key=raw["idempotency_key"],
            item_refs=tuple(raw["item_refs"]),
            gates=tuple(RegressionGate.from_dict(value) for value in raw["gates"]),
            rollback_evidence_digests=tuple(raw["rollback_evidence_digests"]),
            cleanup_evidence_digests=tuple(raw["cleanup_evidence_digests"]),
            proposed_by=raw["proposed_by"],
            created_at=raw["created_at"],
            expires_at=raw["expires_at"],
            retest_plan_id=raw["retest_plan_id"],
            retest_plan_sha256=raw["retest_plan_sha256"],
            effects=raw["effects"],
        )


def build_retest_plan(
    plan: RemediationPlan,
    gates: Sequence[RegressionGate],
    *,
    idempotency_key: str,
    proposed_by: str,
    created_at: str,
    expires_at: str,
) -> RetestPlan:
    """Create a no-effect retest and regression gate plan."""

    if not isinstance(plan, RemediationPlan):
        raise RemediationValidationError("plan must be a remediation plan")
    plan = RemediationPlan.from_dict(plan.to_dict())
    if (
        not isinstance(gates, Sequence)
        or isinstance(gates, (str, bytes))
        or not 1 <= len(gates) <= MAX_ITEMS
        or any(not isinstance(gate, RegressionGate) for gate in gates)
    ):
        raise RemediationValidationError("gates must be a bounded typed sequence")
    created = _timestamp(created_at, "created_at")
    if created < _timestamp(plan.created_at, "plan created_at"):
        raise RemediationValidationError("retest plan predates remediation plan")
    if _timestamp(expires_at, "expires_at") > _timestamp(plan.expires_at, "plan expires_at"):
        raise RemediationValidationError("retest plan outlives remediation plan")
    item_refs = tuple(item.item_ref for item in plan.items)
    item_set = set(item_refs)
    gate_values = tuple(RegressionGate.from_dict(gate.to_dict()) for gate in gates)
    if {item for gate in gate_values for item in gate.item_refs} != item_set:
        raise RemediationValidationError(
            "regression gates must cover exactly all remediation items"
        )
    return RetestPlan(
        context_id=plan.context_id,
        context_sha256=plan.context_sha256,
        remediation_plan_id=plan.plan_id,
        remediation_plan_sha256=plan.plan_sha256,
        idempotency_key=idempotency_key,
        item_refs=item_refs,
        gates=gate_values,
        rollback_evidence_digests=tuple(sorted({item.rollback_sha256 for item in plan.items})),
        cleanup_evidence_digests=tuple(sorted({item.cleanup_sha256 for item in plan.items})),
        proposed_by=proposed_by,
        created_at=created_at,
        expires_at=expires_at,
    )


def verify_retest_plan(plan: RemediationPlan, retest: RetestPlan) -> None:
    """Replay all item, restoration, and time bindings from the exact source plan."""

    if not isinstance(retest, RetestPlan):
        raise RemediationValidationError("retest must be a retest plan")
    retest = RetestPlan.from_dict(retest.to_dict())
    expected = build_retest_plan(
        plan,
        retest.gates,
        idempotency_key=retest.idempotency_key,
        proposed_by=retest.proposed_by,
        created_at=retest.created_at,
        expires_at=retest.expires_at,
    )
    if retest.to_dict() != expected.to_dict():
        raise RemediationValidationError("retest plan does not replay from remediation plan")


@dataclass(frozen=True, slots=True)
class GateObservation:
    gate_ref: str
    disposition: GateDisposition
    evidence_digests: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        _reference(self.gate_ref, "gate_ref", "gateref")
        object.__setattr__(
            self, "disposition", _enum(GateDisposition, self.disposition, "disposition")
        )
        object.__setattr__(
            self,
            "evidence_digests",
            _digest_tuple(self.evidence_digests, "evidence_digests", minimum=0),
        )
        _code(self.reason_code, "reason_code")

    def to_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "evidence_digests": list(self.evidence_digests),
            "gate_ref": self.gate_ref,
            "reason_code": self.reason_code,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GateObservation:
        _exact(raw, _field_names(cls), "gate observation")
        return cls(
            raw["gate_ref"], raw["disposition"], tuple(raw["evidence_digests"]), raw["reason_code"]
        )


@dataclass(frozen=True, slots=True)
class RetestObservation:
    context_id: str
    context_sha256: str
    remediation_plan_id: str
    remediation_plan_sha256: str
    retest_plan_id: str
    retest_plan_sha256: str
    observed_by: str
    observed_at: str
    gate_observations: tuple[GateObservation, ...]
    rollback_evidence_digests: tuple[str, ...]
    cleanup_evidence_digests: tuple[str, ...]
    observation_id: str = ""
    observation_sha256: str = ""
    effects: Mapping[str, str] = field(default_factory=lambda: dict(NO_EFFECTS))

    DOMAIN: ClassVar[str] = "sunderkey.remediation-retest-observation.v1"

    def __post_init__(self) -> None:
        for name, prefix in (
            ("context_id", "RMC"),
            ("remediation_plan_id", "RMP"),
            ("retest_plan_id", "RTP"),
        ):
            if not re.fullmatch(prefix + r"-[0-9A-F]{32}", getattr(self, name)):
                raise RemediationValidationError(f"{name} is invalid")
        for name in ("context_sha256", "remediation_plan_sha256", "retest_plan_sha256"):
            _digest(getattr(self, name), name)
        _reference(self.observed_by, "observed_by", "principalref")
        _timestamp(self.observed_at, "observed_at")
        observations = tuple(self.gate_observations)
        if not 1 <= len(observations) <= MAX_ITEMS or len(
            {value.gate_ref for value in observations}
        ) != len(observations):
            raise RemediationValidationError("gate observations must be bounded and unique")
        object.__setattr__(
            self,
            "gate_observations",
            tuple(sorted(observations, key=lambda value: value.gate_ref)),
        )
        object.__setattr__(
            self,
            "rollback_evidence_digests",
            _digest_tuple(self.rollback_evidence_digests, "rollback_evidence_digests", minimum=0),
        )
        object.__setattr__(
            self,
            "cleanup_evidence_digests",
            _digest_tuple(self.cleanup_evidence_digests, "cleanup_evidence_digests", minimum=0),
        )
        _verify_effects(self.effects)
        object.__setattr__(self, "effects", NO_EFFECTS)
        identity, digest = _identity("RTO", self.DOMAIN, self._body())
        if self.observation_id not in {"", identity} or self.observation_sha256 not in {"", digest}:
            raise RemediationValidationError("observation content address does not match content")
        object.__setattr__(self, "observation_id", identity)
        object.__setattr__(self, "observation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cleanup_evidence_digests": list(self.cleanup_evidence_digests),
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "effects": dict(NO_EFFECTS),
            "gate_observations": [value.to_dict() for value in self.gate_observations],
            "kind": self.DOMAIN,
            "observed_at": self.observed_at,
            "observed_by": self.observed_by,
            "remediation_plan_id": self.remediation_plan_id,
            "remediation_plan_sha256": self.remediation_plan_sha256,
            "retest_plan_id": self.retest_plan_id,
            "retest_plan_sha256": self.retest_plan_sha256,
            "rollback_evidence_digests": list(self.rollback_evidence_digests),
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetestObservation:
        expected = set(cls.__dataclass_fields__) - {"DOMAIN"} | {"kind", "schema_version"}
        _exact(raw, expected, "retest observation")
        if raw["kind"] != cls.DOMAIN or raw["schema_version"] != SCHEMA_VERSION:
            raise RemediationValidationError("observation kind or schema version is invalid")
        _verify_address(raw, "observation_id", "observation_sha256", "RTO", cls.DOMAIN)
        return cls(
            context_id=raw["context_id"],
            context_sha256=raw["context_sha256"],
            remediation_plan_id=raw["remediation_plan_id"],
            remediation_plan_sha256=raw["remediation_plan_sha256"],
            retest_plan_id=raw["retest_plan_id"],
            retest_plan_sha256=raw["retest_plan_sha256"],
            observed_by=raw["observed_by"],
            observed_at=raw["observed_at"],
            gate_observations=tuple(
                GateObservation.from_dict(value) for value in raw["gate_observations"]
            ),
            rollback_evidence_digests=tuple(raw["rollback_evidence_digests"]),
            cleanup_evidence_digests=tuple(raw["cleanup_evidence_digests"]),
            observation_id=raw["observation_id"],
            observation_sha256=raw["observation_sha256"],
            effects=raw["effects"],
        )


def verify_retest_observation(
    plan: RemediationPlan, retest: RetestPlan, observation: RetestObservation
) -> None:
    """Check source binding and coverage without treating any observed gate as proof."""

    if not isinstance(plan, RemediationPlan) or not isinstance(retest, RetestPlan):
        raise RemediationValidationError("observation needs typed remediation and retest plans")
    if not isinstance(observation, RetestObservation):
        raise RemediationValidationError("observation must be a typed retest observation")
    plan = RemediationPlan.from_dict(plan.to_dict())
    retest = RetestPlan.from_dict(retest.to_dict())
    observation = RetestObservation.from_dict(observation.to_dict())
    verify_retest_plan(plan, retest)
    bindings = {
        (plan.context_id, plan.context_sha256, plan.plan_id, plan.plan_sha256),
        (
            retest.context_id, retest.context_sha256,
            retest.remediation_plan_id, retest.remediation_plan_sha256,
        ),
        (
            observation.context_id, observation.context_sha256,
            observation.remediation_plan_id, observation.remediation_plan_sha256,
        ),
    }
    if (
        len(bindings) != 1
        or observation.retest_plan_id != retest.retest_plan_id
        or observation.retest_plan_sha256 != retest.retest_plan_sha256
    ):
        raise RemediationValidationError("observation inputs are cross-context or rebound")
    observed = _timestamp(observation.observed_at, "observation observed_at")
    if not _timestamp(retest.created_at, "retest created_at") <= observed <= _timestamp(
        retest.expires_at, "retest expires_at"
    ):
        raise RemediationValidationError("observation is outside its retest window")
    if {gate.gate_ref for gate in retest.gates} != {
        gate.gate_ref for gate in observation.gate_observations
    }:
        raise RemediationValidationError("observation must cover exactly all regression gates")


@dataclass(frozen=True, slots=True)
class RiskException:
    context_id: str
    context_sha256: str
    remediation_plan_id: str
    remediation_plan_sha256: str
    exception_ref: str
    item_refs: tuple[str, ...]
    control_refs: tuple[str, ...]
    requested_by: str
    approved_by: str
    approved_at: str
    expires_at: str
    rationale_code: str
    exception_id: str = ""
    exception_sha256: str = ""
    effects: Mapping[str, str] = field(default_factory=lambda: dict(NO_EFFECTS))

    DOMAIN: ClassVar[str] = "sunderkey.remediation-risk-exception.v1"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"RMC-[0-9A-F]{32}", self.context_id) or not re.fullmatch(
            r"RMP-[0-9A-F]{32}", self.remediation_plan_id
        ):
            raise RemediationValidationError("exception bindings are invalid")
        _digest(self.context_sha256, "context_sha256")
        _digest(self.remediation_plan_sha256, "remediation_plan_sha256")
        _reference(self.exception_ref, "exception_ref", "exceptionref")
        object.__setattr__(
            self, "item_refs", _tuple(self.item_refs, "item_refs", namespace="itemref")
        )
        object.__setattr__(
            self, "control_refs", _tuple(self.control_refs, "control_refs", namespace="controlref")
        )
        _reference(self.requested_by, "requested_by", "principalref")
        _reference(self.approved_by, "approved_by", "principalref")
        if self.requested_by == self.approved_by:
            raise RemediationValidationError(
                "exception approver must be independent from requester"
            )
        approved = _timestamp(self.approved_at, "approved_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if not approved < expires <= approved + timedelta(days=MAX_EXCEPTION_DAYS):
            raise RemediationValidationError("exception expiry must be bounded to 90 days")
        _code(self.rationale_code, "rationale_code")
        _verify_effects(self.effects)
        object.__setattr__(self, "effects", NO_EFFECTS)
        identity, digest = _identity("REX", self.DOMAIN, self._body())
        if self.exception_id not in {"", identity} or self.exception_sha256 not in {"", digest}:
            raise RemediationValidationError("exception content address does not match content")
        object.__setattr__(self, "exception_id", identity)
        object.__setattr__(self, "exception_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "control_refs": list(self.control_refs),
            "effects": dict(NO_EFFECTS),
            "exception_ref": self.exception_ref,
            "expires_at": self.expires_at,
            "item_refs": list(self.item_refs),
            "kind": self.DOMAIN,
            "rationale_code": self.rationale_code,
            "remediation_plan_id": self.remediation_plan_id,
            "remediation_plan_sha256": self.remediation_plan_sha256,
            "requested_by": self.requested_by,
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "exception_id": self.exception_id,
            "exception_sha256": self.exception_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RiskException:
        expected = set(cls.__dataclass_fields__) - {"DOMAIN"} | {"kind", "schema_version"}
        _exact(raw, expected, "risk exception")
        if raw["kind"] != cls.DOMAIN or raw["schema_version"] != SCHEMA_VERSION:
            raise RemediationValidationError("exception kind or schema version is invalid")
        _verify_address(raw, "exception_id", "exception_sha256", "REX", cls.DOMAIN)
        values = {key: raw[key] for key in _field_names(cls)}
        values["item_refs"] = tuple(values["item_refs"])
        values["control_refs"] = tuple(values["control_refs"])
        return cls(**values)


def verify_risk_exception(plan: RemediationPlan, exception: RiskException) -> None:
    """Check supplied exception lineage, not current approval or effective control."""

    if not isinstance(plan, RemediationPlan) or not isinstance(exception, RiskException):
        raise RemediationValidationError("exception needs typed plan and exception sources")
    plan = RemediationPlan.from_dict(plan.to_dict())
    exception = RiskException.from_dict(exception.to_dict())
    if (
        exception.context_id != plan.context_id
        or exception.context_sha256 != plan.context_sha256
        or exception.remediation_plan_id != plan.plan_id
        or exception.remediation_plan_sha256 != plan.plan_sha256
    ):
        raise RemediationValidationError("exception is cross-context or rebound")
    if not set(exception.item_refs) <= {item.item_ref for item in plan.items} or not set(
        exception.control_refs
    ) <= {control.control_ref for control in plan.compensating_controls}:
        raise RemediationValidationError("exception references sources outside the plan")
    approved = _timestamp(exception.approved_at, "exception approved_at")
    if not _timestamp(plan.created_at, "plan created_at") <= approved <= _timestamp(
        plan.expires_at, "plan expires_at"
    ):
        raise RemediationValidationError("exception approval is outside its source plan window")


@dataclass(frozen=True, slots=True)
class ClosureDecision:
    context_id: str
    context_sha256: str
    remediation_plan_id: str
    remediation_plan_sha256: str
    retest_plan_id: str
    retest_plan_sha256: str
    observation_id: str
    observation_sha256: str
    idempotency_key: str
    reviewer_ref: str
    reviewed_at: str
    disposition: ClosureDisposition
    reason_codes: tuple[str, ...]
    exception_id: str | None
    exception_sha256: str | None
    decision_id: str = ""
    decision_sha256: str = ""
    effects: Mapping[str, str] = field(default_factory=lambda: dict(NO_EFFECTS))

    DOMAIN: ClassVar[str] = "sunderkey.remediation-closure-decision.v1"

    def __post_init__(self) -> None:
        for name, prefix in (
            ("context_id", "RMC"),
            ("remediation_plan_id", "RMP"),
            ("retest_plan_id", "RTP"),
            ("observation_id", "RTO"),
        ):
            if not re.fullmatch(prefix + r"-[0-9A-F]{32}", getattr(self, name)):
                raise RemediationValidationError(f"{name} is invalid")
        for name in (
            "context_sha256",
            "remediation_plan_sha256",
            "retest_plan_sha256",
            "observation_sha256",
        ):
            _digest(getattr(self, name), name)
        _reference(self.idempotency_key, "idempotency_key", "idemref")
        _reference(self.reviewer_ref, "reviewer_ref", "principalref")
        _timestamp(self.reviewed_at, "reviewed_at")
        object.__setattr__(
            self, "disposition", _enum(ClosureDisposition, self.disposition, "disposition")
        )
        reasons = tuple(self.reason_codes)
        if not 1 <= len(reasons) <= 32 or len(set(reasons)) != len(reasons):
            raise RemediationValidationError("reason_codes must be bounded and unique")
        for value in reasons:
            _code(value, "reason_code")
        object.__setattr__(self, "reason_codes", reasons)
        if (self.exception_id is None) != (self.exception_sha256 is None):
            raise RemediationValidationError("exception identity and digest must appear together")
        if self.exception_id is not None:
            if not re.fullmatch(r"REX-[0-9A-F]{32}", self.exception_id):
                raise RemediationValidationError("exception_id is invalid")
            _digest(self.exception_sha256, "exception_sha256")
        _verify_effects(self.effects)
        object.__setattr__(self, "effects", NO_EFFECTS)
        identity, digest = _identity("RCD", self.DOMAIN, self._body())
        if self.decision_id not in {"", identity} or self.decision_sha256 not in {"", digest}:
            raise RemediationValidationError("decision content address does not match content")
        object.__setattr__(self, "decision_id", identity)
        object.__setattr__(self, "decision_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "disposition": self.disposition.value,
            "effects": dict(NO_EFFECTS),
            "exception_id": self.exception_id,
            "exception_sha256": self.exception_sha256,
            "idempotency_key": self.idempotency_key,
            "kind": self.DOMAIN,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "reason_codes": list(self.reason_codes),
            "remediation_plan_id": self.remediation_plan_id,
            "remediation_plan_sha256": self.remediation_plan_sha256,
            "retest_plan_id": self.retest_plan_id,
            "retest_plan_sha256": self.retest_plan_sha256,
            "reviewed_at": self.reviewed_at,
            "reviewer_ref": self.reviewer_ref,
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "decision_id": self.decision_id,
            "decision_sha256": self.decision_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ClosureDecision:
        expected = set(cls.__dataclass_fields__) - {"DOMAIN"} | {"kind", "schema_version"}
        _exact(raw, expected, "closure decision")
        if raw["kind"] != cls.DOMAIN or raw["schema_version"] != SCHEMA_VERSION:
            raise RemediationValidationError("decision kind or schema version is invalid")
        _verify_address(raw, "decision_id", "decision_sha256", "RCD", cls.DOMAIN)
        values = {key: raw[key] for key in _field_names(cls)}
        values["reason_codes"] = tuple(values["reason_codes"])
        return cls(**values)


def decide_closure(
    plan: RemediationPlan,
    retest: RetestPlan,
    observation: RetestObservation,
    *,
    reviewer_ref: str,
    reviewed_at: str,
    idempotency_key: str,
    exception: RiskException | None = None,
) -> ClosureDecision:
    """Return a repository-only closure recommendation with no authority effect."""

    if not isinstance(plan, RemediationPlan) or not isinstance(retest, RetestPlan):
        raise RemediationValidationError("closure needs typed remediation and retest plans")
    if not isinstance(observation, RetestObservation):
        raise RemediationValidationError("closure needs a typed retest observation")
    plan = RemediationPlan.from_dict(plan.to_dict())
    retest = RetestPlan.from_dict(retest.to_dict())
    observation = RetestObservation.from_dict(observation.to_dict())
    if exception is not None:
        if not isinstance(exception, RiskException):
            raise RemediationValidationError("exception must be a typed risk exception")
        exception = RiskException.from_dict(exception.to_dict())
        verify_risk_exception(plan, exception)
    verify_retest_observation(plan, retest, observation)
    reviewed = _timestamp(reviewed_at, "reviewed_at")
    if reviewer_ref in {plan.proposed_by, retest.proposed_by, observation.observed_by}:
        raise RemediationValidationError("closure reviewer must be independent")
    if reviewed > _timestamp(plan.expires_at, "plan expires_at") or reviewed > _timestamp(
        retest.expires_at, "retest expires_at"
    ):
        raise RemediationValidationError("closure input is stale")
    if _timestamp(observation.observed_at, "observation observed_at") > reviewed:
        raise RemediationValidationError("closure review predates its observation")
    required_gates = {gate.gate_ref: gate for gate in retest.gates}
    observed_gates = {gate.gate_ref: gate for gate in observation.gate_observations}
    evidence_complete = all(
        set(required.required_evidence_digests) <= set(observed_gates[ref].evidence_digests)
        for ref, required in required_gates.items()
    )
    all_passed = all(value.disposition is GateDisposition.PASS for value in observed_gates.values())
    restoration_complete = set(retest.rollback_evidence_digests) <= set(
        observation.rollback_evidence_digests
    ) and set(retest.cleanup_evidence_digests) <= set(observation.cleanup_evidence_digests)
    exception_id = None
    exception_sha256 = None
    if all_passed and evidence_complete and restoration_complete:
        disposition = ClosureDisposition.CLOSED_NONQUALIFIED
        reasons = (
            "all_regression_gates_passed",
            "rollback_cleanup_evidence_bound",
            "repository_only_nonqualified",
        )
    elif exception is not None:
        if reviewed >= _timestamp(exception.expires_at, "exception expires_at"):
            raise RemediationValidationError("exception has expired")
        if _timestamp(exception.approved_at, "exception approved_at") > reviewed:
            raise RemediationValidationError("exception approval follows closure review")
        if reviewer_ref in {exception.requested_by, exception.approved_by}:
            raise RemediationValidationError(
                "closure reviewer must be independent from exception actors"
            )
        plan_items = {item.item_ref for item in plan.items}
        plan_controls = {
            control.control_ref
            for control in plan.compensating_controls
            if reviewed < _timestamp(control.expires_at, "control expires_at")
        }
        covered_items = {
            item_ref
            for control in plan.compensating_controls
            if control.control_ref in set(exception.control_refs)
            and reviewed < _timestamp(control.expires_at, "control expires_at")
            for item_ref in control.item_refs
        }
        if (
            set(exception.item_refs) != plan_items
            or not set(exception.control_refs) <= plan_controls
            or covered_items != plan_items
        ):
            raise RemediationValidationError("exception coverage is incomplete or stale")
        disposition = ClosureDisposition.EXCEPTION_ACTIVE_NONQUALIFIED
        reasons = ("active_exception_with_compensating_controls", "repository_only_nonqualified")
        exception_id = exception.exception_id
        exception_sha256 = exception.exception_sha256
    else:
        disposition = ClosureDisposition.OPEN
        reasons_list = []
        if not all_passed:
            reasons_list.append("regression_gate_not_passed")
        if not evidence_complete:
            reasons_list.append("required_evidence_missing")
        if not restoration_complete:
            reasons_list.append("rollback_cleanup_evidence_missing")
        reasons_list.append("repository_only_nonqualified")
        reasons = tuple(reasons_list)
    return ClosureDecision(
        context_id=plan.context_id,
        context_sha256=plan.context_sha256,
        remediation_plan_id=plan.plan_id,
        remediation_plan_sha256=plan.plan_sha256,
        retest_plan_id=retest.retest_plan_id,
        retest_plan_sha256=retest.retest_plan_sha256,
        observation_id=observation.observation_id,
        observation_sha256=observation.observation_sha256,
        idempotency_key=idempotency_key,
        reviewer_ref=reviewer_ref,
        reviewed_at=reviewed_at,
        disposition=disposition,
        reason_codes=reasons,
        exception_id=exception_id,
        exception_sha256=exception_sha256,
    )


def verify_closure_decision(
    plan: RemediationPlan,
    retest: RetestPlan,
    observation: RetestObservation,
    decision: ClosureDecision,
    *,
    exception: RiskException | None = None,
) -> None:
    """Replay a recommendation from its complete supplied sources, without live proof."""

    if not isinstance(decision, ClosureDecision):
        raise RemediationValidationError("decision must be a typed closure decision")
    decision = ClosureDecision.from_dict(decision.to_dict())
    expected = decide_closure(
        plan,
        retest,
        observation,
        reviewer_ref=decision.reviewer_ref,
        reviewed_at=decision.reviewed_at,
        idempotency_key=decision.idempotency_key,
        exception=exception,
    )
    if decision.to_dict() != expected.to_dict():
        raise RemediationValidationError("closure decision does not replay from its sources")


def ensure_idempotent(
    existing: RemediationPlan | RetestPlan | ClosureDecision,
    candidate: RemediationPlan | RetestPlan | ClosureDecision,
) -> None:
    """Reconstruct both immutable records before accepting an exact replay."""

    if type(existing) is not type(candidate):
        raise RemediationValidationError("idempotency records must have the same type")
    record_type = type(existing)
    if record_type not in {RemediationPlan, RetestPlan, ClosureDecision}:
        raise RemediationValidationError("idempotency records must have a supported exact type")
    _verify_effects(existing.effects)
    _verify_effects(candidate.effects)
    existing = record_type.from_dict(existing.to_dict())
    candidate = record_type.from_dict(candidate.to_dict())
    if existing.idempotency_key != candidate.idempotency_key:
        raise RemediationValidationError("idempotency keys do not match")
    if canonical_json(existing.to_dict()) != canonical_json(candidate.to_dict()):
        raise RemediationValidationError("idempotency key is bound to different content")


def parse_contract(
    raw: Any,
) -> (
    ContextBinding
    | RemediationPlan
    | RetestPlan
    | RetestObservation
    | RiskException
    | ClosureDecision
):
    """Parse and content-verify one top-level remediation contract."""

    if not isinstance(raw, Mapping):
        raise RemediationValidationError("contract must be an object")
    kind = raw.get("kind")
    parsers = {
        ContextBinding.DOMAIN: ContextBinding.from_dict,
        RemediationPlan.DOMAIN: RemediationPlan.from_dict,
        RetestPlan.DOMAIN: RetestPlan.from_dict,
        RetestObservation.DOMAIN: RetestObservation.from_dict,
        RiskException.DOMAIN: RiskException.from_dict,
        ClosureDecision.DOMAIN: ClosureDecision.from_dict,
    }
    parser = parsers.get(kind)
    if parser is None:
        raise RemediationValidationError("contract kind is unsupported")
    return parser(raw)
