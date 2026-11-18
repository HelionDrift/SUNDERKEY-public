"""Deterministic health-state contracts with no runtime effects.

The records in this module describe probe intent, externally supplied
observations, dependency health, aggregate health, and execution recovery
admission. They do not run probes, contact dependencies, pause work, resume
work, grant authorization, mutate persistence, or make live-health claims.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MAX_ITEMS = 4096
NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "execution": "none",
        "health_probe": "none",
        "network": "none",
        "pause": "none",
        "persistence": "none",
        "qualification": "none",
        "recovery": "none",
        "resume": "none",
    }
)
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|missionref|workerref|dependencyref|proberef|provenanceref|"
    r"artifactref|principalref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)


class HealthStateContractError(ValueError):
    """Raised when a health-state contract fails closed."""


class ProbeKind(StrEnum):
    LIVENESS = "liveness"
    READINESS = "readiness"
    DEPENDENCY = "dependency"
    INTEGRITY = "integrity"


class ObservationStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RECOVERING = "recovering"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class PauseCause(StrEnum):
    CONFLICTING_OBSERVATION = "conflicting_observation"
    FUTURE_OBSERVATION = "future_observation"
    MISSING_REQUIRED_OBSERVATION = "missing_required_observation"
    REQUIRED_DEPENDENCY_RECOVERING = "required_dependency_recovering"
    REQUIRED_DEPENDENCY_UNHEALTHY = "required_dependency_unhealthy"
    STALE_REQUIRED_OBSERVATION = "stale_required_observation"


class RecoveryAdmissionStatus(StrEnum):
    DENIED = "denied"
    ELIGIBLE_FOR_SEPARATE_AUTHORIZATION = "eligible_for_separate_authorization"


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
        raise HealthStateContractError("value cannot be serialized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _validate_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 14:
        raise HealthStateContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise HealthStateContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise HealthStateContractError(f"{label} has an unsupported value")


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise HealthStateContractError(f"{label} fields are invalid")
    return raw


def _ref(value: Any, label: str, namespace: str) -> str:
    if (
        not isinstance(value, str)
        or REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise HealthStateContractError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise HealthStateContractError(f"{label} must be a SHA-256 content address")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise HealthStateContractError(f"{label} must be an exact version")
    if value.lower() in {"latest", "stable", "current", "default", "auto"}:
        raise HealthStateContractError(f"{label} must not be a moving alias")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise HealthStateContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise HealthStateContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _positive(value: Any, label: str, maximum: int = 2_147_483_647) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise HealthStateContractError(f"{label} must be between 1 and {maximum}")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HealthStateContractError(f"{label} must be a nonnegative integer")
    return value


def _enum(value: Any, enum_type: type[StrEnum], label: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise HealthStateContractError(f"{label} is invalid") from exc


def _codes(values: Sequence[Any], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise HealthStateContractError(f"{label} must be a sequence")
    result = tuple(values)
    if len(result) > MAX_ITEMS or len(result) != len(set(result)):
        raise HealthStateContractError(f"{label} must be a bounded unique sequence")
    if any(
        not isinstance(item, str)
        or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None
        for item in result
    ):
        raise HealthStateContractError(f"{label} contains an invalid code")
    return tuple(sorted(result))


def _verify_effects(raw: Any) -> None:
    if not isinstance(raw, Mapping) or dict(raw) != dict(NO_EFFECTS):
        raise HealthStateContractError("effects must preserve the no-effect boundary")


@dataclass(frozen=True, slots=True)
class HealthContext:
    tenant_ref: str
    mission_ref: str
    worker_ref: str
    system_version: str
    worker_version: str

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("mission_ref", "missionref"),
            ("worker_ref", "workerref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "system_version", _version(self.system_version, "system_version")
        )
        object.__setattr__(
            self, "worker_version", _version(self.worker_version, "worker_version")
        )

    def to_dict(self) -> dict[str, str]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> HealthContext:
        _exact(raw, {item.name for item in fields(cls)}, "health context")
        return cls(**dict(raw))


class _AddressedRecord:
    KIND: ClassVar[str]
    ID_FIELD: ClassVar[str]
    DIGEST_FIELD: ClassVar[str]
    PREFIX: ClassVar[str]

    def _body(self) -> dict[str, Any]:
        raise NotImplementedError

    def _set_address(self) -> None:
        identifier, digest = _identity(self.PREFIX, self.KIND, self._body())
        object.__setattr__(self, self.ID_FIELD, identifier)
        object.__setattr__(self, self.DIGEST_FIELD, digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            self.ID_FIELD: getattr(self, self.ID_FIELD),
            self.DIGEST_FIELD: getattr(self, self.DIGEST_FIELD),
            **self._body(),
        }

    @classmethod
    def _verify(cls, raw: Mapping[str, Any], record: Any) -> Any:
        if dict(raw) != record.to_dict():
            raise HealthStateContractError("record content address does not match content")
        return record


@dataclass(frozen=True, slots=True)
class ProbeDefinition(_AddressedRecord):
    context: HealthContext
    probe_ref: str
    dependency_ref: str
    probe_version: str
    kind: ProbeKind | str
    required: bool
    interval_seconds: int
    max_age_seconds: int
    failure_threshold: int
    recovery_threshold: int
    issued_at: str
    definition_id: str = field(init=False)
    definition_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.health-probe-definition.v1"
    ID_FIELD: ClassVar[str] = "definition_id"
    DIGEST_FIELD: ClassVar[str] = "definition_sha256"
    PREFIX: ClassVar[str] = "HPD"

    def __post_init__(self) -> None:
        if not isinstance(self.context, HealthContext):
            object.__setattr__(self, "context", HealthContext.from_dict(self.context))
        object.__setattr__(
            self, "probe_ref", _ref(self.probe_ref, "probe_ref", "proberef")
        )
        object.__setattr__(
            self,
            "dependency_ref",
            _ref(self.dependency_ref, "dependency_ref", "dependencyref"),
        )
        object.__setattr__(
            self, "probe_version", _version(self.probe_version, "probe_version")
        )
        object.__setattr__(self, "kind", _enum(self.kind, ProbeKind, "kind"))
        if not isinstance(self.required, bool):
            raise HealthStateContractError("required must be boolean")
        _positive(self.interval_seconds, "interval_seconds", 86_400)
        _positive(self.max_age_seconds, "max_age_seconds", 604_800)
        if self.max_age_seconds < self.interval_seconds:
            raise HealthStateContractError("max_age_seconds must cover one probe interval")
        _positive(self.failure_threshold, "failure_threshold", 10_000)
        _positive(self.recovery_threshold, "recovery_threshold", 10_000)
        object.__setattr__(self, "issued_at", _time(self.issued_at, "issued_at"))
        self._set_address()

    def _body(self) -> dict[str, Any]:
        return {
            "context": self.context.to_dict(),
            "dependency_ref": self.dependency_ref,
            "effects": dict(NO_EFFECTS),
            "failure_threshold": self.failure_threshold,
            "interval_seconds": self.interval_seconds,
            "issued_at": self.issued_at,
            "kind": self.KIND,
            "max_age_seconds": self.max_age_seconds,
            "probe_kind": self.kind.value,
            "probe_ref": self.probe_ref,
            "probe_version": self.probe_version,
            "recovery_threshold": self.recovery_threshold,
            "required": self.required,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ProbeDefinition:
        expected = {
            "context", "definition_id", "definition_sha256", "dependency_ref",
            "effects", "failure_threshold", "interval_seconds", "issued_at", "kind",
            "max_age_seconds", "probe_kind", "probe_ref", "probe_version",
            "recovery_threshold", "required", "schema_version",
        }
        _exact(raw, expected, "probe definition")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise HealthStateContractError("probe definition metadata is invalid")
        _verify_effects(raw["effects"])
        record = cls(
            context=HealthContext.from_dict(raw["context"]),
            probe_ref=raw["probe_ref"],
            dependency_ref=raw["dependency_ref"],
            probe_version=raw["probe_version"],
            kind=raw["probe_kind"],
            required=raw["required"],
            interval_seconds=raw["interval_seconds"],
            max_age_seconds=raw["max_age_seconds"],
            failure_threshold=raw["failure_threshold"],
            recovery_threshold=raw["recovery_threshold"],
            issued_at=raw["issued_at"],
        )
        return cls._verify(raw, record)


@dataclass(frozen=True, slots=True)
class ProbeObservation(_AddressedRecord):
    context: HealthContext
    definition_id: str
    definition_sha256: str
    probe_ref: str
    probe_version: str
    sequence: int
    status: ObservationStatus | str
    observed_at: str
    collected_at: str
    provenance_ref: str
    provenance_sha256: str
    detail_sha256: str
    observation_id: str = field(init=False)
    observation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.health-probe-observation.v1"
    ID_FIELD: ClassVar[str] = "observation_id"
    DIGEST_FIELD: ClassVar[str] = "observation_sha256"
    PREFIX: ClassVar[str] = "HPO"

    def __post_init__(self) -> None:
        if not isinstance(self.context, HealthContext):
            object.__setattr__(self, "context", HealthContext.from_dict(self.context))
        if (
            not isinstance(self.definition_id, str)
            or re.fullmatch(r"HPD-[0-9A-F]{32}", self.definition_id) is None
        ):
            raise HealthStateContractError("definition_id is invalid")
        object.__setattr__(
            self,
            "definition_sha256",
            _digest(self.definition_sha256, "definition_sha256"),
        )
        object.__setattr__(
            self, "probe_ref", _ref(self.probe_ref, "probe_ref", "proberef")
        )
        object.__setattr__(
            self, "probe_version", _version(self.probe_version, "probe_version")
        )
        _nonnegative(self.sequence, "sequence")
        object.__setattr__(
            self, "status", _enum(self.status, ObservationStatus, "status")
        )
        object.__setattr__(self, "observed_at", _time(self.observed_at, "observed_at"))
        object.__setattr__(
            self, "collected_at", _time(self.collected_at, "collected_at")
        )
        if _instant(self.collected_at) < _instant(self.observed_at):
            raise HealthStateContractError("collected_at must not precede observed_at")
        object.__setattr__(
            self,
            "provenance_ref",
            _ref(self.provenance_ref, "provenance_ref", "provenanceref"),
        )
        object.__setattr__(
            self,
            "provenance_sha256",
            _digest(self.provenance_sha256, "provenance_sha256"),
        )
        object.__setattr__(
            self, "detail_sha256", _digest(self.detail_sha256, "detail_sha256")
        )
        self._set_address()

    def _body(self) -> dict[str, Any]:
        return {
            "collected_at": self.collected_at,
            "context": self.context.to_dict(),
            "definition_id": self.definition_id,
            "definition_sha256": self.definition_sha256,
            "detail_sha256": self.detail_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "observed_at": self.observed_at,
            "probe_ref": self.probe_ref,
            "probe_version": self.probe_version,
            "provenance_ref": self.provenance_ref,
            "provenance_sha256": self.provenance_sha256,
            "schema_version": SCHEMA_VERSION,
            "sequence": self.sequence,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ProbeObservation:
        expected = {
            "collected_at", "context", "definition_id", "definition_sha256",
            "detail_sha256", "effects", "kind", "observation_id",
            "observation_sha256", "observed_at", "probe_ref", "probe_version",
            "provenance_ref", "provenance_sha256", "schema_version", "sequence", "status",
        }
        _exact(raw, expected, "probe observation")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise HealthStateContractError("probe observation metadata is invalid")
        _verify_effects(raw["effects"])
        excluded = {"effects", "kind", "observation_id", "observation_sha256", "schema_version"}
        kwargs = {key: raw[key] for key in expected if key not in excluded}
        kwargs["context"] = HealthContext.from_dict(raw["context"])
        return cls._verify(raw, cls(**kwargs))


@dataclass(frozen=True, slots=True)
class DependencyHealth:
    definition_id: str
    definition_sha256: str
    dependency_ref: str
    required: bool
    state: HealthState | str
    success_streak: int
    failure_streak: int
    selected_observation_id: str | None
    selected_observation_sha256: str | None
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.definition_id, str)
            or re.fullmatch(r"HPD-[0-9A-F]{32}", self.definition_id) is None
        ):
            raise HealthStateContractError("definition_id is invalid")
        _digest(self.definition_sha256, "definition_sha256")
        _ref(self.dependency_ref, "dependency_ref", "dependencyref")
        if not isinstance(self.required, bool):
            raise HealthStateContractError("required must be boolean")
        object.__setattr__(self, "state", _enum(self.state, HealthState, "state"))
        _nonnegative(self.success_streak, "success_streak")
        _nonnegative(self.failure_streak, "failure_streak")
        if self.success_streak and self.failure_streak:
            raise HealthStateContractError(
                "success and failure streaks cannot both be active"
            )
        if (self.selected_observation_id is None) != (
            self.selected_observation_sha256 is None
        ):
            raise HealthStateContractError("selected observation binding is incomplete")
        if self.selected_observation_id is not None:
            if re.fullmatch(r"HPO-[0-9A-F]{32}", self.selected_observation_id) is None:
                raise HealthStateContractError("selected_observation_id is invalid")
            _digest(self.selected_observation_sha256, "selected_observation_sha256")
        object.__setattr__(
            self, "reason_codes", _codes(self.reason_codes, "reason_codes")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "definition_id": self.definition_id,
            "definition_sha256": self.definition_sha256,
            "dependency_ref": self.dependency_ref,
            "failure_streak": self.failure_streak,
            "reason_codes": list(self.reason_codes),
            "required": self.required,
            "selected_observation_id": self.selected_observation_id,
            "selected_observation_sha256": self.selected_observation_sha256,
            "state": self.state.value,
            "success_streak": self.success_streak,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DependencyHealth:
        expected = {item.name for item in fields(cls)}
        _exact(raw, expected, "dependency health")
        kwargs = dict(raw)
        kwargs["reason_codes"] = tuple(kwargs["reason_codes"])
        return cls(**kwargs)


@dataclass(frozen=True, slots=True)
class HealthSnapshot(_AddressedRecord):
    context: HealthContext
    evaluated_at: str
    state: HealthState | str
    dependencies: tuple[DependencyHealth, ...]
    pause_causes: tuple[str, ...]
    prior_snapshot_id: str | None
    prior_snapshot_sha256: str | None
    snapshot_id: str = field(init=False)
    snapshot_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.health-snapshot.v1"
    ID_FIELD: ClassVar[str] = "snapshot_id"
    DIGEST_FIELD: ClassVar[str] = "snapshot_sha256"
    PREFIX: ClassVar[str] = "HSS"

    def __post_init__(self) -> None:
        if not isinstance(self.context, HealthContext):
            object.__setattr__(self, "context", HealthContext.from_dict(self.context))
        object.__setattr__(self, "evaluated_at", _time(self.evaluated_at, "evaluated_at"))
        object.__setattr__(self, "state", _enum(self.state, HealthState, "state"))
        items = tuple(
            item
            if isinstance(item, DependencyHealth)
            else DependencyHealth.from_dict(item)
            for item in self.dependencies
        )
        if not 1 <= len(items) <= MAX_ITEMS:
            raise HealthStateContractError("dependencies must be bounded and non-empty")
        refs = tuple(item.dependency_ref for item in items)
        if len(refs) != len(set(refs)):
            raise HealthStateContractError("dependencies contain duplicate references")
        object.__setattr__(
            self, "dependencies", tuple(sorted(items, key=lambda item: item.dependency_ref))
        )
        object.__setattr__(
            self, "pause_causes", _codes(self.pause_causes, "pause_causes")
        )
        if (self.prior_snapshot_id is None) != (self.prior_snapshot_sha256 is None):
            raise HealthStateContractError("prior snapshot binding is incomplete")
        if self.prior_snapshot_id is not None:
            if re.fullmatch(r"HSS-[0-9A-F]{32}", self.prior_snapshot_id) is None:
                raise HealthStateContractError("prior_snapshot_id is invalid")
            _digest(self.prior_snapshot_sha256, "prior_snapshot_sha256")
        healthy = not self.pause_causes and all(
            item.state is HealthState.HEALTHY for item in self.dependencies
        )
        if (self.state is HealthState.HEALTHY) != healthy:
            raise HealthStateContractError("snapshot state and pause causes disagree")
        self._set_address()

    def _body(self) -> dict[str, Any]:
        return {
            "context": self.context.to_dict(),
            "dependencies": [item.to_dict() for item in self.dependencies],
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "kind": self.KIND,
            "pause_causes": list(self.pause_causes),
            "prior_snapshot_id": self.prior_snapshot_id,
            "prior_snapshot_sha256": self.prior_snapshot_sha256,
            "schema_version": SCHEMA_VERSION,
            "state": self.state.value,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> HealthSnapshot:
        expected = {
            "context", "dependencies", "effects", "evaluated_at", "kind", "pause_causes",
            "prior_snapshot_id", "prior_snapshot_sha256", "schema_version", "snapshot_id",
            "snapshot_sha256", "state",
        }
        _exact(raw, expected, "health snapshot")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise HealthStateContractError("health snapshot metadata is invalid")
        _verify_effects(raw["effects"])
        record = cls(
            context=HealthContext.from_dict(raw["context"]),
            evaluated_at=raw["evaluated_at"],
            state=raw["state"],
            dependencies=tuple(
                DependencyHealth.from_dict(item) for item in raw["dependencies"]
            ),
            pause_causes=tuple(raw["pause_causes"]),
            prior_snapshot_id=raw["prior_snapshot_id"],
            prior_snapshot_sha256=raw["prior_snapshot_sha256"],
        )
        return cls._verify(raw, record)


@dataclass(frozen=True, slots=True)
class ExecutionRecoveryAdmission(_AddressedRecord):
    context: HealthContext
    snapshot_bindings: tuple[tuple[str, str], ...]
    evaluated_at: str
    max_snapshot_age_seconds: int
    required_consecutive_healthy_snapshots: int
    status: RecoveryAdmissionStatus | str
    blocker_codes: tuple[str, ...]
    authorization_effect: str
    admission_id: str = field(init=False)
    admission_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.health-execution-recovery-admission.v1"
    ID_FIELD: ClassVar[str] = "admission_id"
    DIGEST_FIELD: ClassVar[str] = "admission_sha256"
    PREFIX: ClassVar[str] = "HRA"

    def __post_init__(self) -> None:
        if not isinstance(self.context, HealthContext):
            object.__setattr__(self, "context", HealthContext.from_dict(self.context))
        bindings = tuple(tuple(item) for item in self.snapshot_bindings)
        if not 1 <= len(bindings) <= MAX_ITEMS:
            raise HealthStateContractError(
                "snapshot_bindings must be bounded and non-empty"
            )
        for item in bindings:
            if len(item) != 2 or re.fullmatch(r"HSS-[0-9A-F]{32}", item[0]) is None:
                raise HealthStateContractError("snapshot binding is invalid")
            _digest(item[1], "snapshot binding digest")
        if len(bindings) != len(set(bindings)):
            raise HealthStateContractError("snapshot_bindings contain duplicates")
        object.__setattr__(self, "snapshot_bindings", bindings)
        object.__setattr__(self, "evaluated_at", _time(self.evaluated_at, "evaluated_at"))
        _positive(self.max_snapshot_age_seconds, "max_snapshot_age_seconds", 604_800)
        _positive(
            self.required_consecutive_healthy_snapshots,
            "required_consecutive_healthy_snapshots",
            MAX_ITEMS,
        )
        object.__setattr__(
            self, "status", _enum(self.status, RecoveryAdmissionStatus, "status")
        )
        object.__setattr__(
            self, "blocker_codes", _codes(self.blocker_codes, "blocker_codes")
        )
        if (
            self.status is RecoveryAdmissionStatus.ELIGIBLE_FOR_SEPARATE_AUTHORIZATION
        ) != (not self.blocker_codes):
            raise HealthStateContractError("admission status and blockers disagree")
        if self.authorization_effect != "none":
            raise HealthStateContractError("health admission cannot grant authority")
        self._set_address()

    def _body(self) -> dict[str, Any]:
        return {
            "authorization_effect": self.authorization_effect,
            "blocker_codes": list(self.blocker_codes),
            "context": self.context.to_dict(),
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "kind": self.KIND,
            "max_snapshot_age_seconds": self.max_snapshot_age_seconds,
            "required_consecutive_healthy_snapshots": self.required_consecutive_healthy_snapshots,
            "schema_version": SCHEMA_VERSION,
            "snapshot_bindings": [
                {"snapshot_id": item[0], "snapshot_sha256": item[1]}
                for item in self.snapshot_bindings
            ],
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ExecutionRecoveryAdmission:
        expected = {
            "admission_id", "admission_sha256", "authorization_effect", "blocker_codes",
            "context", "effects", "evaluated_at", "kind", "max_snapshot_age_seconds",
            "required_consecutive_healthy_snapshots", "schema_version", "snapshot_bindings",
            "status",
        }
        _exact(raw, expected, "execution recovery admission")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise HealthStateContractError(
                "execution recovery admission metadata is invalid"
            )
        _verify_effects(raw["effects"])
        bindings = []
        for item in raw["snapshot_bindings"]:
            _exact(item, {"snapshot_id", "snapshot_sha256"}, "snapshot binding")
            bindings.append((item["snapshot_id"], item["snapshot_sha256"]))
        record = cls(
            context=HealthContext.from_dict(raw["context"]),
            snapshot_bindings=tuple(bindings),
            evaluated_at=raw["evaluated_at"],
            max_snapshot_age_seconds=raw["max_snapshot_age_seconds"],
            required_consecutive_healthy_snapshots=raw[
                "required_consecutive_healthy_snapshots"
            ],
            status=raw["status"],
            blocker_codes=tuple(raw["blocker_codes"]),
            authorization_effect=raw["authorization_effect"],
        )
        return cls._verify(raw, record)


def _same_context(expected: HealthContext, actual: HealthContext, label: str) -> None:
    if expected != actual:
        raise HealthStateContractError(f"{label} crosses a health context boundary")


def aggregate_health(
    definitions: Sequence[ProbeDefinition],
    observations: Sequence[ProbeObservation],
    *,
    evaluated_at: str,
    prior_snapshot: HealthSnapshot | None = None,
) -> HealthSnapshot:
    """Aggregate supplied evidence without running probes or changing runtime state."""

    definitions = tuple(definitions)
    observations = tuple(observations)
    if not 1 <= len(definitions) <= MAX_ITEMS or len(observations) > MAX_ITEMS:
        raise HealthStateContractError("health inputs exceed bounds")
    if not all(isinstance(item, ProbeDefinition) for item in definitions):
        raise HealthStateContractError("definitions must contain probe definitions")
    if not all(isinstance(item, ProbeObservation) for item in observations):
        raise HealthStateContractError("observations must contain probe observations")
    context = definitions[0].context
    by_id = {item.definition_id: item for item in definitions}
    if len(by_id) != len(definitions) or len(
        {item.dependency_ref for item in definitions}
    ) != len(definitions):
        raise HealthStateContractError(
            "definitions must be unique by identity and dependency"
        )
    for definition in definitions:
        _same_context(context, definition.context, "definition")
    evaluation_text = _time(evaluated_at, "evaluated_at")
    if prior_snapshot is not None:
        _same_context(context, prior_snapshot.context, "prior snapshot")
        if _instant(prior_snapshot.evaluated_at) >= _instant(evaluation_text):
            raise HealthStateContractError("prior snapshot must precede evaluation")
        previous = {item.definition_id: item for item in prior_snapshot.dependencies}
    else:
        previous = {}
    grouped: defaultdict[str, list[ProbeObservation]] = defaultdict(list)
    for observation in observations:
        _same_context(context, observation.context, "observation")
        definition = by_id.get(observation.definition_id)
        if definition is None:
            raise HealthStateContractError(
                "observation references an unknown definition"
            )
        if (
            observation.definition_sha256 != definition.definition_sha256
            or observation.probe_ref != definition.probe_ref
            or observation.probe_version != definition.probe_version
        ):
            raise HealthStateContractError(
                "observation and definition bindings disagree"
            )
        grouped[observation.definition_id].append(observation)

    evaluated = _instant(evaluation_text)
    dependencies: list[DependencyHealth] = []
    pause_causes: set[str] = set()
    for definition in sorted(definitions, key=lambda item: item.dependency_ref):
        candidates = grouped[definition.definition_id]
        reasons: set[str] = set()
        future = [
            item
            for item in candidates
            if _instant(item.collected_at) > evaluated
            or _instant(item.observed_at) > evaluated
        ]
        usable = [item for item in candidates if item not in future]
        if future:
            reasons.add(PauseCause.FUTURE_OBSERVATION.value)
        selected = None
        conflict = False
        if usable:
            highest_sequence = max(item.sequence for item in usable)
            latest = [item for item in usable if item.sequence == highest_sequence]
            if len({item.observation_sha256 for item in latest}) > 1:
                conflict = True
                reasons.add(PauseCause.CONFLICTING_OBSERVATION.value)
            else:
                selected = latest[0]
        stale = selected is not None and (
            evaluated - _instant(selected.observed_at)
        ).total_seconds() > definition.max_age_seconds
        prior = previous.get(definition.definition_id)
        success_streak = 0
        failure_streak = 0
        if conflict or selected is None or stale:
            state = HealthState.UNKNOWN
            if selected is None and not future:
                reasons.add("missing_observation")
            if stale:
                reasons.add("stale_observation")
        elif selected.status is ObservationStatus.PASS:
            success_streak = (prior.success_streak if prior else 0) + 1
            if (
                (prior is None or prior.state is not HealthState.HEALTHY)
                and success_streak < definition.recovery_threshold
            ):
                state = HealthState.RECOVERING
                reasons.add("recovery_threshold_not_met")
            else:
                state = HealthState.HEALTHY
        elif selected.status is ObservationStatus.FAIL:
            failure_streak = (prior.failure_streak if prior else 0) + 1
            state = (
                HealthState.UNHEALTHY
                if failure_streak >= definition.failure_threshold
                else HealthState.DEGRADED
            )
            reasons.add(
                "failure_threshold_met"
                if state is HealthState.UNHEALTHY
                else "failure_threshold_not_met"
            )
        else:
            state = HealthState.UNKNOWN
            reasons.add("observation_unknown")
        if definition.required and state is HealthState.UNKNOWN:
            if stale:
                pause_causes.add(PauseCause.STALE_REQUIRED_OBSERVATION.value)
            elif conflict:
                pause_causes.add(PauseCause.CONFLICTING_OBSERVATION.value)
            else:
                pause_causes.add(PauseCause.MISSING_REQUIRED_OBSERVATION.value)
            if future:
                pause_causes.add(PauseCause.FUTURE_OBSERVATION.value)
        elif definition.required and state is HealthState.RECOVERING:
            pause_causes.add(PauseCause.REQUIRED_DEPENDENCY_RECOVERING.value)
        elif definition.required and state in {
            HealthState.UNHEALTHY,
            HealthState.DEGRADED,
        }:
            pause_causes.add(PauseCause.REQUIRED_DEPENDENCY_UNHEALTHY.value)
        dependencies.append(
            DependencyHealth(
                definition_id=definition.definition_id,
                definition_sha256=definition.definition_sha256,
                dependency_ref=definition.dependency_ref,
                required=definition.required,
                state=state,
                success_streak=success_streak,
                failure_streak=failure_streak,
                selected_observation_id=(
                    selected.observation_id if selected and not conflict else None
                ),
                selected_observation_sha256=(
                    selected.observation_sha256 if selected and not conflict else None
                ),
                reason_codes=tuple(sorted(reasons)),
            )
        )
    states = {item.state for item in dependencies}
    required_states = {item.state for item in dependencies if item.required}
    if HealthState.UNKNOWN in required_states:
        overall = HealthState.UNKNOWN
    elif HealthState.UNHEALTHY in required_states:
        overall = HealthState.UNHEALTHY
    elif required_states & {HealthState.DEGRADED, HealthState.RECOVERING}:
        overall = HealthState.DEGRADED
    elif states == {HealthState.HEALTHY}:
        overall = HealthState.HEALTHY
    else:
        overall = HealthState.DEGRADED
        pause_causes.add("optional_dependency_not_healthy")
    return HealthSnapshot(
        context=context,
        evaluated_at=evaluated_at,
        state=overall,
        dependencies=tuple(dependencies),
        pause_causes=tuple(sorted(pause_causes)),
        prior_snapshot_id=prior_snapshot.snapshot_id if prior_snapshot else None,
        prior_snapshot_sha256=prior_snapshot.snapshot_sha256 if prior_snapshot else None,
    )


def evaluate_execution_recovery_admission(
    snapshots: Sequence[HealthSnapshot],
    *,
    evaluated_at: str,
    max_snapshot_age_seconds: int,
    required_consecutive_healthy_snapshots: int,
) -> ExecutionRecoveryAdmission:
    """Evaluate recovery eligibility while granting no authority or effects."""

    items = tuple(snapshots)
    if not 1 <= len(items) <= MAX_ITEMS or not all(
        isinstance(item, HealthSnapshot) for item in items
    ):
        raise HealthStateContractError(
            "snapshots must be a bounded non-empty sequence"
        )
    _positive(max_snapshot_age_seconds, "max_snapshot_age_seconds", 604_800)
    _positive(
        required_consecutive_healthy_snapshots,
        "required_consecutive_healthy_snapshots",
        MAX_ITEMS,
    )
    context = items[0].context
    for item in items:
        _same_context(context, item.context, "snapshot")
    ordered = tuple(sorted(items, key=lambda item: item.evaluated_at))
    if len({item.snapshot_id for item in ordered}) != len(ordered):
        raise HealthStateContractError("snapshots contain duplicates")
    evaluation = _instant(_time(evaluated_at, "evaluated_at"))
    blockers: set[str] = set()
    if any(_instant(item.evaluated_at) > evaluation for item in ordered):
        blockers.add("future_snapshot")
    if (
        evaluation - _instant(ordered[-1].evaluated_at)
    ).total_seconds() > max_snapshot_age_seconds:
        blockers.add("latest_snapshot_stale")
    if len(ordered) < required_consecutive_healthy_snapshots:
        blockers.add("insufficient_snapshot_history")
    window = ordered[-required_consecutive_healthy_snapshots:]
    if any(
        item.state is not HealthState.HEALTHY or item.pause_causes for item in window
    ):
        blockers.add("healthy_sequence_not_met")
    for earlier, later in zip(ordered, ordered[1:], strict=False):
        if (
            later.prior_snapshot_id != earlier.snapshot_id
            or later.prior_snapshot_sha256 != earlier.snapshot_sha256
        ):
            blockers.add("snapshot_chain_discontinuous")
    definition_sets = [
        {item.definition_id for item in snapshot.dependencies} for snapshot in window
    ]
    if any(value != definition_sets[0] for value in definition_sets[1:]):
        blockers.add("dependency_set_changed")
    status = (
        RecoveryAdmissionStatus.ELIGIBLE_FOR_SEPARATE_AUTHORIZATION
        if not blockers
        else RecoveryAdmissionStatus.DENIED
    )
    return ExecutionRecoveryAdmission(
        context=context,
        snapshot_bindings=tuple(
            (item.snapshot_id, item.snapshot_sha256) for item in ordered
        ),
        evaluated_at=evaluated_at,
        max_snapshot_age_seconds=max_snapshot_age_seconds,
        required_consecutive_healthy_snapshots=required_consecutive_healthy_snapshots,
        status=status,
        blocker_codes=tuple(sorted(blockers)),
        authorization_effect="none",
    )


CONTRACT_TYPES: Mapping[str, type[Any]] = MappingProxyType(
    {
        ProbeDefinition.KIND: ProbeDefinition,
        ProbeObservation.KIND: ProbeObservation,
        HealthSnapshot.KIND: HealthSnapshot,
        ExecutionRecoveryAdmission.KIND: ExecutionRecoveryAdmission,
    }
)


def parse_contract(raw: Mapping[str, Any] | str) -> Any:
    """Parse one closed, content-addressed health-state contract."""

    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise HealthStateContractError("contract JSON is invalid") from exc
    if not isinstance(raw, Mapping):
        raise HealthStateContractError("contract must be an object")
    contract_type = CONTRACT_TYPES.get(raw.get("kind"))
    if contract_type is None:
        raise HealthStateContractError("contract kind is unsupported")
    return contract_type.from_dict(raw)
