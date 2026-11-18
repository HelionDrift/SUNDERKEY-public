"""Deterministic high-availability coordination contracts with no runtime effects.

Callers provide all identity, version, time, quorum, lease, and recovery evidence.
This module does not implement consensus, read a clock, persist state, fence a
process, dispatch work, authorize an action, or qualify a deployment.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "clock": "caller_supplied",
        "consensus": "none",
        "dispatch": "none",
        "failover": "none",
        "fencing": "none",
        "network": "none",
        "persistence": "none",
        "processes": "none",
        "qualification": "none",
        "threads": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
REGION_RE = re.compile(r"[a-z][a-z0-9-]{1,62}\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|serviceref|clusterref|memberref|observerref|resourceref|"
    r"leaseref|evidenceref|recoveryref|scoperef|missionref|authorityref|"
    r"operationref|grantref|requirementref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)


class HACoordinationContractError(ValueError):
    """Raised when a high-availability coordination record fails closed."""


class MemberRole(StrEnum):
    VOTER = "voter"
    WITNESS = "witness"
    LEARNER = "learner"


class MemberState(StrEnum):
    ACTIVE = "active"
    DRAINING = "draining"
    REMOVED = "removed"


class FailoverReason(StrEnum):
    LEASE_EXPIRED = "lease_expired"
    EXPLICIT_RELINQUISHMENT = "explicit_relinquishment"
    MEMBER_UNAVAILABLE = "member_unavailable"
    INTEGRITY_FAILURE = "integrity_failure"


class SplitBrainStatus(StrEnum):
    CLEAR = "clear"
    AMBIGUOUS = "ambiguous"
    CONFLICTING_LEADERS = "conflicting_leaders"
    INSUFFICIENT_QUORUM = "insufficient_quorum"
    STALE_EPOCH = "stale_epoch"


class DegradedMode(StrEnum):
    READ_ONLY = "read_only"
    CONTROL_PLANE_ONLY = "control_plane_only"
    STOP_ONLY = "stop_only"


class WriteOperation(StrEnum):
    METADATA_WRITE = "metadata_write"
    SCHEDULER_CLAIM = "scheduler_claim"
    OUTBOX_CLAIM = "outbox_claim"
    CONTROL_PLANE_WRITE = "control_plane_write"
    TARGET_ACTION_DISPATCH = "target_action_dispatch"


class AdmissionStatus(StrEnum):
    DENIED = "denied"
    ELIGIBLE_FOR_SEPARATE_AUTHORIZATION = "eligible_for_separate_authorization"


class FailoverObservationStatus(StrEnum):
    REJECTED = "rejected"
    EVIDENCE_COMPLETE_UNQUALIFIED = "evidence_complete_unqualified"


class RecoveryEvidenceKind(StrEnum):
    MEMBER_HEALTH = "member_health"
    QUORUM_CONTINUITY = "quorum_continuity"
    LEADER_EPOCH_CONTINUITY = "leader_epoch_continuity"
    FENCING_CONTINUITY = "fencing_continuity"
    DURABLE_STATE_RECONCILIATION = "durable_state_reconciliation"
    MISSION_STOP_RECONCILIATION = "mission_stop_reconciliation"
    EXECUTION_SESSION_RECONCILIATION = "execution_session_reconciliation"
    OUTBOX_RECONCILIATION = "outbox_reconciliation"
    SCHEDULER_RECONCILIATION = "scheduler_reconciliation"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    _validate_json(value, "value")
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 12:
        raise HACoordinationContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 10_000:
            raise HACoordinationContractError(f"{label} exceeds the item limit")
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise HACoordinationContractError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise HACoordinationContractError(f"{label} contains an unsupported value")


def _exact(raw: Mapping[str, Any], fields: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise HACoordinationContractError(f"{label} fields are invalid")


def _ref(value: Any, label: str, namespace: str) -> str:
    if (
        not isinstance(value, str)
        or REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise HACoordinationContractError(f"{label} must be a {namespace} reference")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise HACoordinationContractError(f"{label} must be a SHA-256 content address")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise HACoordinationContractError(f"{label} must be an exact numeric version")
    return value


def _positive(value: Any, label: str, maximum: int = 2_147_483_647) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise HACoordinationContractError(f"{label} must be between 1 and {maximum}")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HACoordinationContractError(f"{label} must be a non-negative integer")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise HACoordinationContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise HACoordinationContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _enum(value: Any, enum_type: type[StrEnum], label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise HACoordinationContractError(f"{label} is invalid") from exc


def _codes(values: Sequence[str], label: str = "blocker_codes") -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise HACoordinationContractError(f"{label} must be a sequence")
    result = tuple(sorted(values))
    if any(not isinstance(item, str) or CODE_RE.fullmatch(item) is None for item in result):
        raise HACoordinationContractError(f"{label} contains an invalid value")
    if len(result) != len(set(result)):
        raise HACoordinationContractError(f"{label} must contain unique values")
    return result


def _refs(
    values: Sequence[str], label: str, namespace: str, *, minimum: int = 1
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise HACoordinationContractError(f"{label} must be a sequence")
    result = tuple(sorted(_ref(item, f"{label} item", namespace) for item in values))
    if len(result) < minimum or len(result) != len(set(result)):
        raise HACoordinationContractError(f"{label} has invalid cardinality")
    return result


def _metadata(raw: Mapping[str, Any], kind: str) -> None:
    if raw.get("kind") != kind or raw.get("schema_version") != SCHEMA_VERSION:
        raise HACoordinationContractError("contract metadata is invalid")
    if raw.get("effects") != dict(NO_EFFECTS):
        raise HACoordinationContractError("contract attempts effect escalation")


def _addressed(instance: Any, id_name: str, hash_name: str) -> dict[str, Any]:
    return {
        **instance._body(),  # noqa: SLF001
        id_name: getattr(instance, id_name),
        hash_name: getattr(instance, hash_name),
    }


def _verify(raw: Mapping[str, Any], candidate: Any) -> Any:
    if dict(raw) != candidate.to_dict():
        raise HACoordinationContractError("record identity or contents are invalid")
    return candidate


def _load(raw: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise HACoordinationContractError("contract JSON is invalid") from exc
    if not isinstance(value, Mapping) or canonical_json(value) != raw:
        raise HACoordinationContractError("contract JSON must be canonical")
    return value


def _same_cluster(*records: Any) -> None:
    bindings = {(record.tenant_ref, record.service_ref, record.cluster_ref) for record in records}
    if len(bindings) != 1:
        raise HACoordinationContractError("cluster identity binding does not match")


def _same_versions(*records: Any) -> None:
    versions = {(record.service_version, record.cluster_version) for record in records}
    if len(versions) != 1:
        raise HACoordinationContractError("expected service or cluster version does not match")


def _data_field_names(record_type: type[Any]) -> set[str]:
    return {item.name for item in fields(record_type)}


def _init_values(record_type: type[Any], raw: Mapping[str, Any]) -> dict[str, Any]:
    return {item.name: raw[item.name] for item in fields(record_type) if item.init}


class _JsonRecord:
    def to_json(self) -> str:
        return canonical_json(self.to_dict())  # type: ignore[attr-defined]


@dataclass(frozen=True, slots=True)
class ClusterMemberDeclaration(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    member_ref: str
    service_version: str
    cluster_version: str
    declaration_version: int
    role: MemberRole | str
    state: MemberState | str
    region: str
    eligible_for_leadership: bool
    declared_at: str
    declaration_id: str = field(init=False)
    declaration_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-cluster-member-declaration.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
            ("member_ref", "memberref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        _positive(self.declaration_version, "declaration_version")
        object.__setattr__(self, "role", _enum(self.role, MemberRole, "role"))
        object.__setattr__(self, "state", _enum(self.state, MemberState, "state"))
        if not isinstance(self.region, str) or REGION_RE.fullmatch(self.region) is None:
            raise HACoordinationContractError("region is invalid")
        if not isinstance(self.eligible_for_leadership, bool):
            raise HACoordinationContractError("eligible_for_leadership must be boolean")
        if self.eligible_for_leadership and (
            self.role is not MemberRole.VOTER or self.state is not MemberState.ACTIVE
        ):
            raise HACoordinationContractError("only an active voter may be leader eligible")
        object.__setattr__(self, "declared_at", _time(self.declared_at, "declared_at"))
        identifier, digest = _identity("HMD", self.KIND, self._body())
        object.__setattr__(self, "declaration_id", identifier)
        object.__setattr__(self, "declaration_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "declaration_version": self.declaration_version,
            "declared_at": self.declared_at,
            "effects": dict(NO_EFFECTS),
            "eligible_for_leadership": self.eligible_for_leadership,
            "kind": self.KIND,
            "member_ref": self.member_ref,
            "region": self.region,
            "role": self.role.value,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "state": self.state.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "declaration_id", "declaration_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ClusterMemberDeclaration:
        _exact(
            raw,
            {
                "cluster_ref",
                "cluster_version",
                "declaration_id",
                "declaration_sha256",
                "declaration_version",
                "declared_at",
                "effects",
                "eligible_for_leadership",
                "kind",
                "member_ref",
                "region",
                "role",
                "schema_version",
                "service_ref",
                "service_version",
                "state",
                "tenant_ref",
            },
            "cluster member declaration",
        )
        _metadata(raw, cls.KIND)
        return _verify(
            raw,
            cls(
                tenant_ref=raw["tenant_ref"],
                service_ref=raw["service_ref"],
                cluster_ref=raw["cluster_ref"],
                member_ref=raw["member_ref"],
                service_version=raw["service_version"],
                cluster_version=raw["cluster_version"],
                declaration_version=raw["declaration_version"],
                role=raw["role"],
                state=raw["state"],
                region=raw["region"],
                eligible_for_leadership=raw["eligible_for_leadership"],
                declared_at=raw["declared_at"],
            ),
        )

    @classmethod
    def from_json(cls, raw: str) -> ClusterMemberDeclaration:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class LeaderEpoch(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    leader_member_ref: str
    leader_declaration_id: str
    leader_declaration_sha256: str
    service_version: str
    cluster_version: str
    epoch: int
    expected_prior_epoch: int
    lease_ref: str
    issued_at: str
    lease_expires_at: str
    maximum_clock_skew_seconds: int
    epoch_id: str = field(init=False)
    epoch_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-leader-epoch.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
            ("leader_member_ref", "memberref"),
            ("lease_ref", "leaseref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        if (
            not isinstance(self.leader_declaration_id, str)
            or re.fullmatch(r"HMD-[0-9A-F]{32}", self.leader_declaration_id) is None
        ):
            raise HACoordinationContractError("leader_declaration_id is invalid")
        object.__setattr__(
            self,
            "leader_declaration_sha256",
            _digest(self.leader_declaration_sha256, "leader_declaration_sha256"),
        )
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        _positive(self.epoch, "epoch")
        _nonnegative(self.expected_prior_epoch, "expected_prior_epoch")
        if self.epoch != self.expected_prior_epoch + 1:
            raise HACoordinationContractError("epoch must advance exactly once")
        object.__setattr__(self, "issued_at", _time(self.issued_at, "issued_at"))
        object.__setattr__(
            self, "lease_expires_at", _time(self.lease_expires_at, "lease_expires_at")
        )
        _positive(self.maximum_clock_skew_seconds, "maximum_clock_skew_seconds", 3600)
        if _instant(self.issued_at) >= _instant(self.lease_expires_at):
            raise HACoordinationContractError("leader lease expiry must follow issuance")
        identifier, digest = _identity("HLE", self.KIND, self._body())
        object.__setattr__(self, "epoch_id", identifier)
        object.__setattr__(self, "epoch_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "effects": dict(NO_EFFECTS),
            "epoch": self.epoch,
            "expected_prior_epoch": self.expected_prior_epoch,
            "issued_at": self.issued_at,
            "kind": self.KIND,
            "leader_declaration_id": self.leader_declaration_id,
            "leader_declaration_sha256": self.leader_declaration_sha256,
            "leader_member_ref": self.leader_member_ref,
            "lease_expires_at": self.lease_expires_at,
            "lease_ref": self.lease_ref,
            "maximum_clock_skew_seconds": self.maximum_clock_skew_seconds,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "epoch_id", "epoch_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> LeaderEpoch:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "leader epoch")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        return _verify(raw, cls(**kwargs))

    @classmethod
    def from_json(cls, raw: str) -> LeaderEpoch:
        return cls.from_dict(_load(raw))


def declare_leader_epoch(
    member: ClusterMemberDeclaration,
    *,
    epoch: int,
    expected_prior_epoch: int,
    lease_ref: str,
    issued_at: str,
    lease_expires_at: str,
    maximum_clock_skew_seconds: int,
) -> LeaderEpoch:
    """Describe a next leader epoch without electing or activating a leader."""

    if member.role is not MemberRole.VOTER or not member.eligible_for_leadership:
        raise HACoordinationContractError("leader must be an active eligible voter")
    return LeaderEpoch(
        tenant_ref=member.tenant_ref,
        service_ref=member.service_ref,
        cluster_ref=member.cluster_ref,
        leader_member_ref=member.member_ref,
        leader_declaration_id=member.declaration_id,
        leader_declaration_sha256=member.declaration_sha256,
        service_version=member.service_version,
        cluster_version=member.cluster_version,
        epoch=epoch,
        expected_prior_epoch=expected_prior_epoch,
        lease_ref=lease_ref,
        issued_at=issued_at,
        lease_expires_at=lease_expires_at,
        maximum_clock_skew_seconds=maximum_clock_skew_seconds,
    )


@dataclass(frozen=True, slots=True)
class QuorumObservation:
    observer_ref: str
    observed_leader_ref: str
    observed_epoch: int
    observed_at: str
    observed_lease_expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "observer_ref", _ref(self.observer_ref, "observer_ref", "observerref")
        )
        object.__setattr__(
            self,
            "observed_leader_ref",
            _ref(self.observed_leader_ref, "observed_leader_ref", "memberref"),
        )
        _positive(self.observed_epoch, "observed_epoch")
        object.__setattr__(self, "observed_at", _time(self.observed_at, "observed_at"))
        object.__setattr__(
            self,
            "observed_lease_expires_at",
            _time(self.observed_lease_expires_at, "observed_lease_expires_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_at": self.observed_at,
            "observed_epoch": self.observed_epoch,
            "observed_leader_ref": self.observed_leader_ref,
            "observed_lease_expires_at": self.observed_lease_expires_at,
            "observer_ref": self.observer_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> QuorumObservation:
        _exact(raw, _data_field_names(cls), "quorum observation")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class QuorumObservationSet(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    service_version: str
    cluster_version: str
    expected_epoch_id: str
    expected_epoch_sha256: str
    voter_member_refs: tuple[str, ...]
    quorum_size: int
    maximum_clock_skew_seconds: int
    evaluated_at: str
    observations: tuple[QuorumObservation, ...]
    observation_set_id: str = field(init=False)
    observation_set_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-quorum-observation-set.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        if (
            not isinstance(self.expected_epoch_id, str)
            or re.fullmatch(r"HLE-[0-9A-F]{32}", self.expected_epoch_id) is None
        ):
            raise HACoordinationContractError("expected_epoch_id is invalid")
        object.__setattr__(
            self,
            "expected_epoch_sha256",
            _digest(self.expected_epoch_sha256, "expected_epoch_sha256"),
        )
        object.__setattr__(
            self,
            "voter_member_refs",
            _refs(self.voter_member_refs, "voter_member_refs", "memberref", minimum=3),
        )
        _positive(self.quorum_size, "quorum_size", len(self.voter_member_refs))
        if self.quorum_size <= len(self.voter_member_refs) // 2:
            raise HACoordinationContractError("quorum_size must be a strict majority")
        _positive(self.maximum_clock_skew_seconds, "maximum_clock_skew_seconds", 3600)
        object.__setattr__(self, "evaluated_at", _time(self.evaluated_at, "evaluated_at"))
        if isinstance(self.observations, (str, bytes)):
            raise HACoordinationContractError("observations must be a sequence")
        parsed = tuple(
            item if isinstance(item, QuorumObservation) else QuorumObservation.from_dict(item)
            for item in self.observations
        )
        if len(parsed) < self.quorum_size:
            raise HACoordinationContractError("observation set does not contain quorum")
        observers = tuple(item.observer_ref for item in parsed)
        if len(observers) != len(set(observers)):
            raise HACoordinationContractError("observers must be distinct")
        expected_observers = {
            f"observerref:{item.removeprefix('memberref:')}" for item in self.voter_member_refs
        }
        if not set(observers).issubset(expected_observers):
            raise HACoordinationContractError("observer is not bound to a voter")
        evaluated = _instant(self.evaluated_at)
        skew = timedelta(seconds=self.maximum_clock_skew_seconds)
        for item in parsed:
            if abs(evaluated - _instant(item.observed_at)) > skew:
                raise HACoordinationContractError("observation exceeds maximum clock skew")
            if _instant(item.observed_at) >= _instant(item.observed_lease_expires_at) + skew:
                raise HACoordinationContractError("observation reports an expired leader lease")
        object.__setattr__(
            self, "observations", tuple(sorted(parsed, key=lambda item: item.observer_ref))
        )
        identifier, digest = _identity("HQO", self.KIND, self._body())
        object.__setattr__(self, "observation_set_id", identifier)
        object.__setattr__(self, "observation_set_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "expected_epoch_id": self.expected_epoch_id,
            "expected_epoch_sha256": self.expected_epoch_sha256,
            "kind": self.KIND,
            "maximum_clock_skew_seconds": self.maximum_clock_skew_seconds,
            "observations": [item.to_dict() for item in self.observations],
            "quorum_size": self.quorum_size,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "tenant_ref": self.tenant_ref,
            "voter_member_refs": list(self.voter_member_refs),
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "observation_set_id", "observation_set_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> QuorumObservationSet:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "quorum observation set")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        kwargs["voter_member_refs"] = tuple(kwargs["voter_member_refs"])
        kwargs["observations"] = tuple(
            QuorumObservation.from_dict(item) for item in kwargs["observations"]
        )
        return _verify(raw, cls(**kwargs))

    @classmethod
    def from_json(cls, raw: str) -> QuorumObservationSet:
        return cls.from_dict(_load(raw))


@dataclass(frozen=True, slots=True)
class SplitBrainAssessment(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    service_version: str
    cluster_version: str
    expected_epoch: int
    quorum_size: int
    observation_set_ids: tuple[str, ...]
    observation_set_sha256s: tuple[str, ...]
    candidate_support: tuple[str, ...]
    status: SplitBrainStatus | str
    blocker_codes: tuple[str, ...]
    assessed_at: str
    assessment_id: str = field(init=False)
    assessment_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-split-brain-assessment.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        _positive(self.expected_epoch, "expected_epoch")
        _positive(self.quorum_size, "quorum_size")
        if not self.observation_set_ids or any(
            not isinstance(item, str) or re.fullmatch(r"HQO-[0-9A-F]{32}", item) is None
            for item in self.observation_set_ids
        ):
            raise HACoordinationContractError("observation_set_ids are invalid")
        if len(self.observation_set_ids) != len(set(self.observation_set_ids)):
            raise HACoordinationContractError("observation_set_ids must be unique")
        if len(self.observation_set_sha256s) != len(self.observation_set_ids):
            raise HACoordinationContractError("observation set hashes are incomplete")
        for value in self.observation_set_sha256s:
            _digest(value, "observation_set_sha256")
        if any(
            not isinstance(item, str) or CODE_RE.fullmatch(item) is None
            for item in self.candidate_support
        ):
            raise HACoordinationContractError("candidate_support is invalid")
        object.__setattr__(self, "status", _enum(self.status, SplitBrainStatus, "status"))
        object.__setattr__(self, "blocker_codes", _codes(self.blocker_codes))
        if (self.status is SplitBrainStatus.CLEAR) != (not self.blocker_codes):
            raise HACoordinationContractError("split-brain status and blockers disagree")
        object.__setattr__(self, "assessed_at", _time(self.assessed_at, "assessed_at"))
        identifier, digest = _identity("HSA", self.KIND, self._body())
        object.__setattr__(self, "assessment_id", identifier)
        object.__setattr__(self, "assessment_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessed_at": self.assessed_at,
            "blocker_codes": list(self.blocker_codes),
            "candidate_support": list(self.candidate_support),
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "effects": dict(NO_EFFECTS),
            "expected_epoch": self.expected_epoch,
            "kind": self.KIND,
            "observation_set_ids": list(self.observation_set_ids),
            "observation_set_sha256s": list(self.observation_set_sha256s),
            "quorum_size": self.quorum_size,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "status": self.status.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "assessment_id", "assessment_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SplitBrainAssessment:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "split-brain assessment")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        for name in (
            "observation_set_ids",
            "observation_set_sha256s",
            "candidate_support",
            "blocker_codes",
        ):
            kwargs[name] = tuple(kwargs[name])
        return _verify(raw, cls(**kwargs))


def assess_split_brain(
    epoch: LeaderEpoch,
    observation_sets: Sequence[QuorumObservationSet],
    *,
    assessed_at: str,
) -> SplitBrainAssessment:
    """Assess caller-supplied observations without performing leader discovery."""

    if not observation_sets:
        raise HACoordinationContractError("at least one observation set is required")
    _time(assessed_at, "assessed_at")
    for item in observation_sets:
        _same_cluster(epoch, item)
        _same_versions(epoch, item)
        if (
            item.expected_epoch_id != epoch.epoch_id
            or item.expected_epoch_sha256 != epoch.epoch_sha256
        ):
            raise HACoordinationContractError("observation set is bound to another leader epoch")
        if item.maximum_clock_skew_seconds != epoch.maximum_clock_skew_seconds:
            raise HACoordinationContractError("observation set clock skew does not match epoch")
        if _instant(item.evaluated_at) > _instant(assessed_at):
            raise HACoordinationContractError("observation set is later than assessment")
    if len({item.quorum_size for item in observation_sets}) != 1:
        raise HACoordinationContractError("observation sets disagree on quorum size")
    quorum_size = observation_sets[0].quorum_size
    latest: dict[str, QuorumObservation] = {}
    observer_conflict = False
    for set_item in observation_sets:
        for observation in set_item.observations:
            prior = latest.get(observation.observer_ref)
            if prior is not None and (
                prior.observed_leader_ref != observation.observed_leader_ref
                or prior.observed_epoch != observation.observed_epoch
            ):
                observer_conflict = True
            if prior is None or _instant(observation.observed_at) > _instant(prior.observed_at):
                latest[observation.observer_ref] = observation
    support = Counter(
        (
            item.observed_leader_ref,
            item.observed_epoch,
            item.observed_lease_expires_at,
        )
        for item in latest.values()
    )
    quorum_candidates = sorted(
        candidate for candidate, count in support.items() if count >= quorum_size
    )
    expected = (epoch.leader_member_ref, epoch.epoch, epoch.lease_expires_at)
    blockers: set[str] = set()
    if _instant(assessed_at) >= _instant(epoch.lease_expires_at) + timedelta(
        seconds=epoch.maximum_clock_skew_seconds
    ):
        status = SplitBrainStatus.STALE_EPOCH
        blockers.add("leader_lease_expired")
    elif observer_conflict:
        status = SplitBrainStatus.AMBIGUOUS
        blockers.add("observer_reports_conflict")
    elif len(quorum_candidates) > 1:
        status = SplitBrainStatus.CONFLICTING_LEADERS
        blockers.add("multiple_quorum_leaders")
    elif not quorum_candidates:
        status = SplitBrainStatus.INSUFFICIENT_QUORUM
        blockers.add("insufficient_quorum")
    elif quorum_candidates[0] != expected:
        status = SplitBrainStatus.CONFLICTING_LEADERS
        blockers.add("unexpected_quorum_leader")
    else:
        status = SplitBrainStatus.CLEAR
    candidate_support = tuple(
        "_".join(
            (
                "candidate",
                str(candidate_epoch),
                str(support[(leader, candidate_epoch, lease_expiry)]),
                canonical_sha256({"leader": leader, "lease_expires_at": lease_expiry})[7:15],
            )
        )
        for leader, candidate_epoch, lease_expiry in sorted(support)
    )
    ordered = tuple(sorted(observation_sets, key=lambda item: item.observation_set_id))
    return SplitBrainAssessment(
        tenant_ref=epoch.tenant_ref,
        service_ref=epoch.service_ref,
        cluster_ref=epoch.cluster_ref,
        service_version=epoch.service_version,
        cluster_version=epoch.cluster_version,
        expected_epoch=epoch.epoch,
        quorum_size=quorum_size,
        observation_set_ids=tuple(item.observation_set_id for item in ordered),
        observation_set_sha256s=tuple(item.observation_set_sha256 for item in ordered),
        candidate_support=candidate_support,
        status=status,
        blocker_codes=tuple(sorted(blockers)),
        assessed_at=assessed_at,
    )


@dataclass(frozen=True, slots=True)
class FencingGrant(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    service_version: str
    cluster_version: str
    resource_ref: str
    granted_to_member_ref: str
    epoch_id: str
    epoch_sha256: str
    observation_set_id: str
    observation_set_sha256: str
    fence_epoch: int
    expected_resource_version: int
    lease_expires_at: str
    granted_at: str
    grant_status: str
    fence_token: str = field(init=False)
    grant_id: str = field(init=False)
    grant_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-fencing-grant.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
            ("resource_ref", "resourceref"),
            ("granted_to_member_ref", "memberref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        for name, prefix in (("epoch_id", "HLE"), ("observation_set_id", "HQO")):
            if (
                not isinstance(getattr(self, name), str)
                or re.fullmatch(rf"{prefix}-[0-9A-F]{{32}}", getattr(self, name)) is None
            ):
                raise HACoordinationContractError(f"{name} is invalid")
        object.__setattr__(self, "epoch_sha256", _digest(self.epoch_sha256, "epoch_sha256"))
        object.__setattr__(
            self,
            "observation_set_sha256",
            _digest(self.observation_set_sha256, "observation_set_sha256"),
        )
        _positive(self.fence_epoch, "fence_epoch")
        _nonnegative(self.expected_resource_version, "expected_resource_version")
        object.__setattr__(
            self, "lease_expires_at", _time(self.lease_expires_at, "lease_expires_at")
        )
        object.__setattr__(self, "granted_at", _time(self.granted_at, "granted_at"))
        if _instant(self.granted_at) >= _instant(self.lease_expires_at):
            raise HACoordinationContractError("fencing grant is already expired")
        if self.grant_status != "eligible_for_external_atomic_commit":
            raise HACoordinationContractError("fencing grant cannot claim a commit")
        token_digest = canonical_sha256(
            {
                "cluster_ref": self.cluster_ref,
                "epoch": self.fence_epoch,
                "member_ref": self.granted_to_member_ref,
                "resource_ref": self.resource_ref,
            }
        )
        object.__setattr__(self, "fence_token", "fence:" + token_digest[7:39])
        identifier, digest = _identity("HFG", self.KIND, self._body())
        object.__setattr__(self, "grant_id", identifier)
        object.__setattr__(self, "grant_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "effects": dict(NO_EFFECTS),
            "epoch_id": self.epoch_id,
            "epoch_sha256": self.epoch_sha256,
            "expected_resource_version": self.expected_resource_version,
            "fence_epoch": self.fence_epoch,
            "fence_token": self.fence_token,
            "grant_status": self.grant_status,
            "granted_at": self.granted_at,
            "granted_to_member_ref": self.granted_to_member_ref,
            "kind": self.KIND,
            "lease_expires_at": self.lease_expires_at,
            "observation_set_id": self.observation_set_id,
            "observation_set_sha256": self.observation_set_sha256,
            "resource_ref": self.resource_ref,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "grant_id", "grant_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> FencingGrant:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "fencing grant")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        return _verify(raw, cls(**kwargs))


def issue_fencing_grant(
    epoch: LeaderEpoch,
    observations: QuorumObservationSet,
    assessment: SplitBrainAssessment,
    *,
    resource_ref: str,
    expected_resource_version: int,
    granted_at: str,
    prior_grant: FencingGrant | None = None,
) -> FencingGrant:
    """Describe a fence eligible for an external atomic commit."""

    _same_cluster(epoch, observations, assessment)
    _same_versions(epoch, observations, assessment)
    if assessment.status is not SplitBrainStatus.CLEAR:
        raise HACoordinationContractError("fencing requires a clear split-brain assessment")
    if observations.observation_set_id not in assessment.observation_set_ids:
        raise HACoordinationContractError("assessment does not bind the observation set")
    if _instant(_time(granted_at, "granted_at")) >= _instant(epoch.lease_expires_at):
        raise HACoordinationContractError("expired leader cannot receive a fencing grant")
    support = sum(
        item.observed_leader_ref == epoch.leader_member_ref
        and item.observed_epoch == epoch.epoch
        and item.observed_lease_expires_at == epoch.lease_expires_at
        for item in observations.observations
    )
    if support < observations.quorum_size:
        raise HACoordinationContractError("exact leader epoch lacks quorum support")
    if prior_grant is not None:
        _same_cluster(epoch, prior_grant)
        if prior_grant.resource_ref != resource_ref:
            raise HACoordinationContractError("prior fence is bound to another resource")
        if epoch.epoch <= prior_grant.fence_epoch:
            raise HACoordinationContractError("stale leader epoch cannot supersede a fence")
        if expected_resource_version < prior_grant.expected_resource_version:
            raise HACoordinationContractError("resource version cannot move backward")
    return FencingGrant(
        tenant_ref=epoch.tenant_ref,
        service_ref=epoch.service_ref,
        cluster_ref=epoch.cluster_ref,
        service_version=epoch.service_version,
        cluster_version=epoch.cluster_version,
        resource_ref=resource_ref,
        granted_to_member_ref=epoch.leader_member_ref,
        epoch_id=epoch.epoch_id,
        epoch_sha256=epoch.epoch_sha256,
        observation_set_id=observations.observation_set_id,
        observation_set_sha256=observations.observation_set_sha256,
        fence_epoch=epoch.epoch,
        expected_resource_version=expected_resource_version,
        lease_expires_at=epoch.lease_expires_at,
        granted_at=granted_at,
        grant_status="eligible_for_external_atomic_commit",
    )


@dataclass(frozen=True, slots=True)
class FailoverPlan(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    service_version: str
    cluster_version: str
    prior_epoch_id: str
    prior_epoch_sha256: str
    prior_epoch: int
    proposed_leader_ref: str
    proposed_leader_declaration_id: str
    proposed_leader_declaration_sha256: str
    required_next_epoch: int
    reason: FailoverReason | str
    quorum_size: int
    resource_ref: str
    expected_resource_version: int
    planned_at: str
    plan_status: str
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-failover-plan.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
            ("proposed_leader_ref", "memberref"),
            ("resource_ref", "resourceref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        for name, prefix in (("prior_epoch_id", "HLE"), ("proposed_leader_declaration_id", "HMD")):
            if (
                not isinstance(getattr(self, name), str)
                or re.fullmatch(rf"{prefix}-[0-9A-F]{{32}}", getattr(self, name)) is None
            ):
                raise HACoordinationContractError(f"{name} is invalid")
        object.__setattr__(
            self, "prior_epoch_sha256", _digest(self.prior_epoch_sha256, "prior_epoch_sha256")
        )
        object.__setattr__(
            self,
            "proposed_leader_declaration_sha256",
            _digest(self.proposed_leader_declaration_sha256, "proposed_leader_declaration_sha256"),
        )
        _positive(self.prior_epoch, "prior_epoch")
        _positive(self.required_next_epoch, "required_next_epoch")
        if self.required_next_epoch != self.prior_epoch + 1:
            raise HACoordinationContractError("failover must require the next epoch")
        object.__setattr__(self, "reason", _enum(self.reason, FailoverReason, "reason"))
        _positive(self.quorum_size, "quorum_size")
        _nonnegative(self.expected_resource_version, "expected_resource_version")
        object.__setattr__(self, "planned_at", _time(self.planned_at, "planned_at"))
        if self.plan_status != "planned_only":
            raise HACoordinationContractError("failover plan cannot claim execution")
        identifier, digest = _identity("HFP", self.KIND, self._body())
        object.__setattr__(self, "plan_id", identifier)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "effects": dict(NO_EFFECTS),
            "expected_resource_version": self.expected_resource_version,
            "kind": self.KIND,
            "plan_status": self.plan_status,
            "planned_at": self.planned_at,
            "prior_epoch": self.prior_epoch,
            "prior_epoch_id": self.prior_epoch_id,
            "prior_epoch_sha256": self.prior_epoch_sha256,
            "proposed_leader_declaration_id": self.proposed_leader_declaration_id,
            "proposed_leader_declaration_sha256": self.proposed_leader_declaration_sha256,
            "proposed_leader_ref": self.proposed_leader_ref,
            "quorum_size": self.quorum_size,
            "reason": self.reason.value,
            "required_next_epoch": self.required_next_epoch,
            "resource_ref": self.resource_ref,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "plan_id", "plan_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> FailoverPlan:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "failover plan")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        return _verify(raw, cls(**kwargs))


def plan_failover(
    prior_epoch: LeaderEpoch,
    proposed_leader: ClusterMemberDeclaration,
    *,
    reason: FailoverReason | str,
    quorum_size: int,
    resource_ref: str,
    expected_resource_version: int,
    planned_at: str,
) -> FailoverPlan:
    _same_cluster(prior_epoch, proposed_leader)
    _same_versions(prior_epoch, proposed_leader)
    reason_value = _enum(reason, FailoverReason, "reason")
    planned_instant = _instant(_time(planned_at, "planned_at"))
    if proposed_leader.member_ref == prior_epoch.leader_member_ref:
        raise HACoordinationContractError("failover successor must be a different member")
    if not proposed_leader.eligible_for_leadership:
        raise HACoordinationContractError("failover successor is not eligible for leadership")
    if reason_value is FailoverReason.LEASE_EXPIRED and planned_instant < _instant(
        prior_epoch.lease_expires_at
    ) + timedelta(seconds=prior_epoch.maximum_clock_skew_seconds):
        raise HACoordinationContractError("lease-expiry failover precedes the skew boundary")
    return FailoverPlan(
        tenant_ref=prior_epoch.tenant_ref,
        service_ref=prior_epoch.service_ref,
        cluster_ref=prior_epoch.cluster_ref,
        service_version=prior_epoch.service_version,
        cluster_version=prior_epoch.cluster_version,
        prior_epoch_id=prior_epoch.epoch_id,
        prior_epoch_sha256=prior_epoch.epoch_sha256,
        prior_epoch=prior_epoch.epoch,
        proposed_leader_ref=proposed_leader.member_ref,
        proposed_leader_declaration_id=proposed_leader.declaration_id,
        proposed_leader_declaration_sha256=proposed_leader.declaration_sha256,
        required_next_epoch=prior_epoch.epoch + 1,
        reason=reason_value,
        quorum_size=quorum_size,
        resource_ref=resource_ref,
        expected_resource_version=expected_resource_version,
        planned_at=planned_at,
        plan_status="planned_only",
    )


@dataclass(frozen=True, slots=True)
class RecoveryEvidenceRequirements(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    service_version: str
    cluster_version: str
    requirement_ref: str
    requirement_version: str
    required_evidence_kinds: tuple[RecoveryEvidenceKind | str, ...]
    minimum_distinct_observers: int
    requires_mission_stop_reconciliation: bool
    requires_execution_session_reconciliation: bool
    effective_at: str
    requirement_id: str = field(init=False)
    requirement_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-recovery-evidence-requirements.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
            ("requirement_ref", "requirementref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        object.__setattr__(
            self, "requirement_version", _version(self.requirement_version, "requirement_version")
        )
        if isinstance(self.required_evidence_kinds, (str, bytes)):
            raise HACoordinationContractError("required_evidence_kinds must be a sequence")
        try:
            kinds = tuple(
                sorted(
                    {RecoveryEvidenceKind(item) for item in self.required_evidence_kinds}, key=str
                )
            )
        except ValueError as exc:
            raise HACoordinationContractError(
                "required_evidence_kinds contains an invalid value"
            ) from exc
        if len(kinds) != len(self.required_evidence_kinds) or not kinds:
            raise HACoordinationContractError("required_evidence_kinds must be nonempty and unique")
        required = {
            RecoveryEvidenceKind.QUORUM_CONTINUITY,
            RecoveryEvidenceKind.LEADER_EPOCH_CONTINUITY,
            RecoveryEvidenceKind.FENCING_CONTINUITY,
            RecoveryEvidenceKind.DURABLE_STATE_RECONCILIATION,
            RecoveryEvidenceKind.OUTBOX_RECONCILIATION,
            RecoveryEvidenceKind.SCHEDULER_RECONCILIATION,
        }
        if not required.issubset(kinds):
            raise HACoordinationContractError(
                "recovery requirements omit mandatory continuity evidence"
            )
        if (
            self.requires_mission_stop_reconciliation
            and RecoveryEvidenceKind.MISSION_STOP_RECONCILIATION not in kinds
        ):
            raise HACoordinationContractError("mission stop reconciliation evidence is required")
        if (
            self.requires_execution_session_reconciliation
            and RecoveryEvidenceKind.EXECUTION_SESSION_RECONCILIATION not in kinds
        ):
            raise HACoordinationContractError(
                "execution session reconciliation evidence is required"
            )
        object.__setattr__(self, "required_evidence_kinds", kinds)
        _positive(self.minimum_distinct_observers, "minimum_distinct_observers")
        if not isinstance(self.requires_mission_stop_reconciliation, bool) or not isinstance(
            self.requires_execution_session_reconciliation, bool
        ):
            raise HACoordinationContractError("reconciliation requirements must be boolean")
        object.__setattr__(self, "effective_at", _time(self.effective_at, "effective_at"))
        identifier, digest = _identity("HER", self.KIND, self._body())
        object.__setattr__(self, "requirement_id", identifier)
        object.__setattr__(self, "requirement_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "effects": dict(NO_EFFECTS),
            "effective_at": self.effective_at,
            "kind": self.KIND,
            "minimum_distinct_observers": self.minimum_distinct_observers,
            "required_evidence_kinds": [item.value for item in self.required_evidence_kinds],
            "requirement_ref": self.requirement_ref,
            "requirement_version": self.requirement_version,
            "requires_execution_session_reconciliation": (
                self.requires_execution_session_reconciliation
            ),
            "requires_mission_stop_reconciliation": self.requires_mission_stop_reconciliation,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "requirement_id", "requirement_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> RecoveryEvidenceRequirements:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "recovery evidence requirements")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        kwargs["required_evidence_kinds"] = tuple(kwargs["required_evidence_kinds"])
        return _verify(raw, cls(**kwargs))


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    evidence_kind: RecoveryEvidenceKind | str
    evidence_ref: str
    evidence_sha256: str
    observer_ref: str
    observed_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "evidence_kind", _enum(self.evidence_kind, RecoveryEvidenceKind, "evidence_kind")
        )
        object.__setattr__(
            self, "evidence_ref", _ref(self.evidence_ref, "evidence_ref", "evidenceref")
        )
        object.__setattr__(
            self, "evidence_sha256", _digest(self.evidence_sha256, "evidence_sha256")
        )
        object.__setattr__(
            self, "observer_ref", _ref(self.observer_ref, "observer_ref", "observerref")
        )
        object.__setattr__(self, "observed_at", _time(self.observed_at, "observed_at"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_kind": self.evidence_kind.value,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "observed_at": self.observed_at,
            "observer_ref": self.observer_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> RecoveryEvidence:
        _exact(raw, _data_field_names(cls), "recovery evidence")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class FailoverObservation(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    service_version: str
    cluster_version: str
    plan_id: str
    plan_sha256: str
    new_epoch_id: str
    new_epoch_sha256: str
    fencing_grant_id: str
    fencing_grant_sha256: str
    requirement_id: str
    requirement_sha256: str
    evidence: tuple[RecoveryEvidence, ...]
    observed_at: str
    status: FailoverObservationStatus | str
    blocker_codes: tuple[str, ...]
    observation_id: str = field(init=False)
    observation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-failover-observation.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        for name, prefix in (
            ("plan_id", "HFP"),
            ("new_epoch_id", "HLE"),
            ("fencing_grant_id", "HFG"),
            ("requirement_id", "HER"),
        ):
            if (
                not isinstance(getattr(self, name), str)
                or re.fullmatch(rf"{prefix}-[0-9A-F]{{32}}", getattr(self, name)) is None
            ):
                raise HACoordinationContractError(f"{name} is invalid")
        for name in (
            "plan_sha256",
            "new_epoch_sha256",
            "fencing_grant_sha256",
            "requirement_sha256",
        ):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        parsed = tuple(
            item if isinstance(item, RecoveryEvidence) else RecoveryEvidence.from_dict(item)
            for item in self.evidence
        )
        keys = tuple((item.evidence_kind, item.evidence_ref) for item in parsed)
        if not parsed or len(keys) != len(set(keys)):
            raise HACoordinationContractError("recovery evidence must be nonempty and unique")
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(parsed, key=lambda item: (item.evidence_kind.value, item.evidence_ref))),
        )
        object.__setattr__(self, "observed_at", _time(self.observed_at, "observed_at"))
        object.__setattr__(self, "status", _enum(self.status, FailoverObservationStatus, "status"))
        object.__setattr__(self, "blocker_codes", _codes(self.blocker_codes))
        if (self.status is FailoverObservationStatus.EVIDENCE_COMPLETE_UNQUALIFIED) != (
            not self.blocker_codes
        ):
            raise HACoordinationContractError("failover observation status and blockers disagree")
        identifier, digest = _identity("HFO", self.KIND, self._body())
        object.__setattr__(self, "observation_id", identifier)
        object.__setattr__(self, "observation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "blocker_codes": list(self.blocker_codes),
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "effects": dict(NO_EFFECTS),
            "evidence": [item.to_dict() for item in self.evidence],
            "fencing_grant_id": self.fencing_grant_id,
            "fencing_grant_sha256": self.fencing_grant_sha256,
            "kind": self.KIND,
            "new_epoch_id": self.new_epoch_id,
            "new_epoch_sha256": self.new_epoch_sha256,
            "observed_at": self.observed_at,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "requirement_id": self.requirement_id,
            "requirement_sha256": self.requirement_sha256,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "status": self.status.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "observation_id", "observation_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> FailoverObservation:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "failover observation")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        kwargs["evidence"] = tuple(RecoveryEvidence.from_dict(item) for item in kwargs["evidence"])
        kwargs["blocker_codes"] = tuple(kwargs["blocker_codes"])
        return _verify(raw, cls(**kwargs))


def observe_failover(
    plan: FailoverPlan,
    new_epoch: LeaderEpoch,
    grant: FencingGrant,
    requirements: RecoveryEvidenceRequirements,
    evidence: Sequence[RecoveryEvidence],
    *,
    observed_at: str,
) -> FailoverObservation:
    """Reconcile failover evidence without applying or qualifying failover."""

    _same_cluster(plan, new_epoch, grant, requirements)
    _same_versions(plan, new_epoch, grant, requirements)
    blockers: set[str] = set()
    if new_epoch.epoch != plan.required_next_epoch:
        blockers.add("unexpected_leader_epoch")
    if new_epoch.leader_member_ref != plan.proposed_leader_ref:
        blockers.add("unexpected_successor")
    if (
        new_epoch.leader_declaration_id != plan.proposed_leader_declaration_id
        or new_epoch.leader_declaration_sha256 != plan.proposed_leader_declaration_sha256
    ):
        blockers.add("successor_declaration_mismatch")
    if _instant(new_epoch.issued_at) < _instant(plan.planned_at):
        blockers.add("new_epoch_precedes_plan")
    if (
        grant.epoch_id != new_epoch.epoch_id
        or grant.granted_to_member_ref != new_epoch.leader_member_ref
    ):
        blockers.add("fencing_grant_mismatch")
    if grant.expected_resource_version != plan.expected_resource_version:
        blockers.add("resource_version_mismatch")
    if grant.resource_ref != plan.resource_ref:
        blockers.add("resource_binding_mismatch")
    parsed = tuple(evidence)
    kinds = {item.evidence_kind for item in parsed}
    missing = set(requirements.required_evidence_kinds) - kinds
    if missing:
        blockers.add("recovery_evidence_incomplete")
    observers = {item.observer_ref for item in parsed}
    if len(observers) < requirements.minimum_distinct_observers:
        blockers.add("recovery_observers_insufficient")
    _time(observed_at, "observed_at")
    if any(_instant(item.observed_at) > _instant(observed_at) for item in parsed):
        blockers.add("future_recovery_evidence")
    status = (
        FailoverObservationStatus.EVIDENCE_COMPLETE_UNQUALIFIED
        if not blockers
        else FailoverObservationStatus.REJECTED
    )
    return FailoverObservation(
        tenant_ref=plan.tenant_ref,
        service_ref=plan.service_ref,
        cluster_ref=plan.cluster_ref,
        service_version=plan.service_version,
        cluster_version=plan.cluster_version,
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        new_epoch_id=new_epoch.epoch_id,
        new_epoch_sha256=new_epoch.epoch_sha256,
        fencing_grant_id=grant.grant_id,
        fencing_grant_sha256=grant.grant_sha256,
        requirement_id=requirements.requirement_id,
        requirement_sha256=requirements.requirement_sha256,
        evidence=parsed,
        observed_at=observed_at,
        status=status,
        blocker_codes=tuple(sorted(blockers)),
    )


_DEGRADED_OPERATIONS = {
    DegradedMode.READ_ONLY: frozenset(),
    DegradedMode.CONTROL_PLANE_ONLY: frozenset({WriteOperation.CONTROL_PLANE_WRITE}),
    DegradedMode.STOP_ONLY: frozenset(),
}


@dataclass(frozen=True, slots=True)
class DegradedServiceMode(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    service_version: str
    cluster_version: str
    mode: DegradedMode | str
    reason_codes: tuple[str, ...]
    entered_at: str
    expires_at: str
    allowed_write_operations: tuple[WriteOperation | str, ...]
    enforcement_status: str
    mode_id: str = field(init=False)
    mode_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-degraded-service-mode.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        object.__setattr__(self, "mode", _enum(self.mode, DegradedMode, "mode"))
        object.__setattr__(self, "reason_codes", _codes(self.reason_codes, "reason_codes"))
        if not self.reason_codes:
            raise HACoordinationContractError("degraded mode requires a reason")
        object.__setattr__(self, "entered_at", _time(self.entered_at, "entered_at"))
        object.__setattr__(self, "expires_at", _time(self.expires_at, "expires_at"))
        if _instant(self.entered_at) >= _instant(self.expires_at):
            raise HACoordinationContractError("degraded mode expiry must follow entry")
        try:
            operations = tuple(
                sorted({WriteOperation(item) for item in self.allowed_write_operations}, key=str)
            )
        except ValueError as exc:
            raise HACoordinationContractError(
                "allowed_write_operations contains an invalid value"
            ) from exc
        if len(operations) != len(self.allowed_write_operations) or set(operations) != set(
            _DEGRADED_OPERATIONS[self.mode]
        ):
            raise HACoordinationContractError("degraded mode write operations are not fail-closed")
        object.__setattr__(self, "allowed_write_operations", operations)
        if self.enforcement_status != "external_enforcement_required":
            raise HACoordinationContractError("degraded mode cannot claim enforcement")
        identifier, digest = _identity("HDM", self.KIND, self._body())
        object.__setattr__(self, "mode_id", identifier)
        object.__setattr__(self, "mode_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "allowed_write_operations": [item.value for item in self.allowed_write_operations],
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "effects": dict(NO_EFFECTS),
            "enforcement_status": self.enforcement_status,
            "entered_at": self.entered_at,
            "expires_at": self.expires_at,
            "kind": self.KIND,
            "mode": self.mode.value,
            "reason_codes": list(self.reason_codes),
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "mode_id", "mode_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DegradedServiceMode:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "degraded service mode")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        kwargs["reason_codes"] = tuple(kwargs["reason_codes"])
        kwargs["allowed_write_operations"] = tuple(kwargs["allowed_write_operations"])
        return _verify(raw, cls(**kwargs))


@dataclass(frozen=True, slots=True)
class SafeWriteAdmission(_JsonRecord):
    tenant_ref: str
    service_ref: str
    cluster_ref: str
    service_version: str
    cluster_version: str
    operation_ref: str
    operation: WriteOperation | str
    resource_ref: str
    expected_resource_version: int
    epoch_id: str
    epoch_sha256: str
    observation_set_id: str
    observation_set_sha256: str
    assessment_id: str
    assessment_sha256: str
    fencing_grant_id: str
    fencing_grant_sha256: str
    degraded_mode_id: str | None
    degraded_mode_sha256: str | None
    evaluated_at: str
    status: AdmissionStatus | str
    blocker_codes: tuple[str, ...]
    authorization_effect: str
    admission_id: str = field(init=False)
    admission_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.ha-safe-write-admission.v1"

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("service_ref", "serviceref"),
            ("cluster_ref", "clusterref"),
            ("operation_ref", "operationref"),
            ("resource_ref", "resourceref"),
        ):
            object.__setattr__(self, name, _ref(getattr(self, name), name, namespace))
        object.__setattr__(
            self, "service_version", _version(self.service_version, "service_version")
        )
        object.__setattr__(
            self, "cluster_version", _version(self.cluster_version, "cluster_version")
        )
        object.__setattr__(self, "operation", _enum(self.operation, WriteOperation, "operation"))
        _nonnegative(self.expected_resource_version, "expected_resource_version")
        for name, prefix in (
            ("epoch_id", "HLE"),
            ("observation_set_id", "HQO"),
            ("assessment_id", "HSA"),
            ("fencing_grant_id", "HFG"),
        ):
            if (
                not isinstance(getattr(self, name), str)
                or re.fullmatch(rf"{prefix}-[0-9A-F]{{32}}", getattr(self, name)) is None
            ):
                raise HACoordinationContractError(f"{name} is invalid")
        for name in (
            "epoch_sha256",
            "observation_set_sha256",
            "assessment_sha256",
            "fencing_grant_sha256",
        ):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        if (self.degraded_mode_id is None) != (self.degraded_mode_sha256 is None):
            raise HACoordinationContractError("degraded mode binding is incomplete")
        if self.degraded_mode_id is not None:
            if re.fullmatch(r"HDM-[0-9A-F]{32}", self.degraded_mode_id) is None:
                raise HACoordinationContractError("degraded_mode_id is invalid")
            _digest(self.degraded_mode_sha256, "degraded_mode_sha256")
        object.__setattr__(self, "evaluated_at", _time(self.evaluated_at, "evaluated_at"))
        object.__setattr__(self, "status", _enum(self.status, AdmissionStatus, "status"))
        object.__setattr__(self, "blocker_codes", _codes(self.blocker_codes))
        if (self.status is AdmissionStatus.ELIGIBLE_FOR_SEPARATE_AUTHORIZATION) != (
            not self.blocker_codes
        ):
            raise HACoordinationContractError("write admission status and blockers disagree")
        if self.authorization_effect != "none":
            raise HACoordinationContractError("write admission cannot grant authority")
        identifier, digest = _identity("HWA", self.KIND, self._body())
        object.__setattr__(self, "admission_id", identifier)
        object.__setattr__(self, "admission_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            "authorization_effect": self.authorization_effect,
            "blocker_codes": list(self.blocker_codes),
            "cluster_ref": self.cluster_ref,
            "cluster_version": self.cluster_version,
            "degraded_mode_id": self.degraded_mode_id,
            "degraded_mode_sha256": self.degraded_mode_sha256,
            "effects": dict(NO_EFFECTS),
            "epoch_id": self.epoch_id,
            "epoch_sha256": self.epoch_sha256,
            "evaluated_at": self.evaluated_at,
            "expected_resource_version": self.expected_resource_version,
            "fencing_grant_id": self.fencing_grant_id,
            "fencing_grant_sha256": self.fencing_grant_sha256,
            "kind": self.KIND,
            "observation_set_id": self.observation_set_id,
            "observation_set_sha256": self.observation_set_sha256,
            "operation": self.operation.value,
            "operation_ref": self.operation_ref,
            "resource_ref": self.resource_ref,
            "schema_version": SCHEMA_VERSION,
            "service_ref": self.service_ref,
            "service_version": self.service_version,
            "status": self.status.value,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return _addressed(self, "admission_id", "admission_sha256")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SafeWriteAdmission:
        expected_fields = _data_field_names(cls) | {"effects", "kind", "schema_version"}
        _exact(raw, expected_fields, "safe write admission")
        _metadata(raw, cls.KIND)
        kwargs = _init_values(cls, raw)
        kwargs["blocker_codes"] = tuple(kwargs["blocker_codes"])
        return _verify(raw, cls(**kwargs))


def evaluate_safe_write_admission(
    epoch: LeaderEpoch,
    observations: QuorumObservationSet,
    assessment: SplitBrainAssessment,
    grant: FencingGrant,
    *,
    operation_ref: str,
    operation: WriteOperation | str,
    resource_ref: str,
    expected_resource_version: int,
    evaluated_at: str,
    degraded_mode: DegradedServiceMode | None = None,
) -> SafeWriteAdmission:
    """Evaluate write safety while granting no authorization or runtime effect."""

    _same_cluster(epoch, observations, assessment, grant)
    _same_versions(epoch, observations, assessment, grant)
    operation_value = _enum(operation, WriteOperation, "operation")
    evaluated = _instant(_time(evaluated_at, "evaluated_at"))
    blockers: set[str] = set()
    if assessment.status is not SplitBrainStatus.CLEAR:
        blockers.add("leadership_ambiguous")
    if observations.observation_set_id not in assessment.observation_set_ids:
        blockers.add("observation_not_assessed")
    support = sum(
        item.observed_leader_ref == epoch.leader_member_ref
        and item.observed_epoch == epoch.epoch
        and item.observed_lease_expires_at == epoch.lease_expires_at
        for item in observations.observations
    )
    if support < observations.quorum_size:
        blockers.add("insufficient_quorum")
    if evaluated >= _instant(epoch.lease_expires_at) + timedelta(
        seconds=epoch.maximum_clock_skew_seconds
    ):
        blockers.add("leader_lease_expired")
    if grant.epoch_id != epoch.epoch_id or grant.fence_epoch != epoch.epoch:
        blockers.add("stale_fencing_grant")
    if grant.observation_set_id != observations.observation_set_id:
        blockers.add("fencing_observation_mismatch")
    if grant.granted_to_member_ref != epoch.leader_member_ref:
        blockers.add("fencing_leader_mismatch")
    if grant.resource_ref != resource_ref:
        blockers.add("fencing_resource_mismatch")
    if grant.expected_resource_version != expected_resource_version:
        blockers.add("resource_version_mismatch")
    if evaluated >= _instant(grant.lease_expires_at):
        blockers.add("fencing_grant_expired")
    if (
        _instant(epoch.issued_at) > evaluated
        or _instant(observations.evaluated_at) > evaluated
        or _instant(assessment.assessed_at) > evaluated
        or _instant(grant.granted_at) > evaluated
    ):
        blockers.add("future_coordination_evidence")
    mode_id = None
    mode_sha256 = None
    if degraded_mode is not None:
        _same_cluster(epoch, degraded_mode)
        _same_versions(epoch, degraded_mode)
        mode_id = degraded_mode.mode_id
        mode_sha256 = degraded_mode.mode_sha256
        if (
            _instant(degraded_mode.entered_at) <= evaluated < _instant(degraded_mode.expires_at)
            and operation_value not in degraded_mode.allowed_write_operations
        ):
            blockers.add("degraded_mode_denies_operation")
    status = (
        AdmissionStatus.ELIGIBLE_FOR_SEPARATE_AUTHORIZATION
        if not blockers
        else AdmissionStatus.DENIED
    )
    return SafeWriteAdmission(
        tenant_ref=epoch.tenant_ref,
        service_ref=epoch.service_ref,
        cluster_ref=epoch.cluster_ref,
        service_version=epoch.service_version,
        cluster_version=epoch.cluster_version,
        operation_ref=operation_ref,
        operation=operation_value,
        resource_ref=resource_ref,
        expected_resource_version=expected_resource_version,
        epoch_id=epoch.epoch_id,
        epoch_sha256=epoch.epoch_sha256,
        observation_set_id=observations.observation_set_id,
        observation_set_sha256=observations.observation_set_sha256,
        assessment_id=assessment.assessment_id,
        assessment_sha256=assessment.assessment_sha256,
        fencing_grant_id=grant.grant_id,
        fencing_grant_sha256=grant.grant_sha256,
        degraded_mode_id=mode_id,
        degraded_mode_sha256=mode_sha256,
        evaluated_at=evaluated_at,
        status=status,
        blocker_codes=tuple(sorted(blockers)),
        authorization_effect="none",
    )


CONTRACT_TYPES: Mapping[str, type[Any]] = MappingProxyType(
    {
        item.KIND: item
        for item in (
            ClusterMemberDeclaration,
            LeaderEpoch,
            QuorumObservationSet,
            SplitBrainAssessment,
            FencingGrant,
            FailoverPlan,
            RecoveryEvidenceRequirements,
            FailoverObservation,
            DegradedServiceMode,
            SafeWriteAdmission,
        )
    }
)


def parse_contract(raw: Mapping[str, Any] | str) -> Any:
    """Parse one closed, content-addressed coordination contract."""

    value = _load(raw) if isinstance(raw, str) else raw
    if not isinstance(value, Mapping):
        raise HACoordinationContractError("contract must be an object")
    contract_type = CONTRACT_TYPES.get(value.get("kind"))
    if contract_type is None:
        raise HACoordinationContractError("contract kind is unsupported")
    return contract_type.from_dict(value)
