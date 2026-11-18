"""Deterministic, bounded coverage planning with no execution effects.

This module consumes verified scope and immutable attack world contracts. It
only proposes tasks. It does not authorize, qualify, route, deploy, request,
generate payloads, handle credential values, or execute anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Any

from .attack_world_model import (
    AttackWorldModelError,
    AttackWorldSnapshot,
    NodeKind,
    VerificationState,
    detect_evidence_conflicts,
)
from .signed_scope_compiler import (
    SignedAssessmentScope,
    VerifiedAssessmentScope,
)
from .signed_scope_compiler import (
    canonical_sha256 as scope_canonical_sha256,
)
from .types import ActionTier

SCHEMA_VERSION = 1
SCHEDULE_DOMAIN = "sunderkey.coverage-schedule.v1"
TASK_DOMAIN = "sunderkey.coverage-task.v1"
TASK_KEY_DOMAIN = "sunderkey.coverage-task-key.v1"

NO_EFFECTS = {
    "authority": "none",
    "browser": "none",
    "credential_values": "none",
    "deployment": "none",
    "execution": "none",
    "network": "none",
    "payload_generation": "none",
    "qualification": "none",
    "requests": "none",
    "routing": "none",
    "target_authority": "none",
    "tools": "none",
}

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
TASK_ID_RE = re.compile(r"CST-[0-9A-F]{32}\Z")
SCHEDULE_ID_RE = re.compile(r"CSS-[0-9A-F]{32}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"
    r")",
    re.IGNORECASE,
)

HARD_LIMITS = {
    "max_concurrency": 256,
    "max_snapshot_age_seconds": 31 * 24 * 60 * 60,
    "max_tasks": 4096,
    "max_tasks_per_asset": 512,
    "max_total_cost_units": 10_000_000,
    "max_total_requests": 1_000_000,
}


class CoverageSchedulerError(ValueError):
    """Raised when scheduler input or a serialized schedule fails closed."""


class TaskType(StrEnum):
    """Allowed planning-only task categories."""

    CONTEXT_COLLECTION = "context_collection"
    PASSIVE_ANALYSIS = "passive_analysis"
    SAFE_PROBE = "safe_probe"
    VALIDATION = "validation"
    RESTORATION_CHECK = "restoration_check"
    RETEST_PLAN = "retest_plan"


class ValidatorRole(StrEnum):
    """Independent validator roles available to a proposed task."""

    EVIDENCE = "evidence"
    CONTROL = "control"
    ASSURANCE = "assurance"


class OutcomeStatus(StrEnum):
    """Closed set of prior and live task states."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class SchedulingLimits:
    """Explicit deterministic planning bounds supplied by the caller."""

    as_of: str
    max_tasks: int
    max_total_cost_units: int
    max_total_requests: int
    max_concurrency: int
    max_tasks_per_asset: int
    max_snapshot_age_seconds: int
    review_impact_tier: ActionTier | str

    def __post_init__(self) -> None:
        _utc(self.as_of, "limits as_of")
        for name, hard_limit in HARD_LIMITS.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise CoverageSchedulerError(f"limits {name} must be a positive integer")
            if value > hard_limit:
                raise CoverageSchedulerError(f"limits {name} exceeds its hard safety limit")
        try:
            tier = ActionTier(self.review_impact_tier)
        except (TypeError, ValueError) as exc:
            raise CoverageSchedulerError("limits review_impact_tier is invalid") from exc
        object.__setattr__(self, "review_impact_tier", tier)

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "max_concurrency": self.max_concurrency,
            "max_snapshot_age_seconds": self.max_snapshot_age_seconds,
            "max_tasks": self.max_tasks,
            "max_tasks_per_asset": self.max_tasks_per_asset,
            "max_total_cost_units": self.max_total_cost_units,
            "max_total_requests": self.max_total_requests,
            "review_impact_tier": self.review_impact_tier.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SchedulingLimits:
        _exact_fields(raw, set(HARD_LIMITS) | {"as_of", "review_impact_tier"}, "limits")
        return cls(**raw)


@dataclass(frozen=True)
class ValidatorBinding:
    """One immutable validator identity and version binding."""

    role: ValidatorRole | str
    validator_id: str
    version: str

    def __post_init__(self) -> None:
        try:
            role = ValidatorRole(self.role)
        except (TypeError, ValueError) as exc:
            raise CoverageSchedulerError("validator binding role is invalid") from exc
        object.__setattr__(self, "role", role)
        _identifier(self.validator_id, "validator binding validator_id")
        _version(self.version, "validator binding version")

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role.value,
            "validator_id": self.validator_id,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ValidatorBinding:
        _exact_fields(raw, {"role", "validator_id", "version"}, "validator binding")
        return cls(**raw)


@dataclass(frozen=True)
class BlockedReason:
    """A stable reason that a frontier item or task could not be scheduled."""

    code: str
    frontier_id: str | None
    asset_id: str | None
    technique_id: str | None
    detail: str

    def __post_init__(self) -> None:
        _token(self.code, "blocked code")
        for name in ("frontier_id", "asset_id", "technique_id"):
            value = getattr(self, name)
            if value is not None:
                _identifier(value, f"blocked {name}")
        _safe_text(self.detail, "blocked detail", 512)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "code": self.code,
            "detail": self.detail,
            "frontier_id": self.frontier_id,
            "technique_id": self.technique_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> BlockedReason:
        _exact_fields(
            raw,
            {"asset_id", "code", "detail", "frontier_id", "technique_id"},
            "blocked reason",
        )
        return cls(**raw)


@dataclass(frozen=True)
class ProposedCoverageTask:
    """One immutable, content-addressed, planning-only task."""

    task_id: str
    task_sha256: str
    task_key: str
    task_type: TaskType | str
    frontier_id: str
    priority: int
    wave: int
    scope_sha256: str
    world_snapshot_sha256: str
    asset_ids: tuple[str, ...]
    node_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    required_specialist_profile_id: str
    required_commander_id: str
    validators: tuple[ValidatorBinding, ...]
    prerequisite_task_ids: tuple[str, ...]
    estimated_cost_units: int
    estimated_requests: int
    impact_tier: ActionTier | str
    stop_conditions: tuple[str, ...]
    expected_evidence: tuple[str, ...]
    restoration_required: bool
    supersedes_task_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.task_id:
            _task_id(self.task_id, "task_id")
        if self.task_sha256:
            _sha256(self.task_sha256, "task_sha256")
        _sha256(self.task_key, "task_key")
        try:
            task_type = TaskType(self.task_type)
        except (TypeError, ValueError) as exc:
            raise CoverageSchedulerError("task_type is invalid") from exc
        object.__setattr__(self, "task_type", task_type)
        _identifier(self.frontier_id, "frontier_id")
        for name in ("priority", "wave", "estimated_cost_units", "estimated_requests"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise CoverageSchedulerError(f"task {name} must be a non-negative integer")
        _sha256(self.scope_sha256, "task scope_sha256")
        _sha256(self.world_snapshot_sha256, "task world_snapshot_sha256")
        for name in ("asset_ids", "node_ids", "technique_ids"):
            object.__setattr__(self, name, _refs(getattr(self, name), f"task {name}"))
        if not self.asset_ids or not self.node_ids or not self.technique_ids:
            raise CoverageSchedulerError(
                "task asset_ids, node_ids, and technique_ids cannot be empty"
            )
        _identifier(self.required_specialist_profile_id, "required specialist profile ID")
        _identifier(self.required_commander_id, "required commander ID")
        if not isinstance(self.validators, tuple) or not self.validators:
            raise CoverageSchedulerError("task validators must be a non-empty tuple")
        if not all(isinstance(item, ValidatorBinding) for item in self.validators):
            raise CoverageSchedulerError("task validators contain an invalid binding")
        canonical_validators = tuple(
            sorted(
                self.validators, key=lambda item: (item.role.value, item.validator_id, item.version)
            )
        )
        if len({item.role for item in canonical_validators}) != len(canonical_validators):
            raise CoverageSchedulerError("task validator roles must be unique")
        if {item.validator_id for item in canonical_validators} & {
            self.required_specialist_profile_id,
            self.required_commander_id,
        }:
            raise CoverageSchedulerError("task validator cannot be its specialist or commander")
        object.__setattr__(self, "validators", canonical_validators)
        object.__setattr__(
            self,
            "prerequisite_task_ids",
            _task_refs(self.prerequisite_task_ids, "task prerequisite_task_ids"),
        )
        try:
            impact = ActionTier(self.impact_tier)
        except (TypeError, ValueError) as exc:
            raise CoverageSchedulerError("task impact_tier is invalid") from exc
        object.__setattr__(self, "impact_tier", impact)
        object.__setattr__(
            self, "stop_conditions", _text_refs(self.stop_conditions, "task stop_conditions")
        )
        object.__setattr__(
            self, "expected_evidence", _text_refs(self.expected_evidence, "task expected_evidence")
        )
        if not self.stop_conditions or not self.expected_evidence:
            raise CoverageSchedulerError(
                "task stop conditions and expected evidence cannot be empty"
            )
        if not isinstance(self.restoration_required, bool):
            raise CoverageSchedulerError("task restoration_required must be boolean")
        object.__setattr__(
            self,
            "supersedes_task_ids",
            _task_refs(self.supersedes_task_ids, "task supersedes_task_ids"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_task_body(self),
            "task_id": self.task_id,
            "task_sha256": self.task_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ProposedCoverageTask:
        fields = {
            "asset_ids",
            "effects",
            "estimated_cost_units",
            "estimated_requests",
            "expected_evidence",
            "frontier_id",
            "impact_tier",
            "node_ids",
            "prerequisite_task_ids",
            "priority",
            "required_commander_id",
            "required_specialist_profile_id",
            "restoration_required",
            "scope_sha256",
            "stop_conditions",
            "supersedes_task_ids",
            "task_id",
            "task_key",
            "task_sha256",
            "task_type",
            "technique_ids",
            "validators",
            "wave",
            "world_snapshot_sha256",
        }
        _exact_fields(raw, fields, "proposed task")
        if raw["effects"] != NO_EFFECTS:
            raise CoverageSchedulerError("task effects must all be none")
        candidate = cls(
            task_id=raw["task_id"],
            task_sha256=raw["task_sha256"],
            task_key=raw["task_key"],
            task_type=raw["task_type"],
            frontier_id=raw["frontier_id"],
            priority=raw["priority"],
            wave=raw["wave"],
            scope_sha256=raw["scope_sha256"],
            world_snapshot_sha256=raw["world_snapshot_sha256"],
            asset_ids=_tuple_json(raw["asset_ids"], "task asset_ids"),
            node_ids=_tuple_json(raw["node_ids"], "task node_ids"),
            technique_ids=_tuple_json(raw["technique_ids"], "task technique_ids"),
            required_specialist_profile_id=raw["required_specialist_profile_id"],
            required_commander_id=raw["required_commander_id"],
            validators=tuple(ValidatorBinding.from_dict(item) for item in raw["validators"]),
            prerequisite_task_ids=_tuple_json(
                raw["prerequisite_task_ids"], "task prerequisite_task_ids"
            ),
            estimated_cost_units=raw["estimated_cost_units"],
            estimated_requests=raw["estimated_requests"],
            impact_tier=raw["impact_tier"],
            stop_conditions=_tuple_json(raw["stop_conditions"], "task stop_conditions"),
            expected_evidence=_tuple_json(raw["expected_evidence"], "task expected_evidence"),
            restoration_required=raw["restoration_required"],
            supersedes_task_ids=_tuple_json(raw["supersedes_task_ids"], "task supersedes_task_ids"),
        )
        expected = _address_task(replace(candidate, task_id="", task_sha256=""))
        if raw != expected.to_dict():
            raise CoverageSchedulerError("task identity, contents, or ordering is invalid")
        return expected


@dataclass(frozen=True)
class CoverageSchedule:
    """Immutable content-addressed DAG of proposed coverage tasks."""

    schedule_id: str
    schedule_sha256: str
    scope_sha256: str
    world_snapshot_sha256: str
    parent_schedule_sha256: str | None
    supersedes_schedule_id: str | None
    limits: SchedulingLimits
    effective_max_concurrency: int
    tasks: tuple[ProposedCoverageTask, ...]
    accepted_prior_outcome_ids: tuple[str, ...]
    blocked_reasons: tuple[BlockedReason, ...]

    def to_dict(self) -> dict[str, Any]:
        body = _schedule_body(
            scope_sha256=self.scope_sha256,
            world_snapshot_sha256=self.world_snapshot_sha256,
            parent_schedule_sha256=self.parent_schedule_sha256,
            supersedes_schedule_id=self.supersedes_schedule_id,
            limits=self.limits,
            effective_max_concurrency=self.effective_max_concurrency,
            tasks=self.tasks,
            accepted_prior_outcome_ids=self.accepted_prior_outcome_ids,
            blocked_reasons=self.blocked_reasons,
        )
        return {
            **body,
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CoverageSchedule:
        fields = {
            "accepted_prior_outcome_ids",
            "blocked_reasons",
            "budget_summary",
            "effects",
            "effective_max_concurrency",
            "limits",
            "parent_schedule_sha256",
            "schedule_id",
            "schedule_sha256",
            "schema_version",
            "scope_sha256",
            "supersedes_schedule_id",
            "tasks",
            "world_snapshot_sha256",
        }
        _exact_fields(raw, fields, "coverage schedule")
        if raw["schema_version"] != SCHEMA_VERSION:
            raise CoverageSchedulerError("schedule schema_version is invalid")
        if raw["effects"] != NO_EFFECTS:
            raise CoverageSchedulerError("schedule effects must all be none")
        limits = SchedulingLimits.from_dict(raw["limits"])
        candidate = _address_schedule(
            scope_sha256=raw["scope_sha256"],
            world_snapshot_sha256=raw["world_snapshot_sha256"],
            parent_schedule_sha256=raw["parent_schedule_sha256"],
            supersedes_schedule_id=raw["supersedes_schedule_id"],
            limits=limits,
            effective_max_concurrency=raw["effective_max_concurrency"],
            tasks=tuple(ProposedCoverageTask.from_dict(item) for item in raw["tasks"]),
            accepted_prior_outcome_ids=_tuple_json(
                raw["accepted_prior_outcome_ids"], "schedule accepted_prior_outcome_ids"
            ),
            blocked_reasons=tuple(BlockedReason.from_dict(item) for item in raw["blocked_reasons"]),
        )
        if raw != candidate.to_dict():
            raise CoverageSchedulerError(
                "schedule identity, contents, summary, or ordering is invalid"
            )
        return candidate


@dataclass(frozen=True)
class _Capability:
    available: bool
    specialist_profile_id: str
    commander_id: str
    qualified_scope_ids: tuple[str, ...]
    qualified_technique_ids: tuple[str, ...]
    impact_tier: ActionTier
    estimated_cost_units: int
    estimated_requests: int
    stop_conditions: tuple[str, ...]
    expected_evidence: tuple[str, ...]
    restoration_required: bool


@dataclass(frozen=True)
class _Validator:
    validator_id: str
    available: bool
    role: ValidatorRole
    version: str
    qualified_task_types: tuple[TaskType, ...]
    qualified_scope_ids: tuple[str, ...]
    max_impact_tier: ActionTier


@dataclass(frozen=True)
class _Outcome:
    task_id: str
    task_key: str
    status: OutcomeStatus
    world_snapshot_sha256: str
    evidence_digests: tuple[str, ...]


@dataclass(frozen=True)
class _Pipeline:
    frontier_id: str
    frontier_kind: str
    asset_id: str
    node_ids: tuple[str, ...]
    technique_id: str
    priority_base: int


def compute_coverage_schedule(
    scope: VerifiedAssessmentScope,
    world_snapshot: AttackWorldSnapshot,
    capability_availability: Mapping[str, Any],
    validator_availability: Mapping[str, Any],
    prior_task_outcomes: Mapping[str, Any],
    limits: SchedulingLimits,
) -> CoverageSchedule:
    """Derive a bounded, deterministic task DAG without performing any task."""

    return _compute_schedule(
        scope,
        world_snapshot,
        capability_availability,
        validator_availability,
        prior_task_outcomes,
        limits,
        previous_schedule=None,
    )


def replan_coverage_schedule(
    previous_schedule: CoverageSchedule,
    scope: VerifiedAssessmentScope,
    new_world_snapshot: AttackWorldSnapshot,
    capability_availability: Mapping[str, Any],
    validator_availability: Mapping[str, Any],
    prior_task_outcomes: Mapping[str, Any],
    limits: SchedulingLimits,
) -> CoverageSchedule:
    """Plan from an immediate child snapshot and preserve supersession lineage."""

    if not isinstance(previous_schedule, CoverageSchedule):
        raise CoverageSchedulerError("previous_schedule must be a CoverageSchedule")
    CoverageSchedule.from_dict(previous_schedule.to_dict())
    if not isinstance(new_world_snapshot, AttackWorldSnapshot):
        raise CoverageSchedulerError("new_world_snapshot must be an AttackWorldSnapshot")
    if previous_schedule.scope_sha256 != _verified_scope_document(scope)["content_sha256"]:
        raise CoverageSchedulerError("replan scope does not match the previous schedule")
    if new_world_snapshot.snapshot_sha256 == previous_schedule.world_snapshot_sha256:
        raise CoverageSchedulerError("replan requires a new immutable world snapshot")
    if new_world_snapshot.parent_sha256 != previous_schedule.world_snapshot_sha256:
        raise CoverageSchedulerError(
            "new world snapshot does not directly supersede the prior snapshot"
        )
    return _compute_schedule(
        scope,
        new_world_snapshot,
        capability_availability,
        validator_availability,
        prior_task_outcomes,
        limits,
        previous_schedule=previous_schedule,
    )


def select_next_ready_task(
    schedule: CoverageSchedule,
    completion_state: Mapping[str, str | OutcomeStatus],
) -> ProposedCoverageTask | None:
    """Select the next ready task from caller-supplied state without side effects."""

    if not isinstance(schedule, CoverageSchedule):
        raise CoverageSchedulerError("schedule must be a CoverageSchedule")
    CoverageSchedule.from_dict(schedule.to_dict())
    if not isinstance(completion_state, Mapping):
        raise CoverageSchedulerError("completion_state must be a mapping")
    known = {item.task_id for item in schedule.tasks} | set(schedule.accepted_prior_outcome_ids)
    states: dict[str, OutcomeStatus] = {}
    for task_id, raw_status in completion_state.items():
        _task_id(task_id, "completion task ID")
        if task_id not in known:
            raise CoverageSchedulerError("completion_state references an unknown task")
        try:
            status = OutcomeStatus(raw_status)
        except (TypeError, ValueError) as exc:
            raise CoverageSchedulerError("completion_state has an invalid status") from exc
        states[task_id] = status
    accepted = set(schedule.accepted_prior_outcome_ids)
    if any(
        states.get(task_id, OutcomeStatus.SUCCEEDED) is not OutcomeStatus.SUCCEEDED
        for task_id in accepted
    ):
        raise CoverageSchedulerError("completion_state contradicts an accepted prior outcome")
    completed = {
        task_id for task_id, status in states.items() if status is OutcomeStatus.SUCCEEDED
    } | accepted
    if any(
        states.get(task.task_id) in {OutcomeStatus.RUNNING, OutcomeStatus.SUCCEEDED}
        and not set(task.prerequisite_task_ids) <= completed
        for task in schedule.tasks
    ):
        raise CoverageSchedulerError("completion_state violates task prerequisites")
    running = sum(states.get(task.task_id) is OutcomeStatus.RUNNING for task in schedule.tasks)
    if running > schedule.effective_max_concurrency:
        raise CoverageSchedulerError("completion_state exceeds schedule concurrency")
    if running >= schedule.effective_max_concurrency:
        return None
    candidates = [
        task
        for task in schedule.tasks
        if states.get(task.task_id, OutcomeStatus.PENDING) is OutcomeStatus.PENDING
        and set(task.prerequisite_task_ids) <= completed
    ]
    if not candidates:
        return None
    return min(candidates, key=_task_sort_key)


def _compute_schedule(
    scope: VerifiedAssessmentScope,
    snapshot: AttackWorldSnapshot,
    capability_raw: Mapping[str, Any],
    validator_raw: Mapping[str, Any],
    outcome_raw: Mapping[str, Any],
    limits: SchedulingLimits,
    *,
    previous_schedule: CoverageSchedule | None,
) -> CoverageSchedule:
    scope_doc = _verified_scope_document(scope)
    if not isinstance(snapshot, AttackWorldSnapshot):
        raise CoverageSchedulerError("world_snapshot must be an AttackWorldSnapshot")
    try:
        snapshot = AttackWorldSnapshot.from_dict(snapshot.to_dict())
    except AttackWorldModelError as exc:
        raise CoverageSchedulerError(
            "world_snapshot failed immutable identity verification"
        ) from exc
    if not isinstance(limits, SchedulingLimits):
        raise CoverageSchedulerError("limits must be SchedulingLimits")
    capabilities = _parse_capabilities(capability_raw)
    validators = _parse_validators(validator_raw)
    outcomes = _parse_outcomes(outcome_raw)
    scope_id = str(scope_doc["scope_id"])
    scope_hash = str(scope_doc["content_sha256"])
    unexpected_techniques = {
        technique_id
        for _, technique_id in capabilities
        if technique_id is not None and technique_id not in scope_doc["allowed_technique_ids"]
    }
    if unexpected_techniques:
        raise CoverageSchedulerError("capability route names a technique outside scope")
    blocked: list[BlockedReason] = []

    if not _scope_active(scope_doc, limits.as_of):
        blocked.append(
            _blocked("scope_inactive", None, None, None, "Scope is not active at limits as_of.")
        )
        return _finish_schedule(
            scope_hash, snapshot, limits, (), (), blocked, previous_schedule, scope_doc
        )

    evidence_times = [item.evidence.observed_at for item in snapshot.nodes]
    evidence_times.extend(item.evidence.observed_at for item in snapshot.edges)
    if not evidence_times:
        blocked.append(
            _blocked(
                "empty_world_snapshot",
                None,
                None,
                None,
                "World snapshot has no evidence-bearing facts.",
            )
        )
        return _finish_schedule(
            scope_hash, snapshot, limits, (), (), blocked, previous_schedule, scope_doc
        )
    newest = max(_utc(value, "world evidence observed_at") for value in evidence_times)
    age = int((_utc(limits.as_of, "limits as_of") - newest).total_seconds())
    if age < 0:
        blocked.append(
            _blocked(
                "future_world_evidence",
                None,
                None,
                None,
                "World snapshot contains evidence observed after limits as_of.",
            )
        )
        return _finish_schedule(
            scope_hash, snapshot, limits, (), (), blocked, previous_schedule, scope_doc
        )
    if age > limits.max_snapshot_age_seconds:
        blocked.append(
            _blocked(
                "stale_world_snapshot",
                None,
                None,
                None,
                "World snapshot exceeds max_snapshot_age_seconds.",
            )
        )
        return _finish_schedule(
            scope_hash, snapshot, limits, (), (), blocked, previous_schedule, scope_doc
        )

    assets = tuple(
        item
        for item in snapshot.nodes
        if item.node_kind is NodeKind.ASSET and scope_id in item.scope_refs
    )
    mismatched_assets = tuple(
        item.node_id
        for item in snapshot.nodes
        if item.node_kind is NodeKind.ASSET and scope_id not in item.scope_refs
    )
    for asset_id in sorted(mismatched_assets):
        blocked.append(
            _blocked(
                "scope_mismatch",
                None,
                asset_id,
                None,
                "Asset is not bound to the verified scope ID.",
            )
        )
    if not assets:
        blocked.append(
            _blocked(
                "no_in_scope_assets",
                None,
                None,
                None,
                "World snapshot contains no asset bound to the verified scope ID.",
            )
        )
        return _finish_schedule(
            scope_hash, snapshot, limits, (), (), blocked, previous_schedule, scope_doc
        )

    pipelines: list[_Pipeline] = []
    asset_ids = {
        item.node_id for item in snapshot.nodes if item.node_kind is NodeKind.ASSET
    }
    conflicted_fact_ids = {
        fact_id
        for conflict in detect_evidence_conflicts(snapshot, as_of=limits.as_of)
        for fact_id in conflict.fact_ids
    }
    for asset in assets:
        for technique_id in scope_doc["allowed_technique_ids"]:
            related = tuple(
                edge
                for edge in snapshot.edges
                if scope_id in edge.scope_refs
                and technique_id in edge.technique_refs
                and (
                    edge.target_node_id == asset.node_id
                    or (
                        edge.source_node_id == asset.node_id
                        and edge.target_node_id not in asset_ids
                    )
                )
            )
            active = tuple(edge for edge in related if edge.evidence.is_active(limits.as_of))
            states = {edge.evidence.verification_state for edge in active}
            has_conflict = any(edge.fact_id in conflicted_fact_ids for edge in active)
            if VerificationState.VERIFIED in states and not has_conflict:
                continue
            if has_conflict:
                kind = "evidence_conflict_requires_review"
            elif VerificationState.HYPOTHESIS in states:
                kind = "hypothesis_requires_verification"
            elif VerificationState.NEGATIVE in states:
                kind = "negative_evidence_requires_review"
            else:
                kind = "missing_technique_evidence"
            priority_base = {
                "missing_technique_evidence": 10,
                "negative_evidence_requires_review": 40,
                "hypothesis_requires_verification": 60,
                "evidence_conflict_requires_review": 80,
            }[kind]
            if any(
                edge.evidence.verification_state is VerificationState.HYPOTHESIS
                and edge.evidence.is_stale(limits.as_of)
                for edge in related
            ):
                priority_base += 80
            if asset.evidence.is_stale(limits.as_of):
                priority_base += 30
            node_ids = {asset.node_id}
            for edge in related:
                node_ids.update((edge.source_node_id, edge.target_node_id))
            frontier_digest = _digest(
                {
                    "asset_id": asset.node_id,
                    "kind": kind,
                    "scope_id": scope_id,
                    "technique_id": technique_id,
                    "fact_ids": sorted(edge.fact_id for edge in related),
                }
            )
            pipelines.append(
                _Pipeline(
                    frontier_id=f"CFI-{frontier_digest[7:39].upper()}",
                    frontier_kind=kind,
                    asset_id=asset.node_id,
                    node_ids=tuple(sorted(node_ids)),
                    technique_id=technique_id,
                    priority_base=priority_base,
                )
            )
    pipelines.sort(key=lambda item: (item.asset_id, item.technique_id, item.frontier_id))

    task_types = tuple(TaskType)
    previous_by_semantic: dict[tuple[Any, ...], str] = {}
    if previous_schedule is not None:
        for old in previous_schedule.tasks:
            previous_by_semantic[_semantic_task_key(old)] = old.task_id
    completed_by_key = {
        item.task_key: item
        for item in outcomes.values()
        if item.status is OutcomeStatus.SUCCEEDED
        and item.world_snapshot_sha256 == snapshot.snapshot_sha256
    }
    accepted_prior: set[str] = set()
    scheduled: list[ProposedCoverageTask] = []
    seen_task_keys: set[str] = set()
    last_task: dict[tuple[str, str], str] = {}
    pipeline_open = {(item.asset_id, item.technique_id): True for item in pipelines}
    tasks_per_asset = {item.asset_id: 0 for item in pipelines}
    total_cost = 0
    total_requests = 0
    budget_stopped: set[tuple[str, str]] = set()
    scope_budgets = scope_doc["budgets"]
    effective_request_limit = min(limits.max_total_requests, scope_budgets["max_requests"])

    for stage_index, task_type in enumerate(task_types):
        for pipeline in pipelines:
            pipeline_key = (pipeline.asset_id, pipeline.technique_id)
            if not pipeline_open[pipeline_key]:
                continue
            if pipeline.frontier_kind in {
                "negative_evidence_requires_review",
                "evidence_conflict_requires_review",
            } and task_type in {TaskType.SAFE_PROBE, TaskType.RESTORATION_CHECK}:
                blocked.append(
                    _blocked(
                        (
                            "active_evidence_conflict"
                            if pipeline.frontier_kind == "evidence_conflict_requires_review"
                            else "active_negative_evidence"
                        ),
                        pipeline.frontier_id,
                        pipeline.asset_id,
                        pipeline.technique_id,
                        "Active negative or conflicting evidence suppresses probe and "
                        "restoration proposals.",
                    )
                )
                continue
            capability = capabilities.get((task_type, pipeline.technique_id))
            if capability is None:
                capability = capabilities.get((task_type, None))
            reason = _capability_block(
                capability,
                scope_id,
                pipeline.technique_id,
                ActionTier(scope_doc["impact_tier_ceiling"]),
            )
            if reason is not None:
                blocked.append(
                    _blocked(
                        reason,
                        pipeline.frontier_id,
                        pipeline.asset_id,
                        pipeline.technique_id,
                        f"Required {task_type.value} capability is unavailable or unqualified.",
                    )
                )
                pipeline_open[pipeline_key] = False
                continue
            assert capability is not None
            validator_bindings = _select_validators(
                validators,
                task_type,
                scope_id,
                capability.impact_tier,
                limits.review_impact_tier,
                {capability.specialist_profile_id, capability.commander_id},
            )
            if validator_bindings is None:
                blocked.append(
                    _blocked(
                        "validator_unavailable",
                        pipeline.frontier_id,
                        pipeline.asset_id,
                        pipeline.technique_id,
                        "Required validators are unavailable or unqualified for "
                        f"{task_type.value}.",
                    )
                )
                pipeline_open[pipeline_key] = False
                continue
            prerequisite = (last_task[pipeline_key],) if pipeline_key in last_task else ()
            draft = ProposedCoverageTask(
                task_id="",
                task_sha256="",
                task_key=_make_task_key(
                    task_type,
                    scope_hash,
                    snapshot.snapshot_sha256,
                    pipeline.asset_id,
                    pipeline.node_ids,
                    pipeline.technique_id,
                    capability,
                    validator_bindings,
                ),
                task_type=task_type,
                frontier_id=pipeline.frontier_id,
                priority=pipeline.priority_base + stage_index,
                wave=stage_index,
                scope_sha256=scope_hash,
                world_snapshot_sha256=snapshot.snapshot_sha256,
                asset_ids=(pipeline.asset_id,),
                node_ids=pipeline.node_ids,
                technique_ids=(pipeline.technique_id,),
                required_specialist_profile_id=capability.specialist_profile_id,
                required_commander_id=capability.commander_id,
                validators=validator_bindings,
                prerequisite_task_ids=prerequisite,
                estimated_cost_units=capability.estimated_cost_units,
                estimated_requests=capability.estimated_requests,
                impact_tier=capability.impact_tier,
                stop_conditions=capability.stop_conditions,
                expected_evidence=capability.expected_evidence,
                restoration_required=capability.restoration_required,
            )
            semantic = _semantic_task_key(draft)
            old_task_id = previous_by_semantic.get(semantic)
            if old_task_id is not None:
                draft = replace(draft, supersedes_task_ids=(old_task_id,))
            task = _address_task(draft)
            prior = completed_by_key.get(task.task_key)
            if prior is not None:
                accepted_prior.add(prior.task_id)
                last_task[pipeline_key] = prior.task_id
                continue
            if task.task_key in seen_task_keys:
                blocked.append(
                    _blocked(
                        "equivalent_task_deduplicated",
                        pipeline.frontier_id,
                        pipeline.asset_id,
                        pipeline.technique_id,
                        "An equivalent proposed task already exists.",
                    )
                )
                continue
            if tasks_per_asset[pipeline.asset_id] >= limits.max_tasks_per_asset:
                blocked.append(
                    _blocked(
                        "asset_task_limit_exhausted",
                        pipeline.frontier_id,
                        pipeline.asset_id,
                        pipeline.technique_id,
                        "Asset task limit is exhausted.",
                    )
                )
                pipeline_open[pipeline_key] = False
                continue
            exceeds = (
                len(scheduled) >= limits.max_tasks
                or total_cost + task.estimated_cost_units > limits.max_total_cost_units
                or total_requests + task.estimated_requests > effective_request_limit
            )
            if exceeds:
                budget_stopped.add(pipeline_key)
                pipeline_open[pipeline_key] = False
                continue
            scheduled.append(task)
            seen_task_keys.add(task.task_key)
            last_task[pipeline_key] = task.task_id
            tasks_per_asset[pipeline.asset_id] += 1
            total_cost += task.estimated_cost_units
            total_requests += task.estimated_requests

    for asset_id, technique_id in sorted(budget_stopped):
        matching = next(
            item
            for item in pipelines
            if (item.asset_id, item.technique_id) == (asset_id, technique_id)
        )
        blocked.append(
            _blocked(
                "schedule_budget_exhausted",
                matching.frontier_id,
                asset_id,
                technique_id,
                "A configured task, cost, or request budget is exhausted.",
            )
        )

    return _finish_schedule(
        scope_hash,
        snapshot,
        limits,
        tuple(scheduled),
        tuple(sorted(accepted_prior)),
        blocked,
        previous_schedule,
        scope_doc,
    )


def _finish_schedule(
    scope_hash: str,
    snapshot: AttackWorldSnapshot,
    limits: SchedulingLimits,
    tasks: tuple[ProposedCoverageTask, ...],
    accepted_prior: tuple[str, ...],
    blocked: Sequence[BlockedReason],
    previous: CoverageSchedule | None,
    scope_doc: Mapping[str, Any],
) -> CoverageSchedule:
    effective_concurrency = min(
        limits.max_concurrency,
        int(scope_doc["budgets"]["max_concurrency"]),
    )
    ordered_tasks = tuple(sorted(tasks, key=_task_sort_key))
    ordered_blocked = tuple(
        sorted(
            set(blocked),
            key=lambda item: (
                item.code,
                item.asset_id or "",
                item.technique_id or "",
                item.frontier_id or "",
                item.detail,
            ),
        )
    )
    return _address_schedule(
        scope_sha256=scope_hash,
        world_snapshot_sha256=snapshot.snapshot_sha256,
        parent_schedule_sha256=None if previous is None else previous.schedule_sha256,
        supersedes_schedule_id=None if previous is None else previous.schedule_id,
        limits=limits,
        effective_max_concurrency=effective_concurrency,
        tasks=ordered_tasks,
        accepted_prior_outcome_ids=accepted_prior,
        blocked_reasons=ordered_blocked,
    )


def _parse_capability_record(value: Any, label: str) -> _Capability:
    _exact_fields(
        value,
        {
            "available",
            "commander_id",
            "estimated_cost_units",
            "estimated_requests",
            "expected_evidence",
            "impact_tier",
            "qualified_scope_ids",
            "qualified_technique_ids",
            "restoration_required",
            "specialist_profile_id",
            "stop_conditions",
        },
        label,
    )
    if not isinstance(value["available"], bool) or not isinstance(
        value["restoration_required"], bool
    ):
        raise CoverageSchedulerError("capability availability flags must be boolean")
    _identifier(value["specialist_profile_id"], "capability specialist_profile_id")
    _identifier(value["commander_id"], "capability commander_id")
    scopes = _refs(
        _tuple_json(value["qualified_scope_ids"], "qualified_scope_ids"), "qualified_scope_ids"
    )
    techniques = _refs(
        _tuple_json(value["qualified_technique_ids"], "qualified_technique_ids"),
        "qualified_technique_ids",
    )
    if not scopes or not techniques:
        raise CoverageSchedulerError("capability qualification sets cannot be empty")
    try:
        impact = ActionTier(value["impact_tier"])
    except (TypeError, ValueError) as exc:
        raise CoverageSchedulerError("capability impact_tier is invalid") from exc
    for field in ("estimated_cost_units", "estimated_requests"):
        amount = value[field]
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise CoverageSchedulerError(f"capability {field} must be non-negative")
    capability = _Capability(
        available=value["available"],
        specialist_profile_id=value["specialist_profile_id"],
        commander_id=value["commander_id"],
        qualified_scope_ids=scopes,
        qualified_technique_ids=techniques,
        impact_tier=impact,
        estimated_cost_units=value["estimated_cost_units"],
        estimated_requests=value["estimated_requests"],
        stop_conditions=_text_refs(
            _tuple_json(value["stop_conditions"], "stop_conditions"), "stop_conditions"
        ),
        expected_evidence=_text_refs(
            _tuple_json(value["expected_evidence"], "expected_evidence"), "expected_evidence"
        ),
        restoration_required=value["restoration_required"],
    )
    if not capability.stop_conditions or not capability.expected_evidence:
        raise CoverageSchedulerError(
            "capability stop conditions and expected evidence cannot be empty"
        )
    return capability


def _parse_capabilities(raw: Any) -> dict[tuple[TaskType, str | None], _Capability]:
    if not isinstance(raw, Mapping):
        raise CoverageSchedulerError("capability_availability must be a mapping")
    result: dict[tuple[TaskType, str | None], _Capability] = {}
    for raw_name, value in raw.items():
        try:
            name = TaskType(raw_name)
        except (TypeError, ValueError) as exc:
            raise CoverageSchedulerError(
                "capability_availability has an unknown task type"
            ) from exc
        if isinstance(value, Mapping) and set(value) == {"default", "by_technique"}:
            if value["default"] is not None:
                result[(name, None)] = _parse_capability_record(
                    value["default"], f"capability {name.value} default"
                )
            overrides = value["by_technique"]
            if not isinstance(overrides, Mapping) or len(overrides) > 512:
                raise CoverageSchedulerError("capability technique routes are invalid")
            if value["default"] is None and not overrides:
                raise CoverageSchedulerError("capability routing has no route")
            for technique_id, record in overrides.items():
                _identifier(technique_id, "capability technique ID")
                result[(name, technique_id)] = _parse_capability_record(
                    record, f"capability {name.value} technique {technique_id}"
                )
        else:
            result[(name, None)] = _parse_capability_record(value, f"capability {name.value}")
    return result


def _parse_validators(raw: Any) -> tuple[_Validator, ...]:
    if not isinstance(raw, Mapping):
        raise CoverageSchedulerError("validator_availability must be a mapping")
    result: list[_Validator] = []
    for validator_id, value in raw.items():
        _identifier(validator_id, "validator ID")
        _exact_fields(
            value,
            {
                "available",
                "max_impact_tier",
                "qualified_scope_ids",
                "qualified_task_types",
                "role",
                "version",
            },
            f"validator {validator_id}",
        )
        if not isinstance(value["available"], bool):
            raise CoverageSchedulerError("validator available must be boolean")
        try:
            role = ValidatorRole(value["role"])
            max_impact = ActionTier(value["max_impact_tier"])
            task_types = tuple(
                sorted(
                    {
                        TaskType(item)
                        for item in _tuple_json(
                            value["qualified_task_types"], "qualified_task_types"
                        )
                    },
                    key=lambda item: item.value,
                )
            )
        except (TypeError, ValueError) as exc:
            raise CoverageSchedulerError(
                "validator role, impact, or task qualification is invalid"
            ) from exc
        _version(value["version"], "validator version")
        scopes = _refs(
            _tuple_json(value["qualified_scope_ids"], "qualified_scope_ids"), "qualified_scope_ids"
        )
        if not scopes or not task_types:
            raise CoverageSchedulerError("validator qualification sets cannot be empty")
        result.append(
            _Validator(
                validator_id=validator_id,
                available=value["available"],
                role=role,
                version=value["version"],
                qualified_task_types=task_types,
                qualified_scope_ids=scopes,
                max_impact_tier=max_impact,
            )
        )
    return tuple(
        sorted(result, key=lambda item: (item.role.value, item.validator_id, item.version))
    )


def _parse_outcomes(raw: Any) -> dict[str, _Outcome]:
    if not isinstance(raw, Mapping):
        raise CoverageSchedulerError("prior_task_outcomes must be a mapping")
    result: dict[str, _Outcome] = {}
    successful_keys: set[tuple[str, str]] = set()
    for task_id, value in raw.items():
        _task_id(task_id, "prior outcome task ID")
        _exact_fields(
            value,
            {"evidence_digests", "status", "task_key", "world_snapshot_sha256"},
            f"prior outcome {task_id}",
        )
        try:
            status = OutcomeStatus(value["status"])
        except (TypeError, ValueError) as exc:
            raise CoverageSchedulerError("prior outcome status is invalid") from exc
        if status in {OutcomeStatus.PENDING, OutcomeStatus.RUNNING}:
            raise CoverageSchedulerError("prior outcome must be terminal")
        _sha256(value["task_key"], "prior outcome task_key")
        _sha256(value["world_snapshot_sha256"], "prior outcome world_snapshot_sha256")
        digests = _tuple_json(value["evidence_digests"], "prior outcome evidence_digests")
        for digest in digests:
            _sha256(digest, "prior outcome evidence digest")
        if status is OutcomeStatus.SUCCEEDED:
            if not digests:
                raise CoverageSchedulerError("successful prior outcome requires evidence")
            key = (value["task_key"], value["world_snapshot_sha256"])
            if key in successful_keys:
                raise CoverageSchedulerError("successful prior outcome task key is ambiguous")
            successful_keys.add(key)
        result[task_id] = _Outcome(
            task_id=task_id,
            task_key=value["task_key"],
            status=status,
            world_snapshot_sha256=value["world_snapshot_sha256"],
            evidence_digests=tuple(sorted(set(digests))),
        )
    return result


def _capability_block(
    capability: _Capability | None,
    scope_id: str,
    technique_id: str,
    scope_impact_ceiling: ActionTier,
) -> str | None:
    if capability is None or not capability.available:
        return "capability_unavailable"
    if scope_id not in capability.qualified_scope_ids:
        return "profile_scope_unqualified"
    if technique_id not in capability.qualified_technique_ids:
        return "profile_technique_unqualified"
    if capability.impact_tier.rank > scope_impact_ceiling.rank:
        return "scope_impact_ceiling_exceeded"
    return None


def _select_validators(
    validators: tuple[_Validator, ...],
    task_type: TaskType,
    scope_id: str,
    impact: ActionTier,
    review_threshold: ActionTier,
    forbidden_ids: set[str],
) -> tuple[ValidatorBinding, ...] | None:
    roles = [ValidatorRole.EVIDENCE]
    if impact.rank >= review_threshold.rank:
        roles.extend((ValidatorRole.CONTROL, ValidatorRole.ASSURANCE))
    selected: list[ValidatorBinding] = []
    used_ids = set(forbidden_ids)
    for role in roles:
        candidates = [
            item
            for item in validators
            if item.available
            and item.role is role
            and item.validator_id not in used_ids
            and scope_id in item.qualified_scope_ids
            and task_type in item.qualified_task_types
            and impact.rank <= item.max_impact_tier.rank
        ]
        if not candidates:
            return None
        choice = min(candidates, key=lambda item: (item.validator_id, item.version))
        used_ids.add(choice.validator_id)
        selected.append(ValidatorBinding(role, choice.validator_id, choice.version))
    return tuple(selected)


def _verified_scope_document(scope: Any) -> dict[str, Any]:
    if not isinstance(scope, VerifiedAssessmentScope):
        raise CoverageSchedulerError("scope must be a VerifiedAssessmentScope")
    if not isinstance(scope.signed_scope, SignedAssessmentScope):
        raise CoverageSchedulerError("verified scope contains an invalid signed scope")
    try:
        document = scope.to_dict()
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CoverageSchedulerError("verified scope document is invalid") from exc
    if not isinstance(document, dict):
        raise CoverageSchedulerError("verified scope document must be an object")
    required = {
        "assessment_window",
        "budgets",
        "content_sha256",
        "effects",
        "expires_at",
        "issued_at",
        "allowed_technique_ids",
        "scope_id",
        "signature",
        "signature_algorithm",
    }
    if not required <= set(document):
        raise CoverageSchedulerError("verified scope document is incomplete")
    content = {
        key: value
        for key, value in document.items()
        if key not in {"content_sha256", "signature_algorithm", "signature"}
    }
    if scope_canonical_sha256(content) != document["content_sha256"]:
        raise CoverageSchedulerError("verified scope content hash is invalid")
    if document["scope_id"] != scope.scope_id or document["content_sha256"] != scope.content_sha256:
        raise CoverageSchedulerError("verified scope identity is invalid")
    expected_effects = {
        "authority": "none",
        "deployment": "none",
        "execution": "none",
        "network": "none",
        "qualification": "none",
        "routing": "none",
    }
    if document["effects"] != expected_effects:
        raise CoverageSchedulerError("verified scope effects are invalid")
    return document


def _scope_active(document: Mapping[str, Any], as_of: str) -> bool:
    instant = _utc(as_of, "limits as_of")
    return (
        _utc(document["issued_at"], "scope issued_at") <= instant
        and _utc(document["assessment_window"]["starts_at"], "scope starts_at") <= instant
        and instant < _utc(document["assessment_window"]["ends_at"], "scope ends_at")
        and instant < _utc(document["expires_at"], "scope expires_at")
    )


def _make_task_key(
    task_type: TaskType,
    scope_hash: str,
    snapshot_hash: str,
    asset_id: str,
    node_ids: tuple[str, ...],
    technique_id: str,
    capability: _Capability,
    validators: tuple[ValidatorBinding, ...],
) -> str:
    return _digest(
        {
            "asset_ids": [asset_id],
            "domain": TASK_KEY_DOMAIN,
            "node_ids": list(node_ids),
            "scope_sha256": scope_hash,
            "task_type": task_type.value,
            "technique_ids": [technique_id],
            "world_snapshot_sha256": snapshot_hash,
            "specialist_profile_id": capability.specialist_profile_id,
            "commander_id": capability.commander_id,
            "validator_bindings": [item.to_dict() for item in validators],
            "impact_tier": capability.impact_tier.value,
            "stop_conditions": list(capability.stop_conditions),
            "expected_evidence": list(capability.expected_evidence),
            "restoration_required": capability.restoration_required,
        }
    )


def _semantic_task_key(task: ProposedCoverageTask) -> tuple[Any, ...]:
    return (task.task_type.value, task.asset_ids, task.node_ids, task.technique_ids)


def _task_body(task: ProposedCoverageTask) -> dict[str, Any]:
    return {
        "asset_ids": list(task.asset_ids),
        "effects": dict(NO_EFFECTS),
        "estimated_cost_units": task.estimated_cost_units,
        "estimated_requests": task.estimated_requests,
        "expected_evidence": list(task.expected_evidence),
        "frontier_id": task.frontier_id,
        "impact_tier": task.impact_tier.value,
        "node_ids": list(task.node_ids),
        "prerequisite_task_ids": list(task.prerequisite_task_ids),
        "priority": task.priority,
        "required_commander_id": task.required_commander_id,
        "required_specialist_profile_id": task.required_specialist_profile_id,
        "restoration_required": task.restoration_required,
        "scope_sha256": task.scope_sha256,
        "stop_conditions": list(task.stop_conditions),
        "supersedes_task_ids": list(task.supersedes_task_ids),
        "task_key": task.task_key,
        "task_type": task.task_type.value,
        "technique_ids": list(task.technique_ids),
        "validators": [item.to_dict() for item in task.validators],
        "wave": task.wave,
        "world_snapshot_sha256": task.world_snapshot_sha256,
    }


def _address_task(task: ProposedCoverageTask) -> ProposedCoverageTask:
    body = _task_body(task)
    digest = _digest({"domain": TASK_DOMAIN, "task": body})
    return replace(
        task,
        task_id=f"CST-{digest.removeprefix('sha256:')[:32].upper()}",
        task_sha256=digest,
    )


def _schedule_body(
    *,
    scope_sha256: str,
    world_snapshot_sha256: str,
    parent_schedule_sha256: str | None,
    supersedes_schedule_id: str | None,
    limits: SchedulingLimits,
    effective_max_concurrency: int,
    tasks: tuple[ProposedCoverageTask, ...],
    accepted_prior_outcome_ids: tuple[str, ...],
    blocked_reasons: tuple[BlockedReason, ...],
) -> dict[str, Any]:
    return {
        "accepted_prior_outcome_ids": list(accepted_prior_outcome_ids),
        "blocked_reasons": [item.to_dict() for item in blocked_reasons],
        "budget_summary": {
            "scheduled_cost_units": sum(item.estimated_cost_units for item in tasks),
            "scheduled_requests": sum(item.estimated_requests for item in tasks),
            "scheduled_tasks": len(tasks),
        },
        "effects": dict(NO_EFFECTS),
        "effective_max_concurrency": effective_max_concurrency,
        "limits": limits.to_dict(),
        "parent_schedule_sha256": parent_schedule_sha256,
        "schema_version": SCHEMA_VERSION,
        "scope_sha256": scope_sha256,
        "supersedes_schedule_id": supersedes_schedule_id,
        "tasks": [item.to_dict() for item in tasks],
        "world_snapshot_sha256": world_snapshot_sha256,
    }


def _address_schedule(
    *,
    scope_sha256: str,
    world_snapshot_sha256: str,
    parent_schedule_sha256: str | None,
    supersedes_schedule_id: str | None,
    limits: SchedulingLimits,
    effective_max_concurrency: int,
    tasks: tuple[ProposedCoverageTask, ...],
    accepted_prior_outcome_ids: tuple[str, ...],
    blocked_reasons: tuple[BlockedReason, ...],
) -> CoverageSchedule:
    _sha256(scope_sha256, "schedule scope_sha256")
    _sha256(world_snapshot_sha256, "schedule world_snapshot_sha256")
    if parent_schedule_sha256 is not None:
        _sha256(parent_schedule_sha256, "schedule parent_schedule_sha256")
    if supersedes_schedule_id is not None:
        _schedule_id(supersedes_schedule_id, "schedule supersedes_schedule_id")
    if (
        isinstance(effective_max_concurrency, bool)
        or not isinstance(effective_max_concurrency, int)
        or not 1 <= effective_max_concurrency <= limits.max_concurrency
    ):
        raise CoverageSchedulerError("schedule effective_max_concurrency is invalid")
    accepted = _task_refs(accepted_prior_outcome_ids, "accepted prior outcome IDs")
    task_ids = [item.task_id for item in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise CoverageSchedulerError("schedule task IDs must be unique")
    if len({item.task_key for item in tasks}) != len(tasks):
        raise CoverageSchedulerError("schedule contains equivalent duplicate tasks")
    if tuple(sorted(tasks, key=_task_sort_key)) != tasks:
        raise CoverageSchedulerError("schedule task ordering is not canonical")
    known = set(task_ids) | set(accepted)
    for task in tasks:
        if task.scope_sha256 != scope_sha256 or task.world_snapshot_sha256 != world_snapshot_sha256:
            raise CoverageSchedulerError("task scope or world binding does not match schedule")
        if not set(task.prerequisite_task_ids) <= known:
            raise CoverageSchedulerError("task prerequisite references an unknown task")
        if task.task_id in task.prerequisite_task_ids:
            raise CoverageSchedulerError("task cannot depend on itself")
    _assert_acyclic(tasks, set(accepted))
    if len(tasks) > limits.max_tasks:
        raise CoverageSchedulerError("schedule exceeds max_tasks")
    if sum(item.estimated_cost_units for item in tasks) > limits.max_total_cost_units:
        raise CoverageSchedulerError("schedule exceeds max_total_cost_units")
    if sum(item.estimated_requests for item in tasks) > limits.max_total_requests:
        raise CoverageSchedulerError("schedule exceeds max_total_requests")
    by_wave: dict[int, int] = {}
    for task in tasks:
        by_wave[task.wave] = by_wave.get(task.wave, 0) + 1
    if any(count > effective_max_concurrency for count in by_wave.values()):
        tasks = _assign_waves(tasks, effective_max_concurrency, set(accepted))
    body = _schedule_body(
        scope_sha256=scope_sha256,
        world_snapshot_sha256=world_snapshot_sha256,
        parent_schedule_sha256=parent_schedule_sha256,
        supersedes_schedule_id=supersedes_schedule_id,
        limits=limits,
        effective_max_concurrency=effective_max_concurrency,
        tasks=tasks,
        accepted_prior_outcome_ids=accepted,
        blocked_reasons=blocked_reasons,
    )
    digest = _digest({"domain": SCHEDULE_DOMAIN, "schedule": body})
    return CoverageSchedule(
        schedule_id=f"CSS-{digest.removeprefix('sha256:')[:32].upper()}",
        schedule_sha256=digest,
        scope_sha256=scope_sha256,
        world_snapshot_sha256=world_snapshot_sha256,
        parent_schedule_sha256=parent_schedule_sha256,
        supersedes_schedule_id=supersedes_schedule_id,
        limits=limits,
        effective_max_concurrency=effective_max_concurrency,
        tasks=tasks,
        accepted_prior_outcome_ids=accepted,
        blocked_reasons=blocked_reasons,
    )


def _assign_waves(
    tasks: tuple[ProposedCoverageTask, ...],
    max_concurrency: int,
    external: set[str],
) -> tuple[ProposedCoverageTask, ...]:
    assigned: dict[str, ProposedCoverageTask] = {}
    wave_counts: dict[int, int] = {}
    result: list[ProposedCoverageTask] = []
    for original in tasks:
        internal_prereqs = [
            assigned[item] for item in original.prerequisite_task_ids if item not in external
        ]
        wave = max((item.wave + 1 for item in internal_prereqs), default=0)
        while wave_counts.get(wave, 0) >= max_concurrency:
            wave += 1
        updated = _address_task(replace(original, task_id="", task_sha256="", wave=wave))
        if updated.task_id != original.task_id:
            replacements = {old_id: item.task_id for old_id, item in assigned.items()}
            prereqs = tuple(replacements.get(item, item) for item in updated.prerequisite_task_ids)
            updated = _address_task(
                replace(updated, task_id="", task_sha256="", prerequisite_task_ids=prereqs)
            )
        assigned[original.task_id] = updated
        wave_counts[wave] = wave_counts.get(wave, 0) + 1
        result.append(updated)
    return tuple(sorted(result, key=_task_sort_key))


def _assert_acyclic(tasks: tuple[ProposedCoverageTask, ...], external: set[str]) -> None:
    dependencies = {task.task_id: set(task.prerequisite_task_ids) - external for task in tasks}
    remaining = dict(dependencies)
    while remaining:
        ready = sorted(task_id for task_id, deps in remaining.items() if not deps)
        if not ready:
            raise CoverageSchedulerError("schedule task dependency graph contains a cycle")
        for task_id in ready:
            remaining.pop(task_id)
        for deps in remaining.values():
            deps.difference_update(ready)


def _task_sort_key(task: ProposedCoverageTask) -> tuple[Any, ...]:
    return (
        task.wave,
        task.priority,
        task.asset_ids,
        task.technique_ids,
        task.task_type.value,
        task.task_id,
    )


def _blocked(
    code: str, frontier_id: str | None, asset_id: str | None, technique_id: str | None, detail: str
) -> BlockedReason:
    return BlockedReason(code, frontier_id, asset_id, technique_id, detail)


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
    except (TypeError, ValueError) as exc:
        raise CoverageSchedulerError("value cannot be serialized as canonical JSON") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("ascii")).hexdigest()


def _exact_fields(raw: Any, required: set[str], label: str) -> None:
    if not isinstance(raw, Mapping):
        raise CoverageSchedulerError(f"{label} must be an object")
    keys = set(raw)
    if keys != required:
        missing = sorted(required - keys)
        extra = sorted(keys - required)
        raise CoverageSchedulerError(
            f"{label} fields are invalid; missing={missing}, extra={extra}"
        )


def _tuple_json(value: Any, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list | tuple):
        raise CoverageSchedulerError(f"{label} must be a list")
    return tuple(value)


def _refs(value: Sequence[Any], label: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise CoverageSchedulerError(f"{label} must be a sequence")
    refs: list[str] = []
    for item in value:
        _identifier(item, label)
        refs.append(item)
    canonical = tuple(sorted(set(refs)))
    if len(canonical) != len(refs):
        raise CoverageSchedulerError(f"{label} cannot contain duplicates")
    return canonical


def _task_refs(value: Sequence[Any], label: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise CoverageSchedulerError(f"{label} must be a sequence")
    refs: list[str] = []
    for item in value:
        _task_id(item, label)
        refs.append(item)
    canonical = tuple(sorted(set(refs)))
    if len(canonical) != len(refs):
        raise CoverageSchedulerError(f"{label} cannot contain duplicates")
    return canonical


def _text_refs(value: Sequence[Any], label: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise CoverageSchedulerError(f"{label} must be a sequence")
    result: list[str] = []
    for item in value:
        _safe_text(item, label, 512)
        result.append(item)
    canonical = tuple(sorted(set(result)))
    if len(canonical) != len(result):
        raise CoverageSchedulerError(f"{label} cannot contain duplicates")
    return canonical


def _safe_text(value: Any, label: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise CoverageSchedulerError(f"{label} must be printable ASCII text")
    if SECRET_RE.search(value):
        raise CoverageSchedulerError(f"{label} appears to contain secret material")


def _identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise CoverageSchedulerError(f"{label} is invalid")
    _safe_text(value, label, 256)


def _token(value: Any, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) is None:
        raise CoverageSchedulerError(f"{label} is invalid")


def _version(value: Any, label: str) -> None:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise CoverageSchedulerError(f"{label} is invalid")


def _sha256(value: Any, label: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CoverageSchedulerError(f"{label} is invalid")


def _task_id(value: Any, label: str) -> None:
    if not isinstance(value, str) or TASK_ID_RE.fullmatch(value) is None:
        raise CoverageSchedulerError(f"{label} is invalid")


def _schedule_id(value: Any, label: str) -> None:
    if not isinstance(value, str) or SCHEDULE_ID_RE.fullmatch(value) is None:
        raise CoverageSchedulerError(f"{label} is invalid")


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise CoverageSchedulerError(f"{label} must be canonical UTC seconds")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CoverageSchedulerError(f"{label} is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise CoverageSchedulerError(f"{label} is not canonical")
    return parsed


__all__ = [
    "BlockedReason",
    "CoverageSchedule",
    "CoverageSchedulerError",
    "NO_EFFECTS",
    "OutcomeStatus",
    "ProposedCoverageTask",
    "SchedulingLimits",
    "TaskType",
    "ValidatorBinding",
    "ValidatorRole",
    "compute_coverage_schedule",
    "replan_coverage_schedule",
    "select_next_ready_task",
]
