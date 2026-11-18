"""Deterministic, effect-free capacity rehearsal for a coverage schedule."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .coverage_scheduler import (
    CoverageSchedule,
    CoverageSchedulerError,
    OutcomeStatus,
    ProposedCoverageTask,
    select_next_ready_task,
)
from .registry import ExpertRegistry, RegistryError
from .types import ProfileKind

KIND = "sunderkey.coverage-capacity-rehearsal.v1"
SCHEMA_VERSION = 1
NO_EFFECTS = {
    "authorization": "none",
    "dispatch": "none",
    "network": "none",
    "qualification": "none",
    "routing": "none",
    "target_action": "none",
}


class CapacityRehearsalError(ValueError):
    """Raised when a capacity assumption or rehearsal is invalid."""


@dataclass(frozen=True, slots=True)
class CapacityAssignment:
    task_id: str
    task_sha256: str
    baseline_wave: int
    rehearsal_wave: int
    specialist_profile_id: str
    commander_id: str
    validator_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_sha256": self.task_sha256,
            "baseline_wave": self.baseline_wave,
            "rehearsal_wave": self.rehearsal_wave,
            "specialist_profile_id": self.specialist_profile_id,
            "commander_id": self.commander_id,
            "validator_ids": list(self.validator_ids),
        }


@dataclass(frozen=True, slots=True)
class CapacityRehearsal:
    schedule_id: str
    schedule_sha256: str
    specialist_capacity: tuple[tuple[str, int], ...]
    commander_capacity: tuple[tuple[str, int], ...]
    validator_capacity: tuple[tuple[str, int], ...]
    assignments: tuple[CapacityAssignment, ...]
    baseline_wave_count: int
    rehearsal_wave_count: int
    additional_waves: int
    rehearsal_id: str
    rehearsal_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "specialist_capacity": dict(self.specialist_capacity),
            "commander_capacity": dict(self.commander_capacity),
            "validator_capacity": dict(self.validator_capacity),
            "assignments": [item.to_dict() for item in self.assignments],
            "baseline_wave_count": self.baseline_wave_count,
            "rehearsal_wave_count": self.rehearsal_wave_count,
            "additional_waves": self.additional_waves,
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "rehearsal_id": self.rehearsal_id,
            "rehearsal_sha256": self.rehearsal_sha256,
        }


def _capacity(
    raw: Mapping[str, int], expected: set[str], label: str, maximum: int
) -> tuple[tuple[str, int], ...]:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise CapacityRehearsalError(f"{label} must name every required profile exactly once")
    result: list[tuple[str, int]] = []
    for profile_id in sorted(expected):
        value = raw[profile_id]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise CapacityRehearsalError(f"{label} has an invalid slot limit")
        result.append((profile_id, value))
    return tuple(result)


def plan_capacity_rehearsal(
    schedule: CoverageSchedule,
    *,
    specialist_capacity: Mapping[str, int],
    commander_capacity: Mapping[str, int],
    validator_capacity: Mapping[str, int],
) -> CapacityRehearsal:
    """Repack proposal waves with declared per-profile slot limits only."""

    if not isinstance(schedule, CoverageSchedule):
        raise CapacityRehearsalError("schedule must be typed")
    try:
        CoverageSchedule.from_dict(schedule.to_dict())
    except CoverageSchedulerError as exc:
        raise CapacityRehearsalError("schedule identity is invalid") from exc
    specialist = _capacity(
        specialist_capacity,
        {item.required_specialist_profile_id for item in schedule.tasks},
        "specialist_capacity",
        schedule.effective_max_concurrency,
    )
    commander = _capacity(
        commander_capacity,
        {item.required_commander_id for item in schedule.tasks},
        "commander_capacity",
        schedule.effective_max_concurrency,
    )
    validators = _capacity(
        validator_capacity,
        {item.validator_id for task in schedule.tasks for item in task.validators},
        "validator_capacity",
        schedule.effective_max_concurrency,
    )
    specialist_limits = dict(specialist)
    commander_limits = dict(commander)
    validator_limits = dict(validators)
    wave_total: Counter[int] = Counter()
    wave_specialist: Counter[tuple[int, str]] = Counter()
    wave_commander: Counter[tuple[int, str]] = Counter()
    wave_validator: Counter[tuple[int, str]] = Counter()
    assigned_wave: dict[str, int] = {}
    assignments: list[CapacityAssignment] = []
    external = set(schedule.accepted_prior_outcome_ids)
    for task in sorted(
        schedule.tasks,
        key=lambda item: (item.wave, item.priority, item.task_id),
    ):
        prerequisites = [
            assigned_wave[item] for item in task.prerequisite_task_ids if item not in external
        ]
        validator_ids = tuple(sorted({item.validator_id for item in task.validators}))
        wave = max(task.wave, max(prerequisites, default=-1) + 1)
        while (
            wave_total[wave] >= schedule.effective_max_concurrency
            or wave_specialist[(wave, task.required_specialist_profile_id)]
            >= specialist_limits[task.required_specialist_profile_id]
            or wave_commander[(wave, task.required_commander_id)]
            >= commander_limits[task.required_commander_id]
            or any(
                wave_validator[(wave, validator_id)] >= validator_limits[validator_id]
                for validator_id in validator_ids
            )
        ):
            wave += 1
        wave_total[wave] += 1
        wave_specialist[(wave, task.required_specialist_profile_id)] += 1
        wave_commander[(wave, task.required_commander_id)] += 1
        for validator_id in validator_ids:
            wave_validator[(wave, validator_id)] += 1
        assigned_wave[task.task_id] = wave
        assignments.append(
            CapacityAssignment(
                task_id=task.task_id,
                task_sha256=task.task_sha256,
                baseline_wave=task.wave,
                rehearsal_wave=wave,
                specialist_profile_id=task.required_specialist_profile_id,
                commander_id=task.required_commander_id,
                validator_ids=validator_ids,
            )
        )
    baseline_count = max((item.wave for item in schedule.tasks), default=-1) + 1
    rehearsal_count = max(assigned_wave.values(), default=-1) + 1
    draft = CapacityRehearsal(
        schedule_id=schedule.schedule_id,
        schedule_sha256=schedule.schedule_sha256,
        specialist_capacity=specialist,
        commander_capacity=commander,
        validator_capacity=validators,
        assignments=tuple(sorted(assignments, key=lambda item: item.task_id)),
        baseline_wave_count=baseline_count,
        rehearsal_wave_count=rehearsal_count,
        additional_waves=rehearsal_count - baseline_count,
        rehearsal_id="",
        rehearsal_sha256="",
    )
    encoded = json.dumps(
        {"domain": KIND, "body": draft.body()},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    digest = hashlib.sha256(encoded).hexdigest()
    return CapacityRehearsal(
        schedule_id=draft.schedule_id,
        schedule_sha256=draft.schedule_sha256,
        specialist_capacity=draft.specialist_capacity,
        commander_capacity=draft.commander_capacity,
        validator_capacity=draft.validator_capacity,
        assignments=draft.assignments,
        baseline_wave_count=draft.baseline_wave_count,
        rehearsal_wave_count=draft.rehearsal_wave_count,
        additional_waves=draft.additional_waves,
        rehearsal_id=f"CCR-{digest[:32].upper()}",
        rehearsal_sha256=f"sha256:{digest}",
    )


def verify_capacity_rehearsal(
    schedule: CoverageSchedule, raw: CapacityRehearsal | Mapping[str, Any]
) -> CapacityRehearsal:
    """Recompute every derived assignment and identity from the bound schedule."""

    if isinstance(raw, CapacityRehearsal):
        document = raw.to_dict()
    elif isinstance(raw, Mapping):
        document = dict(raw)
    else:
        raise CapacityRehearsalError("rehearsal document is invalid")
    try:
        candidate = plan_capacity_rehearsal(
            schedule,
            specialist_capacity=document["specialist_capacity"],
            commander_capacity=document["commander_capacity"],
            validator_capacity=document["validator_capacity"],
        )
    except (KeyError, TypeError) as exc:
        raise CapacityRehearsalError("rehearsal capacity fields are invalid") from exc
    if document != candidate.to_dict():
        raise CapacityRehearsalError("rehearsal content or identity is invalid")
    return candidate


def select_next_capacity_ready_task(
    schedule: CoverageSchedule,
    rehearsal: CapacityRehearsal | Mapping[str, Any],
    completion_state: Mapping[str, str | OutcomeStatus],
) -> ProposedCoverageTask | None:
    """Select a ready proposal while respecting all declared slot limits."""

    checked = verify_capacity_rehearsal(schedule, rehearsal)
    try:
        globally_ready = select_next_ready_task(schedule, completion_state)
    except CoverageSchedulerError as exc:
        raise CapacityRehearsalError("completion state is invalid") from exc
    states = {task_id: OutcomeStatus(value) for task_id, value in completion_state.items()}
    completed = {
        task_id for task_id, state in states.items() if state is OutcomeStatus.SUCCEEDED
    } | set(schedule.accepted_prior_outcome_ids)
    running = [task for task in schedule.tasks if states.get(task.task_id) is OutcomeStatus.RUNNING]
    specialists = Counter(task.required_specialist_profile_id for task in running)
    commanders = Counter(task.required_commander_id for task in running)
    validators = Counter(
        validator_id
        for task in running
        for validator_id in {item.validator_id for item in task.validators}
    )
    specialist_limits = dict(checked.specialist_capacity)
    commander_limits = dict(checked.commander_capacity)
    validator_limits = dict(checked.validator_capacity)
    if (
        any(count > specialist_limits[profile_id] for profile_id, count in specialists.items())
        or any(count > commander_limits[profile_id] for profile_id, count in commanders.items())
        or any(count > validator_limits[profile_id] for profile_id, count in validators.items())
    ):
        raise CapacityRehearsalError("running state exceeds declared profile capacity")
    if globally_ready is None:
        return None
    assigned_waves = {item.task_id: item.rehearsal_wave for item in checked.assignments}
    ready = sorted(
        (
            task
            for task in schedule.tasks
            if states.get(task.task_id, OutcomeStatus.PENDING) is OutcomeStatus.PENDING
            and set(task.prerequisite_task_ids) <= completed
        ),
        key=lambda task: (
            assigned_waves[task.task_id],
            task.priority,
            task.asset_ids,
            task.technique_ids,
            task.task_type.value,
            task.task_id,
        ),
    )
    for task in ready:
        if (
            specialists[task.required_specialist_profile_id]
            >= specialist_limits[task.required_specialist_profile_id]
        ):
            continue
        if commanders[task.required_commander_id] >= commander_limits[task.required_commander_id]:
            continue
        if any(
            validators[item.validator_id] >= validator_limits[item.validator_id]
            for item in task.validators
        ):
            continue
        return task
    return None


@dataclass(frozen=True, slots=True)
class RegistryCapacityBinding:
    schedule_id: str
    schedule_sha256: str
    rehearsal_id: str
    rehearsal_sha256: str
    catalog_id: str
    catalog_version: str
    catalog_sha256: str
    task_count: int
    binding_id: str
    binding_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "sunderkey.registry-capacity-binding.v1",
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "rehearsal_id": self.rehearsal_id,
            "rehearsal_sha256": self.rehearsal_sha256,
            "catalog_id": self.catalog_id,
            "catalog_version": self.catalog_version,
            "catalog_sha256": self.catalog_sha256,
            "task_count": self.task_count,
            "qualification_effect": "none",
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "binding_id": self.binding_id, "binding_sha256": self.binding_sha256}


def _address(kind: str, body: Mapping[str, Any], prefix: str) -> tuple[str, str]:
    encoded = json.dumps(
        {"domain": kind, "body": dict(body)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    digest = hashlib.sha256(encoded).hexdigest()
    return f"{prefix}-{digest[:32].upper()}", f"sha256:{digest}"


def bind_rehearsal_to_army_registry(
    schedule: CoverageSchedule,
    rehearsal: CapacityRehearsal,
    registry: ExpertRegistry,
) -> RegistryCapacityBinding:
    """Bind a rehearsal to a valid catalog and exact command membership."""

    verify_capacity_rehearsal(schedule, rehearsal)
    if not isinstance(registry, ExpertRegistry):
        raise CapacityRehearsalError("registry must be typed")
    try:
        checked = ExpertRegistry.from_dict(registry.to_dict())
    except RegistryError as exc:
        raise CapacityRehearsalError("registry structure is invalid") from exc
    if (
        checked.catalog_id != "sunderkey-offensive-expert-army"
        or checked.catalog_version != "2.0.0"
        or len(checked.profiles) != 451
        or len(checked.commands) != 25
    ):
        raise CapacityRehearsalError("registry must be the 451-profile Army v2 catalog")
    profiles = checked.profiles_by_id
    commands = checked.commands_by_id
    for task in schedule.tasks:
        specialist = profiles.get(task.required_specialist_profile_id)
        commander = profiles.get(task.required_commander_id)
        if specialist is None or specialist.kind is not ProfileKind.SPECIALIST:
            raise CapacityRehearsalError("task specialist is not in the Army catalog")
        if commander is None or commander.kind is not ProfileKind.DOMAIN_COMMANDER:
            raise CapacityRehearsalError("task commander is not in the Army catalog")
        if specialist.status not in {"defined", "qualified"} or commander.status not in {
            "defined",
            "qualified",
        }:
            raise CapacityRehearsalError("task profile is inactive in the Army catalog")
        command = commands.get(specialist.command_id)
        if command is None or command.commander_profile_id != commander.id:
            raise CapacityRehearsalError(
                "task specialist and commander belong to different commands"
            )
    catalog_body = checked.to_dict()
    catalog_encoded = json.dumps(
        catalog_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    catalog_digest = "sha256:" + hashlib.sha256(catalog_encoded).hexdigest()
    draft = RegistryCapacityBinding(
        schedule_id=schedule.schedule_id,
        schedule_sha256=schedule.schedule_sha256,
        rehearsal_id=rehearsal.rehearsal_id,
        rehearsal_sha256=rehearsal.rehearsal_sha256,
        catalog_id=checked.catalog_id,
        catalog_version=checked.catalog_version,
        catalog_sha256=catalog_digest,
        task_count=len(schedule.tasks),
        binding_id="",
        binding_sha256="",
    )
    identity, digest = _address(draft.body()["kind"], draft.body(), "RCB")
    return RegistryCapacityBinding(
        schedule_id=draft.schedule_id,
        schedule_sha256=draft.schedule_sha256,
        rehearsal_id=draft.rehearsal_id,
        rehearsal_sha256=draft.rehearsal_sha256,
        catalog_id=draft.catalog_id,
        catalog_version=draft.catalog_version,
        catalog_sha256=draft.catalog_sha256,
        task_count=draft.task_count,
        binding_id=identity,
        binding_sha256=digest,
    )


def verify_registry_capacity_binding(
    schedule: CoverageSchedule,
    rehearsal: CapacityRehearsal,
    registry: ExpertRegistry,
    raw: RegistryCapacityBinding | Mapping[str, Any],
) -> RegistryCapacityBinding:
    """Recompute a catalog binding without granting profile qualification."""

    if isinstance(raw, RegistryCapacityBinding):
        document = raw.to_dict()
    elif isinstance(raw, Mapping):
        document = dict(raw)
    else:
        raise CapacityRehearsalError("registry binding document is invalid")
    candidate = bind_rehearsal_to_army_registry(schedule, rehearsal, registry)
    if document != candidate.to_dict():
        raise CapacityRehearsalError("registry binding content or identity is invalid")
    return candidate
