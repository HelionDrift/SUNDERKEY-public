"""Pure contracts for durable, tenant-bound assessment scheduling.

The records in this module describe scheduling state transitions without
performing them. Callers supply every timestamp and all prior state. The
module does not read a clock, persist data, create workers, authorize an
assessment, contact a target, or execute scheduled work.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any

SCHEMA_VERSION = 1

NO_EFFECTS = MappingProxyType({
    "authorization": "none",
    "clock": "caller_supplied",
    "execution": "none",
    "network": "none",
    "persistence": "none",
    "processes": "none",
    "scheduling": "none",
    "target_actions": "none",
    "threads": "none",
})

HARD_LIMITS = {
    "clock_skew_tolerance_seconds": 900,
    "concurrency_limit": 4096,
    "lease_duration_seconds": 86_400,
    "max_catch_up_occurrences": 1024,
    "max_occurrences": 1_000_000,
    "max_occurrences_per_evaluation": 4096,
    "retry_attempts": 32,
    "retry_budget_units": 1_000_000,
}

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
RECORD_ID_RE = re.compile(r"DS[A-Z]-[0-9A-F]{32}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class DurableSchedulerContractError(ValueError):
    """Raised when a scheduler contract fails closed."""


class MisfirePolicy(StrEnum):
    """Deterministic treatment of occurrences missed beyond clock skew."""

    SKIP = "skip"
    FIRE_ONCE = "fire_once"
    CATCH_UP_BOUNDED = "catch_up_bounded"


class DueReason(StrEnum):
    """Reason an occurrence was materialized by an evaluation."""

    SCHEDULED = "scheduled"
    MISFIRE_ONCE = "misfire_once"
    MISFIRE_CATCH_UP = "misfire_catch_up"


class LeaseTransition(StrEnum):
    """Immutable lease snapshot transition."""

    CLAIM = "claim"
    HEARTBEAT = "heartbeat"


class CompletionStatus(StrEnum):
    """Worker outcome supplied to a completion observation."""

    SUCCEEDED = "succeeded"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"
    CANCELLED = "cancelled"


class CompletionResolution(StrEnum):
    """Pure scheduler resolution for one completion observation."""

    COMPLETED = "completed"
    RETRY_PLANNED = "retry_planned"
    DEAD_LETTERED = "dead_lettered"
    CANCELLED = "cancelled"


class RecoveryDisposition(StrEnum):
    """Pure recovery result for an expired lease."""

    REQUEUE = "requeue"
    DEAD_LETTER = "dead_letter"


class CancellationTarget(StrEnum):
    """Aggregate addressed by a cancellation record."""

    SCHEDULE = "schedule"
    OCCURRENCE = "occurrence"


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation used for every digest."""

    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise DurableSchedulerContractError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    """Hash canonical JSON with the repository digest prefix."""

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": body, "domain": domain})
    return prefix + digest.removeprefix("sha256:")[:32].upper(), digest


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise DurableSchedulerContractError(f"{label} fields are invalid")
    return raw


def _sequence(raw: Any, label: str) -> list[Any]:
    if not isinstance(raw, list):
        raise DurableSchedulerContractError(f"{label} must be a JSON list")
    return raw


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise DurableSchedulerContractError(f"{label} is invalid")
    return value


def _record_id(value: Any, label: str, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or RECORD_ID_RE.fullmatch(value) is None
    ):
        raise DurableSchedulerContractError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DurableSchedulerContractError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise DurableSchedulerContractError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise DurableSchedulerContractError(f"{label} is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise DurableSchedulerContractError(f"{label} is not canonical")
    return value


def _instant(value: str) -> datetime:
    _timestamp(value, "timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _format(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _positive(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DurableSchedulerContractError(f"{label} must be between 1 and {maximum}")
    return value


def _nonnegative(value: Any, label: str, maximum: int = 2_147_483_647) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise DurableSchedulerContractError(f"{label} must be between 0 and {maximum}")
    return value


def _idempotency(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDEMPOTENCY_RE.fullmatch(value) is None:
        raise DurableSchedulerContractError(f"{label} is invalid")
    return value


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise DurableSchedulerContractError(f"{label} is invalid")
    return value


def _digests(values: Sequence[Any], label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise DurableSchedulerContractError(f"{label} must be a sequence")
    result = tuple(sorted(_digest(value, label) for value in values))
    if not allow_empty and not result:
        raise DurableSchedulerContractError(f"{label} cannot be empty")
    if len(result) != len(set(result)):
        raise DurableSchedulerContractError(f"{label} contains duplicates")
    return result


def _record_refs(values: Sequence[Any], label: str, prefix: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise DurableSchedulerContractError(f"{label} must be a sequence")
    result = tuple(sorted(_record_id(value, label, prefix) for value in values))
    if len(result) != len(set(result)):
        raise DurableSchedulerContractError(f"{label} contains duplicates")
    return result


def _enum(value: Any, enum_type: type[StrEnum], label: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise DurableSchedulerContractError(f"{label} is invalid") from exc


def _common(record_type: str) -> dict[str, Any]:
    return {
        "effects": dict(NO_EFFECTS),
        "record_type": record_type,
        "schema_version": SCHEMA_VERSION,
    }


def _verify_common(raw: Mapping[str, Any], record_type: str) -> None:
    if (
        raw["schema_version"] != SCHEMA_VERSION
        or raw["record_type"] != record_type
        or raw["effects"] != NO_EFFECTS
    ):
        raise DurableSchedulerContractError("record type, version, or effects are invalid")


def _verify_addressed(raw: Mapping[str, Any], actual: Mapping[str, Any], label: str) -> None:
    if dict(raw) != dict(actual):
        raise DurableSchedulerContractError(f"{label} identity, content, or ordering is invalid")


@dataclass(frozen=True, slots=True)
class RetryBackoffPlan:
    """Bounded retry and dead-letter policy with deterministic delays."""

    retry_plan_id: str
    retry_plan_sha256: str
    max_attempts: int
    retry_budget_units: int
    retry_cost_units: int
    base_delay_seconds: int
    multiplier: int
    maximum_delay_seconds: int

    def __post_init__(self) -> None:
        if self.retry_plan_id:
            _record_id(self.retry_plan_id, "retry_plan_id", "DSP-")
        if self.retry_plan_sha256:
            _digest(self.retry_plan_sha256, "retry_plan_sha256")
        _positive(self.max_attempts, "max_attempts", HARD_LIMITS["retry_attempts"])
        _positive(
            self.retry_budget_units,
            "retry_budget_units",
            HARD_LIMITS["retry_budget_units"],
        )
        _positive(self.retry_cost_units, "retry_cost_units", self.retry_budget_units)
        _positive(self.base_delay_seconds, "base_delay_seconds", 86_400)
        _positive(self.multiplier, "multiplier", 16)
        _positive(self.maximum_delay_seconds, "maximum_delay_seconds", 31_536_000)
        if self.maximum_delay_seconds < self.base_delay_seconds:
            raise DurableSchedulerContractError("maximum delay cannot be below base delay")
        retry_count = self.max_attempts - 1
        if retry_count * self.retry_cost_units > self.retry_budget_units:
            raise DurableSchedulerContractError("retry attempts exceed retry budget")

    def delay_for_next_attempt(self, completed_attempt: int) -> int:
        """Return delay before the attempt following completed_attempt."""

        _positive(completed_attempt, "completed_attempt", self.max_attempts)
        if completed_attempt >= self.max_attempts:
            raise DurableSchedulerContractError("retry attempts are exhausted")
        return min(
            self.maximum_delay_seconds,
            self.base_delay_seconds * (self.multiplier ** (completed_attempt - 1)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common("retry_backoff_plan"),
            "base_delay_seconds": self.base_delay_seconds,
            "max_attempts": self.max_attempts,
            "maximum_delay_seconds": self.maximum_delay_seconds,
            "multiplier": self.multiplier,
            "retry_budget_units": self.retry_budget_units,
            "retry_cost_units": self.retry_cost_units,
            "retry_plan_id": self.retry_plan_id,
            "retry_plan_sha256": self.retry_plan_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetryBackoffPlan:
        fields = {
            "base_delay_seconds",
            "effects",
            "max_attempts",
            "maximum_delay_seconds",
            "multiplier",
            "record_type",
            "retry_budget_units",
            "retry_cost_units",
            "retry_plan_id",
            "retry_plan_sha256",
            "schema_version",
        }
        value = _exact(raw, fields, "retry plan")
        _verify_common(value, "retry_backoff_plan")
        candidate = create_retry_backoff_plan(
            max_attempts=value["max_attempts"],
            retry_budget_units=value["retry_budget_units"],
            retry_cost_units=value["retry_cost_units"],
            base_delay_seconds=value["base_delay_seconds"],
            multiplier=value["multiplier"],
            maximum_delay_seconds=value["maximum_delay_seconds"],
        )
        _verify_addressed(value, candidate.to_dict(), "retry plan")
        return candidate


def create_retry_backoff_plan(
    *,
    max_attempts: int,
    retry_budget_units: int,
    retry_cost_units: int,
    base_delay_seconds: int,
    multiplier: int,
    maximum_delay_seconds: int,
) -> RetryBackoffPlan:
    """Build a content-addressed retry policy without starting timers."""

    candidate = RetryBackoffPlan(
        retry_plan_id="",
        retry_plan_sha256="",
        max_attempts=max_attempts,
        retry_budget_units=retry_budget_units,
        retry_cost_units=retry_cost_units,
        base_delay_seconds=base_delay_seconds,
        multiplier=multiplier,
        maximum_delay_seconds=maximum_delay_seconds,
    )
    body = {
        key: value
        for key, value in candidate.to_dict().items()
        if key not in {"retry_plan_id", "retry_plan_sha256"}
    }
    record_id, digest = _identity("DSP-", "sunderkey.durable-retry-plan.v1", body)
    return replace(candidate, retry_plan_id=record_id, retry_plan_sha256=digest)


@dataclass(frozen=True, slots=True)
class ScheduleDefinition:
    """Immutable tenant-bound interval schedule definition."""

    schedule_id: str
    schedule_sha256: str
    tenant_id: str
    assessment_template_ref: str
    scope_sha256: str
    authority_evidence_sha256: str
    definition_version: int
    starts_at: str
    ends_at: str | None
    interval_seconds: int
    max_occurrences: int
    max_occurrences_per_evaluation: int
    concurrency_limit: int
    lease_duration_seconds: int
    clock_skew_tolerance_seconds: int
    misfire_policy: MisfirePolicy | str
    max_catch_up_occurrences: int
    retry_plan: RetryBackoffPlan

    def __post_init__(self) -> None:
        if self.schedule_id:
            _record_id(self.schedule_id, "schedule_id", "DSD-")
        if self.schedule_sha256:
            _digest(self.schedule_sha256, "schedule_sha256")
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.assessment_template_ref, "assessment_template_ref")
        _digest(self.scope_sha256, "scope_sha256")
        _digest(self.authority_evidence_sha256, "authority_evidence_sha256")
        _positive(self.definition_version, "definition_version", 2_147_483_647)
        _timestamp(self.starts_at, "starts_at")
        if self.ends_at is not None:
            _timestamp(self.ends_at, "ends_at")
            if _instant(self.ends_at) < _instant(self.starts_at):
                raise DurableSchedulerContractError("ends_at cannot precede starts_at")
        _positive(self.interval_seconds, "interval_seconds", 31_536_000)
        _positive(self.max_occurrences, "max_occurrences", HARD_LIMITS["max_occurrences"])
        _positive(
            self.max_occurrences_per_evaluation,
            "max_occurrences_per_evaluation",
            HARD_LIMITS["max_occurrences_per_evaluation"],
        )
        if self.max_occurrences_per_evaluation > self.max_occurrences:
            raise DurableSchedulerContractError(
                "max occurrences per evaluation exceeds schedule maximum"
            )
        _positive(
            self.concurrency_limit,
            "concurrency_limit",
            HARD_LIMITS["concurrency_limit"],
        )
        _positive(
            self.lease_duration_seconds,
            "lease_duration_seconds",
            HARD_LIMITS["lease_duration_seconds"],
        )
        _nonnegative(
            self.clock_skew_tolerance_seconds,
            "clock_skew_tolerance_seconds",
            HARD_LIMITS["clock_skew_tolerance_seconds"],
        )
        object.__setattr__(
            self,
            "misfire_policy",
            _enum(self.misfire_policy, MisfirePolicy, "misfire_policy"),
        )
        _positive(
            self.max_catch_up_occurrences,
            "max_catch_up_occurrences",
            HARD_LIMITS["max_catch_up_occurrences"],
        )
        if self.max_catch_up_occurrences > self.max_occurrences_per_evaluation:
            raise DurableSchedulerContractError("catch-up maximum exceeds per-evaluation maximum")
        if not isinstance(self.retry_plan, RetryBackoffPlan):
            raise DurableSchedulerContractError("retry_plan is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common("schedule_definition"),
            "assessment_template_ref": self.assessment_template_ref,
            "authority_evidence_sha256": self.authority_evidence_sha256,
            "clock_skew_tolerance_seconds": self.clock_skew_tolerance_seconds,
            "concurrency_limit": self.concurrency_limit,
            "definition_version": self.definition_version,
            "ends_at": self.ends_at,
            "interval_seconds": self.interval_seconds,
            "lease_duration_seconds": self.lease_duration_seconds,
            "max_catch_up_occurrences": self.max_catch_up_occurrences,
            "max_occurrences": self.max_occurrences,
            "max_occurrences_per_evaluation": self.max_occurrences_per_evaluation,
            "misfire_policy": self.misfire_policy.value,
            "retry_plan": self.retry_plan.to_dict(),
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "scope_sha256": self.scope_sha256,
            "starts_at": self.starts_at,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ScheduleDefinition:
        fields = {
            "assessment_template_ref",
            "authority_evidence_sha256",
            "clock_skew_tolerance_seconds",
            "concurrency_limit",
            "definition_version",
            "effects",
            "ends_at",
            "interval_seconds",
            "lease_duration_seconds",
            "max_catch_up_occurrences",
            "max_occurrences",
            "max_occurrences_per_evaluation",
            "misfire_policy",
            "record_type",
            "retry_plan",
            "schedule_id",
            "schedule_sha256",
            "schema_version",
            "scope_sha256",
            "starts_at",
            "tenant_id",
        }
        value = _exact(raw, fields, "schedule definition")
        _verify_common(value, "schedule_definition")
        candidate = create_schedule_definition(
            tenant_id=value["tenant_id"],
            assessment_template_ref=value["assessment_template_ref"],
            scope_sha256=value["scope_sha256"],
            authority_evidence_sha256=value["authority_evidence_sha256"],
            definition_version=value["definition_version"],
            starts_at=value["starts_at"],
            ends_at=value["ends_at"],
            interval_seconds=value["interval_seconds"],
            max_occurrences=value["max_occurrences"],
            max_occurrences_per_evaluation=value["max_occurrences_per_evaluation"],
            concurrency_limit=value["concurrency_limit"],
            lease_duration_seconds=value["lease_duration_seconds"],
            clock_skew_tolerance_seconds=value["clock_skew_tolerance_seconds"],
            misfire_policy=value["misfire_policy"],
            max_catch_up_occurrences=value["max_catch_up_occurrences"],
            retry_plan=RetryBackoffPlan.from_dict(value["retry_plan"]),
        )
        _verify_addressed(value, candidate.to_dict(), "schedule definition")
        return candidate


def create_schedule_definition(
    *,
    tenant_id: str,
    assessment_template_ref: str,
    scope_sha256: str,
    authority_evidence_sha256: str,
    definition_version: int,
    starts_at: str,
    ends_at: str | None,
    interval_seconds: int,
    max_occurrences: int,
    max_occurrences_per_evaluation: int,
    concurrency_limit: int,
    lease_duration_seconds: int,
    clock_skew_tolerance_seconds: int,
    misfire_policy: MisfirePolicy | str,
    max_catch_up_occurrences: int,
    retry_plan: RetryBackoffPlan,
) -> ScheduleDefinition:
    """Build a schedule definition without registering or activating it."""

    candidate = ScheduleDefinition(
        schedule_id="",
        schedule_sha256="",
        tenant_id=tenant_id,
        assessment_template_ref=assessment_template_ref,
        scope_sha256=scope_sha256,
        authority_evidence_sha256=authority_evidence_sha256,
        definition_version=definition_version,
        starts_at=starts_at,
        ends_at=ends_at,
        interval_seconds=interval_seconds,
        max_occurrences=max_occurrences,
        max_occurrences_per_evaluation=max_occurrences_per_evaluation,
        concurrency_limit=concurrency_limit,
        lease_duration_seconds=lease_duration_seconds,
        clock_skew_tolerance_seconds=clock_skew_tolerance_seconds,
        misfire_policy=misfire_policy,
        max_catch_up_occurrences=max_catch_up_occurrences,
        retry_plan=retry_plan,
    )
    body = {
        key: value
        for key, value in candidate.to_dict().items()
        if key not in {"schedule_id", "schedule_sha256"}
    }
    record_id, digest = _identity("DSD-", "sunderkey.durable-schedule.v1", body)
    return replace(candidate, schedule_id=record_id, schedule_sha256=digest)


@dataclass(frozen=True, slots=True)
class DueOccurrence:
    """Content-addressed occurrence derived from a schedule and caller time."""

    occurrence_id: str
    occurrence_sha256: str
    tenant_id: str
    schedule_id: str
    schedule_sha256: str
    occurrence_index: int
    nominal_at: str
    evaluated_at: str
    due_reason: DueReason | str
    occurrence_version: int
    idempotency_key: str

    def __post_init__(self) -> None:
        if self.occurrence_id:
            _record_id(self.occurrence_id, "occurrence_id", "DSO-")
        if self.occurrence_sha256:
            _digest(self.occurrence_sha256, "occurrence_sha256")
        _identifier(self.tenant_id, "tenant_id")
        _record_id(self.schedule_id, "schedule_id", "DSD-")
        _digest(self.schedule_sha256, "schedule_sha256")
        _nonnegative(self.occurrence_index, "occurrence_index")
        _timestamp(self.nominal_at, "nominal_at")
        _timestamp(self.evaluated_at, "evaluated_at")
        if _instant(self.nominal_at) > _instant(self.evaluated_at):
            raise DurableSchedulerContractError(
                "occurrence cannot be evaluated before nominal time"
            )
        object.__setattr__(self, "due_reason", _enum(self.due_reason, DueReason, "due_reason"))
        _positive(self.occurrence_version, "occurrence_version", 2_147_483_647)
        _idempotency(self.idempotency_key, "idempotency_key")

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common("due_occurrence"),
            "due_reason": self.due_reason.value,
            "evaluated_at": self.evaluated_at,
            "idempotency_key": self.idempotency_key,
            "nominal_at": self.nominal_at,
            "occurrence_id": self.occurrence_id,
            "occurrence_index": self.occurrence_index,
            "occurrence_sha256": self.occurrence_sha256,
            "occurrence_version": self.occurrence_version,
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DueOccurrence:
        fields = {
            "due_reason",
            "effects",
            "evaluated_at",
            "idempotency_key",
            "nominal_at",
            "occurrence_id",
            "occurrence_index",
            "occurrence_sha256",
            "occurrence_version",
            "record_type",
            "schedule_id",
            "schedule_sha256",
            "schema_version",
            "tenant_id",
        }
        value = _exact(raw, fields, "due occurrence")
        _verify_common(value, "due_occurrence")
        candidate = _create_occurrence(
            tenant_id=value["tenant_id"],
            schedule_id=value["schedule_id"],
            schedule_sha256=value["schedule_sha256"],
            occurrence_index=value["occurrence_index"],
            nominal_at=value["nominal_at"],
            evaluated_at=value["evaluated_at"],
            due_reason=value["due_reason"],
        )
        _verify_addressed(value, candidate.to_dict(), "due occurrence")
        return candidate


def _create_occurrence(
    *,
    tenant_id: str,
    schedule_id: str,
    schedule_sha256: str,
    occurrence_index: int,
    nominal_at: str,
    evaluated_at: str,
    due_reason: DueReason | str,
) -> DueOccurrence:
    key_digest = canonical_sha256(
        {
            "occurrence_index": occurrence_index,
            "schedule_sha256": schedule_sha256,
            "tenant_id": tenant_id,
        }
    )
    candidate = DueOccurrence(
        occurrence_id="",
        occurrence_sha256="",
        tenant_id=tenant_id,
        schedule_id=schedule_id,
        schedule_sha256=schedule_sha256,
        occurrence_index=occurrence_index,
        nominal_at=nominal_at,
        evaluated_at=evaluated_at,
        due_reason=due_reason,
        occurrence_version=1,
        idempotency_key="idem:occurrence:" + key_digest.removeprefix("sha256:"),
    )
    body = {
        key: value
        for key, value in candidate.to_dict().items()
        if key not in {"occurrence_id", "occurrence_sha256"}
    }
    record_id, digest = _identity("DSO-", "sunderkey.durable-occurrence.v1", body)
    return replace(candidate, occurrence_id=record_id, occurrence_sha256=digest)


def derive_due_occurrences(
    schedule: ScheduleDefinition,
    *,
    evaluated_at: str,
    materialized_occurrence_indices: Sequence[int] = (),
) -> tuple[DueOccurrence, ...]:
    """Derive bounded due occurrences from caller-supplied state and time."""

    if not isinstance(schedule, ScheduleDefinition):
        raise DurableSchedulerContractError("schedule is invalid")
    _timestamp(evaluated_at, "evaluated_at")
    evaluated = _instant(evaluated_at)
    start = _instant(schedule.starts_at)
    existing: set[int] = set()
    for index in materialized_occurrence_indices:
        _nonnegative(index, "materialized occurrence index")
        if index >= schedule.max_occurrences:
            raise DurableSchedulerContractError("materialized occurrence exceeds schedule maximum")
        if index in existing:
            raise DurableSchedulerContractError(
                "materialized occurrence indices contain duplicates"
            )
        existing.add(index)
    if evaluated < start:
        return ()
    last_index = int((evaluated - start).total_seconds()) // schedule.interval_seconds
    last_index = min(last_index, schedule.max_occurrences - 1)
    end = None if schedule.ends_at is None else _instant(schedule.ends_at)
    due: list[tuple[int, datetime, DueReason]] = []
    missed: list[tuple[int, datetime]] = []
    tolerance = timedelta(seconds=schedule.clock_skew_tolerance_seconds)
    for index in range(last_index + 1):
        if index in existing:
            continue
        nominal = start + timedelta(seconds=index * schedule.interval_seconds)
        if end is not None and nominal > end:
            break
        if evaluated - nominal > tolerance:
            missed.append((index, nominal))
        else:
            due.append((index, nominal, DueReason.SCHEDULED))
    if schedule.misfire_policy is MisfirePolicy.FIRE_ONCE and missed:
        index, nominal = missed[-1]
        due.append((index, nominal, DueReason.MISFIRE_ONCE))
    elif schedule.misfire_policy is MisfirePolicy.CATCH_UP_BOUNDED:
        for index, nominal in missed[-schedule.max_catch_up_occurrences :]:
            due.append((index, nominal, DueReason.MISFIRE_CATCH_UP))
    due.sort(key=lambda item: item[0])
    if len(due) > schedule.max_occurrences_per_evaluation:
        due = due[-schedule.max_occurrences_per_evaluation :]
    return tuple(
        _create_occurrence(
            tenant_id=schedule.tenant_id,
            schedule_id=schedule.schedule_id,
            schedule_sha256=schedule.schedule_sha256,
            occurrence_index=index,
            nominal_at=_format(nominal),
            evaluated_at=evaluated_at,
            due_reason=reason,
        )
        for index, nominal, reason in due
    )


@dataclass(frozen=True, slots=True)
class DurableLease:
    """Immutable claim or heartbeat snapshot guarded by versions and fencing."""

    lease_id: str
    lease_sha256: str
    tenant_id: str
    schedule_id: str
    schedule_sha256: str
    occurrence_id: str
    occurrence_sha256: str
    worker_ref: str
    attempt_number: int
    fence_epoch: int
    transition: LeaseTransition | str
    lease_version: int
    parent_lease_sha256: str | None
    expected_occurrence_version: int
    leased_at: str
    observed_at: str
    expires_at: str
    idempotency_key: str

    def __post_init__(self) -> None:
        if self.lease_id:
            _record_id(self.lease_id, "lease_id", "DSL-")
        if self.lease_sha256:
            _digest(self.lease_sha256, "lease_sha256")
        _identifier(self.tenant_id, "tenant_id")
        _record_id(self.schedule_id, "schedule_id", "DSD-")
        _digest(self.schedule_sha256, "schedule_sha256")
        _record_id(self.occurrence_id, "occurrence_id", "DSO-")
        _digest(self.occurrence_sha256, "occurrence_sha256")
        _identifier(self.worker_ref, "worker_ref")
        _positive(self.attempt_number, "attempt_number", HARD_LIMITS["retry_attempts"])
        _positive(self.fence_epoch, "fence_epoch", 2_147_483_647)
        object.__setattr__(
            self, "transition", _enum(self.transition, LeaseTransition, "transition")
        )
        _positive(self.lease_version, "lease_version", 2_147_483_647)
        if self.parent_lease_sha256 is not None:
            _digest(self.parent_lease_sha256, "parent_lease_sha256")
        _positive(
            self.expected_occurrence_version,
            "expected_occurrence_version",
            2_147_483_647,
        )
        for name in ("leased_at", "observed_at", "expires_at"):
            _timestamp(getattr(self, name), name)
        if not _instant(self.leased_at) <= _instant(self.observed_at) < _instant(self.expires_at):
            raise DurableSchedulerContractError("lease time ordering is invalid")
        _idempotency(self.idempotency_key, "idempotency_key")
        if self.transition is LeaseTransition.CLAIM:
            if self.lease_version != 1 or self.parent_lease_sha256 is not None:
                raise DurableSchedulerContractError("claim must start lease version 1")
            if self.leased_at != self.observed_at:
                raise DurableSchedulerContractError("claim leased_at must equal observed_at")
        elif self.lease_version < 2 or self.parent_lease_sha256 is None:
            raise DurableSchedulerContractError("heartbeat requires a parent lease")

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common("durable_lease"),
            "attempt_number": self.attempt_number,
            "expected_occurrence_version": self.expected_occurrence_version,
            "expires_at": self.expires_at,
            "fence_epoch": self.fence_epoch,
            "idempotency_key": self.idempotency_key,
            "lease_id": self.lease_id,
            "lease_sha256": self.lease_sha256,
            "lease_version": self.lease_version,
            "leased_at": self.leased_at,
            "observed_at": self.observed_at,
            "occurrence_id": self.occurrence_id,
            "occurrence_sha256": self.occurrence_sha256,
            "parent_lease_sha256": self.parent_lease_sha256,
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "tenant_id": self.tenant_id,
            "transition": self.transition.value,
            "worker_ref": self.worker_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DurableLease:
        fields = {
            "attempt_number",
            "effects",
            "expected_occurrence_version",
            "expires_at",
            "fence_epoch",
            "idempotency_key",
            "lease_id",
            "lease_sha256",
            "lease_version",
            "leased_at",
            "observed_at",
            "occurrence_id",
            "occurrence_sha256",
            "parent_lease_sha256",
            "record_type",
            "schedule_id",
            "schedule_sha256",
            "schema_version",
            "tenant_id",
            "transition",
            "worker_ref",
        }
        value = _exact(raw, fields, "durable lease")
        _verify_common(value, "durable_lease")
        candidate = cls(
            lease_id=value["lease_id"],
            lease_sha256="",
            tenant_id=value["tenant_id"],
            schedule_id=value["schedule_id"],
            schedule_sha256=value["schedule_sha256"],
            occurrence_id=value["occurrence_id"],
            occurrence_sha256=value["occurrence_sha256"],
            worker_ref=value["worker_ref"],
            attempt_number=value["attempt_number"],
            fence_epoch=value["fence_epoch"],
            transition=value["transition"],
            lease_version=value["lease_version"],
            parent_lease_sha256=value["parent_lease_sha256"],
            expected_occurrence_version=value["expected_occurrence_version"],
            leased_at=value["leased_at"],
            observed_at=value["observed_at"],
            expires_at=value["expires_at"],
            idempotency_key=value["idempotency_key"],
        )
        addressed = _address_lease(candidate)
        _verify_addressed(value, addressed.to_dict(), "durable lease")
        return addressed


def _lease_stable_id(candidate: DurableLease) -> str:
    stable = {
        "attempt_number": candidate.attempt_number,
        "fence_epoch": candidate.fence_epoch,
        "occurrence_id": candidate.occurrence_id,
        "schedule_id": candidate.schedule_id,
        "tenant_id": candidate.tenant_id,
        "worker_ref": candidate.worker_ref,
    }
    return _identity("DSL-", "sunderkey.durable-lease-id.v1", stable)[0]


def _address_lease(candidate: DurableLease) -> DurableLease:
    lease_id = candidate.lease_id or _lease_stable_id(candidate)
    if lease_id != _lease_stable_id(candidate):
        raise DurableSchedulerContractError("lease_id does not match stable lease binding")
    body = {
        key: value
        for key, value in replace(candidate, lease_id=lease_id).to_dict().items()
        if key != "lease_sha256"
    }
    digest = canonical_sha256({"body": body, "domain": "sunderkey.durable-lease.v1"})
    return replace(candidate, lease_id=lease_id, lease_sha256=digest)


def _schedule_occurrence(schedule: ScheduleDefinition, occurrence: DueOccurrence) -> None:
    if (
        occurrence.tenant_id != schedule.tenant_id
        or occurrence.schedule_id != schedule.schedule_id
        or occurrence.schedule_sha256 != schedule.schedule_sha256
        or occurrence.occurrence_index >= schedule.max_occurrences
    ):
        raise DurableSchedulerContractError("occurrence is not bound to schedule")


def _active(lease: DurableLease, as_of: str) -> bool:
    return _instant(lease.expires_at) > _instant(as_of)


def assert_no_duplicate_active_leases(leases: Sequence[DurableLease], *, as_of: str) -> None:
    """Reject multiple unexpired lease snapshots for an occurrence."""

    _timestamp(as_of, "as_of")
    active: dict[str, DurableLease] = {}
    latest_by_lease: dict[str, DurableLease] = {}
    for lease in leases:
        if not isinstance(lease, DurableLease):
            raise DurableSchedulerContractError("lease collection contains an invalid record")
        current = latest_by_lease.get(lease.lease_id)
        if current is None or lease.lease_version > current.lease_version:
            latest_by_lease[lease.lease_id] = lease
        elif (
            lease.lease_version == current.lease_version
            and lease.lease_sha256 != current.lease_sha256
        ):
            raise DurableSchedulerContractError("lease version has conflicting content")
    for lease in latest_by_lease.values():
        if not _active(lease, as_of):
            continue
        prior = active.get(lease.occurrence_id)
        if prior is not None and prior.lease_id != lease.lease_id:
            raise DurableSchedulerContractError("occurrence has duplicate active leases")
        active[lease.occurrence_id] = lease


def _idempotent_lease(
    known_leases: Sequence[DurableLease], desired: DurableLease
) -> DurableLease | None:
    for lease in known_leases:
        if lease.idempotency_key != desired.idempotency_key:
            continue
        if lease.to_dict() != desired.to_dict():
            raise DurableSchedulerContractError("lease idempotency key is rebound")
        return lease
    return None


def claim_due_occurrence(
    schedule: ScheduleDefinition,
    occurrence: DueOccurrence,
    *,
    worker_ref: str,
    attempt_number: int,
    fence_epoch: int,
    expected_occurrence_version: int,
    claimed_at: str,
    expires_at: str,
    idempotency_key: str,
    known_leases: Sequence[DurableLease] = (),
) -> DurableLease:
    """Propose a fenced lease claim with no persistence or worker effect."""

    _schedule_occurrence(schedule, occurrence)
    if expected_occurrence_version != occurrence.occurrence_version:
        raise DurableSchedulerContractError("expected occurrence version does not match")
    if attempt_number > schedule.retry_plan.max_attempts:
        raise DurableSchedulerContractError("attempt exceeds retry plan")
    _timestamp(claimed_at, "claimed_at")
    _timestamp(expires_at, "expires_at")
    claimed = _instant(claimed_at)
    nominal = _instant(occurrence.nominal_at)
    if claimed + timedelta(seconds=schedule.clock_skew_tolerance_seconds) < nominal:
        raise DurableSchedulerContractError("claim is earlier than allowed clock skew")
    if _instant(expires_at) - claimed > timedelta(seconds=schedule.lease_duration_seconds):
        raise DurableSchedulerContractError("claim exceeds lease duration")
    candidate = _address_lease(
        DurableLease(
            lease_id="",
            lease_sha256="",
            tenant_id=schedule.tenant_id,
            schedule_id=schedule.schedule_id,
            schedule_sha256=schedule.schedule_sha256,
            occurrence_id=occurrence.occurrence_id,
            occurrence_sha256=occurrence.occurrence_sha256,
            worker_ref=worker_ref,
            attempt_number=attempt_number,
            fence_epoch=fence_epoch,
            transition=LeaseTransition.CLAIM,
            lease_version=1,
            parent_lease_sha256=None,
            expected_occurrence_version=expected_occurrence_version,
            leased_at=claimed_at,
            observed_at=claimed_at,
            expires_at=expires_at,
            idempotency_key=idempotency_key,
        )
    )
    replay = _idempotent_lease(known_leases, candidate)
    if replay is not None:
        return replay
    assert_no_duplicate_active_leases(known_leases, as_of=claimed_at)
    active = {
        lease.lease_id
        for lease in known_leases
        if lease.schedule_id == schedule.schedule_id and _active(lease, claimed_at)
    }
    if len(active) >= schedule.concurrency_limit:
        raise DurableSchedulerContractError("schedule concurrency limit is exhausted")
    for lease in known_leases:
        if lease.occurrence_id == occurrence.occurrence_id and _active(lease, claimed_at):
            raise DurableSchedulerContractError("occurrence already has an active lease")
        if lease.occurrence_id == occurrence.occurrence_id and lease.fence_epoch >= fence_epoch:
            raise DurableSchedulerContractError("fence epoch must advance past prior leases")
    return candidate


def heartbeat_lease(
    schedule: ScheduleDefinition,
    lease: DurableLease,
    *,
    expected_lease_version: int,
    expected_fence_epoch: int,
    observed_at: str,
    expires_at: str,
    idempotency_key: str,
    known_leases: Sequence[DurableLease] = (),
) -> DurableLease:
    """Propose an exact-version heartbeat snapshot without renewing live work."""

    if lease.tenant_id != schedule.tenant_id or lease.schedule_sha256 != schedule.schedule_sha256:
        raise DurableSchedulerContractError("lease is not bound to schedule")
    if expected_lease_version != lease.lease_version:
        raise DurableSchedulerContractError("expected lease version does not match")
    if expected_fence_epoch != lease.fence_epoch:
        raise DurableSchedulerContractError("lease fence does not match")
    _timestamp(observed_at, "observed_at")
    _timestamp(expires_at, "expires_at")
    observed = _instant(observed_at)
    tolerance = timedelta(seconds=schedule.clock_skew_tolerance_seconds)
    if observed > _instant(lease.expires_at) + tolerance:
        raise DurableSchedulerContractError("expired lease cannot be heartbeated")
    if _instant(expires_at) <= _instant(lease.expires_at):
        raise DurableSchedulerContractError("heartbeat must advance lease expiry")
    if _instant(expires_at) - observed > timedelta(seconds=schedule.lease_duration_seconds):
        raise DurableSchedulerContractError("heartbeat exceeds lease duration")
    candidate = _address_lease(
        DurableLease(
            lease_id=lease.lease_id,
            lease_sha256="",
            tenant_id=lease.tenant_id,
            schedule_id=lease.schedule_id,
            schedule_sha256=lease.schedule_sha256,
            occurrence_id=lease.occurrence_id,
            occurrence_sha256=lease.occurrence_sha256,
            worker_ref=lease.worker_ref,
            attempt_number=lease.attempt_number,
            fence_epoch=lease.fence_epoch,
            transition=LeaseTransition.HEARTBEAT,
            lease_version=lease.lease_version + 1,
            parent_lease_sha256=lease.lease_sha256,
            expected_occurrence_version=lease.expected_occurrence_version,
            leased_at=lease.leased_at,
            observed_at=observed_at,
            expires_at=expires_at,
            idempotency_key=idempotency_key,
        )
    )
    replay = _idempotent_lease(known_leases, candidate)
    if replay is not None:
        return replay
    for known in known_leases:
        if (
            known.lease_id == lease.lease_id
            and known.lease_version >= candidate.lease_version
            and known.lease_sha256 != candidate.lease_sha256
        ):
            raise DurableSchedulerContractError("lease version already advanced")
    others = tuple(item for item in known_leases if item.lease_id != lease.lease_id)
    assert_no_duplicate_active_leases((*others, candidate), as_of=observed_at)
    return candidate


@dataclass(frozen=True, slots=True)
class CompletionObservation:
    """Immutable outcome and bounded retry or dead-letter resolution."""

    completion_id: str
    completion_sha256: str
    tenant_id: str
    schedule_id: str
    schedule_sha256: str
    occurrence_id: str
    occurrence_sha256: str
    lease_id: str
    lease_sha256: str
    expected_lease_version: int
    expected_fence_epoch: int
    expected_occurrence_version: int
    new_occurrence_version: int
    attempt_number: int
    status: CompletionStatus | str
    resolution: CompletionResolution | str
    observed_at: str
    retry_at: str | None
    retry_delay_seconds: int | None
    retry_budget_consumed_units: int
    evidence_sha256s: tuple[str, ...]
    idempotency_key: str

    def __post_init__(self) -> None:
        if self.completion_id:
            _record_id(self.completion_id, "completion_id", "DSC-")
        if self.completion_sha256:
            _digest(self.completion_sha256, "completion_sha256")
        _identifier(self.tenant_id, "tenant_id")
        _record_id(self.schedule_id, "schedule_id", "DSD-")
        _digest(self.schedule_sha256, "schedule_sha256")
        _record_id(self.occurrence_id, "occurrence_id", "DSO-")
        _digest(self.occurrence_sha256, "occurrence_sha256")
        _record_id(self.lease_id, "lease_id", "DSL-")
        _digest(self.lease_sha256, "lease_sha256")
        _positive(self.expected_lease_version, "expected_lease_version", 2_147_483_647)
        _positive(self.expected_fence_epoch, "expected_fence_epoch", 2_147_483_647)
        _positive(
            self.expected_occurrence_version,
            "expected_occurrence_version",
            2_147_483_647,
        )
        if self.new_occurrence_version != self.expected_occurrence_version + 1:
            raise DurableSchedulerContractError(
                "new occurrence version must increment exactly once"
            )
        _positive(self.attempt_number, "attempt_number", HARD_LIMITS["retry_attempts"])
        object.__setattr__(self, "status", _enum(self.status, CompletionStatus, "status"))
        object.__setattr__(
            self,
            "resolution",
            _enum(self.resolution, CompletionResolution, "resolution"),
        )
        _timestamp(self.observed_at, "observed_at")
        if (self.retry_at is None) != (self.retry_delay_seconds is None):
            raise DurableSchedulerContractError("retry time and delay must be present together")
        if self.retry_at is not None:
            _timestamp(self.retry_at, "retry_at")
            _positive(self.retry_delay_seconds, "retry_delay_seconds", 31_536_000)
            if _instant(self.retry_at) != _instant(self.observed_at) + timedelta(
                seconds=self.retry_delay_seconds
            ):
                raise DurableSchedulerContractError("retry time does not match delay")
        allowed_resolutions = {
            CompletionStatus.SUCCEEDED: {CompletionResolution.COMPLETED},
            CompletionStatus.RETRYABLE_FAILURE: {
                CompletionResolution.RETRY_PLANNED,
                CompletionResolution.DEAD_LETTERED,
            },
            CompletionStatus.PERMANENT_FAILURE: {CompletionResolution.DEAD_LETTERED},
            CompletionStatus.CANCELLED: {CompletionResolution.CANCELLED},
        }
        if self.resolution not in allowed_resolutions[self.status]:
            raise DurableSchedulerContractError("completion status and resolution are inconsistent")
        if self.resolution is CompletionResolution.RETRY_PLANNED:
            if self.retry_at is None or self.retry_delay_seconds is None:
                raise DurableSchedulerContractError("retry resolution requires retry timing")
        elif self.retry_at is not None or self.retry_delay_seconds is not None:
            raise DurableSchedulerContractError("terminal resolution cannot include retry timing")
        _nonnegative(
            self.retry_budget_consumed_units,
            "retry_budget_consumed_units",
            HARD_LIMITS["retry_budget_units"],
        )
        object.__setattr__(
            self,
            "evidence_sha256s",
            _digests(self.evidence_sha256s, "evidence_sha256s"),
        )
        _idempotency(self.idempotency_key, "idempotency_key")

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common("completion_observation"),
            "attempt_number": self.attempt_number,
            "completion_id": self.completion_id,
            "completion_sha256": self.completion_sha256,
            "evidence_sha256s": list(self.evidence_sha256s),
            "expected_fence_epoch": self.expected_fence_epoch,
            "expected_lease_version": self.expected_lease_version,
            "expected_occurrence_version": self.expected_occurrence_version,
            "idempotency_key": self.idempotency_key,
            "lease_id": self.lease_id,
            "lease_sha256": self.lease_sha256,
            "new_occurrence_version": self.new_occurrence_version,
            "observed_at": self.observed_at,
            "occurrence_id": self.occurrence_id,
            "occurrence_sha256": self.occurrence_sha256,
            "resolution": self.resolution.value,
            "retry_at": self.retry_at,
            "retry_budget_consumed_units": self.retry_budget_consumed_units,
            "retry_delay_seconds": self.retry_delay_seconds,
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "status": self.status.value,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CompletionObservation:
        fields = {
            "attempt_number",
            "completion_id",
            "completion_sha256",
            "effects",
            "evidence_sha256s",
            "expected_fence_epoch",
            "expected_lease_version",
            "expected_occurrence_version",
            "idempotency_key",
            "lease_id",
            "lease_sha256",
            "new_occurrence_version",
            "observed_at",
            "occurrence_id",
            "occurrence_sha256",
            "record_type",
            "resolution",
            "retry_at",
            "retry_budget_consumed_units",
            "retry_delay_seconds",
            "schedule_id",
            "schedule_sha256",
            "schema_version",
            "status",
            "tenant_id",
        }
        value = _exact(raw, fields, "completion observation")
        _verify_common(value, "completion_observation")
        candidate = cls(
            completion_id="",
            completion_sha256="",
            tenant_id=value["tenant_id"],
            schedule_id=value["schedule_id"],
            schedule_sha256=value["schedule_sha256"],
            occurrence_id=value["occurrence_id"],
            occurrence_sha256=value["occurrence_sha256"],
            lease_id=value["lease_id"],
            lease_sha256=value["lease_sha256"],
            expected_lease_version=value["expected_lease_version"],
            expected_fence_epoch=value["expected_fence_epoch"],
            expected_occurrence_version=value["expected_occurrence_version"],
            new_occurrence_version=value["new_occurrence_version"],
            attempt_number=value["attempt_number"],
            status=value["status"],
            resolution=value["resolution"],
            observed_at=value["observed_at"],
            retry_at=value["retry_at"],
            retry_delay_seconds=value["retry_delay_seconds"],
            retry_budget_consumed_units=value["retry_budget_consumed_units"],
            evidence_sha256s=tuple(_sequence(value["evidence_sha256s"], "evidence_sha256s")),
            idempotency_key=value["idempotency_key"],
        )
        addressed = _address_completion(candidate)
        _verify_addressed(value, addressed.to_dict(), "completion observation")
        return addressed


def _address_completion(candidate: CompletionObservation) -> CompletionObservation:
    body = {
        key: value
        for key, value in candidate.to_dict().items()
        if key not in {"completion_id", "completion_sha256"}
    }
    record_id, digest = _identity("DSC-", "sunderkey.durable-completion.v1", body)
    if candidate.completion_id and candidate.completion_id != record_id:
        raise DurableSchedulerContractError("completion_id is invalid")
    return replace(candidate, completion_id=record_id, completion_sha256=digest)


def observe_completion(
    schedule: ScheduleDefinition,
    occurrence: DueOccurrence,
    lease: DurableLease,
    *,
    expected_lease_version: int,
    expected_fence_epoch: int,
    expected_occurrence_version: int,
    status: CompletionStatus | str,
    observed_at: str,
    evidence_sha256s: Sequence[str],
    idempotency_key: str,
    known_observations: Sequence[CompletionObservation] = (),
) -> CompletionObservation:
    """Resolve a supplied result to terminal, retry, or dead-letter state."""

    _schedule_occurrence(schedule, occurrence)
    if (
        lease.tenant_id != schedule.tenant_id
        or lease.schedule_sha256 != schedule.schedule_sha256
        or lease.occurrence_sha256 != occurrence.occurrence_sha256
    ):
        raise DurableSchedulerContractError("lease is not bound to occurrence")
    if expected_lease_version != lease.lease_version:
        raise DurableSchedulerContractError("expected lease version does not match")
    if expected_fence_epoch != lease.fence_epoch:
        raise DurableSchedulerContractError("expected fence epoch does not match")
    if expected_occurrence_version != occurrence.occurrence_version:
        raise DurableSchedulerContractError("expected occurrence version does not match")
    _timestamp(observed_at, "observed_at")
    if _instant(observed_at) > _instant(lease.expires_at) + timedelta(
        seconds=schedule.clock_skew_tolerance_seconds
    ):
        raise DurableSchedulerContractError("completion is outside the lease clock-skew bound")
    normalized_status = _enum(status, CompletionStatus, "status")
    retry_at: str | None = None
    retry_delay: int | None = None
    consumed = max(0, lease.attempt_number - 1) * schedule.retry_plan.retry_cost_units
    if normalized_status is CompletionStatus.SUCCEEDED:
        resolution = CompletionResolution.COMPLETED
    elif normalized_status is CompletionStatus.CANCELLED:
        resolution = CompletionResolution.CANCELLED
    elif normalized_status is CompletionStatus.RETRYABLE_FAILURE:
        next_budget = lease.attempt_number * schedule.retry_plan.retry_cost_units
        if (
            lease.attempt_number < schedule.retry_plan.max_attempts
            and next_budget <= schedule.retry_plan.retry_budget_units
        ):
            resolution = CompletionResolution.RETRY_PLANNED
            retry_delay = schedule.retry_plan.delay_for_next_attempt(lease.attempt_number)
            retry_at = _format(_instant(observed_at) + timedelta(seconds=retry_delay))
            consumed = next_budget
        else:
            resolution = CompletionResolution.DEAD_LETTERED
    else:
        resolution = CompletionResolution.DEAD_LETTERED
    candidate = _address_completion(
        CompletionObservation(
            completion_id="",
            completion_sha256="",
            tenant_id=schedule.tenant_id,
            schedule_id=schedule.schedule_id,
            schedule_sha256=schedule.schedule_sha256,
            occurrence_id=occurrence.occurrence_id,
            occurrence_sha256=occurrence.occurrence_sha256,
            lease_id=lease.lease_id,
            lease_sha256=lease.lease_sha256,
            expected_lease_version=expected_lease_version,
            expected_fence_epoch=expected_fence_epoch,
            expected_occurrence_version=expected_occurrence_version,
            new_occurrence_version=expected_occurrence_version + 1,
            attempt_number=lease.attempt_number,
            status=normalized_status,
            resolution=resolution,
            observed_at=observed_at,
            retry_at=retry_at,
            retry_delay_seconds=retry_delay,
            retry_budget_consumed_units=consumed,
            evidence_sha256s=tuple(evidence_sha256s),
            idempotency_key=idempotency_key,
        )
    )
    for known in known_observations:
        if known.idempotency_key == candidate.idempotency_key:
            if known.to_dict() != candidate.to_dict():
                raise DurableSchedulerContractError("completion idempotency key is rebound")
            return known
        if known.lease_id == lease.lease_id and known.lease_sha256 == lease.lease_sha256:
            raise DurableSchedulerContractError("lease already has a completion observation")
    return candidate


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    """Immutable replay-safe disposition for one expired lease."""

    recovery_id: str
    recovery_sha256: str
    tenant_id: str
    schedule_id: str
    schedule_sha256: str
    occurrence_id: str
    occurrence_sha256: str
    expired_lease_id: str
    expired_lease_sha256: str
    expired_lease_version: int
    prior_fence_epoch: int
    next_fence_epoch: int
    expected_occurrence_version: int
    new_occurrence_version: int
    disposition: RecoveryDisposition | str
    recovered_at: str
    next_attempt_number: int | None
    retry_at: str | None
    observed_completion_sha256s: tuple[str, ...]
    idempotency_key: str

    def __post_init__(self) -> None:
        if self.recovery_id:
            _record_id(self.recovery_id, "recovery_id", "DSR-")
        if self.recovery_sha256:
            _digest(self.recovery_sha256, "recovery_sha256")
        _identifier(self.tenant_id, "tenant_id")
        _record_id(self.schedule_id, "schedule_id", "DSD-")
        _digest(self.schedule_sha256, "schedule_sha256")
        _record_id(self.occurrence_id, "occurrence_id", "DSO-")
        _digest(self.occurrence_sha256, "occurrence_sha256")
        _record_id(self.expired_lease_id, "expired_lease_id", "DSL-")
        _digest(self.expired_lease_sha256, "expired_lease_sha256")
        _positive(self.expired_lease_version, "expired_lease_version", 2_147_483_647)
        _positive(self.prior_fence_epoch, "prior_fence_epoch", 2_147_483_647)
        if self.next_fence_epoch != self.prior_fence_epoch + 1:
            raise DurableSchedulerContractError("recovery fence must increment exactly once")
        _positive(
            self.expected_occurrence_version,
            "expected_occurrence_version",
            2_147_483_647,
        )
        if self.new_occurrence_version != self.expected_occurrence_version + 1:
            raise DurableSchedulerContractError("recovery version must increment exactly once")
        object.__setattr__(
            self,
            "disposition",
            _enum(self.disposition, RecoveryDisposition, "disposition"),
        )
        _timestamp(self.recovered_at, "recovered_at")
        if self.disposition is RecoveryDisposition.REQUEUE:
            _positive(
                self.next_attempt_number,
                "next_attempt_number",
                HARD_LIMITS["retry_attempts"],
            )
            _timestamp(self.retry_at, "retry_at")
        elif self.next_attempt_number is not None or self.retry_at is not None:
            raise DurableSchedulerContractError("dead-letter recovery cannot schedule retry")
        object.__setattr__(
            self,
            "observed_completion_sha256s",
            _digests(self.observed_completion_sha256s, "observed_completion_sha256s"),
        )
        _idempotency(self.idempotency_key, "idempotency_key")

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common("recovery_plan"),
            "disposition": self.disposition.value,
            "expected_occurrence_version": self.expected_occurrence_version,
            "expired_lease_id": self.expired_lease_id,
            "expired_lease_sha256": self.expired_lease_sha256,
            "expired_lease_version": self.expired_lease_version,
            "idempotency_key": self.idempotency_key,
            "new_occurrence_version": self.new_occurrence_version,
            "next_attempt_number": self.next_attempt_number,
            "next_fence_epoch": self.next_fence_epoch,
            "observed_completion_sha256s": list(self.observed_completion_sha256s),
            "occurrence_id": self.occurrence_id,
            "occurrence_sha256": self.occurrence_sha256,
            "prior_fence_epoch": self.prior_fence_epoch,
            "recovered_at": self.recovered_at,
            "recovery_id": self.recovery_id,
            "recovery_sha256": self.recovery_sha256,
            "retry_at": self.retry_at,
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RecoveryPlan:
        fields = {
            "disposition",
            "effects",
            "expected_occurrence_version",
            "expired_lease_id",
            "expired_lease_sha256",
            "expired_lease_version",
            "idempotency_key",
            "new_occurrence_version",
            "next_attempt_number",
            "next_fence_epoch",
            "observed_completion_sha256s",
            "occurrence_id",
            "occurrence_sha256",
            "prior_fence_epoch",
            "record_type",
            "recovered_at",
            "recovery_id",
            "recovery_sha256",
            "retry_at",
            "schedule_id",
            "schedule_sha256",
            "schema_version",
            "tenant_id",
        }
        value = _exact(raw, fields, "recovery plan")
        _verify_common(value, "recovery_plan")
        candidate = cls(
            recovery_id="",
            recovery_sha256="",
            tenant_id=value["tenant_id"],
            schedule_id=value["schedule_id"],
            schedule_sha256=value["schedule_sha256"],
            occurrence_id=value["occurrence_id"],
            occurrence_sha256=value["occurrence_sha256"],
            expired_lease_id=value["expired_lease_id"],
            expired_lease_sha256=value["expired_lease_sha256"],
            expired_lease_version=value["expired_lease_version"],
            prior_fence_epoch=value["prior_fence_epoch"],
            next_fence_epoch=value["next_fence_epoch"],
            expected_occurrence_version=value["expected_occurrence_version"],
            new_occurrence_version=value["new_occurrence_version"],
            disposition=value["disposition"],
            recovered_at=value["recovered_at"],
            next_attempt_number=value["next_attempt_number"],
            retry_at=value["retry_at"],
            observed_completion_sha256s=tuple(
                _sequence(value["observed_completion_sha256s"], "observed completion digests")
            ),
            idempotency_key=value["idempotency_key"],
        )
        addressed = _address_recovery(candidate)
        _verify_addressed(value, addressed.to_dict(), "recovery plan")
        return addressed


def _address_recovery(candidate: RecoveryPlan) -> RecoveryPlan:
    body = {
        key: value
        for key, value in candidate.to_dict().items()
        if key not in {"recovery_id", "recovery_sha256"}
    }
    record_id, digest = _identity("DSR-", "sunderkey.durable-recovery.v1", body)
    if candidate.recovery_id and candidate.recovery_id != record_id:
        raise DurableSchedulerContractError("recovery_id is invalid")
    return replace(candidate, recovery_id=record_id, recovery_sha256=digest)


def plan_expired_lease_recovery(
    schedule: ScheduleDefinition,
    occurrence: DueOccurrence,
    lease: DurableLease,
    *,
    expected_occurrence_version: int,
    recovered_at: str,
    idempotency_key: str,
    known_completions: Sequence[CompletionObservation] = (),
    known_recoveries: Sequence[RecoveryPlan] = (),
) -> RecoveryPlan:
    """Propose requeue or dead-letter handling for an expired lease."""

    _schedule_occurrence(schedule, occurrence)
    if lease.occurrence_sha256 != occurrence.occurrence_sha256:
        raise DurableSchedulerContractError("lease is not bound to occurrence")
    if expected_occurrence_version != occurrence.occurrence_version:
        raise DurableSchedulerContractError("expected occurrence version does not match")
    _timestamp(recovered_at, "recovered_at")
    if _instant(recovered_at) <= _instant(lease.expires_at) + timedelta(
        seconds=schedule.clock_skew_tolerance_seconds
    ):
        raise DurableSchedulerContractError("lease is not expired beyond clock skew")
    completion_digests = tuple(
        item.completion_sha256 for item in known_completions if item.lease_id == lease.lease_id
    )
    if completion_digests:
        raise DurableSchedulerContractError("completed lease cannot enter recovery")
    next_attempt = lease.attempt_number + 1
    next_budget = lease.attempt_number * schedule.retry_plan.retry_cost_units
    if (
        next_attempt <= schedule.retry_plan.max_attempts
        and next_budget <= schedule.retry_plan.retry_budget_units
    ):
        disposition = RecoveryDisposition.REQUEUE
        delay = schedule.retry_plan.delay_for_next_attempt(lease.attempt_number)
        retry_at = _format(_instant(recovered_at) + timedelta(seconds=delay))
    else:
        disposition = RecoveryDisposition.DEAD_LETTER
        next_attempt = None
        retry_at = None
    candidate = _address_recovery(
        RecoveryPlan(
            recovery_id="",
            recovery_sha256="",
            tenant_id=schedule.tenant_id,
            schedule_id=schedule.schedule_id,
            schedule_sha256=schedule.schedule_sha256,
            occurrence_id=occurrence.occurrence_id,
            occurrence_sha256=occurrence.occurrence_sha256,
            expired_lease_id=lease.lease_id,
            expired_lease_sha256=lease.lease_sha256,
            expired_lease_version=lease.lease_version,
            prior_fence_epoch=lease.fence_epoch,
            next_fence_epoch=lease.fence_epoch + 1,
            expected_occurrence_version=expected_occurrence_version,
            new_occurrence_version=expected_occurrence_version + 1,
            disposition=disposition,
            recovered_at=recovered_at,
            next_attempt_number=next_attempt,
            retry_at=retry_at,
            observed_completion_sha256s=completion_digests,
            idempotency_key=idempotency_key,
        )
    )
    for known in known_recoveries:
        if known.idempotency_key == candidate.idempotency_key:
            if known.to_dict() != candidate.to_dict():
                raise DurableSchedulerContractError("recovery idempotency key is rebound")
            return known
        if known.expired_lease_sha256 == lease.lease_sha256:
            raise DurableSchedulerContractError("expired lease already has a recovery plan")
    return candidate


@dataclass(frozen=True, slots=True)
class CancellationRecord:
    """Immutable versioned cancellation intent with lease revocation bindings."""

    cancellation_id: str
    cancellation_sha256: str
    tenant_id: str
    schedule_id: str
    schedule_sha256: str
    target: CancellationTarget | str
    occurrence_id: str | None
    occurrence_sha256: str | None
    expected_version: int
    new_version: int
    requested_at: str
    reason_code: str
    revoked_lease_ids: tuple[str, ...]
    revoked_lease_sha256s: tuple[str, ...]
    idempotency_key: str

    def __post_init__(self) -> None:
        if self.cancellation_id:
            _record_id(self.cancellation_id, "cancellation_id", "DSX-")
        if self.cancellation_sha256:
            _digest(self.cancellation_sha256, "cancellation_sha256")
        _identifier(self.tenant_id, "tenant_id")
        _record_id(self.schedule_id, "schedule_id", "DSD-")
        _digest(self.schedule_sha256, "schedule_sha256")
        object.__setattr__(self, "target", _enum(self.target, CancellationTarget, "target"))
        if self.target is CancellationTarget.OCCURRENCE:
            _record_id(self.occurrence_id, "occurrence_id", "DSO-")
            _digest(self.occurrence_sha256, "occurrence_sha256")
        elif self.occurrence_id is not None or self.occurrence_sha256 is not None:
            raise DurableSchedulerContractError("schedule cancellation cannot bind occurrence")
        _positive(self.expected_version, "expected_version", 2_147_483_647)
        if self.new_version != self.expected_version + 1:
            raise DurableSchedulerContractError("cancellation version must increment exactly once")
        _timestamp(self.requested_at, "requested_at")
        _token(self.reason_code, "reason_code")
        object.__setattr__(
            self,
            "revoked_lease_ids",
            _record_refs(self.revoked_lease_ids, "revoked_lease_ids", "DSL-"),
        )
        object.__setattr__(
            self,
            "revoked_lease_sha256s",
            _digests(self.revoked_lease_sha256s, "revoked_lease_sha256s"),
        )
        if len(self.revoked_lease_ids) != len(self.revoked_lease_sha256s):
            raise DurableSchedulerContractError("revoked lease identifiers and digests differ")
        _idempotency(self.idempotency_key, "idempotency_key")

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common("cancellation_record"),
            "cancellation_id": self.cancellation_id,
            "cancellation_sha256": self.cancellation_sha256,
            "expected_version": self.expected_version,
            "idempotency_key": self.idempotency_key,
            "new_version": self.new_version,
            "occurrence_id": self.occurrence_id,
            "occurrence_sha256": self.occurrence_sha256,
            "reason_code": self.reason_code,
            "requested_at": self.requested_at,
            "revoked_lease_ids": list(self.revoked_lease_ids),
            "revoked_lease_sha256s": list(self.revoked_lease_sha256s),
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "target": self.target.value,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CancellationRecord:
        fields = {
            "cancellation_id",
            "cancellation_sha256",
            "effects",
            "expected_version",
            "idempotency_key",
            "new_version",
            "occurrence_id",
            "occurrence_sha256",
            "reason_code",
            "record_type",
            "requested_at",
            "revoked_lease_ids",
            "revoked_lease_sha256s",
            "schedule_id",
            "schedule_sha256",
            "schema_version",
            "target",
            "tenant_id",
        }
        value = _exact(raw, fields, "cancellation record")
        _verify_common(value, "cancellation_record")
        candidate = cls(
            cancellation_id="",
            cancellation_sha256="",
            tenant_id=value["tenant_id"],
            schedule_id=value["schedule_id"],
            schedule_sha256=value["schedule_sha256"],
            target=value["target"],
            occurrence_id=value["occurrence_id"],
            occurrence_sha256=value["occurrence_sha256"],
            expected_version=value["expected_version"],
            new_version=value["new_version"],
            requested_at=value["requested_at"],
            reason_code=value["reason_code"],
            revoked_lease_ids=tuple(_sequence(value["revoked_lease_ids"], "revoked leases")),
            revoked_lease_sha256s=tuple(
                _sequence(value["revoked_lease_sha256s"], "revoked lease digests")
            ),
            idempotency_key=value["idempotency_key"],
        )
        addressed = _address_cancellation(candidate)
        _verify_addressed(value, addressed.to_dict(), "cancellation record")
        return addressed


def _address_cancellation(candidate: CancellationRecord) -> CancellationRecord:
    body = {
        key: value
        for key, value in candidate.to_dict().items()
        if key not in {"cancellation_id", "cancellation_sha256"}
    }
    record_id, digest = _identity("DSX-", "sunderkey.durable-cancellation.v1", body)
    if candidate.cancellation_id and candidate.cancellation_id != record_id:
        raise DurableSchedulerContractError("cancellation_id is invalid")
    return replace(candidate, cancellation_id=record_id, cancellation_sha256=digest)


def create_cancellation_record(
    schedule: ScheduleDefinition,
    *,
    target: CancellationTarget | str,
    expected_version: int,
    requested_at: str,
    reason_code: str,
    active_leases: Sequence[DurableLease],
    idempotency_key: str,
    occurrence: DueOccurrence | None = None,
    known_cancellations: Sequence[CancellationRecord] = (),
) -> CancellationRecord:
    """Create a cancellation intent without mutating the schedule or leases."""

    normalized_target = _enum(target, CancellationTarget, "target")
    if normalized_target is CancellationTarget.OCCURRENCE:
        if occurrence is None:
            raise DurableSchedulerContractError("occurrence cancellation requires occurrence")
        _schedule_occurrence(schedule, occurrence)
        if expected_version != occurrence.occurrence_version:
            raise DurableSchedulerContractError("expected occurrence version does not match")
    else:
        if occurrence is not None:
            raise DurableSchedulerContractError("schedule cancellation cannot include occurrence")
        if expected_version != schedule.definition_version:
            raise DurableSchedulerContractError("expected schedule version does not match")
    assert_no_duplicate_active_leases(active_leases, as_of=requested_at)
    matching = tuple(
        lease
        for lease in active_leases
        if lease.tenant_id == schedule.tenant_id
        and lease.schedule_id == schedule.schedule_id
        and _active(lease, requested_at)
        and (
            normalized_target is CancellationTarget.SCHEDULE
            or lease.occurrence_id == occurrence.occurrence_id
        )
    )
    matching = tuple(sorted(matching, key=lambda item: item.lease_id))
    candidate = _address_cancellation(
        CancellationRecord(
            cancellation_id="",
            cancellation_sha256="",
            tenant_id=schedule.tenant_id,
            schedule_id=schedule.schedule_id,
            schedule_sha256=schedule.schedule_sha256,
            target=normalized_target,
            occurrence_id=None if occurrence is None else occurrence.occurrence_id,
            occurrence_sha256=None if occurrence is None else occurrence.occurrence_sha256,
            expected_version=expected_version,
            new_version=expected_version + 1,
            requested_at=requested_at,
            reason_code=reason_code,
            revoked_lease_ids=tuple(item.lease_id for item in matching),
            revoked_lease_sha256s=tuple(item.lease_sha256 for item in matching),
            idempotency_key=idempotency_key,
        )
    )
    for known in known_cancellations:
        if known.idempotency_key == candidate.idempotency_key:
            if known.to_dict() != candidate.to_dict():
                raise DurableSchedulerContractError("cancellation idempotency key is rebound")
            return known
    return candidate


ContractRecord = (
    RetryBackoffPlan
    | ScheduleDefinition
    | DueOccurrence
    | DurableLease
    | CompletionObservation
    | RecoveryPlan
    | CancellationRecord
)


def parse_contract(raw: Any) -> ContractRecord:
    """Parse any scheduler record with strict fields and digest verification."""

    if not isinstance(raw, Mapping):
        raise DurableSchedulerContractError("scheduler record must be a mapping")
    record_type = raw.get("record_type")
    parsers = {
        "retry_backoff_plan": RetryBackoffPlan.from_dict,
        "schedule_definition": ScheduleDefinition.from_dict,
        "due_occurrence": DueOccurrence.from_dict,
        "durable_lease": DurableLease.from_dict,
        "completion_observation": CompletionObservation.from_dict,
        "recovery_plan": RecoveryPlan.from_dict,
        "cancellation_record": CancellationRecord.from_dict,
    }
    parser = parsers.get(record_type)
    if parser is None:
        raise DurableSchedulerContractError("scheduler record_type is invalid")
    return parser(raw)


__all__ = [
    "CancellationRecord",
    "CancellationTarget",
    "CompletionObservation",
    "CompletionResolution",
    "CompletionStatus",
    "DueOccurrence",
    "DueReason",
    "DurableLease",
    "DurableSchedulerContractError",
    "LeaseTransition",
    "MisfirePolicy",
    "NO_EFFECTS",
    "RecoveryDisposition",
    "RecoveryPlan",
    "RetryBackoffPlan",
    "SCHEMA_VERSION",
    "ScheduleDefinition",
    "assert_no_duplicate_active_leases",
    "canonical_json",
    "canonical_sha256",
    "claim_due_occurrence",
    "create_cancellation_record",
    "create_retry_backoff_plan",
    "create_schedule_definition",
    "derive_due_occurrences",
    "heartbeat_lease",
    "observe_completion",
    "parse_contract",
    "plan_expired_lease_recovery",
]
