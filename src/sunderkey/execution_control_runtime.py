"""Fail-closed execution controls around a caller-supplied transport.

The runtime has no built-in network, filesystem, credential, or authorization
capability. It can call only the injected transport, and only after it verifies
an exact state transition returned by the injected state repository.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, ClassVar, Protocol

SCHEMA_VERSION = 1
NO_BUILTIN_IO = True
ENFORCEMENT_BOUNDARY = "injected_adapter_boundary_only"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")


class ExecutionControlError(ValueError):
    """Raised when an execution-control value or transition fails closed."""


class RateMode(StrEnum):
    FIXED_WINDOW = "fixed_window"
    INTEGER_TOKEN_BUCKET = "integer_token_bucket"


class HealthState(StrEnum):
    HEALTHY = "healthy"
    PAUSED = "paused"
    UNHEALTHY = "unhealthy"


class AdmissionStatus(StrEnum):
    ADMITTED = "admitted"
    BLOCKED = "blocked"


class ExecutionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    TRANSPORT_FAILED = "transport_failed"
    COMPLETION_FAILED = "completion_failed"


class RetryDisposition(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    RETRY_PERMITTED = "retry_permitted"
    RETRY_EXHAUSTED = "retry_exhausted"
    FAILURE_NOT_RETRYABLE = "failure_not_retryable"


class CleanupStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING_EXTERNAL_VERIFICATION = "pending_external_verification"


class BlockReason(StrEnum):
    OUTSIDE_ALLOWED_WINDOW = "outside_allowed_window"
    RATE_EXHAUSTED = "rate_exhausted"
    BYTE_BUDGET_EXHAUSTED = "byte_budget_exhausted"
    SESSION_LIMIT_EXHAUSTED = "session_limit_exhausted"
    SEQUENTIAL_CONFLICT = "sequential_conflict"
    LEASE_EXPIRED = "lease_expired"
    STALE_FENCE = "stale_fence"
    TIME_ROLLBACK = "time_rollback"
    HEALTH_PAUSED = "health_paused"
    HEALTH_UNHEALTHY = "health_unhealthy"
    CANCELED = "canceled"
    EMERGENCY_STOP = "emergency_stop"
    ATTEMPT_BUDGET_EXHAUSTED = "attempt_budget_exhausted"
    BINDING_MISMATCH = "binding_mismatch"
    IDEMPOTENCY_REBINDING = "idempotency_rebinding"
    STATE_TAMPERING = "state_tampering"
    STATE_REPOSITORY_FAILURE = "state_repository_failure"


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ExecutionControlError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: dict[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": body, "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ExecutionControlError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ExecutionControlError(f"{label} must be a sha256 digest")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        raise ExecutionControlError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ExecutionControlError(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ExecutionControlError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ExecutionControlError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ExecutionControlError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


@dataclass(frozen=True, slots=True)
class ClockObservation:
    observed_at: str
    monotonic_tick: int

    def __post_init__(self) -> None:
        _utc(self.observed_at, "observed_at")
        _integer(self.monotonic_tick, "monotonic_tick", 1)


class ExecutionClock(Protocol):
    def observe(self) -> ClockObservation: ...


@dataclass(frozen=True, slots=True)
class AllowedUtcWindow:
    starts_at: str
    ends_at: str

    def __post_init__(self) -> None:
        _utc(self.starts_at, "starts_at")
        _utc(self.ends_at, "ends_at")
        if _instant(self.ends_at) <= _instant(self.starts_at):
            raise ExecutionControlError("allowed window end must follow start")

    def includes(self, observed_at: str) -> bool:
        value = _instant(observed_at)
        return _instant(self.starts_at) <= value < _instant(self.ends_at)

    def to_dict(self) -> dict[str, str]:
        return {"ends_at": self.ends_at, "starts_at": self.starts_at}


@dataclass(frozen=True, slots=True)
class ExecutionBinding:
    tenant_id: str
    context_id: str
    context_sha256: str
    scope_id: str
    scope_sha256: str
    target_id: str
    target_sha256: str
    session_id: str
    lease_id: str
    fence_epoch: int

    def __post_init__(self) -> None:
        for label in (
            "tenant_id",
            "context_id",
            "scope_id",
            "target_id",
            "session_id",
            "lease_id",
        ):
            _identifier(getattr(self, label), label)
        _digest(self.context_sha256, "context_sha256")
        _digest(self.scope_sha256, "scope_sha256")
        _digest(self.target_sha256, "target_sha256")
        _integer(self.fence_epoch, "fence_epoch", 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "context_sha256": self.context_sha256,
            "fence_epoch": self.fence_epoch,
            "lease_id": self.lease_id,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "session_id": self.session_id,
            "target_id": self.target_id,
            "target_sha256": self.target_sha256,
            "tenant_id": self.tenant_id,
        }


@dataclass(frozen=True, slots=True)
class ExecutionControlPolicy:
    policy_id: str
    allowed_windows: tuple[AllowedUtcWindow, ...]
    rate_mode: RateMode
    request_ceiling: int
    period_seconds: int
    token_capacity: int
    token_refill_amount: int
    byte_ceiling: int
    maximum_concurrent_sessions: int
    sequential_only: bool
    maximum_attempts: int
    retryable_failure_codes: tuple[str, ...]
    cleanup_required: bool
    policy_sha256: str = ""

    KIND: ClassVar[str] = "execution_control_policy"

    def __post_init__(self) -> None:
        _identifier(self.policy_id, "policy_id")
        if not self.allowed_windows or len(self.allowed_windows) > 64:
            raise ExecutionControlError("allowed_windows is invalid")
        if (
            tuple(sorted(self.allowed_windows, key=lambda item: item.starts_at))
            != self.allowed_windows
        ):
            raise ExecutionControlError("allowed_windows must be sorted")
        for earlier, later in zip(self.allowed_windows, self.allowed_windows[1:], strict=False):
            if _instant(later.starts_at) < _instant(earlier.ends_at):
                raise ExecutionControlError("allowed_windows must not overlap")
        if not isinstance(self.rate_mode, RateMode):
            raise ExecutionControlError("rate_mode is invalid")
        for value, label in (
            (self.request_ceiling, "request_ceiling"),
            (self.period_seconds, "period_seconds"),
            (self.byte_ceiling, "byte_ceiling"),
            (self.maximum_concurrent_sessions, "maximum_concurrent_sessions"),
            (self.maximum_attempts, "maximum_attempts"),
        ):
            _integer(value, label, 1)
        _integer(self.token_capacity, "token_capacity", 0)
        _integer(self.token_refill_amount, "token_refill_amount", 0)
        if self.rate_mode is RateMode.INTEGER_TOKEN_BUCKET:
            if self.token_capacity < 1 or self.token_refill_amount < 1:
                raise ExecutionControlError("token bucket values must be positive")
            if self.request_ceiling != self.token_capacity:
                raise ExecutionControlError("request_ceiling must equal token_capacity")
        elif self.token_capacity != 0 or self.token_refill_amount != 0:
            raise ExecutionControlError("fixed window must not define token values")
        if not isinstance(self.sequential_only, bool) or not isinstance(
            self.cleanup_required, bool
        ):
            raise ExecutionControlError("policy flags are invalid")
        if not self.retryable_failure_codes:
            raise ExecutionControlError("retryable_failure_codes must not be empty")
        for item in self.retryable_failure_codes:
            _code(item, "retryable failure code")
        if len(set(self.retryable_failure_codes)) != len(self.retryable_failure_codes):
            raise ExecutionControlError("retryable_failure_codes contains duplicates")
        policy_id, digest = _identity("ECP", self.KIND, self.body())
        if self.policy_id != policy_id:
            raise ExecutionControlError("policy_id does not match content")
        if self.policy_sha256 and self.policy_sha256 != digest:
            raise ExecutionControlError("policy_sha256 does not match content")
        object.__setattr__(self, "policy_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "allowed_windows": [item.to_dict() for item in self.allowed_windows],
            "byte_ceiling": self.byte_ceiling,
            "cleanup_required": self.cleanup_required,
            "maximum_attempts": self.maximum_attempts,
            "maximum_concurrent_sessions": self.maximum_concurrent_sessions,
            "period_seconds": self.period_seconds,
            "rate_mode": self.rate_mode.value,
            "request_ceiling": self.request_ceiling,
            "retryable_failure_codes": list(self.retryable_failure_codes),
            "sequential_only": self.sequential_only,
            "token_capacity": self.token_capacity,
            "token_refill_amount": self.token_refill_amount,
        }

    @classmethod
    def build(cls, **values: Any) -> ExecutionControlPolicy:
        temporary = object.__new__(cls)
        body = {
            "allowed_windows": [item.to_dict() for item in values["allowed_windows"]],
            "byte_ceiling": values["byte_ceiling"],
            "cleanup_required": values["cleanup_required"],
            "maximum_attempts": values["maximum_attempts"],
            "maximum_concurrent_sessions": values["maximum_concurrent_sessions"],
            "period_seconds": values["period_seconds"],
            "rate_mode": values["rate_mode"].value,
            "request_ceiling": values["request_ceiling"],
            "retryable_failure_codes": list(values["retryable_failure_codes"]),
            "sequential_only": values["sequential_only"],
            "token_capacity": values["token_capacity"],
            "token_refill_amount": values["token_refill_amount"],
        }
        policy_id, _ = _identity("ECP", cls.KIND, body)
        del temporary
        return cls(policy_id=policy_id, **values)


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    binding: ExecutionBinding
    policy_id: str
    policy_sha256: str
    idempotency_key: str
    operation_code: str
    payload_sha256: str
    payload_size_bytes: int
    attempt_number: int
    prior_execution_sha256: str | None
    cleanup_obligation_sha256: str
    request_id: str = ""
    request_sha256: str = ""

    KIND: ClassVar[str] = "execution_control_request"

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ExecutionBinding):
            raise ExecutionControlError("binding is invalid")
        _identifier(self.policy_id, "policy_id")
        _digest(self.policy_sha256, "policy_sha256")
        _identifier(self.idempotency_key, "idempotency_key")
        _code(self.operation_code, "operation_code")
        _digest(self.payload_sha256, "payload_sha256")
        _integer(self.payload_size_bytes, "payload_size_bytes", 1)
        _integer(self.attempt_number, "attempt_number", 1)
        if self.attempt_number == 1 and self.prior_execution_sha256 is not None:
            raise ExecutionControlError("first attempt must not bind a prior execution")
        if self.attempt_number > 1:
            _digest(self.prior_execution_sha256, "prior_execution_sha256")
        _digest(self.cleanup_obligation_sha256, "cleanup_obligation_sha256")
        request_id, digest = _identity("ECRQ", self.KIND, self.body())
        if self.request_id and self.request_id != request_id:
            raise ExecutionControlError("request_id does not match content")
        if self.request_sha256 and self.request_sha256 != digest:
            raise ExecutionControlError("request_sha256 does not match content")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "request_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "binding": self.binding.to_dict(),
            "cleanup_obligation_sha256": self.cleanup_obligation_sha256,
            "idempotency_key": self.idempotency_key,
            "operation_code": self.operation_code,
            "payload_sha256": self.payload_sha256,
            "payload_size_bytes": self.payload_size_bytes,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "prior_execution_sha256": self.prior_execution_sha256,
        }


@dataclass(frozen=True, slots=True)
class ControlState:
    binding: ExecutionBinding
    lease_expires_at: str
    health: HealthState
    canceled: bool
    emergency_stop: bool
    active_sessions: tuple[str, ...]
    active_executions: int
    fixed_window_started_at: str
    requests_used: int
    bytes_used: int
    tokens_available: int
    token_refill_tick: int
    last_observed_at: str
    last_monotonic_tick: int
    state_version: int
    reservation_request_sha256: str | None = None
    state_sha256: str = ""

    KIND: ClassVar[str] = "execution_control_state"

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ExecutionBinding):
            raise ExecutionControlError("state binding is invalid")
        for label in ("lease_expires_at", "fixed_window_started_at", "last_observed_at"):
            _utc(getattr(self, label), label)
        if not isinstance(self.health, HealthState):
            raise ExecutionControlError("health is invalid")
        if not isinstance(self.canceled, bool) or not isinstance(self.emergency_stop, bool):
            raise ExecutionControlError("stop flags are invalid")
        if tuple(sorted(set(self.active_sessions))) != self.active_sessions:
            raise ExecutionControlError("active_sessions must be sorted and unique")
        for item in self.active_sessions:
            _identifier(item, "active session")
        for value, label in (
            (self.active_executions, "active_executions"),
            (self.requests_used, "requests_used"),
            (self.bytes_used, "bytes_used"),
            (self.tokens_available, "tokens_available"),
            (self.token_refill_tick, "token_refill_tick"),
            (self.last_monotonic_tick, "last_monotonic_tick"),
            (self.state_version, "state_version"),
        ):
            _integer(value, label, 0)
        if self.state_version < 1 or self.last_monotonic_tick < 1:
            raise ExecutionControlError("state version and clock tick must be positive")
        if self.reservation_request_sha256 is not None:
            _digest(self.reservation_request_sha256, "reservation_request_sha256")
        _, digest = _identity("ECS", self.KIND, self.body())
        if self.state_sha256 and self.state_sha256 != digest:
            raise ExecutionControlError("state_sha256 does not match content")
        object.__setattr__(self, "state_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "active_executions": self.active_executions,
            "active_sessions": list(self.active_sessions),
            "binding": self.binding.to_dict(),
            "bytes_used": self.bytes_used,
            "canceled": self.canceled,
            "emergency_stop": self.emergency_stop,
            "fixed_window_started_at": self.fixed_window_started_at,
            "health": self.health.value,
            "last_monotonic_tick": self.last_monotonic_tick,
            "last_observed_at": self.last_observed_at,
            "lease_expires_at": self.lease_expires_at,
            "requests_used": self.requests_used,
            "reservation_request_sha256": self.reservation_request_sha256,
            "state_version": self.state_version,
            "token_refill_tick": self.token_refill_tick,
            "tokens_available": self.tokens_available,
        }


@dataclass(frozen=True, slots=True)
class StateTransition:
    before: ControlState
    after: ControlState


@dataclass(frozen=True, slots=True)
class StoredExecution:
    request_sha256: str
    admission: AdmissionReceipt
    execution: ExecutionReceipt


class ExecutionStateRepository(Protocol):
    def lookup(self, binding: ExecutionBinding, idempotency_key: str) -> StoredExecution | None: ...

    def reserve(
        self,
        request: ExecutionRequest,
        policy: ExecutionControlPolicy,
        observation: ClockObservation,
    ) -> StateTransition: ...

    def complete(
        self,
        request: ExecutionRequest,
        reservation: ControlState,
        observation: ClockObservation,
        outcome: StoredExecution,
    ) -> StateTransition: ...


@dataclass(frozen=True, slots=True)
class TransportEnvelope:
    request_id: str
    request_sha256: str
    binding: ExecutionBinding
    operation_code: str
    payload_sha256: str
    payload_size_bytes: int


@dataclass(frozen=True, slots=True)
class TransportObservation:
    succeeded: bool
    failure_code: str | None
    response_sha256: str
    response_size_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.succeeded, bool):
            raise ExecutionControlError("transport succeeded flag is invalid")
        if self.succeeded and self.failure_code is not None:
            raise ExecutionControlError("successful transport must not carry a failure code")
        if not self.succeeded:
            _code(self.failure_code, "failure_code")
        _digest(self.response_sha256, "response_sha256")
        _integer(self.response_size_bytes, "response_size_bytes", 0)


class ExecutionTransport(Protocol):
    def execute(self, envelope: TransportEnvelope) -> TransportObservation: ...


@dataclass(frozen=True, slots=True)
class AdmissionReceipt:
    request_id: str
    request_sha256: str
    policy_id: str
    policy_sha256: str
    status: AdmissionStatus
    reason: str | None
    observed_at: str
    monotonic_tick: int
    state_before_sha256: str | None
    state_after_sha256: str | None
    enforcement_boundary: str = ENFORCEMENT_BOUNDARY
    receipt_id: str = ""
    receipt_sha256: str = ""

    KIND: ClassVar[str] = "execution_control_admission_receipt"

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _digest(self.request_sha256, "request_sha256")
        _identifier(self.policy_id, "policy_id")
        _digest(self.policy_sha256, "policy_sha256")
        if not isinstance(self.status, AdmissionStatus):
            raise ExecutionControlError("admission status is invalid")
        if self.status is AdmissionStatus.ADMITTED and self.reason is not None:
            raise ExecutionControlError("admitted receipt must not carry a reason")
        if self.status is AdmissionStatus.BLOCKED:
            BlockReason(self.reason)
        _utc(self.observed_at, "observed_at")
        _integer(self.monotonic_tick, "monotonic_tick", 1)
        for value, label in (
            (self.state_before_sha256, "state_before_sha256"),
            (self.state_after_sha256, "state_after_sha256"),
        ):
            if value is not None:
                _digest(value, label)
        if self.enforcement_boundary != ENFORCEMENT_BOUNDARY:
            raise ExecutionControlError("enforcement boundary claim is invalid")
        receipt_id, digest = _identity("ECAR", self.KIND, self.body())
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ExecutionControlError("receipt_id does not match content")
        if self.receipt_sha256 and self.receipt_sha256 != digest:
            raise ExecutionControlError("receipt_sha256 does not match content")
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "enforcement_boundary": self.enforcement_boundary,
            "monotonic_tick": self.monotonic_tick,
            "observed_at": self.observed_at,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "reason": self.reason,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "state_after_sha256": self.state_after_sha256,
            "state_before_sha256": self.state_before_sha256,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    admission_receipt_id: str
    admission_receipt_sha256: str
    request_id: str
    request_sha256: str
    status: ExecutionStatus
    transport_called: bool
    transport_succeeded: bool
    transport_failure_code: str | None
    response_sha256: str
    response_size_bytes: int
    retry_disposition: RetryDisposition
    cleanup_required: bool
    cleanup_status: CleanupStatus
    completed_at: str
    monotonic_tick: int
    reservation_state_sha256: str
    completion_state_sha256: str | None
    enforcement_boundary: str = ENFORCEMENT_BOUNDARY
    receipt_id: str = ""
    receipt_sha256: str = ""

    KIND: ClassVar[str] = "execution_control_execution_receipt"

    def __post_init__(self) -> None:
        _identifier(self.admission_receipt_id, "admission_receipt_id")
        _digest(self.admission_receipt_sha256, "admission_receipt_sha256")
        _identifier(self.request_id, "request_id")
        _digest(self.request_sha256, "request_sha256")
        if not isinstance(self.status, ExecutionStatus):
            raise ExecutionControlError("execution status is invalid")
        if self.transport_called is not True or not isinstance(self.transport_succeeded, bool):
            raise ExecutionControlError("execution receipt requires a transport call")
        if not self.transport_succeeded:
            _code(self.transport_failure_code, "transport_failure_code")
        elif self.transport_failure_code is not None:
            raise ExecutionControlError("successful transport must not carry a failure code")
        if self.status is ExecutionStatus.SUCCEEDED and not self.transport_succeeded:
            raise ExecutionControlError("execution status contradicts transport evidence")
        if self.status is ExecutionStatus.TRANSPORT_FAILED and self.transport_succeeded:
            raise ExecutionControlError("transport failure status contradicts evidence")
        _digest(self.response_sha256, "response_sha256")
        _integer(self.response_size_bytes, "response_size_bytes", 0)
        if not isinstance(self.retry_disposition, RetryDisposition):
            raise ExecutionControlError("retry_disposition is invalid")
        if not isinstance(self.cleanup_required, bool) or not isinstance(
            self.cleanup_status, CleanupStatus
        ):
            raise ExecutionControlError("cleanup evidence is invalid")
        expected_cleanup = (
            CleanupStatus.PENDING_EXTERNAL_VERIFICATION
            if self.cleanup_required
            else CleanupStatus.NOT_REQUIRED
        )
        if self.cleanup_status is not expected_cleanup:
            raise ExecutionControlError("cleanup status overclaims completion")
        _utc(self.completed_at, "completed_at")
        _integer(self.monotonic_tick, "monotonic_tick", 1)
        _digest(self.reservation_state_sha256, "reservation_state_sha256")
        if self.completion_state_sha256 is not None:
            _digest(self.completion_state_sha256, "completion_state_sha256")
        if self.status is ExecutionStatus.COMPLETION_FAILED and self.completion_state_sha256:
            raise ExecutionControlError("completion failure must not claim persisted state")
        if (
            self.status is not ExecutionStatus.COMPLETION_FAILED
            and not self.completion_state_sha256
        ):
            raise ExecutionControlError("completed execution requires completion state")
        if self.enforcement_boundary != ENFORCEMENT_BOUNDARY:
            raise ExecutionControlError("enforcement boundary claim is invalid")
        receipt_id, digest = _identity("ECER", self.KIND, self.body())
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ExecutionControlError("receipt_id does not match content")
        if self.receipt_sha256 and self.receipt_sha256 != digest:
            raise ExecutionControlError("receipt_sha256 does not match content")
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "admission_receipt_id": self.admission_receipt_id,
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "cleanup_required": self.cleanup_required,
            "cleanup_status": self.cleanup_status.value,
            "completed_at": self.completed_at,
            "completion_state_sha256": self.completion_state_sha256,
            "enforcement_boundary": self.enforcement_boundary,
            "monotonic_tick": self.monotonic_tick,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "reservation_state_sha256": self.reservation_state_sha256,
            "response_sha256": self.response_sha256,
            "response_size_bytes": self.response_size_bytes,
            "retry_disposition": self.retry_disposition.value,
            "status": self.status.value,
            "transport_called": self.transport_called,
            "transport_failure_code": self.transport_failure_code,
            "transport_succeeded": self.transport_succeeded,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class ExecutionControlResult:
    admission: AdmissionReceipt
    execution: ExecutionReceipt | None
    idempotent_replay: bool


def _same_binding(left: ExecutionBinding, right: ExecutionBinding) -> bool:
    return left == right


def _same_binding_except_fence(left: ExecutionBinding, right: ExecutionBinding) -> bool:
    return replace(left, fence_epoch=right.fence_epoch) == right


def _refilled_tokens(
    state: ControlState,
    policy: ExecutionControlPolicy,
    observation: ClockObservation,
) -> tuple[int, int]:
    elapsed = observation.monotonic_tick - state.token_refill_tick
    periods = elapsed // policy.period_seconds
    tokens = min(
        policy.token_capacity,
        state.tokens_available + periods * policy.token_refill_amount,
    )
    refill_tick = state.token_refill_tick + periods * policy.period_seconds
    return tokens, refill_tick


def _expected_reservation(
    state: ControlState,
    request: ExecutionRequest,
    policy: ExecutionControlPolicy,
    observation: ClockObservation,
) -> tuple[ControlState | None, BlockReason | None]:
    if not _same_binding_except_fence(state.binding, request.binding):
        return None, BlockReason.BINDING_MISMATCH
    if observation.monotonic_tick <= state.last_monotonic_tick or _instant(
        observation.observed_at
    ) < _instant(state.last_observed_at):
        return None, BlockReason.TIME_ROLLBACK
    if _instant(observation.observed_at) >= _instant(state.lease_expires_at):
        return None, BlockReason.LEASE_EXPIRED
    if state.binding.fence_epoch != request.binding.fence_epoch:
        return None, BlockReason.STALE_FENCE
    if state.emergency_stop:
        return None, BlockReason.EMERGENCY_STOP
    if state.canceled:
        return None, BlockReason.CANCELED
    if state.health is HealthState.PAUSED:
        return None, BlockReason.HEALTH_PAUSED
    if state.health is HealthState.UNHEALTHY:
        return None, BlockReason.HEALTH_UNHEALTHY
    if not any(window.includes(observation.observed_at) for window in policy.allowed_windows):
        return None, BlockReason.OUTSIDE_ALLOWED_WINDOW
    if request.attempt_number > policy.maximum_attempts:
        return None, BlockReason.ATTEMPT_BUDGET_EXHAUSTED
    active_sessions = set(state.active_sessions)
    if (
        request.binding.session_id not in active_sessions
        and len(active_sessions) >= policy.maximum_concurrent_sessions
    ):
        return None, BlockReason.SESSION_LIMIT_EXHAUSTED
    if policy.sequential_only and state.active_executions:
        return None, BlockReason.SEQUENTIAL_CONFLICT

    fixed_start = state.fixed_window_started_at
    requests_used = state.requests_used
    bytes_used = state.bytes_used
    tokens = state.tokens_available
    refill_tick = state.token_refill_tick
    period = timedelta(seconds=policy.period_seconds)
    if _instant(observation.observed_at) >= _instant(fixed_start) + period:
        fixed_start = observation.observed_at
        requests_used = 0
        bytes_used = 0
    if bytes_used + request.payload_size_bytes > policy.byte_ceiling:
        return None, BlockReason.BYTE_BUDGET_EXHAUSTED
    if policy.rate_mode is RateMode.FIXED_WINDOW:
        if requests_used + 1 > policy.request_ceiling:
            return None, BlockReason.RATE_EXHAUSTED
    else:
        tokens, refill_tick = _refilled_tokens(state, policy, observation)
        if tokens < 1:
            return None, BlockReason.RATE_EXHAUSTED
        tokens -= 1

    active_sessions.add(request.binding.session_id)
    return (
        replace(
            state,
            active_sessions=tuple(sorted(active_sessions)),
            active_executions=state.active_executions + 1,
            fixed_window_started_at=fixed_start,
            requests_used=requests_used + 1,
            bytes_used=bytes_used + request.payload_size_bytes,
            tokens_available=tokens,
            token_refill_tick=refill_tick,
            last_observed_at=observation.observed_at,
            last_monotonic_tick=observation.monotonic_tick,
            state_version=state.state_version + 1,
            reservation_request_sha256=request.request_sha256,
            state_sha256="",
        ),
        None,
    )


def _expected_completion(
    reservation: ControlState,
    request: ExecutionRequest,
    observation: ClockObservation,
) -> ControlState:
    if not _same_binding(reservation.binding, request.binding):
        raise ExecutionControlError("completion binding mismatch")
    if reservation.reservation_request_sha256 != request.request_sha256:
        raise ExecutionControlError("completion reservation mismatch")
    if observation.monotonic_tick <= reservation.last_monotonic_tick or _instant(
        observation.observed_at
    ) < _instant(reservation.last_observed_at):
        raise ExecutionControlError("completion time rollback")
    sessions = tuple(
        item for item in reservation.active_sessions if item != request.binding.session_id
    )
    return replace(
        reservation,
        active_sessions=sessions,
        active_executions=reservation.active_executions - 1,
        last_observed_at=observation.observed_at,
        last_monotonic_tick=observation.monotonic_tick,
        state_version=reservation.state_version + 1,
        reservation_request_sha256=None,
        state_sha256="",
    )


def _blocked(
    request: ExecutionRequest,
    policy: ExecutionControlPolicy,
    observation: ClockObservation,
    reason: BlockReason,
    before: ControlState | None = None,
    after: ControlState | None = None,
) -> ExecutionControlResult:
    return ExecutionControlResult(
        admission=AdmissionReceipt(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            policy_id=policy.policy_id,
            policy_sha256=policy.policy_sha256,
            status=AdmissionStatus.BLOCKED,
            reason=reason.value,
            observed_at=observation.observed_at,
            monotonic_tick=observation.monotonic_tick,
            state_before_sha256=before.state_sha256 if before else None,
            state_after_sha256=after.state_sha256 if after else None,
        ),
        execution=None,
        idempotent_replay=False,
    )


def execute_with_controls(
    request: ExecutionRequest,
    policy: ExecutionControlPolicy,
    clock: ExecutionClock,
    repository: ExecutionStateRepository,
    transport: ExecutionTransport,
) -> ExecutionControlResult:
    """Admit once, call only the injected transport, and emit receipts."""

    if request.policy_id != policy.policy_id or request.policy_sha256 != policy.policy_sha256:
        observation = clock.observe()
        return _blocked(request, policy, observation, BlockReason.BINDING_MISMATCH)

    try:
        stored = repository.lookup(request.binding, request.idempotency_key)
    except Exception:
        observation = clock.observe()
        return _blocked(request, policy, observation, BlockReason.STATE_REPOSITORY_FAILURE)
    if stored is not None:
        if stored.request_sha256 != request.request_sha256:
            observation = clock.observe()
            return _blocked(request, policy, observation, BlockReason.IDEMPOTENCY_REBINDING)
        return ExecutionControlResult(stored.admission, stored.execution, True)

    observation = clock.observe()
    try:
        transition = repository.reserve(request, policy, observation)
    except Exception:
        return _blocked(request, policy, observation, BlockReason.STATE_REPOSITORY_FAILURE)
    expected, reason = _expected_reservation(transition.before, request, policy, observation)
    if reason is not None:
        return _blocked(request, policy, observation, reason, transition.before, transition.after)
    if expected != transition.after:
        return _blocked(
            request,
            policy,
            observation,
            BlockReason.STATE_TAMPERING,
            transition.before,
            transition.after,
        )

    admission = AdmissionReceipt(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        policy_id=policy.policy_id,
        policy_sha256=policy.policy_sha256,
        status=AdmissionStatus.ADMITTED,
        reason=None,
        observed_at=observation.observed_at,
        monotonic_tick=observation.monotonic_tick,
        state_before_sha256=transition.before.state_sha256,
        state_after_sha256=transition.after.state_sha256,
    )
    envelope = TransportEnvelope(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        binding=request.binding,
        operation_code=request.operation_code,
        payload_sha256=request.payload_sha256,
        payload_size_bytes=request.payload_size_bytes,
    )
    try:
        transport_observation = transport.execute(envelope)
    except Exception:
        transport_observation = TransportObservation(
            succeeded=False,
            failure_code="transport_exception",
            response_sha256=canonical_sha256({"response": "not_observed"}),
            response_size_bytes=0,
        )

    completed = clock.observe()
    transport_status = (
        ExecutionStatus.SUCCEEDED
        if transport_observation.succeeded
        else ExecutionStatus.TRANSPORT_FAILED
    )
    if transport_observation.succeeded:
        retry = RetryDisposition.NOT_APPLICABLE
    elif (
        transport_observation.failure_code in policy.retryable_failure_codes
        and request.attempt_number < policy.maximum_attempts
    ):
        retry = RetryDisposition.RETRY_PERMITTED
    elif request.attempt_number >= policy.maximum_attempts:
        retry = RetryDisposition.RETRY_EXHAUSTED
    else:
        retry = RetryDisposition.FAILURE_NOT_RETRYABLE
    try:
        expected_completion = _expected_completion(transition.after, request, completed)
    except Exception:
        expected_completion = None
    candidate = ExecutionReceipt(
        admission_receipt_id=admission.receipt_id,
        admission_receipt_sha256=admission.receipt_sha256,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        status=(
            transport_status
            if expected_completion is not None
            else ExecutionStatus.COMPLETION_FAILED
        ),
        transport_called=True,
        transport_succeeded=transport_observation.succeeded,
        transport_failure_code=(
            transport_observation.failure_code if not transport_observation.succeeded else None
        ),
        response_sha256=transport_observation.response_sha256,
        response_size_bytes=transport_observation.response_size_bytes,
        retry_disposition=retry,
        cleanup_required=policy.cleanup_required,
        cleanup_status=(
            CleanupStatus.PENDING_EXTERNAL_VERIFICATION
            if policy.cleanup_required
            else CleanupStatus.NOT_REQUIRED
        ),
        completed_at=completed.observed_at,
        monotonic_tick=completed.monotonic_tick,
        reservation_state_sha256=transition.after.state_sha256,
        completion_state_sha256=(
            expected_completion.state_sha256 if expected_completion is not None else None
        ),
    )
    execution = candidate
    if expected_completion is not None:
        outcome = StoredExecution(request.request_sha256, admission, candidate)
        try:
            completion = repository.complete(request, transition.after, completed, outcome)
            if completion.before != transition.after or completion.after != expected_completion:
                raise ExecutionControlError("completion state was tampered")
        except Exception:
            execution = replace(
                candidate,
                status=ExecutionStatus.COMPLETION_FAILED,
                completion_state_sha256=None,
                receipt_id="",
                receipt_sha256="",
            )
    return ExecutionControlResult(admission, execution, False)


__all__ = [
    "AdmissionReceipt",
    "AdmissionStatus",
    "AllowedUtcWindow",
    "BlockReason",
    "CleanupStatus",
    "ClockObservation",
    "ControlState",
    "ExecutionBinding",
    "ExecutionClock",
    "ExecutionControlError",
    "ExecutionControlPolicy",
    "ExecutionControlResult",
    "ExecutionRequest",
    "ExecutionStateRepository",
    "ExecutionStatus",
    "ExecutionTransport",
    "HealthState",
    "RateMode",
    "RetryDisposition",
    "StateTransition",
    "StoredExecution",
    "TransportEnvelope",
    "TransportObservation",
    "canonical_json",
    "canonical_sha256",
    "execute_with_controls",
]
