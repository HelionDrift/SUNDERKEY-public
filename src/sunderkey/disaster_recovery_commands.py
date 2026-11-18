"""Fail-closed disaster recovery commands over an injected backend.

This module binds existing disaster recovery contracts to exact command requests,
backend-supplied observations, and receipts. It does not discover files, start a
process, open a socket, resolve credentials, connect to a database, or restore a
production destination.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar, Protocol

from sunderkey.disaster_recovery_contracts import (
    BackupManifest,
    RecoveryObjective,
    RestorationRehearsalPlan,
)

SCHEMA_VERSION = 1
MAX_REASONS = 64

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|systemref|scoperef|backendref|authorizationref|principalref|"
    r"rehearsalref|evidenceref|fenceref|cleanupref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{15,190}\Z")
REASON_RE = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")


class DisasterRecoveryCommandError(ValueError):
    """Raised when a command boundary fails closed."""


class CommandKind(StrEnum):
    CREATE_BACKUP = "create_backup"
    VERIFY_BACKUP = "verify_backup"
    REHEARSE_RESTORE = "rehearse_restore"
    VERIFY_RESTORE = "verify_restore"
    CLEANUP_REHEARSAL = "cleanup_rehearsal"


class CommandOutcome(StrEnum):
    COMPLETED = "completed"
    RETRYABLE_FAILURE = "retryable_failure"
    TERMINAL_FAILURE = "terminal_failure"
    PARTIAL_CLEANUP = "partial_cleanup"
    BLOCKED_PREFLIGHT = "blocked_preflight"


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
        raise DisasterRecoveryCommandError("value cannot be serialized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise DisasterRecoveryCommandError(f"{label} fields are invalid")
    return raw


def _field_names(record_type: type[Any], *, omit: set[str] | None = None) -> set[str]:
    omitted = omit or set()
    return {item.name for item in fields(record_type)} - omitted


def _reference(value: Any, label: str, namespace: str) -> str:
    if (
        not isinstance(value, str)
        or REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise DisasterRecoveryCommandError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DisasterRecoveryCommandError(f"{label} must be a SHA-256 content address")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise DisasterRecoveryCommandError(f"{label} must be an exact version")
    if value.lower() in {"latest", "stable", "current", "default", "auto"}:
        raise DisasterRecoveryCommandError(f"{label} must not be a moving alias")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise DisasterRecoveryCommandError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise DisasterRecoveryCommandError(f"{label} must be valid") from exc


def _positive(value: Any, label: str, maximum: int = 2_147_483_647) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DisasterRecoveryCommandError(f"{label} must be between 1 and {maximum}")
    return value


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise DisasterRecoveryCommandError(f"{label} is invalid") from exc


def _reasons(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise DisasterRecoveryCommandError("reason_codes must be a sequence")
    result = tuple(values)
    if len(result) > MAX_REASONS or len(result) != len(set(result)):
        raise DisasterRecoveryCommandError("reason_codes must be bounded and unique")
    if any(not isinstance(item, str) or REASON_RE.fullmatch(item) is None for item in result):
        raise DisasterRecoveryCommandError("reason_codes contains an invalid code")
    return tuple(sorted(result))


def _verify_address(
    raw: Mapping[str, Any], id_field: str, digest_field: str, prefix: str, domain: str
) -> None:
    body = {key: value for key, value in raw.items() if key not in {id_field, digest_field}}
    expected_id, expected_digest = _identity(prefix, domain, body)
    if raw[id_field] != expected_id or raw[digest_field] != expected_digest:
        raise DisasterRecoveryCommandError("record content address does not match content")


@dataclass(frozen=True, slots=True)
class ExecutionBudget:
    max_runtime_seconds: int
    max_bytes: int
    max_objects: int
    max_backend_calls: int

    def __post_init__(self) -> None:
        _positive(self.max_runtime_seconds, "max_runtime_seconds", 86_400)
        _positive(self.max_bytes, "max_bytes", 1_099_511_627_776)
        _positive(self.max_objects, "max_objects", 1_000_000)
        if self.max_backend_calls != 1:
            raise DisasterRecoveryCommandError("max_backend_calls must equal one")

    def to_dict(self) -> dict[str, int]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, raw: Any) -> ExecutionBudget:
        return cls(**dict(_exact(raw, _field_names(cls), "execution budget")))


@dataclass(frozen=True, slots=True)
class RehearsalIsolationBinding:
    destination_ref: str
    destination_sha256: str
    isolation_proof_ref: str
    isolation_proof_sha256: str
    isolation_class: str
    network_mode: str
    caller_proved_isolated: bool
    production_destination: bool

    def __post_init__(self) -> None:
        _reference(self.destination_ref, "destination_ref", "rehearsalref")
        _digest(self.destination_sha256, "destination_sha256")
        _reference(self.isolation_proof_ref, "isolation_proof_ref", "evidenceref")
        _digest(self.isolation_proof_sha256, "isolation_proof_sha256")
        if self.isolation_class != "ephemeral_rehearsal":
            raise DisasterRecoveryCommandError("isolation_class must be ephemeral_rehearsal")
        if self.network_mode != "isolated":
            raise DisasterRecoveryCommandError("network_mode must be isolated")
        if self.caller_proved_isolated is not True:
            raise DisasterRecoveryCommandError("caller must prove rehearsal isolation")
        if self.production_destination is not False:
            raise DisasterRecoveryCommandError("production restoration is forbidden")

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, raw: Any) -> RehearsalIsolationBinding:
        return cls(**dict(_exact(raw, _field_names(cls), "rehearsal isolation binding")))


@dataclass(frozen=True, slots=True)
class AuthorizationBinding:
    authorization_ref: str
    authorization_sha256: str
    tenant_ref: str
    system_ref: str
    scope_ref: str
    scope_sha256: str
    objective_id: str
    objective_sha256: str
    manifest_id: str
    manifest_sha256: str
    plan_id: str
    plan_sha256: str
    backend_ref: str
    backend_version: str
    destination_ref: str
    destination_sha256: str
    operator_ref: str
    approver_ref: str
    allowed_command_kinds: tuple[CommandKind, ...]
    authorized_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _reference(self.authorization_ref, "authorization_ref", "authorizationref")
        _digest(self.authorization_sha256, "authorization_sha256")
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.system_ref, "system_ref", "systemref")
        _reference(self.scope_ref, "scope_ref", "scoperef")
        _digest(self.scope_sha256, "scope_sha256")
        for name, prefix in (
            ("objective_id", "DRO-"),
            ("manifest_id", "DRB-"),
            ("plan_id", "DRP-"),
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.startswith(prefix):
                raise DisasterRecoveryCommandError(f"{name} is invalid")
        _digest(self.objective_sha256, "objective_sha256")
        _digest(self.manifest_sha256, "manifest_sha256")
        _digest(self.plan_sha256, "plan_sha256")
        _reference(self.backend_ref, "backend_ref", "backendref")
        _version(self.backend_version, "backend_version")
        _reference(self.destination_ref, "destination_ref", "rehearsalref")
        _digest(self.destination_sha256, "destination_sha256")
        _reference(self.operator_ref, "operator_ref", "principalref")
        _reference(self.approver_ref, "approver_ref", "principalref")
        if self.operator_ref == self.approver_ref:
            raise DisasterRecoveryCommandError("operator and approver must be separate")
        values = tuple(
            _enum(CommandKind, item, "allowed_command_kinds item")
            for item in self.allowed_command_kinds
        )
        if not values or len(values) != len(set(values)):
            raise DisasterRecoveryCommandError("allowed_command_kinds must be non-empty and unique")
        object.__setattr__(self, "allowed_command_kinds", tuple(sorted(values, key=str)))
        if _timestamp(self.expires_at, "expires_at") <= _timestamp(
            self.authorized_at, "authorized_at"
        ):
            raise DisasterRecoveryCommandError("authorization must expire after approval")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_command_kinds": [item.value for item in self.allowed_command_kinds],
            "approver_ref": self.approver_ref,
            "authorization_ref": self.authorization_ref,
            "authorization_sha256": self.authorization_sha256,
            "authorized_at": self.authorized_at,
            "backend_ref": self.backend_ref,
            "backend_version": self.backend_version,
            "destination_ref": self.destination_ref,
            "destination_sha256": self.destination_sha256,
            "expires_at": self.expires_at,
            "manifest_id": self.manifest_id,
            "manifest_sha256": self.manifest_sha256,
            "objective_id": self.objective_id,
            "objective_sha256": self.objective_sha256,
            "operator_ref": self.operator_ref,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "system_ref": self.system_ref,
            "tenant_ref": self.tenant_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AuthorizationBinding:
        value = _exact(raw, _field_names(cls), "authorization binding")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class FenceBinding:
    fence_ref: str
    fence_sha256: str
    fence_epoch: int
    scope_ref: str
    scope_sha256: str

    def __post_init__(self) -> None:
        _reference(self.fence_ref, "fence_ref", "fenceref")
        _digest(self.fence_sha256, "fence_sha256")
        _positive(self.fence_epoch, "fence_epoch")
        _reference(self.scope_ref, "scope_ref", "scoperef")
        _digest(self.scope_sha256, "scope_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, raw: Any) -> FenceBinding:
        return cls(**dict(_exact(raw, _field_names(cls), "fence binding")))


@dataclass(frozen=True, slots=True)
class CleanupBinding:
    cleanup_ref: str
    cleanup_sha256: str
    destination_ref: str
    destination_sha256: str
    cleanup_required: bool
    destination_absence_required: bool
    max_cleanup_seconds: int

    def __post_init__(self) -> None:
        _reference(self.cleanup_ref, "cleanup_ref", "cleanupref")
        _digest(self.cleanup_sha256, "cleanup_sha256")
        _reference(self.destination_ref, "destination_ref", "rehearsalref")
        _digest(self.destination_sha256, "destination_sha256")
        if self.cleanup_required is not True or self.destination_absence_required is not True:
            raise DisasterRecoveryCommandError(
                "rehearsal cleanup and destination absence are required"
            )
        _positive(self.max_cleanup_seconds, "max_cleanup_seconds", 86_400)

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, raw: Any) -> CleanupBinding:
        return cls(**dict(_exact(raw, _field_names(cls), "cleanup binding")))


@dataclass(frozen=True, slots=True)
class DisasterRecoveryCommandRequest:
    tenant_ref: str
    system_ref: str
    system_version: str
    scope_ref: str
    scope_sha256: str
    command_kind: CommandKind
    objective_id: str
    objective_sha256: str
    manifest_id: str
    manifest_sha256: str
    plan_id: str
    plan_sha256: str
    backend_ref: str
    backend_version: str
    authorization: AuthorizationBinding
    idempotency_key: str
    budget: ExecutionBudget
    isolation: RehearsalIsolationBinding
    fence: FenceBinding
    cleanup: CleanupBinding
    preflight_passed: bool
    preflight_evidence_ref: str
    preflight_evidence_sha256: str
    preflight_reason_codes: tuple[str, ...]
    requested_at: str
    expires_at: str
    request_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-command-request.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.system_ref, "system_ref", "systemref")
        _version(self.system_version, "system_version")
        _reference(self.scope_ref, "scope_ref", "scoperef")
        _digest(self.scope_sha256, "scope_sha256")
        object.__setattr__(
            self, "command_kind", _enum(CommandKind, self.command_kind, "command_kind")
        )
        if not isinstance(self.objective_id, str) or not self.objective_id.startswith("DRO-"):
            raise DisasterRecoveryCommandError("objective_id is invalid")
        if not isinstance(self.manifest_id, str) or not self.manifest_id.startswith("DRB-"):
            raise DisasterRecoveryCommandError("manifest_id is invalid")
        if not isinstance(self.plan_id, str) or not self.plan_id.startswith("DRP-"):
            raise DisasterRecoveryCommandError("plan_id is invalid")
        _digest(self.objective_sha256, "objective_sha256")
        _digest(self.manifest_sha256, "manifest_sha256")
        _digest(self.plan_sha256, "plan_sha256")
        _reference(self.backend_ref, "backend_ref", "backendref")
        _version(self.backend_version, "backend_version")
        authorization = (
            self.authorization
            if isinstance(self.authorization, AuthorizationBinding)
            else AuthorizationBinding.from_dict(self.authorization)
        )
        budget = (
            self.budget
            if isinstance(self.budget, ExecutionBudget)
            else ExecutionBudget.from_dict(self.budget)
        )
        isolation = (
            self.isolation
            if isinstance(self.isolation, RehearsalIsolationBinding)
            else RehearsalIsolationBinding.from_dict(self.isolation)
        )
        fence = (
            self.fence
            if isinstance(self.fence, FenceBinding)
            else FenceBinding.from_dict(self.fence)
        )
        cleanup = (
            self.cleanup
            if isinstance(self.cleanup, CleanupBinding)
            else CleanupBinding.from_dict(self.cleanup)
        )
        object.__setattr__(self, "authorization", authorization)
        object.__setattr__(self, "budget", budget)
        object.__setattr__(self, "isolation", isolation)
        object.__setattr__(self, "fence", fence)
        object.__setattr__(self, "cleanup", cleanup)
        if self.command_kind not in authorization.allowed_command_kinds:
            raise DisasterRecoveryCommandError("authorization does not allow command kind")
        authorization_context = (
            authorization.tenant_ref,
            authorization.system_ref,
            authorization.scope_ref,
            authorization.scope_sha256,
            authorization.objective_id,
            authorization.objective_sha256,
            authorization.manifest_id,
            authorization.manifest_sha256,
            authorization.plan_id,
            authorization.plan_sha256,
            authorization.backend_ref,
            authorization.backend_version,
            authorization.destination_ref,
            authorization.destination_sha256,
        )
        request_context = (
            self.tenant_ref,
            self.system_ref,
            self.scope_ref,
            self.scope_sha256,
            self.objective_id,
            self.objective_sha256,
            self.manifest_id,
            self.manifest_sha256,
            self.plan_id,
            self.plan_sha256,
            self.backend_ref,
            self.backend_version,
            isolation.destination_ref,
            isolation.destination_sha256,
        )
        if authorization_context != request_context:
            raise DisasterRecoveryCommandError("authorization context does not match request")
        if (fence.scope_ref, fence.scope_sha256) != (self.scope_ref, self.scope_sha256):
            raise DisasterRecoveryCommandError("fence scope does not match request")
        if (cleanup.destination_ref, cleanup.destination_sha256) != (
            isolation.destination_ref,
            isolation.destination_sha256,
        ):
            raise DisasterRecoveryCommandError("cleanup destination does not match isolation")
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise DisasterRecoveryCommandError("idempotency_key is invalid")
        if not isinstance(self.preflight_passed, bool):
            raise DisasterRecoveryCommandError("preflight_passed must be boolean")
        _reference(self.preflight_evidence_ref, "preflight_evidence_ref", "evidenceref")
        _digest(self.preflight_evidence_sha256, "preflight_evidence_sha256")
        object.__setattr__(self, "preflight_reason_codes", _reasons(self.preflight_reason_codes))
        if self.preflight_passed == bool(self.preflight_reason_codes):
            raise DisasterRecoveryCommandError(
                "passing preflight must have no reasons and blocked preflight must have reasons"
            )
        requested = _timestamp(self.requested_at, "requested_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= requested:
            raise DisasterRecoveryCommandError("request must expire after creation")
        if requested < _timestamp(authorization.authorized_at, "authorized_at"):
            raise DisasterRecoveryCommandError("request predates authorization")
        if expires > _timestamp(authorization.expires_at, "authorization expires_at"):
            raise DisasterRecoveryCommandError("request exceeds authorization lifetime")
        request_id, digest = _identity("DRCQ", self.KIND, self._body())
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "request_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "authorization": self.authorization.to_dict(),
            "backend_ref": self.backend_ref,
            "backend_version": self.backend_version,
            "budget": self.budget.to_dict(),
            "cleanup": self.cleanup.to_dict(),
            "command_kind": self.command_kind.value,
            "expires_at": self.expires_at,
            "fence": self.fence.to_dict(),
            "idempotency_key": self.idempotency_key,
            "isolation": self.isolation.to_dict(),
            "kind": self.KIND,
            "manifest_id": self.manifest_id,
            "manifest_sha256": self.manifest_sha256,
            "objective_id": self.objective_id,
            "objective_sha256": self.objective_sha256,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "preflight_evidence_ref": self.preflight_evidence_ref,
            "preflight_evidence_sha256": self.preflight_evidence_sha256,
            "preflight_passed": self.preflight_passed,
            "preflight_reason_codes": list(self.preflight_reason_codes),
            "requested_at": self.requested_at,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "system_ref": self.system_ref,
            "system_version": self.system_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DisasterRecoveryCommandRequest:
        expected = _field_names(cls, omit={"request_id", "request_sha256"})
        expected |= {"schema_version", "kind", "request_id", "request_sha256"}
        value = _exact(raw, expected, "disaster recovery command request")
        if value["schema_version"] != SCHEMA_VERSION or value["kind"] != cls.KIND:
            raise DisasterRecoveryCommandError("command request discriminator is invalid")
        _verify_address(value, "request_id", "request_sha256", "DRCQ", cls.KIND)
        return cls(
            **{
                key: value[key]
                for key in _field_names(cls)
                if key not in {"request_id", "request_sha256"}
            }
        )


@dataclass(frozen=True, slots=True)
class BackendCommandResult:
    """Exact result supplied by a backend implementation."""

    request_id: str
    request_sha256: str
    backend_ref: str
    backend_version: str
    idempotency_key: str
    outcome: CommandOutcome
    evidence_ref: str
    evidence_sha256: str
    backup_observed: bool
    restore_observed: bool
    recovery_objectives_observed_passed: bool
    cleanup_observed_complete: bool
    reason_codes: tuple[str, ...]
    observed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.startswith("DRCQ-"):
            raise DisasterRecoveryCommandError("backend result request_id is invalid")
        _digest(self.request_sha256, "request_sha256")
        _reference(self.backend_ref, "backend_ref", "backendref")
        _version(self.backend_version, "backend_version")
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise DisasterRecoveryCommandError("backend result idempotency_key is invalid")
        object.__setattr__(self, "outcome", _enum(CommandOutcome, self.outcome, "outcome"))
        if self.outcome is CommandOutcome.BLOCKED_PREFLIGHT:
            raise DisasterRecoveryCommandError("backend must not report blocked_preflight")
        _reference(self.evidence_ref, "evidence_ref", "evidenceref")
        _digest(self.evidence_sha256, "evidence_sha256")
        for name in (
            "backup_observed",
            "restore_observed",
            "recovery_objectives_observed_passed",
            "cleanup_observed_complete",
        ):
            if not isinstance(getattr(self, name), bool):
                raise DisasterRecoveryCommandError(f"{name} must be boolean")
        object.__setattr__(self, "reason_codes", _reasons(self.reason_codes))
        if self.outcome is CommandOutcome.COMPLETED and self.reason_codes:
            raise DisasterRecoveryCommandError("completed backend result must not have reasons")
        if self.outcome is not CommandOutcome.COMPLETED and not self.reason_codes:
            raise DisasterRecoveryCommandError("failed backend result must have reasons")
        if self.outcome is CommandOutcome.PARTIAL_CLEANUP and self.cleanup_observed_complete:
            raise DisasterRecoveryCommandError("partial cleanup cannot be complete")
        if (
            self.outcome
            in {
                CommandOutcome.RETRYABLE_FAILURE,
                CommandOutcome.TERMINAL_FAILURE,
                CommandOutcome.PARTIAL_CLEANUP,
            }
            and self.recovery_objectives_observed_passed
        ):
            raise DisasterRecoveryCommandError("failed result cannot pass recovery objectives")
        _timestamp(self.observed_at, "observed_at")


class DisasterRecoveryCommandBackend(Protocol):
    """Injected execution boundary for disaster recovery commands."""

    def execute(self, request: DisasterRecoveryCommandRequest) -> BackendCommandResult: ...


@dataclass(frozen=True, slots=True)
class DisasterRecoveryCommandObservation:
    request_id: str
    request_sha256: str
    command_kind: CommandKind
    backend_ref: str
    backend_version: str
    idempotency_key: str
    outcome: CommandOutcome
    evidence_ref: str
    evidence_sha256: str
    backup_observed: bool
    restore_observed: bool
    recovery_objectives_observed_passed: bool
    cleanup_observed_complete: bool
    reason_codes: tuple[str, ...]
    backend_call_performed: bool
    observation_source: str
    observed_at: str
    observation_id: str = field(init=False)
    observation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-command-observation.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.startswith("DRCQ-"):
            raise DisasterRecoveryCommandError("observation request_id is invalid")
        _digest(self.request_sha256, "request_sha256")
        object.__setattr__(
            self, "command_kind", _enum(CommandKind, self.command_kind, "command_kind")
        )
        _reference(self.backend_ref, "backend_ref", "backendref")
        _version(self.backend_version, "backend_version")
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise DisasterRecoveryCommandError("observation idempotency_key is invalid")
        object.__setattr__(self, "outcome", _enum(CommandOutcome, self.outcome, "outcome"))
        _reference(self.evidence_ref, "evidence_ref", "evidenceref")
        _digest(self.evidence_sha256, "evidence_sha256")
        for name in (
            "backup_observed",
            "restore_observed",
            "recovery_objectives_observed_passed",
            "cleanup_observed_complete",
        ):
            if not isinstance(getattr(self, name), bool):
                raise DisasterRecoveryCommandError(f"{name} must be boolean")
        object.__setattr__(self, "reason_codes", _reasons(self.reason_codes))
        if self.outcome is CommandOutcome.COMPLETED and self.reason_codes:
            raise DisasterRecoveryCommandError("completed observation must not have reasons")
        if self.outcome is not CommandOutcome.COMPLETED and not self.reason_codes:
            raise DisasterRecoveryCommandError("non-completed observation must have reasons")
        if self.outcome is CommandOutcome.PARTIAL_CLEANUP and self.cleanup_observed_complete:
            raise DisasterRecoveryCommandError("partial cleanup cannot be complete")
        if not isinstance(self.backend_call_performed, bool):
            raise DisasterRecoveryCommandError("backend_call_performed must be boolean")
        if self.outcome is CommandOutcome.BLOCKED_PREFLIGHT:
            if self.backend_call_performed or self.observation_source != "request_preflight":
                raise DisasterRecoveryCommandError("blocked preflight cannot call the backend")
            if any(
                (
                    self.backup_observed,
                    self.restore_observed,
                    self.recovery_objectives_observed_passed,
                    self.cleanup_observed_complete,
                )
            ):
                raise DisasterRecoveryCommandError("blocked preflight cannot claim execution")
        elif (
            not self.backend_call_performed or self.observation_source != "supplied_backend_result"
        ):
            raise DisasterRecoveryCommandError("runtime observation must come from the backend")
        if (
            self.outcome is not CommandOutcome.COMPLETED
            and self.recovery_objectives_observed_passed
        ):
            raise DisasterRecoveryCommandError("failed observation cannot pass recovery objectives")
        _timestamp(self.observed_at, "observed_at")
        observation_id, digest = _identity("DRCO", self.KIND, self._body())
        object.__setattr__(self, "observation_id", observation_id)
        object.__setattr__(self, "observation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "backend_call_performed": self.backend_call_performed,
            "backend_ref": self.backend_ref,
            "backend_version": self.backend_version,
            "backup_observed": self.backup_observed,
            "cleanup_observed_complete": self.cleanup_observed_complete,
            "command_kind": self.command_kind.value,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "idempotency_key": self.idempotency_key,
            "kind": self.KIND,
            "observation_source": self.observation_source,
            "observed_at": self.observed_at,
            "outcome": self.outcome.value,
            "reason_codes": list(self.reason_codes),
            "recovery_objectives_observed_passed": self.recovery_objectives_observed_passed,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "restore_observed": self.restore_observed,
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DisasterRecoveryCommandObservation:
        expected = _field_names(cls, omit={"observation_id", "observation_sha256"})
        expected |= {"schema_version", "kind", "observation_id", "observation_sha256"}
        value = _exact(raw, expected, "disaster recovery command observation")
        if value["schema_version"] != SCHEMA_VERSION or value["kind"] != cls.KIND:
            raise DisasterRecoveryCommandError("command observation discriminator is invalid")
        _verify_address(value, "observation_id", "observation_sha256", "DRCO", cls.KIND)
        return cls(
            **{
                key: value[key]
                for key in _field_names(cls)
                if key not in {"observation_id", "observation_sha256"}
            }
        )


@dataclass(frozen=True, slots=True)
class DisasterRecoveryCommandReceipt:
    tenant_ref: str
    system_ref: str
    scope_ref: str
    request_id: str
    request_sha256: str
    observation_id: str
    observation_sha256: str
    command_kind: CommandKind
    outcome: CommandOutcome
    idempotency_key: str
    backup_observed: bool
    restore_observed: bool
    recovery_objectives_observed_passed: bool
    cleanup_observed_complete: bool
    claim_source: str
    qualification_effect: str
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.disaster-recovery-command-receipt.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.system_ref, "system_ref", "systemref")
        _reference(self.scope_ref, "scope_ref", "scoperef")
        if not isinstance(self.request_id, str) or not self.request_id.startswith("DRCQ-"):
            raise DisasterRecoveryCommandError("receipt request_id is invalid")
        if not isinstance(self.observation_id, str) or not self.observation_id.startswith("DRCO-"):
            raise DisasterRecoveryCommandError("receipt observation_id is invalid")
        _digest(self.request_sha256, "request_sha256")
        _digest(self.observation_sha256, "observation_sha256")
        object.__setattr__(
            self, "command_kind", _enum(CommandKind, self.command_kind, "command_kind")
        )
        object.__setattr__(self, "outcome", _enum(CommandOutcome, self.outcome, "outcome"))
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise DisasterRecoveryCommandError("receipt idempotency_key is invalid")
        for name in (
            "backup_observed",
            "restore_observed",
            "recovery_objectives_observed_passed",
            "cleanup_observed_complete",
        ):
            if not isinstance(getattr(self, name), bool):
                raise DisasterRecoveryCommandError(f"{name} must be boolean")
        if self.claim_source not in {"supplied_backend_result", "request_preflight"}:
            raise DisasterRecoveryCommandError("claim_source is invalid")
        if self.claim_source == "request_preflight":
            if self.outcome is not CommandOutcome.BLOCKED_PREFLIGHT or any(
                (
                    self.backup_observed,
                    self.restore_observed,
                    self.recovery_objectives_observed_passed,
                    self.cleanup_observed_complete,
                )
            ):
                raise DisasterRecoveryCommandError("preflight receipt cannot claim execution")
        elif self.outcome is CommandOutcome.BLOCKED_PREFLIGHT:
            raise DisasterRecoveryCommandError("backend receipt cannot claim blocked preflight")
        if self.qualification_effect != "none":
            raise DisasterRecoveryCommandError("command receipt cannot change qualification")
        receipt_id, digest = _identity("DRCR", self.KIND, self._body())
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "backup_observed": self.backup_observed,
            "claim_source": self.claim_source,
            "cleanup_observed_complete": self.cleanup_observed_complete,
            "command_kind": self.command_kind.value,
            "idempotency_key": self.idempotency_key,
            "kind": self.KIND,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "outcome": self.outcome.value,
            "qualification_effect": self.qualification_effect,
            "recovery_objectives_observed_passed": self.recovery_objectives_observed_passed,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "restore_observed": self.restore_observed,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "system_ref": self.system_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DisasterRecoveryCommandReceipt:
        expected = _field_names(cls, omit={"receipt_id", "receipt_sha256"})
        expected |= {"schema_version", "kind", "receipt_id", "receipt_sha256"}
        value = _exact(raw, expected, "disaster recovery command receipt")
        if value["schema_version"] != SCHEMA_VERSION or value["kind"] != cls.KIND:
            raise DisasterRecoveryCommandError("command receipt discriminator is invalid")
        _verify_address(value, "receipt_id", "receipt_sha256", "DRCR", cls.KIND)
        return cls(
            **{
                key: value[key]
                for key in _field_names(cls)
                if key not in {"receipt_id", "receipt_sha256"}
            }
        )


def _validate_source_contracts(
    objective: RecoveryObjective,
    manifest: BackupManifest,
    plan: RestorationRehearsalPlan,
) -> None:
    if RecoveryObjective.from_dict(objective.to_dict()) != objective:
        raise DisasterRecoveryCommandError("objective is not canonical")
    if BackupManifest.from_dict(manifest.to_dict()) != manifest:
        raise DisasterRecoveryCommandError("manifest is not canonical")
    if RestorationRehearsalPlan.from_dict(plan.to_dict()) != plan:
        raise DisasterRecoveryCommandError("plan is not canonical")
    contexts = {
        (objective.tenant_ref, objective.system_ref, objective.system_version),
        (manifest.tenant_ref, manifest.system_ref, manifest.system_version),
        (plan.tenant_ref, plan.system_ref, plan.system_version),
    }
    if len(contexts) != 1:
        raise DisasterRecoveryCommandError("tenant and system bindings do not match")
    if (plan.objective_id, plan.objective_sha256) != (
        objective.objective_id,
        objective.objective_sha256,
    ):
        raise DisasterRecoveryCommandError("plan objective binding does not match")
    if (plan.backup_manifest_id, plan.backup_manifest_sha256) != (
        manifest.manifest_id,
        manifest.manifest_sha256,
    ):
        raise DisasterRecoveryCommandError("plan manifest binding does not match")


def build_disaster_recovery_command_request(
    *,
    objective: RecoveryObjective,
    manifest: BackupManifest,
    plan: RestorationRehearsalPlan,
    scope_ref: str,
    scope_sha256: str,
    command_kind: CommandKind | str,
    backend_ref: str,
    backend_version: str,
    authorization: AuthorizationBinding,
    idempotency_key: str,
    budget: ExecutionBudget,
    isolation: RehearsalIsolationBinding,
    fence: FenceBinding,
    cleanup: CleanupBinding,
    preflight_passed: bool,
    preflight_evidence_ref: str,
    preflight_evidence_sha256: str,
    preflight_reason_codes: Sequence[str],
    requested_at: str,
    expires_at: str,
) -> DisasterRecoveryCommandRequest:
    """Build an exact request after validating all source contract bindings."""

    _validate_source_contracts(objective, manifest, plan)
    if authorization.operator_ref != plan.executor_ref:
        raise DisasterRecoveryCommandError("authorized operator does not match rehearsal executor")
    return DisasterRecoveryCommandRequest(
        tenant_ref=objective.tenant_ref,
        system_ref=objective.system_ref,
        system_version=objective.system_version,
        scope_ref=scope_ref,
        scope_sha256=scope_sha256,
        command_kind=command_kind,
        objective_id=objective.objective_id,
        objective_sha256=objective.objective_sha256,
        manifest_id=manifest.manifest_id,
        manifest_sha256=manifest.manifest_sha256,
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        backend_ref=backend_ref,
        backend_version=backend_version,
        authorization=authorization,
        idempotency_key=idempotency_key,
        budget=budget,
        isolation=isolation,
        fence=fence,
        cleanup=cleanup,
        preflight_passed=preflight_passed,
        preflight_evidence_ref=preflight_evidence_ref,
        preflight_evidence_sha256=preflight_evidence_sha256,
        preflight_reason_codes=tuple(preflight_reason_codes),
        requested_at=requested_at,
        expires_at=expires_at,
    )


def execute_disaster_recovery_command(
    request: DisasterRecoveryCommandRequest,
    backend: DisasterRecoveryCommandBackend,
    *,
    observed_at: str,
) -> tuple[DisasterRecoveryCommandObservation, DisasterRecoveryCommandReceipt]:
    """Execute at most one injected call and preserve the observation boundary."""

    if DisasterRecoveryCommandRequest.from_dict(request.to_dict()) != request:
        raise DisasterRecoveryCommandError("request is not canonical")
    observed = _timestamp(observed_at, "observed_at")
    if observed < _timestamp(request.requested_at, "requested_at"):
        raise DisasterRecoveryCommandError("observation predates request")
    if observed >= _timestamp(request.expires_at, "expires_at"):
        raise DisasterRecoveryCommandError("request expired before execution")

    if not request.preflight_passed:
        observation = DisasterRecoveryCommandObservation(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            command_kind=request.command_kind,
            backend_ref=request.backend_ref,
            backend_version=request.backend_version,
            idempotency_key=request.idempotency_key,
            outcome=CommandOutcome.BLOCKED_PREFLIGHT,
            evidence_ref=request.preflight_evidence_ref,
            evidence_sha256=request.preflight_evidence_sha256,
            backup_observed=False,
            restore_observed=False,
            recovery_objectives_observed_passed=False,
            cleanup_observed_complete=False,
            reason_codes=request.preflight_reason_codes,
            backend_call_performed=False,
            observation_source="request_preflight",
            observed_at=observed_at,
        )
    else:
        result = backend.execute(request)
        if not isinstance(result, BackendCommandResult):
            raise DisasterRecoveryCommandError("backend returned an invalid result")
        expected = (
            request.request_id,
            request.request_sha256,
            request.backend_ref,
            request.backend_version,
            request.idempotency_key,
        )
        actual = (
            result.request_id,
            result.request_sha256,
            result.backend_ref,
            result.backend_version,
            result.idempotency_key,
        )
        if actual != expected:
            raise DisasterRecoveryCommandError("backend result binding does not match request")
        if result.observed_at != observed_at:
            raise DisasterRecoveryCommandError(
                "backend observation time does not match caller binding"
            )
        if (
            request.command_kind
            in {
                CommandKind.REHEARSE_RESTORE,
                CommandKind.VERIFY_RESTORE,
            }
            and result.outcome is CommandOutcome.COMPLETED
            and not result.restore_observed
        ):
            raise DisasterRecoveryCommandError(
                "completed restore command requires restore observation"
            )
        if (
            request.command_kind in {CommandKind.CREATE_BACKUP, CommandKind.VERIFY_BACKUP}
            and result.outcome is CommandOutcome.COMPLETED
            and not result.backup_observed
        ):
            raise DisasterRecoveryCommandError(
                "completed backup command requires backup observation"
            )
        if (
            request.command_kind is CommandKind.CLEANUP_REHEARSAL
            and result.outcome is CommandOutcome.COMPLETED
            and not result.cleanup_observed_complete
        ):
            raise DisasterRecoveryCommandError("completed cleanup requires cleanup observation")
        if (
            request.command_kind is CommandKind.VERIFY_RESTORE
            and result.outcome is CommandOutcome.COMPLETED
            and not result.recovery_objectives_observed_passed
        ):
            raise DisasterRecoveryCommandError(
                "completed restore verification requires objective observation"
            )
        if (
            result.recovery_objectives_observed_passed
            and request.command_kind is not CommandKind.VERIFY_RESTORE
        ):
            raise DisasterRecoveryCommandError(
                "only restore verification may pass recovery objectives"
            )
        observation = DisasterRecoveryCommandObservation(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            command_kind=request.command_kind,
            backend_ref=result.backend_ref,
            backend_version=result.backend_version,
            idempotency_key=result.idempotency_key,
            outcome=result.outcome,
            evidence_ref=result.evidence_ref,
            evidence_sha256=result.evidence_sha256,
            backup_observed=result.backup_observed,
            restore_observed=result.restore_observed,
            recovery_objectives_observed_passed=result.recovery_objectives_observed_passed,
            cleanup_observed_complete=result.cleanup_observed_complete,
            reason_codes=result.reason_codes,
            backend_call_performed=True,
            observation_source="supplied_backend_result",
            observed_at=observed_at,
        )

    receipt = DisasterRecoveryCommandReceipt(
        tenant_ref=request.tenant_ref,
        system_ref=request.system_ref,
        scope_ref=request.scope_ref,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        observation_id=observation.observation_id,
        observation_sha256=observation.observation_sha256,
        command_kind=request.command_kind,
        outcome=observation.outcome,
        idempotency_key=request.idempotency_key,
        backup_observed=observation.backup_observed,
        restore_observed=observation.restore_observed,
        recovery_objectives_observed_passed=(observation.recovery_objectives_observed_passed),
        cleanup_observed_complete=observation.cleanup_observed_complete,
        claim_source=observation.observation_source,
        qualification_effect="none",
    )
    return observation, receipt


def parse_disaster_recovery_command_record(
    raw: Mapping[str, Any] | str,
) -> (
    DisasterRecoveryCommandRequest
    | DisasterRecoveryCommandObservation
    | DisasterRecoveryCommandReceipt
):
    """Parse one strict command record by its discriminator."""

    try:
        document = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as exc:
        raise DisasterRecoveryCommandError("record is not valid JSON") from exc
    if not isinstance(document, Mapping):
        raise DisasterRecoveryCommandError("record must be an object")
    factories = {
        DisasterRecoveryCommandRequest.KIND: DisasterRecoveryCommandRequest.from_dict,
        DisasterRecoveryCommandObservation.KIND: DisasterRecoveryCommandObservation.from_dict,
        DisasterRecoveryCommandReceipt.KIND: DisasterRecoveryCommandReceipt.from_dict,
    }
    factory = factories.get(document.get("kind"))
    if factory is None:
        raise DisasterRecoveryCommandError("record kind is unsupported")
    return factory(document)
