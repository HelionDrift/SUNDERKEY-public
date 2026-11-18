"""Closed, repository-only target-health execution gate contracts.

The contracts bind exact current health custody to a target-scoped deny gate.
They grant no authority, scope, tier, budget, credential use, dispatch, network
access, target effect, executor pause, or executor resume.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

from .action_admission_contracts import (
    ContextBinding,
    CredentialLease,
    TargetBinding,
    WorkerSession,
)
from .authorized_target_health_runtime import HealthSignalState, TargetHealthStatus
from .execution_control_runtime import ExecutionBinding
from .target_health_custody_contracts import TargetHealthCurrentHeadInspection

SCHEMA_VERSION = 1
MINIMUM_RECOVERY_HEALTHY_OBSERVATIONS = 2
MAX_DOCUMENT_BYTES = 1_048_576
TARGET_HEALTH_GATE_RESUME_OPERATION = "sunderkey.target-health-gate.resume.v1"

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_RECORD_RE = re.compile(r"([A-Z]{3,8})-([0-9A-F]{32})\Z")

_NO_EFFECTS = {
    "authority_effect": "none",
    "budget_effect": "none",
    "credential_effect": "none",
    "dispatch_effect": "none",
    "network_call_performed": False,
    "qualification_effect": "none",
    "scope_effect": "none",
    "target_effect_performed": False,
    "tier_effect": "none",
}
_NO_EFFECT_FIELDS = frozenset(_NO_EFFECTS)
_RESUMPTION_AUTHORIZATION_FIELDS = {
    "assertion_id",
    "assertion_issuer",
    "assertion_sha256",
    "authority_use_sequence",
    "canonical_replay_key_sha256",
    "decision",
    "expires_at",
    "issued_at",
    "mission_id",
    "operation",
    "operation_intent_sha256",
    "pause_epoch",
    "principal_profile_id",
    "principal_subject",
    "recovery_intent_id",
    "recovery_intent_sha256",
    "role",
    "scope_sha256",
    "target_sha256",
    "tenant_id",
}


class TargetHealthGateContractError(ValueError):
    """Raised when a target-health gate contract fails closed."""


class TargetHealthGateState(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    RECOVERY_PENDING = "recovery_pending"


class TargetHealthGateClassification(StrEnum):
    HEALTHY = "healthy"
    ADVERSE = "adverse"


class TargetHealthGateTransitionKind(StrEnum):
    INITIALIZED_ACTIVE = "initialized_active"
    INITIALIZED_PAUSED = "initialized_paused"
    ACTIVE_HEALTH_CONFIRMED = "active_health_confirmed"
    PAUSE_ASSERTED = "pause_asserted"
    PAUSE_REAFFIRMED = "pause_reaffirmed"
    RECOVERY_STARTED = "recovery_started"
    RECOVERY_ADVANCED = "recovery_advanced"
    RECOVERY_RESTARTED = "recovery_restarted"
    RECOVERY_HELD = "recovery_held"
    RECOVERY_RESET = "recovery_reset"
    CONTROL_RESUMED = "control_resumed"


class TargetHealthGateDecisionStatus(StrEnum):
    DENY_NEW_TARGET_WORK = "deny_new_target_work"
    PERMIT_HEALTH_GATE_EVALUATION = "permit_health_gate_evaluation"


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
        raise TargetHealthGateContractError("value cannot be canonicalized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": dict(body), "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise TargetHealthGateContractError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise TargetHealthGateContractError(f"{label} must be a SHA-256 content address")
    return value


def _record_id(value: Any, prefix: str, label: str) -> str:
    if not isinstance(value, str):
        raise TargetHealthGateContractError(f"{label} is invalid")
    match = _RECORD_RE.fullmatch(value)
    if match is None or match.group(1) != prefix:
        raise TargetHealthGateContractError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TargetHealthGateContractError(f"{label} is invalid")
    if maximum is not None and value > maximum:
        raise TargetHealthGateContractError(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise TargetHealthGateContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise TargetHealthGateContractError(f"{label} is invalid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise TargetHealthGateContractError(f"{label} is invalid") from exc


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise TargetHealthGateContractError(f"{label} fields are invalid")
    return dict(value)


def _check_metadata(value: Mapping[str, Any], kind: str) -> None:
    if value.get("kind") != kind:
        raise TargetHealthGateContractError("contract kind is invalid")
    version = value.get("schema_version")
    if isinstance(version, bool) or version != SCHEMA_VERSION:
        raise TargetHealthGateContractError("contract schema version is invalid")
    for field, expected in _NO_EFFECTS.items():
        actual = value.get(field)
        valid = actual is expected if isinstance(expected, bool) else actual == expected
        if not valid:
            raise TargetHealthGateContractError("contract attempts effect escalation")


def _execution_binding_from_dict(value: Any) -> ExecutionBinding:
    try:
        return ExecutionBinding(
            **_exact(value, set(ExecutionBinding.__dataclass_fields__), "execution binding")
        )
    except TargetHealthGateContractError:
        raise
    except ValueError as exc:
        raise TargetHealthGateContractError("execution binding is invalid") from exc


def execution_binding_sha256(binding: ExecutionBinding) -> str:
    if not isinstance(binding, ExecutionBinding):
        raise TargetHealthGateContractError("execution binding is invalid")
    return canonical_sha256(binding.to_dict())


def build_target_health_execution_binding(
    *,
    context: ContextBinding,
    worker_session: WorkerSession,
    credential_lease: CredentialLease,
    target: TargetBinding,
) -> ExecutionBinding:
    """Build the one exact health binding from authenticated admission records."""

    values = (
        (context, ContextBinding, "context"),
        (worker_session, WorkerSession, "worker_session"),
        (credential_lease, CredentialLease, "credential_lease"),
        (target, TargetBinding, "target"),
    )
    for value, expected, label in values:
        if not isinstance(value, expected):
            raise TargetHealthGateContractError(f"{label} is invalid")
    try:
        validated = (
            ContextBinding.from_dict(context.to_dict()),
            WorkerSession.from_dict(worker_session.to_dict()),
            CredentialLease.from_dict(credential_lease.to_dict()),
            TargetBinding.from_dict(target.to_dict()),
        )
    except (TypeError, ValueError) as exc:
        raise TargetHealthGateContractError("admission record is invalid") from exc
    if validated != (context, worker_session, credential_lease, target):
        raise TargetHealthGateContractError("admission record is not canonical")
    matches = (
        worker_session.tenant_id == context.tenant_id,
        credential_lease.tenant_id == context.tenant_id,
        target.tenant_id == context.tenant_id,
        worker_session.mission_id == context.mission_id,
        credential_lease.mission_id == context.mission_id,
        target.mission_id == context.mission_id,
        hmac.compare_digest(credential_lease.scope_sha256, context.scope_sha256),
        hmac.compare_digest(target.scope_sha256, context.scope_sha256),
        credential_lease.worker_id == worker_session.worker_id,
        credential_lease.session_id == worker_session.session_id,
        hmac.compare_digest(
            credential_lease.fence_token_sha256,
            worker_session.fence_token_sha256,
        ),
        credential_lease.leader_epoch == worker_session.leader_epoch,
    )
    if not all(matches):
        raise TargetHealthGateContractError("admission records cross an identity boundary")
    if credential_lease.revoked:
        raise TargetHealthGateContractError("revoked credential lease cannot bind health")
    return ExecutionBinding(
        tenant_id=context.tenant_id,
        context_id=context.mission_id,
        context_sha256=canonical_sha256(context.to_dict()),
        scope_id=context.scope_id,
        scope_sha256=context.scope_sha256,
        target_id=target.target_id,
        target_sha256=target.target_sha256,
        session_id=worker_session.session_id,
        lease_id=credential_lease.lease_id,
        fence_epoch=worker_session.leader_epoch,
    )


@dataclass(frozen=True, slots=True)
class TargetHealthGateSubject:
    tenant_id: str
    mission_id: str
    scope_sha256: str
    target_sha256: str
    subject_id: str = ""
    subject_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-gate-subject.v1"
    PREFIX: ClassVar[str] = "THGS"

    def __post_init__(self) -> None:
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _digest(self.scope_sha256, "scope_sha256")
        _digest(self.target_sha256, "target_sha256")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.subject_id and not hmac.compare_digest(self.subject_id, identifier):
            raise TargetHealthGateContractError("subject_id does not match content")
        if self.subject_sha256 and not hmac.compare_digest(self.subject_sha256, digest):
            raise TargetHealthGateContractError("subject_sha256 does not match content")
        object.__setattr__(self, "subject_id", identifier)
        object.__setattr__(self, "subject_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "scope_sha256": self.scope_sha256,
            "target_sha256": self.target_sha256,
            "tenant_id": self.tenant_id,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "subject_id": self.subject_id,
            "subject_sha256": self.subject_sha256,
        }

    @classmethod
    def from_dict(cls, value: Any) -> TargetHealthGateSubject:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        data = _exact(value, fields | {"kind", "schema_version", *_NO_EFFECT_FIELDS}, "subject")
        _check_metadata(data, cls.KIND)
        return cls(**{field: data[field] for field in fields})


def target_health_gate_subject(binding: ExecutionBinding) -> TargetHealthGateSubject:
    if not isinstance(binding, ExecutionBinding):
        raise TargetHealthGateContractError("execution binding is invalid")
    return TargetHealthGateSubject(
        tenant_id=binding.tenant_id,
        mission_id=binding.context_id,
        scope_sha256=binding.scope_sha256,
        target_sha256=binding.target_sha256,
    )


def _binds_subject(subject: TargetHealthGateSubject, binding: ExecutionBinding) -> bool:
    return (
        binding.tenant_id == subject.tenant_id
        and binding.context_id == subject.mission_id
        and hmac.compare_digest(binding.scope_sha256, subject.scope_sha256)
        and hmac.compare_digest(binding.target_sha256, subject.target_sha256)
    )


def target_health_gate_inspection_context_sha256(
    *,
    subject: TargetHealthGateSubject,
    binding_sha256: str,
    observation_sequence: int,
    previous_observation_sha256: str | None,
) -> str:
    """Bind one live inspection to its exact append position."""

    if not isinstance(subject, TargetHealthGateSubject):
        raise TargetHealthGateContractError("inspection context subject is invalid")
    _digest(binding_sha256, "binding_sha256")
    _integer(observation_sequence, "observation_sequence", 1)
    if observation_sequence == 1:
        if previous_observation_sha256 is not None:
            raise TargetHealthGateContractError(
                "first inspection context has a predecessor"
            )
    else:
        _digest(previous_observation_sha256, "previous_observation_sha256")
    return canonical_sha256(
        {
            "binding_sha256": binding_sha256,
            "domain": "sunderkey.target-health-gate-inspection-context.v1",
            "observation_sequence": observation_sequence,
            "previous_observation_sha256": previous_observation_sha256,
            "subject_id": subject.subject_id,
            "subject_sha256": subject.subject_sha256,
        }
    )


@dataclass(frozen=True, slots=True)
class TargetHealthGateObservation:
    subject: TargetHealthGateSubject
    observation_sequence: int
    previous_observation_sha256: str | None
    binding: ExecutionBinding
    binding_sha256: str
    inspection: TargetHealthCurrentHeadInspection
    classification: TargetHealthGateClassification
    evidence_advanced: bool
    recorded_at: str
    observation_id: str = ""
    observation_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-gate-observation.v1"
    PREFIX: ClassVar[str] = "THGO"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, TargetHealthGateSubject):
            raise TargetHealthGateContractError("observation subject is invalid")
        _integer(self.observation_sequence, "observation_sequence", 1)
        if self.observation_sequence == 1:
            if self.previous_observation_sha256 is not None:
                raise TargetHealthGateContractError("first observation has a predecessor")
        else:
            _digest(self.previous_observation_sha256, "previous_observation_sha256")
        if not isinstance(self.binding, ExecutionBinding):
            raise TargetHealthGateContractError("observation binding is invalid")
        _digest(self.binding_sha256, "binding_sha256")
        if not hmac.compare_digest(self.binding_sha256, execution_binding_sha256(self.binding)):
            raise TargetHealthGateContractError("binding_sha256 does not match binding")
        if not _binds_subject(self.subject, self.binding):
            raise TargetHealthGateContractError("observation binding crosses its subject")
        if not isinstance(self.inspection, TargetHealthCurrentHeadInspection):
            raise TargetHealthGateContractError("inspection is invalid")
        expected_inspection_context = target_health_gate_inspection_context_sha256(
            subject=self.subject,
            binding_sha256=self.binding_sha256,
            observation_sequence=self.observation_sequence,
            previous_observation_sha256=self.previous_observation_sha256,
        )
        if self.inspection.inspection_context_sha256 is not None and not hmac.compare_digest(
            self.inspection.inspection_context_sha256, expected_inspection_context
        ):
            raise TargetHealthGateContractError(
                "inspection context does not match observation position"
            )
        receipt = self.inspection.envelope.receipt
        if receipt.binding != self.binding or not hmac.compare_digest(
            receipt.binding_sha256, self.binding_sha256
        ):
            raise TargetHealthGateContractError("inspection binding is substituted")
        object.__setattr__(
            self,
            "classification",
            _enum(TargetHealthGateClassification, self.classification, "classification"),
        )
        expected_classification = (
            TargetHealthGateClassification.HEALTHY
            if receipt.status is TargetHealthStatus.COMPLETED
            and receipt.overall_health is HealthSignalState.HEALTHY
            else TargetHealthGateClassification.ADVERSE
        )
        if self.classification is not expected_classification:
            raise TargetHealthGateContractError("observation classification is overclaimed")
        if not isinstance(self.evidence_advanced, bool):
            raise TargetHealthGateContractError("evidence_advanced must be boolean")
        if (
            self.evidence_advanced
            and self.classification is not TargetHealthGateClassification.HEALTHY
        ):
            raise TargetHealthGateContractError("adverse evidence cannot advance recovery")
        _utc(self.recorded_at, "recorded_at")
        if _instant(self.recorded_at) < _instant(self.inspection.inspected_at):
            raise TargetHealthGateContractError("observation predates inspection")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.observation_id and not hmac.compare_digest(self.observation_id, identifier):
            raise TargetHealthGateContractError("observation_id does not match content")
        if self.observation_sha256 and not hmac.compare_digest(self.observation_sha256, digest):
            raise TargetHealthGateContractError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_id", identifier)
        object.__setattr__(self, "observation_sha256", digest)

    @property
    def inspection_id(self) -> str:
        return self.inspection.inspection_id

    @property
    def inspection_sha256(self) -> str:
        return self.inspection.inspection_sha256

    @property
    def head_binding_id(self) -> str:
        return self.inspection.head_binding.head_binding_id

    @property
    def head_binding_sha256(self) -> str:
        return self.inspection.head_binding.head_binding_sha256

    @property
    def global_transition_sequence(self) -> int:
        return self.inspection.head_binding.global_transition_sequence

    @property
    def chain_id(self) -> str:
        return self.inspection.chain_id

    @property
    def envelope_id(self) -> str:
        return self.inspection.envelope.envelope_id

    @property
    def envelope_sha256(self) -> str:
        return self.inspection.envelope.envelope_sha256

    @property
    def envelope_sequence(self) -> int:
        return self.inspection.envelope.sequence

    @property
    def predecessor_envelope_id(self) -> str | None:
        return self.inspection.envelope.predecessor_envelope_id

    @property
    def predecessor_envelope_sha256(self) -> str | None:
        return self.inspection.envelope.predecessor_envelope_sha256

    @property
    def receipt_id(self) -> str:
        return self.inspection.envelope.receipt.receipt_id

    @property
    def receipt_sha256(self) -> str:
        return self.inspection.envelope.receipt.receipt_sha256

    @property
    def receipt_status(self) -> str:
        return self.inspection.envelope.receipt.status.value

    @property
    def overall_health(self) -> str | None:
        health = self.inspection.envelope.receipt.overall_health
        return None if health is None else health.value

    @property
    def observed_at(self) -> str:
        return self.inspection.envelope.receipt.observed_at

    @property
    def inspected_at(self) -> str:
        return self.inspection.inspected_at

    @property
    def current_material_sha256(self) -> str:
        return self.inspection.current_material_sha256

    def body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "classification": self.classification.value,
            "evidence_advanced": self.evidence_advanced,
            "inspection": self.inspection.to_dict(),
            "observation_sequence": self.observation_sequence,
            "previous_observation_sha256": self.previous_observation_sha256,
            "recorded_at": self.recorded_at,
            "subject": self.subject.to_dict(),
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: Any) -> TargetHealthGateObservation:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        data = _exact(value, fields | {"kind", "schema_version", *_NO_EFFECT_FIELDS}, "observation")
        _check_metadata(data, cls.KIND)
        args = {field: data[field] for field in fields}
        args["subject"] = TargetHealthGateSubject.from_dict(args["subject"])
        args["binding"] = _execution_binding_from_dict(args["binding"])
        args["inspection"] = TargetHealthCurrentHeadInspection.from_dict(args["inspection"])
        return cls(**args)


def build_target_health_gate_observation(
    *,
    inspection: TargetHealthCurrentHeadInspection,
    observation_sequence: int,
    previous_observation_sha256: str | None,
    evidence_advanced: bool,
    recorded_at: str,
) -> TargetHealthGateObservation:
    if not isinstance(inspection, TargetHealthCurrentHeadInspection):
        raise TargetHealthGateContractError("inspection is invalid")
    if inspection.inspection_context_sha256 is None:
        raise TargetHealthGateContractError(
            "new observation requires an inspection context"
        )
    binding = inspection.envelope.receipt.binding
    healthy = (
        inspection.envelope.receipt.status is TargetHealthStatus.COMPLETED
        and inspection.envelope.receipt.overall_health is HealthSignalState.HEALTHY
    )
    return TargetHealthGateObservation(
        subject=target_health_gate_subject(binding),
        observation_sequence=observation_sequence,
        previous_observation_sha256=previous_observation_sha256,
        binding=binding,
        binding_sha256=inspection.envelope.receipt.binding_sha256,
        inspection=inspection,
        classification=(
            TargetHealthGateClassification.HEALTHY
            if healthy
            else TargetHealthGateClassification.ADVERSE
        ),
        evidence_advanced=evidence_advanced,
        recorded_at=recorded_at,
    )


_TRANSITION_SHAPES = {
    TargetHealthGateTransitionKind.INITIALIZED_ACTIVE: (None, TargetHealthGateState.ACTIVE, 0, 0),
    TargetHealthGateTransitionKind.INITIALIZED_PAUSED: (None, TargetHealthGateState.PAUSED, 1, 0),
    TargetHealthGateTransitionKind.ACTIVE_HEALTH_CONFIRMED: (
        TargetHealthGateState.ACTIVE,
        TargetHealthGateState.ACTIVE,
        None,
        0,
    ),
    TargetHealthGateTransitionKind.PAUSE_ASSERTED: (
        TargetHealthGateState.ACTIVE,
        TargetHealthGateState.PAUSED,
        None,
        0,
    ),
    TargetHealthGateTransitionKind.PAUSE_REAFFIRMED: (
        TargetHealthGateState.PAUSED,
        TargetHealthGateState.PAUSED,
        None,
        0,
    ),
    TargetHealthGateTransitionKind.RECOVERY_STARTED: (
        TargetHealthGateState.PAUSED,
        TargetHealthGateState.RECOVERY_PENDING,
        None,
        1,
    ),
    TargetHealthGateTransitionKind.RECOVERY_ADVANCED: (
        TargetHealthGateState.RECOVERY_PENDING,
        TargetHealthGateState.RECOVERY_PENDING,
        None,
        2,
    ),
    TargetHealthGateTransitionKind.RECOVERY_RESTARTED: (
        TargetHealthGateState.RECOVERY_PENDING,
        TargetHealthGateState.RECOVERY_PENDING,
        None,
        1,
    ),
    TargetHealthGateTransitionKind.RECOVERY_HELD: (
        TargetHealthGateState.RECOVERY_PENDING,
        TargetHealthGateState.RECOVERY_PENDING,
        None,
        None,
    ),
    TargetHealthGateTransitionKind.RECOVERY_RESET: (
        TargetHealthGateState.RECOVERY_PENDING,
        TargetHealthGateState.PAUSED,
        None,
        0,
    ),
    TargetHealthGateTransitionKind.CONTROL_RESUMED: (
        TargetHealthGateState.RECOVERY_PENDING,
        TargetHealthGateState.ACTIVE,
        None,
        0,
    ),
}


@dataclass(frozen=True, slots=True)
class TargetHealthGateTransition:
    subject: TargetHealthGateSubject
    transition_sequence: int
    previous_transition_sha256: str | None
    transition_kind: TargetHealthGateTransitionKind
    from_state: TargetHealthGateState | None
    to_state: TargetHealthGateState
    pause_epoch: int
    recovery_healthy_count: int
    observation_id: str | None
    observation_sha256: str | None
    resumption_id: str | None
    resumption_sha256: str | None
    occurred_at: str
    pause_effect: str
    resume_effect: str
    transition_id: str = ""
    transition_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-gate-transition.v1"
    PREFIX: ClassVar[str] = "THGT"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, TargetHealthGateSubject):
            raise TargetHealthGateContractError("transition subject is invalid")
        _integer(self.transition_sequence, "transition_sequence", 1)
        if self.transition_sequence == 1:
            if self.previous_transition_sha256 is not None or self.from_state is not None:
                raise TargetHealthGateContractError("initial transition predecessor is invalid")
        else:
            _digest(self.previous_transition_sha256, "previous_transition_sha256")
            if self.from_state is None:
                raise TargetHealthGateContractError("transition prior state is missing")
        object.__setattr__(
            self,
            "transition_kind",
            _enum(TargetHealthGateTransitionKind, self.transition_kind, "transition_kind"),
        )
        if self.from_state is not None:
            object.__setattr__(
                self, "from_state", _enum(TargetHealthGateState, self.from_state, "from_state")
            )
        object.__setattr__(
            self, "to_state", _enum(TargetHealthGateState, self.to_state, "to_state")
        )
        _integer(self.pause_epoch, "pause_epoch")
        _integer(self.recovery_healthy_count, "recovery_healthy_count", 0, 2)
        observation_lineage = self.observation_id is not None or self.observation_sha256 is not None
        resumption_lineage = self.resumption_id is not None or self.resumption_sha256 is not None
        if observation_lineage == resumption_lineage:
            raise TargetHealthGateContractError("transition must have exactly one lineage")
        if observation_lineage:
            _record_id(self.observation_id, "THGO", "observation_id")
            _digest(self.observation_sha256, "observation_sha256")
        else:
            _record_id(self.resumption_id, "THGR", "resumption_id")
            _digest(self.resumption_sha256, "resumption_sha256")
        expected_from, expected_to, fixed_epoch, fixed_count = _TRANSITION_SHAPES[
            self.transition_kind
        ]
        if self.from_state is not expected_from or self.to_state is not expected_to:
            raise TargetHealthGateContractError("transition state shape is invalid")
        if fixed_epoch is not None and self.pause_epoch != fixed_epoch:
            raise TargetHealthGateContractError("transition pause epoch is invalid")
        if fixed_count is not None and self.recovery_healthy_count != fixed_count:
            raise TargetHealthGateContractError("transition recovery count is invalid")
        if self.transition_kind is TargetHealthGateTransitionKind.RECOVERY_HELD and not (
            1 <= self.recovery_healthy_count <= 2
        ):
            raise TargetHealthGateContractError("recovery held count is invalid")
        is_resumption = self.transition_kind is TargetHealthGateTransitionKind.CONTROL_RESUMED
        if is_resumption != resumption_lineage:
            raise TargetHealthGateContractError("transition lineage kind is invalid")
        expected_pause = (
            "none"
            if self.to_state is TargetHealthGateState.ACTIVE
            else TargetHealthGateDecisionStatus.DENY_NEW_TARGET_WORK.value
        )
        expected_resume = (
            TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION.value
            if is_resumption
            else "none"
        )
        if self.pause_effect != expected_pause or self.resume_effect != expected_resume:
            raise TargetHealthGateContractError("transition effects are invalid")
        _utc(self.occurred_at, "occurred_at")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.transition_id and not hmac.compare_digest(self.transition_id, identifier):
            raise TargetHealthGateContractError("transition_id does not match content")
        if self.transition_sha256 and not hmac.compare_digest(self.transition_sha256, digest):
            raise TargetHealthGateContractError("transition_sha256 does not match content")
        object.__setattr__(self, "transition_id", identifier)
        object.__setattr__(self, "transition_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "from_state": None if self.from_state is None else self.from_state.value,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "occurred_at": self.occurred_at,
            "pause_effect": self.pause_effect,
            "pause_epoch": self.pause_epoch,
            "previous_transition_sha256": self.previous_transition_sha256,
            "recovery_healthy_count": self.recovery_healthy_count,
            "resume_effect": self.resume_effect,
            "resumption_id": self.resumption_id,
            "resumption_sha256": self.resumption_sha256,
            "subject": self.subject.to_dict(),
            "to_state": self.to_state.value,
            "transition_kind": self.transition_kind.value,
            "transition_sequence": self.transition_sequence,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "transition_id": self.transition_id,
            "transition_sha256": self.transition_sha256,
        }

    @classmethod
    def from_dict(cls, value: Any) -> TargetHealthGateTransition:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        data = _exact(value, fields | {"kind", "schema_version", *_NO_EFFECT_FIELDS}, "transition")
        _check_metadata(data, cls.KIND)
        args = {field: data[field] for field in fields}
        args["subject"] = TargetHealthGateSubject.from_dict(args["subject"])
        return cls(**args)


@dataclass(frozen=True, slots=True)
class TargetHealthGateHead:
    subject: TargetHealthGateSubject
    latch_state: TargetHealthGateState
    pause_epoch: int
    observation_count: int
    observation_head_sha256: str
    transition_count: int
    transition_head_sha256: str
    resumption_count: int
    recovery_healthy_count: int
    recovery_chain_id: str | None
    recovery_envelope_id: str | None
    recovery_envelope_sha256: str | None
    recovery_envelope_sequence: int | None
    recovery_observed_at: str | None
    last_observation_id: str
    last_observation_sha256: str
    last_binding_sha256: str
    last_inspection_id: str
    last_inspection_sha256: str
    last_head_binding_id: str
    last_head_binding_sha256: str
    last_global_transition_sequence: int
    last_current_material_sha256: str
    last_adverse_observation_id: str | None
    last_adverse_observation_sha256: str | None
    last_resumption_id: str | None
    last_resumption_sha256: str | None
    version: int
    updated_at: str
    head_id: str = ""
    head_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-gate-head.v1"
    PREFIX: ClassVar[str] = "THGH"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, TargetHealthGateSubject):
            raise TargetHealthGateContractError("head subject is invalid")
        object.__setattr__(
            self, "latch_state", _enum(TargetHealthGateState, self.latch_state, "latch_state")
        )
        _integer(self.pause_epoch, "pause_epoch")
        _integer(self.observation_count, "observation_count", 1)
        _digest(self.observation_head_sha256, "observation_head_sha256")
        _integer(self.transition_count, "transition_count", 1)
        _digest(self.transition_head_sha256, "transition_head_sha256")
        _integer(self.resumption_count, "resumption_count")
        if self.transition_count != self.observation_count + self.resumption_count:
            raise TargetHealthGateContractError("head counts are inconsistent")
        _integer(self.recovery_healthy_count, "recovery_healthy_count", 0, 2)
        recovery_values = (
            self.recovery_chain_id,
            self.recovery_envelope_id,
            self.recovery_envelope_sha256,
            self.recovery_envelope_sequence,
            self.recovery_observed_at,
        )
        if self.latch_state is TargetHealthGateState.RECOVERY_PENDING:
            if any(value is None for value in recovery_values):
                raise TargetHealthGateContractError("recovery head lineage is incomplete")
            if not 1 <= self.recovery_healthy_count <= 2:
                raise TargetHealthGateContractError("recovery head count is invalid")
            _record_id(self.recovery_chain_id, "THCH", "recovery_chain_id")
            _record_id(self.recovery_envelope_id, "THCE", "recovery_envelope_id")
            _digest(self.recovery_envelope_sha256, "recovery_envelope_sha256")
            _integer(self.recovery_envelope_sequence, "recovery_envelope_sequence", 1)
            _utc(self.recovery_observed_at, "recovery_observed_at")
        elif (
            any(value is not None for value in recovery_values) or self.recovery_healthy_count != 0
        ):
            raise TargetHealthGateContractError("non-recovery head claims recovery lineage")
        _record_id(self.last_observation_id, "THGO", "last_observation_id")
        for label in (
            "last_observation_sha256",
            "last_binding_sha256",
            "last_inspection_sha256",
            "last_head_binding_sha256",
            "last_current_material_sha256",
        ):
            _digest(getattr(self, label), label)
        _record_id(self.last_inspection_id, "THCI", "last_inspection_id")
        _record_id(self.last_head_binding_id, "THHB", "last_head_binding_id")
        _integer(self.last_global_transition_sequence, "last_global_transition_sequence", 1)
        adverse = (self.last_adverse_observation_id, self.last_adverse_observation_sha256)
        if (adverse[0] is None) != (adverse[1] is None):
            raise TargetHealthGateContractError("last adverse lineage is incomplete")
        if adverse[0] is not None:
            _record_id(adverse[0], "THGO", "last_adverse_observation_id")
            _digest(adverse[1], "last_adverse_observation_sha256")
        resumption = (self.last_resumption_id, self.last_resumption_sha256)
        if self.resumption_count == 0:
            if any(value is not None for value in resumption):
                raise TargetHealthGateContractError("head has unexpected resumption lineage")
        else:
            _record_id(resumption[0], "THGR", "last_resumption_id")
            _digest(resumption[1], "last_resumption_sha256")
        _integer(self.version, "version", 1)
        _utc(self.updated_at, "updated_at")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.head_id and not hmac.compare_digest(self.head_id, identifier):
            raise TargetHealthGateContractError("head_id does not match content")
        if self.head_sha256 and not hmac.compare_digest(self.head_sha256, digest):
            raise TargetHealthGateContractError("head_sha256 does not match content")
        object.__setattr__(self, "head_id", identifier)
        object.__setattr__(self, "head_sha256", digest)

    def body(self) -> dict[str, Any]:
        fields = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field not in {"KIND", "PREFIX", "head_id", "head_sha256", "subject", "latch_state"}
        }
        return {
            **fields,
            "latch_state": self.latch_state.value,
            "subject": self.subject.to_dict(),
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "head_id": self.head_id,
            "head_sha256": self.head_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: Any) -> TargetHealthGateHead:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        data = _exact(value, fields | {"kind", "schema_version", *_NO_EFFECT_FIELDS}, "head")
        _check_metadata(data, cls.KIND)
        args = {field: data[field] for field in fields}
        args["subject"] = TargetHealthGateSubject.from_dict(args["subject"])
        return cls(**args)


def _pair_tuple(values: Sequence[Any], label: str, validator: Any) -> tuple[str, str]:
    if isinstance(values, (str, bytes)) or len(values) != 2:
        raise TargetHealthGateContractError(f"{label} must contain exactly two values")
    result = tuple(validator(value, label) for value in values)
    if result[0] == result[1]:
        raise TargetHealthGateContractError(f"{label} values must be distinct")
    return result  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class TargetHealthGateRecoveryIntent:
    subject: TargetHealthGateSubject
    pause_epoch: int
    current_head_id: str
    current_head_sha256: str
    qualifying_observation_ids: tuple[str, str]
    qualifying_observation_sha256s: tuple[str, str]
    latest_head_binding_id: str
    latest_head_binding_sha256: str
    global_transition_sequence: int
    current_envelope_id: str
    current_envelope_sha256: str
    current_inspection_id: str
    current_inspection_sha256: str
    current_material_sha256: str
    head_last_inspection_id: str
    head_last_inspection_sha256: str
    head_last_current_material_sha256: str
    prepared_at: str
    authority_expires_at: str
    pause_effect: str = "deny_new_target_work"
    resume_effect: str = "permit_health_gate_evaluation"
    recovery_intent_id: str = ""
    recovery_intent_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-gate-recovery-intent.v1"
    PREFIX: ClassVar[str] = "THGI"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, TargetHealthGateSubject):
            raise TargetHealthGateContractError("recovery intent subject is invalid")
        _integer(self.pause_epoch, "pause_epoch", 1)
        _record_id(self.current_head_id, "THGH", "current_head_id")
        _digest(self.current_head_sha256, "current_head_sha256")
        object.__setattr__(
            self,
            "qualifying_observation_ids",
            _pair_tuple(
                self.qualifying_observation_ids,
                "qualifying observation ids",
                lambda value, label: _record_id(value, "THGO", label),
            ),
        )
        object.__setattr__(
            self,
            "qualifying_observation_sha256s",
            _pair_tuple(
                self.qualifying_observation_sha256s, "qualifying observation digests", _digest
            ),
        )
        _record_id(self.latest_head_binding_id, "THHB", "latest_head_binding_id")
        _digest(self.latest_head_binding_sha256, "latest_head_binding_sha256")
        _integer(self.global_transition_sequence, "global_transition_sequence", 1)
        _record_id(self.current_envelope_id, "THCE", "current_envelope_id")
        _digest(self.current_envelope_sha256, "current_envelope_sha256")
        _record_id(self.current_inspection_id, "THCI", "current_inspection_id")
        _digest(self.current_inspection_sha256, "current_inspection_sha256")
        _digest(self.current_material_sha256, "current_material_sha256")
        _record_id(self.head_last_inspection_id, "THCI", "head_last_inspection_id")
        _digest(self.head_last_inspection_sha256, "head_last_inspection_sha256")
        _digest(
            self.head_last_current_material_sha256,
            "head_last_current_material_sha256",
        )
        if (
            self.current_inspection_id == self.head_last_inspection_id
            or hmac.compare_digest(
                self.current_inspection_sha256,
                self.head_last_inspection_sha256,
            )
            or hmac.compare_digest(
                self.current_material_sha256,
                self.head_last_current_material_sha256,
            )
        ):
            raise TargetHealthGateContractError(
                "recovery intent preparation inspection is not fresh"
            )
        _utc(self.prepared_at, "prepared_at")
        _utc(self.authority_expires_at, "authority_expires_at")
        if _instant(self.authority_expires_at) <= _instant(self.prepared_at):
            raise TargetHealthGateContractError("recovery intent validity window is invalid")
        if self.pause_effect != "deny_new_target_work":
            raise TargetHealthGateContractError("recovery intent must preserve denial")
        if self.resume_effect != "permit_health_gate_evaluation":
            raise TargetHealthGateContractError("recovery intent cannot directly resume")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.recovery_intent_id and not hmac.compare_digest(self.recovery_intent_id, identifier):
            raise TargetHealthGateContractError("recovery_intent_id does not match content")
        if self.recovery_intent_sha256 and not hmac.compare_digest(
            self.recovery_intent_sha256, digest
        ):
            raise TargetHealthGateContractError("recovery_intent_sha256 does not match content")
        object.__setattr__(self, "recovery_intent_id", identifier)
        object.__setattr__(self, "recovery_intent_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "authority_expires_at": self.authority_expires_at,
            "current_envelope_id": self.current_envelope_id,
            "current_envelope_sha256": self.current_envelope_sha256,
            "current_head_id": self.current_head_id,
            "current_head_sha256": self.current_head_sha256,
            "current_inspection_id": self.current_inspection_id,
            "current_inspection_sha256": self.current_inspection_sha256,
            "current_material_sha256": self.current_material_sha256,
            "global_transition_sequence": self.global_transition_sequence,
            "head_last_inspection_id": self.head_last_inspection_id,
            "head_last_inspection_sha256": self.head_last_inspection_sha256,
            "head_last_current_material_sha256": self.head_last_current_material_sha256,
            "latest_head_binding_id": self.latest_head_binding_id,
            "latest_head_binding_sha256": self.latest_head_binding_sha256,
            "pause_effect": self.pause_effect,
            "pause_epoch": self.pause_epoch,
            "prepared_at": self.prepared_at,
            "qualifying_observation_ids": list(self.qualifying_observation_ids),
            "qualifying_observation_sha256s": list(self.qualifying_observation_sha256s),
            "resume_effect": self.resume_effect,
            "subject": self.subject.to_dict(),
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "recovery_intent_id": self.recovery_intent_id,
            "recovery_intent_sha256": self.recovery_intent_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: Any) -> TargetHealthGateRecoveryIntent:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        data = _exact(
            value, fields | {"kind", "schema_version", *_NO_EFFECT_FIELDS}, "recovery intent"
        )
        _check_metadata(data, cls.KIND)
        args = {field: data[field] for field in fields}
        args["subject"] = TargetHealthGateSubject.from_dict(args["subject"])
        args["qualifying_observation_ids"] = tuple(args["qualifying_observation_ids"])
        args["qualifying_observation_sha256s"] = tuple(args["qualifying_observation_sha256s"])
        return cls(**args)


@dataclass(frozen=True, slots=True)
class TargetHealthGateResumption:
    subject: TargetHealthGateSubject
    pause_epoch: int
    recovery_intent: TargetHealthGateRecoveryIntent
    qualifying_observation_ids: tuple[str, str]
    qualifying_observation_sha256s: tuple[str, str]
    fresh_inspection: TargetHealthCurrentHeadInspection
    authorization: Mapping[str, Any]
    assertion_issuer: str
    assertion_id: str
    assertion_sha256: str
    authority_use_sequence: int
    canonical_replay_key_sha256: str
    operation_intent_sha256: str
    resumed_at: str
    pause_effect: str = "none"
    resume_effect: str = "permit_health_gate_evaluation"
    resumption_id: str = ""
    resumption_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-gate-resumption.v1"
    PREFIX: ClassVar[str] = "THGR"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, TargetHealthGateSubject):
            raise TargetHealthGateContractError("resumption subject is invalid")
        _integer(self.pause_epoch, "pause_epoch", 1)
        if not isinstance(self.recovery_intent, TargetHealthGateRecoveryIntent):
            raise TargetHealthGateContractError("recovery intent is invalid")
        if (
            self.recovery_intent.subject != self.subject
            or self.recovery_intent.pause_epoch != self.pause_epoch
        ):
            raise TargetHealthGateContractError("resumption crosses its recovery intent")
        ids = _pair_tuple(
            self.qualifying_observation_ids,
            "qualifying observation ids",
            lambda value, label: _record_id(value, "THGO", label),
        )
        digests = _pair_tuple(
            self.qualifying_observation_sha256s, "qualifying observation digests", _digest
        )
        object.__setattr__(self, "qualifying_observation_ids", ids)
        object.__setattr__(self, "qualifying_observation_sha256s", digests)
        if (
            ids != self.recovery_intent.qualifying_observation_ids
            or digests != self.recovery_intent.qualifying_observation_sha256s
        ):
            raise TargetHealthGateContractError(
                "resumption qualifying observations are substituted"
            )
        if not isinstance(self.fresh_inspection, TargetHealthCurrentHeadInspection):
            raise TargetHealthGateContractError("fresh inspection is invalid")
        if not _binds_subject(
            self.subject,
            self.fresh_inspection.envelope.receipt.binding,
        ):
            raise TargetHealthGateContractError("fresh inspection crosses its subject")
        receipt = self.fresh_inspection.envelope.receipt
        if (
            receipt.status is not TargetHealthStatus.COMPLETED
            or receipt.overall_health is not HealthSignalState.HEALTHY
        ):
            raise TargetHealthGateContractError("resumption requires fresh healthy evidence")
        if not isinstance(self.authorization, Mapping):
            raise TargetHealthGateContractError("authorization is invalid")
        authorization = _exact(
            json.loads(canonical_json(dict(self.authorization))),
            _RESUMPTION_AUTHORIZATION_FIELDS,
            "authorization",
        )
        if authorization.get("operation") != TARGET_HEALTH_GATE_RESUME_OPERATION:
            raise TargetHealthGateContractError("authorization operation is invalid")
        if authorization["role"] != "independent_control":
            raise TargetHealthGateContractError("authorization role is invalid")
        for field in (
            "principal_profile_id",
            "principal_subject",
            "assertion_issuer",
            "assertion_id",
        ):
            _identifier(authorization[field], f"authorization {field}")
        for field in (
            "assertion_sha256",
            "canonical_replay_key_sha256",
            "operation_intent_sha256",
            "scope_sha256",
            "target_sha256",
            "recovery_intent_sha256",
        ):
            _digest(authorization[field], f"authorization {field}")
        for field in ("tenant_id", "mission_id", "recovery_intent_id"):
            _identifier(authorization[field], f"authorization {field}")
        _integer(authorization["authority_use_sequence"], "authorization authority_use_sequence", 1)
        _integer(authorization["pause_epoch"], "authorization pause_epoch", 1)
        _utc(authorization["issued_at"], "authorization issued_at")
        _utc(authorization["expires_at"], "authorization expires_at")
        if authorization["decision"] != "approved":
            raise TargetHealthGateContractError("authorization decision is invalid")
        if authorization["assertion_issuer"] == authorization["principal_subject"]:
            raise TargetHealthGateContractError("authorization principal is not independent")
        object.__setattr__(self, "authorization", MappingProxyType(authorization))
        _identifier(self.assertion_issuer, "assertion_issuer")
        _identifier(self.assertion_id, "assertion_id")
        _digest(self.assertion_sha256, "assertion_sha256")
        _integer(self.authority_use_sequence, "authority_use_sequence", 1)
        _digest(self.canonical_replay_key_sha256, "canonical_replay_key_sha256")
        _digest(self.operation_intent_sha256, "operation_intent_sha256")
        _utc(self.resumed_at, "resumed_at")
        intent = self.recovery_intent
        if (
            self.fresh_inspection.inspection_id == intent.current_inspection_id
            or hmac.compare_digest(
                self.fresh_inspection.inspection_sha256,
                intent.current_inspection_sha256,
            )
            or self.fresh_inspection.inspection_id == intent.head_last_inspection_id
            or hmac.compare_digest(
                self.fresh_inspection.inspection_sha256,
                intent.head_last_inspection_sha256,
            )
            or hmac.compare_digest(
                self.fresh_inspection.current_material_sha256,
                intent.current_material_sha256,
            )
            or hmac.compare_digest(
                self.fresh_inspection.current_material_sha256,
                intent.head_last_current_material_sha256,
            )
        ):
            raise TargetHealthGateContractError("resumption inspection is not fresh")
        if (
            self.fresh_inspection.head_binding.head_binding_id != intent.latest_head_binding_id
            or not hmac.compare_digest(
                self.fresh_inspection.head_binding.head_binding_sha256,
                intent.latest_head_binding_sha256,
            )
            or self.fresh_inspection.head_binding.global_transition_sequence
            != intent.global_transition_sequence
            or self.fresh_inspection.envelope.envelope_id != intent.current_envelope_id
            or not hmac.compare_digest(
                self.fresh_inspection.envelope.envelope_sha256,
                intent.current_envelope_sha256,
            )
        ):
            raise TargetHealthGateContractError("fresh inspection does not bind recovery head")
        if self.resumed_at != self.fresh_inspection.inspected_at:
            raise TargetHealthGateContractError("resumption did not use a final live inspection")
        if not (
            _instant(self.recovery_intent.prepared_at)
            <= _instant(self.resumed_at)
            < _instant(self.recovery_intent.authority_expires_at)
        ):
            raise TargetHealthGateContractError("recovery intent is not current")
        expected_authorization = {
            "assertion_id": self.assertion_id,
            "assertion_issuer": self.assertion_issuer,
            "assertion_sha256": self.assertion_sha256,
            "authority_use_sequence": self.authority_use_sequence,
            "canonical_replay_key_sha256": self.canonical_replay_key_sha256,
            "mission_id": self.subject.mission_id,
            "operation_intent_sha256": self.operation_intent_sha256,
            "pause_epoch": self.pause_epoch,
            "recovery_intent_id": intent.recovery_intent_id,
            "recovery_intent_sha256": intent.recovery_intent_sha256,
            "scope_sha256": self.subject.scope_sha256,
            "target_sha256": self.subject.target_sha256,
            "tenant_id": self.subject.tenant_id,
        }
        if any(authorization[field] != value for field, value in expected_authorization.items()):
            raise TargetHealthGateContractError("authorization does not bind resumption")
        if not (
            _instant(authorization["issued_at"])
            <= _instant(self.resumed_at)
            < _instant(authorization["expires_at"])
        ):
            raise TargetHealthGateContractError("authorization is not current")
        if self.pause_effect != "none" or self.resume_effect != "permit_health_gate_evaluation":
            raise TargetHealthGateContractError("resumption effects are invalid")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.resumption_id and not hmac.compare_digest(self.resumption_id, identifier):
            raise TargetHealthGateContractError("resumption_id does not match content")
        if self.resumption_sha256 and not hmac.compare_digest(self.resumption_sha256, digest):
            raise TargetHealthGateContractError("resumption_sha256 does not match content")
        object.__setattr__(self, "resumption_id", identifier)
        object.__setattr__(self, "resumption_sha256", digest)

    @property
    def fresh_inspection_id(self) -> str:
        return self.fresh_inspection.inspection_id

    @property
    def fresh_inspection_sha256(self) -> str:
        return self.fresh_inspection.inspection_sha256

    @property
    def fresh_head_binding_sha256(self) -> str:
        return self.fresh_inspection.head_binding.head_binding_sha256

    def body(self) -> dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "assertion_issuer": self.assertion_issuer,
            "assertion_sha256": self.assertion_sha256,
            "authority_use_sequence": self.authority_use_sequence,
            "authorization": dict(self.authorization),
            "canonical_replay_key_sha256": self.canonical_replay_key_sha256,
            "fresh_inspection": self.fresh_inspection.to_dict(),
            "operation_intent_sha256": self.operation_intent_sha256,
            "pause_effect": self.pause_effect,
            "pause_epoch": self.pause_epoch,
            "qualifying_observation_ids": list(self.qualifying_observation_ids),
            "qualifying_observation_sha256s": list(self.qualifying_observation_sha256s),
            "recovery_intent": self.recovery_intent.to_dict(),
            "resume_effect": self.resume_effect,
            "resumed_at": self.resumed_at,
            "subject": self.subject.to_dict(),
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "resumption_id": self.resumption_id,
            "resumption_sha256": self.resumption_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: Any) -> TargetHealthGateResumption:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        data = _exact(value, fields | {"kind", "schema_version", *_NO_EFFECT_FIELDS}, "resumption")
        _check_metadata(data, cls.KIND)
        args = {field: data[field] for field in fields}
        args["subject"] = TargetHealthGateSubject.from_dict(args["subject"])
        args["recovery_intent"] = TargetHealthGateRecoveryIntent.from_dict(args["recovery_intent"])
        args["qualifying_observation_ids"] = tuple(args["qualifying_observation_ids"])
        args["qualifying_observation_sha256s"] = tuple(args["qualifying_observation_sha256s"])
        args["fresh_inspection"] = TargetHealthCurrentHeadInspection.from_dict(
            args["fresh_inspection"]
        )
        return cls(**args)


def build_target_health_gate_transition(
    *,
    previous_head: TargetHealthGateHead | None,
    observation: TargetHealthGateObservation | None = None,
    resumption: TargetHealthGateResumption | None = None,
) -> TargetHealthGateTransition:
    """Derive the closed schema 35 transition from exact durable lineage."""

    if (observation is None) == (resumption is None):
        raise TargetHealthGateContractError("exactly one transition source is required")
    if previous_head is not None and not isinstance(previous_head, TargetHealthGateHead):
        raise TargetHealthGateContractError("previous_head is invalid")
    if previous_head is None:
        if observation is None or resumption is not None:
            raise TargetHealthGateContractError("initial transition requires observation")
        if observation.observation_sequence != 1:
            raise TargetHealthGateContractError("initial observation sequence is invalid")
        if observation.evidence_advanced:
            raise TargetHealthGateContractError(
                "initial observation cannot advance recovery evidence"
            )
        healthy = observation.classification is TargetHealthGateClassification.HEALTHY
        kind = (
            TargetHealthGateTransitionKind.INITIALIZED_ACTIVE
            if healthy
            else TargetHealthGateTransitionKind.INITIALIZED_PAUSED
        )
        to_state = TargetHealthGateState.ACTIVE if healthy else TargetHealthGateState.PAUSED
        return TargetHealthGateTransition(
            subject=observation.subject,
            transition_sequence=1,
            previous_transition_sha256=None,
            transition_kind=kind,
            from_state=None,
            to_state=to_state,
            pause_epoch=0 if healthy else 1,
            recovery_healthy_count=0,
            observation_id=observation.observation_id,
            observation_sha256=observation.observation_sha256,
            resumption_id=None,
            resumption_sha256=None,
            occurred_at=observation.recorded_at,
            pause_effect=("none" if healthy else "deny_new_target_work"),
            resume_effect="none",
        )
    source_subject = observation.subject if observation is not None else resumption.subject
    if source_subject != previous_head.subject:
        raise TargetHealthGateContractError("transition source crosses its durable head")
    sequence = previous_head.transition_count + 1
    if resumption is not None:
        if (
            previous_head.latch_state is not TargetHealthGateState.RECOVERY_PENDING
            or previous_head.recovery_healthy_count != 2
            or resumption.pause_epoch != previous_head.pause_epoch
            or resumption.recovery_intent.current_head_id != previous_head.head_id
            or not hmac.compare_digest(
                resumption.recovery_intent.current_head_sha256,
                previous_head.head_sha256,
            )
        ):
            raise TargetHealthGateContractError("resumption does not bind an eligible head")
        return TargetHealthGateTransition(
            subject=source_subject,
            transition_sequence=sequence,
            previous_transition_sha256=previous_head.transition_head_sha256,
            transition_kind=TargetHealthGateTransitionKind.CONTROL_RESUMED,
            from_state=previous_head.latch_state,
            to_state=TargetHealthGateState.ACTIVE,
            pause_epoch=previous_head.pause_epoch,
            recovery_healthy_count=0,
            observation_id=None,
            observation_sha256=None,
            resumption_id=resumption.resumption_id,
            resumption_sha256=resumption.resumption_sha256,
            occurred_at=resumption.resumed_at,
            pause_effect="none",
            resume_effect="permit_health_gate_evaluation",
        )
    if observation.observation_sequence != previous_head.observation_count + 1:
        raise TargetHealthGateContractError("observation sequence does not advance head")
    if not hmac.compare_digest(
        observation.previous_observation_sha256 or "",
        previous_head.observation_head_sha256,
    ):
        raise TargetHealthGateContractError("observation predecessor does not match head")
    healthy = observation.classification is TargetHealthGateClassification.HEALTHY
    state = previous_head.latch_state
    pause_epoch = previous_head.pause_epoch
    if state is TargetHealthGateState.ACTIVE:
        if observation.evidence_advanced:
            raise TargetHealthGateContractError(
                "active observation cannot advance recovery evidence"
            )
        if healthy:
            kind = TargetHealthGateTransitionKind.ACTIVE_HEALTH_CONFIRMED
            to_state = TargetHealthGateState.ACTIVE
        else:
            kind = TargetHealthGateTransitionKind.PAUSE_ASSERTED
            to_state = TargetHealthGateState.PAUSED
            pause_epoch += 1
        count = 0
    elif state is TargetHealthGateState.PAUSED:
        if healthy:
            if not observation.evidence_advanced:
                raise TargetHealthGateContractError(
                    "recovery start requires advancing healthy evidence"
                )
            kind = TargetHealthGateTransitionKind.RECOVERY_STARTED
            to_state = TargetHealthGateState.RECOVERY_PENDING
            count = 1
        else:
            if observation.evidence_advanced:
                raise TargetHealthGateContractError("adverse evidence cannot advance recovery")
            kind = TargetHealthGateTransitionKind.PAUSE_REAFFIRMED
            to_state = TargetHealthGateState.PAUSED
            count = 0
    elif not healthy:
        if observation.evidence_advanced:
            raise TargetHealthGateContractError("adverse evidence cannot advance recovery")
        kind = TargetHealthGateTransitionKind.RECOVERY_RESET
        to_state = TargetHealthGateState.PAUSED
        count = 0
    elif previous_head.recovery_healthy_count == 2:
        if observation.evidence_advanced:
            raise TargetHealthGateContractError(
                "completed recovery streak cannot advance beyond two"
            )
        kind = TargetHealthGateTransitionKind.RECOVERY_HELD
        to_state = TargetHealthGateState.RECOVERY_PENDING
        count = 2
    elif not observation.evidence_advanced:
        same_envelope = (
            observation.chain_id == previous_head.recovery_chain_id
            and observation.envelope_id == previous_head.recovery_envelope_id
            and hmac.compare_digest(
                observation.envelope_sha256,
                previous_head.recovery_envelope_sha256 or "",
            )
        )
        if not same_envelope:
            raise TargetHealthGateContractError("new recovery evidence must be marked advanced")
        kind = TargetHealthGateTransitionKind.RECOVERY_HELD
        to_state = TargetHealthGateState.RECOVERY_PENDING
        count = previous_head.recovery_healthy_count
    else:
        same_envelope = (
            observation.chain_id == previous_head.recovery_chain_id
            and observation.envelope_id == previous_head.recovery_envelope_id
            and hmac.compare_digest(
                observation.envelope_sha256,
                previous_head.recovery_envelope_sha256 or "",
            )
        )
        if same_envelope:
            raise TargetHealthGateContractError(
                "unchanged recovery evidence cannot be marked advanced"
            )
        if observation.global_transition_sequence <= previous_head.last_global_transition_sequence:
            raise TargetHealthGateContractError(
                "recovery evidence does not advance the global transition"
            )
        if _instant(observation.observed_at) <= _instant(
            previous_head.recovery_observed_at or observation.observed_at
        ):
            raise TargetHealthGateContractError(
                "recovery evidence does not advance observation time"
            )
        same_chain = observation.chain_id == previous_head.recovery_chain_id
        if same_chain and observation.envelope_sequence <= (
            previous_head.recovery_envelope_sequence or 0
        ):
            raise TargetHealthGateContractError(
                "same-chain recovery evidence does not advance envelope sequence"
            )
        contiguous = (
            same_chain
            and observation.envelope_sequence == (previous_head.recovery_envelope_sequence or 0) + 1
            and observation.predecessor_envelope_id == previous_head.recovery_envelope_id
            and hmac.compare_digest(
                observation.predecessor_envelope_sha256 or "",
                previous_head.recovery_envelope_sha256 or "",
            )
        )
        kind = (
            TargetHealthGateTransitionKind.RECOVERY_ADVANCED
            if contiguous
            else TargetHealthGateTransitionKind.RECOVERY_RESTARTED
        )
        to_state = TargetHealthGateState.RECOVERY_PENDING
        count = 2 if contiguous else 1
    return TargetHealthGateTransition(
        subject=source_subject,
        transition_sequence=sequence,
        previous_transition_sha256=previous_head.transition_head_sha256,
        transition_kind=kind,
        from_state=state,
        to_state=to_state,
        pause_epoch=pause_epoch,
        recovery_healthy_count=count,
        observation_id=observation.observation_id,
        observation_sha256=observation.observation_sha256,
        resumption_id=None,
        resumption_sha256=None,
        occurred_at=observation.recorded_at,
        pause_effect=(
            "none" if to_state is TargetHealthGateState.ACTIVE else "deny_new_target_work"
        ),
        resume_effect="none",
    )


def build_target_health_gate_head(
    *,
    transition: TargetHealthGateTransition,
    observation: TargetHealthGateObservation | None,
    resumption: TargetHealthGateResumption | None,
    previous_head: TargetHealthGateHead | None,
) -> TargetHealthGateHead:
    """Project one exact transition into the durable schema 35 latch head."""

    if not isinstance(transition, TargetHealthGateTransition):
        raise TargetHealthGateContractError("transition is invalid")
    if (observation is None) == (resumption is None):
        raise TargetHealthGateContractError("exactly one head source is required")
    if transition.subject != (observation.subject if observation else resumption.subject):
        raise TargetHealthGateContractError("head source crosses transition subject")
    expected_transition = build_target_health_gate_transition(
        previous_head=previous_head,
        observation=observation,
        resumption=resumption,
    )
    if transition != expected_transition:
        raise TargetHealthGateContractError("head transition does not match its exact source")
    if previous_head is None:
        if observation is None or transition.transition_sequence != 1:
            raise TargetHealthGateContractError("head initialization is invalid")
        observation_count = transition_count = version = 1
        resumption_count = 0
        last_resumption_id = last_resumption_sha256 = None
        last_adverse_id = (
            observation.observation_id
            if observation.classification is TargetHealthGateClassification.ADVERSE
            else None
        )
        last_adverse_sha = observation.observation_sha256 if last_adverse_id is not None else None
    else:
        if transition.previous_transition_sha256 != previous_head.transition_head_sha256:
            raise TargetHealthGateContractError("head transition predecessor is invalid")
        observation_count = previous_head.observation_count + (observation is not None)
        transition_count = previous_head.transition_count + 1
        resumption_count = previous_head.resumption_count + (resumption is not None)
        version = previous_head.version + 1
        last_resumption_id = (
            resumption.resumption_id if resumption else previous_head.last_resumption_id
        )
        last_resumption_sha256 = (
            resumption.resumption_sha256 if resumption else previous_head.last_resumption_sha256
        )
        if observation and observation.classification is TargetHealthGateClassification.ADVERSE:
            last_adverse_id = observation.observation_id
            last_adverse_sha = observation.observation_sha256
        else:
            last_adverse_id = previous_head.last_adverse_observation_id
            last_adverse_sha = previous_head.last_adverse_observation_sha256
    latest_observation = observation
    if latest_observation is None:
        if previous_head is None:
            raise TargetHealthGateContractError("resumption cannot initialize a head")
        observation_fields = {
            "last_observation_id": previous_head.last_observation_id,
            "last_observation_sha256": previous_head.last_observation_sha256,
            "last_binding_sha256": previous_head.last_binding_sha256,
            "last_inspection_id": previous_head.last_inspection_id,
            "last_inspection_sha256": previous_head.last_inspection_sha256,
            "last_head_binding_id": previous_head.last_head_binding_id,
            "last_head_binding_sha256": previous_head.last_head_binding_sha256,
            "last_global_transition_sequence": previous_head.last_global_transition_sequence,
            "last_current_material_sha256": previous_head.last_current_material_sha256,
            "observation_head_sha256": previous_head.observation_head_sha256,
        }
    else:
        observation_fields = {
            "last_observation_id": latest_observation.observation_id,
            "last_observation_sha256": latest_observation.observation_sha256,
            "last_binding_sha256": latest_observation.binding_sha256,
            "last_inspection_id": latest_observation.inspection_id,
            "last_inspection_sha256": latest_observation.inspection_sha256,
            "last_head_binding_id": latest_observation.head_binding_id,
            "last_head_binding_sha256": latest_observation.head_binding_sha256,
            "last_global_transition_sequence": latest_observation.global_transition_sequence,
            "last_current_material_sha256": latest_observation.current_material_sha256,
            "observation_head_sha256": latest_observation.observation_sha256,
        }
    if transition.to_state is TargetHealthGateState.RECOVERY_PENDING:
        if observation and observation.evidence_advanced:
            anchor = observation
            recovery = (
                anchor.chain_id,
                anchor.envelope_id,
                anchor.envelope_sha256,
                anchor.envelope_sequence,
                anchor.observed_at,
            )
        elif previous_head is not None:
            recovery = (
                previous_head.recovery_chain_id,
                previous_head.recovery_envelope_id,
                previous_head.recovery_envelope_sha256,
                previous_head.recovery_envelope_sequence,
                previous_head.recovery_observed_at,
            )
        else:
            raise TargetHealthGateContractError("recovery transition lacks anchor evidence")
    else:
        recovery = (None, None, None, None, None)
    return TargetHealthGateHead(
        subject=transition.subject,
        latch_state=transition.to_state,
        pause_epoch=transition.pause_epoch,
        observation_count=int(observation_count),
        transition_count=transition_count,
        transition_head_sha256=transition.transition_sha256,
        resumption_count=int(resumption_count),
        recovery_healthy_count=transition.recovery_healthy_count,
        recovery_chain_id=recovery[0],
        recovery_envelope_id=recovery[1],
        recovery_envelope_sha256=recovery[2],
        recovery_envelope_sequence=recovery[3],
        recovery_observed_at=recovery[4],
        last_adverse_observation_id=last_adverse_id,
        last_adverse_observation_sha256=last_adverse_sha,
        last_resumption_id=last_resumption_id,
        last_resumption_sha256=last_resumption_sha256,
        version=version,
        updated_at=transition.occurred_at,
        **observation_fields,
    )


@dataclass(frozen=True, slots=True)
class TargetHealthGateDecision:
    subject: TargetHealthGateSubject
    binding: ExecutionBinding
    binding_sha256: str
    head: TargetHealthGateHead
    current_observation: TargetHealthGateObservation
    evaluated_at: str
    status: TargetHealthGateDecisionStatus
    reason: str
    pause_effect: str
    resume_effect: str
    decision_id: str = ""
    decision_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.target-health-gate-decision.v1"
    PREFIX: ClassVar[str] = "THGD"

    def __post_init__(self) -> None:
        if not isinstance(self.subject, TargetHealthGateSubject):
            raise TargetHealthGateContractError("decision subject is invalid")
        if not isinstance(self.binding, ExecutionBinding):
            raise TargetHealthGateContractError("decision binding is invalid")
        _digest(self.binding_sha256, "binding_sha256")
        if not hmac.compare_digest(self.binding_sha256, execution_binding_sha256(self.binding)):
            raise TargetHealthGateContractError("decision binding digest does not match")
        if not _binds_subject(self.subject, self.binding):
            raise TargetHealthGateContractError("decision binding crosses its subject")
        if not isinstance(self.head, TargetHealthGateHead) or self.head.subject != self.subject:
            raise TargetHealthGateContractError("decision head is invalid")
        if not isinstance(self.current_observation, TargetHealthGateObservation):
            raise TargetHealthGateContractError("decision observation is invalid")
        if (
            self.current_observation.subject != self.subject
            or self.current_observation.binding != self.binding
            or not hmac.compare_digest(self.current_observation.binding_sha256, self.binding_sha256)
        ):
            raise TargetHealthGateContractError("decision observation is substituted")
        _utc(self.evaluated_at, "evaluated_at")
        if self.evaluated_at != self.current_observation.inspected_at:
            raise TargetHealthGateContractError("decision did not use a final live inspection")
        object.__setattr__(
            self, "status", _enum(TargetHealthGateDecisionStatus, self.status, "status")
        )
        _identifier(self.reason, "reason")
        permit = (
            self.head.latch_state is TargetHealthGateState.ACTIVE
            and self.current_observation.classification is TargetHealthGateClassification.HEALTHY
        )
        expected_status = (
            TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
            if permit
            else TargetHealthGateDecisionStatus.DENY_NEW_TARGET_WORK
        )
        expected_reason = "health_gate_current" if permit else "health_gate_denied"
        expected_pause = "none" if permit else "deny_new_target_work"
        if (
            self.status is not expected_status
            or self.reason != expected_reason
            or self.pause_effect != expected_pause
            or self.resume_effect != "none"
        ):
            raise TargetHealthGateContractError("decision overclaims health gate eligibility")
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.decision_id and not hmac.compare_digest(self.decision_id, identifier):
            raise TargetHealthGateContractError("decision_id does not match content")
        if self.decision_sha256 and not hmac.compare_digest(self.decision_sha256, digest):
            raise TargetHealthGateContractError("decision_sha256 does not match content")
        object.__setattr__(self, "decision_id", identifier)
        object.__setattr__(self, "decision_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "current_observation": self.current_observation.to_dict(),
            "evaluated_at": self.evaluated_at,
            "head": self.head.to_dict(),
            "pause_effect": self.pause_effect,
            "reason": self.reason,
            "resume_effect": self.resume_effect,
            "status": self.status.value,
            "subject": self.subject.to_dict(),
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "decision_id": self.decision_id,
            "decision_sha256": self.decision_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: Any) -> TargetHealthGateDecision:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        data = _exact(value, fields | {"kind", "schema_version", *_NO_EFFECT_FIELDS}, "decision")
        _check_metadata(data, cls.KIND)
        args = {field: data[field] for field in fields}
        args["subject"] = TargetHealthGateSubject.from_dict(args["subject"])
        args["binding"] = _execution_binding_from_dict(args["binding"])
        args["head"] = TargetHealthGateHead.from_dict(args["head"])
        args["current_observation"] = TargetHealthGateObservation.from_dict(
            args["current_observation"]
        )
        return cls(**args)


_PARSERS = {
    TargetHealthGateSubject.KIND: TargetHealthGateSubject.from_dict,
    TargetHealthGateObservation.KIND: TargetHealthGateObservation.from_dict,
    TargetHealthGateTransition.KIND: TargetHealthGateTransition.from_dict,
    TargetHealthGateHead.KIND: TargetHealthGateHead.from_dict,
    TargetHealthGateRecoveryIntent.KIND: TargetHealthGateRecoveryIntent.from_dict,
    TargetHealthGateResumption.KIND: TargetHealthGateResumption.from_dict,
    TargetHealthGateDecision.KIND: TargetHealthGateDecision.from_dict,
}

TargetHealthGateDocument = (
    TargetHealthGateSubject
    | TargetHealthGateObservation
    | TargetHealthGateTransition
    | TargetHealthGateHead
    | TargetHealthGateRecoveryIntent
    | TargetHealthGateResumption
    | TargetHealthGateDecision
)


def parse_target_health_gate_document(document: str) -> TargetHealthGateDocument:
    """Parse one canonical, closed target-health gate document."""

    if not isinstance(document, str):
        raise TargetHealthGateContractError("document must be text")
    if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise TargetHealthGateContractError("document exceeds maximum size")
    try:
        value = json.loads(document)
    except json.JSONDecodeError as exc:
        raise TargetHealthGateContractError("document is not valid JSON") from exc
    if not isinstance(value, Mapping) or canonical_json(value) != document:
        raise TargetHealthGateContractError("document is not canonical JSON")
    parser = _PARSERS.get(value.get("kind"))
    if parser is None:
        raise TargetHealthGateContractError("document kind is invalid")
    return parser(value)
