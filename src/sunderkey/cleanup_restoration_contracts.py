"""Deterministic cleanup and restoration contracts with no execution effects.

The records in this module bind an externally authorized action to an ordered
cleanup and restoration plan, caller-supplied observations, residual risk, and
an independent completion assessment. They do not contact targets, execute
cleanup, restore state, delete artifacts, persist records, grant authorization,
or change qualification state.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MAX_ITEMS = 2048

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "cleanup": "none",
        "deletion": "none",
        "network": "none",
        "persistence": "none",
        "qualification": "none",
        "restore": "none",
        "target_action": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|missionref|principalref|reviewerref|stepref|targetstateref|"
    r"evidenceref|actionref|artifactref|observationref|riskref|approvalref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class CleanupRestorationContractError(ValueError):
    """Raised when a cleanup and restoration contract fails closed."""


class TargetState(StrEnum):
    ABSENT = "absent"
    RESTORED = "restored"
    RETAINED = "retained"


class StepKind(StrEnum):
    REMOVE = "remove"
    RESTORE = "restore"
    VERIFY = "verify"
    RELEASE = "release"


class FailureBehavior(StrEnum):
    HALT = "halt"
    ROLLBACK = "rollback"
    COMPENSATE_THEN_HALT = "compensate_then_halt"


class StepOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    NOT_OBSERVED = "not_observed"


class ResidualDisposition(StrEnum):
    UNRESOLVED = "unresolved"
    ACCEPTED_BY_SEPARATE_AUTHORITY = "accepted_by_separate_authority"
    QUARANTINED_BY_SEPARATE_AUTHORITY = "quarantined_by_separate_authority"


class CompletionStatus(StrEnum):
    INCOMPLETE = "incomplete"
    CONTRACT_COMPLETE_UNVERIFIED = "contract_complete_unverified"


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
        raise CleanupRestorationContractError("value cannot be serialized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise CleanupRestorationContractError(f"{label} fields are invalid")
    return raw


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise CleanupRestorationContractError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise CleanupRestorationContractError(f"{label} must use {namespace}")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CleanupRestorationContractError(f"{label} must be a SHA-256 digest")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise CleanupRestorationContractError(f"{label} must be an exact version")
    if value.lower() in {"latest", "stable", "current", "default", "auto"}:
        raise CleanupRestorationContractError(f"{label} must not be a moving alias")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise CleanupRestorationContractError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CleanupRestorationContractError(f"{label} must be valid") from exc


def _positive(value: Any, label: str, maximum: int = 2_147_483_647) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise CleanupRestorationContractError(f"{label} must be between 1 and {maximum}")
    return value


def _reason(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 3 <= len(value) <= 500 or "\n" in value:
        raise CleanupRestorationContractError(f"{label} must be bounded single-line text")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or CODE_RE.fullmatch(value) is None:
        raise CleanupRestorationContractError(f"{label} must be a reason code")
    return value


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise CleanupRestorationContractError(f"{label} is invalid") from exc


def _bounded_unique(values: Sequence[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise CleanupRestorationContractError(f"{label} must be a sequence")
    result = tuple(values)
    if not 1 <= len(result) <= MAX_ITEMS or len(set(result)) != len(result):
        raise CleanupRestorationContractError(f"{label} must be bounded and unique")
    return result


def _verify_effects(value: Any) -> None:
    if not isinstance(value, Mapping) or dict(value) != dict(NO_EFFECTS):
        raise CleanupRestorationContractError("effects must preserve the no-effect boundary")


def _verify_address(
    raw: Mapping[str, Any], id_field: str, digest_field: str, prefix: str, domain: str
) -> None:
    body = {key: value for key, value in raw.items() if key not in {id_field, digest_field}}
    expected_id, expected_digest = _identity(prefix, domain, body)
    if raw[id_field] != expected_id or raw[digest_field] != expected_digest:
        raise CleanupRestorationContractError("record content address does not match content")


def _field_names(record_type: type[Any]) -> set[str]:
    return {item.name for item in fields(record_type)}


@dataclass(frozen=True, slots=True)
class TargetStateObligation:
    target_state_ref: str
    target_ref: str
    target_sha256: str
    required_state: TargetState
    baseline_sha256: str
    verification_sha256: str

    def __post_init__(self) -> None:
        _reference(self.target_state_ref, "target_state_ref", "targetstateref")
        _reference(self.target_ref, "target_ref", "artifactref")
        _digest(self.target_sha256, "target_sha256")
        object.__setattr__(
            self, "required_state", _enum(TargetState, self.required_state, "required_state")
        )
        _digest(self.baseline_sha256, "baseline_sha256")
        _digest(self.verification_sha256, "verification_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_sha256": self.baseline_sha256,
            "required_state": self.required_state.value,
            "target_ref": self.target_ref,
            "target_sha256": self.target_sha256,
            "target_state_ref": self.target_state_ref,
            "verification_sha256": self.verification_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TargetStateObligation:
        value = _exact(raw, _field_names(cls), "target state obligation")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    evidence_ref: str
    evidence_sha256: str
    evidence_version: str

    def __post_init__(self) -> None:
        _reference(self.evidence_ref, "evidence_ref", "evidenceref")
        _digest(self.evidence_sha256, "evidence_sha256")
        _version(self.evidence_version, "evidence_version")

    def to_dict(self) -> dict[str, str]:
        return {
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "evidence_version": self.evidence_version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceRequirement:
        value = _exact(raw, _field_names(cls), "evidence requirement")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class CompensatingAction:
    action_ref: str
    action_sha256: str
    action_version: str
    reason_code: str

    def __post_init__(self) -> None:
        _reference(self.action_ref, "action_ref", "actionref")
        _digest(self.action_sha256, "action_sha256")
        _version(self.action_version, "action_version")
        _code(self.reason_code, "reason_code")

    def to_dict(self) -> dict[str, str]:
        return {
            "action_ref": self.action_ref,
            "action_sha256": self.action_sha256,
            "action_version": self.action_version,
            "reason_code": self.reason_code,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CompensatingAction:
        value = _exact(raw, _field_names(cls), "compensating action")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class CleanupStep:
    step_ref: str
    sequence: int
    kind: StepKind
    target_state_ref: str
    action_ref: str
    action_sha256: str
    timeout_seconds: int
    failure_behavior: FailureBehavior
    evidence_requirements: tuple[EvidenceRequirement, ...]
    compensating_actions: tuple[CompensatingAction, ...]

    def __post_init__(self) -> None:
        _reference(self.step_ref, "step_ref", "stepref")
        _positive(self.sequence, "sequence", MAX_ITEMS)
        object.__setattr__(self, "kind", _enum(StepKind, self.kind, "kind"))
        _reference(self.target_state_ref, "target_state_ref", "targetstateref")
        _reference(self.action_ref, "action_ref", "actionref")
        _digest(self.action_sha256, "action_sha256")
        _positive(self.timeout_seconds, "timeout_seconds", 86_400)
        behavior = _enum(FailureBehavior, self.failure_behavior, "failure_behavior")
        object.__setattr__(self, "failure_behavior", behavior)
        requirements = tuple(
            item if isinstance(item, EvidenceRequirement) else EvidenceRequirement.from_dict(item)
            for item in self.evidence_requirements
        )
        compensations = tuple(
            item if isinstance(item, CompensatingAction) else CompensatingAction.from_dict(item)
            for item in self.compensating_actions
        )
        if not requirements or len(requirements) > MAX_ITEMS:
            raise CleanupRestorationContractError("evidence requirements must be non-empty")
        refs = tuple(item.evidence_ref for item in requirements)
        if len(refs) != len(set(refs)):
            raise CleanupRestorationContractError("evidence requirements must be unique")
        action_refs = tuple(item.action_ref for item in compensations)
        if len(action_refs) != len(set(action_refs)) or len(compensations) > MAX_ITEMS:
            raise CleanupRestorationContractError("compensating actions must be unique")
        if behavior is not FailureBehavior.HALT and not compensations:
            raise CleanupRestorationContractError("rollback behavior requires compensation")
        object.__setattr__(self, "evidence_requirements", requirements)
        object.__setattr__(self, "compensating_actions", compensations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_ref": self.action_ref,
            "action_sha256": self.action_sha256,
            "compensating_actions": [item.to_dict() for item in self.compensating_actions],
            "evidence_requirements": [item.to_dict() for item in self.evidence_requirements],
            "failure_behavior": self.failure_behavior.value,
            "kind": self.kind.value,
            "sequence": self.sequence,
            "step_ref": self.step_ref,
            "target_state_ref": self.target_state_ref,
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CleanupStep:
        value = _exact(raw, _field_names(cls), "cleanup step")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class CleanupRestorationPlan:
    tenant_ref: str
    tenant_sha256: str
    mission_ref: str
    mission_sha256: str
    scope_sha256: str
    action_sha256: str
    worker_ref: str
    worker_profile_sha256: str
    target_sha256: str
    contract_version: str
    contract_version_sha256: str
    approval_ref: str
    approval_sha256: str
    obligations: tuple[TargetStateObligation, ...]
    steps: tuple[CleanupStep, ...]
    created_at: str
    expires_at: str
    plan_id: str = ""
    plan_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.cleanup-restoration-plan.v1"
    DOMAIN: ClassVar[str] = "sunderkey.cleanup-restoration-plan.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.mission_ref, "mission_ref", "missionref")
        for name in (
            "tenant_sha256",
            "mission_sha256",
            "scope_sha256",
            "action_sha256",
            "worker_profile_sha256",
            "target_sha256",
            "contract_version_sha256",
            "approval_sha256",
        ):
            _digest(getattr(self, name), name)
        _reference(self.worker_ref, "worker_ref", "principalref")
        _version(self.contract_version, "contract_version")
        _reference(self.approval_ref, "approval_ref", "approvalref")
        obligations = tuple(
            item
            if isinstance(item, TargetStateObligation)
            else TargetStateObligation.from_dict(item)
            for item in self.obligations
        )
        steps = tuple(
            item if isinstance(item, CleanupStep) else CleanupStep.from_dict(item)
            for item in self.steps
        )
        if not obligations or not steps or len(obligations) > MAX_ITEMS or len(steps) > MAX_ITEMS:
            raise CleanupRestorationContractError("plan collections must be bounded and non-empty")
        obligation_refs = tuple(item.target_state_ref for item in obligations)
        if len(obligation_refs) != len(set(obligation_refs)):
            raise CleanupRestorationContractError("obligation references must be unique")
        step_refs = tuple(item.step_ref for item in steps)
        ordered_sequences = tuple(item.sequence for item in steps)
        if len(step_refs) != len(set(step_refs)) or ordered_sequences != tuple(
            range(1, len(steps) + 1)
        ):
            raise CleanupRestorationContractError("steps must be unique and contiguously ordered")
        if any(item.target_state_ref not in set(obligation_refs) for item in steps):
            raise CleanupRestorationContractError("every step must bind a declared obligation")
        if set(obligation_refs) - {item.target_state_ref for item in steps}:
            raise CleanupRestorationContractError("every obligation must have an ordered step")
        created = _timestamp(self.created_at, "created_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= created:
            raise CleanupRestorationContractError("expires_at must follow created_at")
        object.__setattr__(self, "obligations", obligations)
        object.__setattr__(self, "steps", steps)
        expected_id, expected_digest = _identity("CRP", self.DOMAIN, self._body())
        if self.plan_id and self.plan_id != expected_id:
            raise CleanupRestorationContractError("plan_id does not match content")
        if self.plan_sha256 and self.plan_sha256 != expected_digest:
            raise CleanupRestorationContractError("plan_sha256 does not match content")
        object.__setattr__(self, "plan_id", expected_id)
        object.__setattr__(self, "plan_sha256", expected_digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "approval_ref": self.approval_ref,
            "approval_sha256": self.approval_sha256,
            "contract_version": self.contract_version,
            "contract_version_sha256": self.contract_version_sha256,
            "created_at": self.created_at,
            "effects": dict(NO_EFFECTS),
            "expires_at": self.expires_at,
            "kind": self.KIND,
            "mission_ref": self.mission_ref,
            "mission_sha256": self.mission_sha256,
            "obligations": [item.to_dict() for item in self.obligations],
            "schema_version": SCHEMA_VERSION,
            "scope_sha256": self.scope_sha256,
            "steps": [item.to_dict() for item in self.steps],
            "target_sha256": self.target_sha256,
            "tenant_ref": self.tenant_ref,
            "tenant_sha256": self.tenant_sha256,
            "worker_profile_sha256": self.worker_profile_sha256,
            "worker_ref": self.worker_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_id": self.plan_id, "plan_sha256": self.plan_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> CleanupRestorationPlan:
        expected_fields = _field_names(cls) | {"effects", "kind", "schema_version"}
        value = _exact(raw, expected_fields, "cleanup restoration plan")
        _verify_effects(value["effects"])
        if value["kind"] != cls.KIND or value["schema_version"] != SCHEMA_VERSION:
            raise CleanupRestorationContractError("plan discriminator is invalid")
        _verify_address(value, "plan_id", "plan_sha256", "CRP", cls.DOMAIN)
        return cls(**{key: value[key] for key in _field_names(cls)})


@dataclass(frozen=True, slots=True)
class StepObservation:
    step_ref: str
    sequence: int
    outcome: StepOutcome
    started_at: str
    completed_at: str | None
    observed_evidence: tuple[EvidenceRequirement, ...]
    compensation_observed: bool
    reason_code: str

    def __post_init__(self) -> None:
        _reference(self.step_ref, "step_ref", "stepref")
        _positive(self.sequence, "sequence", MAX_ITEMS)
        outcome = _enum(StepOutcome, self.outcome, "outcome")
        object.__setattr__(self, "outcome", outcome)
        started = _timestamp(self.started_at, "started_at")
        if self.completed_at is not None:
            completed = _timestamp(self.completed_at, "completed_at")
            if completed < started:
                raise CleanupRestorationContractError("completed_at precedes started_at")
        elif outcome not in {StepOutcome.TIMED_OUT, StepOutcome.NOT_OBSERVED}:
            raise CleanupRestorationContractError("completed_at is required for terminal outcomes")
        evidence = tuple(
            item if isinstance(item, EvidenceRequirement) else EvidenceRequirement.from_dict(item)
            for item in self.observed_evidence
        )
        if (
            len(evidence) > MAX_ITEMS
            or len({item.evidence_ref for item in evidence}) != len(evidence)
        ):
            raise CleanupRestorationContractError("observed evidence must be bounded and unique")
        if outcome is StepOutcome.SUCCEEDED and not evidence:
            raise CleanupRestorationContractError("successful steps require observed evidence")
        _code(self.reason_code, "reason_code")
        object.__setattr__(self, "observed_evidence", evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed_at": self.completed_at,
            "compensation_observed": self.compensation_observed,
            "observed_evidence": [item.to_dict() for item in self.observed_evidence],
            "outcome": self.outcome.value,
            "reason_code": self.reason_code,
            "sequence": self.sequence,
            "started_at": self.started_at,
            "step_ref": self.step_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> StepObservation:
        value = _exact(raw, _field_names(cls), "step observation")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class ResidualArtifact:
    risk_ref: str
    artifact_ref: str
    expected_sha256: str
    observed_sha256: str | None
    disposition: ResidualDisposition
    separate_authority_ref: str | None
    reason: str

    def __post_init__(self) -> None:
        _reference(self.risk_ref, "risk_ref", "riskref")
        _reference(self.artifact_ref, "artifact_ref", "artifactref")
        _digest(self.expected_sha256, "expected_sha256")
        if self.observed_sha256 is not None:
            _digest(self.observed_sha256, "observed_sha256")
        disposition = _enum(ResidualDisposition, self.disposition, "disposition")
        object.__setattr__(self, "disposition", disposition)
        if disposition is ResidualDisposition.UNRESOLVED:
            if self.separate_authority_ref is not None:
                raise CleanupRestorationContractError("unresolved residual cannot claim authority")
        else:
            _reference(self.separate_authority_ref, "separate_authority_ref", "approvalref")
        _reason(self.reason, "reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_ref": self.artifact_ref,
            "disposition": self.disposition.value,
            "expected_sha256": self.expected_sha256,
            "observed_sha256": self.observed_sha256,
            "reason": self.reason,
            "risk_ref": self.risk_ref,
            "separate_authority_ref": self.separate_authority_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ResidualArtifact:
        value = _exact(raw, _field_names(cls), "residual artifact")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class CleanupObservation:
    tenant_ref: str
    tenant_sha256: str
    mission_ref: str
    mission_sha256: str
    scope_sha256: str
    action_sha256: str
    worker_ref: str
    worker_profile_sha256: str
    target_sha256: str
    contract_version: str
    contract_version_sha256: str
    plan_id: str
    plan_sha256: str
    observer_ref: str
    reviewer_ref: str
    observations: tuple[StepObservation, ...]
    residual_artifacts: tuple[ResidualArtifact, ...]
    observed_at: str
    observation_id: str = ""
    observation_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.cleanup-restoration-observation.v1"
    DOMAIN: ClassVar[str] = "sunderkey.cleanup-restoration-observation.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.mission_ref, "mission_ref", "missionref")
        for name in (
            "tenant_sha256",
            "mission_sha256",
            "scope_sha256",
            "action_sha256",
            "worker_profile_sha256",
            "target_sha256",
            "contract_version_sha256",
            "plan_sha256",
        ):
            _digest(getattr(self, name), name)
        _reference(self.worker_ref, "worker_ref", "principalref")
        _version(self.contract_version, "contract_version")
        if not re.fullmatch(r"CRP-[0-9A-F]{32}", self.plan_id):
            raise CleanupRestorationContractError("plan_id is invalid")
        _reference(self.observer_ref, "observer_ref", "principalref")
        _reference(self.reviewer_ref, "reviewer_ref", "reviewerref")
        if self.observer_ref in {self.worker_ref, self.reviewer_ref}:
            raise CleanupRestorationContractError("observer must be independent")
        observations = tuple(
            item if isinstance(item, StepObservation) else StepObservation.from_dict(item)
            for item in self.observations
        )
        residuals = tuple(
            item if isinstance(item, ResidualArtifact) else ResidualArtifact.from_dict(item)
            for item in self.residual_artifacts
        )
        if not observations or len(observations) > MAX_ITEMS or len(residuals) > MAX_ITEMS:
            raise CleanupRestorationContractError("observation collections are invalid")
        if len({item.step_ref for item in observations}) != len(observations):
            raise CleanupRestorationContractError("step observations must be unique")
        if len({item.risk_ref for item in residuals}) != len(residuals):
            raise CleanupRestorationContractError("residual risks must be unique")
        _timestamp(self.observed_at, "observed_at")
        object.__setattr__(self, "observations", observations)
        object.__setattr__(self, "residual_artifacts", residuals)
        expected_id, expected_digest = _identity("CRO", self.DOMAIN, self._body())
        if self.observation_id and self.observation_id != expected_id:
            raise CleanupRestorationContractError("observation_id does not match content")
        if self.observation_sha256 and self.observation_sha256 != expected_digest:
            raise CleanupRestorationContractError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_id", expected_id)
        object.__setattr__(self, "observation_sha256", expected_digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "contract_version": self.contract_version,
            "contract_version_sha256": self.contract_version_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "mission_ref": self.mission_ref,
            "mission_sha256": self.mission_sha256,
            "observations": [item.to_dict() for item in self.observations],
            "observed_at": self.observed_at,
            "observer_ref": self.observer_ref,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "residual_artifacts": [item.to_dict() for item in self.residual_artifacts],
            "reviewer_ref": self.reviewer_ref,
            "schema_version": SCHEMA_VERSION,
            "scope_sha256": self.scope_sha256,
            "target_sha256": self.target_sha256,
            "tenant_ref": self.tenant_ref,
            "tenant_sha256": self.tenant_sha256,
            "worker_profile_sha256": self.worker_profile_sha256,
            "worker_ref": self.worker_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CleanupObservation:
        expected_fields = _field_names(cls) | {"effects", "kind", "schema_version"}
        value = _exact(raw, expected_fields, "cleanup observation")
        _verify_effects(value["effects"])
        if value["kind"] != cls.KIND or value["schema_version"] != SCHEMA_VERSION:
            raise CleanupRestorationContractError("observation discriminator is invalid")
        _verify_address(value, "observation_id", "observation_sha256", "CRO", cls.DOMAIN)
        return cls(**{key: value[key] for key in _field_names(cls)})


@dataclass(frozen=True, slots=True)
class CleanupCompletionAssessment:
    tenant_ref: str
    tenant_sha256: str
    mission_ref: str
    mission_sha256: str
    scope_sha256: str
    action_sha256: str
    worker_ref: str
    worker_profile_sha256: str
    target_sha256: str
    contract_version: str
    contract_version_sha256: str
    plan_id: str
    plan_sha256: str
    observation_id: str
    observation_sha256: str
    reviewer_ref: str
    reviewed_at: str
    status: CompletionStatus
    reason_codes: tuple[str, ...]
    assessment_id: str = ""
    assessment_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.cleanup-restoration-assessment.v1"
    DOMAIN: ClassVar[str] = "sunderkey.cleanup-restoration-assessment.v1"

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref", "tenantref")
        _reference(self.mission_ref, "mission_ref", "missionref")
        for name in (
            "tenant_sha256",
            "mission_sha256",
            "scope_sha256",
            "action_sha256",
            "worker_profile_sha256",
            "target_sha256",
            "contract_version_sha256",
            "plan_sha256",
            "observation_sha256",
        ):
            _digest(getattr(self, name), name)
        _reference(self.worker_ref, "worker_ref", "principalref")
        _version(self.contract_version, "contract_version")
        if not re.fullmatch(r"CRP-[0-9A-F]{32}", self.plan_id) or not re.fullmatch(
            r"CRO-[0-9A-F]{32}", self.observation_id
        ):
            raise CleanupRestorationContractError("assessment source identity is invalid")
        _reference(self.reviewer_ref, "reviewer_ref", "reviewerref")
        _timestamp(self.reviewed_at, "reviewed_at")
        object.__setattr__(self, "status", _enum(CompletionStatus, self.status, "status"))
        reasons = _bounded_unique(self.reason_codes, "reason_codes")
        for reason in reasons:
            _code(reason, "reason_code")
        object.__setattr__(self, "reason_codes", tuple(sorted(reasons)))
        expected_id, expected_digest = _identity("CRA", self.DOMAIN, self._body())
        if self.assessment_id and self.assessment_id != expected_id:
            raise CleanupRestorationContractError("assessment_id does not match content")
        if self.assessment_sha256 and self.assessment_sha256 != expected_digest:
            raise CleanupRestorationContractError("assessment_sha256 does not match content")
        object.__setattr__(self, "assessment_id", expected_id)
        object.__setattr__(self, "assessment_sha256", expected_digest)

    def _body(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "contract_version": self.contract_version,
            "contract_version_sha256": self.contract_version_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "mission_ref": self.mission_ref,
            "mission_sha256": self.mission_sha256,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "reason_codes": list(self.reason_codes),
            "reviewed_at": self.reviewed_at,
            "reviewer_ref": self.reviewer_ref,
            "schema_version": SCHEMA_VERSION,
            "scope_sha256": self.scope_sha256,
            "status": self.status.value,
            "target_sha256": self.target_sha256,
            "tenant_ref": self.tenant_ref,
            "tenant_sha256": self.tenant_sha256,
            "worker_profile_sha256": self.worker_profile_sha256,
            "worker_ref": self.worker_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CleanupCompletionAssessment:
        expected_fields = _field_names(cls) | {"effects", "kind", "schema_version"}
        value = _exact(raw, expected_fields, "cleanup completion assessment")
        _verify_effects(value["effects"])
        if value["kind"] != cls.KIND or value["schema_version"] != SCHEMA_VERSION:
            raise CleanupRestorationContractError("assessment discriminator is invalid")
        _verify_address(value, "assessment_id", "assessment_sha256", "CRA", cls.DOMAIN)
        return cls(**{key: value[key] for key in _field_names(cls)})


def assess_cleanup_completion(
    plan: CleanupRestorationPlan,
    observation: CleanupObservation,
    *,
    reviewer_ref: str,
    reviewed_at: str,
) -> CleanupCompletionAssessment:
    """Assess supplied observations without performing cleanup or restoration."""

    _reference(reviewer_ref, "reviewer_ref", "reviewerref")
    reviewed = _timestamp(reviewed_at, "reviewed_at")
    if reviewer_ref != observation.reviewer_ref:
        raise CleanupRestorationContractError("reviewer does not match observation binding")
    if reviewer_ref in {plan.worker_ref, observation.observer_ref}:
        raise CleanupRestorationContractError("reviewer must be independent")
    bindings = (
        "tenant_ref",
        "tenant_sha256",
        "mission_ref",
        "mission_sha256",
        "scope_sha256",
        "action_sha256",
        "worker_ref",
        "worker_profile_sha256",
        "target_sha256",
        "contract_version",
        "contract_version_sha256",
    )
    if any(getattr(plan, name) != getattr(observation, name) for name in bindings):
        raise CleanupRestorationContractError("plan and observation context differs")
    if observation.plan_id != plan.plan_id or observation.plan_sha256 != plan.plan_sha256:
        raise CleanupRestorationContractError("observation does not bind the plan")
    if reviewed < _timestamp(observation.observed_at, "observed_at"):
        raise CleanupRestorationContractError("review precedes observation")
    if reviewed > _timestamp(plan.expires_at, "expires_at"):
        reasons: set[str] = {"plan_expired"}
    else:
        reasons = set()

    expected = {item.step_ref: item for item in plan.steps}
    observed = {item.step_ref: item for item in observation.observations}
    if set(expected) != set(observed):
        reasons.add("observation_set_incomplete")
    for step_ref, step in expected.items():
        result = observed.get(step_ref)
        if result is None:
            continue
        if result.sequence != step.sequence:
            reasons.add("step_order_mismatch")
        if result.outcome is StepOutcome.TIMED_OUT:
            reasons.add("step_timed_out")
        elif result.outcome is StepOutcome.FAILED:
            reasons.add("step_failed")
        elif result.outcome is StepOutcome.NOT_OBSERVED:
            reasons.add("step_not_observed")
        required = {item.evidence_ref: item for item in step.evidence_requirements}
        supplied = {item.evidence_ref: item for item in result.observed_evidence}
        if any(supplied.get(ref) != requirement for ref, requirement in required.items()):
            reasons.add("required_evidence_missing_or_mismatched")
        if result.outcome is not StepOutcome.SUCCEEDED:
            needs_compensation = step.failure_behavior is not FailureBehavior.HALT
            if needs_compensation and not result.compensation_observed:
                reasons.add("compensation_unobserved")

    if observation.residual_artifacts:
        reasons.add("residual_artifact_present")
    if any(
        item.disposition is ResidualDisposition.UNRESOLVED
        for item in observation.residual_artifacts
    ):
        reasons.add("residual_risk_unresolved")
    if not reasons:
        reasons.add("all_obligations_observed")
        status = CompletionStatus.CONTRACT_COMPLETE_UNVERIFIED
    else:
        status = CompletionStatus.INCOMPLETE
    return CleanupCompletionAssessment(
        tenant_ref=plan.tenant_ref,
        tenant_sha256=plan.tenant_sha256,
        mission_ref=plan.mission_ref,
        mission_sha256=plan.mission_sha256,
        scope_sha256=plan.scope_sha256,
        action_sha256=plan.action_sha256,
        worker_ref=plan.worker_ref,
        worker_profile_sha256=plan.worker_profile_sha256,
        target_sha256=plan.target_sha256,
        contract_version=plan.contract_version,
        contract_version_sha256=plan.contract_version_sha256,
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        observation_id=observation.observation_id,
        observation_sha256=observation.observation_sha256,
        reviewer_ref=reviewer_ref,
        reviewed_at=reviewed_at,
        status=status,
        reason_codes=tuple(reasons),
    )


def parse_contract(
    raw: Any,
) -> CleanupRestorationPlan | CleanupObservation | CleanupCompletionAssessment:
    """Parse one strict top-level cleanup and restoration record."""

    if not isinstance(raw, Mapping):
        raise CleanupRestorationContractError("contract must be an object")
    kind = raw.get("kind")
    factories = {
        CleanupRestorationPlan.KIND: CleanupRestorationPlan.from_dict,
        CleanupObservation.KIND: CleanupObservation.from_dict,
        CleanupCompletionAssessment.KIND: CleanupCompletionAssessment.from_dict,
    }
    try:
        factory = factories[kind]
    except (KeyError, TypeError) as exc:
        raise CleanupRestorationContractError("contract kind is invalid") from exc
    return factory(raw)
