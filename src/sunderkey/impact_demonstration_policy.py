"""Deterministic, effect-free impact demonstration policy planning.

The module turns caller-supplied opaque references into content-addressed
plans and planning receipts. It does not authorize actions, contact targets,
read artifacts, use credentials, execute payloads, modify data, or verify
cleanup. Every output remains evidence-only and requires a separate governed
runtime before any target interaction could be considered.
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
MAX_INTENTS = 6
MAX_TEXT = 256

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
REF_RE = re.compile(r"[a-z][a-z0-9_-]{1,31}:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

NO_EFFECTS = {
    "authorization": "none",
    "availability_change": "none",
    "credential_access": "none",
    "data_change": "none",
    "execution": "none",
    "lateral_movement": "none",
    "network": "none",
    "role_change": "none",
    "target_contact": "none",
}

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:api[_-]?key|password|passwd|secret|token)\s*[:=]", re.IGNORECASE),
    re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
)
_PAYLOAD_PATTERNS = (
    re.compile(r"(?:https?://|file://|\\\\|`|\$\(|&&|\|\||[<>])", re.IGNORECASE),
    re.compile(
        r"\b(?:shellcode|reverse[-_ ]shell|payload[-_ ]bytes|powershell[-_ ]enc)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:run|execute|launch)[-_ ](?:this[-_ ]|the[-_ ])?(?:command|payload|shell)\b",
        re.IGNORECASE,
    ),
)


class ImpactDemonstrationPolicyError(ValueError):
    """Raised when policy input or serialized output fails closed."""


class DemonstrationMode(StrEnum):
    OFF = "off"
    MODERATE = "moderate"
    DEEP = "deep"


class ProofCategory(StrEnum):
    CAPTURED_CREDENTIAL = "captured_credential"
    ROLE_CHANGE = "role_change"
    LATERAL_PIVOT = "lateral_pivot"
    DATA_MODIFICATION = "data_modification"
    AVAILABILITY_IMPACT = "availability_impact"
    DESTRUCTIVE_PROOF = "destructive_proof"


class ArtifactClass(StrEnum):
    AGGREGATE_METRIC = "aggregate_metric"
    METADATA_SNAPSHOT = "metadata_snapshot"
    REDACTED_TRANSCRIPT = "redacted_transcript"
    STATE_DELTA = "state_delta"


class PlanStatus(StrEnum):
    OFF = "off"
    EVIDENCE_PLAN_ONLY = "evidence_plan_only"
    DENIED = "denied"


class StepDisposition(StrEnum):
    SUPPRESSED = "suppressed"
    PLANNED_EVIDENCE_ONLY = "planned_evidence_only"
    PROHIBITED = "prohibited"


MODE_ALLOWED_CATEGORIES = {
    DemonstrationMode.OFF: frozenset(),
    DemonstrationMode.MODERATE: frozenset(
        {ProofCategory.CAPTURED_CREDENTIAL, ProofCategory.ROLE_CHANGE}
    ),
    DemonstrationMode.DEEP: frozenset(
        {
            ProofCategory.CAPTURED_CREDENTIAL,
            ProofCategory.ROLE_CHANGE,
            ProofCategory.LATERAL_PIVOT,
            ProofCategory.DATA_MODIFICATION,
        }
    ),
}
ALWAYS_PROHIBITED = frozenset({ProofCategory.AVAILABILITY_IMPACT, ProofCategory.DESTRUCTIVE_PROOF})
MODE_ARTIFACT_CEILINGS = {
    DemonstrationMode.OFF: 0,
    DemonstrationMode.MODERATE: 4096,
    DemonstrationMode.DEEP: 16384,
}
CLEANUP_CODES = {
    ProofCategory.CAPTURED_CREDENTIAL: "credential_invalidation_verified",
    ProofCategory.ROLE_CHANGE: "role_restoration_verified",
    ProofCategory.LATERAL_PIVOT: "pivot_session_termination_verified",
    ProofCategory.DATA_MODIFICATION: "data_restoration_verified",
    ProofCategory.AVAILABILITY_IMPACT: "availability_restoration_verified",
    ProofCategory.DESTRUCTIVE_PROOF: "destructive_recovery_verified",
}


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
        raise ImpactDemonstrationPolicyError("value cannot be serialized") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise ImpactDemonstrationPolicyError(f"{label} fields are invalid")
    return raw


def _field_names(record_type: type[Any]) -> set[str]:
    return {item.name for item in fields(record_type)}


def _ref(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or len(value) > MAX_TEXT or REF_RE.fullmatch(value) is None:
        raise ImpactDemonstrationPolicyError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise ImpactDemonstrationPolicyError(f"{label} must use {namespace}")
    if any(pattern.search(value) for pattern in (*_SECRET_PATTERNS, *_PAYLOAD_PATTERNS)):
        raise ImpactDemonstrationPolicyError(f"{label} contains secret or payload material")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ImpactDemonstrationPolicyError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ImpactDemonstrationPolicyError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ImpactDemonstrationPolicyError(f"{label} must be valid") from exc


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ImpactDemonstrationPolicyError(f"{label} is invalid") from exc


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ImpactDemonstrationPolicyError(f"{label} must be between {minimum} and {maximum}")
    return value


def _tuple(values: Sequence[Any], label: str, maximum: int = MAX_INTENTS) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ImpactDemonstrationPolicyError(f"{label} must be a sequence")
    result = tuple(values)
    if len(result) > maximum:
        raise ImpactDemonstrationPolicyError(f"{label} exceeds its limit")
    return result


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ImpactDemonstrationPolicyError(f"{label} must be a boolean")
    return value


@dataclass(frozen=True, slots=True)
class DemonstrationBinding:
    """Exact tenant, context, scope, target, session, and policy binding."""

    tenant_ref: str
    context_ref: str
    scope_ref: str
    scope_sha256: str
    target_ref: str
    target_sha256: str
    session_ref: str
    session_sha256: str
    policy_ref: str
    policy_sha256: str
    protected_target: bool
    production_data_present: bool

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("context_ref", "contextref"),
            ("scope_ref", "scoperef"),
            ("target_ref", "targetref"),
            ("session_ref", "sessionref"),
            ("policy_ref", "policyref"),
        ):
            _ref(getattr(self, name), name, namespace)
        for name in ("scope_sha256", "target_sha256", "session_sha256", "policy_sha256"):
            _digest(getattr(self, name), name)
        _bool(self.protected_target, "protected_target")
        _bool(self.production_data_present, "production_data_present")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(_field_names(type(self)))}

    @classmethod
    def from_dict(cls, raw: Any) -> DemonstrationBinding:
        return cls(**_exact(raw, _field_names(cls), "demonstration binding"))

    @property
    def binding_sha256(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class ProofIntent:
    """Opaque, non-operational evidence references for one proof category."""

    category: ProofCategory | str
    evidence_ref: str
    evidence_sha256: str
    reversible_proof_ref: str
    reversible_proof_sha256: str
    cleanup_plan_ref: str
    cleanup_plan_sha256: str
    artifact_class: ArtifactClass | str
    artifact_byte_limit: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "category", _enum(ProofCategory, self.category, "category"))
        object.__setattr__(
            self, "artifact_class", _enum(ArtifactClass, self.artifact_class, "artifact_class")
        )
        for name, namespace in (
            ("evidence_ref", "evidenceref"),
            ("reversible_proof_ref", "reversalref"),
            ("cleanup_plan_ref", "cleanupref"),
        ):
            _ref(getattr(self, name), name, namespace)
        for name in (
            "evidence_sha256",
            "reversible_proof_sha256",
            "cleanup_plan_sha256",
        ):
            _digest(getattr(self, name), name)
        _bounded_int(self.artifact_byte_limit, "artifact_byte_limit", 1, 16384)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_byte_limit": self.artifact_byte_limit,
            "artifact_class": self.artifact_class.value,
            "category": self.category.value,
            "cleanup_plan_ref": self.cleanup_plan_ref,
            "cleanup_plan_sha256": self.cleanup_plan_sha256,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "reversible_proof_ref": self.reversible_proof_ref,
            "reversible_proof_sha256": self.reversible_proof_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ProofIntent:
        return cls(**_exact(raw, _field_names(cls), "proof intent"))


@dataclass(frozen=True, slots=True)
class OperatorApproval:
    approval_ref: str
    approval_sha256: str
    operator_ref: str
    binding_sha256: str
    approved_mode: DemonstrationMode | str
    approved_categories: tuple[ProofCategory | str, ...]
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _ref(self.approval_ref, "approval_ref", "approvalref")
        _ref(self.operator_ref, "operator_ref", "principalref")
        _digest(self.approval_sha256, "approval_sha256")
        _digest(self.binding_sha256, "binding_sha256")
        object.__setattr__(
            self, "approved_mode", _enum(DemonstrationMode, self.approved_mode, "approved_mode")
        )
        categories = tuple(
            sorted(
                {
                    _enum(ProofCategory, item, "approved_category")
                    for item in self.approved_categories
                },
                key=lambda item: item.value,
            )
        )
        object.__setattr__(self, "approved_categories", categories)
        if _timestamp(self.expires_at, "approval expires_at") <= _timestamp(
            self.issued_at, "approval issued_at"
        ):
            raise ImpactDemonstrationPolicyError("approval expiration must follow issuance")

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_ref": self.approval_ref,
            "approval_sha256": self.approval_sha256,
            "approved_categories": [item.value for item in self.approved_categories],
            "approved_mode": self.approved_mode.value,
            "binding_sha256": self.binding_sha256,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "operator_ref": self.operator_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OperatorApproval:
        values = dict(_exact(raw, _field_names(cls), "operator approval"))
        values["approved_categories"] = tuple(values["approved_categories"])
        return cls(**values)


@dataclass(frozen=True, slots=True)
class IndependentReview:
    review_ref: str
    review_sha256: str
    reviewer_ref: str
    binding_sha256: str
    approval_sha256: str
    reviewed_mode: DemonstrationMode | str
    reviewed_categories: tuple[ProofCategory | str, ...]
    decision: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _ref(self.review_ref, "review_ref", "reviewref")
        _ref(self.reviewer_ref, "reviewer_ref", "principalref")
        for name in ("review_sha256", "binding_sha256", "approval_sha256"):
            _digest(getattr(self, name), name)
        object.__setattr__(
            self, "reviewed_mode", _enum(DemonstrationMode, self.reviewed_mode, "reviewed_mode")
        )
        categories = tuple(
            sorted(
                {
                    _enum(ProofCategory, item, "reviewed_category")
                    for item in self.reviewed_categories
                },
                key=lambda item: item.value,
            )
        )
        object.__setattr__(self, "reviewed_categories", categories)
        if self.decision != "accepted":
            raise ImpactDemonstrationPolicyError("independent review must be accepted")
        if _timestamp(self.expires_at, "review expires_at") <= _timestamp(
            self.issued_at, "review issued_at"
        ):
            raise ImpactDemonstrationPolicyError("review expiration must follow issuance")

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_sha256": self.approval_sha256,
            "binding_sha256": self.binding_sha256,
            "decision": self.decision,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "review_ref": self.review_ref,
            "review_sha256": self.review_sha256,
            "reviewed_categories": [item.value for item in self.reviewed_categories],
            "reviewed_mode": self.reviewed_mode.value,
            "reviewer_ref": self.reviewer_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IndependentReview:
        values = dict(_exact(raw, _field_names(cls), "independent review"))
        values["reviewed_categories"] = tuple(values["reviewed_categories"])
        return cls(**values)


@dataclass(frozen=True, slots=True)
class ImpactDemonstrationRequest:
    binding: DemonstrationBinding
    mode: DemonstrationMode | str
    intents: tuple[ProofIntent, ...]
    operator_approval: OperatorApproval | None
    independent_review: IndependentReview | None
    created_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.binding, DemonstrationBinding):
            raise ImpactDemonstrationPolicyError("binding is invalid")
        object.__setattr__(self, "mode", _enum(DemonstrationMode, self.mode, "mode"))
        raw_intents = _tuple(self.intents, "intents")
        if any(not isinstance(item, ProofIntent) for item in raw_intents):
            raise ImpactDemonstrationPolicyError("intents contains an invalid item")
        intents = tuple(sorted(raw_intents, key=lambda item: item.category.value))
        categories = [item.category for item in intents]
        if len(categories) != len(set(categories)):
            raise ImpactDemonstrationPolicyError("proof categories must be unique")
        object.__setattr__(self, "intents", intents)
        if self.operator_approval is not None and not isinstance(
            self.operator_approval, OperatorApproval
        ):
            raise ImpactDemonstrationPolicyError("operator_approval is invalid")
        if self.independent_review is not None and not isinstance(
            self.independent_review, IndependentReview
        ):
            raise ImpactDemonstrationPolicyError("independent_review is invalid")
        if _timestamp(self.expires_at, "request expires_at") <= _timestamp(
            self.created_at, "request created_at"
        ):
            raise ImpactDemonstrationPolicyError("request expiration must follow creation")

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "independent_review": (
                None if self.independent_review is None else self.independent_review.to_dict()
            ),
            "intents": [item.to_dict() for item in self.intents],
            "mode": self.mode.value,
            "operator_approval": (
                None if self.operator_approval is None else self.operator_approval.to_dict()
            ),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ImpactDemonstrationRequest:
        values = dict(_exact(raw, _field_names(cls), "impact demonstration request"))
        values["binding"] = DemonstrationBinding.from_dict(values["binding"])
        values["intents"] = tuple(ProofIntent.from_dict(item) for item in values["intents"])
        values["operator_approval"] = (
            None
            if values["operator_approval"] is None
            else OperatorApproval.from_dict(values["operator_approval"])
        )
        values["independent_review"] = (
            None
            if values["independent_review"] is None
            else IndependentReview.from_dict(values["independent_review"])
        )
        return cls(**values)


@dataclass(frozen=True, slots=True)
class DemonstrationStep:
    category: ProofCategory | str
    disposition: StepDisposition | str
    evidence_ref: str
    evidence_sha256: str
    reversible_proof_ref: str
    reversible_proof_sha256: str
    cleanup_plan_ref: str
    cleanup_plan_sha256: str
    cleanup_verification_code: str
    artifact_class: ArtifactClass | str
    artifact_byte_limit: int
    persist_raw_content: bool = False
    persist_secret_material: bool = False
    proof_method: str = "existing_evidence_reference"

    def __post_init__(self) -> None:
        object.__setattr__(self, "category", _enum(ProofCategory, self.category, "category"))
        object.__setattr__(
            self, "disposition", _enum(StepDisposition, self.disposition, "disposition")
        )
        object.__setattr__(
            self, "artifact_class", _enum(ArtifactClass, self.artifact_class, "artifact_class")
        )
        for name, namespace in (
            ("evidence_ref", "evidenceref"),
            ("reversible_proof_ref", "reversalref"),
            ("cleanup_plan_ref", "cleanupref"),
        ):
            _ref(getattr(self, name), name, namespace)
        for name in (
            "evidence_sha256",
            "reversible_proof_sha256",
            "cleanup_plan_sha256",
        ):
            _digest(getattr(self, name), name)
        if self.cleanup_verification_code != CLEANUP_CODES[self.category]:
            raise ImpactDemonstrationPolicyError("cleanup verification code is invalid")
        _bounded_int(self.artifact_byte_limit, "artifact_byte_limit", 0, 16384)
        if self.persist_raw_content or self.persist_secret_material:
            raise ImpactDemonstrationPolicyError("artifact persistence violates minimization")
        if self.proof_method != "existing_evidence_reference":
            raise ImpactDemonstrationPolicyError("proof method must remain evidence-only")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_byte_limit": self.artifact_byte_limit,
            "artifact_class": self.artifact_class.value,
            "category": self.category.value,
            "cleanup_plan_ref": self.cleanup_plan_ref,
            "cleanup_plan_sha256": self.cleanup_plan_sha256,
            "cleanup_verification_code": self.cleanup_verification_code,
            "disposition": self.disposition.value,
            "evidence_ref": self.evidence_ref,
            "evidence_sha256": self.evidence_sha256,
            "persist_raw_content": self.persist_raw_content,
            "persist_secret_material": self.persist_secret_material,
            "proof_method": self.proof_method,
            "reversible_proof_ref": self.reversible_proof_ref,
            "reversible_proof_sha256": self.reversible_proof_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DemonstrationStep:
        return cls(**_exact(raw, _field_names(cls), "demonstration step"))


@dataclass(frozen=True, slots=True)
class ImpactDemonstrationPlan:
    schema_version: int
    plan_id: str
    plan_sha256: str
    request_sha256: str
    binding_sha256: str
    evaluated_at: str
    request: ImpactDemonstrationRequest
    status: PlanStatus | str
    steps: tuple[DemonstrationStep, ...]
    denial_reasons: tuple[str, ...]
    operator_approval_required: bool
    operator_approval_satisfied: bool
    independent_review_required: bool
    independent_review_satisfied: bool
    cleanup_verification_required: bool
    artifact_total_byte_ceiling: int
    effects: Mapping[str, str]
    qualification_effect: str = "none"

    DOMAIN: ClassVar[str] = "sunderkey.impact-demonstration-plan.v1"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ImpactDemonstrationPolicyError("schema_version is unsupported")
        _digest(self.request_sha256, "request_sha256")
        _digest(self.binding_sha256, "binding_sha256")
        if not isinstance(self.request, ImpactDemonstrationRequest):
            raise ImpactDemonstrationPolicyError("request is invalid")
        if self.request_sha256 != canonical_sha256(self.request.to_dict()):
            raise ImpactDemonstrationPolicyError("request digest does not match content")
        if self.binding_sha256 != self.request.binding.binding_sha256:
            raise ImpactDemonstrationPolicyError("binding digest does not match content")
        evaluation_time = _timestamp(self.evaluated_at, "evaluated_at")
        object.__setattr__(self, "status", _enum(PlanStatus, self.status, "status"))
        steps = tuple(self.steps)
        if any(not isinstance(item, DemonstrationStep) for item in steps):
            raise ImpactDemonstrationPolicyError("steps contains an invalid item")
        if tuple(item.category for item in steps) != tuple(
            item.category for item in self.request.intents
        ):
            raise ImpactDemonstrationPolicyError("steps do not match requested categories")
        for step, intent in zip(steps, self.request.intents, strict=True):
            if (
                step.evidence_ref != intent.evidence_ref
                or step.evidence_sha256 != intent.evidence_sha256
                or step.reversible_proof_ref != intent.reversible_proof_ref
                or step.reversible_proof_sha256 != intent.reversible_proof_sha256
                or step.cleanup_plan_ref != intent.cleanup_plan_ref
                or step.cleanup_plan_sha256 != intent.cleanup_plan_sha256
                or step.artifact_class is not intent.artifact_class
            ):
                raise ImpactDemonstrationPolicyError("step evidence does not match its intent")
        object.__setattr__(self, "steps", steps)
        reasons = tuple(sorted(set(self.denial_reasons)))
        if any(
            not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item)
            for item in reasons
        ):
            raise ImpactDemonstrationPolicyError("denial reasons are invalid")
        object.__setattr__(self, "denial_reasons", reasons)
        for name in (
            "operator_approval_required",
            "operator_approval_satisfied",
            "independent_review_required",
            "independent_review_satisfied",
            "cleanup_verification_required",
        ):
            _bool(getattr(self, name), name)
        _bounded_int(
            self.artifact_total_byte_ceiling,
            "artifact_total_byte_ceiling",
            0,
            16384,
        )
        (
            expected_status,
            expected_reasons,
            expected_approval_required,
            expected_approval_satisfied,
            expected_review_required,
            expected_review_satisfied,
        ) = _evaluate_policy(self.request, evaluation_time)
        observed_policy = (
            self.status,
            reasons,
            self.operator_approval_required,
            self.operator_approval_satisfied,
            self.independent_review_required,
            self.independent_review_satisfied,
        )
        expected_policy = (
            expected_status,
            expected_reasons,
            expected_approval_required,
            expected_approval_satisfied,
            expected_review_required,
            expected_review_satisfied,
        )
        if observed_policy != expected_policy:
            raise ImpactDemonstrationPolicyError("policy result is inconsistent with bound inputs")
        expected_disposition = {
            PlanStatus.OFF: StepDisposition.SUPPRESSED,
            PlanStatus.EVIDENCE_PLAN_ONLY: StepDisposition.PLANNED_EVIDENCE_ONLY,
            PlanStatus.DENIED: StepDisposition.PROHIBITED,
        }[self.status]
        if any(item.disposition is not expected_disposition for item in steps):
            raise ImpactDemonstrationPolicyError("step disposition does not match plan status")
        if self.status is PlanStatus.EVIDENCE_PLAN_ONLY:
            if reasons:
                raise ImpactDemonstrationPolicyError(
                    "accepted inert plan cannot have denial reasons"
                )
            if not self.operator_approval_satisfied or not self.independent_review_satisfied:
                raise ImpactDemonstrationPolicyError("accepted inert plan lacks required review")
            if self.cleanup_verification_required != bool(steps):
                raise ImpactDemonstrationPolicyError(
                    "cleanup verification requirement is inconsistent"
                )
            if self.artifact_total_byte_ceiling != sum(item.artifact_byte_limit for item in steps):
                raise ImpactDemonstrationPolicyError("artifact ceiling does not match steps")
        else:
            if self.status is PlanStatus.DENIED and not reasons:
                raise ImpactDemonstrationPolicyError("denied plan requires a denial reason")
            if self.cleanup_verification_required or self.artifact_total_byte_ceiling != 0:
                raise ImpactDemonstrationPolicyError(
                    "inactive plan cannot require cleanup or artifacts"
                )
            if any(item.artifact_byte_limit != 0 for item in steps):
                raise ImpactDemonstrationPolicyError("inactive steps cannot retain artifacts")
        if not isinstance(self.effects, Mapping):
            raise ImpactDemonstrationPolicyError("effects must preserve the no-effect boundary")
        effects = dict(self.effects)
        if effects != NO_EFFECTS or set(effects) != set(NO_EFFECTS):
            raise ImpactDemonstrationPolicyError("effects must preserve the no-effect boundary")
        object.__setattr__(self, "effects", MappingProxyType(effects))
        if self.qualification_effect != "none":
            raise ImpactDemonstrationPolicyError("plan cannot create a qualification effect")
        expected_id, expected_sha = _identity("IDP", self.DOMAIN, self._body())
        if self.plan_id != expected_id or self.plan_sha256 != expected_sha:
            raise ImpactDemonstrationPolicyError("plan content address does not match content")

    def _body(self) -> dict[str, Any]:
        return {
            "artifact_total_byte_ceiling": self.artifact_total_byte_ceiling,
            "binding_sha256": self.binding_sha256,
            "cleanup_verification_required": self.cleanup_verification_required,
            "denial_reasons": list(self.denial_reasons),
            "effects": dict(self.effects),
            "evaluated_at": self.evaluated_at,
            "independent_review_required": self.independent_review_required,
            "independent_review_satisfied": self.independent_review_satisfied,
            "kind": self.DOMAIN,
            "operator_approval_required": self.operator_approval_required,
            "operator_approval_satisfied": self.operator_approval_satisfied,
            "qualification_effect": self.qualification_effect,
            "request": self.request.to_dict(),
            "request_sha256": self.request_sha256,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "steps": [item.to_dict() for item in self.steps],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_id": self.plan_id, "plan_sha256": self.plan_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> ImpactDemonstrationPlan:
        expected = {
            "artifact_total_byte_ceiling",
            "binding_sha256",
            "cleanup_verification_required",
            "denial_reasons",
            "effects",
            "evaluated_at",
            "independent_review_required",
            "independent_review_satisfied",
            "kind",
            "operator_approval_required",
            "operator_approval_satisfied",
            "plan_id",
            "plan_sha256",
            "qualification_effect",
            "request",
            "request_sha256",
            "schema_version",
            "status",
            "steps",
        }
        _exact(raw, expected, "impact demonstration plan")
        if raw["kind"] != cls.DOMAIN:
            raise ImpactDemonstrationPolicyError("plan kind is invalid")
        return cls(
            schema_version=raw["schema_version"],
            plan_id=raw["plan_id"],
            plan_sha256=raw["plan_sha256"],
            request_sha256=raw["request_sha256"],
            binding_sha256=raw["binding_sha256"],
            evaluated_at=raw["evaluated_at"],
            request=ImpactDemonstrationRequest.from_dict(raw["request"]),
            status=raw["status"],
            steps=tuple(DemonstrationStep.from_dict(item) for item in raw["steps"]),
            denial_reasons=tuple(raw["denial_reasons"]),
            operator_approval_required=raw["operator_approval_required"],
            operator_approval_satisfied=raw["operator_approval_satisfied"],
            independent_review_required=raw["independent_review_required"],
            independent_review_satisfied=raw["independent_review_satisfied"],
            cleanup_verification_required=raw["cleanup_verification_required"],
            artifact_total_byte_ceiling=raw["artifact_total_byte_ceiling"],
            effects=raw["effects"],
            qualification_effect=raw["qualification_effect"],
        )


@dataclass(frozen=True, slots=True)
class ImpactDemonstrationReceipt:
    schema_version: int
    receipt_id: str
    receipt_sha256: str
    plan_id: str
    plan_sha256: str
    binding_sha256: str
    plan_status: PlanStatus | str
    policy_result: str
    effects: Mapping[str, str]
    qualification_effect: str = "none"

    DOMAIN: ClassVar[str] = "sunderkey.impact-demonstration-planning-receipt.v1"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ImpactDemonstrationPolicyError("schema_version is unsupported")
        if not re.fullmatch(r"IDP-[0-9A-F]{32}", self.plan_id):
            raise ImpactDemonstrationPolicyError("plan_id is invalid")
        _digest(self.plan_sha256, "plan_sha256")
        _digest(self.binding_sha256, "binding_sha256")
        object.__setattr__(self, "plan_status", _enum(PlanStatus, self.plan_status, "plan_status"))
        expected_result = (
            "accepted_inert_plan"
            if self.plan_status is PlanStatus.EVIDENCE_PLAN_ONLY
            else "no_plan_effect"
        )
        if self.policy_result != expected_result:
            raise ImpactDemonstrationPolicyError("policy_result does not match plan status")
        if not isinstance(self.effects, Mapping):
            raise ImpactDemonstrationPolicyError("receipt effects must remain empty")
        effects = dict(self.effects)
        if effects != NO_EFFECTS or set(effects) != set(NO_EFFECTS):
            raise ImpactDemonstrationPolicyError("receipt effects must remain empty")
        object.__setattr__(self, "effects", MappingProxyType(effects))
        if self.qualification_effect != "none":
            raise ImpactDemonstrationPolicyError("receipt cannot create a qualification effect")
        expected_id, expected_sha = _identity("IDR", self.DOMAIN, self._body())
        if self.receipt_id != expected_id or self.receipt_sha256 != expected_sha:
            raise ImpactDemonstrationPolicyError("receipt content address does not match content")

    def _body(self) -> dict[str, Any]:
        return {
            "binding_sha256": self.binding_sha256,
            "effects": dict(self.effects),
            "kind": self.DOMAIN,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "plan_status": self.plan_status.value,
            "policy_result": self.policy_result,
            "qualification_effect": self.qualification_effect,
            "schema_version": self.schema_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ImpactDemonstrationReceipt:
        expected = {
            "binding_sha256",
            "effects",
            "kind",
            "plan_id",
            "plan_sha256",
            "plan_status",
            "policy_result",
            "qualification_effect",
            "receipt_id",
            "receipt_sha256",
            "schema_version",
        }
        _exact(raw, expected, "impact demonstration receipt")
        if raw["kind"] != cls.DOMAIN:
            raise ImpactDemonstrationPolicyError("receipt kind is invalid")
        values = dict(raw)
        values.pop("kind")
        return cls(**values)


def _approval_satisfied(request: ImpactDemonstrationRequest, evaluated_at: datetime) -> bool:
    approval = request.operator_approval
    if approval is None:
        return False
    categories = tuple(item.category for item in request.intents)
    return bool(
        approval.binding_sha256 == request.binding.binding_sha256
        and approval.approved_mode is request.mode
        and approval.approved_categories == categories
        and _timestamp(approval.issued_at, "approval issued_at")
        <= evaluated_at
        < _timestamp(approval.expires_at, "approval expires_at")
    )


def _review_satisfied(request: ImpactDemonstrationRequest, evaluated_at: datetime) -> bool:
    review = request.independent_review
    approval = request.operator_approval
    if review is None or approval is None:
        return False
    categories = tuple(item.category for item in request.intents)
    return bool(
        review.binding_sha256 == request.binding.binding_sha256
        and review.approval_sha256 == approval.approval_sha256
        and review.reviewed_mode is request.mode
        and review.reviewed_categories == categories
        and review.reviewer_ref != approval.operator_ref
        and _timestamp(review.issued_at, "review issued_at")
        <= evaluated_at
        < _timestamp(review.expires_at, "review expires_at")
    )


def _evaluate_policy(
    request: ImpactDemonstrationRequest,
    evaluated_at: datetime,
) -> tuple[PlanStatus, tuple[str, ...], bool, bool, bool, bool]:
    reasons: set[str] = set()
    categories = tuple(item.category for item in request.intents)
    approval_required = request.mode is not DemonstrationMode.OFF
    review_required = request.mode is DemonstrationMode.DEEP
    approval_satisfied = not approval_required or _approval_satisfied(request, evaluated_at)
    review_satisfied = not review_required or _review_satisfied(request, evaluated_at)
    if not (
        _timestamp(request.created_at, "request created_at")
        <= evaluated_at
        < _timestamp(request.expires_at, "request expires_at")
    ):
        reasons.add("request_not_current")
    if approval_required and not approval_satisfied:
        reasons.add("operator_approval_unsatisfied")
    if review_required and not review_satisfied:
        reasons.add("independent_review_unsatisfied")
    if request.binding.protected_target and request.mode is not DemonstrationMode.OFF:
        reasons.add("protected_target_prohibited")
    if request.binding.production_data_present and request.mode is not DemonstrationMode.OFF:
        reasons.add("production_data_prohibited")
    requested = set(categories)
    if requested & ALWAYS_PROHIBITED:
        reasons.add("prohibited_proof_category")
    if requested - MODE_ALLOWED_CATEGORIES[request.mode]:
        reasons.add("mode_category_ceiling_exceeded")
    ceiling = MODE_ARTIFACT_CEILINGS[request.mode]
    if sum(item.artifact_byte_limit for item in request.intents) > ceiling:
        reasons.add("artifact_minimization_ceiling_exceeded")
    if request.mode is DemonstrationMode.OFF:
        status = PlanStatus.OFF
    elif reasons:
        status = PlanStatus.DENIED
    else:
        status = PlanStatus.EVIDENCE_PLAN_ONLY
    return (
        status,
        tuple(sorted(reasons)),
        approval_required,
        approval_satisfied,
        review_required,
        review_satisfied,
    )


def build_impact_demonstration_plan(
    request: ImpactDemonstrationRequest,
    *,
    evaluated_at: datetime,
) -> ImpactDemonstrationPlan:
    """Build an inert policy plan using only caller-injected records."""

    if not isinstance(request, ImpactDemonstrationRequest):
        raise ImpactDemonstrationPolicyError("request is invalid")
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ImpactDemonstrationPolicyError("evaluated_at must be timezone-aware")
    evaluated_at = evaluated_at.astimezone(UTC)
    if evaluated_at.microsecond:
        raise ImpactDemonstrationPolicyError("evaluated_at must use whole seconds")
    evaluated_at_text = evaluated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    (
        status,
        reasons,
        approval_required,
        approval_satisfied,
        review_required,
        review_satisfied,
    ) = _evaluate_policy(request, evaluated_at)
    steps = tuple(
        DemonstrationStep(
            category=item.category,
            disposition=(
                StepDisposition.SUPPRESSED
                if request.mode is DemonstrationMode.OFF
                else (
                    StepDisposition.PLANNED_EVIDENCE_ONLY
                    if status is PlanStatus.EVIDENCE_PLAN_ONLY
                    else StepDisposition.PROHIBITED
                )
            ),
            evidence_ref=item.evidence_ref,
            evidence_sha256=item.evidence_sha256,
            reversible_proof_ref=item.reversible_proof_ref,
            reversible_proof_sha256=item.reversible_proof_sha256,
            cleanup_plan_ref=item.cleanup_plan_ref,
            cleanup_plan_sha256=item.cleanup_plan_sha256,
            cleanup_verification_code=CLEANUP_CODES[item.category],
            artifact_class=item.artifact_class,
            artifact_byte_limit=(
                item.artifact_byte_limit if status is PlanStatus.EVIDENCE_PLAN_ONLY else 0
            ),
        )
        for item in request.intents
    )
    request_sha256 = canonical_sha256(request.to_dict())
    body = {
        "artifact_total_byte_ceiling": (
            sum(item.artifact_byte_limit for item in steps)
            if status is PlanStatus.EVIDENCE_PLAN_ONLY
            else 0
        ),
        "binding_sha256": request.binding.binding_sha256,
        "cleanup_verification_required": status is PlanStatus.EVIDENCE_PLAN_ONLY and bool(steps),
        "denial_reasons": list(reasons),
        "effects": dict(NO_EFFECTS),
        "evaluated_at": evaluated_at_text,
        "independent_review_required": review_required,
        "independent_review_satisfied": review_satisfied,
        "kind": ImpactDemonstrationPlan.DOMAIN,
        "operator_approval_required": approval_required,
        "operator_approval_satisfied": approval_satisfied,
        "qualification_effect": "none",
        "request": request.to_dict(),
        "request_sha256": request_sha256,
        "schema_version": SCHEMA_VERSION,
        "status": status.value,
        "steps": [item.to_dict() for item in steps],
    }
    plan_id, plan_sha256 = _identity("IDP", ImpactDemonstrationPlan.DOMAIN, body)
    return ImpactDemonstrationPlan(
        schema_version=SCHEMA_VERSION,
        plan_id=plan_id,
        plan_sha256=plan_sha256,
        request_sha256=request_sha256,
        binding_sha256=request.binding.binding_sha256,
        evaluated_at=evaluated_at_text,
        request=request,
        status=status,
        steps=steps,
        denial_reasons=reasons,
        operator_approval_required=approval_required,
        operator_approval_satisfied=approval_satisfied,
        independent_review_required=review_required,
        independent_review_satisfied=review_satisfied,
        cleanup_verification_required=status is PlanStatus.EVIDENCE_PLAN_ONLY and bool(steps),
        artifact_total_byte_ceiling=body["artifact_total_byte_ceiling"],
        effects=dict(NO_EFFECTS),
    )


def build_impact_demonstration_receipt(
    plan: ImpactDemonstrationPlan,
) -> ImpactDemonstrationReceipt:
    """Publish a content-addressed receipt for an already validated inert plan."""

    if not isinstance(plan, ImpactDemonstrationPlan):
        raise ImpactDemonstrationPolicyError("plan is invalid")
    policy_result = (
        "accepted_inert_plan" if plan.status is PlanStatus.EVIDENCE_PLAN_ONLY else "no_plan_effect"
    )
    body = {
        "binding_sha256": plan.binding_sha256,
        "effects": dict(NO_EFFECTS),
        "kind": ImpactDemonstrationReceipt.DOMAIN,
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "plan_status": plan.status.value,
        "policy_result": policy_result,
        "qualification_effect": "none",
        "schema_version": SCHEMA_VERSION,
    }
    receipt_id, receipt_sha256 = _identity("IDR", ImpactDemonstrationReceipt.DOMAIN, body)
    return ImpactDemonstrationReceipt(
        schema_version=SCHEMA_VERSION,
        receipt_id=receipt_id,
        receipt_sha256=receipt_sha256,
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        binding_sha256=plan.binding_sha256,
        plan_status=plan.status,
        policy_result=policy_result,
        effects=dict(NO_EFFECTS),
    )


def parse_impact_demonstration_plan(
    raw: str | bytes | Mapping[str, Any],
) -> ImpactDemonstrationPlan:
    """Strictly parse and verify a plan, including its content address."""

    decoded = _decode(raw, "plan")
    plan = ImpactDemonstrationPlan.from_dict(decoded)
    if plan.to_dict() != decoded:
        raise ImpactDemonstrationPolicyError("plan encoding is not canonical")
    return plan


def parse_impact_demonstration_receipt(
    raw: str | bytes | Mapping[str, Any],
) -> ImpactDemonstrationReceipt:
    """Strictly parse and verify a receipt, including its content address."""

    decoded = _decode(raw, "receipt")
    receipt = ImpactDemonstrationReceipt.from_dict(decoded)
    if receipt.to_dict() != decoded:
        raise ImpactDemonstrationPolicyError("receipt encoding is not canonical")
    return receipt


def _decode(raw: str | bytes | Mapping[str, Any], label: str) -> Mapping[str, Any]:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ImpactDemonstrationPolicyError(f"{label} bytes must be UTF-8 JSON") from exc
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ImpactDemonstrationPolicyError(f"{label} must be valid JSON") from exc
        if canonical_json(decoded) != raw:
            raise ImpactDemonstrationPolicyError(f"{label} document must be canonical JSON")
        return decoded
    if not isinstance(raw, Mapping):
        raise ImpactDemonstrationPolicyError(f"{label} must be a mapping or canonical JSON")
    return raw


__all__ = [
    "ALWAYS_PROHIBITED",
    "CLEANUP_CODES",
    "MODE_ALLOWED_CATEGORIES",
    "MODE_ARTIFACT_CEILINGS",
    "NO_EFFECTS",
    "ArtifactClass",
    "DemonstrationBinding",
    "DemonstrationMode",
    "DemonstrationStep",
    "ImpactDemonstrationPlan",
    "ImpactDemonstrationPolicyError",
    "ImpactDemonstrationReceipt",
    "ImpactDemonstrationRequest",
    "IndependentReview",
    "OperatorApproval",
    "PlanStatus",
    "ProofCategory",
    "ProofIntent",
    "StepDisposition",
    "build_impact_demonstration_plan",
    "build_impact_demonstration_receipt",
    "canonical_json",
    "canonical_sha256",
    "parse_impact_demonstration_plan",
    "parse_impact_demonstration_receipt",
]
