"""Offline end-to-end conformance coordination over injected step adapters.

This module validates content-addressed observations. It does not execute a
target, open a network connection, access credentials, deploy resources,
grant authority, promote a candidate, or prove a live workflow.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

SCHEMA_VERSION = 1

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|contextref|scoperef|missionref|operatorref|adapterref|"
    r"reviewerref|fenceref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")

EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credentials": "not_accessed",
        "deployment": "none",
        "filesystem_discovery": "none",
        "live_workflow_proof": "none",
        "network": "none",
        "promotion": "none",
        "qualification": "none",
        "target_execution": "none",
    }
)


class EndToEndConformanceError(ValueError):
    """Raised when a conformance record or adapter observation fails closed."""


class ConformanceStage(StrEnum):
    SERVICE_INTAKE = "service_intake"
    SCHEDULER_DISPATCH = "scheduler_dispatch"
    ACTION_ADMISSION = "action_admission"
    SPECIALIST_EXECUTION = "specialist_execution"
    EVIDENCE_RECORDING = "evidence_recording"
    FINDING_VALIDATION = "finding_validation"
    REPORTING = "reporting"
    ACTIVATION_REVIEW = "activation_review"
    ACTIVATION = "activation"
    CLEANUP_RESTORATION = "cleanup_restoration"
    ROLLBACK_VERIFICATION = "rollback_verification"


@dataclass(frozen=True, slots=True)
class StageDefinition:
    stage: ConformanceStage
    ordinal: int
    requires_independent_review: bool


STAGE_DEFINITIONS = (
    StageDefinition(ConformanceStage.SERVICE_INTAKE, 1, False),
    StageDefinition(ConformanceStage.SCHEDULER_DISPATCH, 2, False),
    StageDefinition(ConformanceStage.ACTION_ADMISSION, 3, True),
    StageDefinition(ConformanceStage.SPECIALIST_EXECUTION, 4, False),
    StageDefinition(ConformanceStage.EVIDENCE_RECORDING, 5, False),
    StageDefinition(ConformanceStage.FINDING_VALIDATION, 6, True),
    StageDefinition(ConformanceStage.REPORTING, 7, False),
    StageDefinition(ConformanceStage.ACTIVATION_REVIEW, 8, True),
    StageDefinition(ConformanceStage.ACTIVATION, 9, False),
    StageDefinition(ConformanceStage.CLEANUP_RESTORATION, 10, True),
    StageDefinition(ConformanceStage.ROLLBACK_VERIFICATION, 11, True),
)
STAGE_BY_NAME = MappingProxyType({item.stage: item for item in STAGE_DEFINITIONS})


class StageStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ReviewDecision(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class ReceiptStatus(StrEnum):
    CONFORMANT = "conformant"
    NONCONFORMANT = "nonconformant"


def canonical_json(value: Any) -> str:
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


def _validate_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 12:
        raise EndToEndConformanceError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EndToEndConformanceError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise EndToEndConformanceError(f"{label} has an unsupported value")


def _exact(raw: Mapping[str, Any], expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise EndToEndConformanceError(f"{label} fields are invalid")


def _reference(value: Any, label: str, namespace: str) -> str:
    if (
        not isinstance(value, str)
        or REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise EndToEndConformanceError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EndToEndConformanceError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise EndToEndConformanceError(f"{label} must be canonical UTC")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EndToEndConformanceError(f"{label} must be a non-negative integer")
    return value


def _positive(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EndToEndConformanceError(f"{label} must be a positive integer")
    return value


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _verify_identity(
    raw: Mapping[str, Any], id_field: str, hash_field: str, prefix: str, domain: str
) -> None:
    body = {key: value for key, value in raw.items() if key not in {id_field, hash_field}}
    record_id, record_sha256 = _identity(prefix, domain, body)
    if raw[id_field] != record_id or raw[hash_field] != record_sha256:
        raise EndToEndConformanceError("record content address does not match content")


def _canonical_document(document: str) -> Mapping[str, Any]:
    if not isinstance(document, str):
        raise EndToEndConformanceError("document must be text")
    try:
        raw = json.loads(document)
    except json.JSONDecodeError as exc:
        raise EndToEndConformanceError("document must be valid JSON") from exc
    if not isinstance(raw, Mapping) or canonical_json(raw) != document:
        raise EndToEndConformanceError("document must be canonical JSON")
    return raw


@dataclass(frozen=True, slots=True)
class ExecutionBinding:
    tenant_ref: str
    context_ref: str
    scope_ref: str
    mission_ref: str
    operator_ref: str

    def __post_init__(self) -> None:
        for name, namespace in (
            ("tenant_ref", "tenantref"),
            ("context_ref", "contextref"),
            ("scope_ref", "scoperef"),
            ("mission_ref", "missionref"),
            ("operator_ref", "operatorref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))

    @property
    def binding_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {
            "context_ref": self.context_ref,
            "mission_ref": self.mission_ref,
            "operator_ref": self.operator_ref,
            "scope_ref": self.scope_ref,
            "tenant_ref": self.tenant_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ExecutionBinding:
        _exact(
            raw,
            {"context_ref", "mission_ref", "operator_ref", "scope_ref", "tenant_ref"},
            "execution binding",
        )
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class FenceBinding:
    fence_ref: str
    fence_token: str
    fence_epoch: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "fence_ref", _reference(self.fence_ref, "fence_ref", "fenceref"))
        if (
            not isinstance(self.fence_token, str)
            or len(self.fence_token) < 16
            or len(self.fence_token) > 128
            or not self.fence_token.isascii()
        ):
            raise EndToEndConformanceError("fence_token must be bounded ASCII text")
        _positive(self.fence_epoch, "fence_epoch")

    @property
    def fence_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "fence_epoch": self.fence_epoch,
            "fence_ref": self.fence_ref,
            "fence_token": self.fence_token,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> FenceBinding:
        _exact(raw, {"fence_epoch", "fence_ref", "fence_token"}, "fence binding")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class Budget:
    requests: int
    tokens: int
    elapsed_ms: int
    evidence_bytes: int

    def __post_init__(self) -> None:
        for name in ("requests", "tokens", "elapsed_ms", "evidence_bytes"):
            _nonnegative(getattr(self, name), name)

    def to_dict(self) -> dict[str, int]:
        return {
            "elapsed_ms": self.elapsed_ms,
            "evidence_bytes": self.evidence_bytes,
            "requests": self.requests,
            "tokens": self.tokens,
        }

    def plus(self, other: Budget) -> Budget:
        return Budget(
            requests=self.requests + other.requests,
            tokens=self.tokens + other.tokens,
            elapsed_ms=self.elapsed_ms + other.elapsed_ms,
            evidence_bytes=self.evidence_bytes + other.evidence_bytes,
        )

    def remaining(self, used: Budget) -> Budget:
        return Budget(
            requests=max(0, self.requests - used.requests),
            tokens=max(0, self.tokens - used.tokens),
            elapsed_ms=max(0, self.elapsed_ms - used.elapsed_ms),
            evidence_bytes=max(0, self.evidence_bytes - used.evidence_bytes),
        )

    def exceeds(self, ceiling: Budget) -> bool:
        return any(
            getattr(self, name) > getattr(ceiling, name)
            for name in ("requests", "tokens", "elapsed_ms", "evidence_bytes")
        )

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Budget:
        _exact(raw, {"elapsed_ms", "evidence_bytes", "requests", "tokens"}, "budget")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class ConformancePlan:
    plan_id: str
    plan_sha256: str
    binding: ExecutionBinding
    start_version: int
    fence: FenceBinding
    budget_ceiling: Budget
    cleanup_obligation_sha256: str
    rollback_policy_sha256: str
    idempotency_seed: str
    created_at: str

    KIND: ClassVar[str] = "sunderkey.end-to-end-conformance-plan.v1"
    PREFIX: ClassVar[str] = "ECP"
    DOMAIN: ClassVar[str] = "sunderkey.end-to-end-conformance-plan.v1"

    def __post_init__(self) -> None:
        _nonnegative(self.start_version, "start_version")
        _digest(self.cleanup_obligation_sha256, "cleanup_obligation_sha256")
        _digest(self.rollback_policy_sha256, "rollback_policy_sha256")
        if (
            not isinstance(self.idempotency_seed, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_seed) is None
        ):
            raise EndToEndConformanceError("idempotency_seed is invalid")
        _timestamp(self.created_at, "created_at")
        body = {
            key: value
            for key, value in self.to_dict().items()
            if key not in {"plan_id", "plan_sha256"}
        }
        expected_id, expected_sha256 = _identity(self.PREFIX, self.DOMAIN, body)
        if self.plan_id != expected_id or self.plan_sha256 != expected_sha256:
            raise EndToEndConformanceError("plan content address does not match content")

    @classmethod
    def create(
        cls,
        *,
        binding: ExecutionBinding,
        start_version: int,
        fence: FenceBinding,
        budget_ceiling: Budget,
        cleanup_obligation_sha256: str,
        rollback_policy_sha256: str,
        idempotency_seed: str,
        created_at: str,
    ) -> ConformancePlan:
        body = {
            "binding": binding.to_dict(),
            "budget_ceiling": budget_ceiling.to_dict(),
            "cleanup_obligation_sha256": cleanup_obligation_sha256,
            "created_at": created_at,
            "effects": dict(EFFECTS),
            "fence": fence.to_dict(),
            "idempotency_seed": idempotency_seed,
            "kind": cls.KIND,
            "rollback_policy_sha256": rollback_policy_sha256,
            "schema_version": SCHEMA_VERSION,
            "stage_order": [item.stage.value for item in STAGE_DEFINITIONS],
            "start_version": start_version,
        }
        record_id, record_sha256 = _identity(cls.PREFIX, cls.DOMAIN, body)
        return cls(
            record_id,
            record_sha256,
            binding,
            start_version,
            fence,
            budget_ceiling,
            cleanup_obligation_sha256,
            rollback_policy_sha256,
            idempotency_seed,
            created_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "budget_ceiling": self.budget_ceiling.to_dict(),
            "cleanup_obligation_sha256": self.cleanup_obligation_sha256,
            "created_at": self.created_at,
            "effects": dict(EFFECTS),
            "fence": self.fence.to_dict(),
            "idempotency_seed": self.idempotency_seed,
            "kind": self.KIND,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "rollback_policy_sha256": self.rollback_policy_sha256,
            "schema_version": SCHEMA_VERSION,
            "stage_order": [item.stage.value for item in STAGE_DEFINITIONS],
            "start_version": self.start_version,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ConformancePlan:
        expected = {
            "binding",
            "budget_ceiling",
            "cleanup_obligation_sha256",
            "created_at",
            "effects",
            "fence",
            "idempotency_seed",
            "kind",
            "plan_id",
            "plan_sha256",
            "rollback_policy_sha256",
            "schema_version",
            "stage_order",
            "start_version",
        }
        _exact(raw, expected, "conformance plan")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise EndToEndConformanceError("conformance plan kind or schema is invalid")
        if raw["effects"] != dict(EFFECTS):
            raise EndToEndConformanceError("conformance plan effects are invalid")
        if raw["stage_order"] != [item.stage.value for item in STAGE_DEFINITIONS]:
            raise EndToEndConformanceError("conformance plan stage order is invalid")
        _verify_identity(raw, "plan_id", "plan_sha256", cls.PREFIX, cls.DOMAIN)
        return cls(
            raw["plan_id"],
            raw["plan_sha256"],
            ExecutionBinding.from_dict(raw["binding"]),
            raw["start_version"],
            FenceBinding.from_dict(raw["fence"]),
            Budget.from_dict(raw["budget_ceiling"]),
            raw["cleanup_obligation_sha256"],
            raw["rollback_policy_sha256"],
            raw["idempotency_seed"],
            raw["created_at"],
        )

    @classmethod
    def from_json(cls, document: str) -> ConformancePlan:
        return cls.from_dict(_canonical_document(document))


@dataclass(frozen=True, slots=True)
class StageRequest:
    plan_id: str
    plan_sha256: str
    stage: ConformanceStage
    ordinal: int
    binding: ExecutionBinding
    expected_version: int
    fence: FenceBinding
    prior_stage_sha256: str | None
    prior_custody_sha256: str | None
    remaining_budget: Budget
    idempotency_key: str
    required_control_links: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage", ConformanceStage(self.stage))
        definition = STAGE_BY_NAME[self.stage]
        if self.ordinal != definition.ordinal:
            raise EndToEndConformanceError("stage request ordinal is invalid")
        _digest(self.plan_sha256, "plan_sha256")
        _nonnegative(self.expected_version, "expected_version")
        if self.prior_stage_sha256 is not None:
            _digest(self.prior_stage_sha256, "prior_stage_sha256")
        if self.prior_custody_sha256 is not None:
            _digest(self.prior_custody_sha256, "prior_custody_sha256")
        if IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None:
            raise EndToEndConformanceError("idempotency_key is invalid")
        links = dict(sorted(self.required_control_links.items()))
        for name, digest in links.items():
            if not isinstance(name, str) or not name.isascii():
                raise EndToEndConformanceError("control link name is invalid")
            _digest(digest, "control link")
        object.__setattr__(self, "required_control_links", MappingProxyType(links))


@dataclass(frozen=True, slots=True)
class ReviewAttestation:
    reviewer_ref: str
    reviewed_observation_sha256: str
    decision: ReviewDecision
    reviewed_at: str
    review_sha256: str

    @classmethod
    def create(
        cls,
        *,
        reviewer_ref: str,
        reviewed_observation_sha256: str,
        decision: ReviewDecision,
        reviewed_at: str,
    ) -> ReviewAttestation:
        body = {
            "decision": ReviewDecision(decision).value,
            "reviewed_at": reviewed_at,
            "reviewed_observation_sha256": reviewed_observation_sha256,
            "reviewer_ref": reviewer_ref,
        }
        return cls(
            reviewer_ref,
            reviewed_observation_sha256,
            ReviewDecision(decision),
            reviewed_at,
            canonical_sha256({"domain": "independent-stage-review.v1", "review": body}),
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reviewer_ref",
            _reference(self.reviewer_ref, "reviewer_ref", "reviewerref"),
        )
        object.__setattr__(self, "decision", ReviewDecision(self.decision))
        _digest(self.reviewed_observation_sha256, "reviewed_observation_sha256")
        _timestamp(self.reviewed_at, "reviewed_at")
        body = {
            "decision": self.decision.value,
            "reviewed_at": self.reviewed_at,
            "reviewed_observation_sha256": self.reviewed_observation_sha256,
            "reviewer_ref": self.reviewer_ref,
        }
        expected = canonical_sha256({"domain": "independent-stage-review.v1", "review": body})
        if self.review_sha256 != expected:
            raise EndToEndConformanceError("review content address does not match content")

    def to_dict(self) -> dict[str, str]:
        return {
            "decision": self.decision.value,
            "review_sha256": self.review_sha256,
            "reviewed_at": self.reviewed_at,
            "reviewed_observation_sha256": self.reviewed_observation_sha256,
            "reviewer_ref": self.reviewer_ref,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ReviewAttestation:
        _exact(
            raw,
            {
                "decision",
                "review_sha256",
                "reviewed_at",
                "reviewed_observation_sha256",
                "reviewer_ref",
            },
            "review attestation",
        )
        return cls(**raw)


def _stage_idempotency(plan: ConformancePlan, definition: StageDefinition) -> str:
    suffix = canonical_sha256(
        {
            "ordinal": definition.ordinal,
            "plan_sha256": plan.plan_sha256,
            "seed": plan.idempotency_seed,
            "stage": definition.stage.value,
        }
    )[7:39]
    return f"idem:conformance:{suffix}"


def _custody_sha256(
    stage: ConformanceStage,
    prior_custody_sha256: str | None,
    artifact_sha256s: Sequence[str],
) -> str:
    return canonical_sha256(
        {
            "artifact_sha256s": list(artifact_sha256s),
            "prior_custody_sha256": prior_custody_sha256,
            "stage": stage.value,
        }
    )


@dataclass(frozen=True, slots=True)
class StageEvidence:
    evidence_id: str
    evidence_sha256: str
    plan_id: str
    plan_sha256: str
    stage: ConformanceStage
    ordinal: int
    binding: ExecutionBinding
    binding_sha256: str
    fence: FenceBinding
    fence_sha256: str
    idempotency_key: str
    status: StageStatus
    version_before: int
    version_after: int
    prior_stage_sha256: str | None
    prior_custody_sha256: str | None
    custody_sha256: str
    artifact_sha256s: tuple[str, ...]
    budget_used: Budget
    control_links: Mapping[str, str]
    adapter_ref: str
    completed_at: str
    reason_code: str | None
    observation_sha256: str
    review: ReviewAttestation | None

    KIND: ClassVar[str] = "sunderkey.end-to-end-stage-evidence.v1"
    PREFIX: ClassVar[str] = "ECE"
    DOMAIN: ClassVar[str] = "sunderkey.end-to-end-stage-evidence.v1"

    @classmethod
    def create(
        cls,
        request: StageRequest,
        *,
        adapter_ref: str,
        status: StageStatus,
        artifact_sha256s: Sequence[str],
        budget_used: Budget,
        completed_at: str,
        reason_code: str | None = None,
        reviewer_ref: str | None = None,
        review_decision: ReviewDecision = ReviewDecision.ACCEPTED,
        reviewed_at: str | None = None,
    ) -> StageEvidence:
        status = StageStatus(status)
        artifacts = tuple(artifact_sha256s)
        version_after = request.expected_version + (1 if status is StageStatus.PASSED else 0)
        custody_sha256 = _custody_sha256(request.stage, request.prior_custody_sha256, artifacts)
        observation = {
            "adapter_ref": adapter_ref,
            "artifact_sha256s": list(artifacts),
            "binding": request.binding.to_dict(),
            "binding_sha256": request.binding.binding_sha256,
            "budget_used": budget_used.to_dict(),
            "completed_at": completed_at,
            "control_links": dict(request.required_control_links),
            "custody_sha256": custody_sha256,
            "fence": request.fence.to_dict(),
            "fence_sha256": request.fence.fence_sha256,
            "idempotency_key": request.idempotency_key,
            "ordinal": request.ordinal,
            "plan_id": request.plan_id,
            "plan_sha256": request.plan_sha256,
            "prior_custody_sha256": request.prior_custody_sha256,
            "prior_stage_sha256": request.prior_stage_sha256,
            "reason_code": reason_code,
            "stage": request.stage.value,
            "status": status.value,
            "version_after": version_after,
            "version_before": request.expected_version,
        }
        observation_sha256 = canonical_sha256(
            {"domain": "end-to-end-stage-observation.v1", "observation": observation}
        )
        review = None
        if reviewer_ref is not None:
            if reviewed_at is None:
                raise EndToEndConformanceError("reviewed_at is required with reviewer_ref")
            review = ReviewAttestation.create(
                reviewer_ref=reviewer_ref,
                reviewed_observation_sha256=observation_sha256,
                decision=review_decision,
                reviewed_at=reviewed_at,
            )
        body = {
            **observation,
            "effects": dict(EFFECTS),
            "kind": cls.KIND,
            "observation_sha256": observation_sha256,
            "qualification_effect": "none",
            "review": None if review is None else review.to_dict(),
            "schema_version": SCHEMA_VERSION,
        }
        record_id, record_sha256 = _identity(cls.PREFIX, cls.DOMAIN, body)
        return cls(
            record_id,
            record_sha256,
            request.plan_id,
            request.plan_sha256,
            request.stage,
            request.ordinal,
            request.binding,
            request.binding.binding_sha256,
            request.fence,
            request.fence.fence_sha256,
            request.idempotency_key,
            status,
            request.expected_version,
            version_after,
            request.prior_stage_sha256,
            request.prior_custody_sha256,
            custody_sha256,
            artifacts,
            budget_used,
            request.required_control_links,
            adapter_ref,
            completed_at,
            reason_code,
            observation_sha256,
            review,
        )

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage", ConformanceStage(self.stage))
        object.__setattr__(self, "status", StageStatus(self.status))
        if self.ordinal != STAGE_BY_NAME[self.stage].ordinal:
            raise EndToEndConformanceError("stage evidence ordinal is invalid")
        _digest(self.plan_sha256, "plan_sha256")
        if self.binding_sha256 != self.binding.binding_sha256:
            raise EndToEndConformanceError("binding content address does not match binding")
        if self.fence_sha256 != self.fence.fence_sha256:
            raise EndToEndConformanceError("fence content address does not match fence")
        if IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None:
            raise EndToEndConformanceError("idempotency_key is invalid")
        _nonnegative(self.version_before, "version_before")
        _nonnegative(self.version_after, "version_after")
        if self.status is StageStatus.PASSED:
            if self.version_after != self.version_before + 1 or self.reason_code is not None:
                raise EndToEndConformanceError("passed stage version or reason is invalid")
        elif self.version_after != self.version_before or not self.reason_code:
            raise EndToEndConformanceError("failed or skipped stage version or reason is invalid")
        if self.reason_code is not None and (
            not self.reason_code.isascii()
            or re.fullmatch(r"[a-z][a-z0-9_.-]{2,95}", self.reason_code) is None
        ):
            raise EndToEndConformanceError("reason_code is invalid")
        for value, label in (
            (self.prior_stage_sha256, "prior_stage_sha256"),
            (self.prior_custody_sha256, "prior_custody_sha256"),
        ):
            if value is not None:
                _digest(value, label)
        artifacts = tuple(self.artifact_sha256s)
        if not artifacts or artifacts != tuple(sorted(set(artifacts))):
            raise EndToEndConformanceError("artifact_sha256s must be sorted, unique, and non-empty")
        for artifact in artifacts:
            _digest(artifact, "artifact_sha256")
        object.__setattr__(self, "artifact_sha256s", artifacts)
        expected_custody = _custody_sha256(
            self.stage, self.prior_custody_sha256, self.artifact_sha256s
        )
        if self.custody_sha256 != expected_custody:
            raise EndToEndConformanceError("custody content address does not match content")
        links = dict(sorted(self.control_links.items()))
        for name, digest in links.items():
            if not isinstance(name, str) or not name.isascii():
                raise EndToEndConformanceError("control link name is invalid")
            _digest(digest, "control link")
        object.__setattr__(self, "control_links", MappingProxyType(links))
        object.__setattr__(
            self, "adapter_ref", _reference(self.adapter_ref, "adapter_ref", "adapterref")
        )
        _timestamp(self.completed_at, "completed_at")
        observation = self._observation_body()
        expected_observation = canonical_sha256(
            {"domain": "end-to-end-stage-observation.v1", "observation": observation}
        )
        if self.observation_sha256 != expected_observation:
            raise EndToEndConformanceError("observation content address does not match content")
        if (
            self.review is not None
            and self.review.reviewed_observation_sha256 != self.observation_sha256
        ):
            raise EndToEndConformanceError("review does not bind the stage observation")
        body = {
            key: value
            for key, value in self.to_dict().items()
            if key not in {"evidence_id", "evidence_sha256"}
        }
        expected_id, expected_sha256 = _identity(self.PREFIX, self.DOMAIN, body)
        if self.evidence_id != expected_id or self.evidence_sha256 != expected_sha256:
            raise EndToEndConformanceError("evidence content address does not match content")

    def _observation_body(self) -> dict[str, Any]:
        return {
            "adapter_ref": self.adapter_ref,
            "artifact_sha256s": list(self.artifact_sha256s),
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "budget_used": self.budget_used.to_dict(),
            "completed_at": self.completed_at,
            "control_links": dict(self.control_links),
            "custody_sha256": self.custody_sha256,
            "fence": self.fence.to_dict(),
            "fence_sha256": self.fence_sha256,
            "idempotency_key": self.idempotency_key,
            "ordinal": self.ordinal,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "prior_custody_sha256": self.prior_custody_sha256,
            "prior_stage_sha256": self.prior_stage_sha256,
            "reason_code": self.reason_code,
            "stage": self.stage.value,
            "status": self.status.value,
            "version_after": self.version_after,
            "version_before": self.version_before,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._observation_body(),
            "effects": dict(EFFECTS),
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            "kind": self.KIND,
            "observation_sha256": self.observation_sha256,
            "qualification_effect": "none",
            "review": None if self.review is None else self.review.to_dict(),
            "schema_version": SCHEMA_VERSION,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StageEvidence:
        expected = {
            "adapter_ref",
            "artifact_sha256s",
            "binding",
            "binding_sha256",
            "budget_used",
            "completed_at",
            "control_links",
            "custody_sha256",
            "effects",
            "evidence_id",
            "evidence_sha256",
            "fence",
            "fence_sha256",
            "idempotency_key",
            "kind",
            "observation_sha256",
            "ordinal",
            "plan_id",
            "plan_sha256",
            "prior_custody_sha256",
            "prior_stage_sha256",
            "qualification_effect",
            "reason_code",
            "review",
            "schema_version",
            "stage",
            "status",
            "version_after",
            "version_before",
        }
        _exact(raw, expected, "stage evidence")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(EFFECTS)
            or raw["qualification_effect"] != "none"
        ):
            raise EndToEndConformanceError("stage evidence envelope is invalid")
        _verify_identity(raw, "evidence_id", "evidence_sha256", cls.PREFIX, cls.DOMAIN)
        return cls(
            raw["evidence_id"],
            raw["evidence_sha256"],
            raw["plan_id"],
            raw["plan_sha256"],
            raw["stage"],
            raw["ordinal"],
            ExecutionBinding.from_dict(raw["binding"]),
            raw["binding_sha256"],
            FenceBinding.from_dict(raw["fence"]),
            raw["fence_sha256"],
            raw["idempotency_key"],
            raw["status"],
            raw["version_before"],
            raw["version_after"],
            raw["prior_stage_sha256"],
            raw["prior_custody_sha256"],
            raw["custody_sha256"],
            tuple(raw["artifact_sha256s"]),
            Budget.from_dict(raw["budget_used"]),
            raw["control_links"],
            raw["adapter_ref"],
            raw["completed_at"],
            raw["reason_code"],
            raw["observation_sha256"],
            None if raw["review"] is None else ReviewAttestation.from_dict(raw["review"]),
        )

    @classmethod
    def from_json(cls, document: str) -> StageEvidence:
        return cls.from_dict(_canonical_document(document))


@dataclass(frozen=True, slots=True)
class ConformanceGap:
    code: str
    stage: ConformanceStage
    detail: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_]{2,63}", self.code) is None:
            raise EndToEndConformanceError("gap code is invalid")
        object.__setattr__(self, "stage", ConformanceStage(self.stage))
        if not self.detail or not self.detail.isascii() or len(self.detail) > 240:
            raise EndToEndConformanceError("gap detail is invalid")

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail, "stage": self.stage.value}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ConformanceGap:
        _exact(raw, {"code", "detail", "stage"}, "conformance gap")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class GapReport:
    report_id: str
    report_sha256: str
    plan_id: str
    plan_sha256: str
    observed_stage_count: int
    completed_stages: tuple[ConformanceStage, ...]
    gaps: tuple[ConformanceGap, ...]
    generated_at: str

    KIND: ClassVar[str] = "sunderkey.end-to-end-conformance-gap-report.v1"
    PREFIX: ClassVar[str] = "ECG"
    DOMAIN: ClassVar[str] = "sunderkey.end-to-end-conformance-gap-report.v1"

    @classmethod
    def create(
        cls,
        plan: ConformancePlan,
        *,
        observed_stage_count: int,
        completed_stages: Sequence[ConformanceStage],
        gaps: Sequence[ConformanceGap],
        generated_at: str,
    ) -> GapReport:
        ordered_gaps = tuple(
            sorted(
                set(gaps),
                key=lambda item: (STAGE_BY_NAME[item.stage].ordinal, item.code, item.detail),
            )
        )
        body = {
            "completed_stages": [ConformanceStage(item).value for item in completed_stages],
            "effects": dict(EFFECTS),
            "gaps": [item.to_dict() for item in ordered_gaps],
            "generated_at": generated_at,
            "kind": cls.KIND,
            "observed_stage_count": observed_stage_count,
            "plan_id": plan.plan_id,
            "plan_sha256": plan.plan_sha256,
            "qualification_effect": "none",
            "schema_version": SCHEMA_VERSION,
        }
        record_id, record_sha256 = _identity(cls.PREFIX, cls.DOMAIN, body)
        return cls(
            record_id,
            record_sha256,
            plan.plan_id,
            plan.plan_sha256,
            observed_stage_count,
            tuple(completed_stages),
            ordered_gaps,
            generated_at,
        )

    def __post_init__(self) -> None:
        _digest(self.plan_sha256, "plan_sha256")
        _nonnegative(self.observed_stage_count, "observed_stage_count")
        object.__setattr__(
            self, "completed_stages", tuple(ConformanceStage(x) for x in self.completed_stages)
        )
        gaps = tuple(self.gaps)
        expected_gaps = tuple(
            sorted(
                set(gaps),
                key=lambda item: (STAGE_BY_NAME[item.stage].ordinal, item.code, item.detail),
            )
        )
        if gaps != expected_gaps:
            raise EndToEndConformanceError("gap report entries must be sorted and unique")
        object.__setattr__(self, "gaps", gaps)
        completed = self.completed_stages
        if completed != tuple(
            sorted(set(completed), key=lambda stage: STAGE_BY_NAME[stage].ordinal)
        ):
            raise EndToEndConformanceError("completed stages must be sorted and unique")
        _timestamp(self.generated_at, "generated_at")
        body = {
            key: value
            for key, value in self.to_dict().items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_id, expected_sha256 = _identity(self.PREFIX, self.DOMAIN, body)
        if self.report_id != expected_id or self.report_sha256 != expected_sha256:
            raise EndToEndConformanceError("gap report content address does not match content")

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed_stages": [item.value for item in self.completed_stages],
            "effects": dict(EFFECTS),
            "gaps": [item.to_dict() for item in self.gaps],
            "generated_at": self.generated_at,
            "kind": self.KIND,
            "observed_stage_count": self.observed_stage_count,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "qualification_effect": "none",
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> GapReport:
        expected = {
            "completed_stages",
            "effects",
            "gaps",
            "generated_at",
            "kind",
            "observed_stage_count",
            "plan_id",
            "plan_sha256",
            "qualification_effect",
            "report_id",
            "report_sha256",
            "schema_version",
        }
        _exact(raw, expected, "gap report")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(EFFECTS)
            or raw["qualification_effect"] != "none"
        ):
            raise EndToEndConformanceError("gap report envelope is invalid")
        _verify_identity(raw, "report_id", "report_sha256", cls.PREFIX, cls.DOMAIN)
        return cls(
            raw["report_id"],
            raw["report_sha256"],
            raw["plan_id"],
            raw["plan_sha256"],
            raw["observed_stage_count"],
            tuple(raw["completed_stages"]),
            tuple(ConformanceGap.from_dict(item) for item in raw["gaps"]),
            raw["generated_at"],
        )

    @classmethod
    def from_json(cls, document: str) -> GapReport:
        return cls.from_dict(_canonical_document(document))


@dataclass(frozen=True, slots=True)
class ConformanceReceipt:
    receipt_id: str
    receipt_sha256: str
    plan_id: str
    plan_sha256: str
    status: ReceiptStatus
    evidence_sha256s: tuple[str, ...]
    gap_report_id: str
    gap_report_sha256: str
    total_budget_used: Budget
    final_version: int
    final_custody_sha256: str | None
    completed_at: str

    KIND: ClassVar[str] = "sunderkey.end-to-end-conformance-receipt.v1"
    PREFIX: ClassVar[str] = "ECR"
    DOMAIN: ClassVar[str] = "sunderkey.end-to-end-conformance-receipt.v1"

    @classmethod
    def create(
        cls,
        plan: ConformancePlan,
        *,
        status: ReceiptStatus,
        evidence_sha256s: Sequence[str],
        gap_report: GapReport,
        total_budget_used: Budget,
        final_version: int,
        final_custody_sha256: str | None,
        completed_at: str,
    ) -> ConformanceReceipt:
        body = {
            "completed_at": completed_at,
            "effects": dict(EFFECTS),
            "evidence_sha256s": list(evidence_sha256s),
            "final_custody_sha256": final_custody_sha256,
            "final_version": final_version,
            "gap_report_id": gap_report.report_id,
            "gap_report_sha256": gap_report.report_sha256,
            "kind": cls.KIND,
            "plan_id": plan.plan_id,
            "plan_sha256": plan.plan_sha256,
            "proof_scope": "repository_only_offline_adapter_conformance",
            "qualification_effect": "none",
            "schema_version": SCHEMA_VERSION,
            "status": ReceiptStatus(status).value,
            "total_budget_used": total_budget_used.to_dict(),
        }
        record_id, record_sha256 = _identity(cls.PREFIX, cls.DOMAIN, body)
        return cls(
            record_id,
            record_sha256,
            plan.plan_id,
            plan.plan_sha256,
            ReceiptStatus(status),
            tuple(evidence_sha256s),
            gap_report.report_id,
            gap_report.report_sha256,
            total_budget_used,
            final_version,
            final_custody_sha256,
            completed_at,
        )

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", ReceiptStatus(self.status))
        _digest(self.plan_sha256, "plan_sha256")
        evidence = tuple(self.evidence_sha256s)
        if evidence != tuple(dict.fromkeys(evidence)):
            raise EndToEndConformanceError("receipt evidence addresses must be unique")
        for digest in evidence:
            _digest(digest, "evidence_sha256")
        object.__setattr__(self, "evidence_sha256s", evidence)
        _digest(self.gap_report_sha256, "gap_report_sha256")
        _nonnegative(self.final_version, "final_version")
        if self.final_custody_sha256 is not None:
            _digest(self.final_custody_sha256, "final_custody_sha256")
        _timestamp(self.completed_at, "completed_at")
        body = {
            key: value
            for key, value in self.to_dict().items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_id, expected_sha256 = _identity(self.PREFIX, self.DOMAIN, body)
        if self.receipt_id != expected_id or self.receipt_sha256 != expected_sha256:
            raise EndToEndConformanceError("receipt content address does not match content")

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed_at": self.completed_at,
            "effects": dict(EFFECTS),
            "evidence_sha256s": list(self.evidence_sha256s),
            "final_custody_sha256": self.final_custody_sha256,
            "final_version": self.final_version,
            "gap_report_id": self.gap_report_id,
            "gap_report_sha256": self.gap_report_sha256,
            "kind": self.KIND,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "proof_scope": "repository_only_offline_adapter_conformance",
            "qualification_effect": "none",
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
            "total_budget_used": self.total_budget_used.to_dict(),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ConformanceReceipt:
        expected = {
            "completed_at",
            "effects",
            "evidence_sha256s",
            "final_custody_sha256",
            "final_version",
            "gap_report_id",
            "gap_report_sha256",
            "kind",
            "plan_id",
            "plan_sha256",
            "proof_scope",
            "qualification_effect",
            "receipt_id",
            "receipt_sha256",
            "schema_version",
            "status",
            "total_budget_used",
        }
        _exact(raw, expected, "conformance receipt")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["effects"] != dict(EFFECTS)
            or raw["proof_scope"] != "repository_only_offline_adapter_conformance"
            or raw["qualification_effect"] != "none"
        ):
            raise EndToEndConformanceError("conformance receipt envelope is invalid")
        _verify_identity(raw, "receipt_id", "receipt_sha256", cls.PREFIX, cls.DOMAIN)
        return cls(
            raw["receipt_id"],
            raw["receipt_sha256"],
            raw["plan_id"],
            raw["plan_sha256"],
            raw["status"],
            tuple(raw["evidence_sha256s"]),
            raw["gap_report_id"],
            raw["gap_report_sha256"],
            Budget.from_dict(raw["total_budget_used"]),
            raw["final_version"],
            raw["final_custody_sha256"],
            raw["completed_at"],
        )

    @classmethod
    def from_json(cls, document: str) -> ConformanceReceipt:
        return cls.from_dict(_canonical_document(document))


@dataclass(frozen=True, slots=True)
class ConformanceResult:
    receipt: ConformanceReceipt
    gap_report: GapReport
    evidence: tuple[StageEvidence, ...]


class StepAdapter(Protocol):
    def observe_stage(self, request: StageRequest) -> StageEvidence | Mapping[str, Any]: ...


def _control_links(
    plan: ConformancePlan,
    stage: ConformanceStage,
    evidence_by_stage: Mapping[ConformanceStage, StageEvidence],
) -> Mapping[str, str]:
    if stage is ConformanceStage.ACTIVATION_REVIEW:
        item = evidence_by_stage.get(ConformanceStage.REPORTING)
        return {} if item is None else {"reporting_evidence": item.evidence_sha256}
    if stage is ConformanceStage.ACTIVATION:
        item = evidence_by_stage.get(ConformanceStage.ACTIVATION_REVIEW)
        return {} if item is None else {"activation_review_evidence": item.evidence_sha256}
    if stage is ConformanceStage.CLEANUP_RESTORATION:
        item = evidence_by_stage.get(ConformanceStage.SPECIALIST_EXECUTION)
        if item is None:
            return {"cleanup_obligation": plan.cleanup_obligation_sha256}
        return {
            "cleanup_obligation": plan.cleanup_obligation_sha256,
            "specialist_execution_evidence": item.evidence_sha256,
        }
    if stage is ConformanceStage.ROLLBACK_VERIFICATION:
        activation = evidence_by_stage.get(ConformanceStage.ACTIVATION)
        cleanup = evidence_by_stage.get(ConformanceStage.CLEANUP_RESTORATION)
        links = {"rollback_policy": plan.rollback_policy_sha256}
        if activation is not None:
            links["activation_evidence"] = activation.evidence_sha256
        if cleanup is not None:
            links["cleanup_restoration_evidence"] = cleanup.evidence_sha256
        return links
    return {}


def _request_for(
    plan: ConformancePlan,
    definition: StageDefinition,
    *,
    current_version: int,
    prior_stage_sha256: str | None,
    prior_custody_sha256: str | None,
    budget_used: Budget,
    evidence_by_stage: Mapping[ConformanceStage, StageEvidence],
) -> StageRequest:
    return StageRequest(
        plan.plan_id,
        plan.plan_sha256,
        definition.stage,
        definition.ordinal,
        plan.binding,
        current_version,
        plan.fence,
        prior_stage_sha256,
        prior_custody_sha256,
        plan.budget_ceiling.remaining(budget_used),
        _stage_idempotency(plan, definition),
        _control_links(plan, definition.stage, evidence_by_stage),
    )


def _gap(code: str, stage: ConformanceStage, detail: str) -> ConformanceGap:
    return ConformanceGap(code, stage, detail)


def _evidence_gaps(
    plan: ConformancePlan,
    request: StageRequest,
    evidence: StageEvidence,
    cumulative_budget: Budget,
) -> list[ConformanceGap]:
    stage = request.stage
    gaps: list[ConformanceGap] = []
    if evidence.stage is not stage or evidence.ordinal != request.ordinal:
        gaps.append(_gap("reordered_stage", stage, "Stage evidence is out of order."))
    if evidence.plan_id != plan.plan_id or evidence.plan_sha256 != plan.plan_sha256:
        gaps.append(_gap("rebound_plan", stage, "Stage evidence is bound to another plan."))
    if evidence.binding != plan.binding or evidence.binding_sha256 != plan.binding.binding_sha256:
        gaps.append(_gap("rebound_context", stage, "Stage evidence changed execution binding."))
    if evidence.fence != plan.fence or evidence.fence_sha256 != plan.fence.fence_sha256:
        gaps.append(_gap("stale_fence", stage, "Stage evidence changed the active fence."))
    if evidence.idempotency_key != request.idempotency_key:
        gaps.append(_gap("idempotency_mismatch", stage, "Stage idempotency key is invalid."))
    if (
        evidence.version_before != request.expected_version
        or evidence.version_after
        != request.expected_version + (1 if evidence.status is StageStatus.PASSED else 0)
    ):
        gaps.append(_gap("stale_version", stage, "Stage version continuity is invalid."))
    if evidence.prior_stage_sha256 != request.prior_stage_sha256:
        gaps.append(_gap("broken_stage_chain", stage, "Prior stage evidence link is invalid."))
    if evidence.prior_custody_sha256 != request.prior_custody_sha256:
        gaps.append(_gap("broken_custody_chain", stage, "Prior custody link is invalid."))
    if dict(evidence.control_links) != dict(request.required_control_links):
        gaps.append(_gap("control_link_mismatch", stage, "Required control links are invalid."))
    if evidence.budget_used.exceeds(request.remaining_budget) or cumulative_budget.plus(
        evidence.budget_used
    ).exceeds(plan.budget_ceiling):
        gaps.append(_gap("budget_exceeded", stage, "Stage use exceeds the bound budget."))
    if evidence.completed_at < plan.created_at:
        gaps.append(_gap("stale_observation", stage, "Stage evidence predates the plan."))
    definition = STAGE_BY_NAME[stage]
    if definition.requires_independent_review:
        if evidence.review is None:
            gaps.append(_gap("unreviewed_stage", stage, "Independent review is required."))
        elif evidence.review.reviewer_ref in {
            plan.binding.operator_ref.replace("operatorref:", "reviewerref:", 1),
            evidence.adapter_ref.replace("adapterref:", "reviewerref:", 1),
        }:
            gaps.append(_gap("nonindependent_review", stage, "Reviewer must be independent."))
        elif evidence.review.decision is not ReviewDecision.ACCEPTED:
            gaps.append(_gap("review_rejected", stage, "Independent review rejected the stage."))
        elif evidence.review.reviewed_at < evidence.completed_at:
            gaps.append(_gap("stale_review", stage, "Independent review predates the stage."))
    if evidence.status is StageStatus.FAILED:
        gaps.append(_gap("failed_stage", stage, "Stage adapter reported failure."))
    elif evidence.status is StageStatus.SKIPPED:
        gaps.append(_gap("skipped_stage", stage, "Required stage was skipped."))
    return gaps


def _assess(
    plan: ConformancePlan,
    raw_evidence: Sequence[StageEvidence | Mapping[str, Any]],
    *,
    completed_at: str,
    seed_gaps: Sequence[ConformanceGap] = (),
) -> ConformanceResult:
    _timestamp(completed_at, "completed_at")
    gaps = list(seed_gaps)
    parsed: list[StageEvidence] = []
    for index, raw in enumerate(raw_evidence):
        fallback_stage = STAGE_DEFINITIONS[min(index, len(STAGE_DEFINITIONS) - 1)].stage
        try:
            item = (
                StageEvidence.from_dict(raw.to_dict())
                if isinstance(raw, StageEvidence)
                else StageEvidence.from_dict(raw)
            )
        except (EndToEndConformanceError, KeyError, TypeError, ValueError):
            gaps.append(
                _gap("tampered_stage", fallback_stage, "Stage evidence failed integrity checks.")
            )
            continue
        parsed.append(item)

    seen: set[ConformanceStage] = set()
    for item in parsed:
        if item.stage in seen:
            gaps.append(_gap("duplicate_stage", item.stage, "Stage evidence is duplicated."))
        seen.add(item.stage)

    current_version = plan.start_version
    prior_stage_sha256: str | None = None
    prior_custody_sha256: str | None = None
    total_budget = Budget(0, 0, 0, 0)
    evidence_by_stage: dict[ConformanceStage, StageEvidence] = {}
    completed: list[ConformanceStage] = []
    for index, definition in enumerate(STAGE_DEFINITIONS):
        if index >= len(parsed):
            gaps.append(
                _gap("missing_stage", definition.stage, "Required stage evidence is missing.")
            )
            continue
        item = parsed[index]
        request = _request_for(
            plan,
            definition,
            current_version=current_version,
            prior_stage_sha256=prior_stage_sha256,
            prior_custody_sha256=prior_custody_sha256,
            budget_used=total_budget,
            evidence_by_stage=evidence_by_stage,
        )
        local_gaps = _evidence_gaps(plan, request, item, total_budget)
        gaps.extend(local_gaps)
        total_budget = total_budget.plus(item.budget_used)
        if not local_gaps and item.status is StageStatus.PASSED:
            completed.append(definition.stage)
            current_version = item.version_after
            prior_stage_sha256 = item.evidence_sha256
            prior_custody_sha256 = item.custody_sha256
            evidence_by_stage[definition.stage] = item

    if len(parsed) > len(STAGE_DEFINITIONS):
        extras = parsed[len(STAGE_DEFINITIONS) :]
        for item in extras:
            gaps.append(
                _gap("unexpected_stage", item.stage, "Unexpected extra evidence is present.")
            )

    report = GapReport.create(
        plan,
        observed_stage_count=len(parsed),
        completed_stages=completed,
        gaps=gaps,
        generated_at=completed_at,
    )
    status = ReceiptStatus.CONFORMANT if not report.gaps else ReceiptStatus.NONCONFORMANT
    receipt = ConformanceReceipt.create(
        plan,
        status=status,
        evidence_sha256s=list(dict.fromkeys(item.evidence_sha256 for item in parsed)),
        gap_report=report,
        total_budget_used=total_budget,
        final_version=current_version,
        final_custody_sha256=prior_custody_sha256,
        completed_at=completed_at,
    )
    return ConformanceResult(receipt, report, tuple(parsed))


def assess_conformance(
    plan: ConformancePlan,
    evidence: Sequence[StageEvidence | Mapping[str, Any]],
    *,
    completed_at: str,
) -> ConformanceResult:
    """Assess already collected evidence without invoking any adapter."""

    return _assess(plan, evidence, completed_at=completed_at)


def run_conformance(
    plan: ConformancePlan,
    adapters: Mapping[ConformanceStage | str, StepAdapter],
    *,
    completed_at: str,
) -> ConformanceResult:
    """Collect ordered observations from injected adapters and assess them."""

    normalized = {ConformanceStage(key): value for key, value in adapters.items()}
    raw: list[StageEvidence | Mapping[str, Any]] = []
    seed_gaps: list[ConformanceGap] = []
    current_version = plan.start_version
    prior_stage_sha256: str | None = None
    prior_custody_sha256: str | None = None
    budget_used = Budget(0, 0, 0, 0)
    evidence_by_stage: dict[ConformanceStage, StageEvidence] = {}
    for definition in STAGE_DEFINITIONS:
        adapter = normalized.get(definition.stage)
        if adapter is None:
            seed_gaps.append(
                _gap(
                    "missing_stage_adapter",
                    definition.stage,
                    "No injected adapter was provided for the required stage.",
                )
            )
            break
        request = _request_for(
            plan,
            definition,
            current_version=current_version,
            prior_stage_sha256=prior_stage_sha256,
            prior_custody_sha256=prior_custody_sha256,
            budget_used=budget_used,
            evidence_by_stage=evidence_by_stage,
        )
        try:
            observed = adapter.observe_stage(request)
        except Exception:  # noqa: BLE001 - adapter boundary is intentionally fail closed
            seed_gaps.append(
                _gap("adapter_failure", definition.stage, "Injected adapter raised an error.")
            )
            break
        if isinstance(observed, StageEvidence):
            item = observed
            raw.append(observed)
        elif isinstance(observed, Mapping):
            raw.append(observed)
            try:
                item = StageEvidence.from_dict(observed)
            except (EndToEndConformanceError, KeyError, TypeError, ValueError):
                seed_gaps.append(
                    _gap(
                        "stage_evidence_rejected",
                        definition.stage,
                        "Injected stage evidence failed integrity checks.",
                    )
                )
                break
        else:
            seed_gaps.append(
                _gap(
                    "invalid_adapter_result",
                    definition.stage,
                    "Injected adapter returned an unsupported result.",
                )
            )
            break
        local_gaps = _evidence_gaps(plan, request, item, budget_used)
        if local_gaps:
            seed_gaps.extend(local_gaps)
            break
        if item.status is not StageStatus.PASSED:
            break
        current_version = item.version_after
        prior_stage_sha256 = item.evidence_sha256
        prior_custody_sha256 = item.custody_sha256
        budget_used = budget_used.plus(item.budget_used)
        evidence_by_stage[item.stage] = item
    return _assess(
        plan,
        raw,
        completed_at=completed_at,
        seed_gaps=seed_gaps,
    )


def parse_record(
    raw: Mapping[str, Any],
) -> ConformancePlan | StageEvidence | GapReport | ConformanceReceipt:
    kind = raw.get("kind") if isinstance(raw, Mapping) else None
    parsers = {
        ConformancePlan.KIND: ConformancePlan.from_dict,
        StageEvidence.KIND: StageEvidence.from_dict,
        GapReport.KIND: GapReport.from_dict,
        ConformanceReceipt.KIND: ConformanceReceipt.from_dict,
    }
    parser = parsers.get(kind)
    if parser is None:
        raise EndToEndConformanceError("record kind is unsupported")
    return parser(raw)
