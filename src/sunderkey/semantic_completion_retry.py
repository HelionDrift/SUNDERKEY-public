"""Evidence-bound semantic completion and explicit retry authorization.

This module is repository-only and provider-neutral. It performs no provider,
budget, credential, tool, network, or target operation.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, ClassVar, Protocol, runtime_checkable

from .errors import RegistryError
from .expert_model_execution_custody import (
    ExpertBudgetReservationCommit,
    ExpertBudgetSettlement,
    ExpertExecutionAuthority,
    ExpertInvocationPlan,
    ExpertModelExecutionReceipt,
    ExpertProviderObservation,
    build_invocation_plan,
)
from .expert_runtime import (
    ExecutionEnvelope,
    RuntimePackCatalog,
    WorkProduct,
    parse_execution_envelope,
    parse_work_product,
)
from .multi_model_routing import (
    BudgetEnvelope,
    ModelCapabilityDeclaration,
    RoutingDecision,
    canonical_json,
    canonical_sha256,
)
from .validation import DuplicateJsonKeyError, loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 524_288
MAX_ITEMS = 128
MAX_ATTEMPTS = 10
ASCII_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
UTC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

COMPLETION_STATES = (
    "abstained",
    "blocked",
    "completed",
    "failed",
    "incomplete",
    "indeterminate",
    "malformed",
    "partial",
    "pending_independent_review",
)
FAILURE_CLASSES = (
    "dependency_blocked",
    "expert_abstained",
    "incomplete_output",
    "independent_review_pending",
    "independent_review_rejected",
    "indeterminate",
    "invalid_output",
    "missing_evidence",
    "none",
    "operator_input_required",
    "transient_provider",
)
RETRYABLE_FAILURE_CLASSES = frozenset(
    {
        "dependency_blocked",
        "expert_abstained",
        "incomplete_output",
        "invalid_output",
        "missing_evidence",
        "operator_input_required",
        "transient_provider",
    }
)
REASON_CODES = frozenset(
    {
        "all_requirements_satisfied",
        "approval_rejected",
        "dependency_blocked",
        "expert_abstained",
        "expert_reported_blocker",
        "independent_review_pending",
        "independent_review_rejected",
        "operator_input_required",
        "provider_failed",
        "provider_incomplete",
        "provider_outcome_indeterminate",
        "required_conditions_partial",
        "structured_output_malformed",
    }
)
BLOCKER_CODES = frozenset(
    {
        "approval_rejected",
        "approval_unsatisfied",
        "cleanup_unsatisfied",
        "dependency_blocked",
        "dependency_unsatisfied",
        "evidence_unsatisfied",
        "expert_reported_blocker",
        "independent_review_pending",
        "independent_review_rejected",
        "operator_input_required",
        "provider_failed",
        "provider_incomplete",
        "provider_outcome_indeterminate",
        "structured_output_malformed",
    }
)
DISPOSITION_STATES = frozenset(
    {"blocked", "failed", "invalid", "missing", "pending", "rejected", "satisfied", "stale"}
)
REVIEW_STATES = frozenset({"accepted", "not_required", "pending", "rejected"})
CHANGED_CONDITION_CODES = frozenset(
    {
        "approval_changed",
        "context_changed",
        "dependency_changed",
        "evidence_changed",
        "implementation_defect_remediated",
        "operator_input_supplied",
        "provider_health_changed",
        "route_changed",
    }
)
FAILURE_CHANGE_CODES = MappingProxyType(
    {
        "dependency_blocked": frozenset({"dependency_changed"}),
        "expert_abstained": frozenset(
            {"context_changed", "evidence_changed", "operator_input_supplied", "route_changed"}
        ),
        "incomplete_output": frozenset(
            {
                "context_changed",
                "implementation_defect_remediated",
                "provider_health_changed",
                "route_changed",
            }
        ),
        "invalid_output": frozenset(
            {"implementation_defect_remediated", "provider_health_changed", "route_changed"}
        ),
        "missing_evidence": frozenset(
            {
                "approval_changed",
                "dependency_changed",
                "evidence_changed",
                "operator_input_supplied",
            }
        ),
        "operator_input_required": frozenset(
            {"approval_changed", "context_changed", "evidence_changed", "operator_input_supplied"}
        ),
        "transient_provider": frozenset({"provider_health_changed", "route_changed"}),
    }
)
NO_EFFECTS = MappingProxyType(
    {
        "action": "none",
        "authorization": "none",
        "budget_mutation": "none",
        "finding": "none",
        "independent_review": "none",
        "provider_call": "none",
        "qualification": "none",
        "retry_execution": "none",
        "target": "none",
        "tools": "none",
    }
)


class SemanticCompletionRetryError(ValueError):
    """A semantic completion or retry boundary was invalid."""


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ASCII_ID.fullmatch(value) is None:
        raise SemanticCompletionRetryError(f"{label} must be a safe identifier")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise SemanticCompletionRetryError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_TIME.fullmatch(value) is None:
        raise SemanticCompletionRetryError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SemanticCompletionRetryError(f"{label} must be a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _natural(value: Any, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SemanticCompletionRetryError(f"{label} must be at least {minimum}")
    return value


def _tuple(value: Any, label: str, *, allow_empty: bool = True) -> tuple[Any, ...]:
    if not isinstance(value, tuple) or (not allow_empty and not value) or len(value) > MAX_ITEMS:
        raise SemanticCompletionRetryError(f"{label} must be a bounded immutable tuple")
    return value


def _unique_identifiers(value: Any, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    items = _tuple(value, label, allow_empty=allow_empty)
    parsed = tuple(_identifier(item, f"{label} item") for item in items)
    if len(parsed) != len(set(parsed)):
        raise SemanticCompletionRetryError(f"{label} contains duplicates")
    return parsed


def _unique_digests(value: Any, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    items = _tuple(value, label, allow_empty=allow_empty)
    parsed = tuple(_digest(item, f"{label} item") for item in items)
    if len(parsed) != len(set(parsed)):
        raise SemanticCompletionRetryError(f"{label} contains duplicates")
    return parsed


def _exact(raw: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise SemanticCompletionRetryError(f"{label} fields are invalid")
    return dict(raw)


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _record_json(raw: str, label: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
        raise SemanticCompletionRetryError(f"{label} JSON exceeds the byte ceiling")
    try:
        value = loads_json_without_duplicate_keys(raw)
    except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
        raise SemanticCompletionRetryError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise SemanticCompletionRetryError(f"{label} JSON must be a canonical object")
    return value


def _validate_record(
    raw: Any,
    *,
    kind: str,
    prefix: str,
    id_field: str,
    sha_field: str,
    body_fields: set[str],
) -> dict[str, Any]:
    fields = {"schema_version", "kind", id_field, sha_field} | body_fields
    value = _exact(raw, fields, kind)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
        or value["kind"] != kind
    ):
        raise SemanticCompletionRetryError(f"{kind} type is invalid")
    body = {name: value[name] for name in body_fields}
    record_id, digest = _identity(prefix, kind, body)
    if value[id_field] != record_id or value[sha_field] != digest:
        raise SemanticCompletionRetryError(f"{kind} content address mismatch")
    return value


def _effects(value: Any) -> None:
    if not isinstance(value, Mapping) or dict(value) != dict(NO_EFFECTS):
        raise SemanticCompletionRetryError("record effects are invalid")


@dataclass(frozen=True, slots=True)
class RequirementDisposition:
    requirement_id: str
    state: str
    proof_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.requirement_id, "requirement_id")
        if self.state not in DISPOSITION_STATES:
            raise SemanticCompletionRetryError("requirement disposition state is invalid")
        proofs = _unique_digests(
            self.proof_sha256s,
            "requirement disposition proofs",
            allow_empty=self.state not in {"satisfied", "rejected", "failed"},
        )
        if proofs != tuple(sorted(proofs)):
            raise SemanticCompletionRetryError("requirement disposition proofs are not sorted")

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "state": self.state,
            "proof_sha256s": list(self.proof_sha256s),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RequirementDisposition:
        value = _exact(
            raw,
            {"requirement_id", "state", "proof_sha256s"},
            "requirement disposition",
        )
        if not isinstance(value["proof_sha256s"], list):
            raise SemanticCompletionRetryError("requirement disposition proofs must be a list")
        return cls(
            requirement_id=value["requirement_id"],
            state=value["state"],
            proof_sha256s=tuple(value["proof_sha256s"]),
        )


def _dispositions(value: Any, label: str) -> tuple[RequirementDisposition, ...]:
    items = _tuple(value, label)
    if any(type(item) is not RequirementDisposition for item in items):
        raise SemanticCompletionRetryError(f"{label} contains mutable or invalid state")
    identifiers = tuple(item.requirement_id for item in items)
    if identifiers != tuple(sorted(identifiers)) or len(identifiers) != len(set(identifiers)):
        raise SemanticCompletionRetryError(f"{label} identifiers must be sorted and unique")
    return items


@dataclass(frozen=True, slots=True)
class SemanticCompletionRequirements:
    mission_id: str
    plan_id: str
    work_id: str
    target_scope_sha256: str
    authority_snapshot_sha256: str
    evidence_snapshot_sha256: str
    runtime_catalog_sha256: str
    runtime_pack_sha256: str
    execution_envelope_sha256: str
    dependency_ids: tuple[str, ...]
    evidence_requirement_ids: tuple[str, ...]
    cleanup_requirement_ids: tuple[str, ...]
    approval_requirement_ids: tuple[str, ...]
    independent_review_required: bool
    requirements_source_sha256: str
    requirements_id: str = field(init=False)
    requirements_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.semantic-completion-requirements.v1"

    def __post_init__(self) -> None:
        for name in ("mission_id", "plan_id", "work_id"):
            _identifier(getattr(self, name), name)
        for name in (
            "target_scope_sha256",
            "authority_snapshot_sha256",
            "evidence_snapshot_sha256",
            "runtime_catalog_sha256",
            "runtime_pack_sha256",
            "execution_envelope_sha256",
            "requirements_source_sha256",
        ):
            _digest(getattr(self, name), name)
        for name in (
            "dependency_ids",
            "evidence_requirement_ids",
            "cleanup_requirement_ids",
            "approval_requirement_ids",
        ):
            items = _unique_identifiers(getattr(self, name), name)
            if items != tuple(sorted(items)):
                raise SemanticCompletionRetryError(f"{name} must be sorted")
        if not isinstance(self.independent_review_required, bool):
            raise SemanticCompletionRetryError("independent_review_required must be boolean")
        record_id, digest = _identity("SCR", self.KIND, self._body())
        object.__setattr__(self, "requirements_id", record_id)
        object.__setattr__(self, "requirements_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "approval_requirement_ids": list(self.approval_requirement_ids),
            "authority_snapshot_sha256": self.authority_snapshot_sha256,
            "cleanup_requirement_ids": list(self.cleanup_requirement_ids),
            "dependency_ids": list(self.dependency_ids),
            "evidence_requirement_ids": list(self.evidence_requirement_ids),
            "evidence_snapshot_sha256": self.evidence_snapshot_sha256,
            "execution_envelope_sha256": self.execution_envelope_sha256,
            "independent_review_required": self.independent_review_required,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "requirements_source_sha256": self.requirements_source_sha256,
            "runtime_catalog_sha256": self.runtime_catalog_sha256,
            "runtime_pack_sha256": self.runtime_pack_sha256,
            "target_scope_sha256": self.target_scope_sha256,
            "work_id": self.work_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "requirements_id": self.requirements_id,
            "requirements_sha256": self.requirements_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SemanticCompletionRequirements:
        computed = {"requirements_id", "requirements_sha256"}
        body_fields = set(cls.__dataclass_fields__) - computed - {"KIND"}
        value = _validate_record(
            raw,
            kind=cls.KIND,
            prefix="SCR",
            id_field="requirements_id",
            sha_field="requirements_sha256",
            body_fields=body_fields,
        )
        values = {name: value[name] for name in body_fields}
        for name in (
            "dependency_ids",
            "evidence_requirement_ids",
            "cleanup_requirement_ids",
            "approval_requirement_ids",
        ):
            if not isinstance(values[name], list):
                raise SemanticCompletionRetryError(f"{name} must be a list")
            values[name] = tuple(values[name])
        return cls(**values)

    @classmethod
    def from_json(cls, raw: str) -> SemanticCompletionRequirements:
        return cls.from_dict(_record_json(raw, "semantic completion requirements"))


@dataclass(frozen=True, slots=True)
class SemanticCompletionEvidence:
    requirements_id: str
    requirements_sha256: str
    execution_receipt_id: str
    execution_receipt_sha256: str
    work_product_id: str | None
    work_product_sha256: str | None
    lineage_product_ids: tuple[str, ...]
    dependency_dispositions: tuple[RequirementDisposition, ...]
    evidence_dispositions: tuple[RequirementDisposition, ...]
    cleanup_dispositions: tuple[RequirementDisposition, ...]
    approval_dispositions: tuple[RequirementDisposition, ...]
    independent_review_state: str
    independent_review_record_sha256: str | None
    verifier_principal_id: str
    verifier_assertion_sha256: str
    authentication_verification_sha256: str
    verification_sha256: str
    verified_at: str
    expires_at: str
    evidence_id: str = field(init=False)
    evidence_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.semantic-completion-evidence.v1"

    def __post_init__(self) -> None:
        for name in ("requirements_id", "execution_receipt_id", "verifier_principal_id"):
            _identifier(getattr(self, name), name)
        for name in (
            "requirements_sha256",
            "execution_receipt_sha256",
            "verifier_assertion_sha256",
            "authentication_verification_sha256",
            "verification_sha256",
        ):
            _digest(getattr(self, name), name)
        if (self.work_product_id is None) != (self.work_product_sha256 is None):
            raise SemanticCompletionRetryError("work-product identity is incomplete")
        if self.work_product_id is not None:
            _identifier(self.work_product_id, "work_product_id")
            _digest(self.work_product_sha256, "work_product_sha256")
        lineage = _unique_identifiers(self.lineage_product_ids, "lineage_product_ids")
        if lineage != tuple(sorted(lineage)):
            raise SemanticCompletionRetryError("lineage_product_ids must be sorted")
        for name in (
            "dependency_dispositions",
            "evidence_dispositions",
            "cleanup_dispositions",
            "approval_dispositions",
        ):
            _dispositions(getattr(self, name), name)
        if self.independent_review_state not in REVIEW_STATES:
            raise SemanticCompletionRetryError("independent review state is invalid")
        if (self.independent_review_state in {"accepted", "rejected"}) != (
            self.independent_review_record_sha256 is not None
        ):
            raise SemanticCompletionRetryError("independent review evidence is inconsistent")
        if self.independent_review_record_sha256 is not None:
            _digest(self.independent_review_record_sha256, "independent_review_record_sha256")
        _timestamp(self.verified_at, "verified_at")
        _timestamp(self.expires_at, "expires_at")
        if _instant(self.verified_at) >= _instant(self.expires_at):
            raise SemanticCompletionRetryError("semantic evidence validity window is invalid")
        record_id, digest = _identity("SCE", self.KIND, self._body())
        object.__setattr__(self, "evidence_id", record_id)
        object.__setattr__(self, "evidence_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "approval_dispositions": [item.to_dict() for item in self.approval_dispositions],
            "cleanup_dispositions": [item.to_dict() for item in self.cleanup_dispositions],
            "dependency_dispositions": [item.to_dict() for item in self.dependency_dispositions],
            "evidence_dispositions": [item.to_dict() for item in self.evidence_dispositions],
            "execution_receipt_id": self.execution_receipt_id,
            "execution_receipt_sha256": self.execution_receipt_sha256,
            "expires_at": self.expires_at,
            "independent_review_record_sha256": self.independent_review_record_sha256,
            "independent_review_state": self.independent_review_state,
            "lineage_product_ids": list(self.lineage_product_ids),
            "requirements_id": self.requirements_id,
            "requirements_sha256": self.requirements_sha256,
            "verification_sha256": self.verification_sha256,
            "verifier_assertion_sha256": self.verifier_assertion_sha256,
            "authentication_verification_sha256": self.authentication_verification_sha256,
            "verified_at": self.verified_at,
            "verifier_principal_id": self.verifier_principal_id,
            "work_product_id": self.work_product_id,
            "work_product_sha256": self.work_product_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SemanticCompletionEvidence:
        computed = {"evidence_id", "evidence_sha256"}
        body_fields = set(cls.__dataclass_fields__) - computed - {"KIND"}
        value = _validate_record(
            raw,
            kind=cls.KIND,
            prefix="SCE",
            id_field="evidence_id",
            sha_field="evidence_sha256",
            body_fields=body_fields,
        )
        values = {name: value[name] for name in body_fields}
        for name in ("lineage_product_ids",):
            if not isinstance(values[name], list):
                raise SemanticCompletionRetryError(f"{name} must be a list")
            values[name] = tuple(values[name])
        for name in (
            "dependency_dispositions",
            "evidence_dispositions",
            "cleanup_dispositions",
            "approval_dispositions",
        ):
            if not isinstance(values[name], list):
                raise SemanticCompletionRetryError(f"{name} must be a list")
            values[name] = tuple(RequirementDisposition.from_dict(item) for item in values[name])
        return cls(**values)

    @classmethod
    def from_json(cls, raw: str) -> SemanticCompletionEvidence:
        return cls.from_dict(_record_json(raw, "semantic completion evidence"))


@dataclass(frozen=True, slots=True)
class SemanticCompletionAssessment:
    requirements_id: str
    requirements_sha256: str
    semantic_evidence_id: str
    semantic_evidence_sha256: str
    mission_id: str
    plan_id: str
    work_id: str
    target_scope_sha256: str
    authority_snapshot_sha256: str
    evidence_snapshot_sha256: str
    runtime_catalog_sha256: str
    runtime_pack_sha256: str
    execution_envelope_sha256: str
    routing_decision_sha256: str
    execution_authority_sha256: str
    invocation_plan_sha256: str
    reservation_commit_sha256: str
    provider_observation_sha256: str | None
    settlement_sha256: str
    execution_receipt_id: str
    execution_receipt_sha256: str
    work_product_id: str | None
    work_product_sha256: str | None
    lineage_product_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...]
    evidence_requirement_ids: tuple[str, ...]
    cleanup_requirement_ids: tuple[str, ...]
    approval_requirement_ids: tuple[str, ...]
    independent_review_required: bool
    independent_review_state: str
    completion_state: str
    failure_class: str
    reason_codes: tuple[str, ...]
    blocker_codes: tuple[str, ...]
    retry_eligible: bool
    assessed_at: str
    assessment_id: str = field(init=False)
    assessment_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.semantic-completion-assessment.v1"

    def __post_init__(self) -> None:
        for name in (
            "requirements_id",
            "semantic_evidence_id",
            "mission_id",
            "plan_id",
            "work_id",
            "execution_receipt_id",
        ):
            _identifier(getattr(self, name), name)
        for name in (
            "requirements_sha256",
            "semantic_evidence_sha256",
            "target_scope_sha256",
            "authority_snapshot_sha256",
            "evidence_snapshot_sha256",
            "runtime_catalog_sha256",
            "runtime_pack_sha256",
            "execution_envelope_sha256",
            "routing_decision_sha256",
            "execution_authority_sha256",
            "invocation_plan_sha256",
            "reservation_commit_sha256",
            "settlement_sha256",
            "execution_receipt_sha256",
        ):
            _digest(getattr(self, name), name)
        if self.provider_observation_sha256 is not None:
            _digest(self.provider_observation_sha256, "provider_observation_sha256")
        if (self.work_product_id is None) != (self.work_product_sha256 is None):
            raise SemanticCompletionRetryError("assessment work-product identity is incomplete")
        if self.work_product_id is not None:
            _identifier(self.work_product_id, "work_product_id")
            _digest(self.work_product_sha256, "work_product_sha256")
        for name in (
            "lineage_product_ids",
            "dependency_ids",
            "evidence_requirement_ids",
            "cleanup_requirement_ids",
            "approval_requirement_ids",
        ):
            items = _unique_identifiers(getattr(self, name), name)
            if items != tuple(sorted(items)):
                raise SemanticCompletionRetryError(f"{name} must be sorted")
        if not isinstance(self.independent_review_required, bool):
            raise SemanticCompletionRetryError("independent_review_required must be boolean")
        if self.independent_review_state not in REVIEW_STATES:
            raise SemanticCompletionRetryError("assessment review state is invalid")
        if self.completion_state not in COMPLETION_STATES:
            raise SemanticCompletionRetryError("completion state is invalid")
        if self.failure_class not in FAILURE_CLASSES:
            raise SemanticCompletionRetryError("failure class is invalid")
        reasons = _unique_identifiers(self.reason_codes, "reason_codes", allow_empty=False)
        blockers = _unique_identifiers(self.blocker_codes, "blocker_codes")
        if reasons != tuple(sorted(reasons)) or blockers != tuple(sorted(blockers)):
            raise SemanticCompletionRetryError("reason and blocker codes must be sorted")
        if not set(reasons).issubset(REASON_CODES) or not set(blockers).issubset(BLOCKER_CODES):
            raise SemanticCompletionRetryError("reason or blocker code is unknown")
        if not isinstance(self.retry_eligible, bool) or self.retry_eligible != (
            self.failure_class in RETRYABLE_FAILURE_CLASSES
        ):
            raise SemanticCompletionRetryError("retry eligibility is inconsistent")
        if self.completion_state == "completed" and self.failure_class != "none":
            raise SemanticCompletionRetryError("completed assessment cannot carry failure")
        if self.completion_state != "completed" and self.failure_class == "none":
            raise SemanticCompletionRetryError("noncompleted assessment requires a failure class")
        _timestamp(self.assessed_at, "assessed_at")
        record_id, digest = _identity("SCA", self.KIND, self._body())
        object.__setattr__(self, "assessment_id", record_id)
        object.__setattr__(self, "assessment_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            name: (
                list(getattr(self, name))
                if name
                in {
                    "approval_requirement_ids",
                    "blocker_codes",
                    "cleanup_requirement_ids",
                    "dependency_ids",
                    "evidence_requirement_ids",
                    "lineage_product_ids",
                    "reason_codes",
                }
                else getattr(self, name)
            )
            for name in self.__dataclass_fields__
            if name not in {"assessment_id", "assessment_sha256", "KIND"}
        } | {"effects": dict(NO_EFFECTS)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SemanticCompletionAssessment:
        body_fields = set(cls.__dataclass_fields__) - {"assessment_id", "assessment_sha256", "KIND"}
        value = _validate_record(
            raw,
            kind=cls.KIND,
            prefix="SCA",
            id_field="assessment_id",
            sha_field="assessment_sha256",
            body_fields=body_fields | {"effects"},
        )
        _effects(value["effects"])
        values = {name: value[name] for name in body_fields}
        for name in (
            "lineage_product_ids",
            "dependency_ids",
            "evidence_requirement_ids",
            "cleanup_requirement_ids",
            "approval_requirement_ids",
            "reason_codes",
            "blocker_codes",
        ):
            if not isinstance(values[name], list):
                raise SemanticCompletionRetryError(f"{name} must be a list")
            values[name] = tuple(values[name])
        return cls(**values)

    @classmethod
    def from_json(cls, raw: str) -> SemanticCompletionAssessment:
        return cls.from_dict(_record_json(raw, "semantic completion assessment"))


def _disposition_map(
    values: tuple[RequirementDisposition, ...], expected: tuple[str, ...], label: str
) -> dict[str, RequirementDisposition]:
    actual = tuple(item.requirement_id for item in values)
    if actual != expected:
        raise SemanticCompletionRetryError(f"{label} requirement coverage is not exact")
    return {item.requirement_id: item for item in values}


@dataclass(frozen=True, slots=True)
class _ValidatedExecutionChain:
    runtime_pack: dict[str, Any]
    envelope: ExecutionEnvelope
    decision: RoutingDecision
    authority: ExpertExecutionAuthority
    invocation_plan: ExpertInvocationPlan
    reservation_commit: ExpertBudgetReservationCommit
    observation: ExpertProviderObservation | None
    settlement: ExpertBudgetSettlement
    receipt: ExpertModelExecutionReceipt
    work_product: WorkProduct | None


def _execution_chain(
    runtime_catalog: RuntimePackCatalog,
    runtime_pack: Mapping[str, Any],
    envelope: ExecutionEnvelope,
    decision: RoutingDecision,
    authority: ExpertExecutionAuthority,
    invocation_plan: ExpertInvocationPlan,
    reservation_commit: ExpertBudgetReservationCommit,
    observation: ExpertProviderObservation | None,
    settlement: ExpertBudgetSettlement,
    receipt: ExpertModelExecutionReceipt,
    work_product: WorkProduct | None,
) -> _ValidatedExecutionChain:
    if type(runtime_catalog) is not RuntimePackCatalog:
        raise SemanticCompletionRetryError("runtime catalog is not validated")
    exact_types = (
        (envelope, ExecutionEnvelope),
        (decision, RoutingDecision),
        (authority, ExpertExecutionAuthority),
        (invocation_plan, ExpertInvocationPlan),
        (reservation_commit, ExpertBudgetReservationCommit),
        (settlement, ExpertBudgetSettlement),
        (receipt, ExpertModelExecutionReceipt),
    )
    if any(type(value) is not expected for value, expected in exact_types):
        raise SemanticCompletionRetryError("execution chain contains an untyped record")
    if observation is not None and type(observation) is not ExpertProviderObservation:
        raise SemanticCompletionRetryError("execution chain contains an untyped observation")
    if work_product is not None and type(work_product) is not WorkProduct:
        raise SemanticCompletionRetryError("execution chain contains an untyped work product")
    exact_pack = runtime_catalog.pack_for_profile_id(envelope.profile_id)
    if exact_pack is None or dict(runtime_pack) != exact_pack:
        raise SemanticCompletionRetryError("runtime pack or catalog substitution detected")
    try:
        envelope = parse_execution_envelope(envelope.to_dict(), exact_pack, runtime_catalog)
        decision = RoutingDecision.from_dict(decision.to_dict())
        authority = ExpertExecutionAuthority.from_dict(authority.to_dict())
        invocation_plan = ExpertInvocationPlan.from_dict(invocation_plan.to_dict())
        reservation_commit = ExpertBudgetReservationCommit.from_dict(reservation_commit.to_dict())
        observation = (
            ExpertProviderObservation.from_dict(observation.to_dict())
            if observation is not None
            else None
        )
        settlement = ExpertBudgetSettlement.from_dict(settlement.to_dict())
        receipt = ExpertModelExecutionReceipt.from_dict(receipt.to_dict())
        work_product = (
            parse_work_product(work_product.to_dict(), exact_pack, envelope, runtime_catalog)
            if work_product is not None
            else None
        )
    except (RegistryError, ValueError) as exc:
        raise SemanticCompletionRetryError("execution chain validation failed") from exc
    selection = decision.selection
    reservation = decision.budget_reservation
    if decision.status != "selected" or selection is None or reservation is None:
        raise SemanticCompletionRetryError("execution chain route is not selected")
    expected = (
        authority.runtime_catalog_sha256 == runtime_catalog.catalog_sha256,
        authority.runtime_pack_sha256 == exact_pack["runtime_pack_sha256"],
        authority.execution_envelope_sha256 == envelope.envelope_sha256,
        authority.routing_decision_sha256 == decision.decision_sha256,
        authority.capability_sha256 == selection.capability_sha256,
        authority.reservation_sha256 == reservation.reservation_sha256,
        authority.tenant_id == decision.tenant_id,
        authority.assessment_id == decision.assessment_id,
        authority.task_id == decision.task_id,
        authority.mission_id == envelope.mission_id,
        authority.plan_id == envelope.plan_id,
        authority.work_id == envelope.work_id,
        authority.expert_profile_id == envelope.profile_id,
        invocation_plan.authority_id == authority.authority_id,
        invocation_plan.authority_sha256 == authority.authority_sha256,
        invocation_plan.routing_decision_id == decision.decision_id,
        invocation_plan.routing_decision_sha256 == decision.decision_sha256,
        invocation_plan.reservation_id == reservation.reservation_id,
        invocation_plan.reservation_sha256 == reservation.reservation_sha256,
        invocation_plan.capability_sha256 == selection.capability_sha256,
        invocation_plan.provider_id == selection.provider_id,
        invocation_plan.provider_api_version == selection.provider_api_version,
        invocation_plan.model_id == selection.model_id,
        invocation_plan.model_version == selection.model_version,
        invocation_plan.pricing_revision == selection.pricing_revision,
        invocation_plan.runtime_catalog_sha256 == runtime_catalog.catalog_sha256,
        invocation_plan.runtime_pack_id == exact_pack["runtime_pack_id"],
        invocation_plan.runtime_pack_sha256 == exact_pack["runtime_pack_sha256"],
        invocation_plan.execution_envelope_id == envelope.envelope_id,
        invocation_plan.execution_envelope_sha256 == envelope.envelope_sha256,
        invocation_plan.input_token_ceiling == reservation.input_tokens,
        invocation_plan.output_token_ceiling == reservation.output_tokens,
        invocation_plan.cost_ceiling_micros == reservation.estimated_cost_micros,
        reservation.input_tokens <= authority.maximum_input_tokens,
        reservation.output_tokens <= authority.maximum_output_tokens,
        reservation.estimated_cost_micros <= authority.maximum_cost_micros,
        reservation.input_tokens <= envelope.token_budget["input_token_ceiling"],
        reservation.output_tokens <= envelope.token_budget["output_token_ceiling"],
        reservation_commit.authority_id == authority.authority_id,
        reservation_commit.authority_sha256 == authority.authority_sha256,
        reservation_commit.invocation_plan_id == invocation_plan.plan_id,
        reservation_commit.invocation_plan_sha256 == invocation_plan.plan_sha256,
        reservation_commit.routing_decision_sha256 == decision.decision_sha256,
        reservation_commit.proposed_reservation_sha256 == reservation.reservation_sha256,
        reservation_commit.budget_sha256 == decision.budget_sha256,
        reservation_commit.tenant_id == decision.tenant_id,
        reservation_commit.assessment_id == decision.assessment_id,
        reservation_commit.task_id == decision.task_id,
        reservation_commit.capability_sha256 == selection.capability_sha256,
        reservation_commit.reserved_input_tokens == reservation.input_tokens,
        reservation_commit.reserved_output_tokens == reservation.output_tokens,
        reservation_commit.reserved_cost_micros == reservation.estimated_cost_micros,
        settlement.reservation_commit_id == reservation_commit.commit_id,
        settlement.reservation_commit_sha256 == reservation_commit.commit_sha256,
        settlement.budget_revision_before == reservation_commit.budget_revision_after,
        receipt.authority_id == authority.authority_id,
        receipt.authority_sha256 == authority.authority_sha256,
        receipt.invocation_plan_id == invocation_plan.plan_id,
        receipt.invocation_plan_sha256 == invocation_plan.plan_sha256,
        receipt.reservation_commit_id == reservation_commit.commit_id,
        receipt.reservation_commit_sha256 == reservation_commit.commit_sha256,
        receipt.settlement_id == settlement.settlement_id,
        receipt.settlement_sha256 == settlement.settlement_sha256,
        receipt.execution_state == settlement.terminal_state,
    )
    if not all(expected):
        raise SemanticCompletionRetryError("execution chain binding substitution detected")
    expected_observation = (
        (observation.observation_id, observation.observation_sha256)
        if observation is not None
        else (None, None)
    )
    expected_product = (
        (work_product.product_id, work_product.product_sha256)
        if work_product is not None
        else (None, None)
    )
    if (
        (receipt.provider_observation_id, receipt.provider_observation_sha256)
        != expected_observation
        or (settlement.provider_observation_id, settlement.provider_observation_sha256)
        != expected_observation
        or (receipt.work_product_id, receipt.work_product_sha256) != expected_product
    ):
        raise SemanticCompletionRetryError("receipt output binding substitution detected")
    if observation is not None and (
        observation.invocation_plan_id != invocation_plan.plan_id
        or observation.invocation_plan_sha256 != invocation_plan.plan_sha256
        or observation.provider_id != invocation_plan.provider_id
        or observation.provider_api_version != invocation_plan.provider_api_version
        or observation.model_id != invocation_plan.model_id
        or observation.model_version != invocation_plan.model_version
    ):
        raise SemanticCompletionRetryError("provider observation route substitution detected")
    parsed_observation_product: WorkProduct | None = None
    observation_output_invalid = False
    if observation is not None and observation.structured_output_json is not None:
        try:
            parsed_output = loads_json_without_duplicate_keys(observation.structured_output_json)
            if (
                not isinstance(parsed_output, dict)
                or canonical_json(parsed_output) != observation.structured_output_json
            ):
                raise SemanticCompletionRetryError("provider output is not canonical")
            parsed_observation_product = parse_work_product(
                parsed_output, exact_pack, envelope, runtime_catalog
            )
        except (DuplicateJsonKeyError, RegistryError, ValueError):
            observation_output_invalid = True
    if work_product is not None and (
        parsed_observation_product is None
        or parsed_observation_product.product_id != work_product.product_id
        or parsed_observation_product.product_sha256 != work_product.product_sha256
    ):
        raise SemanticCompletionRetryError("work product does not match provider output")
    if receipt.output_status == "malformed_output" and not observation_output_invalid:
        raise SemanticCompletionRetryError("malformed output status contradicts provider output")
    charges = (
        settlement.charged_input_tokens,
        settlement.charged_output_tokens,
        settlement.charged_cost_micros,
    )
    reserved = (
        reservation_commit.reserved_input_tokens,
        reservation_commit.reserved_output_tokens,
        reservation_commit.reserved_cost_micros,
    )
    observed_usage = (
        (
            observation.input_tokens,
            observation.output_tokens,
            observation.billable_cost_micros,
        )
        if observation is not None
        else (None, None, None)
    )
    if any(charge > ceiling for charge, ceiling in zip(charges, reserved, strict=True)):
        raise SemanticCompletionRetryError("settlement exceeds the committed reservation")
    observation_has_trustworthy_usage = (
        observation is not None
        and observation.usage_trustworthy
        and all(item is not None for item in observed_usage)
    )
    if observation_has_trustworthy_usage and any(
        item > ceiling for item, ceiling in zip(observed_usage, reserved, strict=True)
    ):
        raise SemanticCompletionRetryError("trusted provider usage exceeds the reservation")
    if observation_has_trustworthy_usage and not settlement.quarantined:
        usage_consistent = settlement.usage_basis == "trusted_actual" and charges == observed_usage
    else:
        usage_consistent = settlement.usage_basis == "full_reservation" and charges == reserved
    if not usage_consistent:
        raise SemanticCompletionRetryError("settlement usage provenance is inconsistent")
    if not (
        _instant(authority.valid_from)
        <= _instant(reservation_commit.committed_at)
        < _instant(authority.expires_at)
        and _instant(authority.issued_at) <= _instant(reservation_commit.committed_at)
        and _instant(decision.decided_at) <= _instant(reservation_commit.committed_at)
        and (
            _instant(reservation_commit.committed_at) - _instant(decision.decided_at)
        ).total_seconds()
        <= authority.maximum_route_age_seconds
        and _instant(reservation_commit.committed_at) <= _instant(settlement.settled_at)
        and settlement.settled_at == receipt.recorded_at
    ):
        raise SemanticCompletionRetryError("execution chain time ordering is invalid")
    if observation is not None and not (
        _instant(reservation_commit.committed_at)
        <= _instant(observation.started_at)
        <= _instant(observation.completed_at)
        <= _instant(settlement.settled_at)
    ):
        raise SemanticCompletionRetryError("provider observation time ordering is invalid")
    statuses_by_state = {
        "completed_settled": {"parsed_advisory_work_product"},
        "provider_failed_settled": {"no_output"},
        "incomplete_settled": {
            "malformed_output",
            "no_output",
            "referenced_output_not_parsed",
        },
        "indeterminate_quarantined": {"indeterminate"},
    }
    if receipt.output_status not in statuses_by_state[receipt.execution_state]:
        raise SemanticCompletionRetryError("receipt execution and output states are inconsistent")
    if settlement.terminal_state == "incomplete_settled" and observation is not None:
        if observation.structured_output_reference is not None:
            expected_incomplete_status = "referenced_output_not_parsed"
        elif observation.terminal_state == "completed":
            expected_incomplete_status = "malformed_output"
        else:
            expected_incomplete_status = "no_output"
        if receipt.output_status != expected_incomplete_status:
            raise SemanticCompletionRetryError("incomplete output status is inconsistent")
    if settlement.quarantined:
        outcome_consistent = work_product is None
    elif settlement.terminal_state == "completed_settled":
        outcome_consistent = (
            observation is not None
            and observation.terminal_state == "completed"
            and work_product is not None
        )
    elif settlement.terminal_state == "provider_failed_settled":
        outcome_consistent = observation is None or observation.terminal_state == "failed"
    else:
        outcome_consistent = (
            work_product is None
            and observation is not None
            and observation.terminal_state in {"completed", "incomplete"}
        )
    if not outcome_consistent:
        raise SemanticCompletionRetryError("execution outcome chain is inconsistent")
    return _ValidatedExecutionChain(
        runtime_pack=exact_pack,
        envelope=envelope,
        decision=decision,
        authority=authority,
        invocation_plan=invocation_plan,
        reservation_commit=reservation_commit,
        observation=observation,
        settlement=settlement,
        receipt=receipt,
        work_product=work_product,
    )


def _derive_completion(
    receipt: ExpertModelExecutionReceipt,
    product: WorkProduct | None,
    evidence: SemanticCompletionEvidence,
) -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
    if receipt.execution_state == "indeterminate_quarantined":
        return (
            "indeterminate",
            "indeterminate",
            ("provider_outcome_indeterminate",),
            ("provider_outcome_indeterminate",),
        )
    if receipt.execution_state == "provider_failed_settled":
        return "failed", "transient_provider", ("provider_failed",), ("provider_failed",)
    if receipt.output_status == "malformed_output":
        return (
            "malformed",
            "invalid_output",
            ("structured_output_malformed",),
            ("structured_output_malformed",),
        )
    if receipt.execution_state == "incomplete_settled" or product is None:
        return (
            "incomplete",
            "incomplete_output",
            ("provider_incomplete",),
            ("provider_incomplete",),
        )
    if product.product_type == "abstention":
        return "abstained", "expert_abstained", ("expert_abstained",), ()
    if product.product_type == "blocker":
        return (
            "blocked",
            "dependency_blocked",
            ("expert_reported_blocker",),
            ("expert_reported_blocker",),
        )
    if product.product_type == "clarification_question" and product.payload["blocking"] is True:
        return (
            "blocked",
            "operator_input_required",
            ("operator_input_required",),
            ("operator_input_required",),
        )
    disposition_groups = (
        (evidence.dependency_dispositions, "dependency_unsatisfied"),
        (evidence.evidence_dispositions, "evidence_unsatisfied"),
        (evidence.cleanup_dispositions, "cleanup_unsatisfied"),
        (evidence.approval_dispositions, "approval_unsatisfied"),
    )
    blockers: set[str] = set()
    all_dispositions = []
    for dispositions, code in disposition_groups:
        all_dispositions.extend(dispositions)
        if any(item.state != "satisfied" for item in dispositions):
            blockers.add(code)
    if any(item.state in {"blocked", "failed"} for item in evidence.dependency_dispositions):
        blockers.add("dependency_blocked")
        return (
            "blocked",
            "dependency_blocked",
            ("dependency_blocked",),
            tuple(sorted(blockers)),
        )
    if any(item.state in {"rejected", "invalid"} for item in evidence.approval_dispositions):
        blockers.add("approval_rejected")
        return (
            "blocked",
            "operator_input_required",
            ("approval_rejected",),
            tuple(sorted(blockers)),
        )
    if evidence.independent_review_state == "rejected":
        return (
            "blocked",
            "independent_review_rejected",
            ("independent_review_rejected",),
            ("independent_review_rejected",),
        )
    if any(item.state != "satisfied" for item in all_dispositions):
        return (
            "partial",
            "missing_evidence",
            ("required_conditions_partial",),
            tuple(sorted(blockers)),
        )
    if evidence.independent_review_state == "pending":
        return (
            "pending_independent_review",
            "independent_review_pending",
            ("independent_review_pending",),
            ("independent_review_pending",),
        )
    return "completed", "none", ("all_requirements_satisfied",), ()


def assess_semantic_completion(
    runtime_catalog: RuntimePackCatalog,
    runtime_pack: Mapping[str, Any],
    envelope: ExecutionEnvelope,
    decision: RoutingDecision,
    authority: ExpertExecutionAuthority,
    invocation_plan: ExpertInvocationPlan,
    reservation_commit: ExpertBudgetReservationCommit,
    observation: ExpertProviderObservation | None,
    settlement: ExpertBudgetSettlement,
    receipt: ExpertModelExecutionReceipt,
    work_product: WorkProduct | None,
    requirements: SemanticCompletionRequirements,
    evidence: SemanticCompletionEvidence,
    *,
    now: str,
) -> SemanticCompletionAssessment:
    """Assess semantic completion from exact evidence, never model prose."""

    chain = _execution_chain(
        runtime_catalog,
        runtime_pack,
        envelope,
        decision,
        authority,
        invocation_plan,
        reservation_commit,
        observation,
        settlement,
        receipt,
        work_product,
    )
    exact_pack = chain.runtime_pack
    envelope = chain.envelope
    decision = chain.decision
    authority = chain.authority
    invocation_plan = chain.invocation_plan
    reservation_commit = chain.reservation_commit
    observation = chain.observation
    settlement = chain.settlement
    receipt = chain.receipt
    work_product = chain.work_product
    requirements = SemanticCompletionRequirements.from_dict(requirements.to_dict())
    evidence = SemanticCompletionEvidence.from_dict(evidence.to_dict())
    current = _instant(_timestamp(now, "now"))
    if current < _instant(evidence.verified_at) or current >= _instant(evidence.expires_at):
        raise SemanticCompletionRetryError("semantic completion evidence is stale or future-dated")
    if _instant(evidence.verified_at) < _instant(receipt.recorded_at) or current < _instant(
        receipt.recorded_at
    ):
        raise SemanticCompletionRetryError("semantic evidence predates its execution receipt")
    expected_requirements = {
        "mission_id": envelope.mission_id,
        "plan_id": envelope.plan_id,
        "work_id": envelope.work_id,
        "target_scope_sha256": envelope.target_scope_sha256,
        "authority_snapshot_sha256": envelope.authority_snapshot_sha256,
        "evidence_snapshot_sha256": envelope.evidence_snapshot_sha256,
        "runtime_catalog_sha256": runtime_catalog.catalog_sha256,
        "runtime_pack_sha256": exact_pack["runtime_pack_sha256"],
        "execution_envelope_sha256": envelope.envelope_sha256,
        "evidence_requirement_ids": tuple(sorted(envelope.evidence_requirement_ids)),
        "cleanup_requirement_ids": tuple(sorted(envelope.cleanup_requirement_ids)),
        "approval_requirement_ids": tuple(sorted(envelope.approval_requirement_ids)),
    }
    if any(getattr(requirements, name) != value for name, value in expected_requirements.items()):
        raise SemanticCompletionRetryError("semantic requirements cross-context substitution")
    if (
        evidence.requirements_id != requirements.requirements_id
        or evidence.requirements_sha256 != requirements.requirements_sha256
        or evidence.execution_receipt_id != receipt.receipt_id
        or evidence.execution_receipt_sha256 != receipt.receipt_sha256
        or evidence.work_product_id != receipt.work_product_id
        or evidence.work_product_sha256 != receipt.work_product_sha256
    ):
        raise SemanticCompletionRetryError("semantic evidence binding substitution detected")
    product_document = work_product.to_dict() if work_product is not None else None
    lineage = (
        tuple(sorted(product_document["lineage_product_ids"]))
        if product_document is not None
        else ()
    )
    if evidence.lineage_product_ids != lineage:
        raise SemanticCompletionRetryError("work-product lineage substitution detected")
    _disposition_map(evidence.dependency_dispositions, requirements.dependency_ids, "dependency")
    _disposition_map(
        evidence.evidence_dispositions,
        requirements.evidence_requirement_ids,
        "evidence",
    )
    _disposition_map(
        evidence.cleanup_dispositions,
        requirements.cleanup_requirement_ids,
        "cleanup",
    )
    _disposition_map(
        evidence.approval_dispositions,
        requirements.approval_requirement_ids,
        "approval",
    )
    producer = (
        work_product.producer_profile_id
        if work_product is not None
        else authority.expert_profile_id
    )
    if evidence.verifier_principal_id in {
        producer,
        authority.requester_principal_id,
        authority.provider_adapter_principal_id,
        authority.model_principal_id,
    }:
        raise SemanticCompletionRetryError("semantic evidence verifier is not independent")
    product_review_required = bool(
        product_document is not None and product_document["independent_review"]["required"]
    )
    review_required = requirements.independent_review_required or product_review_required
    if review_required and evidence.independent_review_state == "not_required":
        raise SemanticCompletionRetryError("required independent review was omitted")
    if not review_required and evidence.independent_review_state != "not_required":
        raise SemanticCompletionRetryError("independent review state was invented")
    state, failure_class, reasons, blockers = _derive_completion(receipt, work_product, evidence)
    return SemanticCompletionAssessment(
        requirements_id=requirements.requirements_id,
        requirements_sha256=requirements.requirements_sha256,
        semantic_evidence_id=evidence.evidence_id,
        semantic_evidence_sha256=evidence.evidence_sha256,
        mission_id=envelope.mission_id,
        plan_id=envelope.plan_id,
        work_id=envelope.work_id,
        target_scope_sha256=envelope.target_scope_sha256,
        authority_snapshot_sha256=envelope.authority_snapshot_sha256,
        evidence_snapshot_sha256=envelope.evidence_snapshot_sha256,
        runtime_catalog_sha256=runtime_catalog.catalog_sha256,
        runtime_pack_sha256=exact_pack["runtime_pack_sha256"],
        execution_envelope_sha256=envelope.envelope_sha256,
        routing_decision_sha256=decision.decision_sha256,
        execution_authority_sha256=authority.authority_sha256,
        invocation_plan_sha256=invocation_plan.plan_sha256,
        reservation_commit_sha256=reservation_commit.commit_sha256,
        provider_observation_sha256=(
            observation.observation_sha256 if observation is not None else None
        ),
        settlement_sha256=settlement.settlement_sha256,
        execution_receipt_id=receipt.receipt_id,
        execution_receipt_sha256=receipt.receipt_sha256,
        work_product_id=receipt.work_product_id,
        work_product_sha256=receipt.work_product_sha256,
        lineage_product_ids=lineage,
        dependency_ids=requirements.dependency_ids,
        evidence_requirement_ids=requirements.evidence_requirement_ids,
        cleanup_requirement_ids=requirements.cleanup_requirement_ids,
        approval_requirement_ids=requirements.approval_requirement_ids,
        independent_review_required=review_required,
        independent_review_state=evidence.independent_review_state,
        completion_state=state,
        failure_class=failure_class,
        reason_codes=reasons,
        blocker_codes=blockers,
        retry_eligible=failure_class in RETRYABLE_FAILURE_CLASSES,
        assessed_at=now,
    )


@dataclass(frozen=True, slots=True)
class RetryAuthorizationAuthority:
    assessment_id: str
    assessment_sha256: str
    prior_execution_receipt_id: str
    prior_execution_receipt_sha256: str
    prior_failure_class: str
    prior_routing_decision_sha256: str
    prior_execution_authority_sha256: str
    prior_execution_envelope_sha256: str
    previous_retry_receipt_id: str | None
    previous_retry_receipt_sha256: str | None
    new_routing_decision_id: str
    new_routing_decision_sha256: str
    new_execution_authority_id: str
    new_execution_authority_sha256: str
    new_execution_envelope_sha256: str
    runtime_catalog_sha256: str
    runtime_pack_sha256: str
    mission_id: str
    plan_id: str
    work_id: str
    target_scope_sha256: str
    authority_snapshot_sha256: str
    budget_id: str
    budget_sha256: str
    budget_revision: str
    remaining_input_tokens: int
    remaining_output_tokens: int
    remaining_cost_micros: int
    changed_condition_codes: tuple[str, ...]
    changed_condition_evidence_sha256: str
    attempt_number: int
    maximum_attempts: int
    cooldown_until: str
    issued_at: str
    valid_from: str
    expires_at: str
    issuer_principal_id: str
    subject_principal_id: str
    producer_principal_id: str
    requester_principal_id: str
    provider_adapter_principal_id: str
    model_principal_id: str
    issuer_assertion_sha256: str
    authentication_verification_sha256: str
    retry_authority_id: str = field(init=False)
    retry_authority_sha256: str = field(init=False)
    replay_identity_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.retry-authorization-authority.v1"

    def __post_init__(self) -> None:
        for name in (
            "assessment_id",
            "prior_execution_receipt_id",
            "new_routing_decision_id",
            "new_execution_authority_id",
            "mission_id",
            "plan_id",
            "work_id",
            "budget_id",
            "budget_revision",
            "issuer_principal_id",
            "subject_principal_id",
            "producer_principal_id",
            "requester_principal_id",
            "provider_adapter_principal_id",
            "model_principal_id",
        ):
            _identifier(getattr(self, name), name)
        if (self.previous_retry_receipt_id is None) != (self.previous_retry_receipt_sha256 is None):
            raise SemanticCompletionRetryError("previous retry receipt identity is incomplete")
        if self.previous_retry_receipt_id is not None:
            _identifier(self.previous_retry_receipt_id, "previous_retry_receipt_id")
            _digest(self.previous_retry_receipt_sha256, "previous_retry_receipt_sha256")
        for name in (
            "assessment_sha256",
            "prior_execution_receipt_sha256",
            "prior_routing_decision_sha256",
            "prior_execution_authority_sha256",
            "prior_execution_envelope_sha256",
            "new_routing_decision_sha256",
            "new_execution_authority_sha256",
            "new_execution_envelope_sha256",
            "runtime_catalog_sha256",
            "runtime_pack_sha256",
            "target_scope_sha256",
            "authority_snapshot_sha256",
            "budget_sha256",
            "changed_condition_evidence_sha256",
            "issuer_assertion_sha256",
            "authentication_verification_sha256",
        ):
            _digest(getattr(self, name), name)
        if self.prior_failure_class not in RETRYABLE_FAILURE_CLASSES:
            raise SemanticCompletionRetryError("retry authority failure class is not retryable")
        codes = _unique_identifiers(
            self.changed_condition_codes, "changed_condition_codes", allow_empty=False
        )
        if codes != tuple(sorted(codes)) or not set(codes).issubset(CHANGED_CONDITION_CODES):
            raise SemanticCompletionRetryError("changed-condition codes are invalid")
        for name in ("remaining_input_tokens", "remaining_output_tokens", "remaining_cost_micros"):
            _natural(getattr(self, name), name, positive=True)
        _natural(self.attempt_number, "attempt_number", positive=True)
        _natural(self.maximum_attempts, "maximum_attempts", positive=True)
        if (
            self.attempt_number < 2
            or self.attempt_number > self.maximum_attempts
            or self.maximum_attempts > MAX_ATTEMPTS
        ):
            raise SemanticCompletionRetryError("retry attempt ceiling is invalid")
        if (self.attempt_number == 2) != (self.previous_retry_receipt_id is None):
            raise SemanticCompletionRetryError("retry attempt chain is invalid")
        for name in ("cooldown_until", "issued_at", "valid_from", "expires_at"):
            _timestamp(getattr(self, name), name)
        if not (
            _instant(self.valid_from)
            <= _instant(self.issued_at)
            <= _instant(self.cooldown_until)
            < _instant(self.expires_at)
        ):
            raise SemanticCompletionRetryError("retry authority time window is invalid")
        excluded = {
            self.subject_principal_id,
            self.producer_principal_id,
            self.requester_principal_id,
            self.provider_adapter_principal_id,
            self.model_principal_id,
        }
        if self.issuer_principal_id in excluded:
            raise SemanticCompletionRetryError("retry authority issuer is not independent")
        if self.new_routing_decision_sha256 == self.prior_routing_decision_sha256:
            raise SemanticCompletionRetryError("retry requires a new routing decision identity")
        if self.new_execution_authority_sha256 == self.prior_execution_authority_sha256:
            raise SemanticCompletionRetryError("retry requires a new execution authority identity")
        body = self._body(include_replay=False)
        replay = canonical_sha256(
            {
                "assessment_sha256": self.assessment_sha256,
                "attempt_number": self.attempt_number,
                "changed_condition_evidence_sha256": self.changed_condition_evidence_sha256,
                "domain": "sunderkey.retry-replay-identity.v1",
                "new_execution_authority_sha256": self.new_execution_authority_sha256,
                "new_routing_decision_sha256": self.new_routing_decision_sha256,
                "prior_execution_receipt_sha256": self.prior_execution_receipt_sha256,
                "previous_retry_receipt_sha256": self.previous_retry_receipt_sha256,
            }
        )
        object.__setattr__(self, "replay_identity_sha256", replay)
        record_id, digest = _identity("RAA", self.KIND, {**body, "replay_identity_sha256": replay})
        object.__setattr__(self, "retry_authority_id", record_id)
        object.__setattr__(self, "retry_authority_sha256", digest)

    def _body(self, *, include_replay: bool = True) -> dict[str, Any]:
        result = {
            name: (
                list(getattr(self, name))
                if name == "changed_condition_codes"
                else getattr(self, name)
            )
            for name in self.__dataclass_fields__
            if name
            not in {
                "retry_authority_id",
                "retry_authority_sha256",
                "replay_identity_sha256",
                "KIND",
            }
        }
        if include_replay:
            result["replay_identity_sha256"] = self.replay_identity_sha256
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "retry_authority_id": self.retry_authority_id,
            "retry_authority_sha256": self.retry_authority_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetryAuthorizationAuthority:
        computed = {"retry_authority_id", "retry_authority_sha256", "replay_identity_sha256"}
        body_fields = set(cls.__dataclass_fields__) - computed - {"KIND"}
        value = _validate_record(
            raw,
            kind=cls.KIND,
            prefix="RAA",
            id_field="retry_authority_id",
            sha_field="retry_authority_sha256",
            body_fields=body_fields | {"replay_identity_sha256"},
        )
        values = {name: value[name] for name in body_fields}
        if not isinstance(values["changed_condition_codes"], list):
            raise SemanticCompletionRetryError("changed_condition_codes must be a list")
        values["changed_condition_codes"] = tuple(values["changed_condition_codes"])
        instance = cls(**values)
        if instance.replay_identity_sha256 != value["replay_identity_sha256"]:
            raise SemanticCompletionRetryError("retry replay identity mismatch")
        return instance

    @classmethod
    def from_json(cls, raw: str) -> RetryAuthorizationAuthority:
        return cls.from_dict(_record_json(raw, "retry authorization authority"))


@dataclass(frozen=True, slots=True)
class RetryReplayCommit:
    replay_identity_sha256: str
    retry_authority_id: str
    retry_authority_sha256: str
    consumed_at: str
    replay_commit_id: str = field(init=False)
    replay_commit_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.retry-replay-commit.v1"

    def __post_init__(self) -> None:
        _digest(self.replay_identity_sha256, "replay_identity_sha256")
        _identifier(self.retry_authority_id, "retry_authority_id")
        _digest(self.retry_authority_sha256, "retry_authority_sha256")
        _timestamp(self.consumed_at, "consumed_at")
        record_id, digest = _identity("RRC", self.KIND, self._body())
        object.__setattr__(self, "replay_commit_id", record_id)
        object.__setattr__(self, "replay_commit_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "consumed_at": self.consumed_at,
            "replay_identity_sha256": self.replay_identity_sha256,
            "retry_authority_id": self.retry_authority_id,
            "retry_authority_sha256": self.retry_authority_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "replay_commit_id": self.replay_commit_id,
            "replay_commit_sha256": self.replay_commit_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetryReplayCommit:
        body_fields = {
            "replay_identity_sha256",
            "retry_authority_id",
            "retry_authority_sha256",
            "consumed_at",
        }
        value = _validate_record(
            raw,
            kind=cls.KIND,
            prefix="RRC",
            id_field="replay_commit_id",
            sha_field="replay_commit_sha256",
            body_fields=body_fields,
        )
        return cls(**{name: value[name] for name in body_fields})

    @classmethod
    def from_json(cls, raw: str) -> RetryReplayCommit:
        return cls.from_dict(_record_json(raw, "retry replay commit"))


@runtime_checkable
class RetryReplayGuard(Protocol):
    def consume(self, authority: RetryAuthorizationAuthority, now: str) -> RetryReplayCommit:
        """Atomically consume one exact replay identity without other effects."""


class InMemoryRetryReplayGuard:
    """Nonqualifying process-local replay guard for deterministic tests."""

    qualifying = False
    durability = "process_local_test_fixture"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._commits: dict[str, RetryReplayCommit] = {}
        self._last_clock: datetime | None = None

    def consume(self, authority: RetryAuthorizationAuthority, now: str) -> RetryReplayCommit:
        with self._lock:
            current = _instant(_timestamp(now, "now"))
            if self._last_clock is not None and current < self._last_clock:
                raise SemanticCompletionRetryError("retry replay clock rollback detected")
            if authority.replay_identity_sha256 in self._commits:
                raise SemanticCompletionRetryError("retry replay identity was already consumed")
            commit = RetryReplayCommit(
                replay_identity_sha256=authority.replay_identity_sha256,
                retry_authority_id=authority.retry_authority_id,
                retry_authority_sha256=authority.retry_authority_sha256,
                consumed_at=now,
            )
            self._commits[authority.replay_identity_sha256] = commit
            self._last_clock = current
            return commit

    def verifies(self, receipt: RetryAuthorizationReceipt) -> bool:
        with self._lock:
            commit = self._commits.get(receipt.replay_identity_sha256)
            return commit is not None and (
                receipt.replay_commit_id == commit.replay_commit_id
                and receipt.replay_commit_sha256 == commit.replay_commit_sha256
                and receipt.retry_authority_id == commit.retry_authority_id
                and receipt.retry_authority_sha256 == commit.retry_authority_sha256
            )


@dataclass(frozen=True, slots=True)
class RetryAuthorizationReceipt:
    assessment_id: str
    assessment_sha256: str
    prior_execution_receipt_id: str
    prior_execution_receipt_sha256: str
    retry_authority_id: str
    retry_authority_sha256: str
    replay_identity_sha256: str
    replay_commit_id: str
    replay_commit_sha256: str
    new_routing_decision_id: str
    new_routing_decision_sha256: str
    new_execution_authority_id: str
    new_execution_authority_sha256: str
    new_execution_envelope_sha256: str
    budget_sha256: str
    changed_condition_evidence_sha256: str
    attempt_number: int
    maximum_attempts: int
    authorized_at: str
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.retry-authorization-receipt.v1"

    def __post_init__(self) -> None:
        for name in (
            "assessment_id",
            "prior_execution_receipt_id",
            "retry_authority_id",
            "replay_commit_id",
            "new_routing_decision_id",
            "new_execution_authority_id",
        ):
            _identifier(getattr(self, name), name)
        for name in (
            "assessment_sha256",
            "prior_execution_receipt_sha256",
            "retry_authority_sha256",
            "replay_identity_sha256",
            "replay_commit_sha256",
            "new_routing_decision_sha256",
            "new_execution_authority_sha256",
            "new_execution_envelope_sha256",
            "budget_sha256",
            "changed_condition_evidence_sha256",
        ):
            _digest(getattr(self, name), name)
        _natural(self.attempt_number, "attempt_number", positive=True)
        _natural(self.maximum_attempts, "maximum_attempts", positive=True)
        if (
            self.attempt_number < 2
            or self.attempt_number > self.maximum_attempts
            or self.maximum_attempts > MAX_ATTEMPTS
        ):
            raise SemanticCompletionRetryError("retry receipt exceeds the attempt ceiling")
        _timestamp(self.authorized_at, "authorized_at")
        record_id, digest = _identity("RAR", self.KIND, self._body())
        object.__setattr__(self, "receipt_id", record_id)
        object.__setattr__(self, "receipt_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"receipt_id", "receipt_sha256", "KIND"}
        } | {"effects": dict(NO_EFFECTS)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetryAuthorizationReceipt:
        body_fields = set(cls.__dataclass_fields__) - {"receipt_id", "receipt_sha256", "KIND"}
        value = _validate_record(
            raw,
            kind=cls.KIND,
            prefix="RAR",
            id_field="receipt_id",
            sha_field="receipt_sha256",
            body_fields=body_fields | {"effects"},
        )
        _effects(value["effects"])
        return cls(**{name: value[name] for name in body_fields})

    @classmethod
    def from_json(cls, raw: str) -> RetryAuthorizationReceipt:
        return cls.from_dict(_record_json(raw, "retry authorization receipt"))


def _pinned_route(value: str, label: str) -> None:
    lowered = value.casefold()
    aliases = {"auto", "current", "default", "latest", "stable"}
    if any(token in aliases for token in re.split(r"[-._:/@]+", lowered)):
        raise SemanticCompletionRetryError(f"{label} is a moving alias")


def authorize_retry(
    runtime_catalog: RuntimePackCatalog,
    runtime_pack: Mapping[str, Any],
    prior_envelope: ExecutionEnvelope,
    prior_decision: RoutingDecision,
    prior_execution_authority: ExpertExecutionAuthority,
    prior_receipt: ExpertModelExecutionReceipt,
    assessment: SemanticCompletionAssessment,
    new_envelope: ExecutionEnvelope,
    new_decision: RoutingDecision,
    new_capability: ModelCapabilityDeclaration,
    new_execution_authority: ExpertExecutionAuthority,
    budget: BudgetEnvelope,
    retry_authority: RetryAuthorizationAuthority,
    replay_guard: RetryReplayGuard,
    *,
    now: str,
    previous_retry_receipt: RetryAuthorizationReceipt | None = None,
) -> RetryAuthorizationReceipt:
    """Record nonqualifying retry eligibility without any operational effect."""

    exact_types = (
        (runtime_catalog, RuntimePackCatalog),
        (prior_envelope, ExecutionEnvelope),
        (prior_decision, RoutingDecision),
        (prior_execution_authority, ExpertExecutionAuthority),
        (prior_receipt, ExpertModelExecutionReceipt),
        (assessment, SemanticCompletionAssessment),
        (new_envelope, ExecutionEnvelope),
        (new_decision, RoutingDecision),
        (new_capability, ModelCapabilityDeclaration),
        (new_execution_authority, ExpertExecutionAuthority),
        (budget, BudgetEnvelope),
        (retry_authority, RetryAuthorizationAuthority),
    )
    if any(type(value) is not expected for value, expected in exact_types):
        raise SemanticCompletionRetryError("retry inputs must be canonical record types")
    if type(replay_guard) is not InMemoryRetryReplayGuard:
        raise SemanticCompletionRetryError(
            "production retry requires authenticated authority and durable atomic replay custody"
        )
    if (
        previous_retry_receipt is not None
        and type(previous_retry_receipt) is not RetryAuthorizationReceipt
    ):
        raise SemanticCompletionRetryError("previous retry receipt is not canonical")
    assessment = SemanticCompletionAssessment.from_dict(assessment.to_dict())
    prior_receipt = ExpertModelExecutionReceipt.from_dict(prior_receipt.to_dict())
    prior_execution_authority = ExpertExecutionAuthority.from_dict(
        prior_execution_authority.to_dict()
    )
    retry_authority = RetryAuthorizationAuthority.from_dict(retry_authority.to_dict())
    new_execution_authority = ExpertExecutionAuthority.from_dict(new_execution_authority.to_dict())
    new_capability = ModelCapabilityDeclaration(
        **{
            item.name: getattr(new_capability, item.name)
            for item in fields(new_capability)
            if item.init
        }
    )
    budget = BudgetEnvelope(
        **{item.name: getattr(budget, item.name) for item in fields(budget) if item.init}
    )
    previous_retry_receipt = (
        RetryAuthorizationReceipt.from_dict(previous_retry_receipt.to_dict())
        if previous_retry_receipt is not None
        else None
    )
    current = _instant(_timestamp(now, "now"))
    if assessment.completion_state in {"completed", "indeterminate"}:
        raise SemanticCompletionRetryError("completed or indeterminate work cannot be retried")
    if not assessment.retry_eligible or assessment.failure_class not in RETRYABLE_FAILURE_CLASSES:
        raise SemanticCompletionRetryError("semantic completion state is not retryable")
    receipt_compatibility = {
        "indeterminate_quarantined": (
            {"indeterminate"},
            {"indeterminate"},
        ),
        "provider_failed_settled": (
            {"failed"},
            {"transient_provider"},
        ),
        "incomplete_settled": (
            {"incomplete", "malformed"},
            {"incomplete_output", "invalid_output"},
        ),
        "completed_settled": (
            {"abstained", "blocked", "completed", "partial", "pending_independent_review"},
            {
                "dependency_blocked",
                "expert_abstained",
                "independent_review_pending",
                "independent_review_rejected",
                "missing_evidence",
                "none",
                "operator_input_required",
            },
        ),
    }
    compatible_states, compatible_failures = receipt_compatibility[prior_receipt.execution_state]
    if (
        assessment.completion_state not in compatible_states
        or assessment.failure_class not in compatible_failures
        or (
            prior_receipt.output_status == "malformed_output"
            and assessment.completion_state != "malformed"
        )
        or (
            assessment.completion_state == "malformed"
            and prior_receipt.output_status != "malformed_output"
        )
    ):
        raise SemanticCompletionRetryError("semantic assessment contradicts its prior receipt")
    if (
        assessment.execution_receipt_id != prior_receipt.receipt_id
        or assessment.execution_receipt_sha256 != prior_receipt.receipt_sha256
        or assessment.routing_decision_sha256 != prior_decision.decision_sha256
        or assessment.execution_authority_sha256 != prior_execution_authority.authority_sha256
        or assessment.execution_envelope_sha256 != prior_envelope.envelope_sha256
    ):
        raise SemanticCompletionRetryError("prior retry context binding mismatch")
    if not (_instant(retry_authority.valid_from) <= current < _instant(retry_authority.expires_at)):
        raise SemanticCompletionRetryError("retry authority is stale or future-dated")
    if current < _instant(retry_authority.issued_at) or current < _instant(
        retry_authority.cooldown_until
    ):
        raise SemanticCompletionRetryError("retry cooldown or issue time has not elapsed")
    if _instant(retry_authority.issued_at) < max(
        _instant(assessment.assessed_at), _instant(prior_receipt.recorded_at)
    ):
        raise SemanticCompletionRetryError("retry authority predates its assessed execution")
    try:
        exact_pack = runtime_catalog.pack_for_profile_id(prior_envelope.profile_id)
        if exact_pack is None or dict(runtime_pack) != exact_pack:
            raise KeyError
        prior_envelope = parse_execution_envelope(
            prior_envelope.to_dict(), exact_pack, runtime_catalog
        )
        new_envelope = parse_execution_envelope(new_envelope.to_dict(), exact_pack, runtime_catalog)
        prior_decision = RoutingDecision.from_dict(prior_decision.to_dict())
        new_decision = RoutingDecision.from_dict(new_decision.to_dict())
    except (KeyError, RegistryError, ValueError) as exc:
        raise SemanticCompletionRetryError("retry runtime context is invalid") from exc
    if (
        new_envelope.mission_id != prior_envelope.mission_id
        or new_envelope.plan_id != prior_envelope.plan_id
        or new_envelope.work_id != prior_envelope.work_id
        or new_envelope.target_scope_sha256 != prior_envelope.target_scope_sha256
        or new_envelope.authority_snapshot_sha256 != prior_envelope.authority_snapshot_sha256
        or new_envelope.profile_id != prior_envelope.profile_id
        or new_envelope.runtime_catalog_sha256 != prior_envelope.runtime_catalog_sha256
        or new_envelope.runtime_pack_sha256 != prior_envelope.runtime_pack_sha256
    ):
        raise SemanticCompletionRetryError("retry cross-context substitution detected")
    if new_decision.decision_sha256 == prior_decision.decision_sha256:
        raise SemanticCompletionRetryError("retry requires a new routing decision")
    if new_execution_authority.authority_sha256 == prior_execution_authority.authority_sha256:
        raise SemanticCompletionRetryError("retry requires a new execution authority")
    plan = build_invocation_plan(
        runtime_catalog,
        exact_pack,
        new_envelope,
        new_decision,
        new_capability,
        budget,
        new_execution_authority,
        now=now,
    )
    for value, label in (
        (plan.provider_id, "provider_id"),
        (plan.model_id, "model_id"),
        (plan.model_version, "model_version"),
    ):
        _pinned_route(value, label)
    selection = new_decision.selection
    reservation = new_decision.budget_reservation
    if selection is None or reservation is None:
        raise SemanticCompletionRetryError("retry route has no selection or reservation")
    remaining = (
        budget.aggregate_input_token_limit - budget.aggregate_input_tokens_reserved,
        budget.aggregate_output_token_limit - budget.aggregate_output_tokens_reserved,
        budget.aggregate_cost_limit_micros - budget.aggregate_cost_reserved_micros,
    )
    authority_expected = {
        "assessment_id": assessment.assessment_id,
        "assessment_sha256": assessment.assessment_sha256,
        "prior_execution_receipt_id": prior_receipt.receipt_id,
        "prior_execution_receipt_sha256": prior_receipt.receipt_sha256,
        "prior_failure_class": assessment.failure_class,
        "prior_routing_decision_sha256": prior_decision.decision_sha256,
        "prior_execution_authority_sha256": prior_execution_authority.authority_sha256,
        "prior_execution_envelope_sha256": prior_envelope.envelope_sha256,
        "previous_retry_receipt_id": (
            previous_retry_receipt.receipt_id if previous_retry_receipt is not None else None
        ),
        "previous_retry_receipt_sha256": (
            previous_retry_receipt.receipt_sha256 if previous_retry_receipt is not None else None
        ),
        "new_routing_decision_id": new_decision.decision_id,
        "new_routing_decision_sha256": new_decision.decision_sha256,
        "new_execution_authority_id": new_execution_authority.authority_id,
        "new_execution_authority_sha256": new_execution_authority.authority_sha256,
        "new_execution_envelope_sha256": new_envelope.envelope_sha256,
        "runtime_catalog_sha256": runtime_catalog.catalog_sha256,
        "runtime_pack_sha256": exact_pack["runtime_pack_sha256"],
        "mission_id": prior_envelope.mission_id,
        "plan_id": prior_envelope.plan_id,
        "work_id": prior_envelope.work_id,
        "target_scope_sha256": prior_envelope.target_scope_sha256,
        "authority_snapshot_sha256": prior_envelope.authority_snapshot_sha256,
        "budget_id": budget.budget_id,
        "budget_sha256": budget.budget_sha256,
        "budget_revision": budget.budget_revision,
        "remaining_input_tokens": remaining[0],
        "remaining_output_tokens": remaining[1],
        "remaining_cost_micros": remaining[2],
        "subject_principal_id": new_execution_authority.subject_principal_id,
        "producer_principal_id": prior_execution_authority.expert_profile_id,
        "requester_principal_id": new_execution_authority.requester_principal_id,
        "provider_adapter_principal_id": new_execution_authority.provider_adapter_principal_id,
        "model_principal_id": new_execution_authority.model_principal_id,
    }
    if any(getattr(retry_authority, name) != value for name, value in authority_expected.items()):
        raise SemanticCompletionRetryError("retry authority binding substitution detected")
    if retry_authority.issuer_principal_id in {
        prior_execution_authority.issuer_principal_id,
        prior_execution_authority.route_planner_principal_id,
        new_execution_authority.issuer_principal_id,
        new_execution_authority.route_planner_principal_id,
    }:
        raise SemanticCompletionRetryError("retry authority issuer is not independently separated")
    if retry_authority.attempt_number == 2:
        if previous_retry_receipt is not None:
            raise SemanticCompletionRetryError("first retry cannot carry a prior retry receipt")
    elif previous_retry_receipt is None or (
        previous_retry_receipt.attempt_number + 1 != retry_authority.attempt_number
        or previous_retry_receipt.maximum_attempts != retry_authority.maximum_attempts
        or previous_retry_receipt.new_routing_decision_sha256 != prior_decision.decision_sha256
        or previous_retry_receipt.new_execution_authority_sha256
        != prior_execution_authority.authority_sha256
        or previous_retry_receipt.new_execution_envelope_sha256 != prior_envelope.envelope_sha256
        or _instant(previous_retry_receipt.authorized_at) > _instant(prior_receipt.recorded_at)
    ):
        raise SemanticCompletionRetryError("retry attempt chain continuity is invalid")
    if previous_retry_receipt is not None and not InMemoryRetryReplayGuard.verifies(
        replay_guard, previous_retry_receipt
    ):
        raise SemanticCompletionRetryError("previous retry receipt lacks replay custody")
    if retry_authority.changed_condition_evidence_sha256 in {
        assessment.assessment_sha256,
        assessment.evidence_snapshot_sha256,
        prior_receipt.receipt_sha256,
    }:
        raise SemanticCompletionRetryError("retry changed-condition proof is not new")
    route_changed = prior_decision.selection is None or (
        prior_decision.selection.provider_id,
        prior_decision.selection.provider_api_version,
        prior_decision.selection.model_id,
        prior_decision.selection.model_version,
        prior_decision.selection.pricing_revision,
    ) != (
        selection.provider_id,
        selection.provider_api_version,
        selection.model_id,
        selection.model_version,
        selection.pricing_revision,
    )
    envelope_changed = new_envelope.envelope_sha256 != prior_envelope.envelope_sha256
    codes = set(retry_authority.changed_condition_codes)
    if not codes.intersection(FAILURE_CHANGE_CODES[assessment.failure_class]):
        raise SemanticCompletionRetryError("retry change does not address the prior failure")
    if route_changed and "route_changed" not in codes:
        raise SemanticCompletionRetryError("changed route lacks an explicit justification")
    if envelope_changed and not codes.intersection({"context_changed", "evidence_changed"}):
        raise SemanticCompletionRetryError("changed input lacks an explicit justification")
    if not route_changed and not envelope_changed and "provider_health_changed" not in codes:
        raise SemanticCompletionRetryError("blind same-input retry is forbidden")
    proposed = (
        reservation.input_tokens,
        reservation.output_tokens,
        reservation.estimated_cost_micros,
    )
    if any(value > limit for value, limit in zip(proposed, remaining, strict=True)) or any(
        value > limit
        for value, limit in zip(
            proposed,
            (
                retry_authority.remaining_input_tokens,
                retry_authority.remaining_output_tokens,
                retry_authority.remaining_cost_micros,
            ),
            strict=True,
        )
    ):
        raise SemanticCompletionRetryError("retry exceeds remaining token or cost budget")
    replay_commit = InMemoryRetryReplayGuard.consume(replay_guard, retry_authority, now)
    if type(replay_commit) is not RetryReplayCommit:
        raise SemanticCompletionRetryError("replay guard returned an invalid commit")
    replay_commit = RetryReplayCommit.from_dict(replay_commit.to_dict())
    if (
        replay_commit.replay_identity_sha256 != retry_authority.replay_identity_sha256
        or replay_commit.retry_authority_id != retry_authority.retry_authority_id
        or replay_commit.retry_authority_sha256 != retry_authority.retry_authority_sha256
        or replay_commit.consumed_at != now
    ):
        raise SemanticCompletionRetryError("replay commit binding mismatch")
    return RetryAuthorizationReceipt(
        assessment_id=assessment.assessment_id,
        assessment_sha256=assessment.assessment_sha256,
        prior_execution_receipt_id=prior_receipt.receipt_id,
        prior_execution_receipt_sha256=prior_receipt.receipt_sha256,
        retry_authority_id=retry_authority.retry_authority_id,
        retry_authority_sha256=retry_authority.retry_authority_sha256,
        replay_identity_sha256=retry_authority.replay_identity_sha256,
        replay_commit_id=replay_commit.replay_commit_id,
        replay_commit_sha256=replay_commit.replay_commit_sha256,
        new_routing_decision_id=new_decision.decision_id,
        new_routing_decision_sha256=new_decision.decision_sha256,
        new_execution_authority_id=new_execution_authority.authority_id,
        new_execution_authority_sha256=new_execution_authority.authority_sha256,
        new_execution_envelope_sha256=new_envelope.envelope_sha256,
        budget_sha256=budget.budget_sha256,
        changed_condition_evidence_sha256=retry_authority.changed_condition_evidence_sha256,
        attempt_number=retry_authority.attempt_number,
        maximum_attempts=retry_authority.maximum_attempts,
        authorized_at=now,
    )


__all__ = [
    "BLOCKER_CODES",
    "CHANGED_CONDITION_CODES",
    "COMPLETION_STATES",
    "DISPOSITION_STATES",
    "FAILURE_CLASSES",
    "InMemoryRetryReplayGuard",
    "REASON_CODES",
    "RETRYABLE_FAILURE_CLASSES",
    "RetryAuthorizationAuthority",
    "RetryAuthorizationReceipt",
    "RetryReplayCommit",
    "RetryReplayGuard",
    "RequirementDisposition",
    "SemanticCompletionAssessment",
    "SemanticCompletionEvidence",
    "SemanticCompletionRequirements",
    "SemanticCompletionRetryError",
    "assess_semantic_completion",
    "authorize_retry",
]
