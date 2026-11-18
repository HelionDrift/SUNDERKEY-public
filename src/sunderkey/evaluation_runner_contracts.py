"""Deterministic, non-executing contracts for unified evaluation runs.

This module composes immutable inputs, assignments, imported observations,
budgets, evidence, and independent review. It performs no model, provider,
tool, range, corpus, network, or qualification operation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
CONTRACT_DOMAIN = "sunderkey.evaluation-runner-contract.v1"

BINDING_KINDS = (
    "candidate",
    "model",
    "provider",
    "tool",
    "prompt",
    "policy",
    "corpus",
    "range",
    "scoring",
    "budget",
    "custody",
)
COMPARISON_ROLES = ("candidate", "deterministic", "generalist", "prior_release")

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "corpus_access": "none",
        "evaluation_execution": "none",
        "model_calls": "none",
        "network": "none",
        "provider_calls": "none",
        "qualification": "none",
        "range_actions": "none",
        "tool_calls": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
MOVING_VERSIONS = frozenset({"current", "head", "latest", "main", "master", "tip"})


class EvaluationRunnerContractError(ValueError):
    """Raised when a runner contract fails closed."""


class ResultStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    ABSTAINED = "abstained"
    SAFETY_FAILURE = "safety_failure"


class ReadinessStatus(StrEnum):
    READY_FOR_SEPARATE_EXECUTION = "ready_for_separate_execution"
    NOT_READY = "not_ready"


class AggregateStatus(StrEnum):
    COMPLETE = "complete"
    COMPLETE_WITH_HARD_FAILURE = "complete_with_hard_failure"


class CompletionStatus(StrEnum):
    READY_FOR_COMPARISON = "ready_for_comparison"
    HARD_SAFETY_FAILURE = "hard_safety_failure"
    INCOMPLETE = "incomplete"
    REVIEW_REJECTED = "review_rejected"


class ReviewDecision(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    _validate_json(value, "value")
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise EvaluationRunnerContractError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 16:
        raise EvaluationRunnerContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvaluationRunnerContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise EvaluationRunnerContractError(f"{label} has an unsupported value")


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise EvaluationRunnerContractError(f"{label} fields do not match the contract")
    return raw


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise EvaluationRunnerContractError(f"{label} must be a safe identifier")
    return value


def _version(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or VERSION_RE.fullmatch(value) is None
        or value.lower() in MOVING_VERSIONS
        or "*" in value
    ):
        raise EvaluationRunnerContractError(f"{label} must be an exact version")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EvaluationRunnerContractError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise EvaluationRunnerContractError(f"{label} must be a UTC timestamp")
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return value


def _bounded_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 10**15:
        raise EvaluationRunnerContractError(f"{label} must be a bounded integer")
    return value


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise EvaluationRunnerContractError(f"{label} must be a sequence")
    return value


def _effects(raw: Any) -> None:
    if raw != dict(NO_EFFECTS):
        raise EvaluationRunnerContractError("effects must remain none")


def _content_identity(prefix: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256(body)
    return f"{prefix}-{digest[7:39].upper()}", digest


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    kind: str
    artifact_id: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if self.kind not in BINDING_KINDS:
            raise EvaluationRunnerContractError("binding kind is not supported")
        _identifier(self.artifact_id, "artifact_id")
        _version(self.version, "version")
        _sha(self.sha256, "sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ArtifactBinding:
        item = _exact(raw, {"artifact_id", "kind", "sha256", "version"}, "binding")
        return cls(**item)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class RunnerBudget:
    maximum_cost_microusd: int
    maximum_latency_ms: int
    maximum_requests: int
    maximum_tokens: int
    maximum_tool_calls: int

    def __post_init__(self) -> None:
        for name in (
            "maximum_cost_microusd",
            "maximum_latency_ms",
            "maximum_requests",
            "maximum_tokens",
            "maximum_tool_calls",
        ):
            _bounded_int(getattr(self, name), name, minimum=1)

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> RunnerBudget:
        fields = set(cls.__dataclass_fields__)
        return cls(**_exact(raw, fields, "budget"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class RunnerIdentities:
    candidate_owner_id: str
    corpus_custodian_id: str
    execution_controller_id: str
    ground_truth_custodian_id: str
    plan_author_id: str
    evaluator_ids: tuple[str, ...]
    reviewer_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        base = (
            self.candidate_owner_id,
            self.corpus_custodian_id,
            self.execution_controller_id,
            self.ground_truth_custodian_id,
            self.plan_author_id,
        )
        for value in (*base, *self.evaluator_ids, *self.reviewer_ids):
            _identifier(value, "identity")
        if len(self.evaluator_ids) < 1 or len(self.evaluator_ids) > 32:
            raise EvaluationRunnerContractError("at least one evaluator is required")
        if len(self.reviewer_ids) < 2 or len(self.reviewer_ids) > 32:
            raise EvaluationRunnerContractError("at least two independent reviewers are required")
        all_identities = (*base, *self.evaluator_ids, *self.reviewer_ids)
        if len(set(all_identities)) != len(all_identities):
            raise EvaluationRunnerContractError("runner identities must be separate")
        if tuple(sorted(self.evaluator_ids)) != self.evaluator_ids:
            raise EvaluationRunnerContractError("evaluator identities must be sorted")
        if tuple(sorted(self.reviewer_ids)) != self.reviewer_ids:
            raise EvaluationRunnerContractError("reviewer identities must be sorted")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_owner_id": self.candidate_owner_id,
            "corpus_custodian_id": self.corpus_custodian_id,
            "execution_controller_id": self.execution_controller_id,
            "ground_truth_custodian_id": self.ground_truth_custodian_id,
            "plan_author_id": self.plan_author_id,
            "evaluator_ids": list(self.evaluator_ids),
            "reviewer_ids": list(self.reviewer_ids),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RunnerIdentities:
        fields = set(cls.__dataclass_fields__)
        item = dict(_exact(raw, fields, "identities"))
        item["evaluator_ids"] = tuple(_sequence(item["evaluator_ids"], "evaluator_ids"))
        item["reviewer_ids"] = tuple(_sequence(item["reviewer_ids"], "reviewer_ids"))
        return cls(**item)


@dataclass(frozen=True, slots=True)
class CaseAssignment:
    assignment_id: str
    case_id: str
    case_sha256: str
    evaluator_id: str
    partition_id: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.assignment_id, "assignment_id"),
            (self.case_id, "case_id"),
            (self.evaluator_id, "evaluator_id"),
            (self.partition_id, "partition_id"),
        ):
            _identifier(value, label)
        _sha(self.case_sha256, "case_sha256")

    def to_dict(self) -> dict[str, str]:
        return {
            "assignment_id": self.assignment_id,
            "case_id": self.case_id,
            "case_sha256": self.case_sha256,
            "evaluator_id": self.evaluator_id,
            "partition_id": self.partition_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CaseAssignment:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "assignment"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ContaminationAttestation:
    candidate_sha256: str
    corpus_sha256: str
    scanner_version: str
    report_sha256: str
    checked_at: str
    status: str

    def __post_init__(self) -> None:
        _sha(self.candidate_sha256, "candidate_sha256")
        _sha(self.corpus_sha256, "corpus_sha256")
        _version(self.scanner_version, "scanner_version")
        _sha(self.report_sha256, "report_sha256")
        _timestamp(self.checked_at, "checked_at")
        if self.status != "clean":
            raise EvaluationRunnerContractError("contamination status must be clean")

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> ContaminationAttestation:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "contamination_attestation"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class EvaluationRunPlan:
    plan_version: str
    bindings: tuple[ArtifactBinding, ...]
    budget: RunnerBudget
    identities: RunnerIdentities
    assignments: tuple[CaseAssignment, ...]
    contamination_attestation: ContaminationAttestation
    fixed_membership_sha256: str
    idempotency_key: str
    replay_epoch: int
    plan_id: str
    plan_sha256: str
    contract_type: ClassVar[str] = "run_plan"

    def __post_init__(self) -> None:
        _version(self.plan_version, "plan_version")
        _identifier(self.idempotency_key, "idempotency_key")
        _bounded_int(self.replay_epoch, "replay_epoch", minimum=1)
        if tuple(item.kind for item in self.bindings) != BINDING_KINDS:
            raise EvaluationRunnerContractError("all bindings are required in canonical order")
        binding_map = {item.kind: item for item in self.bindings}
        if (
            self.contamination_attestation.candidate_sha256 != binding_map["candidate"].sha256
            or self.contamination_attestation.corpus_sha256 != binding_map["corpus"].sha256
        ):
            raise EvaluationRunnerContractError(
                "contamination attestation must bind the candidate and corpus"
            )
        if not self.assignments:
            raise EvaluationRunnerContractError("at least one fixed case is required")
        ordered = tuple(sorted(self.assignments, key=lambda item: item.case_id))
        if ordered != self.assignments:
            raise EvaluationRunnerContractError("assignments must be sorted by case_id")
        for attribute in ("case_id", "assignment_id", "case_sha256"):
            values = [getattr(item, attribute) for item in self.assignments]
            if len(set(values)) != len(values):
                raise EvaluationRunnerContractError(f"duplicate {attribute} is forbidden")
        evaluators = set(self.identities.evaluator_ids)
        if any(item.evaluator_id not in evaluators for item in self.assignments):
            raise EvaluationRunnerContractError("every assignment must use a bound evaluator")
        membership = canonical_sha256([item.to_dict() for item in self.assignments])
        if self.fixed_membership_sha256 != membership:
            raise EvaluationRunnerContractError("fixed case membership digest does not match")
        expected_id, expected_sha = _content_identity("ERP", self._body())
        if self.plan_id != expected_id or self.plan_sha256 != expected_sha:
            raise EvaluationRunnerContractError("run plan identity does not match content")

    def _body(self) -> dict[str, Any]:
        return {
            "assignments": [item.to_dict() for item in self.assignments],
            "bindings": [item.to_dict() for item in self.bindings],
            "budget": self.budget.to_dict(),
            "contract_type": self.contract_type,
            "contamination_attestation": self.contamination_attestation.to_dict(),
            "effects": dict(NO_EFFECTS),
            "fixed_membership_sha256": self.fixed_membership_sha256,
            "idempotency_key": self.idempotency_key,
            "identities": self.identities.to_dict(),
            "plan_version": self.plan_version,
            "replay_epoch": self.replay_epoch,
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_id": self.plan_id, "plan_sha256": self.plan_sha256}

    @property
    def document_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> EvaluationRunPlan:
        fields = {
            "assignments",
            "bindings",
            "budget",
            "contract_type",
            "contamination_attestation",
            "effects",
            "fixed_membership_sha256",
            "idempotency_key",
            "identities",
            "plan_id",
            "plan_sha256",
            "plan_version",
            "replay_epoch",
            "schema_version",
        }
        item = dict(_exact(raw, fields, "run_plan"))
        if (
            item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("contract_type") != cls.contract_type
        ):
            raise EvaluationRunnerContractError("run plan discriminator is invalid")
        _effects(item.pop("effects"))
        item["bindings"] = tuple(
            ArtifactBinding.from_dict(value) for value in _sequence(item["bindings"], "bindings")
        )
        item["budget"] = RunnerBudget.from_dict(item["budget"])
        item["identities"] = RunnerIdentities.from_dict(item["identities"])
        item["contamination_attestation"] = ContaminationAttestation.from_dict(
            item["contamination_attestation"]
        )
        item["assignments"] = tuple(
            CaseAssignment.from_dict(value)
            for value in _sequence(item["assignments"], "assignments")
        )
        return cls(**item)

    @classmethod
    def from_json(cls, raw: str) -> EvaluationRunPlan:
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise EvaluationRunnerContractError("run plan is not valid JSON") from exc
        return cls.from_dict(parsed)


def build_run_plan(
    *,
    plan_version: str,
    bindings: Sequence[ArtifactBinding],
    budget: RunnerBudget,
    identities: RunnerIdentities,
    assignments: Sequence[CaseAssignment],
    contamination_attestation: ContaminationAttestation,
    idempotency_key: str,
    replay_epoch: int,
) -> EvaluationRunPlan:
    ordered_bindings = tuple(bindings)
    ordered_assignments = tuple(sorted(assignments, key=lambda item: item.case_id))
    membership = canonical_sha256([item.to_dict() for item in ordered_assignments])
    provisional = {
        "assignments": [item.to_dict() for item in ordered_assignments],
        "bindings": [item.to_dict() for item in ordered_bindings],
        "budget": budget.to_dict(),
        "contract_type": EvaluationRunPlan.contract_type,
        "contamination_attestation": contamination_attestation.to_dict(),
        "effects": dict(NO_EFFECTS),
        "fixed_membership_sha256": membership,
        "idempotency_key": idempotency_key,
        "identities": identities.to_dict(),
        "plan_version": plan_version,
        "replay_epoch": replay_epoch,
        "schema_version": SCHEMA_VERSION,
    }
    plan_id, plan_sha = _content_identity("ERP", provisional)
    return EvaluationRunPlan(
        plan_version,
        ordered_bindings,
        budget,
        identities,
        ordered_assignments,
        contamination_attestation,
        membership,
        idempotency_key,
        replay_epoch,
        plan_id,
        plan_sha,
    )


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    evidence_id: str
    evidence_sha256: str
    media_type: str
    size_bytes: int

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence_id")
        _sha(self.evidence_sha256, "evidence_sha256")
        _identifier(self.media_type, "media_type")
        _bounded_int(self.size_bytes, "size_bytes", minimum=1)

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceItem:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "evidence_item"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    items: tuple[EvidenceItem, ...]
    manifest_sha256: str

    def __post_init__(self) -> None:
        if (
            not self.items
            or tuple(sorted(self.items, key=lambda item: item.evidence_id)) != self.items
        ):
            raise EvaluationRunnerContractError("evidence items must be nonempty and sorted")
        identities = [item.evidence_id for item in self.items]
        digests = [item.evidence_sha256 for item in self.items]
        if len(set(identities)) != len(identities) or len(set(digests)) != len(digests):
            raise EvaluationRunnerContractError("duplicate evidence is forbidden")
        expected = canonical_sha256([item.to_dict() for item in self.items])
        if self.manifest_sha256 != expected:
            raise EvaluationRunnerContractError("evidence manifest digest does not match")

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.items],
            "manifest_sha256": self.manifest_sha256,
        }

    @classmethod
    def build(cls, items: Sequence[EvidenceItem]) -> EvidenceManifest:
        ordered = tuple(sorted(items, key=lambda item: item.evidence_id))
        return cls(ordered, canonical_sha256([item.to_dict() for item in ordered]))

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceManifest:
        item = _exact(raw, {"items", "manifest_sha256"}, "evidence_manifest")
        values = tuple(EvidenceItem.from_dict(value) for value in _sequence(item["items"], "items"))
        return cls(values, item["manifest_sha256"])  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class UsageObservation:
    cost_microusd: int
    latency_ms: int
    requests: int
    tokens: int
    tool_calls: int

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            _bounded_int(getattr(self, name), name)

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> UsageObservation:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "usage"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ExecutionResultEnvelope:
    plan_id: str
    plan_sha256: str
    case_id: str
    case_sha256: str
    assignment_id: str
    evaluator_id: str
    idempotency_key: str
    replay_epoch: int
    replay_nonce: str
    status: ResultStatus
    hard_failure_codes: tuple[str, ...]
    usage: UsageObservation
    evidence_manifest: EvidenceManifest
    observed_at: str
    result_id: str
    result_sha256: str
    contract_type: ClassVar[str] = "execution_result"

    def __post_init__(self) -> None:
        for value, label in (
            (self.plan_id, "plan_id"),
            (self.case_id, "case_id"),
            (self.assignment_id, "assignment_id"),
            (self.evaluator_id, "evaluator_id"),
            (self.idempotency_key, "idempotency_key"),
            (self.replay_nonce, "replay_nonce"),
        ):
            _identifier(value, label)
        _sha(self.plan_sha256, "plan_sha256")
        _sha(self.case_sha256, "case_sha256")
        _bounded_int(self.replay_epoch, "replay_epoch", minimum=1)
        _timestamp(self.observed_at, "observed_at")
        if tuple(sorted(set(self.hard_failure_codes))) != self.hard_failure_codes:
            raise EvaluationRunnerContractError("hard failure codes must be unique and sorted")
        for code in self.hard_failure_codes:
            _identifier(code, "hard_failure_code")
        if (self.status is ResultStatus.SAFETY_FAILURE) != bool(self.hard_failure_codes):
            raise EvaluationRunnerContractError("safety failure status and codes must agree")
        expected_id, expected_sha = _content_identity("ERE", self._body())
        if self.result_id != expected_id or self.result_sha256 != expected_sha:
            raise EvaluationRunnerContractError("result envelope identity does not match")

    def _body(self) -> dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "case_id": self.case_id,
            "case_sha256": self.case_sha256,
            "contract_type": self.contract_type,
            "effects": dict(NO_EFFECTS),
            "evaluator_id": self.evaluator_id,
            "evidence_manifest": self.evidence_manifest.to_dict(),
            "hard_failure_codes": list(self.hard_failure_codes),
            "idempotency_key": self.idempotency_key,
            "observed_at": self.observed_at,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "replay_epoch": self.replay_epoch,
            "replay_nonce": self.replay_nonce,
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
            "usage": self.usage.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "result_id": self.result_id, "result_sha256": self.result_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> ExecutionResultEnvelope:
        fields = {
            "assignment_id",
            "case_id",
            "case_sha256",
            "contract_type",
            "effects",
            "evaluator_id",
            "evidence_manifest",
            "hard_failure_codes",
            "idempotency_key",
            "observed_at",
            "plan_id",
            "plan_sha256",
            "replay_epoch",
            "replay_nonce",
            "result_id",
            "result_sha256",
            "schema_version",
            "status",
            "usage",
        }
        item = dict(_exact(raw, fields, "execution_result"))
        if (
            item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("contract_type") != cls.contract_type
        ):
            raise EvaluationRunnerContractError("result discriminator is invalid")
        _effects(item.pop("effects"))
        item["status"] = ResultStatus(item["status"])
        item["hard_failure_codes"] = tuple(
            _sequence(item["hard_failure_codes"], "hard_failure_codes")
        )
        item["usage"] = UsageObservation.from_dict(item["usage"])
        item["evidence_manifest"] = EvidenceManifest.from_dict(item["evidence_manifest"])
        return cls(**item)


def build_result_envelope(
    *,
    plan: EvaluationRunPlan,
    case_id: str,
    idempotency_key: str,
    replay_nonce: str,
    status: ResultStatus,
    hard_failure_codes: Sequence[str],
    usage: UsageObservation,
    evidence_manifest: EvidenceManifest,
    observed_at: str,
) -> ExecutionResultEnvelope:
    assignment = next((item for item in plan.assignments if item.case_id == case_id), None)
    if assignment is None:
        raise EvaluationRunnerContractError("case is not in the fixed plan membership")
    values = {
        "assignment_id": assignment.assignment_id,
        "case_id": assignment.case_id,
        "case_sha256": assignment.case_sha256,
        "evaluator_id": assignment.evaluator_id,
        "evidence_manifest": evidence_manifest,
        "hard_failure_codes": tuple(sorted(set(hard_failure_codes))),
        "idempotency_key": idempotency_key,
        "observed_at": observed_at,
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "replay_epoch": plan.replay_epoch,
        "replay_nonce": replay_nonce,
        "status": status,
        "usage": usage,
    }
    body = {
        "assignment_id": assignment.assignment_id,
        "case_id": assignment.case_id,
        "case_sha256": assignment.case_sha256,
        "contract_type": ExecutionResultEnvelope.contract_type,
        "effects": dict(NO_EFFECTS),
        "evaluator_id": assignment.evaluator_id,
        "evidence_manifest": evidence_manifest.to_dict(),
        "hard_failure_codes": list(values["hard_failure_codes"]),
        "idempotency_key": idempotency_key,
        "observed_at": observed_at,
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "replay_epoch": plan.replay_epoch,
        "replay_nonce": replay_nonce,
        "schema_version": SCHEMA_VERSION,
        "status": status.value,
        "usage": usage.to_dict(),
    }
    result_id, result_sha = _content_identity("ERE", body)
    return ExecutionResultEnvelope(**values, result_id=result_id, result_sha256=result_sha)


@dataclass(frozen=True, slots=True)
class AggregateRunObservation:
    plan_id: str
    plan_sha256: str
    fixed_membership_sha256: str
    result_ids: tuple[str, ...]
    result_manifest_sha256: str
    status_counts: Mapping[str, int]
    usage: UsageObservation
    hard_failure_codes: tuple[str, ...]
    status: AggregateStatus
    observation_id: str
    observation_sha256: str
    contract_type: ClassVar[str] = "aggregate_observation"

    def __post_init__(self) -> None:
        _identifier(self.plan_id, "plan_id")
        _sha(self.plan_sha256, "plan_sha256")
        _sha(self.fixed_membership_sha256, "fixed_membership_sha256")
        _sha(self.result_manifest_sha256, "result_manifest_sha256")
        if not self.result_ids or tuple(sorted(set(self.result_ids))) != self.result_ids:
            raise EvaluationRunnerContractError("result ids must be nonempty, unique, and sorted")
        expected_keys = {item.value for item in ResultStatus}
        if set(self.status_counts) != expected_keys:
            raise EvaluationRunnerContractError("status counts must cover every result status")
        for key, value in self.status_counts.items():
            _identifier(key, "status_key")
            _bounded_int(value, "status_count")
        if sum(self.status_counts.values()) != len(self.result_ids):
            raise EvaluationRunnerContractError("status counts must account for every result")
        if tuple(sorted(set(self.hard_failure_codes))) != self.hard_failure_codes:
            raise EvaluationRunnerContractError("aggregate hard failures must be sorted and unique")
        has_failure = bool(self.hard_failure_codes)
        if (self.status is AggregateStatus.COMPLETE_WITH_HARD_FAILURE) != has_failure:
            raise EvaluationRunnerContractError("aggregate status and hard failures must agree")
        expected_id, expected_sha = _content_identity("ERO", self._body())
        if self.observation_id != expected_id or self.observation_sha256 != expected_sha:
            raise EvaluationRunnerContractError("aggregate identity does not match")

    def _body(self) -> dict[str, Any]:
        return {
            "contract_type": self.contract_type,
            "effects": dict(NO_EFFECTS),
            "fixed_membership_sha256": self.fixed_membership_sha256,
            "hard_failure_codes": list(self.hard_failure_codes),
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "result_ids": list(self.result_ids),
            "result_manifest_sha256": self.result_manifest_sha256,
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
            "status_counts": dict(sorted(self.status_counts.items())),
            "usage": self.usage.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AggregateRunObservation:
        fields = {
            "contract_type",
            "effects",
            "fixed_membership_sha256",
            "hard_failure_codes",
            "observation_id",
            "observation_sha256",
            "plan_id",
            "plan_sha256",
            "result_ids",
            "result_manifest_sha256",
            "schema_version",
            "status",
            "status_counts",
            "usage",
        }
        item = dict(_exact(raw, fields, "aggregate_observation"))
        if (
            item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("contract_type") != cls.contract_type
        ):
            raise EvaluationRunnerContractError("aggregate discriminator is invalid")
        _effects(item.pop("effects"))
        item["status"] = AggregateStatus(item["status"])
        item["result_ids"] = tuple(_sequence(item["result_ids"], "result_ids"))
        item["hard_failure_codes"] = tuple(
            _sequence(item["hard_failure_codes"], "hard_failure_codes")
        )
        counts = item["status_counts"]
        if not isinstance(counts, Mapping):
            raise EvaluationRunnerContractError("status_counts must be an object")
        item["status_counts"] = dict(counts)
        item["usage"] = UsageObservation.from_dict(item["usage"])
        return cls(**item)


def aggregate_results(
    plan: EvaluationRunPlan, results: Sequence[ExecutionResultEnvelope]
) -> AggregateRunObservation:
    values = tuple(results)
    expected = {item.case_id: item for item in plan.assignments}
    if len(values) != len(expected) or {item.case_id for item in values} != set(expected):
        raise EvaluationRunnerContractError("results must cover the complete fixed denominator")
    if len({item.case_id for item in values}) != len(values):
        raise EvaluationRunnerContractError("duplicate case results are forbidden")
    if len({item.result_id for item in values}) != len(values):
        raise EvaluationRunnerContractError("duplicate result envelopes are forbidden")
    if len({item.idempotency_key for item in values}) != len(values):
        raise EvaluationRunnerContractError("duplicate idempotency keys are forbidden")
    if len({item.replay_nonce for item in values}) != len(values):
        raise EvaluationRunnerContractError("replayed result nonce is forbidden")
    for result in values:
        assignment = expected[result.case_id]
        context = (
            result.plan_id == plan.plan_id
            and result.plan_sha256 == plan.plan_sha256
            and result.case_sha256 == assignment.case_sha256
            and result.assignment_id == assignment.assignment_id
            and result.evaluator_id == assignment.evaluator_id
            and result.replay_epoch == plan.replay_epoch
        )
        if not context:
            raise EvaluationRunnerContractError("result crosses its bound plan context")
    totals = UsageObservation(
        sum(item.usage.cost_microusd for item in values),
        sum(item.usage.latency_ms for item in values),
        sum(item.usage.requests for item in values),
        sum(item.usage.tokens for item in values),
        sum(item.usage.tool_calls for item in values),
    )
    for used, maximum, label in (
        (totals.cost_microusd, plan.budget.maximum_cost_microusd, "cost"),
        (totals.latency_ms, plan.budget.maximum_latency_ms, "latency"),
        (totals.requests, plan.budget.maximum_requests, "requests"),
        (totals.tokens, plan.budget.maximum_tokens, "tokens"),
        (totals.tool_calls, plan.budget.maximum_tool_calls, "tool calls"),
    ):
        if used > maximum:
            raise EvaluationRunnerContractError(f"{label} budget is exceeded")
    ordered = tuple(sorted(values, key=lambda item: item.case_id))
    result_ids = tuple(sorted(item.result_id for item in ordered))
    manifest = canonical_sha256([item.to_dict() for item in ordered])
    counts = {
        status.value: sum(item.status is status for item in values) for status in ResultStatus
    }
    failures = tuple(sorted({code for item in values for code in item.hard_failure_codes}))
    status = AggregateStatus.COMPLETE_WITH_HARD_FAILURE if failures else AggregateStatus.COMPLETE
    body = {
        "contract_type": AggregateRunObservation.contract_type,
        "effects": dict(NO_EFFECTS),
        "fixed_membership_sha256": plan.fixed_membership_sha256,
        "hard_failure_codes": list(failures),
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "result_ids": list(result_ids),
        "result_manifest_sha256": manifest,
        "schema_version": SCHEMA_VERSION,
        "status": status.value,
        "status_counts": counts,
        "usage": totals.to_dict(),
    }
    observation_id, observation_sha = _content_identity("ERO", body)
    return AggregateRunObservation(
        plan.plan_id,
        plan.plan_sha256,
        plan.fixed_membership_sha256,
        result_ids,
        manifest,
        counts,
        totals,
        failures,
        status,
        observation_id,
        observation_sha,
    )


@dataclass(frozen=True, slots=True)
class IndependentReview:
    observation_id: str
    observation_sha256: str
    reviewer_id: str
    decision: ReviewDecision
    evidence_sha256: str
    reviewed_at: str

    def __post_init__(self) -> None:
        _identifier(self.observation_id, "observation_id")
        _sha(self.observation_sha256, "observation_sha256")
        _identifier(self.reviewer_id, "reviewer_id")
        _sha(self.evidence_sha256, "evidence_sha256")
        _timestamp(self.reviewed_at, "reviewed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "evidence_sha256": self.evidence_sha256,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "reviewed_at": self.reviewed_at,
            "reviewer_id": self.reviewer_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IndependentReview:
        item = dict(_exact(raw, set(cls.__dataclass_fields__), "independent_review"))
        item["decision"] = ReviewDecision(item["decision"])
        return cls(**item)


@dataclass(frozen=True, slots=True)
class Assessment:
    assessment_kind: str
    subject_id: str
    subject_sha256: str
    status: str
    reason_codes: tuple[str, ...]
    review_ids: tuple[str, ...]
    assessment_id: str
    assessment_sha256: str
    contract_type: ClassVar[str] = "assessment"

    def __post_init__(self) -> None:
        if self.assessment_kind not in {"readiness", "completion"}:
            raise EvaluationRunnerContractError("assessment kind is invalid")
        _identifier(self.subject_id, "subject_id")
        _sha(self.subject_sha256, "subject_sha256")
        _identifier(self.status, "status")
        if tuple(sorted(set(self.reason_codes))) != self.reason_codes:
            raise EvaluationRunnerContractError("reason codes must be sorted and unique")
        if tuple(sorted(set(self.review_ids))) != self.review_ids:
            raise EvaluationRunnerContractError("review ids must be sorted and unique")
        expected_id, expected_sha = _content_identity("ERA", self._body())
        if self.assessment_id != expected_id or self.assessment_sha256 != expected_sha:
            raise EvaluationRunnerContractError("assessment identity does not match")

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_kind": self.assessment_kind,
            "contract_type": self.contract_type,
            "effects": dict(NO_EFFECTS),
            "reason_codes": list(self.reason_codes),
            "review_ids": list(self.review_ids),
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "subject_id": self.subject_id,
            "subject_sha256": self.subject_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> Assessment:
        fields = {
            "assessment_id",
            "assessment_kind",
            "assessment_sha256",
            "contract_type",
            "effects",
            "reason_codes",
            "review_ids",
            "schema_version",
            "status",
            "subject_id",
            "subject_sha256",
        }
        item = dict(_exact(raw, fields, "assessment"))
        if (
            item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("contract_type") != cls.contract_type
        ):
            raise EvaluationRunnerContractError("assessment discriminator is invalid")
        _effects(item.pop("effects"))
        item["reason_codes"] = tuple(_sequence(item["reason_codes"], "reason_codes"))
        item["review_ids"] = tuple(_sequence(item["review_ids"], "review_ids"))
        return cls(**item)


def _assessment(
    kind: str,
    subject_id: str,
    subject_sha: str,
    status: str,
    reasons: Sequence[str],
    review_ids: Sequence[str] = (),
) -> Assessment:
    values = {
        "assessment_kind": kind,
        "subject_id": subject_id,
        "subject_sha256": subject_sha,
        "status": status,
        "reason_codes": tuple(sorted(set(reasons))),
        "review_ids": tuple(sorted(set(review_ids))),
    }
    body = {
        "assessment_kind": kind,
        "contract_type": Assessment.contract_type,
        "effects": dict(NO_EFFECTS),
        "reason_codes": list(values["reason_codes"]),
        "review_ids": list(values["review_ids"]),
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "subject_id": subject_id,
        "subject_sha256": subject_sha,
    }
    assessment_id, assessment_sha = _content_identity("ERA", body)
    return Assessment(**values, assessment_id=assessment_id, assessment_sha256=assessment_sha)


def assess_readiness(plan: EvaluationRunPlan) -> Assessment:
    """Describe plan readiness without authorizing or starting execution."""

    return _assessment(
        "readiness",
        plan.plan_id,
        plan.plan_sha256,
        ReadinessStatus.READY_FOR_SEPARATE_EXECUTION.value,
        (),
    )


def assess_completion(
    plan: EvaluationRunPlan,
    observation: AggregateRunObservation,
    reviews: Sequence[IndependentReview],
) -> Assessment:
    reasons: list[str] = []
    if observation.plan_id != plan.plan_id or observation.plan_sha256 != plan.plan_sha256:
        reasons.append("cross_context_observation")
    values = tuple(reviews)
    reviewer_ids = [item.reviewer_id for item in values]
    if len(values) < 2:
        reasons.append("independent_reviews_missing")
    if len(set(reviewer_ids)) != len(reviewer_ids):
        reasons.append("duplicate_reviewer")
    if any(item.reviewer_id not in plan.identities.reviewer_ids for item in values):
        reasons.append("reviewer_not_assigned")
    if any(
        item.observation_id != observation.observation_id
        or item.observation_sha256 != observation.observation_sha256
        for item in values
    ):
        reasons.append("review_cross_context")
    if any(item.decision is ReviewDecision.REJECTED for item in values):
        status = CompletionStatus.REVIEW_REJECTED
        reasons.append("independent_review_rejected")
    elif observation.status is AggregateStatus.COMPLETE_WITH_HARD_FAILURE:
        status = CompletionStatus.HARD_SAFETY_FAILURE
        reasons.append("hard_safety_failure")
    elif reasons:
        status = CompletionStatus.INCOMPLETE
    else:
        status = CompletionStatus.READY_FOR_COMPARISON
    review_ids = tuple(sorted(canonical_sha256(item.to_dict()) for item in values))
    return _assessment(
        "completion",
        observation.observation_id,
        observation.observation_sha256,
        status.value,
        reasons,
        review_ids,
    )


@dataclass(frozen=True, slots=True)
class ComparisonObservationReference:
    subject_role: str
    subject_version: str
    observation_id: str
    observation_sha256: str
    fixed_membership_sha256: str
    corpus_sha256: str
    policy_sha256: str
    scoring_sha256: str
    budget_sha256: str
    completion_assessment_id: str
    completion_assessment_sha256: str
    completion_status: str

    def __post_init__(self) -> None:
        if self.subject_role not in COMPARISON_ROLES:
            raise EvaluationRunnerContractError("comparison subject role is invalid")
        _version(self.subject_version, "subject_version")
        _identifier(self.observation_id, "observation_id")
        _identifier(self.completion_assessment_id, "completion_assessment_id")
        for name in (
            "observation_sha256",
            "fixed_membership_sha256",
            "corpus_sha256",
            "policy_sha256",
            "scoring_sha256",
            "budget_sha256",
            "completion_assessment_sha256",
        ):
            _sha(getattr(self, name), name)
        if self.completion_status != CompletionStatus.READY_FOR_COMPARISON.value:
            raise EvaluationRunnerContractError("comparison requires a ready completion assessment")

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> ComparisonObservationReference:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "comparison_reference"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ComparisonInput:
    references: tuple[ComparisonObservationReference, ...]
    comparison_id: str
    comparison_sha256: str
    contract_type: ClassVar[str] = "comparison_input"

    def __post_init__(self) -> None:
        if tuple(item.subject_role for item in self.references) != COMPARISON_ROLES:
            raise EvaluationRunnerContractError(
                "all comparison roles are required in canonical order"
            )
        contexts = {
            (
                item.fixed_membership_sha256,
                item.corpus_sha256,
                item.policy_sha256,
                item.scoring_sha256,
                item.budget_sha256,
            )
            for item in self.references
        }
        if len(contexts) != 1:
            raise EvaluationRunnerContractError("comparison references must share exact context")
        if len({item.observation_id for item in self.references}) != len(self.references):
            raise EvaluationRunnerContractError("comparison observations must be distinct")
        expected_id, expected_sha = _content_identity("ECI", self._body())
        if self.comparison_id != expected_id or self.comparison_sha256 != expected_sha:
            raise EvaluationRunnerContractError("comparison identity does not match")

    def _body(self) -> dict[str, Any]:
        return {
            "contract_type": self.contract_type,
            "effects": dict(NO_EFFECTS),
            "references": [item.to_dict() for item in self.references],
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "comparison_id": self.comparison_id,
            "comparison_sha256": self.comparison_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ComparisonInput:
        fields = {
            "comparison_id",
            "comparison_sha256",
            "contract_type",
            "effects",
            "references",
            "schema_version",
        }
        item = dict(_exact(raw, fields, "comparison_input"))
        if (
            item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("contract_type") != cls.contract_type
        ):
            raise EvaluationRunnerContractError("comparison discriminator is invalid")
        _effects(item.pop("effects"))
        references = tuple(
            ComparisonObservationReference.from_dict(value)
            for value in _sequence(item.pop("references"), "references")
        )
        return cls(references=references, **item)


def build_comparison_input(references: Sequence[ComparisonObservationReference]) -> ComparisonInput:
    values = tuple(references)
    body = {
        "contract_type": ComparisonInput.contract_type,
        "effects": dict(NO_EFFECTS),
        "references": [item.to_dict() for item in values],
        "schema_version": SCHEMA_VERSION,
    }
    comparison_id, comparison_sha = _content_identity("ECI", body)
    return ComparisonInput(values, comparison_id, comparison_sha)


def parse_contract(
    raw: str,
) -> (
    EvaluationRunPlan
    | ExecutionResultEnvelope
    | AggregateRunObservation
    | Assessment
    | ComparisonInput
):
    """Parse one supported document and recompute all invariants."""

    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise EvaluationRunnerContractError("document is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise EvaluationRunnerContractError("document must be an object")
    parsers = {
        EvaluationRunPlan.contract_type: EvaluationRunPlan.from_dict,
        ExecutionResultEnvelope.contract_type: ExecutionResultEnvelope.from_dict,
        AggregateRunObservation.contract_type: AggregateRunObservation.from_dict,
        Assessment.contract_type: Assessment.from_dict,
        ComparisonInput.contract_type: ComparisonInput.from_dict,
    }
    parser = parsers.get(value.get("contract_type"))
    if parser is None:
        raise EvaluationRunnerContractError("document contract type is unsupported")
    return parser(value)
