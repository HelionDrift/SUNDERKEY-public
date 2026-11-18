"""Deterministic repository-only evaluation scoring and comparison runtime.

The runtime accepts already scored observations and produces a content-addressed
scorecard receipt. It performs no evaluation execution, provider, model, tool,
network, filesystem discovery, target, qualification, or promotion operation.
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

from sunderkey.evaluation_program_contracts import (
    CORPUS_PARTITIONS,
    CRITICAL_FAILURE_GATES,
    SCORECARD_MEASURES,
    SUBJECT_ROLES,
    recommended_comparison_policy,
    recommended_metric_definitions,
)

SCHEMA_VERSION = 1
CONTRACT_DOMAIN = "sunderkey.evaluation-scorecard-receipt.v1"

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "evaluation_execution": "none",
        "filesystem_discovery": "none",
        "model_calls": "none",
        "network": "none",
        "promotion": "none",
        "provider_calls": "none",
        "qualification": "none",
        "target_actions": "none",
        "tool_calls": "none",
    }
)

METRIC_DEFINITIONS = recommended_metric_definitions()
METRIC_BY_ID = MappingProxyType({item["measure_id"]: item for item in METRIC_DEFINITIONS})
METRIC_VALUE_FIELDS = tuple(
    sorted(
        {field for item in METRIC_DEFINITIONS for field in (item["numerator"], item["denominator"])}
    )
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
MOVING_VERSIONS = frozenset({"current", "head", "latest", "main", "master", "tip"})


class EvaluationScoringRuntimeError(ValueError):
    """Raised when score inputs or a scorecard receipt fail closed."""


class ResultStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    ABSTAINED = "abstained"
    SAFETY_FAILURE = "safety_failure"


class ContaminationStatus(StrEnum):
    CLEAN = "clean"
    UNKNOWN = "unknown"
    CONTAMINATED = "contaminated"


class EvidenceStatus(StrEnum):
    COMPLETE = "complete"
    INSUFFICIENT = "insufficient"
    INVALID = "invalid"


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
        raise EvaluationScoringRuntimeError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 18:
        raise EvaluationScoringRuntimeError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvaluationScoringRuntimeError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise EvaluationScoringRuntimeError(f"{label} contains an unsupported value")


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise EvaluationScoringRuntimeError(f"{label} fields do not match the contract")
    return raw


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise EvaluationScoringRuntimeError(f"{label} must be a sequence")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise EvaluationScoringRuntimeError(f"{label} must be a safe identifier")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EvaluationScoringRuntimeError(f"{label} must be a sha256 digest")
    return value


def _version(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or VERSION_RE.fullmatch(value) is None
        or value.lower() in MOVING_VERSIONS
        or "*" in value
    ):
        raise EvaluationScoringRuntimeError(f"{label} must be an exact version")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise EvaluationScoringRuntimeError(f"{label} must be a UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise EvaluationScoringRuntimeError(f"{label} is not a valid UTC timestamp") from exc
    return value


def _bounded_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 10**15:
        raise EvaluationScoringRuntimeError(f"{label} must be a bounded integer")
    return value


def _content_identity(prefix: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": CONTRACT_DOMAIN})
    return f"{prefix}-{digest[7:39].upper()}", digest


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    case_sha256: str
    partition_type: str
    repeat_group_id: str
    run_index: int

    def __post_init__(self) -> None:
        _identifier(self.case_id, "case_id")
        _sha256(self.case_sha256, "case_sha256")
        if self.partition_type not in CORPUS_PARTITIONS:
            raise EvaluationScoringRuntimeError("partition_type is not supported")
        _identifier(self.repeat_group_id, "repeat_group_id")
        _bounded_int(self.run_index, "run_index", minimum=1)

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> EvaluationCase:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "evaluation_case"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class SubjectBinding:
    role: str
    subject_id: str
    subject_sha256: str
    owner_identity_id: str

    def __post_init__(self) -> None:
        if self.role not in SUBJECT_ROLES:
            raise EvaluationScoringRuntimeError("subject role is not supported")
        _identifier(self.subject_id, "subject_id")
        _sha256(self.subject_sha256, "subject_sha256")
        _identifier(self.owner_identity_id, "owner_identity_id")

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> SubjectBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "subject_binding"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ContaminationAttestation:
    partition_type: str
    status: ContaminationStatus
    evidence_sha256: str
    checker_identity_id: str
    checked_at: str

    def __post_init__(self) -> None:
        if self.partition_type not in CORPUS_PARTITIONS:
            raise EvaluationScoringRuntimeError("contamination partition is not supported")
        _sha256(self.evidence_sha256, "contamination evidence_sha256")
        _identifier(self.checker_identity_id, "checker_identity_id")
        _timestamp(self.checked_at, "checked_at")

    def to_dict(self) -> dict[str, str]:
        return {
            "checked_at": self.checked_at,
            "checker_identity_id": self.checker_identity_id,
            "evidence_sha256": self.evidence_sha256,
            "partition_type": self.partition_type,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ContaminationAttestation:
        item = dict(
            _exact(
                raw,
                {
                    "checked_at",
                    "checker_identity_id",
                    "evidence_sha256",
                    "partition_type",
                    "status",
                },
                "contamination_attestation",
            )
        )
        try:
            item["status"] = ContaminationStatus(item["status"])
        except ValueError as exc:
            raise EvaluationScoringRuntimeError("contamination status is invalid") from exc
        return cls(**item)


@dataclass(frozen=True, slots=True)
class BudgetObservation:
    maximum_cost_microusd: int
    maximum_latency_ms: int
    maximum_requests: int
    maximum_tokens: int
    maximum_tool_calls: int
    used_cost_microusd: int
    used_latency_ms: int
    used_requests: int
    used_tokens: int
    used_tool_calls: int

    def __post_init__(self) -> None:
        for name in (
            "maximum_cost_microusd",
            "maximum_latency_ms",
            "maximum_requests",
            "maximum_tokens",
            "maximum_tool_calls",
        ):
            _bounded_int(getattr(self, name), name, minimum=1)
        for name in (
            "used_cost_microusd",
            "used_latency_ms",
            "used_requests",
            "used_tokens",
            "used_tool_calls",
        ):
            _bounded_int(getattr(self, name), name)

    def maxima(self) -> tuple[int, ...]:
        return (
            self.maximum_cost_microusd,
            self.maximum_latency_ms,
            self.maximum_requests,
            self.maximum_tokens,
            self.maximum_tool_calls,
        )

    def exceeded_dimensions(self) -> tuple[str, ...]:
        pairs = (
            ("cost", self.used_cost_microusd, self.maximum_cost_microusd),
            ("latency", self.used_latency_ms, self.maximum_latency_ms),
            ("requests", self.used_requests, self.maximum_requests),
            ("tokens", self.used_tokens, self.maximum_tokens),
            ("tool_calls", self.used_tool_calls, self.maximum_tool_calls),
        )
        return tuple(name for name, used, maximum in pairs if used > maximum)

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> BudgetObservation:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "budget_observation"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ScoredObservation:
    case_id: str
    case_sha256: str
    partition_type: str
    subject_role: str
    subject_id: str
    subject_sha256: str
    evaluator_identity_id: str
    evidence_manifest_sha256: str
    result_status: ResultStatus
    critical_failure_gate_ids: tuple[str, ...]
    budget: BudgetObservation
    metric_values: Mapping[str, int] | None

    def __post_init__(self) -> None:
        _identifier(self.case_id, "case_id")
        _sha256(self.case_sha256, "case_sha256")
        if self.partition_type not in CORPUS_PARTITIONS:
            raise EvaluationScoringRuntimeError("observation partition is not supported")
        if self.subject_role not in SUBJECT_ROLES:
            raise EvaluationScoringRuntimeError("observation subject role is not supported")
        _identifier(self.subject_id, "subject_id")
        _sha256(self.subject_sha256, "subject_sha256")
        _identifier(self.evaluator_identity_id, "evaluator_identity_id")
        _sha256(self.evidence_manifest_sha256, "evidence_manifest_sha256")
        if tuple(sorted(set(self.critical_failure_gate_ids))) != self.critical_failure_gate_ids:
            raise EvaluationScoringRuntimeError("critical failure gates must be sorted and unique")
        if any(gate not in CRITICAL_FAILURE_GATES for gate in self.critical_failure_gate_ids):
            raise EvaluationScoringRuntimeError("observation has an unknown critical failure gate")
        safety_failure = self.result_status is ResultStatus.SAFETY_FAILURE
        if safety_failure != bool(self.critical_failure_gate_ids):
            raise EvaluationScoringRuntimeError("safety failure status and gates must agree")
        if self.result_status is ResultStatus.COMPLETED:
            if not isinstance(self.metric_values, Mapping) or set(self.metric_values) != set(
                METRIC_VALUE_FIELDS
            ):
                raise EvaluationScoringRuntimeError(
                    "completed observations require every exact metric source value"
                )
            for field in METRIC_VALUE_FIELDS:
                _bounded_int(self.metric_values[field], f"metric_values.{field}")
        elif self.metric_values is not None:
            raise EvaluationScoringRuntimeError(
                "non-completed observations cannot claim metric source values"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget": self.budget.to_dict(),
            "case_id": self.case_id,
            "case_sha256": self.case_sha256,
            "critical_failure_gate_ids": list(self.critical_failure_gate_ids),
            "evaluator_identity_id": self.evaluator_identity_id,
            "evidence_manifest_sha256": self.evidence_manifest_sha256,
            "metric_values": (
                None if self.metric_values is None else dict(sorted(self.metric_values.items()))
            ),
            "partition_type": self.partition_type,
            "result_status": self.result_status.value,
            "subject_id": self.subject_id,
            "subject_role": self.subject_role,
            "subject_sha256": self.subject_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ScoredObservation:
        fields = {
            "budget",
            "case_id",
            "case_sha256",
            "critical_failure_gate_ids",
            "evaluator_identity_id",
            "evidence_manifest_sha256",
            "metric_values",
            "partition_type",
            "result_status",
            "subject_id",
            "subject_role",
            "subject_sha256",
        }
        item = dict(_exact(raw, fields, "scored_observation"))
        try:
            item["result_status"] = ResultStatus(item["result_status"])
        except ValueError as exc:
            raise EvaluationScoringRuntimeError("result_status is invalid") from exc
        item["critical_failure_gate_ids"] = tuple(
            _sequence(item["critical_failure_gate_ids"], "critical_failure_gate_ids")
        )
        item["budget"] = BudgetObservation.from_dict(item["budget"])
        values = item["metric_values"]
        if values is not None:
            if not isinstance(values, Mapping):
                raise EvaluationScoringRuntimeError("metric_values must be an object or null")
            item["metric_values"] = dict(values)
        return cls(**item)


def _validate_cases(
    cases: Sequence[EvaluationCase],
    minimum_cases_per_partition: int,
    minimum_repeated_runs: int,
) -> tuple[EvaluationCase, ...]:
    values = tuple(cases)
    if not values or tuple(sorted(values, key=lambda item: item.case_id)) != values:
        raise EvaluationScoringRuntimeError("evaluation cases must be nonempty and sorted")
    if len({item.case_id for item in values}) != len(values):
        raise EvaluationScoringRuntimeError("evaluation case identifiers must be unique")
    counts = {
        partition: sum(item.partition_type == partition for item in values)
        for partition in CORPUS_PARTITIONS
    }
    if any(counts[partition] < minimum_cases_per_partition for partition in CORPUS_PARTITIONS):
        raise EvaluationScoringRuntimeError("every corpus partition must meet the sample minimum")
    groups: dict[str, list[EvaluationCase]] = {}
    for item in values:
        groups.setdefault(item.repeat_group_id, []).append(item)
    for group in groups.values():
        if len(group) < minimum_repeated_runs:
            raise EvaluationScoringRuntimeError("every repeat group must meet the run minimum")
        if len({item.partition_type for item in group}) != 1:
            raise EvaluationScoringRuntimeError("repeat groups cannot cross corpus partitions")
        if tuple(sorted(item.run_index for item in group)) != tuple(range(1, len(group) + 1)):
            raise EvaluationScoringRuntimeError("repeat group run indexes must be contiguous")
    return values


def _validate_subjects(subjects: Sequence[SubjectBinding]) -> tuple[SubjectBinding, ...]:
    values = tuple(subjects)
    if tuple(item.role for item in values) != SUBJECT_ROLES:
        raise EvaluationScoringRuntimeError("subjects must contain every role in fixed order")
    if len({item.subject_id for item in values}) != len(values):
        raise EvaluationScoringRuntimeError("subject identifiers must be unique")
    if len({item.owner_identity_id for item in values}) != len(values):
        raise EvaluationScoringRuntimeError("subject owners must be distinct")
    return values


def _validate_attestations(
    attestations: Sequence[ContaminationAttestation],
) -> tuple[ContaminationAttestation, ...]:
    values = tuple(attestations)
    if tuple(item.partition_type for item in values) != CORPUS_PARTITIONS:
        raise EvaluationScoringRuntimeError(
            "contamination attestations must cover every partition in fixed order"
        )
    if len({item.evidence_sha256 for item in values}) != len(values):
        raise EvaluationScoringRuntimeError("contamination evidence identities must be unique")
    return values


def _metric_value(definition: Mapping[str, Any], numerator: int, denominator: int) -> int:
    if definition["unit"] == "basis_points":
        return numerator * 10_000 // denominator
    if definition["unit"] == "count":
        return numerator
    return numerator // denominator


def _passes(value: int, threshold: int, direction: str) -> bool:
    if direction == "higher_is_better":
        return value >= threshold
    return value <= threshold


def _reason(code: str, *parts: str) -> str:
    return ":".join((code, *parts))


def _budget_summary(observations: Sequence[ScoredObservation]) -> dict[str, int]:
    maximum = sum(item.budget.maximum_cost_microusd for item in observations)
    used = sum(item.budget.used_cost_microusd for item in observations)
    return {
        "maximum_cost_microusd": maximum,
        "normalized_cost_basis_points": 0 if maximum == 0 else used * 10_000 // maximum,
        "used_cost_microusd": used,
    }


def _subject_score(
    subject: SubjectBinding,
    observations: Sequence[ScoredObservation],
    *,
    global_invalid: bool,
) -> dict[str, Any]:
    completed = [item for item in observations if item.result_status is ResultStatus.COMPLETED]
    hard_gates = tuple(
        sorted({gate for item in observations for gate in item.critical_failure_gate_ids})
    )
    incomplete = any(
        item.result_status in {ResultStatus.FAILED, ResultStatus.ABSTAINED} for item in observations
    )
    missing_values = len(completed) != len(observations) and not hard_gates
    aggregate = {
        field: sum((item.metric_values or {}).get(field, 0) for item in completed)
        for field in METRIC_VALUE_FIELDS
    }
    metric_results: list[dict[str, Any]] = []
    metric_hard_gates: set[str] = set()
    metric_insufficient = False
    scored_fail = False
    for definition in METRIC_DEFINITIONS:
        numerator = aggregate[definition["numerator"]]
        denominator = aggregate[definition["denominator"]]
        confidence_status = "sufficient"
        value: int | None = None
        if global_invalid:
            outcome = "invalid_evidence"
            confidence_status = "insufficient"
        elif hard_gates:
            outcome = "hard_stop"
            confidence_status = "insufficient"
        elif incomplete or missing_values or denominator < definition["minimum_denominator"]:
            outcome = "insufficient"
            confidence_status = "insufficient"
            metric_insufficient = True
        else:
            value = _metric_value(definition, numerator, denominator)
            passed = _passes(value, definition["pass_threshold"], definition["direction"])
            outcome = "pass" if passed else "fail"
            scored_fail = scored_fail or not passed
            critical_threshold = definition["critical_failure_threshold"]
            if critical_threshold is not None and not _passes(
                value, critical_threshold, definition["direction"]
            ):
                metric_hard_gates.update(definition["critical_gate_ids"])
                outcome = "hard_stop"
        metric_results.append(
            {
                "confidence_status": confidence_status,
                "denominator": denominator,
                "direction": definition["direction"],
                "measure_id": definition["measure_id"],
                "minimum_denominator": definition["minimum_denominator"],
                "numerator": numerator,
                "outcome": outcome,
                "pass_threshold": definition["pass_threshold"],
                "sample_count": len(completed),
                "unit": definition["unit"],
                "value": value,
            }
        )
    all_hard_gates = tuple(sorted(set(hard_gates) | metric_hard_gates))
    if global_invalid:
        disposition = "invalid_evidence"
    elif all_hard_gates:
        disposition = "hard_failure"
    elif incomplete or missing_values or metric_insufficient:
        disposition = "insufficient_evidence"
    elif scored_fail:
        disposition = "scored_fail"
    else:
        disposition = "scored_pass"
    return {
        "budget_summary": _budget_summary(observations),
        "disposition": disposition,
        "hard_failure_gate_ids": list(all_hard_gates),
        "metric_results": metric_results,
        "observation_count": len(observations),
        "role": subject.role,
        "subject_id": subject.subject_id,
        "subject_sha256": subject.subject_sha256,
    }


def _comparisons(
    scores: Sequence[Mapping[str, Any]], regression_thresholds: Mapping[str, int]
) -> list[dict[str, Any]]:
    by_role = {item["role"]: item for item in scores}
    candidate = by_role["candidate"]
    result: list[dict[str, Any]] = []
    candidate_metrics = {item["measure_id"]: item for item in candidate["metric_results"]}
    for role in recommended_comparison_policy()["baseline_roles"]:
        baseline = by_role[role]
        baseline_metrics = {item["measure_id"]: item for item in baseline["metric_results"]}
        for measure_id in SCORECARD_MEASURES:
            candidate_metric = candidate_metrics[measure_id]
            baseline_metric = baseline_metrics[measure_id]
            candidate_value = candidate_metric["value"]
            baseline_value = baseline_metric["value"]
            directional_delta: int | None = None
            if "invalid_evidence" in {
                candidate_metric["outcome"],
                baseline_metric["outcome"],
            }:
                status = "invalid_evidence"
            elif "hard_stop" in {
                candidate_metric["outcome"],
                baseline_metric["outcome"],
            }:
                status = "hard_stop"
            elif candidate_value is None or baseline_value is None:
                status = "insufficient"
            else:
                definition = METRIC_BY_ID[measure_id]
                if definition["direction"] == "higher_is_better":
                    directional_delta = candidate_value - baseline_value
                else:
                    directional_delta = baseline_value - candidate_value
                if directional_delta < -regression_thresholds[measure_id]:
                    status = "regression"
                elif directional_delta > 0:
                    status = "improvement"
                else:
                    status = "no_improvement"
            result.append(
                {
                    "baseline_role": role,
                    "baseline_value": baseline_value,
                    "candidate_value": candidate_value,
                    "confidence_status": (
                        "sufficient" if directional_delta is not None else "insufficient"
                    ),
                    "directional_delta": directional_delta,
                    "measure_id": measure_id,
                    "regression_threshold": regression_thresholds[measure_id],
                    "status": status,
                }
            )
    return result


@dataclass(frozen=True, slots=True)
class EvaluationScorecardReceipt:
    receipt_id: str
    receipt_sha256: str
    document_json: str
    contract_type: ClassVar[str] = "evaluation_scorecard_receipt"

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> EvaluationScorecardReceipt:
        fields = {
            "bindings",
            "contract_type",
            "effects",
            "observations",
            "receipt_id",
            "receipt_sha256",
            "result",
            "schema_version",
            "scoring_context",
        }
        value = _exact(raw, fields, "evaluation_scorecard_receipt")
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != SCHEMA_VERSION
            or value["contract_type"] != cls.contract_type
        ):
            raise EvaluationScoringRuntimeError("receipt discriminator is invalid")
        if value["effects"] != dict(NO_EFFECTS):
            raise EvaluationScoringRuntimeError("receipt effects must all remain none")
        bindings = _exact(
            value["bindings"],
            {
                "evaluation_program_contract_id",
                "evaluation_program_contract_sha256",
                "result_manifest_sha256",
            },
            "bindings",
        )
        context = _exact(
            value["scoring_context"],
            {
                "calculated_at",
                "contamination_attestations",
                "evaluation_cases",
                "evaluator_identity_ids",
                "minimum_cases_per_partition",
                "minimum_repeated_runs",
                "regression_thresholds",
                "scorecard_version",
                "scoring_controller_identity_id",
                "subjects",
            },
            "scoring_context",
        )
        cases = tuple(
            EvaluationCase.from_dict(item)
            for item in _sequence(context["evaluation_cases"], "evaluation_cases")
        )
        subjects = tuple(
            SubjectBinding.from_dict(item) for item in _sequence(context["subjects"], "subjects")
        )
        attestations = tuple(
            ContaminationAttestation.from_dict(item)
            for item in _sequence(
                context["contamination_attestations"], "contamination_attestations"
            )
        )
        observations = tuple(
            ScoredObservation.from_dict(item)
            for item in _sequence(value["observations"], "observations")
        )
        thresholds = context["regression_thresholds"]
        if not isinstance(thresholds, Mapping):
            raise EvaluationScoringRuntimeError("regression_thresholds must be an object")
        rebuilt = build_evaluation_scorecard_receipt(
            evaluation_program_contract_id=bindings["evaluation_program_contract_id"],
            evaluation_program_contract_sha256=bindings["evaluation_program_contract_sha256"],
            result_manifest_sha256=bindings["result_manifest_sha256"],
            scorecard_version=context["scorecard_version"],
            calculated_at=context["calculated_at"],
            scoring_controller_identity_id=context["scoring_controller_identity_id"],
            evaluator_identity_ids=tuple(
                _sequence(context["evaluator_identity_ids"], "evaluator_identity_ids")
            ),
            evaluation_cases=cases,
            subjects=subjects,
            contamination_attestations=attestations,
            observations=observations,
            minimum_cases_per_partition=context["minimum_cases_per_partition"],
            minimum_repeated_runs=context["minimum_repeated_runs"],
            regression_thresholds=dict(thresholds),
        )
        if canonical_json(rebuilt.to_dict()) != canonical_json(dict(value)):
            raise EvaluationScoringRuntimeError("receipt content or identity does not match")
        return rebuilt

    @classmethod
    def from_json(cls, raw: str) -> EvaluationScorecardReceipt:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 16 * 1024 * 1024:
            raise EvaluationScoringRuntimeError("scorecard receipt exceeds the byte limit")
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
            raise EvaluationScoringRuntimeError("scorecard receipt is not valid JSON") from exc
        return cls.from_dict(value)


def build_evaluation_scorecard_receipt(
    *,
    evaluation_program_contract_id: str,
    evaluation_program_contract_sha256: str,
    result_manifest_sha256: str,
    scorecard_version: str,
    calculated_at: str,
    scoring_controller_identity_id: str,
    evaluator_identity_ids: Sequence[str],
    evaluation_cases: Sequence[EvaluationCase],
    subjects: Sequence[SubjectBinding],
    contamination_attestations: Sequence[ContaminationAttestation],
    observations: Sequence[ScoredObservation],
    minimum_cases_per_partition: int,
    minimum_repeated_runs: int,
    regression_thresholds: Mapping[str, int],
) -> EvaluationScorecardReceipt:
    """Calculate a deterministic scorecard from caller-supplied observations."""

    _identifier(evaluation_program_contract_id, "evaluation_program_contract_id")
    _sha256(evaluation_program_contract_sha256, "evaluation_program_contract_sha256")
    _sha256(result_manifest_sha256, "result_manifest_sha256")
    _version(scorecard_version, "scorecard_version")
    _timestamp(calculated_at, "calculated_at")
    _identifier(scoring_controller_identity_id, "scoring_controller_identity_id")
    minimum_cases_per_partition = _bounded_int(
        minimum_cases_per_partition, "minimum_cases_per_partition", minimum=1
    )
    minimum_repeated_runs = _bounded_int(minimum_repeated_runs, "minimum_repeated_runs", minimum=3)
    if minimum_repeated_runs != recommended_comparison_policy()["minimum_repeated_runs"]:
        raise EvaluationScoringRuntimeError("minimum repeated runs must match comparison policy")

    evaluators = tuple(evaluator_identity_ids)
    if len(evaluators) < 2 or tuple(sorted(set(evaluators))) != evaluators:
        raise EvaluationScoringRuntimeError(
            "at least two evaluator identities must be unique and sorted"
        )
    for evaluator in evaluators:
        _identifier(evaluator, "evaluator_identity_id")

    normalized_cases = _validate_cases(
        evaluation_cases, minimum_cases_per_partition, minimum_repeated_runs
    )
    normalized_subjects = _validate_subjects(subjects)
    owners = {item.owner_identity_id for item in normalized_subjects}
    if owners.intersection(evaluators) or scoring_controller_identity_id in owners.union(
        evaluators
    ):
        raise EvaluationScoringRuntimeError(
            "subjects, evaluators, and scoring controller identities must be separate"
        )
    attestations = _validate_attestations(contamination_attestations)

    if set(regression_thresholds) != set(SCORECARD_MEASURES):
        raise EvaluationScoringRuntimeError("regression thresholds must cover every measure")
    thresholds = {
        measure_id: _bounded_int(
            regression_thresholds[measure_id], f"regression_thresholds.{measure_id}"
        )
        for measure_id in SCORECARD_MEASURES
    }

    values = tuple(observations)
    if tuple(sorted(values, key=lambda item: (item.case_id, item.subject_role))) != values:
        raise EvaluationScoringRuntimeError("scored observations must be sorted")
    keys = [(item.case_id, item.subject_role) for item in values]
    if len(set(keys)) != len(keys):
        raise EvaluationScoringRuntimeError("duplicate scored observations are forbidden")
    cases_by_id = {item.case_id: item for item in normalized_cases}
    subjects_by_role = {item.role: item for item in normalized_subjects}
    for item in values:
        case = cases_by_id.get(item.case_id)
        subject = subjects_by_role[item.subject_role]
        if case is None:
            raise EvaluationScoringRuntimeError("observation references an unknown case")
        if (
            item.case_sha256 != case.case_sha256
            or item.partition_type != case.partition_type
            or item.subject_id != subject.subject_id
            or item.subject_sha256 != subject.subject_sha256
        ):
            raise EvaluationScoringRuntimeError("observation crosses its bound case or subject")
        if item.evaluator_identity_id not in evaluators:
            raise EvaluationScoringRuntimeError(
                "observation evaluator is not authorized for scoring"
            )

    expected_keys = {
        (case.case_id, subject.role) for case in normalized_cases for subject in normalized_subjects
    }
    observed_keys = set(keys)
    missing_keys = expected_keys - observed_keys

    invalid_reasons: set[str] = set()
    insufficient_reasons: set[str] = set()
    if len({item.evidence_manifest_sha256 for item in values}) != len(values):
        invalid_reasons.add("duplicate_evidence_identity")
    represented_evaluators = {item.evaluator_identity_id for item in values}
    for evaluator in set(evaluators) - represented_evaluators:
        insufficient_reasons.add(_reason("evaluator_has_no_observations", evaluator))
    for item in attestations:
        if item.status is ContaminationStatus.CONTAMINATED:
            invalid_reasons.add(_reason("contaminated_partition", item.partition_type))
        elif item.status is ContaminationStatus.UNKNOWN:
            insufficient_reasons.add(_reason("unknown_contamination_status", item.partition_type))
    for case_id, role in missing_keys:
        insufficient_reasons.add(_reason("missing_observation", case_id, role))
    for item in values:
        for dimension in item.budget.exceeded_dimensions():
            invalid_reasons.add(
                _reason("budget_exceeded", item.case_id, item.subject_role, dimension)
            )
        if item.result_status in {ResultStatus.FAILED, ResultStatus.ABSTAINED}:
            insufficient_reasons.add(
                _reason("incomplete_observation", item.case_id, item.subject_role)
            )
        if item.metric_values is not None:
            if item.metric_values["evaluation_cost_micro_usd"] != item.budget.used_cost_microusd:
                invalid_reasons.add(
                    _reason("cost_observation_mismatch", item.case_id, item.subject_role)
                )
            if item.metric_values["completed_evaluation_runs"] != 1:
                invalid_reasons.add(
                    _reason("completed_run_count_invalid", item.case_id, item.subject_role)
                )
            for definition in METRIC_DEFINITIONS:
                if definition["unit"] != "basis_points":
                    continue
                numerator = item.metric_values[definition["numerator"]]
                denominator = item.metric_values[definition["denominator"]]
                if denominator and numerator > denominator:
                    invalid_reasons.add(
                        _reason(
                            "metric_ratio_invalid",
                            item.case_id,
                            item.subject_role,
                            definition["measure_id"],
                        )
                    )

    for case in normalized_cases:
        case_observations = [item for item in values if item.case_id == case.case_id]
        profiles = {item.budget.maxima() for item in case_observations}
        if len(profiles) > 1:
            invalid_reasons.add(_reason("unpaired_budget", case.case_id))

    if invalid_reasons:
        evidence_status = EvidenceStatus.INVALID
    elif insufficient_reasons:
        evidence_status = EvidenceStatus.INSUFFICIENT
    else:
        evidence_status = EvidenceStatus.COMPLETE

    observations_by_role = {
        role: [item for item in values if item.subject_role == role] for role in SUBJECT_ROLES
    }
    subject_scores = [
        _subject_score(
            subject,
            observations_by_role[subject.role],
            global_invalid=bool(invalid_reasons),
        )
        for subject in normalized_subjects
    ]
    comparisons = _comparisons(subject_scores, thresholds)
    candidate_score = next(item for item in subject_scores if item["role"] == "candidate")
    comparison_regression = any(item["status"] == "regression" for item in comparisons)
    if evidence_status is EvidenceStatus.INVALID:
        candidate_disposition = "invalid_evidence"
    elif candidate_score["disposition"] == "hard_failure":
        candidate_disposition = "hard_failure"
    elif (
        evidence_status is EvidenceStatus.INSUFFICIENT
        or candidate_score["disposition"] == "insufficient_evidence"
    ):
        candidate_disposition = "insufficient_evidence"
    elif candidate_score["disposition"] == "scored_fail":
        candidate_disposition = "scored_fail"
    elif comparison_regression:
        candidate_disposition = "regression"
    else:
        candidate_disposition = "scored_pass"

    promotion_disposition = (
        "independent_review_required" if candidate_disposition == "scored_pass" else "blocked"
    )
    result = {
        "candidate_disposition": candidate_disposition,
        "comparisons": comparisons,
        "evidence_status": evidence_status.value,
        "independent_review_location": "outside_runtime",
        "invalid_reason_codes": sorted(invalid_reasons),
        "metric_definition_sha256": canonical_sha256(list(METRIC_DEFINITIONS)),
        "promotion_disposition": promotion_disposition,
        "qualification_effect": "none",
        "scorecard_measure_ids": list(SCORECARD_MEASURES),
        "subject_scores": subject_scores,
        "insufficiency_reason_codes": sorted(insufficient_reasons),
    }
    context = {
        "calculated_at": calculated_at,
        "contamination_attestations": [item.to_dict() for item in attestations],
        "evaluation_cases": [item.to_dict() for item in normalized_cases],
        "evaluator_identity_ids": list(evaluators),
        "minimum_cases_per_partition": minimum_cases_per_partition,
        "minimum_repeated_runs": minimum_repeated_runs,
        "regression_thresholds": thresholds,
        "scorecard_version": scorecard_version,
        "scoring_controller_identity_id": scoring_controller_identity_id,
        "subjects": [item.to_dict() for item in normalized_subjects],
    }
    body = {
        "bindings": {
            "evaluation_program_contract_id": evaluation_program_contract_id,
            "evaluation_program_contract_sha256": evaluation_program_contract_sha256,
            "result_manifest_sha256": result_manifest_sha256,
        },
        "contract_type": EvaluationScorecardReceipt.contract_type,
        "effects": dict(NO_EFFECTS),
        "observations": [item.to_dict() for item in values],
        "result": result,
        "schema_version": SCHEMA_VERSION,
        "scoring_context": context,
    }
    receipt_id, receipt_sha256 = _content_identity("ESR", body)
    document = {**body, "receipt_id": receipt_id, "receipt_sha256": receipt_sha256}
    document_json = canonical_json(document)
    if len(document_json.encode("ascii")) > 16 * 1024 * 1024:
        raise EvaluationScoringRuntimeError("scorecard receipt exceeds the byte limit")
    return EvaluationScorecardReceipt(receipt_id, receipt_sha256, document_json)


def verify_evaluation_scorecard_receipt(receipt: EvaluationScorecardReceipt) -> None:
    """Verify the receipt content, calculations, and deterministic identity."""

    if not isinstance(receipt, EvaluationScorecardReceipt):
        raise EvaluationScoringRuntimeError("receipt has the wrong type")
    rebuilt = EvaluationScorecardReceipt.from_json(receipt.document_json)
    if rebuilt != receipt:
        raise EvaluationScoringRuntimeError("scorecard receipt verification failed")
