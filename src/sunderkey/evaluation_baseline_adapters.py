"""Repository-only replay adapters for content-addressed evaluation baselines.

The adapters accept caller-supplied observations and produce immutable replay
envelopes. They do not discover files, resolve credentials, call providers,
execute models, invoke tools, start processes, access targets, or use a
network. Every envelope is nonqualifying and records no operational effects.
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
    SUBJECT_ROLES,
)
from sunderkey.evaluation_scoring_runtime import (
    METRIC_VALUE_FIELDS,
    BudgetObservation,
    ScoredObservation,
)
from sunderkey.evaluation_scoring_runtime import ResultStatus as ScoringResultStatus

SCHEMA_VERSION = 1
OBSERVATION_DOMAIN = "sunderkey.evaluation-baseline-observation.v1"
ENVELOPE_DOMAIN = "sunderkey.evaluation-baseline-replay-envelope.v1"

BASELINE_ROLES = tuple(role for role in SUBJECT_ROLES if role != "candidate")

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credential_access": "none",
        "evaluation_execution": "none",
        "filesystem_discovery": "none",
        "model_calls": "none",
        "network": "none",
        "process_execution": "none",
        "provider_calls": "none",
        "qualification": "none",
        "target_actions": "none",
        "tool_calls": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
MOVING_REVISIONS = frozenset({"current", "head", "latest", "main", "master", "tip"})


class BaselineReplayContractError(ValueError):
    """Raised when baseline replay input fails closed."""


class AdapterKind(StrEnum):
    DETERMINISTIC_RULES = "deterministic_rules"
    STORED_MODEL_SNAPSHOT = "stored_model_snapshot"
    STRATEGY_VARIANT = "strategy_variant"
    HUMAN_REFERENCE_INPUT = "human_reference_input"


class BaselineStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class ContaminationStatus(StrEnum):
    CLEAN = "clean"
    UNKNOWN = "unknown"
    CONTAMINATED = "contaminated"


class ScoringImportStatus(StrEnum):
    AVAILABLE = "available"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    BLOCKED_CONTAMINATION = "blocked_contamination"


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
        raise BaselineReplayContractError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 18:
        raise BaselineReplayContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise BaselineReplayContractError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise BaselineReplayContractError(f"{label} contains an unsupported value")


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise BaselineReplayContractError(f"{label} fields do not match the contract")
    return raw


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise BaselineReplayContractError(f"{label} must be a safe identifier")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise BaselineReplayContractError(f"{label} must be a sha256 digest")
    return value


def _revision(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or VERSION_RE.fullmatch(value) is None
        or value.lower() in MOVING_REVISIONS
        or "*" in value
    ):
        raise BaselineReplayContractError(f"{label} must be an exact revision")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise BaselineReplayContractError(f"{label} must be a UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise BaselineReplayContractError(f"{label} is not a valid UTC timestamp") from exc
    return value


def _bounded_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 10**15:
        raise BaselineReplayContractError(f"{label} must be a bounded integer")
    return value


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise BaselineReplayContractError(f"{label} must be a sequence")
    return value


def _content_identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _enum(enum_type: type[StrEnum], raw: Any, label: str) -> StrEnum:
    try:
        return enum_type(raw)
    except (TypeError, ValueError) as exc:
        raise BaselineReplayContractError(f"{label} is invalid") from exc


@dataclass(frozen=True, slots=True)
class BaselineBudget:
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
        pairs = (
            (self.used_cost_microusd, self.maximum_cost_microusd),
            (self.used_latency_ms, self.maximum_latency_ms),
            (self.used_requests, self.maximum_requests),
            (self.used_tokens, self.maximum_tokens),
            (self.used_tool_calls, self.maximum_tool_calls),
        )
        if any(used > maximum for used, maximum in pairs):
            raise BaselineReplayContractError("observed usage exceeds the bound budget")
        if self.used_tool_calls != 0:
            raise BaselineReplayContractError("baseline replay forbids tool usage")

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> BaselineBudget:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "baseline_budget"))  # type: ignore[arg-type]

    def to_scoring_budget(self) -> BudgetObservation:
        return BudgetObservation(**self.to_dict())


@dataclass(frozen=True, slots=True)
class ContaminationAttestation:
    partition_type: str
    status: ContaminationStatus
    evidence_sha256: str
    checker_identity_id: str
    checked_at: str

    def __post_init__(self) -> None:
        if self.partition_type not in CORPUS_PARTITIONS:
            raise BaselineReplayContractError("contamination partition is not supported")
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
        item = dict(_exact(raw, set(cls.__dataclass_fields__), "contamination"))
        item["status"] = _enum(ContaminationStatus, item["status"], "contamination status")
        return cls(**item)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ReplayProvenance:
    source_artifact_id: str
    source_artifact_sha256: str
    custody_manifest_sha256: str
    producer_identity_id: str
    captured_at: str

    def __post_init__(self) -> None:
        _identifier(self.source_artifact_id, "source_artifact_id")
        _sha256(self.source_artifact_sha256, "source_artifact_sha256")
        _sha256(self.custody_manifest_sha256, "custody_manifest_sha256")
        _identifier(self.producer_identity_id, "producer_identity_id")
        _timestamp(self.captured_at, "captured_at")

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: Any) -> ReplayProvenance:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "replay_provenance"))  # type: ignore[arg-type]


_ALLOWED_ROLES = MappingProxyType(
    {
        AdapterKind.DETERMINISTIC_RULES: frozenset({"deterministic"}),
        AdapterKind.STORED_MODEL_SNAPSHOT: frozenset({"generalist", "prior_release"}),
        AdapterKind.STRATEGY_VARIANT: frozenset({"generalist", "prior_release"}),
        AdapterKind.HUMAN_REFERENCE_INPUT: frozenset({"generalist"}),
    }
)


@dataclass(frozen=True, slots=True)
class BaselineObservation:
    adapter_kind: AdapterKind
    subject_role: str
    subject_id: str
    subject_sha256: str
    subject_owner_identity_id: str
    case_id: str
    case_sha256: str
    partition_type: str
    implementation_id: str
    implementation_revision: str
    implementation_sha256: str
    prompt_sha256: str
    policy_sha256: str
    expected_output_sha256: str
    observed_output_sha256: str | None
    tools_allowed: bool
    result_status: BaselineStatus
    budget: BaselineBudget
    contamination: ContaminationAttestation
    evaluator_identity_id: str
    provenance: ReplayProvenance
    metric_values: Mapping[str, int] | None
    observation_id: str
    observation_sha256: str
    contract_type: ClassVar[str] = "baseline_observation"

    def __post_init__(self) -> None:
        if self.subject_role not in BASELINE_ROLES:
            raise BaselineReplayContractError("subject_role must be a baseline role")
        if self.subject_role not in _ALLOWED_ROLES[self.adapter_kind]:
            raise BaselineReplayContractError("adapter kind is not valid for the subject role")
        for value, label in (
            (self.subject_id, "subject_id"),
            (self.subject_owner_identity_id, "subject_owner_identity_id"),
            (self.case_id, "case_id"),
            (self.implementation_id, "implementation_id"),
            (self.evaluator_identity_id, "evaluator_identity_id"),
        ):
            _identifier(value, label)
        for value, label in (
            (self.subject_sha256, "subject_sha256"),
            (self.case_sha256, "case_sha256"),
            (self.implementation_sha256, "implementation_sha256"),
            (self.prompt_sha256, "prompt_sha256"),
            (self.policy_sha256, "policy_sha256"),
            (self.expected_output_sha256, "expected_output_sha256"),
        ):
            _sha256(value, label)
        if self.observed_output_sha256 is not None:
            _sha256(self.observed_output_sha256, "observed_output_sha256")
        _revision(self.implementation_revision, "implementation_revision")
        if self.partition_type not in CORPUS_PARTITIONS:
            raise BaselineReplayContractError("partition_type is not supported")
        if self.contamination.partition_type != self.partition_type:
            raise BaselineReplayContractError("contamination partition crosses observation context")
        if self.tools_allowed is not False:
            raise BaselineReplayContractError("tools_allowed must remain false")
        protected = {
            self.subject_owner_identity_id,
            self.provenance.producer_identity_id,
        }
        if self.evaluator_identity_id in protected:
            raise BaselineReplayContractError(
                "evaluator identity cannot overlap baseline ownership"
            )
        if self.result_status is BaselineStatus.COMPLETED:
            if self.observed_output_sha256 is None:
                raise BaselineReplayContractError("completed baseline requires an observed output")
            if not isinstance(self.metric_values, Mapping) or set(self.metric_values) != set(
                METRIC_VALUE_FIELDS
            ):
                raise BaselineReplayContractError(
                    "completed baseline requires every exact scoring source value"
                )
            for field in METRIC_VALUE_FIELDS:
                _bounded_int(self.metric_values[field], f"metric_values.{field}")
        elif self.metric_values is not None:
            raise BaselineReplayContractError(
                "failed and unavailable baselines cannot claim scoring values"
            )
        if self.result_status is BaselineStatus.UNAVAILABLE:
            if self.observed_output_sha256 is not None:
                raise BaselineReplayContractError("unavailable baseline cannot claim output")
            if any(
                (
                    self.budget.used_cost_microusd,
                    self.budget.used_latency_ms,
                    self.budget.used_requests,
                    self.budget.used_tokens,
                    self.budget.used_tool_calls,
                )
            ):
                raise BaselineReplayContractError("unavailable baseline cannot claim usage")
        expected_id, expected_sha = _content_identity("EBO", OBSERVATION_DOMAIN, self._body())
        if self.observation_id != expected_id or self.observation_sha256 != expected_sha:
            raise BaselineReplayContractError("baseline observation identity does not match")

    @property
    def scoring_import_status(self) -> ScoringImportStatus:
        if self.contamination.status is not ContaminationStatus.CLEAN:
            return ScoringImportStatus.BLOCKED_CONTAMINATION
        if self.result_status is BaselineStatus.COMPLETED:
            return ScoringImportStatus.AVAILABLE
        if self.result_status is BaselineStatus.FAILED:
            return ScoringImportStatus.FAILED
        return ScoringImportStatus.UNAVAILABLE

    def _body(self) -> dict[str, Any]:
        return {
            "adapter_kind": self.adapter_kind.value,
            "budget": self.budget.to_dict(),
            "case_id": self.case_id,
            "case_sha256": self.case_sha256,
            "contamination": self.contamination.to_dict(),
            "contract_type": self.contract_type,
            "effects": dict(NO_EFFECTS),
            "evaluator_identity_id": self.evaluator_identity_id,
            "expected_output_sha256": self.expected_output_sha256,
            "implementation_id": self.implementation_id,
            "implementation_revision": self.implementation_revision,
            "implementation_sha256": self.implementation_sha256,
            "metric_values": (
                None if self.metric_values is None else dict(sorted(self.metric_values.items()))
            ),
            "observed_output_sha256": self.observed_output_sha256,
            "partition_type": self.partition_type,
            "policy_sha256": self.policy_sha256,
            "prompt_sha256": self.prompt_sha256,
            "provenance": self.provenance.to_dict(),
            "qualification_effect": "none",
            "result_status": self.result_status.value,
            "schema_version": SCHEMA_VERSION,
            "subject_id": self.subject_id,
            "subject_owner_identity_id": self.subject_owner_identity_id,
            "subject_role": self.subject_role,
            "subject_sha256": self.subject_sha256,
            "tools_allowed": self.tools_allowed,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "scoring_import_status": self.scoring_import_status.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> BaselineObservation:
        fields = {
            "adapter_kind",
            "budget",
            "case_id",
            "case_sha256",
            "contamination",
            "contract_type",
            "effects",
            "evaluator_identity_id",
            "expected_output_sha256",
            "implementation_id",
            "implementation_revision",
            "implementation_sha256",
            "metric_values",
            "observation_id",
            "observation_sha256",
            "observed_output_sha256",
            "partition_type",
            "policy_sha256",
            "prompt_sha256",
            "provenance",
            "qualification_effect",
            "result_status",
            "schema_version",
            "scoring_import_status",
            "subject_id",
            "subject_owner_identity_id",
            "subject_role",
            "subject_sha256",
            "tools_allowed",
        }
        item = dict(_exact(raw, fields, "baseline_observation"))
        if (
            type(item["schema_version"]) is not int
            or item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("contract_type") != cls.contract_type
            or item.pop("qualification_effect") != "none"
            or item.pop("effects") != dict(NO_EFFECTS)
        ):
            raise BaselineReplayContractError("baseline observation discriminator is invalid")
        declared_import = item.pop("scoring_import_status")
        item["adapter_kind"] = _enum(AdapterKind, item["adapter_kind"], "adapter_kind")
        item["result_status"] = _enum(BaselineStatus, item["result_status"], "result_status")
        item["budget"] = BaselineBudget.from_dict(item["budget"])
        item["contamination"] = ContaminationAttestation.from_dict(item["contamination"])
        item["provenance"] = ReplayProvenance.from_dict(item["provenance"])
        metrics = item["metric_values"]
        if metrics is not None:
            if not isinstance(metrics, Mapping):
                raise BaselineReplayContractError("metric_values must be an object or null")
            item["metric_values"] = dict(metrics)
        result = cls(**item)  # type: ignore[arg-type]
        if declared_import != result.scoring_import_status.value:
            raise BaselineReplayContractError("scoring import status does not match observation")
        return result

    def to_scored_observation(self) -> ScoredObservation:
        if self.contamination.status is not ContaminationStatus.CLEAN:
            raise BaselineReplayContractError(
                "contaminated or unknown baseline cannot enter scoring"
            )
        status = {
            BaselineStatus.COMPLETED: ScoringResultStatus.COMPLETED,
            BaselineStatus.FAILED: ScoringResultStatus.FAILED,
            BaselineStatus.UNAVAILABLE: ScoringResultStatus.ABSTAINED,
        }[self.result_status]
        return ScoredObservation(
            case_id=self.case_id,
            case_sha256=self.case_sha256,
            partition_type=self.partition_type,
            subject_role=self.subject_role,
            subject_id=self.subject_id,
            subject_sha256=self.subject_sha256,
            evaluator_identity_id=self.evaluator_identity_id,
            evidence_manifest_sha256=self.observation_sha256,
            result_status=status,
            critical_failure_gate_ids=(),
            budget=self.budget.to_scoring_budget(),
            metric_values=self.metric_values,
        )


def build_baseline_observation(
    *,
    adapter_kind: AdapterKind,
    subject_role: str,
    subject_id: str,
    subject_sha256: str,
    subject_owner_identity_id: str,
    case_id: str,
    case_sha256: str,
    partition_type: str,
    implementation_id: str,
    implementation_revision: str,
    implementation_sha256: str,
    prompt_sha256: str,
    policy_sha256: str,
    expected_output_sha256: str,
    observed_output_sha256: str | None,
    tools_allowed: bool,
    result_status: BaselineStatus,
    budget: BaselineBudget,
    contamination: ContaminationAttestation,
    evaluator_identity_id: str,
    provenance: ReplayProvenance,
    metric_values: Mapping[str, int] | None,
) -> BaselineObservation:
    values: dict[str, Any] = {
        "adapter_kind": adapter_kind,
        "budget": budget,
        "case_id": case_id,
        "case_sha256": case_sha256,
        "contamination": contamination,
        "evaluator_identity_id": evaluator_identity_id,
        "expected_output_sha256": expected_output_sha256,
        "implementation_id": implementation_id,
        "implementation_revision": implementation_revision,
        "implementation_sha256": implementation_sha256,
        "metric_values": None if metric_values is None else dict(metric_values),
        "observed_output_sha256": observed_output_sha256,
        "partition_type": partition_type,
        "policy_sha256": policy_sha256,
        "prompt_sha256": prompt_sha256,
        "provenance": provenance,
        "result_status": result_status,
        "subject_id": subject_id,
        "subject_owner_identity_id": subject_owner_identity_id,
        "subject_role": subject_role,
        "subject_sha256": subject_sha256,
        "tools_allowed": tools_allowed,
    }
    body = {
        "adapter_kind": adapter_kind.value,
        "budget": budget.to_dict(),
        "case_id": case_id,
        "case_sha256": case_sha256,
        "contamination": contamination.to_dict(),
        "contract_type": BaselineObservation.contract_type,
        "effects": dict(NO_EFFECTS),
        "evaluator_identity_id": evaluator_identity_id,
        "expected_output_sha256": expected_output_sha256,
        "implementation_id": implementation_id,
        "implementation_revision": implementation_revision,
        "implementation_sha256": implementation_sha256,
        "metric_values": None if metric_values is None else dict(sorted(metric_values.items())),
        "observed_output_sha256": observed_output_sha256,
        "partition_type": partition_type,
        "policy_sha256": policy_sha256,
        "prompt_sha256": prompt_sha256,
        "provenance": provenance.to_dict(),
        "qualification_effect": "none",
        "result_status": result_status.value,
        "schema_version": SCHEMA_VERSION,
        "subject_id": subject_id,
        "subject_owner_identity_id": subject_owner_identity_id,
        "subject_role": subject_role,
        "subject_sha256": subject_sha256,
        "tools_allowed": tools_allowed,
    }
    observation_id, observation_sha = _content_identity("EBO", OBSERVATION_DOMAIN, body)
    return BaselineObservation(
        **values,
        observation_id=observation_id,
        observation_sha256=observation_sha,
    )


@dataclass(frozen=True, slots=True)
class BaselineReplayEnvelope:
    observation: BaselineObservation
    replay_adapter_id: str
    replay_adapter_revision: str
    replay_controller_identity_id: str
    replayed_at: str
    envelope_id: str
    envelope_sha256: str
    contract_type: ClassVar[str] = "baseline_replay_envelope"

    def __post_init__(self) -> None:
        _identifier(self.replay_adapter_id, "replay_adapter_id")
        _revision(self.replay_adapter_revision, "replay_adapter_revision")
        _identifier(self.replay_controller_identity_id, "replay_controller_identity_id")
        _timestamp(self.replayed_at, "replayed_at")
        excluded = {
            self.observation.subject_owner_identity_id,
            self.observation.evaluator_identity_id,
            self.observation.provenance.producer_identity_id,
        }
        if self.replay_controller_identity_id in excluded:
            raise BaselineReplayContractError(
                "replay controller must be independent of subject and evaluation identities"
            )
        expected_id, expected_sha = _content_identity("EBR", ENVELOPE_DOMAIN, self._body())
        if self.envelope_id != expected_id or self.envelope_sha256 != expected_sha:
            raise BaselineReplayContractError("baseline replay envelope identity does not match")

    def _body(self) -> dict[str, Any]:
        return {
            "contract_type": self.contract_type,
            "effects": dict(NO_EFFECTS),
            "observation": self.observation.to_dict(),
            "qualification_effect": "none",
            "replay_adapter_id": self.replay_adapter_id,
            "replay_adapter_revision": self.replay_adapter_revision,
            "replay_controller_identity_id": self.replay_controller_identity_id,
            "replayed_at": self.replayed_at,
            "schema_version": SCHEMA_VERSION,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "envelope_id": self.envelope_id,
            "envelope_sha256": self.envelope_sha256,
        }

    @property
    def document_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> BaselineReplayEnvelope:
        fields = {
            "contract_type",
            "effects",
            "envelope_id",
            "envelope_sha256",
            "observation",
            "qualification_effect",
            "replay_adapter_id",
            "replay_adapter_revision",
            "replay_controller_identity_id",
            "replayed_at",
            "schema_version",
        }
        item = dict(_exact(raw, fields, "baseline_replay_envelope"))
        if (
            type(item["schema_version"]) is not int
            or item.pop("schema_version") != SCHEMA_VERSION
            or item.pop("contract_type") != cls.contract_type
            or item.pop("qualification_effect") != "none"
            or item.pop("effects") != dict(NO_EFFECTS)
        ):
            raise BaselineReplayContractError("baseline envelope discriminator is invalid")
        item["observation"] = BaselineObservation.from_dict(item["observation"])
        return cls(**item)  # type: ignore[arg-type]

    @classmethod
    def from_json(cls, value: str) -> BaselineReplayEnvelope:
        if not isinstance(value, str):
            raise BaselineReplayContractError("envelope JSON must be text")
        try:
            raw = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise BaselineReplayContractError("envelope JSON is invalid") from exc
        result = cls.from_dict(raw)
        if value != result.document_json:
            raise BaselineReplayContractError("envelope JSON is not canonical")
        return result


def replay_baseline_observation(
    *,
    observation: BaselineObservation,
    replay_adapter_id: str,
    replay_adapter_revision: str,
    replay_controller_identity_id: str,
    replayed_at: str,
) -> BaselineReplayEnvelope:
    body = {
        "contract_type": BaselineReplayEnvelope.contract_type,
        "effects": dict(NO_EFFECTS),
        "observation": observation.to_dict(),
        "qualification_effect": "none",
        "replay_adapter_id": replay_adapter_id,
        "replay_adapter_revision": replay_adapter_revision,
        "replay_controller_identity_id": replay_controller_identity_id,
        "replayed_at": replayed_at,
        "schema_version": SCHEMA_VERSION,
    }
    envelope_id, envelope_sha = _content_identity("EBR", ENVELOPE_DOMAIN, body)
    return BaselineReplayEnvelope(
        observation=observation,
        replay_adapter_id=replay_adapter_id,
        replay_adapter_revision=replay_adapter_revision,
        replay_controller_identity_id=replay_controller_identity_id,
        replayed_at=replayed_at,
        envelope_id=envelope_id,
        envelope_sha256=envelope_sha,
    )


def parse_baseline_replay_envelope(raw: Mapping[str, Any]) -> BaselineReplayEnvelope:
    """Parse and verify an exact baseline replay envelope."""

    return BaselineReplayEnvelope.from_dict(raw)


__all__ = [
    "AdapterKind",
    "BASELINE_ROLES",
    "BaselineBudget",
    "BaselineObservation",
    "BaselineReplayContractError",
    "BaselineReplayEnvelope",
    "BaselineStatus",
    "ContaminationAttestation",
    "ContaminationStatus",
    "ENVELOPE_DOMAIN",
    "NO_EFFECTS",
    "OBSERVATION_DOMAIN",
    "ReplayProvenance",
    "SCHEMA_VERSION",
    "ScoringImportStatus",
    "build_baseline_observation",
    "canonical_json",
    "canonical_sha256",
    "parse_baseline_replay_envelope",
    "replay_baseline_observation",
]
