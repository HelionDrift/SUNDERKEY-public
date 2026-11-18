"""Provider-neutral expert model execution and atomic budget custody.

The contracts in this module do not resolve credentials or perform network
access. Provider observations remain advisory and are parsed only through the
Army v2 work-product boundary.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, ClassVar, Protocol, runtime_checkable

from .errors import RegistryError
from .expert_runtime import (
    MAX_WORK_PRODUCT_BYTES,
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
ASCII_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
CREDENTIAL_REFERENCE = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:/-]{2,251}\Z")
RAW_CREDENTIAL_MATERIAL = re.compile(
    r"^ref:(?:"
    r"(?:sk|rk|pk)[-_][A-Za-z0-9_-]{8,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[oprsu]_[A-Za-z0-9]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r")$",
    re.IGNORECASE,
)
RAW_SECRET_TEXT = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"private[_-]?key|client[_-]?secret)\b[\"']?\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\b(?:sk|rk|pk)[-_][A-Za-z0-9_-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r")",
    re.IGNORECASE,
)

NO_EFFECTS = MappingProxyType(
    {
        "action": "none",
        "authorization": "none",
        "finding": "none",
        "independent_review": "none",
        "qualification": "none",
        "target": "none",
        "tools": "none",
    }
)


class ExpertModelExecutionError(ValueError):
    """Raised when the execution boundary must fail closed."""


class ProviderInvocationRejected(RuntimeError):
    """A provider adapter rejected the invocation before dispatch."""


class ProviderOutcomeIndeterminate(RuntimeError):
    """Dispatch may have occurred, but no trustworthy observation exists."""


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ASCII_ID.fullmatch(value) is None:
        raise ExpertModelExecutionError(f"{label} must be a safe identifier")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ExpertModelExecutionError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_TIME.fullmatch(value) is None:
        raise ExpertModelExecutionError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ExpertModelExecutionError(f"{label} must be a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _clock_timestamp(clock: Callable[[], datetime]) -> str:
    if not callable(clock):
        raise ExpertModelExecutionError("clock must be callable")
    current = clock()
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ExpertModelExecutionError("clock must return a timezone-aware datetime")
    return current.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _post_dispatch_timestamp(
    clock: Callable[[], datetime] | None,
    fallback: str,
) -> tuple[str, BaseException | None]:
    if clock is None:
        return fallback, None
    try:
        current = _clock_timestamp(clock)
    except BaseException as exc:
        return fallback, exc
    if _instant(current) < _instant(fallback):
        return fallback, ExpertModelExecutionError("clock rollback detected")
    return current, None


def _natural(value: Any, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ExpertModelExecutionError(f"{label} must be an integer of at least {minimum}")
    return value


def _safe_provider_text(value: Any, label: str, *, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(not (character in "\t\n\r" or 0x20 <= ord(character) <= 0x7E) for character in value)
        or RAW_SECRET_TEXT.search(value) is not None
    ):
        raise ExpertModelExecutionError(f"{label} contains unsafe or secret-like text")
    return value


def _exact(raw: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise ExpertModelExecutionError(f"{label} fields are invalid")
    return dict(raw)


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _record(
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
    if value["schema_version"] != SCHEMA_VERSION or value["kind"] != kind:
        raise ExpertModelExecutionError(f"{kind} type is invalid")
    body = {key: value[key] for key in body_fields}
    record_id, digest = _identity(prefix, kind, body)
    if value[id_field] != record_id or value[sha_field] != digest:
        raise ExpertModelExecutionError(f"{kind} content address mismatch")
    return value


def _record_json(raw: str, label: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 1_048_576:
        raise ExpertModelExecutionError(f"{label} JSON exceeds the byte ceiling")
    try:
        value = loads_json_without_duplicate_keys(raw)
    except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
        raise ExpertModelExecutionError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ExpertModelExecutionError(f"{label} JSON must be a canonical object")
    return value


def _frozen(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _frozen(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_frozen(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ExpertExecutionAuthority:
    tenant_id: str
    assessment_id: str
    mission_id: str
    plan_id: str
    work_id: str
    task_id: str
    expert_profile_id: str
    runtime_catalog_sha256: str
    runtime_pack_sha256: str
    execution_envelope_sha256: str
    routing_decision_sha256: str
    capability_sha256: str
    reservation_sha256: str
    issuer_assertion_sha256: str
    authentication_verification_sha256: str
    maximum_request_count: int
    maximum_input_tokens: int
    maximum_output_tokens: int
    maximum_cost_micros: int
    maximum_route_age_seconds: int
    issued_at: str
    valid_from: str
    expires_at: str
    issuer_principal_id: str
    subject_principal_id: str
    requester_principal_id: str
    route_planner_principal_id: str
    provider_adapter_principal_id: str
    model_principal_id: str
    credential_reference: str = field(repr=False)
    authority_id: str = field(init=False)
    authority_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.expert-execution-authority.v1"

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "assessment_id",
            "mission_id",
            "plan_id",
            "work_id",
            "task_id",
            "expert_profile_id",
            "issuer_principal_id",
            "subject_principal_id",
            "requester_principal_id",
            "route_planner_principal_id",
            "provider_adapter_principal_id",
            "model_principal_id",
        ):
            _identifier(getattr(self, name), name)
        for name in (
            "runtime_catalog_sha256",
            "runtime_pack_sha256",
            "execution_envelope_sha256",
            "routing_decision_sha256",
            "capability_sha256",
            "reservation_sha256",
            "issuer_assertion_sha256",
            "authentication_verification_sha256",
        ):
            _digest(getattr(self, name), name)
        if self.maximum_request_count != 1:
            raise ExpertModelExecutionError("maximum_request_count must be one")
        for name in (
            "maximum_input_tokens",
            "maximum_output_tokens",
            "maximum_cost_micros",
            "maximum_route_age_seconds",
        ):
            _natural(getattr(self, name), name, positive=True)
        for name in ("issued_at", "valid_from", "expires_at"):
            _timestamp(getattr(self, name), name)
        if not (_instant(self.valid_from) <= _instant(self.issued_at) < _instant(self.expires_at)):
            raise ExpertModelExecutionError("execution authority validity window is invalid")
        excluded = {
            self.expert_profile_id,
            self.requester_principal_id,
            self.route_planner_principal_id,
            self.provider_adapter_principal_id,
            self.model_principal_id,
        }
        if self.issuer_principal_id in excluded:
            raise ExpertModelExecutionError("execution authority issuer is not independent")
        if self.subject_principal_id == self.issuer_principal_id:
            raise ExpertModelExecutionError("execution authority subject cannot be its issuer")
        if (
            not isinstance(self.credential_reference, str)
            or CREDENTIAL_REFERENCE.fullmatch(self.credential_reference) is None
            or RAW_CREDENTIAL_MATERIAL.fullmatch(self.credential_reference) is not None
        ):
            raise ExpertModelExecutionError(
                "credential_reference must be an opaque ref: identifier"
            )
        record_id, digest = _identity("EEA", self.KIND, self._body())
        object.__setattr__(self, "authority_id", record_id)
        object.__setattr__(self, "authority_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"authority_id", "authority_sha256", "KIND"}
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "authority_id": self.authority_id,
            "authority_sha256": self.authority_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExpertExecutionAuthority:
        body_fields = set(cls.__dataclass_fields__) - {"authority_id", "authority_sha256", "KIND"}
        value = _record(
            raw,
            kind=cls.KIND,
            prefix="EEA",
            id_field="authority_id",
            sha_field="authority_sha256",
            body_fields=body_fields,
        )
        instance = cls(**{key: value[key] for key in body_fields})
        return instance

    @classmethod
    def from_json(cls, raw: str) -> ExpertExecutionAuthority:
        return cls.from_dict(_record_json(raw, "execution authority"))


@dataclass(frozen=True, slots=True)
class ExpertInvocationPlan:
    authority_id: str
    authority_sha256: str
    routing_decision_id: str
    routing_decision_sha256: str
    reservation_id: str
    reservation_sha256: str
    capability_id: str
    capability_sha256: str
    provider_id: str
    provider_api_version: str
    model_id: str
    model_version: str
    pricing_revision: str
    runtime_catalog_sha256: str
    runtime_pack_id: str
    runtime_pack_sha256: str
    execution_envelope_id: str
    execution_envelope_sha256: str
    trusted_runtime_instructions: Mapping[str, Any]
    untrusted_context: tuple[Mapping[str, Any], ...]
    input_token_ceiling: int
    output_token_ceiling: int
    cost_ceiling_micros: int
    response_contract_sha256: str
    tools_enabled: bool = False
    response_contract: str = "closed_expert_work_product_v1"
    untrusted_text_policy: str = "data_only_never_instruction"
    request_count: int = 1
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.expert-invocation-plan.v1"

    def __post_init__(self) -> None:
        for name in (
            "authority_id",
            "routing_decision_id",
            "reservation_id",
            "capability_id",
            "provider_id",
            "provider_api_version",
            "model_id",
            "model_version",
            "pricing_revision",
            "runtime_pack_id",
            "execution_envelope_id",
        ):
            _identifier(getattr(self, name), name)
        for name in (
            "authority_sha256",
            "routing_decision_sha256",
            "reservation_sha256",
            "capability_sha256",
            "runtime_catalog_sha256",
            "runtime_pack_sha256",
            "execution_envelope_sha256",
            "response_contract_sha256",
        ):
            _digest(getattr(self, name), name)
        for name in ("input_token_ceiling", "output_token_ceiling", "cost_ceiling_micros"):
            _natural(getattr(self, name), name, positive=True)
        if self.tools_enabled is not False or self.request_count != 1:
            raise ExpertModelExecutionError(
                "invocation plans must disable tools and permit one request"
            )
        if self.response_contract != "closed_expert_work_product_v1":
            raise ExpertModelExecutionError("response contract is invalid")
        if self.untrusted_text_policy != "data_only_never_instruction":
            raise ExpertModelExecutionError("untrusted context policy is invalid")
        trusted_fields = {
            "instruction_contract",
            "role_contract",
            "runtime_catalog_sha256",
            "runtime_pack_id",
            "runtime_pack_sha256",
        }
        if (
            not isinstance(self.trusted_runtime_instructions, Mapping)
            or set(self.trusted_runtime_instructions) != trusted_fields
        ):
            raise ExpertModelExecutionError("trusted runtime instructions are invalid")
        if (
            not isinstance(self.untrusted_context, (list, tuple))
            or len(self.untrusted_context) > 48
            or any(not isinstance(item, Mapping) for item in self.untrusted_context)
        ):
            raise ExpertModelExecutionError("untrusted context is invalid")
        canonical_json(_plain(self.trusted_runtime_instructions))
        canonical_json(_plain(self.untrusted_context))
        object.__setattr__(
            self, "trusted_runtime_instructions", _frozen(self.trusted_runtime_instructions)
        )
        object.__setattr__(self, "untrusted_context", _frozen(self.untrusted_context))
        record_id, digest = _identity("EIP", self.KIND, self._body())
        object.__setattr__(self, "plan_id", record_id)
        object.__setattr__(self, "plan_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id,
            "authority_sha256": self.authority_sha256,
            "capability_id": self.capability_id,
            "capability_sha256": self.capability_sha256,
            "cost_ceiling_micros": self.cost_ceiling_micros,
            "execution_envelope_id": self.execution_envelope_id,
            "execution_envelope_sha256": self.execution_envelope_sha256,
            "input_token_ceiling": self.input_token_ceiling,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "output_token_ceiling": self.output_token_ceiling,
            "pricing_revision": self.pricing_revision,
            "provider_api_version": self.provider_api_version,
            "provider_id": self.provider_id,
            "request_count": self.request_count,
            "reservation_id": self.reservation_id,
            "reservation_sha256": self.reservation_sha256,
            "response_contract": self.response_contract,
            "response_contract_sha256": self.response_contract_sha256,
            "routing_decision_id": self.routing_decision_id,
            "routing_decision_sha256": self.routing_decision_sha256,
            "runtime_catalog_sha256": self.runtime_catalog_sha256,
            "runtime_pack_id": self.runtime_pack_id,
            "runtime_pack_sha256": self.runtime_pack_sha256,
            "tools_enabled": self.tools_enabled,
            "trusted_runtime_instructions": _plain(self.trusted_runtime_instructions),
            "untrusted_context": _plain(self.untrusted_context),
            "untrusted_text_policy": self.untrusted_text_policy,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExpertInvocationPlan:
        computed = {"plan_id", "plan_sha256", "KIND"}
        body_fields = set(cls.__dataclass_fields__) - computed
        value = _record(
            raw,
            kind=cls.KIND,
            prefix="EIP",
            id_field="plan_id",
            sha_field="plan_sha256",
            body_fields=body_fields,
        )
        values = {key: value[key] for key in body_fields}
        values["untrusted_context"] = tuple(values["untrusted_context"])
        return cls(**values)

    @classmethod
    def from_json(cls, raw: str) -> ExpertInvocationPlan:
        return cls.from_dict(_record_json(raw, "invocation plan"))


@dataclass(frozen=True, slots=True)
class ExpertBudgetReservationCommit:
    authority_id: str
    authority_sha256: str
    invocation_plan_id: str
    invocation_plan_sha256: str
    routing_decision_sha256: str
    proposed_reservation_sha256: str
    budget_id: str
    budget_sha256: str
    budget_revision_before: str
    budget_revision_after: str
    tenant_id: str
    assessment_id: str
    task_id: str
    capability_sha256: str
    reserved_input_tokens: int
    reserved_output_tokens: int
    reserved_cost_micros: int
    committed_at: str
    reservation_state: str = "committed"
    commit_id: str = field(init=False)
    commit_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.expert-budget-reservation-commit.v1"

    def __post_init__(self) -> None:
        for name in (
            "authority_id",
            "invocation_plan_id",
            "budget_id",
            "budget_revision_before",
            "budget_revision_after",
            "tenant_id",
            "assessment_id",
            "task_id",
        ):
            _identifier(getattr(self, name), name)
        for name in (
            "authority_sha256",
            "invocation_plan_sha256",
            "routing_decision_sha256",
            "proposed_reservation_sha256",
            "budget_sha256",
            "capability_sha256",
        ):
            _digest(getattr(self, name), name)
        for name in ("reserved_input_tokens", "reserved_output_tokens", "reserved_cost_micros"):
            _natural(getattr(self, name), name)
        _timestamp(self.committed_at, "committed_at")
        if self.reservation_state != "committed":
            raise ExpertModelExecutionError("reservation commit state is invalid")
        if self.budget_revision_before == self.budget_revision_after:
            raise ExpertModelExecutionError("reservation commit revision did not advance")
        record_id, digest = _identity("EBC", self.KIND, self._body())
        object.__setattr__(self, "commit_id", record_id)
        object.__setattr__(self, "commit_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"commit_id", "commit_sha256", "KIND"}
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "commit_id": self.commit_id,
            "commit_sha256": self.commit_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExpertBudgetReservationCommit:
        computed = {"commit_id", "commit_sha256", "KIND"}
        body_fields = set(cls.__dataclass_fields__) - computed
        value = _record(
            raw,
            kind=cls.KIND,
            prefix="EBC",
            id_field="commit_id",
            sha_field="commit_sha256",
            body_fields=body_fields,
        )
        return cls(**{key: value[key] for key in body_fields})

    @classmethod
    def from_json(cls, raw: str) -> ExpertBudgetReservationCommit:
        return cls.from_dict(_record_json(raw, "reservation commit"))


@dataclass(frozen=True, slots=True)
class ExpertProviderObservation:
    invocation_plan_id: str
    invocation_plan_sha256: str
    provider_id: str
    provider_api_version: str
    model_id: str
    model_version: str
    provider_request_id: str
    terminal_state: str
    usage_trustworthy: bool
    input_tokens: int | None
    output_tokens: int | None
    billable_cost_micros: int | None
    structured_output_json: str | None
    structured_output_reference: str | None
    incomplete_reason: str | None
    started_at: str
    completed_at: str
    observation_id: str = field(init=False)
    observation_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.expert-provider-observation.v1"

    def __post_init__(self) -> None:
        for name in (
            "invocation_plan_id",
            "provider_id",
            "provider_api_version",
            "model_id",
            "model_version",
            "provider_request_id",
        ):
            _identifier(getattr(self, name), name)
        _digest(self.invocation_plan_sha256, "invocation_plan_sha256")
        if self.terminal_state not in {"completed", "incomplete", "failed"}:
            raise ExpertModelExecutionError("provider terminal_state is invalid")
        if not isinstance(self.usage_trustworthy, bool):
            raise ExpertModelExecutionError("usage_trustworthy must be boolean")
        usage = (self.input_tokens, self.output_tokens, self.billable_cost_micros)
        if self.usage_trustworthy and any(item is None for item in usage):
            raise ExpertModelExecutionError("trustworthy usage must be complete")
        for index, item in enumerate(usage):
            if item is not None:
                _natural(item, ("input_tokens", "output_tokens", "billable_cost_micros")[index])
        if self.structured_output_json is not None:
            if not isinstance(self.structured_output_json, str):
                raise ExpertModelExecutionError("structured_output_json must be text")
            if len(self.structured_output_json.encode("utf-8")) > MAX_WORK_PRODUCT_BYTES:
                raise ExpertModelExecutionError(
                    "structured provider output exceeds the byte ceiling"
                )
            if RAW_SECRET_TEXT.search(self.structured_output_json) is not None:
                raise ExpertModelExecutionError(
                    "structured provider output contains secret-like text"
                )
        if self.structured_output_reference is not None:
            _digest(self.structured_output_reference, "structured_output_reference")
        if self.structured_output_json is not None and self.structured_output_reference is not None:
            raise ExpertModelExecutionError(
                "provider output must be inline or referenced, not both"
            )
        if self.terminal_state == "completed" and (
            self.structured_output_json is None and self.structured_output_reference is None
        ):
            raise ExpertModelExecutionError("completed provider observation requires output")
        if self.terminal_state == "failed" and (
            self.structured_output_json is not None or self.structured_output_reference is not None
        ):
            raise ExpertModelExecutionError("failed provider observation cannot include output")
        if self.terminal_state == "incomplete":
            _safe_provider_text(self.incomplete_reason, "incomplete_reason")
        elif self.incomplete_reason is not None:
            raise ExpertModelExecutionError("incomplete_reason is invalid for this state")
        _timestamp(self.started_at, "started_at")
        _timestamp(self.completed_at, "completed_at")
        if _instant(self.completed_at) < _instant(self.started_at):
            raise ExpertModelExecutionError("provider timing is invalid")
        record_id, digest = _identity("EPO", self.KIND, self._body())
        object.__setattr__(self, "observation_id", record_id)
        object.__setattr__(self, "observation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"observation_id", "observation_sha256", "KIND"}
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExpertProviderObservation:
        computed = {"observation_id", "observation_sha256", "KIND"}
        body_fields = set(cls.__dataclass_fields__) - computed
        value = _record(
            raw,
            kind=cls.KIND,
            prefix="EPO",
            id_field="observation_id",
            sha_field="observation_sha256",
            body_fields=body_fields,
        )
        return cls(**{key: value[key] for key in body_fields})

    @classmethod
    def from_json(cls, raw: str) -> ExpertProviderObservation:
        return cls.from_dict(_record_json(raw, "provider observation"))


@dataclass(frozen=True, slots=True)
class ExpertBudgetSettlement:
    reservation_commit_id: str
    reservation_commit_sha256: str
    provider_observation_id: str | None
    provider_observation_sha256: str | None
    terminal_state: str
    charged_input_tokens: int
    charged_output_tokens: int
    charged_cost_micros: int
    usage_basis: str
    outcome_reason: str
    budget_revision_before: str
    budget_revision_after: str
    settled_at: str
    quarantined: bool
    settlement_id: str = field(init=False)
    settlement_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.expert-budget-settlement.v1"

    def __post_init__(self) -> None:
        for name in ("reservation_commit_id", "budget_revision_before", "budget_revision_after"):
            _identifier(getattr(self, name), name)
        _digest(self.reservation_commit_sha256, "reservation_commit_sha256")
        if (self.provider_observation_id is None) != (self.provider_observation_sha256 is None):
            raise ExpertModelExecutionError("provider observation identity is incomplete")
        if self.provider_observation_id is not None:
            _identifier(self.provider_observation_id, "provider_observation_id")
            _digest(self.provider_observation_sha256, "provider_observation_sha256")
        if self.terminal_state not in {
            "completed_settled",
            "provider_failed_settled",
            "incomplete_settled",
            "indeterminate_quarantined",
        }:
            raise ExpertModelExecutionError("settlement terminal state is invalid")
        for name in ("charged_input_tokens", "charged_output_tokens", "charged_cost_micros"):
            _natural(getattr(self, name), name)
        if self.usage_basis not in {"trusted_actual", "full_reservation"}:
            raise ExpertModelExecutionError("settlement usage basis is invalid")
        _safe_provider_text(self.outcome_reason, "outcome_reason")
        _timestamp(self.settled_at, "settled_at")
        if self.quarantined != (self.terminal_state == "indeterminate_quarantined"):
            raise ExpertModelExecutionError("settlement quarantine state is invalid")
        if self.budget_revision_before == self.budget_revision_after:
            raise ExpertModelExecutionError("settlement revision did not advance")
        record_id, digest = _identity("EBS", self.KIND, self._body())
        object.__setattr__(self, "settlement_id", record_id)
        object.__setattr__(self, "settlement_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"settlement_id", "settlement_sha256", "KIND"}
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "settlement_id": self.settlement_id,
            "settlement_sha256": self.settlement_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExpertBudgetSettlement:
        computed = {"settlement_id", "settlement_sha256", "KIND"}
        body_fields = set(cls.__dataclass_fields__) - computed
        value = _record(
            raw,
            kind=cls.KIND,
            prefix="EBS",
            id_field="settlement_id",
            sha_field="settlement_sha256",
            body_fields=body_fields,
        )
        return cls(**{key: value[key] for key in body_fields})

    @classmethod
    def from_json(cls, raw: str) -> ExpertBudgetSettlement:
        return cls.from_dict(_record_json(raw, "budget settlement"))


@dataclass(frozen=True, slots=True)
class ExpertModelExecutionReceipt:
    authority_id: str
    authority_sha256: str
    invocation_plan_id: str
    invocation_plan_sha256: str
    reservation_commit_id: str
    reservation_commit_sha256: str
    provider_observation_id: str | None
    provider_observation_sha256: str | None
    settlement_id: str
    settlement_sha256: str
    work_product_id: str | None
    work_product_sha256: str | None
    execution_state: str
    output_status: str
    recorded_at: str
    receipt_id: str = field(init=False)
    receipt_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.expert-model-execution-receipt.v1"

    def __post_init__(self) -> None:
        for name in (
            "authority_id",
            "invocation_plan_id",
            "reservation_commit_id",
            "settlement_id",
        ):
            _identifier(getattr(self, name), name)
        for name in (
            "authority_sha256",
            "invocation_plan_sha256",
            "reservation_commit_sha256",
            "settlement_sha256",
        ):
            _digest(getattr(self, name), name)
        for prefix in ("provider_observation", "work_product"):
            record_id = getattr(self, f"{prefix}_id")
            digest = getattr(self, f"{prefix}_sha256")
            if (record_id is None) != (digest is None):
                raise ExpertModelExecutionError(f"{prefix} identity is incomplete")
            if record_id is not None:
                _identifier(record_id, f"{prefix}_id")
                _digest(digest, f"{prefix}_sha256")
        if self.execution_state not in {
            "completed_settled",
            "provider_failed_settled",
            "incomplete_settled",
            "indeterminate_quarantined",
        }:
            raise ExpertModelExecutionError("receipt execution state is invalid")
        if self.output_status not in {
            "parsed_advisory_work_product",
            "no_output",
            "malformed_output",
            "referenced_output_not_parsed",
            "indeterminate",
        }:
            raise ExpertModelExecutionError("receipt output status is invalid")
        if (self.work_product_id is not None) != (
            self.output_status == "parsed_advisory_work_product"
        ):
            raise ExpertModelExecutionError("receipt work-product status is inconsistent")
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
        if self.output_status not in statuses_by_state[self.execution_state]:
            raise ExpertModelExecutionError("receipt execution and output states are inconsistent")
        _timestamp(self.recorded_at, "recorded_at")
        record_id, digest = _identity("EMR", self.KIND, self._body())
        object.__setattr__(self, "receipt_id", record_id)
        object.__setattr__(self, "receipt_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name not in {"receipt_id", "receipt_sha256", "KIND"}
            },
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExpertModelExecutionReceipt:
        computed = {"receipt_id", "receipt_sha256", "KIND"}
        body_fields = (set(cls.__dataclass_fields__) - computed) | {"effects"}
        value = _record(
            raw,
            kind=cls.KIND,
            prefix="EMR",
            id_field="receipt_id",
            sha_field="receipt_sha256",
            body_fields=body_fields,
        )
        if value["effects"] != dict(NO_EFFECTS):
            raise ExpertModelExecutionError("receipt effects are invalid")
        return cls(**{key: value[key] for key in body_fields if key != "effects"})

    @classmethod
    def from_json(cls, raw: str) -> ExpertModelExecutionReceipt:
        return cls.from_dict(_record_json(raw, "execution receipt"))


@runtime_checkable
class ExpertModelProviderAdapter(Protocol):
    adapter_principal_id: str

    def invoke(
        self, plan: ExpertInvocationPlan, credential_reference: str
    ) -> ExpertProviderObservation:
        """Return observation only. The method has no budget mutation authority."""


@runtime_checkable
class ExpertBudgetCustodyAdapter(Protocol):
    def reserve(
        self,
        authority: ExpertExecutionAuthority,
        plan: ExpertInvocationPlan,
        decision: RoutingDecision,
        budget: BudgetEnvelope,
        now: str,
    ) -> ExpertBudgetReservationCommit: ...

    def mark_invoked(self, commit: ExpertBudgetReservationCommit, now: str) -> None: ...

    def settle(
        self,
        commit: ExpertBudgetReservationCommit,
        observation: ExpertProviderObservation | None,
        terminal_state: str,
        reason: str,
        now: str,
    ) -> ExpertBudgetSettlement: ...


class InMemoryExpertBudgetCustody:
    """Deterministic nonqualifying process-local custody fixture."""

    qualifying = False
    durability = "process_local_test_fixture"

    def __init__(self, budget: BudgetEnvelope) -> None:
        self._lock = threading.Lock()
        self._budget = budget
        self._revision = budget.budget_revision
        self._input = budget.aggregate_input_tokens_reserved
        self._output = budget.aggregate_output_tokens_reserved
        self._cost = budget.aggregate_cost_reserved_micros
        self._states: dict[str, str] = {}
        self._commit_by_authority: dict[str, str] = {}
        self._commit_by_request: dict[str, str] = {}
        self._provider_requests: set[str] = set()
        self._settlements: set[str] = set()
        self._last_clock: datetime | None = None

    def _clock(self, now: str) -> None:
        current = _instant(_timestamp(now, "now"))
        if self._last_clock is not None and current < self._last_clock:
            raise ExpertModelExecutionError("clock rollback detected")
        self._last_clock = current

    def _next_revision(self, operation: str, identifier: str) -> str:
        return (
            "custody."
            + canonical_sha256(
                {"identifier": identifier, "operation": operation, "previous": self._revision}
            )[7:23]
        )

    def _publish_snapshot(self) -> None:
        previous = self._budget
        self._budget = BudgetEnvelope(
            tenant_id=previous.tenant_id,
            assessment_id=previous.assessment_id,
            currency=previous.currency,
            request_input_token_limit=previous.request_input_token_limit,
            request_output_token_limit=previous.request_output_token_limit,
            request_cost_limit_micros=previous.request_cost_limit_micros,
            aggregate_input_token_limit=previous.aggregate_input_token_limit,
            aggregate_output_token_limit=previous.aggregate_output_token_limit,
            aggregate_cost_limit_micros=previous.aggregate_cost_limit_micros,
            aggregate_input_tokens_reserved=self._input,
            aggregate_output_tokens_reserved=self._output,
            aggregate_cost_reserved_micros=self._cost,
            budget_revision=self._revision,
        )

    def current_budget_envelope(self) -> BudgetEnvelope:
        """Return the immutable current snapshot for the next test transaction."""

        with self._lock:
            return self._budget

    def reserve(
        self,
        authority: ExpertExecutionAuthority,
        plan: ExpertInvocationPlan,
        decision: RoutingDecision,
        budget: BudgetEnvelope,
        now: str,
    ) -> ExpertBudgetReservationCommit:
        with self._lock:
            self._clock(now)
            if (
                budget.to_dict() != self._budget.to_dict()
                or budget.budget_revision != self._revision
            ):
                raise ExpertModelExecutionError("budget identity or revision is stale")
            if plan.authority_id in self._commit_by_authority:
                raise ExpertModelExecutionError("execution authority replay detected")
            if plan.plan_id in self._commit_by_request:
                raise ExpertModelExecutionError("invocation request replay detected")
            reservation = decision.budget_reservation
            if reservation is None:
                raise ExpertModelExecutionError("routing decision has no proposed reservation")
            if reservation.reservation_state != "proposed" or reservation.planning_only is not True:
                raise ExpertModelExecutionError("routing reservation state was tampered")
            exact_bindings = (
                plan.authority_id == authority.authority_id,
                plan.authority_sha256 == authority.authority_sha256,
                plan.routing_decision_id == decision.decision_id,
                plan.routing_decision_sha256 == decision.decision_sha256,
                plan.reservation_id == reservation.reservation_id,
                plan.reservation_sha256 == reservation.reservation_sha256,
                plan.capability_sha256 == reservation.capability_sha256,
                plan.input_token_ceiling == reservation.input_tokens,
                plan.output_token_ceiling == reservation.output_tokens,
                plan.cost_ceiling_micros == reservation.estimated_cost_micros,
                authority.routing_decision_sha256 == decision.decision_sha256,
                authority.reservation_sha256 == reservation.reservation_sha256,
                authority.capability_sha256 == reservation.capability_sha256,
                decision.budget_sha256 == budget.budget_sha256,
                reservation.budget_sha256 == budget.budget_sha256,
                reservation.tenant_id == budget.tenant_id == authority.tenant_id,
                reservation.assessment_id == budget.assessment_id == authority.assessment_id,
                reservation.task_id == decision.task_id == authority.task_id,
            )
            if not all(exact_bindings):
                raise ExpertModelExecutionError("atomic reservation binding mismatch")
            _validate_authority_time(authority, decision, now)
            if reservation.input_tokens > budget.request_input_token_limit:
                raise ExpertModelExecutionError("request input-token limit exceeded")
            if reservation.output_tokens > budget.request_output_token_limit:
                raise ExpertModelExecutionError("request output-token limit exceeded")
            if reservation.estimated_cost_micros > budget.request_cost_limit_micros:
                raise ExpertModelExecutionError("request cost limit exceeded")
            after = (
                self._input + reservation.input_tokens,
                self._output + reservation.output_tokens,
                self._cost + reservation.estimated_cost_micros,
            )
            limits = (
                budget.aggregate_input_token_limit,
                budget.aggregate_output_token_limit,
                budget.aggregate_cost_limit_micros,
            )
            if any(item > limit for item, limit in zip(after, limits, strict=True)):
                raise ExpertModelExecutionError("aggregate budget limit exceeded")
            proposed_after = (
                reservation.aggregate_input_tokens_after,
                reservation.aggregate_output_tokens_after,
                reservation.aggregate_cost_micros_after,
            )
            if proposed_after != after:
                raise ExpertModelExecutionError("proposed aggregate reservation was tampered")
            revision_before = self._revision
            self._revision = self._next_revision("reserve", plan.plan_id)
            commit = ExpertBudgetReservationCommit(
                authority_id=authority.authority_id,
                authority_sha256=authority.authority_sha256,
                invocation_plan_id=plan.plan_id,
                invocation_plan_sha256=plan.plan_sha256,
                routing_decision_sha256=decision.decision_sha256,
                proposed_reservation_sha256=reservation.reservation_sha256,
                budget_id=budget.budget_id,
                budget_sha256=budget.budget_sha256,
                budget_revision_before=revision_before,
                budget_revision_after=self._revision,
                tenant_id=reservation.tenant_id,
                assessment_id=reservation.assessment_id,
                task_id=reservation.task_id,
                capability_sha256=reservation.capability_sha256,
                reserved_input_tokens=reservation.input_tokens,
                reserved_output_tokens=reservation.output_tokens,
                reserved_cost_micros=reservation.estimated_cost_micros,
                committed_at=now,
            )
            self._input, self._output, self._cost = after
            self._publish_snapshot()
            self._states[commit.commit_id] = "committed"
            self._commit_by_authority[plan.authority_id] = commit.commit_id
            self._commit_by_request[plan.plan_id] = commit.commit_id
            return commit

    def mark_invoked(self, commit: ExpertBudgetReservationCommit, now: str) -> None:
        with self._lock:
            self._clock(now)
            if self._states.get(commit.commit_id) != "committed":
                raise ExpertModelExecutionError("reservation is not in committed state")
            self._states[commit.commit_id] = "invoked"

    def settle(
        self,
        commit: ExpertBudgetReservationCommit,
        observation: ExpertProviderObservation | None,
        terminal_state: str,
        reason: str,
        now: str,
    ) -> ExpertBudgetSettlement:
        with self._lock:
            self._clock(now)
            if (
                self._states.get(commit.commit_id) != "invoked"
                or commit.commit_id in self._settlements
            ):
                raise ExpertModelExecutionError("settlement replay or invalid state transition")
            allowed = {
                "completed_settled",
                "provider_failed_settled",
                "incomplete_settled",
                "indeterminate_quarantined",
            }
            if terminal_state not in allowed:
                raise ExpertModelExecutionError("settlement state is invalid")
            trustworthy = (
                observation is not None
                and observation.usage_trustworthy
                and terminal_state != "indeterminate_quarantined"
            )
            if observation is not None and (
                observation.invocation_plan_id != commit.invocation_plan_id
                or observation.invocation_plan_sha256 != commit.invocation_plan_sha256
            ):
                terminal_state = "indeterminate_quarantined"
                reason = "provider_request_binding_mismatch"
                trustworthy = False
            if (
                observation is not None
                and observation.provider_request_id in self._provider_requests
            ):
                terminal_state = "indeterminate_quarantined"
                reason = "duplicate_provider_request"
                trustworthy = False
            usage = (
                observation.input_tokens if observation else None,
                observation.output_tokens if observation else None,
                observation.billable_cost_micros if observation else None,
            )
            ceilings = (
                commit.reserved_input_tokens,
                commit.reserved_output_tokens,
                commit.reserved_cost_micros,
            )
            if trustworthy and any(
                item is None or item > ceiling
                for item, ceiling in zip(usage, ceilings, strict=True)
            ):
                terminal_state = "indeterminate_quarantined"
                reason = "usage_exceeds_committed_ceiling"
                trustworthy = False
            charged = tuple(int(item) for item in usage) if trustworthy else ceilings
            revision_before = self._revision
            self._revision = self._next_revision("settle", commit.commit_id)
            self._input -= commit.reserved_input_tokens - charged[0]
            self._output -= commit.reserved_output_tokens - charged[1]
            self._cost -= commit.reserved_cost_micros - charged[2]
            self._publish_snapshot()
            if observation is not None:
                self._provider_requests.add(observation.provider_request_id)
            settlement = ExpertBudgetSettlement(
                reservation_commit_id=commit.commit_id,
                reservation_commit_sha256=commit.commit_sha256,
                provider_observation_id=observation.observation_id if observation else None,
                provider_observation_sha256=observation.observation_sha256 if observation else None,
                terminal_state=terminal_state,
                charged_input_tokens=charged[0],
                charged_output_tokens=charged[1],
                charged_cost_micros=charged[2],
                usage_basis="trusted_actual" if trustworthy else "full_reservation",
                outcome_reason=reason,
                budget_revision_before=revision_before,
                budget_revision_after=self._revision,
                settled_at=now,
                quarantined=terminal_state == "indeterminate_quarantined",
            )
            self._states[commit.commit_id] = "quarantined" if settlement.quarantined else "settled"
            self._settlements.add(commit.commit_id)
            return settlement


class DeterministicExpertModelProviderFixture:
    """Nonqualifying provider fixture with exactly one deterministic call path."""

    qualifying = False
    network_call_performed = False

    def __init__(
        self,
        adapter_principal_id: str,
        observation_factory: Callable[[ExpertInvocationPlan], ExpertProviderObservation],
    ) -> None:
        self.adapter_principal_id = _identifier(adapter_principal_id, "adapter_principal_id")
        self._factory = observation_factory
        self.call_count = 0

    def invoke(
        self, plan: ExpertInvocationPlan, credential_reference: str
    ) -> ExpertProviderObservation:
        if CREDENTIAL_REFERENCE.fullmatch(credential_reference) is None:
            raise ExpertModelExecutionError("provider received an invalid credential reference")
        self.call_count += 1
        if self.call_count != 1:
            raise ExpertModelExecutionError("automatic provider retry is forbidden")
        return self._factory(plan)


@dataclass(frozen=True, slots=True)
class ExpertModelExecutionResult:
    receipt: ExpertModelExecutionReceipt
    invocation_plan: ExpertInvocationPlan
    reservation_commit: ExpertBudgetReservationCommit
    observation: ExpertProviderObservation | None
    settlement: ExpertBudgetSettlement
    work_product: WorkProduct | None


def _validate_authority_time(
    authority: ExpertExecutionAuthority, decision: RoutingDecision, now: str
) -> None:
    current = _instant(_timestamp(now, "now"))
    if current < _instant(authority.valid_from) or current >= _instant(authority.expires_at):
        raise ExpertModelExecutionError("execution authority is not currently valid")
    if current < _instant(authority.issued_at) or current < _instant(decision.decided_at):
        raise ExpertModelExecutionError("future-dated authority or route decision detected")
    age = int((current - _instant(decision.decided_at)).total_seconds())
    if age > authority.maximum_route_age_seconds:
        raise ExpertModelExecutionError("routing decision is stale")


def build_invocation_plan(
    runtime_catalog: RuntimePackCatalog,
    runtime_pack: Mapping[str, Any],
    envelope: ExecutionEnvelope,
    decision: RoutingDecision,
    capability: ModelCapabilityDeclaration,
    budget: BudgetEnvelope,
    authority: ExpertExecutionAuthority,
    *,
    now: str,
) -> ExpertInvocationPlan:
    if type(runtime_catalog) is not RuntimePackCatalog:
        raise ExpertModelExecutionError("runtime catalog is not validated")
    if type(capability) is not ModelCapabilityDeclaration:
        raise ExpertModelExecutionError("capability declaration is not canonical")
    if type(budget) is not BudgetEnvelope:
        raise ExpertModelExecutionError("budget envelope is not canonical")
    if type(authority) is not ExpertExecutionAuthority:
        raise ExpertModelExecutionError("execution authority is not canonical")
    if type(decision) is not RoutingDecision:
        raise ExpertModelExecutionError("routing decision is not canonical")
    if type(envelope) is not ExecutionEnvelope:
        raise ExpertModelExecutionError("execution envelope is not canonical")
    exact_pack = runtime_catalog.pack_for_profile_id(envelope.profile_id)
    if exact_pack is None or dict(runtime_pack) != exact_pack:
        raise ExpertModelExecutionError("runtime-pack or catalog substitution detected")
    try:
        envelope = parse_execution_envelope(envelope.to_dict(), exact_pack, runtime_catalog)
        decision = RoutingDecision.from_dict(decision.to_dict())
    except (RegistryError, ValueError) as exc:
        raise ExpertModelExecutionError("runtime envelope or routing decision is invalid") from exc
    if (
        decision.status != "selected"
        or decision.selection is None
        or decision.budget_reservation is None
    ):
        raise ExpertModelExecutionError("routing decision does not select a route")
    selection = decision.selection
    reservation = decision.budget_reservation
    if selection.capability_sha256 != capability.capability_sha256:
        raise ExpertModelExecutionError("selected capability substitution detected")
    route = (
        selection.provider_id,
        selection.provider_api_version,
        selection.model_id,
        selection.model_version,
        selection.pricing_revision,
    )
    declared = (
        capability.provider_id,
        capability.provider_api_version,
        capability.model_id,
        capability.model_version,
        capability.pricing_revision,
    )
    if route != declared:
        raise ExpertModelExecutionError("selected route does not match the capability declaration")
    if capability.tool_policy != "forbidden":
        raise ExpertModelExecutionError("expert model capability must forbid tools")
    if (
        decision.budget_sha256 != budget.budget_sha256
        or reservation.budget_sha256 != budget.budget_sha256
    ):
        raise ExpertModelExecutionError("routing budget substitution detected")
    expected_authority = {
        "tenant_id": decision.tenant_id,
        "assessment_id": decision.assessment_id,
        "mission_id": envelope.mission_id,
        "plan_id": envelope.plan_id,
        "work_id": envelope.work_id,
        "task_id": decision.task_id,
        "expert_profile_id": envelope.profile_id,
        "runtime_catalog_sha256": runtime_catalog.catalog_sha256,
        "runtime_pack_sha256": exact_pack["runtime_pack_sha256"],
        "execution_envelope_sha256": envelope.envelope_sha256,
        "routing_decision_sha256": decision.decision_sha256,
        "capability_sha256": capability.capability_sha256,
        "reservation_sha256": reservation.reservation_sha256,
    }
    if any(getattr(authority, key) != value for key, value in expected_authority.items()):
        raise ExpertModelExecutionError("execution authority binding substitution detected")
    if (budget.tenant_id, budget.assessment_id) != (decision.tenant_id, decision.assessment_id):
        raise ExpertModelExecutionError("budget scope does not match the route")
    if (
        reservation.input_tokens > authority.maximum_input_tokens
        or reservation.output_tokens > authority.maximum_output_tokens
        or reservation.estimated_cost_micros > authority.maximum_cost_micros
        or reservation.input_tokens > envelope.token_budget["input_token_ceiling"]
        or reservation.output_tokens > envelope.token_budget["output_token_ceiling"]
        or reservation.input_tokens > capability.maximum_context_tokens
        or reservation.output_tokens > capability.maximum_output_tokens
    ):
        raise ExpertModelExecutionError("authority or runtime token and cost ceiling exceeded")
    _validate_authority_time(authority, decision, now)
    trusted = {
        "instruction_contract": exact_pack["instruction_contract"],
        "role_contract": exact_pack["role_contract"],
        "runtime_catalog_sha256": runtime_catalog.catalog_sha256,
        "runtime_pack_id": exact_pack["runtime_pack_id"],
        "runtime_pack_sha256": exact_pack["runtime_pack_sha256"],
    }
    response_contract_sha256 = canonical_sha256(
        {
            "allowed_product_types": exact_pack["instruction_contract"]["allowed_product_types"],
            "domain": "sunderkey.expert-work-product-response-contract.v1",
            "execution_envelope_sha256": envelope.envelope_sha256,
            "runtime_catalog_sha256": runtime_catalog.catalog_sha256,
            "runtime_pack_sha256": exact_pack["runtime_pack_sha256"],
            "schema_version": 1,
        }
    )
    return ExpertInvocationPlan(
        authority_id=authority.authority_id,
        authority_sha256=authority.authority_sha256,
        routing_decision_id=decision.decision_id,
        routing_decision_sha256=decision.decision_sha256,
        reservation_id=reservation.reservation_id,
        reservation_sha256=reservation.reservation_sha256,
        capability_id=capability.capability_id,
        capability_sha256=capability.capability_sha256,
        provider_id=selection.provider_id,
        provider_api_version=selection.provider_api_version,
        model_id=selection.model_id,
        model_version=selection.model_version,
        pricing_revision=selection.pricing_revision,
        runtime_catalog_sha256=runtime_catalog.catalog_sha256,
        runtime_pack_id=exact_pack["runtime_pack_id"],
        runtime_pack_sha256=exact_pack["runtime_pack_sha256"],
        execution_envelope_id=envelope.envelope_id,
        execution_envelope_sha256=envelope.envelope_sha256,
        trusted_runtime_instructions=trusted,
        untrusted_context=envelope.context_items,
        input_token_ceiling=reservation.input_tokens,
        output_token_ceiling=reservation.output_tokens,
        cost_ceiling_micros=reservation.estimated_cost_micros,
        response_contract_sha256=response_contract_sha256,
    )


def execute_expert_model(
    runtime_catalog: RuntimePackCatalog,
    runtime_pack: Mapping[str, Any],
    envelope: ExecutionEnvelope,
    decision: RoutingDecision,
    capability: ModelCapabilityDeclaration,
    budget: BudgetEnvelope,
    authority: ExpertExecutionAuthority,
    custody: ExpertBudgetCustodyAdapter,
    provider: ExpertModelProviderAdapter,
    *,
    now: str,
    clock: Callable[[], datetime] | None = None,
) -> ExpertModelExecutionResult:
    """Execute one nonqualifying fixture request and settle it atomically.

    Production admission remains blocked until a proof-sealed signed authority
    and its replay consumption are composed into the same custody transaction.
    """

    request_time = _clock_timestamp(clock) if clock is not None else _timestamp(now, "now")
    if (
        getattr(custody, "qualifying", None) is not False
        or getattr(provider, "qualifying", None) is not False
        or getattr(provider, "network_call_performed", None) is not False
    ):
        raise ExpertModelExecutionError(
            "production execution requires proof-sealed signed authority and atomic replay custody"
        )
    if type(authority) is not ExpertExecutionAuthority:
        raise ExpertModelExecutionError("execution authority is not canonical")
    if type(decision) is not RoutingDecision:
        raise ExpertModelExecutionError("routing decision is not canonical")
    authority = ExpertExecutionAuthority.from_dict(authority.to_dict())
    decision = RoutingDecision.from_dict(decision.to_dict())
    if provider.adapter_principal_id != authority.provider_adapter_principal_id:
        raise ExpertModelExecutionError("provider adapter principal substitution detected")
    plan = build_invocation_plan(
        runtime_catalog,
        runtime_pack,
        envelope,
        decision,
        capability,
        budget,
        authority,
        now=request_time,
    )
    exact_runtime_pack = runtime_catalog.pack_for_profile_id(envelope.profile_id)
    if (
        exact_runtime_pack is None
        or exact_runtime_pack["runtime_pack_sha256"] != plan.runtime_pack_sha256
    ):
        raise ExpertModelExecutionError("validated runtime pack is no longer available")
    commit = custody.reserve(authority, plan, decision, budget, request_time)
    reservation = decision.budget_reservation
    if type(commit) is not ExpertBudgetReservationCommit or reservation is None:
        raise ExpertModelExecutionError("budget custody returned an invalid reservation commit")
    commit = ExpertBudgetReservationCommit.from_dict(commit.to_dict())
    commit_bindings = (
        commit.authority_id == authority.authority_id,
        commit.authority_sha256 == authority.authority_sha256,
        commit.invocation_plan_id == plan.plan_id,
        commit.invocation_plan_sha256 == plan.plan_sha256,
        commit.routing_decision_sha256 == decision.decision_sha256,
        commit.proposed_reservation_sha256 == reservation.reservation_sha256,
        commit.budget_id == budget.budget_id,
        commit.budget_sha256 == budget.budget_sha256,
        commit.budget_revision_before == budget.budget_revision,
        commit.budget_revision_after != commit.budget_revision_before,
        commit.tenant_id == decision.tenant_id,
        commit.assessment_id == decision.assessment_id,
        commit.task_id == decision.task_id,
        commit.capability_sha256 == capability.capability_sha256,
        commit.reserved_input_tokens == reservation.input_tokens,
        commit.reserved_output_tokens == reservation.output_tokens,
        commit.reserved_cost_micros == reservation.estimated_cost_micros,
        commit.committed_at == request_time,
    )
    if not all(commit_bindings):
        raise ExpertModelExecutionError("budget custody commit binding mismatch")
    custody.mark_invoked(commit, request_time)
    observation: ExpertProviderObservation | None = None
    product: WorkProduct | None = None
    output_status = "no_output"
    settlement_state = "provider_failed_settled"
    reason = "provider_rejected_before_dispatch"
    pending_base_exception: BaseException | None = None
    completion_time = request_time
    try:
        observation = provider.invoke(plan, authority.credential_reference)
    except ProviderInvocationRejected:
        pass
    except ProviderOutcomeIndeterminate:
        settlement_state = "indeterminate_quarantined"
        reason = "provider_outcome_indeterminate"
        output_status = "indeterminate"
    except Exception:
        settlement_state = "indeterminate_quarantined"
        reason = "provider_outcome_indeterminate"
        output_status = "indeterminate"
    except BaseException as exc:
        pending_base_exception = exc
        settlement_state = "indeterminate_quarantined"
        reason = "provider_outcome_indeterminate"
        output_status = "indeterminate"
    else:
        if type(observation) is not ExpertProviderObservation:
            observation = None
            settlement_state = "indeterminate_quarantined"
            reason = "provider_observation_type_invalid"
            output_status = "indeterminate"
        else:
            try:
                observation = ExpertProviderObservation.from_dict(observation.to_dict())
            except Exception:
                observation = None
                settlement_state = "indeterminate_quarantined"
                reason = "provider_observation_invalid"
                output_status = "indeterminate"
            except BaseException as exc:
                observation = None
                pending_base_exception = exc
                settlement_state = "indeterminate_quarantined"
                reason = "provider_outcome_indeterminate"
                output_status = "indeterminate"
        completion_time, clock_failure = _post_dispatch_timestamp(clock, request_time)
        if clock_failure is not None:
            pending_base_exception = pending_base_exception or clock_failure
            settlement_state = "indeterminate_quarantined"
            reason = "coordinator_clock_indeterminate"
            output_status = "indeterminate"
        binding = observation is not None and (
            observation.invocation_plan_id == plan.plan_id
            and observation.invocation_plan_sha256 == plan.plan_sha256
            and observation.provider_id == plan.provider_id
            and observation.provider_api_version == plan.provider_api_version
            and observation.model_id == plan.model_id
            and observation.model_version == plan.model_version
        )
        timing = observation is not None and (
            _instant(observation.started_at) >= _instant(commit.committed_at)
            and _instant(observation.completed_at) <= _instant(completion_time)
        )
        if pending_base_exception is not None:
            product = None
        elif observation is not None and not binding:
            settlement_state = "indeterminate_quarantined"
            reason = "provider_route_or_request_substitution"
            output_status = "indeterminate"
        elif observation is not None and not timing:
            settlement_state = "indeterminate_quarantined"
            reason = "provider_observation_time_invalid"
            output_status = "indeterminate"
        elif observation is not None and observation.terminal_state == "failed":
            settlement_state = "provider_failed_settled"
            reason = "provider_failed"
        elif observation is not None and observation.terminal_state == "incomplete":
            settlement_state = "incomplete_settled"
            reason = "provider_incomplete"
            output_status = (
                "referenced_output_not_parsed"
                if observation.structured_output_reference
                else "no_output"
            )
        elif observation is not None and observation.structured_output_reference is not None:
            settlement_state = "incomplete_settled"
            reason = "referenced_output_requires_independent_retrieval_and_parsing"
            output_status = "referenced_output_not_parsed"
        elif observation is not None:
            try:
                raw = observation.structured_output_json
                if raw is None or len(raw.encode("utf-8")) > MAX_WORK_PRODUCT_BYTES:
                    raise ExpertModelExecutionError("provider output is absent or oversized")
                parsed = loads_json_without_duplicate_keys(raw)
                if not isinstance(parsed, dict) or canonical_json(parsed) != raw:
                    raise ExpertModelExecutionError("provider output is not canonical JSON")
                product = parse_work_product(
                    parsed,
                    exact_runtime_pack,
                    envelope,
                    runtime_catalog,
                )
            except ValueError:
                settlement_state = "incomplete_settled"
                reason = "malformed_structured_output"
                output_status = "malformed_output"
            except BaseException as exc:
                pending_base_exception = exc
                settlement_state = "indeterminate_quarantined"
                reason = "provider_output_processing_indeterminate"
                output_status = "indeterminate"
                product = None
            else:
                settlement_state = "completed_settled"
                reason = "completed_with_parsed_advisory_work_product"
                output_status = "parsed_advisory_work_product"
    usage = (
        observation.input_tokens if observation is not None else None,
        observation.output_tokens if observation is not None else None,
        observation.billable_cost_micros if observation is not None else None,
    )
    ceilings = (
        commit.reserved_input_tokens,
        commit.reserved_output_tokens,
        commit.reserved_cost_micros,
    )
    if (
        observation is not None
        and observation.usage_trustworthy
        and any(
            item is None or item > ceiling for item, ceiling in zip(usage, ceilings, strict=True)
        )
    ):
        settlement_state = "indeterminate_quarantined"
        reason = "usage_exceeds_committed_ceiling"
        output_status = "indeterminate"
        product = None
    settlement_time, clock_failure = _post_dispatch_timestamp(
        clock,
        completion_time,
    )
    if clock_failure is not None:
        pending_base_exception = pending_base_exception or clock_failure
        settlement_state = "indeterminate_quarantined"
        reason = "coordinator_clock_indeterminate"
        output_status = "indeterminate"
        product = None
    settlement = custody.settle(
        commit,
        observation,
        settlement_state,
        reason,
        settlement_time,
    )
    if type(settlement) is not ExpertBudgetSettlement:
        raise ExpertModelExecutionError("budget custody returned an invalid settlement")
    settlement = ExpertBudgetSettlement.from_dict(settlement.to_dict())
    trustworthy_usage = (
        observation is not None
        and observation.usage_trustworthy
        and settlement_state != "indeterminate_quarantined"
        and observation.input_tokens is not None
        and observation.output_tokens is not None
        and observation.billable_cost_micros is not None
        and observation.input_tokens <= commit.reserved_input_tokens
        and observation.output_tokens <= commit.reserved_output_tokens
        and observation.billable_cost_micros <= commit.reserved_cost_micros
    )
    expected_charges = (
        (
            observation.input_tokens,
            observation.output_tokens,
            observation.billable_cost_micros,
        )
        if trustworthy_usage and observation is not None
        else (
            commit.reserved_input_tokens,
            commit.reserved_output_tokens,
            commit.reserved_cost_micros,
        )
    )
    expected_observation = (
        (observation.observation_id, observation.observation_sha256)
        if observation is not None
        else (None, None)
    )
    if (
        settlement.reservation_commit_id != commit.commit_id
        or settlement.reservation_commit_sha256 != commit.commit_sha256
        or settlement.budget_revision_before != commit.budget_revision_after
        or settlement.budget_revision_after == settlement.budget_revision_before
        or settlement.settled_at != settlement_time
        or (
            settlement.provider_observation_id,
            settlement.provider_observation_sha256,
        )
        != expected_observation
        or settlement.charged_input_tokens > commit.reserved_input_tokens
        or settlement.charged_output_tokens > commit.reserved_output_tokens
        or settlement.charged_cost_micros > commit.reserved_cost_micros
        or settlement.terminal_state not in {settlement_state, "indeterminate_quarantined"}
        or (settlement.terminal_state == settlement_state and settlement.outcome_reason != reason)
        or (
            not settlement.quarantined
            and (
                (
                    settlement.charged_input_tokens,
                    settlement.charged_output_tokens,
                    settlement.charged_cost_micros,
                )
                != expected_charges
                or settlement.usage_basis
                != ("trusted_actual" if trustworthy_usage else "full_reservation")
            )
        )
        or (
            settlement.quarantined
            and (
                settlement.charged_input_tokens != commit.reserved_input_tokens
                or settlement.charged_output_tokens != commit.reserved_output_tokens
                or settlement.charged_cost_micros != commit.reserved_cost_micros
                or settlement.usage_basis != "full_reservation"
            )
        )
    ):
        raise ExpertModelExecutionError("budget custody settlement binding mismatch")
    if settlement.quarantined:
        product = None
        output_status = "indeterminate"
    receipt = ExpertModelExecutionReceipt(
        authority_id=authority.authority_id,
        authority_sha256=authority.authority_sha256,
        invocation_plan_id=plan.plan_id,
        invocation_plan_sha256=plan.plan_sha256,
        reservation_commit_id=commit.commit_id,
        reservation_commit_sha256=commit.commit_sha256,
        provider_observation_id=observation.observation_id if observation else None,
        provider_observation_sha256=observation.observation_sha256 if observation else None,
        settlement_id=settlement.settlement_id,
        settlement_sha256=settlement.settlement_sha256,
        work_product_id=product.product_id if product else None,
        work_product_sha256=product.product_sha256 if product else None,
        execution_state=settlement.terminal_state,
        output_status=output_status,
        recorded_at=settlement_time,
    )
    result = ExpertModelExecutionResult(receipt, plan, commit, observation, settlement, product)
    if pending_base_exception is not None:
        raise pending_base_exception
    return result
