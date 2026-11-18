"""Repository-only contracts for AI and protocol assessment specialists.

The records in this module describe safe, synthetic validation work for AI
applications, agent protocols, tool boundaries, retrieval systems, model
supply chains, and machine-to-machine protocols. The module contains no
provider client, model runner, prompt attack library, network client, tool
executor, or target implementation. A caller-supplied adapter receives only
opaque references, digests, scenario names, and bounded counters after exact
context, freshness, replay, and declaration checks succeed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol

SCHEMA_VERSION = 1
MAX_WINDOW_SECONDS = 86_400
MAX_REQUESTS = 10_000
MAX_BYTES = 1_000_000_000
MAX_TOKENS = 10_000_000

BOUNDARY_EFFECTS = MappingProxyType(
    {
        "builtin_model_execution": "none",
        "builtin_network": "none",
        "builtin_provider_call": "none",
        "builtin_tool_execution": "none",
        "payload_library": "none",
        "injected_adapter_invocation": "caller_supplied_only",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|contextref|scoperef|modelref|toolref|corpusref|sessionref|"
    r"evidenceref|budgetref|admissionref|agentref|delegationref|protocolref|"
    r"fixtureref|capabilityref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SECRET_MATERIAL_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{4,}|"
    r"\b(?:password|passwd|secret|api_key|access_token|refresh_token|id_token|otp)"
    r"\s*[:=]\s*[^,}\s]+|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b)",
    re.IGNORECASE,
)


class AIProtocolSpecialistContractError(ValueError):
    """Raised when an AI or protocol specialist contract fails closed."""


class SpecialistFamily(StrEnum):
    AI_APPLICATION = "ai_application"
    AGENT_PROTOCOL = "agent_protocol"
    TOOL_BOUNDARY = "tool_boundary"
    RETRIEVAL = "retrieval"
    MODEL_SUPPLY_CHAIN = "model_supply_chain"
    MACHINE_TO_MACHINE_PROTOCOL = "machine_to_machine_protocol"


class AssessmentScenario(StrEnum):
    PROMPT_CONTEXT_BOUNDARY = "prompt_context_boundary_validation"
    TOOL_AUTHORIZATION = "tool_authorization_checks"
    RETRIEVAL_PROVENANCE = "retrieval_provenance_tests"
    INDIRECT_INSTRUCTION_RESISTANCE = "indirect_instruction_resistance_scenarios"
    AGENT_IDENTITY_DELEGATION = "agent_identity_and_delegation_checks"
    MODEL_ARTIFACT_PROVENANCE = "model_artifact_provenance"
    PROTOCOL_STATE = "protocol_state_validation"
    DATA_BOUNDARY_LEAKAGE = "data_boundary_leakage_controls"


class AdapterDisposition(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"


class AssessmentOutcome(StrEnum):
    PASS = "pass"
    CONTROL_GAP = "control_gap"
    INCONCLUSIVE = "inconclusive"


class ReceiptStatus(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"


FAMILY_SCENARIOS = MappingProxyType(
    {
        SpecialistFamily.AI_APPLICATION: frozenset(
            {
                AssessmentScenario.PROMPT_CONTEXT_BOUNDARY,
                AssessmentScenario.INDIRECT_INSTRUCTION_RESISTANCE,
                AssessmentScenario.DATA_BOUNDARY_LEAKAGE,
            }
        ),
        SpecialistFamily.AGENT_PROTOCOL: frozenset(
            {
                AssessmentScenario.AGENT_IDENTITY_DELEGATION,
                AssessmentScenario.PROTOCOL_STATE,
                AssessmentScenario.DATA_BOUNDARY_LEAKAGE,
            }
        ),
        SpecialistFamily.TOOL_BOUNDARY: frozenset(
            {
                AssessmentScenario.TOOL_AUTHORIZATION,
                AssessmentScenario.AGENT_IDENTITY_DELEGATION,
                AssessmentScenario.DATA_BOUNDARY_LEAKAGE,
            }
        ),
        SpecialistFamily.RETRIEVAL: frozenset(
            {
                AssessmentScenario.RETRIEVAL_PROVENANCE,
                AssessmentScenario.INDIRECT_INSTRUCTION_RESISTANCE,
                AssessmentScenario.DATA_BOUNDARY_LEAKAGE,
            }
        ),
        SpecialistFamily.MODEL_SUPPLY_CHAIN: frozenset(
            {
                AssessmentScenario.MODEL_ARTIFACT_PROVENANCE,
                AssessmentScenario.DATA_BOUNDARY_LEAKAGE,
            }
        ),
        SpecialistFamily.MACHINE_TO_MACHINE_PROTOCOL: frozenset(
            {
                AssessmentScenario.AGENT_IDENTITY_DELEGATION,
                AssessmentScenario.PROTOCOL_STATE,
                AssessmentScenario.DATA_BOUNDARY_LEAKAGE,
            }
        ),
    }
)


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after secret scanning."""

    _validate_json(value, "value")
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if SECRET_MATERIAL_RE.search(encoded):
        raise AIProtocolSpecialistContractError("secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise AIProtocolSpecialistContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AIProtocolSpecialistContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise AIProtocolSpecialistContractError(f"{label} has an unsupported value")


def _reference(value: Any, label: str, namespace: str) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise AIProtocolSpecialistContractError(f"{label} must be an opaque reference")
    if not value.startswith(namespace + ":"):
        raise AIProtocolSpecialistContractError(f"{label} must use the {namespace} namespace")
    if SECRET_MATERIAL_RE.search(value):
        raise AIProtocolSpecialistContractError(f"{label} contains secret material")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise AIProtocolSpecialistContractError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise AIProtocolSpecialistContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AIProtocolSpecialistContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _evaluated_at(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AIProtocolSpecialistContractError("evaluated_at must be timezone aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _positive(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise AIProtocolSpecialistContractError(f"{label} is invalid")
    return value


def _nonnegative(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise AIProtocolSpecialistContractError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class SpecialistCapabilityDeclaration:
    family: SpecialistFamily
    capability_ref: str
    scenarios: tuple[AssessmentScenario, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "family", SpecialistFamily(self.family))
        object.__setattr__(
            self,
            "capability_ref",
            _reference(self.capability_ref, "capability_ref", "capabilityref"),
        )
        scenarios = tuple(AssessmentScenario(item) for item in self.scenarios)
        if not scenarios or len(scenarios) != len(set(scenarios)):
            raise AIProtocolSpecialistContractError("scenarios are invalid")
        if not set(scenarios).issubset(FAMILY_SCENARIOS[self.family]):
            raise AIProtocolSpecialistContractError("scenario is outside the specialist family")
        object.__setattr__(self, "scenarios", tuple(sorted(scenarios, key=str)))

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "ai_protocol_specialist_capability_declaration",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "family": self.family.value,
            "capability_ref": self.capability_ref,
            "scenarios": [item.value for item in self.scenarios],
            "fixture_policy": "safe_synthetic_only",
            "qualification_effect": "none",
        }

    @property
    def declaration_id(self) -> str:
        return _identity("APD", "ai-protocol-specialist-declaration-v1", self._body())[0]

    @property
    def declaration_sha256(self) -> str:
        return _identity("APD", "ai-protocol-specialist-declaration-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class AssessmentBudget:
    budget_ref: str
    maximum_adapter_requests: int
    maximum_observed_bytes: int
    maximum_observed_tokens: int
    maximum_duration_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "budget_ref", _reference(self.budget_ref, "budget_ref", "budgetref")
        )
        object.__setattr__(
            self,
            "maximum_adapter_requests",
            _positive(self.maximum_adapter_requests, "maximum_adapter_requests", MAX_REQUESTS),
        )
        object.__setattr__(
            self,
            "maximum_observed_bytes",
            _positive(self.maximum_observed_bytes, "maximum_observed_bytes", MAX_BYTES),
        )
        object.__setattr__(
            self,
            "maximum_observed_tokens",
            _positive(self.maximum_observed_tokens, "maximum_observed_tokens", MAX_TOKENS),
        )
        object.__setattr__(
            self,
            "maximum_duration_seconds",
            _positive(
                self.maximum_duration_seconds,
                "maximum_duration_seconds",
                MAX_WINDOW_SECONDS,
            ),
        )

    @property
    def budget_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_ref": self.budget_ref,
            "maximum_adapter_requests": self.maximum_adapter_requests,
            "maximum_observed_bytes": self.maximum_observed_bytes,
            "maximum_observed_tokens": self.maximum_observed_tokens,
            "maximum_duration_seconds": self.maximum_duration_seconds,
        }


@dataclass(frozen=True, slots=True)
class SpecialistAssessmentContext:
    tenant_ref: str
    context_ref: str
    context_binding_sha256: str
    scope_ref: str
    scope_sha256: str
    model_ref: str
    model_sha256: str
    tool_policy_ref: str
    tool_policy_sha256: str
    corpus_ref: str
    corpus_sha256: str
    session_ref: str
    agent_identity_ref: str
    agent_identity_sha256: str
    delegation_ref: str
    delegation_sha256: str
    protocol_ref: str
    protocol_state_sha256: str
    evidence_plan_ref: str
    evidence_plan_sha256: str
    action_admission_ref: str
    action_admission_sha256: str
    budget: AssessmentBudget

    def __post_init__(self) -> None:
        references = (
            ("tenant_ref", "tenantref"),
            ("context_ref", "contextref"),
            ("scope_ref", "scoperef"),
            ("model_ref", "modelref"),
            ("tool_policy_ref", "toolref"),
            ("corpus_ref", "corpusref"),
            ("session_ref", "sessionref"),
            ("agent_identity_ref", "agentref"),
            ("delegation_ref", "delegationref"),
            ("protocol_ref", "protocolref"),
            ("evidence_plan_ref", "evidenceref"),
            ("action_admission_ref", "admissionref"),
        )
        for field_name, namespace in references:
            object.__setattr__(
                self,
                field_name,
                _reference(getattr(self, field_name), field_name, namespace),
            )
        for field_name in (
            "context_binding_sha256",
            "scope_sha256",
            "model_sha256",
            "tool_policy_sha256",
            "corpus_sha256",
            "agent_identity_sha256",
            "delegation_sha256",
            "protocol_state_sha256",
            "evidence_plan_sha256",
            "action_admission_sha256",
        ):
            object.__setattr__(self, field_name, _digest(getattr(self, field_name), field_name))
        if not isinstance(self.budget, AssessmentBudget):
            raise AIProtocolSpecialistContractError("budget is invalid")

    @property
    def assessment_context_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_ref": self.tenant_ref,
            "context_ref": self.context_ref,
            "context_binding_sha256": self.context_binding_sha256,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "model_ref": self.model_ref,
            "model_sha256": self.model_sha256,
            "tool_policy_ref": self.tool_policy_ref,
            "tool_policy_sha256": self.tool_policy_sha256,
            "corpus_ref": self.corpus_ref,
            "corpus_sha256": self.corpus_sha256,
            "session_ref": self.session_ref,
            "agent_identity_ref": self.agent_identity_ref,
            "agent_identity_sha256": self.agent_identity_sha256,
            "delegation_ref": self.delegation_ref,
            "delegation_sha256": self.delegation_sha256,
            "protocol_ref": self.protocol_ref,
            "protocol_state_sha256": self.protocol_state_sha256,
            "evidence_plan_ref": self.evidence_plan_ref,
            "evidence_plan_sha256": self.evidence_plan_sha256,
            "action_admission_ref": self.action_admission_ref,
            "action_admission_sha256": self.action_admission_sha256,
            "budget": self.budget.to_dict(),
            "budget_sha256": self.budget.budget_sha256,
        }


@dataclass(frozen=True, slots=True)
class SafeSyntheticFixture:
    fixture_ref: str
    fixture_manifest_sha256: str
    synthetic: bool = True
    contains_real_credentials: bool = False
    contains_live_target_data: bool = False
    contains_harmful_payload_body: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "fixture_ref", _reference(self.fixture_ref, "fixture_ref", "fixtureref")
        )
        object.__setattr__(
            self,
            "fixture_manifest_sha256",
            _digest(self.fixture_manifest_sha256, "fixture_manifest_sha256"),
        )
        if self.synthetic is not True:
            raise AIProtocolSpecialistContractError("fixture must be synthetic")
        if (
            self.contains_real_credentials
            or self.contains_live_target_data
            or self.contains_harmful_payload_body
        ):
            raise AIProtocolSpecialistContractError("fixture is not safe for repository validation")

    @property
    def fixture_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_ref": self.fixture_ref,
            "fixture_manifest_sha256": self.fixture_manifest_sha256,
            "synthetic": self.synthetic,
            "contains_real_credentials": self.contains_real_credentials,
            "contains_live_target_data": self.contains_live_target_data,
            "contains_harmful_payload_body": self.contains_harmful_payload_body,
        }


@dataclass(frozen=True, slots=True)
class SpecialistAssessmentRequest:
    declaration_id: str
    declaration_sha256: str
    family: SpecialistFamily
    capability_ref: str
    scenario: AssessmentScenario
    context: SpecialistAssessmentContext
    fixture: SafeSyntheticFixture
    expected_control_sha256: str
    estimated_adapter_requests: int
    estimated_observed_bytes: int
    estimated_observed_tokens: int
    estimated_duration_seconds: int
    idempotency_sha256: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.declaration_id, str)
            or re.fullmatch(r"APD-[0-9A-F]{32}", self.declaration_id) is None
        ):
            raise AIProtocolSpecialistContractError("declaration_id is invalid")
        object.__setattr__(
            self,
            "declaration_sha256",
            _digest(self.declaration_sha256, "declaration_sha256"),
        )
        object.__setattr__(self, "family", SpecialistFamily(self.family))
        object.__setattr__(
            self,
            "capability_ref",
            _reference(self.capability_ref, "capability_ref", "capabilityref"),
        )
        object.__setattr__(self, "scenario", AssessmentScenario(self.scenario))
        if self.scenario not in FAMILY_SCENARIOS[self.family]:
            raise AIProtocolSpecialistContractError("scenario is outside the specialist family")
        if not isinstance(self.context, SpecialistAssessmentContext):
            raise AIProtocolSpecialistContractError("context is invalid")
        if not isinstance(self.fixture, SafeSyntheticFixture):
            raise AIProtocolSpecialistContractError("fixture is invalid")
        object.__setattr__(
            self,
            "expected_control_sha256",
            _digest(self.expected_control_sha256, "expected_control_sha256"),
        )
        object.__setattr__(
            self,
            "idempotency_sha256",
            _digest(self.idempotency_sha256, "idempotency_sha256"),
        )
        estimates = (
            ("estimated_adapter_requests", self.context.budget.maximum_adapter_requests),
            ("estimated_observed_bytes", self.context.budget.maximum_observed_bytes),
            ("estimated_observed_tokens", self.context.budget.maximum_observed_tokens),
            ("estimated_duration_seconds", self.context.budget.maximum_duration_seconds),
        )
        for field_name, maximum in estimates:
            object.__setattr__(
                self,
                field_name,
                _positive(getattr(self, field_name), field_name, maximum),
            )
        issued = _instant(_timestamp(self.issued_at, "issued_at"))
        expires = _instant(_timestamp(self.expires_at, "expires_at"))
        if not 0 < (expires - issued).total_seconds() <= MAX_WINDOW_SECONDS:
            raise AIProtocolSpecialistContractError("request window is invalid")

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "ai_protocol_specialist_assessment_request",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            "family": self.family.value,
            "capability_ref": self.capability_ref,
            "scenario": self.scenario.value,
            "context": self.context.to_dict(),
            "assessment_context_sha256": self.context.assessment_context_sha256,
            "fixture": self.fixture.to_dict(),
            "fixture_sha256": self.fixture.fixture_sha256,
            "expected_control_sha256": self.expected_control_sha256,
            "estimated_adapter_requests": self.estimated_adapter_requests,
            "estimated_observed_bytes": self.estimated_observed_bytes,
            "estimated_observed_tokens": self.estimated_observed_tokens,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "idempotency_sha256": self.idempotency_sha256,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "qualification_effect": "none",
        }

    @property
    def request_id(self) -> str:
        return _identity("APR", "ai-protocol-specialist-request-v1", self._body())[0]

    @property
    def request_sha256(self) -> str:
        return _identity("APR", "ai-protocol-specialist-request-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class SpecialistAssessmentObservation:
    request_id: str
    request_sha256: str
    assessment_context_sha256: str
    fixture_sha256: str
    disposition: AdapterDisposition
    outcome: AssessmentOutcome
    evidence_sha256: str
    actual_adapter_requests: int
    actual_observed_bytes: int
    actual_observed_tokens: int
    actual_duration_seconds: int
    network_call_performed: bool
    provider_call_performed: bool
    model_execution_performed: bool
    tool_execution_performed: bool
    raw_secret_observed: bool
    live_target_data_observed: bool
    started_at: str
    completed_at: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_id, str)
            or re.fullmatch(r"APR-[0-9A-F]{32}", self.request_id) is None
        ):
            raise AIProtocolSpecialistContractError("request_id is invalid")
        for field_name in (
            "request_sha256",
            "assessment_context_sha256",
            "fixture_sha256",
            "evidence_sha256",
        ):
            object.__setattr__(self, field_name, _digest(getattr(self, field_name), field_name))
        object.__setattr__(self, "disposition", AdapterDisposition(self.disposition))
        object.__setattr__(self, "outcome", AssessmentOutcome(self.outcome))
        counters = (
            ("actual_adapter_requests", MAX_REQUESTS),
            ("actual_observed_bytes", MAX_BYTES),
            ("actual_observed_tokens", MAX_TOKENS),
            ("actual_duration_seconds", MAX_WINDOW_SECONDS),
        )
        for field_name, maximum in counters:
            object.__setattr__(
                self,
                field_name,
                _nonnegative(getattr(self, field_name), field_name, maximum),
            )
        started = _instant(_timestamp(self.started_at, "started_at"))
        completed = _instant(_timestamp(self.completed_at, "completed_at"))
        if completed < started:
            raise AIProtocolSpecialistContractError("observation window is invalid")
        if any(
            (
                self.network_call_performed,
                self.provider_call_performed,
                self.model_execution_performed,
                self.tool_execution_performed,
                self.raw_secret_observed,
                self.live_target_data_observed,
            )
        ):
            raise AIProtocolSpecialistContractError("adapter crossed the repository-only boundary")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "assessment_context_sha256": self.assessment_context_sha256,
            "fixture_sha256": self.fixture_sha256,
            "disposition": self.disposition.value,
            "outcome": self.outcome.value,
            "evidence_sha256": self.evidence_sha256,
            "actual_adapter_requests": self.actual_adapter_requests,
            "actual_observed_bytes": self.actual_observed_bytes,
            "actual_observed_tokens": self.actual_observed_tokens,
            "actual_duration_seconds": self.actual_duration_seconds,
            "network_call_performed": self.network_call_performed,
            "provider_call_performed": self.provider_call_performed,
            "model_execution_performed": self.model_execution_performed,
            "tool_execution_performed": self.tool_execution_performed,
            "raw_secret_observed": self.raw_secret_observed,
            "live_target_data_observed": self.live_target_data_observed,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class SpecialistAssessmentAdapter(Protocol):
    """Caller-supplied, repository-safe assessment adapter."""

    def assess(self, request: SpecialistAssessmentRequest) -> SpecialistAssessmentObservation:
        """Evaluate a synthetic fixture without executing a model, tool, or network call."""


@dataclass(frozen=True, slots=True)
class SpecialistAssessmentReceipt:
    request: SpecialistAssessmentRequest
    observation: SpecialistAssessmentObservation
    status: ReceiptStatus

    def __post_init__(self) -> None:
        if not isinstance(self.request, SpecialistAssessmentRequest):
            raise AIProtocolSpecialistContractError("request is invalid")
        if not isinstance(self.observation, SpecialistAssessmentObservation):
            raise AIProtocolSpecialistContractError("observation is invalid")
        object.__setattr__(self, "status", ReceiptStatus(self.status))

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "ai_protocol_specialist_assessment_receipt",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "request_id": self.request.request_id,
            "request_sha256": self.request.request_sha256,
            "declaration_id": self.request.declaration_id,
            "declaration_sha256": self.request.declaration_sha256,
            "family": self.request.family.value,
            "capability_ref": self.request.capability_ref,
            "scenario": self.request.scenario.value,
            "assessment_context_sha256": self.request.context.assessment_context_sha256,
            "fixture_sha256": self.request.fixture.fixture_sha256,
            "idempotency_sha256": self.request.idempotency_sha256,
            "observation": self.observation.to_dict(),
            "status": self.status.value,
            "qualification_effect": "none",
        }

    @property
    def receipt_id(self) -> str:
        return _identity("APC", "ai-protocol-specialist-receipt-v1", self._body())[0]

    @property
    def receipt_sha256(self) -> str:
        return _identity("APC", "ai-protocol-specialist-receipt-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }


def recommended_capability_declarations() -> tuple[SpecialistCapabilityDeclaration, ...]:
    """Return deterministic declarations for all repository-only specialist families."""

    return tuple(
        SpecialistCapabilityDeclaration(
            family=family,
            capability_ref=f"capabilityref:ai-protocol/{family.value}",
            scenarios=tuple(sorted(scenarios, key=str)),
        )
        for family, scenarios in FAMILY_SCENARIOS.items()
    )


def dispatch_specialist_assessment(
    request: SpecialistAssessmentRequest,
    declaration: SpecialistCapabilityDeclaration,
    expected_context: SpecialistAssessmentContext,
    adapter: SpecialistAssessmentAdapter,
    *,
    evaluated_at: datetime,
    seen_request_ids: Iterable[str] = (),
    seen_idempotency_sha256: Iterable[str] = (),
) -> SpecialistAssessmentReceipt:
    """Validate exact bindings and invoke one caller-supplied adapter once."""

    if not isinstance(request, SpecialistAssessmentRequest):
        raise AIProtocolSpecialistContractError("request is invalid")
    if not isinstance(declaration, SpecialistCapabilityDeclaration):
        raise AIProtocolSpecialistContractError("declaration is invalid")
    if not isinstance(expected_context, SpecialistAssessmentContext):
        raise AIProtocolSpecialistContractError("expected_context is invalid")
    if (
        request.declaration_id != declaration.declaration_id
        or request.declaration_sha256 != declaration.declaration_sha256
        or request.family is not declaration.family
        or request.capability_ref != declaration.capability_ref
        or request.scenario not in declaration.scenarios
    ):
        raise AIProtocolSpecialistContractError("declaration binding mismatch")
    if request.context != expected_context:
        raise AIProtocolSpecialistContractError("assessment context mismatch")
    now = _evaluated_at(evaluated_at)
    if not _instant(request.issued_at) <= now <= _instant(request.expires_at):
        raise AIProtocolSpecialistContractError("request is not active")
    if request.request_id in set(seen_request_ids):
        raise AIProtocolSpecialistContractError("request replay is forbidden")
    if request.idempotency_sha256 in set(seen_idempotency_sha256):
        raise AIProtocolSpecialistContractError("idempotency replay is forbidden")

    observation = adapter.assess(request)
    if not isinstance(observation, SpecialistAssessmentObservation):
        raise AIProtocolSpecialistContractError("adapter returned an invalid observation")
    if (
        observation.request_id != request.request_id
        or observation.request_sha256 != request.request_sha256
        or observation.assessment_context_sha256 != request.context.assessment_context_sha256
        or observation.fixture_sha256 != request.fixture.fixture_sha256
    ):
        raise AIProtocolSpecialistContractError("observation binding mismatch")
    budget = request.context.budget
    actuals = (
        (observation.actual_adapter_requests, request.estimated_adapter_requests),
        (observation.actual_observed_bytes, request.estimated_observed_bytes),
        (observation.actual_observed_tokens, request.estimated_observed_tokens),
        (observation.actual_duration_seconds, request.estimated_duration_seconds),
        (observation.actual_adapter_requests, budget.maximum_adapter_requests),
        (observation.actual_observed_bytes, budget.maximum_observed_bytes),
        (observation.actual_observed_tokens, budget.maximum_observed_tokens),
        (observation.actual_duration_seconds, budget.maximum_duration_seconds),
    )
    if any(actual > maximum for actual, maximum in actuals):
        raise AIProtocolSpecialistContractError("adapter exceeded the bound budget")
    status = {
        AdapterDisposition.COMPLETED: ReceiptStatus.COMPLETED,
        AdapterDisposition.DENIED: ReceiptStatus.DENIED,
        AdapterDisposition.FAILED: ReceiptStatus.FAILED,
    }[observation.disposition]
    return SpecialistAssessmentReceipt(request=request, observation=observation, status=status)


def parse_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a serialized record by reconstructing it and comparing canonical form."""

    if not isinstance(value, Mapping):
        raise AIProtocolSpecialistContractError("contract must be an object")
    kind = value.get("kind")
    if kind == "ai_protocol_specialist_capability_declaration":
        expected = SpecialistCapabilityDeclaration(
            family=SpecialistFamily(value["family"]),
            capability_ref=value["capability_ref"],
            scenarios=tuple(AssessmentScenario(item) for item in value["scenarios"]),
        ).to_dict()
    elif kind == "ai_protocol_specialist_assessment_request":
        expected = _request_from_dict(value).to_dict()
    else:
        raise AIProtocolSpecialistContractError("contract kind is unsupported")
    if canonical_json(dict(value)) != canonical_json(expected):
        raise AIProtocolSpecialistContractError("contract identity or content is invalid")
    return expected


def _request_from_dict(value: Mapping[str, Any]) -> SpecialistAssessmentRequest:
    context_value = value["context"]
    budget_value = context_value["budget"]
    fixture_value = value["fixture"]
    budget = AssessmentBudget(
        budget_ref=budget_value["budget_ref"],
        maximum_adapter_requests=budget_value["maximum_adapter_requests"],
        maximum_observed_bytes=budget_value["maximum_observed_bytes"],
        maximum_observed_tokens=budget_value["maximum_observed_tokens"],
        maximum_duration_seconds=budget_value["maximum_duration_seconds"],
    )
    context = SpecialistAssessmentContext(
        tenant_ref=context_value["tenant_ref"],
        context_ref=context_value["context_ref"],
        context_binding_sha256=context_value["context_binding_sha256"],
        scope_ref=context_value["scope_ref"],
        scope_sha256=context_value["scope_sha256"],
        model_ref=context_value["model_ref"],
        model_sha256=context_value["model_sha256"],
        tool_policy_ref=context_value["tool_policy_ref"],
        tool_policy_sha256=context_value["tool_policy_sha256"],
        corpus_ref=context_value["corpus_ref"],
        corpus_sha256=context_value["corpus_sha256"],
        session_ref=context_value["session_ref"],
        agent_identity_ref=context_value["agent_identity_ref"],
        agent_identity_sha256=context_value["agent_identity_sha256"],
        delegation_ref=context_value["delegation_ref"],
        delegation_sha256=context_value["delegation_sha256"],
        protocol_ref=context_value["protocol_ref"],
        protocol_state_sha256=context_value["protocol_state_sha256"],
        evidence_plan_ref=context_value["evidence_plan_ref"],
        evidence_plan_sha256=context_value["evidence_plan_sha256"],
        action_admission_ref=context_value["action_admission_ref"],
        action_admission_sha256=context_value["action_admission_sha256"],
        budget=budget,
    )
    fixture = SafeSyntheticFixture(
        fixture_ref=fixture_value["fixture_ref"],
        fixture_manifest_sha256=fixture_value["fixture_manifest_sha256"],
        synthetic=fixture_value["synthetic"],
        contains_real_credentials=fixture_value["contains_real_credentials"],
        contains_live_target_data=fixture_value["contains_live_target_data"],
        contains_harmful_payload_body=fixture_value["contains_harmful_payload_body"],
    )
    return SpecialistAssessmentRequest(
        declaration_id=value["declaration_id"],
        declaration_sha256=value["declaration_sha256"],
        family=SpecialistFamily(value["family"]),
        capability_ref=value["capability_ref"],
        scenario=AssessmentScenario(value["scenario"]),
        context=context,
        fixture=fixture,
        expected_control_sha256=value["expected_control_sha256"],
        estimated_adapter_requests=value["estimated_adapter_requests"],
        estimated_observed_bytes=value["estimated_observed_bytes"],
        estimated_observed_tokens=value["estimated_observed_tokens"],
        estimated_duration_seconds=value["estimated_duration_seconds"],
        idempotency_sha256=value["idempotency_sha256"],
        issued_at=value["issued_at"],
        expires_at=value["expires_at"],
    )
