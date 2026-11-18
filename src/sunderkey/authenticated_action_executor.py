"""Authenticated single-attempt action execution with conservative custody.

The service prepares one durable claim before invoking a deployment-owned
primitive adapter exactly once. Portable receipts never authorize execution.
The configured authority must revalidate current MissionStore and admission
state while the service holds its immediate transaction. No automatic retry is
provided. A durable claim without a terminal settlement is reconciliation-only.

This reference custody is safe only when every executor instance for the trust
domain shares one database and its authority performs global assertion and
replay consumption in the same transaction. The standalone schema does not by
itself integrate the MissionStore global principal assertion ledger.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from .action_resolution import (
    AuthenticatedActionAdmissionReceipt,
    _identifier,
    _mapping,
    _sha256,
    _timestamp,
    parse_authenticated_action_admission_receipt,
)
from .errors import StoreConflictError, StoreError, StoreIntegrityError
from .qualification import _canonical_json, _canonical_sha256

SCHEMA_VERSION = 1
CUSTODY_APPLICATION_ID = 0x534B4132
CUSTODY_SCHEMA_VERSION = 1
ACTION_EXECUTE = "sunderkey.action.execute.v1"

REQUEST_DOMAIN = "sunderkey.authenticated-action-execution-request.v1"
CLAIM_DOMAIN = "sunderkey.authenticated-action-execution-claim.v1"
TERMINAL_DOMAIN = "sunderkey.authenticated-action-execution-terminal.v1"
COMMAND_DOMAIN = "sunderkey.authenticated-action-execution-command.v1"
AUTHORITY_STATE_DOMAIN = "sunderkey.action-execution-authority-state.v1"
AUTHORIZATION_INTENT_DOMAIN = "sunderkey.action-execute-authorization-intent.v1"
CUSTODY_DOMAIN = "sunderkey.authenticated-action-execution-custody.v1"
INPUT_DOMAIN = "sunderkey.action-adapter-input.v1"
RESULT_DOMAIN = "sunderkey.action-adapter-result.v1"

MAX_DOCUMENT_BYTES = 8_388_608
MAX_RESULT_BYTES = 67_108_864

_SECRET_MATERIAL = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|id[_-]?token|client[_-]?secret|"
    r"private[_-]?key|authorization|token)\b[\"']?\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bbasic\s+[A-Za-z0-9+/=]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"
    r")",
    re.IGNORECASE,
)
_SECRET_FIELD_NAMES = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "authtoken",
        "clientsecret",
        "credential",
        "credentialvalue",
        "credentials",
        "idtoken",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "token",
        "tokenvalue",
    }
)
_OPAQUE_SECRET_REFERENCE_SUFFIXES = (
    "digest",
    "hash",
    "id",
    "ref",
    "reference",
    "sha256",
)

AUTHORITY_CHECKS = (
    "adapter_qualified",
    "admission_current",
    "admission_unrevoked",
    "budget_current",
    "catalog_current",
    "cleanup_ready",
    "credential_current",
    "evidence_ready",
    "fence_current",
    "health_current",
    "lease_current",
    "mission_active",
    "plan_current",
    "scope_current",
    "session_current",
    "stop_ready",
    "trust_current",
)

RESOURCE_FIELDS = (
    "money_microunits",
    "rate_units",
    "request_bytes",
    "response_bytes",
    "duration_ms",
    "impact_events",
)

ADAPTER_FIELDS = (
    "adapter_id",
    "adapter_kind",
    "adapter_version",
    "adapter_build_sha256",
    "deployment_binding_sha256",
)

AUTHORIZATION_FIELDS = (
    "operation",
    "role",
    "principal_profile_id",
    "principal_subject",
    "assertion_issuer",
    "assertion_id",
    "assertion_sha256",
    "assertion_key_sha256",
    "trust_policy_sha256",
    "scope_grant_sha256",
    "operation_intent_sha256",
    "canonical_replay_key_sha256",
    "tenant_id",
    "mission_id",
    "scope_sha256",
    "target_sha256",
    "action_sha256",
    "receipt_sha256",
    "request_sha256",
    "decision",
    "issued_at",
    "expires_at",
)


class ActionExecutionError(StoreError):
    """Raised when execution custody or an adapter boundary fails closed."""


class ActionExecutionReconciliationRequired(ActionExecutionError):
    """Raised when an existing claim cannot be invoked again."""


class TerminalStatus(StrEnum):
    COMPLETED = "completed"
    FAILED_KNOWN = "failed_known"
    PREDISPATCH_ABORTED = "predispatch_aborted"
    INDETERMINATE_QUARANTINED = "indeterminate_quarantined"


class ActionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class AxisStatus(StrEnum):
    COMPLETE = "complete"
    PENDING = "pending"
    FAILED = "failed"
    UNKNOWN = "unknown"


class AdapterKind(StrEnum):
    HTTP = "http"
    BROWSER = "browser"
    SESSION = "session"
    SPECIALIST = "specialist"


def _strict_document(value: Any, label: str, depth: int = 0) -> None:
    if depth > 32:
        raise ActionExecutionError(f"{label} exceeds the nesting limit")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ActionExecutionError(f"{label} integer is outside the signed 64-bit range")
        return
    if isinstance(value, float):
        raise ActionExecutionError(f"{label} cannot contain floating-point values")
    if isinstance(value, str):
        if (
            not value.isascii()
            or len(value) > MAX_DOCUMENT_BYTES
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in value
            )
        ):
            raise ActionExecutionError(f"{label} contains invalid text")
        return
    if isinstance(value, list):
        if len(value) > 4096:
            raise ActionExecutionError(f"{label} contains too many values")
        for index, item in enumerate(value):
            _strict_document(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > 4096:
            raise ActionExecutionError(f"{label} contains too many fields")
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or not key
                or not key.isascii()
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in key
                )
            ):
                raise ActionExecutionError(f"{label} contains an invalid key")
            _strict_document(item, f"{label}.{key}", depth + 1)
        return
    raise ActionExecutionError(f"{label} contains an unsupported value")


def _document(raw: Any, label: str, *, maximum_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    value = _mapping(raw, label)
    _strict_document(value, label)
    serialized = _canonical_json(value)
    if len(serialized.encode("ascii")) > maximum_bytes:
        raise ActionExecutionError(f"{label} exceeds its byte ceiling")
    snapshot = json.loads(serialized)
    if type(snapshot) is not dict:
        raise ActionExecutionError(f"{label} must be an object")
    return snapshot


def _secret_field_name(value: str) -> bool:
    normalized = "".join(character.lower() for character in value if character.isalnum())
    if any(normalized.endswith(suffix) for suffix in _OPAQUE_SECRET_REFERENCE_SUFFIXES):
        return False
    if normalized in _SECRET_FIELD_NAMES:
        return True
    components = tuple(
        "".join(character.lower() for character in item if character.isalnum())
        for item in re.split(r"[^A-Za-z0-9]+", value)
        if item
    )
    return any(item in _SECRET_FIELD_NAMES for item in components)


def _reject_secret_material(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _secret_field_name(key) and item not in (None, "", [], {}):
                raise ActionExecutionError(f"{label} contains a raw secret field")
            _reject_secret_material(item, label)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_material(item, label)
    elif isinstance(value, str) and _SECRET_MATERIAL.search(value):
        raise ActionExecutionError(f"{label} contains raw secret material")


def _exact(value: Mapping[str, Any], fields: Sequence[str], label: str) -> None:
    if set(value) != set(fields):
        raise ActionExecutionError(f"{label} fields are invalid")


def _immutable_document(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _immutable_document(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_immutable_document(item) for item in value)
    return value


def _nonnegative(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ActionExecutionError(f"{label} must be a nonnegative integer")
    return value


def _positive(value: Any, label: str) -> int:
    value = _nonnegative(value, label)
    if value < 1:
        raise ActionExecutionError(f"{label} must be positive")
    return value


def _record(kind: str, prefix: str, domain: str, body: Mapping[str, Any]) -> dict[str, Any]:
    digest = _canonical_sha256({"domain": domain, "record": dict(body)})
    return {
        **dict(body),
        f"{kind}_id": f"{prefix}-{digest.removeprefix('sha256:')[:32].upper()}",
        f"{kind}_sha256": digest,
    }


def _validate_record(
    value: Mapping[str, Any],
    *,
    kind: str,
    prefix: str,
    domain: str,
) -> None:
    if type(value.get("schema_version")) is not int or value.get("schema_version") != 1:
        raise ActionExecutionError(f"{kind} schema version is invalid")
    if value.get("kind") != kind:
        raise ActionExecutionError(f"{kind} kind is invalid")
    record_id = _identifier(value.get(f"{kind}_id"), f"{kind} ID")
    digest = _sha256(value.get(f"{kind}_sha256"), f"{kind} hash")
    body = {
        key: item
        for key, item in value.items()
        if key not in {f"{kind}_id", f"{kind}_sha256"}
    }
    expected = _record(kind, prefix, domain, body)
    if record_id != expected[f"{kind}_id"] or digest != expected[f"{kind}_sha256"]:
        raise ActionExecutionError(f"{kind} content address is invalid")


@dataclass(frozen=True, slots=True)
class ExecutionResources:
    money_microunits: int
    rate_units: int
    request_bytes: int
    response_bytes: int
    duration_ms: int
    impact_events: int

    def __post_init__(self) -> None:
        for field in RESOURCE_FIELDS:
            _nonnegative(getattr(self, field), field)

    def to_dict(self) -> dict[str, int]:
        return {field: getattr(self, field) for field in RESOURCE_FIELDS}

    @classmethod
    def from_dict(cls, raw: Any) -> ExecutionResources:
        value = _document(raw, "execution resources")
        _exact(value, RESOURCE_FIELDS, "execution resources")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class ExecutionBudget:
    budget_id: str
    budget_sha256: str
    limits: ExecutionResources
    used: ExecutionResources
    reservation: ExecutionResources

    def __post_init__(self) -> None:
        _identifier(self.budget_id, "budget ID")
        _sha256(self.budget_sha256, "budget hash")
        if any(
            type(value) is not ExecutionResources
            for value in (self.limits, self.used, self.reservation)
        ):
            raise ActionExecutionError("Execution budget resources are invalid")
        for field in RESOURCE_FIELDS:
            if getattr(self.used, field) + getattr(self.reservation, field) > getattr(
                self.limits, field
            ):
                raise ActionExecutionError(f"{field} reservation exceeds its authority limit")
        for field in (
            "rate_units",
            "request_bytes",
            "response_bytes",
            "duration_ms",
            "impact_events",
        ):
            if getattr(self.reservation, field) < 1:
                raise ActionExecutionError(
                    f"Execution must reserve positive {field}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_id": self.budget_id,
            "budget_sha256": self.budget_sha256,
            "limits": self.limits.to_dict(),
            "reservation": self.reservation.to_dict(),
            "used": self.used.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class AdapterBinding:
    adapter_id: str
    adapter_kind: str
    adapter_version: str
    adapter_build_sha256: str
    deployment_binding_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, "adapter ID")
        AdapterKind(self.adapter_kind)
        _identifier(self.adapter_version, "adapter version")
        _sha256(self.adapter_build_sha256, "adapter build hash")
        _sha256(self.deployment_binding_sha256, "adapter deployment binding")

    def to_dict(self) -> dict[str, str]:
        return {field: getattr(self, field) for field in ADAPTER_FIELDS}

    @classmethod
    def from_dict(cls, raw: Any) -> AdapterBinding:
        value = _document(raw, "adapter binding")
        _exact(value, ADAPTER_FIELDS, "adapter binding")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class CurrentExecutionAuthorityState:
    tenant_id: str
    mission_id: str
    plan_id: str
    scope_sha256: str
    target_sha256: str
    action_sha256: str
    receipt_id: str
    receipt_sha256: str
    review_evidence_sha256: str
    catalog_id: str
    catalog_sha256: str
    catalog_version: str
    catalog_authority_sha256: str
    authority_revision_sha256: str
    checks: Mapping[str, bool]

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "mission_id",
            "plan_id",
            "receipt_id",
            "catalog_id",
            "catalog_version",
        ):
            _identifier(getattr(self, field), field)
        for field in (
            "scope_sha256",
            "target_sha256",
            "action_sha256",
            "receipt_sha256",
            "review_evidence_sha256",
            "catalog_sha256",
            "catalog_authority_sha256",
            "authority_revision_sha256",
        ):
            _sha256(getattr(self, field), field)
        checks = dict(self.checks)
        if set(checks) != set(AUTHORITY_CHECKS) or any(
            type(checks[field]) is not bool for field in AUTHORITY_CHECKS
        ):
            raise ActionExecutionError("Authority checks are invalid")
        object.__setattr__(self, "checks", MappingProxyType(checks))

    def require_all_current(self) -> None:
        failed = [field for field in AUTHORITY_CHECKS if not self.checks[field]]
        if failed:
            raise ActionExecutionError(
                "Execution authority is not current: " + ",".join(failed)
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_sha256": self.action_sha256,
            "authority_revision_sha256": self.authority_revision_sha256,
            "catalog_authority_sha256": self.catalog_authority_sha256,
            "catalog_id": self.catalog_id,
            "catalog_sha256": self.catalog_sha256,
            "catalog_version": self.catalog_version,
            "checks": {field: self.checks[field] for field in AUTHORITY_CHECKS},
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "review_evidence_sha256": self.review_evidence_sha256,
            "scope_sha256": self.scope_sha256,
            "target_sha256": self.target_sha256,
            "tenant_id": self.tenant_id,
        }

    @property
    def state_sha256(self) -> str:
        return _canonical_sha256(
            {"domain": AUTHORITY_STATE_DOMAIN, "state": self.to_dict()}
        )


@dataclass(frozen=True, slots=True)
class CurrentActionExecutionMaterial:
    admission_receipt: AuthenticatedActionAdmissionReceipt
    admission_custody_sha256: str
    authority_state: CurrentExecutionAuthorityState
    adapter: AdapterBinding
    adapter_input: Mapping[str, Any]
    budget: ExecutionBudget
    prior_assertion_sha256s: tuple[str, ...]
    prior_replay_key_sha256s: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActionExecutionCommand:
    receipt_id: str
    idempotency_key_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.receipt_id, "receipt ID")
        _sha256(self.idempotency_key_sha256, "idempotency key hash")

    def to_dict(self) -> dict[str, str]:
        return {
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "receipt_id": self.receipt_id,
        }

    @property
    def command_sha256(self) -> str:
        return _canonical_sha256(
            {"command": self.to_dict(), "domain": COMMAND_DOMAIN}
        )


class PrimitiveActionAdapter(Protocol):
    """Qualified primitive adapter below all retry and finalization layers."""

    @property
    def binding(self) -> AdapterBinding: ...

    def invoke_once(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


class SingleAttemptPrimitiveAdapter:
    """Provider-neutral wrapper around one effect-capable primitive call."""

    __slots__ = ("_binding", "_primitive")
    expected_kind: AdapterKind

    def __init__(
        self,
        binding: AdapterBinding,
        primitive: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> None:
        if type(binding) is not AdapterBinding:
            raise TypeError("primitive adapter binding is invalid")
        if AdapterKind(binding.adapter_kind) is not self.expected_kind:
            raise ValueError("primitive adapter kind is invalid")
        if not callable(primitive):
            raise TypeError("primitive adapter call is not callable")
        object.__setattr__(self, "_binding", binding)
        object.__setattr__(self, "_primitive", primitive)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_binding", "_primitive"} and hasattr(self, name):
            raise AttributeError("primitive adapter implementation is immutable")
        object.__setattr__(self, name, value)

    @property
    def binding(self) -> AdapterBinding:
        return self._binding

    def invoke_once(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(request, Mapping):
            raise TypeError("primitive adapter request must be a mapping")
        return self._primitive(request)


class HttpPrimitiveActionAdapter(SingleAttemptPrimitiveAdapter):
    __slots__ = ()
    expected_kind = AdapterKind.HTTP


class BrowserPrimitiveActionAdapter(SingleAttemptPrimitiveAdapter):
    __slots__ = ()
    expected_kind = AdapterKind.BROWSER


class SessionPrimitiveActionAdapter(SingleAttemptPrimitiveAdapter):
    __slots__ = ()
    expected_kind = AdapterKind.SESSION


class SpecialistPrimitiveActionAdapter(SingleAttemptPrimitiveAdapter):
    __slots__ = ()
    expected_kind = AdapterKind.SPECIALIST


class ActionExecutionAuthority(Protocol):
    """Portable reference authority used only by local contract tests.

    Production authority is reconstructed directly from MissionStore by the
    MissionStore action execution service and never supplied by a caller.
    """

    def load_current_execution(
        self,
        connection: sqlite3.Connection,
        command: ActionExecutionCommand,
        evaluated_at: str,
    ) -> CurrentActionExecutionMaterial: ...

    def authorize_action_execute(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        operation_intent_sha256: str,
        evaluated_at: str,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ActionExecutionRequest:
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def request_id(self) -> str:
        return self.to_dict()["action_execution_request_id"]

    @property
    def request_sha256(self) -> str:
        return self.to_dict()["action_execution_request_sha256"]


@dataclass(frozen=True, slots=True)
class ActionExecutionClaim:
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def claim_id(self) -> str:
        return self.to_dict()["action_execution_claim_id"]

    @property
    def claim_sha256(self) -> str:
        return self.to_dict()["action_execution_claim_sha256"]


@dataclass(frozen=True, slots=True)
class ActionExecutionTerminal:
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def terminal_id(self) -> str:
        return self.to_dict()["action_execution_terminal_id"]

    @property
    def terminal_sha256(self) -> str:
        return self.to_dict()["action_execution_terminal_sha256"]


def _parse_authorization(raw: Any) -> dict[str, Any]:
    value = _document(raw, "ACTION_EXECUTE authorization")
    _exact(value, AUTHORIZATION_FIELDS, "ACTION_EXECUTE authorization")
    if value["operation"] != ACTION_EXECUTE or value["decision"] != "approved":
        raise ActionExecutionError("ACTION_EXECUTE authorization decision is invalid")
    if value["role"] != "admission_control":
        raise ActionExecutionError("ACTION_EXECUTE authorization role is invalid")
    for field in (
        "principal_profile_id",
        "principal_subject",
        "assertion_issuer",
        "assertion_id",
        "tenant_id",
        "mission_id",
    ):
        _identifier(value[field], field)
    if value["principal_subject"] == value["assertion_issuer"]:
        raise ActionExecutionError("Assertion issuer and subject must differ")
    for field in (
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "receipt_sha256",
        "request_sha256",
    ):
        _sha256(value[field], field)
    issued = _timestamp(value["issued_at"], "authorization issued_at")
    expires = _timestamp(value["expires_at"], "authorization expires_at")
    if issued >= expires:
        raise ActionExecutionError("ACTION_EXECUTE authorization window is invalid")
    return value


def action_execute_authorization_intent_sha256(request: ActionExecutionRequest) -> str:
    request = parse_action_execution_request(request.to_dict())
    return _canonical_sha256(
        {
            "domain": AUTHORIZATION_INTENT_DOMAIN,
            "operation": ACTION_EXECUTE,
            "request": request.to_dict(),
        }
    )


def parse_action_execution_request(raw: Any) -> ActionExecutionRequest:
    value = _document(raw, "action execution request")
    fields = (
        "schema_version",
        "kind",
        "action_execution_request_id",
        "action_execution_request_sha256",
        "command_sha256",
        "idempotency_key_sha256",
        "admission_receipt",
        "admission_custody_sha256",
        "authority_state",
        "authority_state_sha256",
        "adapter",
        "adapter_input",
        "adapter_input_sha256",
        "budget_id",
        "budget_sha256",
        "reservation",
        "prepared_at",
        "execution_status",
    )
    _exact(value, fields, "action execution request")
    for field in (
        "command_sha256",
        "idempotency_key_sha256",
        "admission_custody_sha256",
        "budget_sha256",
    ):
        _sha256(value[field], field)
    _identifier(value["budget_id"], "budget ID")
    receipt = parse_authenticated_action_admission_receipt(value["admission_receipt"])
    state_raw = _document(value["authority_state"], "authority state")
    state = CurrentExecutionAuthorityState(**state_raw)
    if value["authority_state_sha256"] != state.state_sha256:
        raise ActionExecutionError("Authority state hash is invalid")
    receipt_doc = receipt.to_dict()
    if (
        state.receipt_id != receipt.receipt_id
        or state.receipt_sha256 != receipt.receipt_sha256
        or state.tenant_id != receipt_doc["tenant_id"]
        or state.mission_id != receipt_doc["mission_id"]
        or state.scope_sha256 != receipt_doc["scope_sha256"]
        or state.target_sha256 != receipt_doc["target_sha256"]
        or state.action_sha256 != receipt_doc["action_sha256"]
    ):
        raise ActionExecutionError("Authority state admission binding is invalid")
    state.require_all_current()
    AdapterBinding.from_dict(value["adapter"])
    adapter_input = _document(value["adapter_input"], "adapter input")
    _reject_secret_material(adapter_input, "adapter input")
    expected_input_hash = _canonical_sha256(
        {"adapter_input": adapter_input, "domain": INPUT_DOMAIN}
    )
    if value["adapter_input_sha256"] != expected_input_hash:
        raise ActionExecutionError("Adapter input hash is invalid")
    reservation = ExecutionResources.from_dict(value["reservation"])
    if any(
        getattr(reservation, field) < 1
        for field in (
            "rate_units",
            "request_bytes",
            "response_bytes",
            "duration_ms",
            "impact_events",
        )
    ):
        raise ActionExecutionError("Execution request reservation is incomplete")
    if len(_canonical_json(adapter_input).encode("ascii")) > reservation.request_bytes:
        raise ActionExecutionError("Adapter input exceeds its request reservation")
    prepared_at = _timestamp(value["prepared_at"], "prepared_at")
    if receipt_doc["evaluated_at"] > prepared_at:
        raise ActionExecutionError("Execution request predates its admission")
    if value["execution_status"] != "reserved_pending_adapter":
        raise ActionExecutionError("Execution request status is invalid")
    _validate_record(
        value,
        kind="action_execution_request",
        prefix="AXR",
        domain=REQUEST_DOMAIN,
    )
    return ActionExecutionRequest(_canonical_json(value))


def parse_action_execution_claim(raw: Any) -> ActionExecutionClaim:
    value = _document(raw, "action execution claim")
    fields = (
        "schema_version",
        "kind",
        "action_execution_claim_id",
        "action_execution_claim_sha256",
        "request_id",
        "request_sha256",
        "authorization",
        "claimed_at",
        "claim_status",
    )
    _exact(value, fields, "action execution claim")
    _identifier(value["request_id"], "request ID")
    _sha256(value["request_sha256"], "request hash")
    _parse_authorization(value["authorization"])
    _timestamp(value["claimed_at"], "claimed_at")
    if value["claim_status"] != "claimed_pending_dispatch":
        raise ActionExecutionError("Action execution claim status is invalid")
    _validate_record(
        value,
        kind="action_execution_claim",
        prefix="AXC",
        domain=CLAIM_DOMAIN,
    )
    return ActionExecutionClaim(_canonical_json(value))


def parse_action_execution_terminal(raw: Any) -> ActionExecutionTerminal:
    value = _document(raw, "action execution terminal", maximum_bytes=MAX_RESULT_BYTES)
    fields = (
        "schema_version",
        "kind",
        "action_execution_terminal_id",
        "action_execution_terminal_sha256",
        "request_id",
        "request_sha256",
        "claim_id",
        "claim_sha256",
        "terminal_status",
        "action_outcome",
        "evidence_status",
        "cleanup_status",
        "restoration_status",
        "result_sha256",
        "result_document",
        "charged_resources",
        "reason_code",
        "settled_at",
        "adapter_call_count",
        "adapter_call_count_status",
        "automatic_retry_count",
    )
    _exact(value, fields, "action execution terminal")
    _identifier(value["request_id"], "request ID")
    _identifier(value["claim_id"], "claim ID")
    _sha256(value["request_sha256"], "request hash")
    _sha256(value["claim_sha256"], "claim hash")
    status = TerminalStatus(value["terminal_status"])
    outcome = ActionOutcome(value["action_outcome"])
    for field in ("evidence_status", "cleanup_status", "restoration_status"):
        AxisStatus(value[field])
    _sha256(value["result_sha256"], "result hash")
    result_document = _document(
        value["result_document"],
        "result document",
        maximum_bytes=MAX_RESULT_BYTES,
    )
    if value["result_sha256"] != _canonical_sha256(
        {"domain": RESULT_DOMAIN, "result": result_document}
    ):
        raise ActionExecutionError("Terminal result hash is invalid")
    ExecutionResources.from_dict(value["charged_resources"])
    _identifier(value["reason_code"], "reason code")
    _timestamp(value["settled_at"], "settled_at")
    call_status = value["adapter_call_count_status"]
    call_count = value["adapter_call_count"]
    if (
        (call_status == "exactly_one" and (type(call_count) is not int or call_count != 1))
        or (call_status == "exactly_zero" and (type(call_count) is not int or call_count != 0))
        or (call_status == "unknown_zero_or_one" and call_count is not None)
        or call_status not in {"exactly_one", "exactly_zero", "unknown_zero_or_one"}
        or type(value["automatic_retry_count"]) is not int
        or value["automatic_retry_count"] != 0
    ):
        raise ActionExecutionError("Adapter call count or retry count is invalid")
    if (
        status in {TerminalStatus.COMPLETED, TerminalStatus.FAILED_KNOWN}
        and (call_status != "exactly_one" or call_count != 1)
    ) or (
        status is TerminalStatus.PREDISPATCH_ABORTED
        and (call_status != "exactly_zero" or call_count != 0)
    ):
        raise ActionExecutionError(
            "Terminal status and adapter call count are inconsistent"
        )
    expected_outcome = {
        TerminalStatus.COMPLETED: ActionOutcome.SUCCEEDED,
        TerminalStatus.FAILED_KNOWN: ActionOutcome.FAILED,
        TerminalStatus.PREDISPATCH_ABORTED: ActionOutcome.FAILED,
        TerminalStatus.INDETERMINATE_QUARANTINED: ActionOutcome.INDETERMINATE,
    }[status]
    if outcome is not expected_outcome:
        raise ActionExecutionError("Terminal status and action outcome are inconsistent")
    if status in {
        TerminalStatus.PREDISPATCH_ABORTED,
        TerminalStatus.INDETERMINATE_QUARANTINED,
    }:
        _exact(result_document, ("reason_code", "trusted_result"), "quarantine result")
        if (
            result_document["reason_code"] != value["reason_code"]
            or result_document["trusted_result"] is not False
            or any(
                value[field] != AxisStatus.UNKNOWN.value
                for field in (
                    "evidence_status",
                    "cleanup_status",
                    "restoration_status",
                )
            )
        ):
            raise ActionExecutionError("Quarantine result and axes are inconsistent")
        if status is TerminalStatus.PREDISPATCH_ABORTED and any(
            value["charged_resources"][field] != 0 for field in RESOURCE_FIELDS
        ):
            raise ActionExecutionError(
                "Predispatch abort must not charge reserved resources"
            )
    else:
        _exact(
            result_document,
            (
                "request_id",
                "request_sha256",
                "action_sha256",
                "adapter",
                "outcome",
                "evidence_status",
                "cleanup_status",
                "restoration_status",
                "result_payload",
                "resources_used",
            ),
            "known terminal result",
        )
        if (
            result_document["request_id"] != value["request_id"]
            or result_document["request_sha256"] != value["request_sha256"]
            or result_document["outcome"] != value["action_outcome"]
            or result_document["evidence_status"] != value["evidence_status"]
            or result_document["cleanup_status"] != value["cleanup_status"]
            or result_document["restoration_status"] != value["restoration_status"]
            or result_document["resources_used"] != value["charged_resources"]
            or call_status != "exactly_one"
        ):
            raise ActionExecutionError("Known terminal result and axes are inconsistent")
        _identifier(result_document["request_id"], "result request ID")
        _sha256(result_document["request_sha256"], "result request hash")
        _sha256(result_document["action_sha256"], "result action hash")
        AdapterBinding.from_dict(result_document["adapter"])
        ActionOutcome(result_document["outcome"])
        for field in (
            "evidence_status",
            "cleanup_status",
            "restoration_status",
        ):
            AxisStatus(result_document[field])
        payload = _document(
            result_document["result_payload"],
            "known terminal result payload",
            maximum_bytes=MAX_RESULT_BYTES,
        )
        _reject_secret_material(payload, "known terminal result payload")
        known_resources = ExecutionResources.from_dict(
            result_document["resources_used"]
        )
        if any(
            getattr(known_resources, field) < 1
            for field in (
                "rate_units",
                "request_bytes",
                "response_bytes",
                "duration_ms",
                "impact_events",
            )
        ):
            raise ActionExecutionError("Known terminal resource use is underreported")
    _validate_record(
        value,
        kind="action_execution_terminal",
        prefix="AXT",
        domain=TERMINAL_DOMAIN,
    )
    return ActionExecutionTerminal(_canonical_json(value))


_SCHEMA = """
CREATE TABLE action_execution_requests (
    request_id TEXT PRIMARY KEY,
    request_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL UNIQUE,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    idempotency_key_sha256 TEXT NOT NULL,
    command_sha256 TEXT NOT NULL,
    request_json TEXT NOT NULL,
    custody_sha256 TEXT NOT NULL UNIQUE,
    prepared_at TEXT NOT NULL,
    UNIQUE (idempotency_key_sha256),
    CHECK (typeof(request_id) = 'text'),
    CHECK (typeof(request_sha256) = 'text'),
    CHECK (typeof(tenant_id) = 'text'),
    CHECK (typeof(mission_id) = 'text'),
    CHECK (typeof(receipt_id) = 'text'),
    CHECK (typeof(receipt_sha256) = 'text'),
    CHECK (typeof(idempotency_key_sha256) = 'text'),
    CHECK (typeof(command_sha256) = 'text'),
    CHECK (typeof(request_json) = 'text'),
    CHECK (typeof(custody_sha256) = 'text'),
    CHECK (typeof(prepared_at) = 'text')
) STRICT;

CREATE TABLE action_execution_claims (
    claim_id TEXT PRIMARY KEY,
    claim_sha256 TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    authorization_json TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    claimed_at TEXT NOT NULL,
    claim_status TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES action_execution_requests(request_id),
    CHECK (typeof(claim_id) = 'text'),
    CHECK (typeof(claim_sha256) = 'text'),
    CHECK (typeof(request_id) = 'text'),
    CHECK (typeof(authorization_json) = 'text'),
    CHECK (typeof(claim_json) = 'text'),
    CHECK (typeof(claimed_at) = 'text'),
    CHECK (typeof(claim_status) = 'text')
) STRICT;

CREATE TABLE action_execution_assertion_uses (
    assertion_issuer TEXT NOT NULL,
    assertion_id TEXT NOT NULL,
    assertion_sha256 TEXT NOT NULL UNIQUE,
    canonical_replay_key_sha256 TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    authorization_json TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    PRIMARY KEY (assertion_issuer, assertion_id),
    FOREIGN KEY (request_id) REFERENCES action_execution_requests(request_id),
    CHECK (typeof(assertion_issuer) = 'text'),
    CHECK (typeof(assertion_id) = 'text'),
    CHECK (typeof(assertion_sha256) = 'text'),
    CHECK (typeof(canonical_replay_key_sha256) = 'text'),
    CHECK (typeof(request_id) = 'text'),
    CHECK (typeof(authorization_json) = 'text'),
    CHECK (typeof(consumed_at) = 'text')
) STRICT;

CREATE TABLE action_execution_reservations (
    request_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    budget_id TEXT NOT NULL,
    budget_sha256 TEXT NOT NULL,
    money_microunits INTEGER NOT NULL CHECK (money_microunits >= 0),
    rate_units INTEGER NOT NULL CHECK (rate_units >= 0),
    request_bytes INTEGER NOT NULL CHECK (request_bytes >= 0),
    response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    impact_events INTEGER NOT NULL CHECK (impact_events >= 0),
    reserved_at TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES action_execution_requests(request_id),
    CHECK (typeof(request_id) = 'text'),
    CHECK (typeof(tenant_id) = 'text'),
    CHECK (typeof(mission_id) = 'text'),
    CHECK (typeof(budget_id) = 'text'),
    CHECK (typeof(budget_sha256) = 'text'),
    CHECK (typeof(money_microunits) = 'integer'),
    CHECK (typeof(rate_units) = 'integer'),
    CHECK (typeof(request_bytes) = 'integer'),
    CHECK (typeof(response_bytes) = 'integer'),
    CHECK (typeof(duration_ms) = 'integer'),
    CHECK (typeof(impact_events) = 'integer'),
    CHECK (typeof(reserved_at) = 'text')
) STRICT;

CREATE TABLE action_execution_terminals (
    terminal_id TEXT PRIMARY KEY,
    terminal_sha256 TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL UNIQUE,
    terminal_status TEXT NOT NULL,
    terminal_json TEXT NOT NULL,
    money_charged_microunits INTEGER NOT NULL CHECK (money_charged_microunits >= 0),
    rate_units_charged INTEGER NOT NULL CHECK (rate_units_charged >= 0),
    request_bytes_charged INTEGER NOT NULL CHECK (request_bytes_charged >= 0),
    response_bytes_charged INTEGER NOT NULL CHECK (response_bytes_charged >= 0),
    duration_ms_charged INTEGER NOT NULL CHECK (duration_ms_charged >= 0),
    impact_events_charged INTEGER NOT NULL CHECK (impact_events_charged >= 0),
    settled_at TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES action_execution_requests(request_id),
    FOREIGN KEY (claim_id) REFERENCES action_execution_claims(claim_id),
    CHECK (typeof(terminal_id) = 'text'),
    CHECK (typeof(terminal_sha256) = 'text'),
    CHECK (typeof(request_id) = 'text'),
    CHECK (typeof(claim_id) = 'text'),
    CHECK (typeof(terminal_status) = 'text'),
    CHECK (typeof(terminal_json) = 'text'),
    CHECK (typeof(money_charged_microunits) = 'integer'),
    CHECK (typeof(rate_units_charged) = 'integer'),
    CHECK (typeof(request_bytes_charged) = 'integer'),
    CHECK (typeof(response_bytes_charged) = 'integer'),
    CHECK (typeof(duration_ms_charged) = 'integer'),
    CHECK (typeof(impact_events_charged) = 'integer'),
    CHECK (typeof(settled_at) = 'text')
) STRICT;

CREATE TRIGGER action_execution_requests_no_update BEFORE UPDATE ON action_execution_requests
BEGIN SELECT RAISE(ABORT, 'action execution request custody is immutable'); END;
CREATE TRIGGER action_execution_requests_no_delete BEFORE DELETE ON action_execution_requests
BEGIN SELECT RAISE(ABORT, 'action execution request custody is immutable'); END;
CREATE TRIGGER action_execution_claims_no_update BEFORE UPDATE ON action_execution_claims
BEGIN SELECT RAISE(ABORT, 'action execution claim custody is immutable'); END;
CREATE TRIGGER action_execution_claims_no_delete BEFORE DELETE ON action_execution_claims
BEGIN SELECT RAISE(ABORT, 'action execution claim custody is immutable'); END;
CREATE TRIGGER action_execution_assertion_uses_no_update
BEFORE UPDATE ON action_execution_assertion_uses
BEGIN SELECT RAISE(ABORT, 'action execution assertion custody is immutable'); END;
CREATE TRIGGER action_execution_assertion_uses_no_delete
BEFORE DELETE ON action_execution_assertion_uses
BEGIN SELECT RAISE(ABORT, 'action execution assertion custody is immutable'); END;
CREATE TRIGGER action_execution_reservations_no_update
BEFORE UPDATE ON action_execution_reservations
BEGIN SELECT RAISE(ABORT, 'action execution reservation custody is immutable'); END;
CREATE TRIGGER action_execution_reservations_no_delete
BEFORE DELETE ON action_execution_reservations
BEGIN SELECT RAISE(ABORT, 'action execution reservation custody is immutable'); END;
CREATE TRIGGER action_execution_terminals_no_update BEFORE UPDATE ON action_execution_terminals
BEGIN SELECT RAISE(ABORT, 'action execution terminal custody is immutable'); END;
CREATE TRIGGER action_execution_terminals_no_delete BEFORE DELETE ON action_execution_terminals
BEGIN SELECT RAISE(ABORT, 'action execution terminal custody is immutable'); END;
"""


def _schema_statements() -> tuple[str, ...]:
    result: list[str] = []
    pending = ""
    for line in _SCHEMA.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            result.append(pending.strip())
            pending = ""
    if pending.strip():
        raise StoreIntegrityError("Action execution schema text is incomplete")
    return tuple(result)


def _schema_objects(connection: sqlite3.Connection) -> dict[tuple[str, str], str]:
    rows = connection.execute(
        """
        SELECT type, name, sql FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name
        """
    ).fetchall()
    objects: dict[tuple[str, str], str] = {}
    for row in rows:
        row_type, name, sql = row[0], row[1], row[2]
        if type(row_type) is not str or type(name) is not str or type(sql) is not str:
            raise StoreIntegrityError("Action execution schema metadata is invalid")
        objects[(row_type, name)] = sql
    return objects


def _expected_schema_objects() -> dict[tuple[str, str], str]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(_SCHEMA)
        return _schema_objects(connection)
    finally:
        connection.close()


_EXPECTED_SCHEMA_OBJECTS = _expected_schema_objects()


def _parse_adapter_result(
    raw: Any,
    request: ActionExecutionRequest,
    adapter: AdapterBinding,
    reservation: ExecutionResources,
) -> tuple[dict[str, Any], ExecutionResources]:
    value = _document(raw, "adapter result", maximum_bytes=MAX_RESULT_BYTES)
    fields = (
        "request_id",
        "request_sha256",
        "action_sha256",
        "adapter",
        "outcome",
        "evidence_status",
        "cleanup_status",
        "restoration_status",
        "result_payload",
        "resources_used",
    )
    _exact(value, fields, "adapter result")
    request_doc = request.to_dict()
    if (
        value["request_id"] != request.request_id
        or value["request_sha256"] != request.request_sha256
        or value["action_sha256"]
        != request_doc["admission_receipt"]["action_sha256"]
        or AdapterBinding.from_dict(value["adapter"]) != adapter
        or AdapterBinding.from_dict(request_doc["adapter"]) != adapter
    ):
        raise ActionExecutionError("Adapter result substitution detected")
    ActionOutcome(value["outcome"])
    if value["outcome"] == ActionOutcome.INDETERMINATE.value:
        raise ActionExecutionError("Adapter cannot assert an indeterminate result")
    for field in ("evidence_status", "cleanup_status", "restoration_status"):
        AxisStatus(value[field])
    payload = _document(
        value["result_payload"],
        "adapter result payload",
        maximum_bytes=MAX_RESULT_BYTES,
    )
    _reject_secret_material(payload, "adapter result payload")
    used = ExecutionResources.from_dict(value["resources_used"])
    if any(getattr(used, field) > getattr(reservation, field) for field in RESOURCE_FIELDS):
        raise ActionExecutionError("Adapter result exceeds an execution reservation")
    request_bytes = len(_canonical_json(request.to_dict()["adapter_input"]).encode("ascii"))
    if (
        used.rate_units < 1
        or used.request_bytes < request_bytes
        or used.response_bytes < 1
        or used.duration_ms < 1
        or used.impact_events < 1
    ):
        raise ActionExecutionError("Adapter result underreports mandatory resource use")
    return value, used


class AuthenticatedActionExecutionService:
    """Local reference custody used by portable contract tests only.

    Production action execution uses MissionStoreAuthenticatedActionExecutionService
    so admission, replay, budget, dispatch, and settlement share one authority store.
    """

    def __init__(
        self,
        path: str | Path,
        authority: ActionExecutionAuthority,
        adapter: PrimitiveActionAdapter,
        *,
        clock: Callable[[], datetime] | None = None,
        busy_timeout_ms: int = 5000,
    ) -> None:
        if any(
            not callable(getattr(authority, name, None))
            for name in ("load_current_execution", "authorize_action_execute")
        ):
            raise TypeError("authority does not implement the action execution contract")
        if not callable(getattr(adapter, "invoke_once", None)):
            raise TypeError("adapter does not implement the primitive single-attempt contract")
        adapter_binding = getattr(adapter, "binding", None)
        if type(adapter_binding) is not AdapterBinding:
            raise TypeError("adapter binding is invalid")
        if type(busy_timeout_ms) is not int or not 1 <= busy_timeout_ms <= 120000:
            raise ValueError("busy_timeout_ms must be between 1 and 120000")
        self._path = Path(path).resolve()
        self._authority = authority
        self._adapter = adapter
        self._adapter_binding = adapter_binding
        self._invoke_once = adapter.invoke_once
        self._clock = clock or (lambda: datetime.now(UTC))
        self._busy_timeout_ms = busy_timeout_ms

    @staticmethod
    def _format_time(value: datetime) -> str:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ActionExecutionError("Execution clock must return an aware datetime")
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _now(self) -> str:
        return self._format_time(self._clock())

    def _require_service_adapter_binding(self) -> None:
        binding = getattr(self._adapter, "binding", None)
        if type(binding) is not AdapterBinding or binding != self._adapter_binding:
            raise ActionExecutionError("Service adapter binding changed")

    def _configure(self, connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA recursive_triggers = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")

    def initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._path, isolation_level=None)
        try:
            self._configure(connection)
            connection.execute("BEGIN IMMEDIATE")
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if type(application_id) is not int or type(user_version) is not int:
                raise StoreIntegrityError("Action execution custody markers are invalid")
            existing = _schema_objects(connection)
            if (application_id, user_version) == (
                CUSTODY_APPLICATION_ID,
                CUSTODY_SCHEMA_VERSION,
            ):
                self._require_schema(connection)
                connection.commit()
                return
            if (application_id, user_version) != (0, 0) or existing:
                raise StoreIntegrityError("Action execution custody is not a pristine store")
            for statement in _schema_statements():
                connection.execute(statement)
            connection.execute(f"PRAGMA application_id = {CUSTODY_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {CUSTODY_SCHEMA_VERSION}")
            connection.commit()
            self._require_schema(connection)
        except sqlite3.Error as exc:
            connection.rollback()
            raise StoreError("Could not initialize action execution custody") from exc
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        if not self._path.is_file():
            raise StoreError("Action execution custody is not initialized")
        connection = sqlite3.connect(
            self._path.as_uri() + "?mode=rw",
            uri=True,
            isolation_level=None,
            timeout=self._busy_timeout_ms / 1000,
        )
        try:
            self._configure(connection)
            self._require_schema(connection)
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
        quick_check = connection.execute("PRAGMA quick_check").fetchall()
        if (
            type(application_id) is not int
            or type(user_version) is not int
            or application_id != CUSTODY_APPLICATION_ID
            or user_version != CUSTODY_SCHEMA_VERSION
            or _schema_objects(connection) != _EXPECTED_SCHEMA_OBJECTS
            or len(quick_check) != 1
            or tuple(quick_check[0]) != ("ok",)
            or connection.execute("PRAGMA foreign_key_check").fetchall()
        ):
            raise StoreIntegrityError("Action execution custody schema is invalid")

    def execute(self, command: ActionExecutionCommand) -> ActionExecutionTerminal:
        if type(command) is not ActionExecutionCommand:
            raise TypeError("command must be an ActionExecutionCommand")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT * FROM action_execution_requests
                WHERE idempotency_key_sha256 = ?
                """,
                (command.idempotency_key_sha256,),
            ).fetchone()
            if existing is not None:
                if existing["command_sha256"] != command.command_sha256:
                    raise StoreConflictError(
                        "Execution idempotency key is bound to different intent"
                    )
                terminal = self._verify_execution(connection, existing)
                if terminal is None:
                    raise ActionExecutionReconciliationRequired(
                        "Execution claim has no settlement and cannot be invoked again"
                    )
                connection.commit()
                return terminal
            self._require_service_adapter_binding()
            prepared_at = self._now()
            material = self._authority.load_current_execution(
                connection, command, prepared_at
            )
            request = self._prepare_request(command, material, prepared_at)
            intent = action_execute_authorization_intent_sha256(request)
            authorization = _parse_authorization(
                self._authority.authorize_action_execute(
                    connection, request, intent, prepared_at
                )
            )
            self._validate_authorization(
                request, material, authorization, intent, prepared_at
            )
            claim = self._build_claim(request, authorization, prepared_at)
            self._reserve(connection, request, material.budget)
            self._insert_prepared(
                connection, command, request, claim, authorization, material
            )
            connection.commit()
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StoreConflictError(
                "Action execution conflicts with replay, budget, or custody state"
            ) from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

        try:
            self._require_service_adapter_binding()
        except BaseException as exc:
            reason = "adapter_binding_failure_" + type(exc).__name__.lower()
            return self._quarantine_after_claim(request, claim, reason)
        try:
            raw_result = self._invoke_once(_immutable_document(request.to_dict()))
        except BaseException as exc:
            reason = "adapter_exception_" + type(exc).__name__.lower()
            return self._quarantine_after_claim(request, claim, reason)
        try:
            result, used = _parse_adapter_result(
                raw_result,
                request,
                self._adapter_binding,
                material.budget.reservation,
            )
        except BaseException as exc:
            reason = "result_rejected_" + type(exc).__name__.lower()
            return self._quarantine_after_claim(request, claim, reason)
        try:
            settled_at = self._now()
        except BaseException:
            return self._quarantine_after_claim(
                request, claim, "settlement_clock_failure"
            )
        status = (
            TerminalStatus.COMPLETED
            if result["outcome"] == ActionOutcome.SUCCEEDED.value
            else TerminalStatus.FAILED_KNOWN
        )
        try:
            terminal = self._build_terminal(
                request=request,
                claim=claim,
                status=status,
                outcome=ActionOutcome(result["outcome"]),
                evidence=AxisStatus(result["evidence_status"]),
                cleanup=AxisStatus(result["cleanup_status"]),
                restoration=AxisStatus(result["restoration_status"]),
                result_document=result,
                charged=used,
                reason_code="adapter_reported_" + result["outcome"],
                settled_at=settled_at,
            )
        except BaseException as exc:
            reason = "terminal_build_failure_" + type(exc).__name__.lower()
            return self._quarantine_after_claim(request, claim, reason)
        try:
            return self._settle(request, claim, terminal)
        except BaseException:
            return self._quarantine_after_claim(
                request, claim, "settlement_failure"
            )

    def reconcile_claim(
        self,
        request_id: str,
        *,
        reason_code: str = "claim_without_settlement",
    ) -> ActionExecutionTerminal:
        _identifier(request_id, "request ID")
        _identifier(reason_code, "reason code")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM action_execution_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise ActionExecutionError("Execution request is absent from custody")
            terminal = self._verify_execution(connection, row)
            if terminal is not None:
                connection.commit()
                return terminal
            claim_row = connection.execute(
                "SELECT * FROM action_execution_claims WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if claim_row is None:
                raise StoreIntegrityError("Execution claim is missing")
            request = parse_action_execution_request(json.loads(row["request_json"]))
            claim = parse_action_execution_claim(json.loads(claim_row["claim_json"]))
            reservation = self._reservation_from_row(
                connection.execute(
                    "SELECT * FROM action_execution_reservations WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
            )
            try:
                settled_at = self._now()
            except BaseException:
                settled_at = claim.to_dict()["claimed_at"]
            terminal = self._indeterminate_terminal(
                request,
                claim,
                reservation,
                reason_code,
                settled_at,
                invocation_known=False,
            )
            self._insert_terminal(connection, terminal)
            connection.commit()
            return terminal
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StoreConflictError("Execution reconciliation conflicts") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def verify_store(self) -> dict[str, int | str]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM action_execution_requests ORDER BY request_id"
            ).fetchall()
            terminal_count = 0
            for row in rows:
                terminal = self._verify_execution(connection, row)
                terminal_count += int(terminal is not None)
            connection.commit()
            return {
                "request_count": len(rows),
                "terminal_count": terminal_count,
                "reconciliation_required_count": len(rows) - terminal_count,
                "status": "valid",
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _prepare_request(
        self,
        command: ActionExecutionCommand,
        material: CurrentActionExecutionMaterial,
        prepared_at: str,
    ) -> ActionExecutionRequest:
        if type(material) is not CurrentActionExecutionMaterial:
            raise ActionExecutionError("Authority returned invalid execution material")
        receipt = parse_authenticated_action_admission_receipt(
            material.admission_receipt.to_dict()
        )
        _sha256(material.admission_custody_sha256, "admission custody hash")
        if type(material.authority_state) is not CurrentExecutionAuthorityState:
            raise ActionExecutionError("Authority returned invalid execution state")
        material.authority_state.require_all_current()
        if (
            type(material.adapter) is not AdapterBinding
            or material.adapter != self._adapter_binding
        ):
            raise ActionExecutionError("Current adapter authority differs from service adapter")
        if type(material.budget) is not ExecutionBudget:
            raise ActionExecutionError("Authority returned invalid execution budget")
        receipt_doc = receipt.to_dict()
        state = material.authority_state
        if (
            command.receipt_id != receipt.receipt_id
            or state.receipt_id != receipt.receipt_id
            or state.receipt_sha256 != receipt.receipt_sha256
            or state.tenant_id != receipt_doc["tenant_id"]
            or state.mission_id != receipt_doc["mission_id"]
            or state.scope_sha256 != receipt_doc["scope_sha256"]
            or state.target_sha256 != receipt_doc["target_sha256"]
            or state.action_sha256 != receipt_doc["action_sha256"]
        ):
            raise ActionExecutionError("Current execution state differs from admission")
        prior_assertions = self._hash_tuple(
            material.prior_assertion_sha256s, "prior assertion hashes"
        )
        prior_replays = self._hash_tuple(
            material.prior_replay_key_sha256s, "prior replay keys"
        )
        admission = receipt_doc["admission_authorization"]
        if (
            admission["assertion_sha256"] not in prior_assertions
            or admission["canonical_replay_key_sha256"] not in prior_replays
        ):
            raise ActionExecutionError("Prior admission authentication custody is incomplete")
        adapter_input = _document(material.adapter_input, "adapter input")
        _reject_secret_material(adapter_input, "adapter input")
        input_hash = _canonical_sha256(
            {"adapter_input": adapter_input, "domain": INPUT_DOMAIN}
        )
        actual_request_bytes = len(_canonical_json(adapter_input).encode("ascii"))
        if actual_request_bytes > material.budget.reservation.request_bytes:
            raise ActionExecutionError("Adapter input exceeds its byte reservation")
        body = {
            "schema_version": 1,
            "kind": "action_execution_request",
            "command_sha256": command.command_sha256,
            "idempotency_key_sha256": command.idempotency_key_sha256,
            "admission_receipt": receipt.to_dict(),
            "admission_custody_sha256": material.admission_custody_sha256,
            "authority_state": state.to_dict(),
            "authority_state_sha256": state.state_sha256,
            "adapter": material.adapter.to_dict(),
            "adapter_input": adapter_input,
            "adapter_input_sha256": input_hash,
            "budget_id": material.budget.budget_id,
            "budget_sha256": material.budget.budget_sha256,
            "reservation": material.budget.reservation.to_dict(),
            "prepared_at": prepared_at,
            "execution_status": "reserved_pending_adapter",
        }
        return parse_action_execution_request(
            _record("action_execution_request", "AXR", REQUEST_DOMAIN, body)
        )

    @staticmethod
    def _hash_tuple(values: Any, label: str) -> tuple[str, ...]:
        if type(values) is not tuple or not values:
            raise ActionExecutionError(f"{label} are invalid")
        checked = tuple(_sha256(value, label) for value in values)
        if checked != tuple(sorted(set(checked))):
            raise ActionExecutionError(f"{label} must be unique and ordered")
        return checked

    @staticmethod
    def _validate_authorization(
        request: ActionExecutionRequest,
        material: CurrentActionExecutionMaterial,
        authorization: Mapping[str, Any],
        intent: str,
        prepared_at: str,
    ) -> None:
        request_doc = request.to_dict()
        receipt = request_doc["admission_receipt"]
        state = request_doc["authority_state"]
        expected = {
            "tenant_id": state["tenant_id"],
            "mission_id": state["mission_id"],
            "scope_sha256": state["scope_sha256"],
            "target_sha256": state["target_sha256"],
            "action_sha256": state["action_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "request_sha256": request.request_sha256,
            "operation_intent_sha256": intent,
        }
        if any(authorization[field] != value for field, value in expected.items()):
            raise ActionExecutionError("ACTION_EXECUTE authorization binding is invalid")
        if not authorization["issued_at"] <= prepared_at < authorization["expires_at"]:
            raise ActionExecutionError("ACTION_EXECUTE authorization is not current")
        if (
            authorization["assertion_sha256"] in material.prior_assertion_sha256s
            or authorization["canonical_replay_key_sha256"]
            in material.prior_replay_key_sha256s
        ):
            raise ActionExecutionError("ACTION_EXECUTE reuses prior authentication")

    @staticmethod
    def _build_claim(
        request: ActionExecutionRequest,
        authorization: Mapping[str, Any],
        claimed_at: str,
    ) -> ActionExecutionClaim:
        body = {
            "schema_version": 1,
            "kind": "action_execution_claim",
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "authorization": dict(authorization),
            "claimed_at": claimed_at,
            "claim_status": "claimed_pending_dispatch",
        }
        return parse_action_execution_claim(
            _record("action_execution_claim", "AXC", CLAIM_DOMAIN, body)
        )

    def _reserve(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        budget: ExecutionBudget,
    ) -> None:
        columns = {
            "money_microunits": "money_microunits",
            "rate_units": "rate_units",
            "request_bytes": "request_bytes",
            "response_bytes": "response_bytes",
            "duration_ms": "duration_ms",
            "impact_events": "impact_events",
        }
        sums = connection.execute(
            """
            SELECT COALESCE(SUM(CASE WHEN t.request_id IS NULL
                                      THEN r.money_microunits
                                      ELSE t.money_charged_microunits END), 0),
                   COALESCE(SUM(CASE WHEN t.request_id IS NULL
                                      THEN r.rate_units
                                      ELSE t.rate_units_charged END), 0),
                   COALESCE(SUM(CASE WHEN t.request_id IS NULL
                                      THEN r.request_bytes
                                      ELSE t.request_bytes_charged END), 0),
                   COALESCE(SUM(CASE WHEN t.request_id IS NULL
                                      THEN r.response_bytes
                                      ELSE t.response_bytes_charged END), 0),
                   COALESCE(SUM(CASE WHEN t.request_id IS NULL
                                      THEN r.duration_ms
                                      ELSE t.duration_ms_charged END), 0),
                   COALESCE(SUM(CASE WHEN t.request_id IS NULL
                                      THEN r.impact_events
                                      ELSE t.impact_events_charged END), 0)
            FROM action_execution_reservations AS r
            LEFT JOIN action_execution_terminals AS t
              ON t.request_id = r.request_id
            WHERE r.tenant_id = ? AND r.mission_id = ?
              AND r.budget_id = ? AND r.budget_sha256 = ?
            """,
            (
                request.to_dict()["authority_state"]["tenant_id"],
                request.to_dict()["authority_state"]["mission_id"],
                budget.budget_id,
                budget.budget_sha256,
            ),
        ).fetchone()
        if sums is None or any(type(value) is not int for value in sums):
            raise StoreIntegrityError("Execution reservation totals have invalid types")
        for index, field in enumerate(columns):
            if (
                getattr(budget.used, field)
                + sums[index]
                + getattr(budget.reservation, field)
                > getattr(budget.limits, field)
            ):
                raise ActionExecutionError(
                    f"Authoritative {field} budget cannot be reserved"
                )

    def _insert_prepared(
        self,
        connection: sqlite3.Connection,
        command: ActionExecutionCommand,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        authorization: Mapping[str, Any],
        material: CurrentActionExecutionMaterial,
    ) -> None:
        request_doc = request.to_dict()
        claim_doc = claim.to_dict()
        receipt = request_doc["admission_receipt"]
        custody = {
            "claim": claim_doc,
            "command": command.to_dict(),
            "command_sha256": command.command_sha256,
            "request": request_doc,
        }
        custody_sha = _canonical_sha256(
            {"custody": custody, "domain": CUSTODY_DOMAIN}
        )
        connection.execute(
            """
            INSERT INTO action_execution_requests(
                request_id, request_sha256, tenant_id, mission_id,
                receipt_id, receipt_sha256, idempotency_key_sha256,
                command_sha256, request_json, custody_sha256, prepared_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.request_id,
                request.request_sha256,
                receipt["tenant_id"],
                receipt["mission_id"],
                receipt["receipt_id"],
                receipt["receipt_sha256"],
                command.idempotency_key_sha256,
                command.command_sha256,
                _canonical_json(request_doc),
                custody_sha,
                request_doc["prepared_at"],
            ),
        )
        connection.execute(
            """
            INSERT INTO action_execution_claims(
                claim_id, claim_sha256, request_id, authorization_json,
                claim_json, claimed_at, claim_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                claim.claim_id,
                claim.claim_sha256,
                request.request_id,
                _canonical_json(dict(authorization)),
                _canonical_json(claim_doc),
                claim_doc["claimed_at"],
                claim_doc["claim_status"],
            ),
        )
        connection.execute(
            """
            INSERT INTO action_execution_assertion_uses(
                assertion_issuer, assertion_id, assertion_sha256,
                canonical_replay_key_sha256, request_id,
                authorization_json, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authorization["assertion_issuer"],
                authorization["assertion_id"],
                authorization["assertion_sha256"],
                authorization["canonical_replay_key_sha256"],
                request.request_id,
                _canonical_json(dict(authorization)),
                claim_doc["claimed_at"],
            ),
        )
        reservation = material.budget.reservation.to_dict()
        connection.execute(
            """
            INSERT INTO action_execution_reservations(
                request_id, tenant_id, mission_id, budget_id, budget_sha256,
                money_microunits, rate_units, request_bytes, response_bytes,
                duration_ms, impact_events, reserved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.request_id,
                receipt["tenant_id"],
                receipt["mission_id"],
                material.budget.budget_id,
                material.budget.budget_sha256,
                *(reservation[field] for field in RESOURCE_FIELDS),
                claim_doc["claimed_at"],
            ),
        )

    def _quarantine_after_claim(
        self,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        reason_code: str,
    ) -> ActionExecutionTerminal:
        _identifier(reason_code, "reason code")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            request_row = connection.execute(
                "SELECT * FROM action_execution_requests WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            if request_row is None:
                raise StoreIntegrityError("Claimed execution request is missing")
            existing = self._verify_execution(connection, request_row)
            self._verify_claim_binding(connection, request, claim)
            if existing is not None:
                connection.commit()
                return existing
            reservation = self._reservation_from_row(
                connection.execute(
                    "SELECT * FROM action_execution_reservations WHERE request_id = ?",
                    (request.request_id,),
                ).fetchone()
            )
            try:
                settled_at = self._now()
            except BaseException:
                settled_at = claim.to_dict()["claimed_at"]
            terminal = self._indeterminate_terminal(
                request,
                claim,
                reservation,
                reason_code,
                settled_at,
                invocation_known=True,
            )
            self._insert_terminal(connection, terminal)
            connection.commit()
            return terminal
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StoreConflictError(
                "Indeterminate execution settlement conflicts"
            ) from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _settle(
        self,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        terminal: ActionExecutionTerminal,
    ) -> ActionExecutionTerminal:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            request_row = connection.execute(
                "SELECT * FROM action_execution_requests WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            if request_row is None:
                raise StoreIntegrityError("Claimed execution request is missing")
            existing = self._verify_execution(connection, request_row)
            self._verify_claim_binding(connection, request, claim)
            if existing is not None:
                if existing.document_json != terminal.document_json:
                    raise StoreConflictError("Execution has a different terminal settlement")
                connection.commit()
                return existing
            reservation = self._reservation_from_row(
                connection.execute(
                    "SELECT * FROM action_execution_reservations WHERE request_id = ?",
                    (request.request_id,),
                ).fetchone()
            )
            charged = ExecutionResources.from_dict(
                terminal.to_dict()["charged_resources"]
            )
            if any(
                getattr(charged, field) > getattr(reservation, field)
                for field in RESOURCE_FIELDS
            ):
                raise StoreIntegrityError("Terminal charges exceed reservation")
            self._insert_terminal(connection, terminal)
            connection.commit()
            return terminal
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StoreConflictError("Execution settlement conflicts") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _build_terminal(
        *,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        status: TerminalStatus,
        outcome: ActionOutcome,
        evidence: AxisStatus,
        cleanup: AxisStatus,
        restoration: AxisStatus,
        result_document: Mapping[str, Any],
        charged: ExecutionResources,
        reason_code: str,
        settled_at: str,
        invocation_known: bool = True,
        invocation_zero: bool = False,
    ) -> ActionExecutionTerminal:
        result = _document(
            result_document, "terminal result", maximum_bytes=MAX_RESULT_BYTES
        )
        result_hash = _canonical_sha256(
            {"domain": RESULT_DOMAIN, "result": result}
        )
        body = {
            "schema_version": 1,
            "kind": "action_execution_terminal",
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "claim_id": claim.claim_id,
            "claim_sha256": claim.claim_sha256,
            "terminal_status": status.value,
            "action_outcome": outcome.value,
            "evidence_status": evidence.value,
            "cleanup_status": cleanup.value,
            "restoration_status": restoration.value,
            "result_sha256": result_hash,
            "result_document": result,
            "charged_resources": charged.to_dict(),
            "reason_code": reason_code,
            "settled_at": settled_at,
            "adapter_call_count": (
                0
                if status is TerminalStatus.PREDISPATCH_ABORTED or invocation_zero
                else (1 if invocation_known else None)
            ),
            "adapter_call_count_status": (
                "exactly_zero"
                if status is TerminalStatus.PREDISPATCH_ABORTED or invocation_zero
                else ("exactly_one" if invocation_known else "unknown_zero_or_one")
            ),
            "automatic_retry_count": 0,
        }
        return parse_action_execution_terminal(
            _record("action_execution_terminal", "AXT", TERMINAL_DOMAIN, body)
        )

    @classmethod
    def _indeterminate_terminal(
        cls,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        reservation: ExecutionResources,
        reason_code: str,
        settled_at: str,
        *,
        invocation_known: bool,
    ) -> ActionExecutionTerminal:
        return cls._build_terminal(
            request=request,
            claim=claim,
            status=TerminalStatus.INDETERMINATE_QUARANTINED,
            outcome=ActionOutcome.INDETERMINATE,
            evidence=AxisStatus.UNKNOWN,
            cleanup=AxisStatus.UNKNOWN,
            restoration=AxisStatus.UNKNOWN,
            result_document={"reason_code": reason_code, "trusted_result": False},
            charged=reservation,
            reason_code=reason_code,
            settled_at=settled_at,
            invocation_known=invocation_known,
        )

    @staticmethod
    def _insert_terminal(
        connection: sqlite3.Connection,
        terminal: ActionExecutionTerminal,
    ) -> None:
        document = terminal.to_dict()
        charged = document["charged_resources"]
        connection.execute(
            """
            INSERT INTO action_execution_terminals(
                terminal_id, terminal_sha256, request_id, claim_id,
                terminal_status, terminal_json, money_charged_microunits,
                rate_units_charged, request_bytes_charged,
                response_bytes_charged, duration_ms_charged,
                impact_events_charged, settled_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                terminal.terminal_id,
                terminal.terminal_sha256,
                document["request_id"],
                document["claim_id"],
                document["terminal_status"],
                _canonical_json(document),
                *(charged[field] for field in RESOURCE_FIELDS),
                document["settled_at"],
            ),
        )

    @staticmethod
    def _reservation_from_row(row: sqlite3.Row | None) -> ExecutionResources:
        if row is None:
            raise StoreIntegrityError("Execution reservation is missing")
        for field in RESOURCE_FIELDS:
            if type(row[field]) is not int:
                raise StoreIntegrityError("Execution reservation type is invalid")
        return ExecutionResources(**{field: row[field] for field in RESOURCE_FIELDS})

    @staticmethod
    def _terminal_for_request(
        connection: sqlite3.Connection,
        request_id: str,
    ) -> ActionExecutionTerminal | None:
        row = connection.execute(
            "SELECT * FROM action_execution_terminals WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        if type(row["terminal_json"]) is not str:
            raise StoreIntegrityError("Stored terminal JSON type is invalid")
        try:
            raw = json.loads(row["terminal_json"])
            if _canonical_json(raw) != row["terminal_json"]:
                raise StoreIntegrityError("Stored terminal JSON is not canonical")
            terminal = parse_action_execution_terminal(raw)
        except (json.JSONDecodeError, TypeError, ValueError, StoreError) as exc:
            raise StoreIntegrityError("Stored execution terminal is invalid") from exc
        document = terminal.to_dict()
        charged = document["charged_resources"]
        text_fields = (
            "terminal_id",
            "terminal_sha256",
            "request_id",
            "claim_id",
            "terminal_status",
            "terminal_json",
            "settled_at",
        )
        integer_fields = (
            "money_charged_microunits",
            "rate_units_charged",
            "request_bytes_charged",
            "response_bytes_charged",
            "duration_ms_charged",
            "impact_events_charged",
        )
        if any(type(row[field]) is not str for field in text_fields) or any(
            type(row[field]) is not int for field in integer_fields
        ):
            raise StoreIntegrityError("Stored terminal column type is invalid")
        expected = {
            "terminal_id": terminal.terminal_id,
            "terminal_sha256": terminal.terminal_sha256,
            "request_id": document["request_id"],
            "claim_id": document["claim_id"],
            "terminal_status": document["terminal_status"],
            "settled_at": document["settled_at"],
            "money_charged_microunits": charged["money_microunits"],
            "rate_units_charged": charged["rate_units"],
            "request_bytes_charged": charged["request_bytes"],
            "response_bytes_charged": charged["response_bytes"],
            "duration_ms_charged": charged["duration_ms"],
            "impact_events_charged": charged["impact_events"],
        }
        if any(row[field] != value for field, value in expected.items()):
            raise StoreIntegrityError("Stored terminal columns are inconsistent")
        return terminal

    def _verify_claim_binding(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM action_execution_claims WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Execution claim is missing")
        if any(
            type(row[field]) is not str
            for field in (
                "claim_id",
                "claim_sha256",
                "request_id",
                "authorization_json",
                "claim_json",
                "claimed_at",
                "claim_status",
            )
        ):
            raise StoreIntegrityError("Execution claim column type is invalid")
        if (
            row["claim_id"] != claim.claim_id
            or row["claim_sha256"] != claim.claim_sha256
            or row["claim_json"] != claim.document_json
            or row["request_id"] != request.request_id
            or row["authorization_json"]
            != _canonical_json(claim.to_dict()["authorization"])
            or row["claimed_at"] != claim.to_dict()["claimed_at"]
            or row["claim_status"] != claim.to_dict()["claim_status"]
            or claim.to_dict()["request_sha256"] != request.request_sha256
        ):
            raise StoreIntegrityError("Execution claim custody differs from caller material")

    def _verify_execution(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> ActionExecutionTerminal | None:
        if any(
            type(row[field]) is not str
            for field in row.keys()  # noqa: SIM118 - Row iteration returns values
        ):
            raise StoreIntegrityError("Execution request column type is invalid")
        try:
            request_raw = json.loads(row["request_json"])
            if _canonical_json(request_raw) != row["request_json"]:
                raise StoreIntegrityError("Stored execution request is not canonical")
            request = parse_action_execution_request(request_raw)
        except (json.JSONDecodeError, TypeError, ValueError, StoreError) as exc:
            raise StoreIntegrityError("Stored execution request is invalid") from exc
        request_doc = request.to_dict()
        receipt = request_doc["admission_receipt"]
        command = {
            "idempotency_key_sha256": request_doc["idempotency_key_sha256"],
            "receipt_id": receipt["receipt_id"],
        }
        command_sha = _canonical_sha256(
            {"command": command, "domain": COMMAND_DOMAIN}
        )
        if (
            row["request_id"] != request.request_id
            or row["request_sha256"] != request.request_sha256
            or row["tenant_id"] != receipt["tenant_id"]
            or row["mission_id"] != receipt["mission_id"]
            or row["receipt_id"] != receipt["receipt_id"]
            or row["receipt_sha256"] != receipt["receipt_sha256"]
            or row["idempotency_key_sha256"] != command["idempotency_key_sha256"]
            or row["command_sha256"] != command_sha
            or row["prepared_at"] != request_doc["prepared_at"]
        ):
            raise StoreIntegrityError("Stored execution request columns are inconsistent")
        claim_row = connection.execute(
            "SELECT * FROM action_execution_claims WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        if claim_row is None or type(claim_row["claim_json"]) is not str:
            raise StoreIntegrityError("Stored execution claim is incomplete")
        try:
            claim_raw = json.loads(claim_row["claim_json"])
            if _canonical_json(claim_raw) != claim_row["claim_json"]:
                raise StoreIntegrityError("Stored execution claim is not canonical")
            claim = parse_action_execution_claim(claim_raw)
        except (json.JSONDecodeError, TypeError, ValueError, StoreError) as exc:
            raise StoreIntegrityError("Stored execution claim is invalid") from exc
        self._verify_claim_binding(connection, request, claim)
        authorization = _parse_authorization(claim.to_dict()["authorization"])
        state = request_doc["authority_state"]
        if (
            authorization["request_sha256"] != request.request_sha256
            or authorization["operation_intent_sha256"]
            != action_execute_authorization_intent_sha256(request)
            or authorization["tenant_id"] != state["tenant_id"]
            or authorization["mission_id"] != state["mission_id"]
            or authorization["scope_sha256"] != state["scope_sha256"]
            or authorization["target_sha256"] != state["target_sha256"]
            or authorization["action_sha256"] != state["action_sha256"]
            or authorization["receipt_sha256"] != receipt["receipt_sha256"]
            or not authorization["issued_at"]
            <= request_doc["prepared_at"]
            <= claim.to_dict()["claimed_at"]
            < authorization["expires_at"]
            or request_doc["prepared_at"] > claim.to_dict()["claimed_at"]
        ):
            raise StoreIntegrityError("Stored execution authorization is invalid")
        auth_rows = connection.execute(
            "SELECT * FROM action_execution_assertion_uses WHERE request_id = ?",
            (request.request_id,),
        ).fetchall()
        if len(auth_rows) != 1:
            raise StoreIntegrityError("Execution assertion custody is incomplete")
        auth_row = auth_rows[0]
        if any(
            type(auth_row[field]) is not str
            for field in auth_row.keys()  # noqa: SIM118 - Row iteration returns values
        ):
            raise StoreIntegrityError("Execution assertion column type is invalid")
        if (
            auth_row["assertion_issuer"] != authorization["assertion_issuer"]
            or auth_row["assertion_id"] != authorization["assertion_id"]
            or auth_row["assertion_sha256"] != authorization["assertion_sha256"]
            or auth_row["canonical_replay_key_sha256"]
            != authorization["canonical_replay_key_sha256"]
            or auth_row["authorization_json"] != _canonical_json(authorization)
            or auth_row["consumed_at"] != claim.to_dict()["claimed_at"]
        ):
            raise StoreIntegrityError("Execution assertion custody is inconsistent")
        reservation_row = connection.execute(
            "SELECT * FROM action_execution_reservations WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        reservation = self._reservation_from_row(reservation_row)
        if any(
            type(reservation_row[field]) is not str
            for field in (
                "request_id",
                "tenant_id",
                "mission_id",
                "budget_id",
                "budget_sha256",
                "reserved_at",
            )
        ):
            raise StoreIntegrityError("Execution reservation column type is invalid")
        if (
            reservation.to_dict() != request_doc["reservation"]
            or reservation_row["request_id"] != request.request_id
            or reservation_row["tenant_id"] != receipt["tenant_id"]
            or reservation_row["mission_id"] != receipt["mission_id"]
            or reservation_row["budget_id"] != request_doc["budget_id"]
            or reservation_row["budget_sha256"] != request_doc["budget_sha256"]
            or reservation_row["reserved_at"] != claim.to_dict()["claimed_at"]
        ):
            raise StoreIntegrityError("Execution reservation custody is inconsistent")
        custody = {
            "claim": claim.to_dict(),
            "command": command,
            "command_sha256": command_sha,
            "request": request.to_dict(),
        }
        expected_custody = _canonical_sha256(
            {"custody": custody, "domain": CUSTODY_DOMAIN}
        )
        if row["custody_sha256"] != expected_custody:
            raise StoreIntegrityError("Execution custody hash is invalid")
        terminal = self._terminal_for_request(connection, request.request_id)
        if terminal is not None:
            terminal_doc = terminal.to_dict()
            charged = ExecutionResources.from_dict(terminal_doc["charged_resources"])
            if (
                terminal_doc["request_sha256"] != request.request_sha256
                or terminal_doc["claim_id"] != claim.claim_id
                or terminal_doc["claim_sha256"] != claim.claim_sha256
                or terminal_doc["settled_at"] < claim.to_dict()["claimed_at"]
                or any(
                    getattr(charged, field) > getattr(reservation, field)
                    for field in RESOURCE_FIELDS
                )
            ):
                raise StoreIntegrityError("Execution terminal chain is invalid")
            if terminal_doc["terminal_status"] != TerminalStatus.INDETERMINATE_QUARANTINED:
                result = terminal_doc["result_document"]
                if (
                    result["action_sha256"] != receipt["action_sha256"]
                    or AdapterBinding.from_dict(result["adapter"])
                    != AdapterBinding.from_dict(request_doc["adapter"])
                ):
                    raise StoreIntegrityError(
                        "Execution terminal adapter binding is invalid"
                    )
            if (
                terminal_doc["terminal_status"]
                == TerminalStatus.INDETERMINATE_QUARANTINED.value
                and charged != reservation
            ):
                raise StoreIntegrityError(
                    "Indeterminate execution did not charge its full reservation"
                )
        return terminal


__all__ = [
    "ACTION_EXECUTE",
    "ActionExecutionClaim",
    "ActionExecutionCommand",
    "ActionExecutionError",
    "ActionExecutionReconciliationRequired",
    "ActionExecutionRequest",
    "ActionExecutionTerminal",
    "ActionOutcome",
    "AdapterKind",
    "AdapterBinding",
    "BrowserPrimitiveActionAdapter",
    "AxisStatus",
    "CurrentActionExecutionMaterial",
    "CurrentExecutionAuthorityState",
    "ExecutionBudget",
    "ExecutionResources",
    "HttpPrimitiveActionAdapter",
    "PrimitiveActionAdapter",
    "SessionPrimitiveActionAdapter",
    "SingleAttemptPrimitiveAdapter",
    "SpecialistPrimitiveActionAdapter",
    "TerminalStatus",
    "action_execute_authorization_intent_sha256",
    "parse_action_execution_claim",
    "parse_action_execution_request",
    "parse_action_execution_terminal",
]
