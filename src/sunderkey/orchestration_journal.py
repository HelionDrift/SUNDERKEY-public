"""Durable, authority-neutral orchestration journal.

The journal coordinates repository work without becoming a source of mission,
workspace, evidence, approval, or execution truth. It persists only immutable
jobs, message envelopes, job lease and outcome records, saga observations,
delivery observations, and source-bound read-model projections.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Any, ClassVar, Generic, TypeVar

SCHEMA_VERSION = 1
APPLICATION_ID = 0x534F4A31
MAX_RECORD_BYTES = 131_072
MAX_JSON_DEPTH = 12
MAX_JSON_ITEMS = 20_000
MAX_PAGE_SIZE = 200

NO_AUTHORITY_EFFECTS = MappingProxyType(
    {
        "action_authority": "none",
        "authoritative_state": "unchanged",
        "completion_inference": "forbidden",
        "credential_access": "none",
        "network": "none",
        "target_interaction": "none",
    }
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_RECORD_ID_RE = re.compile(r"[A-Z]{3}-[0-9A-F]{32}\Z")
_SECRET_TEXT_RE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"\bsk-[A-Za-z0-9_-]{20,}\b|"
    r"\b(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret)\s*[:=])",
    re.IGNORECASE,
)
_FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization_header",
        "client_secret",
        "cookie",
        "credential_value",
        "password",
        "private_key",
        "raw_evidence",
        "refresh_token",
        "secret",
        "secret_value",
    }
)
_EVENT_CONTRACTS = MappingProxyType(
    {
        "action_execution.attempt_claimed": ("job", "AEA-"),
        "action_execution.handoff_quarantined": ("job", "AEQ-"),
        "action_execution.intent_recorded": ("action_execution", "AEI-"),
        "action_execution.reconciled": ("job", "AER-"),
        "action_execution.terminal_observed": ("job", "AEO-"),
        "job.claimed": ("job", "JCL-"),
        "job.claim_renewed": ("job", "JCL-"),
        "job.lease_exhausted": ("job", "JOU-"),
        "job.submitted": ("job", "JOB-"),
        "job.worker_observation": ("job", "JOU-"),
        "message.delivery_observed": ("message", "DLA-"),
        "message.recorded": ("message", "MSG-"),
        "outbox.delivery_claimed": ("job", "ODC-"),
        "projection.reconciled": ("projection", "PRJ-"),
        "saga.step_recorded": ("saga", "SGS-"),
    }
)
_MIGRATION_LOCK = Lock()


def _secret_field_name(value: str) -> bool:
    semantic = re.sub(r"[^a-z0-9]", "", value.lower())
    exact = {
        "accesstoken",
        "apikey",
        "authorization",
        "authorizationheader",
        "clientsecret",
        "cookie",
        "credentialvalue",
        "password",
        "passwd",
        "privatekey",
        "rawcredential",
        "rawsecret",
        "refreshtoken",
        "secretvalue",
    }
    return semantic in exact or semantic.endswith(
        ("password", "passwd", "privatekey", "secret", "cookie")
    )


def _validate_projection_payload(value: Any, label: str = "projection payload") -> None:
    if isinstance(value, Mapping):
        for key, member in value.items():
            if not isinstance(key, str):
                raise OrchestrationValidationError(f"{label} contains an invalid key")
            semantic = re.sub(r"[^a-z0-9]", "", key.lower())
            if _secret_field_name(key) or semantic.endswith(("token", "key")):
                raise OrchestrationValidationError(
                    f"{label} contains a secret-bearing field"
                )
            _validate_projection_payload(member, f"{label}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, member in enumerate(value):
            _validate_projection_payload(member, f"{label}[{index}]")


class OrchestrationJournalError(RuntimeError):
    """Base error for Phase197 orchestration custody."""


class OrchestrationValidationError(OrchestrationJournalError):
    """Raised when a closed record is invalid."""


class OrchestrationConflictError(OrchestrationJournalError):
    """Raised for stale fences, replay rebinding, or source drift."""


class OrchestrationIntegrityError(OrchestrationJournalError):
    """Raised when durable journal state does not verify."""


class OrchestrationBusyError(OrchestrationJournalError):
    """Raised when the bounded SQLite write lock is unavailable."""


class SourceKind(StrEnum):
    MISSION_STORE = "mission_store"
    EXPERT_WORKSPACE = "expert_workspace"
    EVIDENCE_REPOSITORY = "evidence_repository"


class JobKind(StrEnum):
    SOURCE_RECONCILIATION = "source_reconciliation"
    PROJECTION_REFRESH = "projection_refresh"
    INBOX_PROCESSING = "inbox_processing"
    OUTBOX_DELIVERY = "outbox_delivery"
    ACTION_EXECUTION_HANDOFF = "action_execution_handoff"
    SAGA_COORDINATION = "saga_coordination"


_INDETERMINATE_ON_EXPIRED_LEASE = frozenset(
    {JobKind.OUTBOX_DELIVERY}
)
_RESERVED_EXTERNAL_EFFECT_JOBS = frozenset(
    {JobKind.OUTBOX_DELIVERY, JobKind.ACTION_EXECUTION_HANDOFF}
)


class JobState(StrEnum):
    AVAILABLE = "available"
    LEASED = "leased"
    WORKER_REPORTED = "worker_reported"
    DEAD_LETTERED = "dead_lettered"


class JobOutcomeCode(StrEnum):
    HANDLED_OBSERVATION = "handled_observation"
    RETRYABLE_FAILURE_OBSERVATION = "retryable_failure_observation"
    PERMANENT_FAILURE_OBSERVATION = "permanent_failure_observation"
    LEASE_EXHAUSTED_OBSERVATION = "lease_exhausted_observation"


class MessageDirection(StrEnum):
    INBOX = "inbox"
    OUTBOX = "outbox"


class MessageTopic(StrEnum):
    SOURCE_EVENT = "source_event"
    PROJECTION_CHANGE = "projection_change"
    ACTION_EXECUTION_HANDOFF = "action_execution_handoff"
    WORKER_OBSERVATION = "worker_observation"


class SagaKind(StrEnum):
    MISSION_LIFECYCLE = "mission_lifecycle"
    EXPERT_WORK = "expert_work"
    REVIEW = "review"
    ACTION_APPROVAL = "action_approval"
    ACTION_EXECUTION = "action_execution"
    EVIDENCE_CUSTODY = "evidence_custody"
    RECONCILIATION = "reconciliation"


class SagaStepState(StrEnum):
    PLANNED = "planned"
    WORKER_REPORTED = "worker_reported"
    BLOCKED_OBSERVATION = "blocked_observation"


class DeliveryOutcome(StrEnum):
    ACKNOWLEDGED_OBSERVATION = "acknowledged_observation"
    RETRYABLE_FAILURE_OBSERVATION = "retryable_failure_observation"
    PERMANENT_FAILURE_OBSERVATION = "permanent_failure_observation"


_DELIVERY_JOB_OUTCOME = MappingProxyType(
    {
        DeliveryOutcome.ACKNOWLEDGED_OBSERVATION: JobOutcomeCode.HANDLED_OBSERVATION,
        DeliveryOutcome.RETRYABLE_FAILURE_OBSERVATION: (
            JobOutcomeCode.RETRYABLE_FAILURE_OBSERVATION
        ),
        DeliveryOutcome.PERMANENT_FAILURE_OBSERVATION: (
            JobOutcomeCode.PERMANENT_FAILURE_OBSERVATION
        ),
    }
)


class ProjectionKind(StrEnum):
    MISSION = "mission"
    PLAN = "plan"
    EXPERT_WORK = "expert_work"
    REVIEW_QUEUE = "review_queue"
    ACTION_APPROVAL = "action_approval"
    ACTION_EXECUTION = "action_execution"
    FINDING = "finding"
    EVIDENCE = "evidence"
    HEALTH = "health"
    AUDIT = "audit"


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise OrchestrationValidationError("JSON contains duplicate object keys")
        value[key] = member
    return value


def loads_json_without_duplicate_keys(value: str | bytes) -> Any:
    try:
        return json.loads(value, object_pairs_hook=_json_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OrchestrationValidationError("record is not valid JSON") from exc


def _validate_json(
    value: Any,
    label: str,
    *,
    depth: int = 0,
    counter: list[int] | None = None,
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise OrchestrationValidationError(f"{label} exceeds the nesting limit")
    seen = [0] if counter is None else counter
    seen[0] += 1
    if seen[0] > MAX_JSON_ITEMS:
        raise OrchestrationValidationError(f"{label} exceeds the item limit")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise OrchestrationValidationError(f"{label} integer is outside SQLite range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise OrchestrationValidationError(f"{label} contains a non-finite number")
        raise OrchestrationValidationError(f"{label} cannot contain floating-point values")
    if isinstance(value, str):
        if not value.isascii() or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise OrchestrationValidationError(f"{label} contains non-ASCII or control characters")
        if _SECRET_TEXT_RE.search(value):
            raise OrchestrationValidationError(f"{label} contains secret-like material")
        return
    if isinstance(value, list):
        for index, member in enumerate(value):
            _validate_json(member, f"{label}[{index}]", depth=depth + 1, counter=seen)
        return
    if isinstance(value, dict):
        for key, member in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise OrchestrationValidationError(f"{label} contains an invalid object key")
            if any(ord(character) < 32 or ord(character) == 127 for character in key):
                raise OrchestrationValidationError(f"{label} contains a control-bearing key")
            normalized = key.lower().replace("-", "_")
            if normalized in _FORBIDDEN_KEYS or _secret_field_name(key):
                raise OrchestrationValidationError(f"{label} contains a secret-bearing field")
            _validate_json(member, f"{label}.{key}", depth=depth + 1, counter=seen)
        return
    raise OrchestrationValidationError(f"{label} contains an unsupported value")


def canonical_json(value: Any) -> str:
    _validate_json(value, "value")
    try:
        document = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise OrchestrationValidationError("value cannot be canonicalized") from exc
    if len(document.encode("ascii")) > MAX_RECORD_BYTES:
        raise OrchestrationValidationError("record exceeds the byte limit")
    return document


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(member) for key, member in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(member) for member in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(member) for key, member in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(member) for member in value]
    return value


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise OrchestrationValidationError(f"{label} fields are invalid")
    return raw


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None or ".." in value:
        raise OrchestrationValidationError(f"{label} is invalid")
    _validate_json(value, label)
    return value


def _record_id(value: Any, prefix: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or _RECORD_ID_RE.fullmatch(value) is None
    ):
        raise OrchestrationValidationError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise OrchestrationValidationError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise OrchestrationValidationError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise OrchestrationValidationError(f"{label} is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise OrchestrationValidationError(f"{label} is not canonical")
    return value


def _instant(value: str) -> datetime:
    _timestamp(value, "timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OrchestrationValidationError("clock value must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OrchestrationValidationError(f"{label} is outside its allowed range")
    return value


def _enum(value: Any, enum_type: type[StrEnum], label: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise OrchestrationValidationError(f"{label} is invalid") from exc


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": dict(body), "domain": domain})
    return prefix + digest[7:39].upper(), digest


def _common(kind: str) -> dict[str, Any]:
    return {
        "effects": dict(NO_AUTHORITY_EFFECTS),
        "kind": kind,
        "schema_version": SCHEMA_VERSION,
    }


def _verify_common(raw: Mapping[str, Any], kind: str) -> None:
    effects = raw.get("effects")
    if (
        type(raw.get("schema_version")) is not int
        or raw.get("schema_version") != SCHEMA_VERSION
        or raw.get("kind") != kind
        or type(effects) is not dict
        or set(effects) != set(NO_AUTHORITY_EFFECTS)
        or any(
            type(effects[key]) is not str or effects[key] != value
            for key, value in NO_AUTHORITY_EFFECTS.items()
        )
    ):
        raise OrchestrationValidationError("record kind, version, or effects are invalid")


@dataclass(frozen=True, slots=True)
class SourceHighWater:
    source_kind: SourceKind
    source_id: str
    source_revision: int
    source_head_sha256: str
    observed_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_kind", _enum(self.source_kind, SourceKind, "source_kind"))
        _identifier(self.source_id, "source_id")
        _integer(self.source_revision, "source_revision", 0, 2_147_483_647)
        _digest(self.source_head_sha256, "source_head_sha256")
        _timestamp(self.observed_at, "observed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_at": self.observed_at,
            "source_head_sha256": self.source_head_sha256,
            "source_id": self.source_id,
            "source_kind": self.source_kind.value,
            "source_revision": self.source_revision,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SourceHighWater:
        value = _exact(
            raw,
            {"observed_at", "source_head_sha256", "source_id", "source_kind", "source_revision"},
            "source high-water binding",
        )
        return cls(
            source_kind=_enum(value["source_kind"], SourceKind, "source_kind"),
            source_id=value["source_id"],
            source_revision=value["source_revision"],
            source_head_sha256=value["source_head_sha256"],
            observed_at=value["observed_at"],
        )


def _source_bindings(
    values: Sequence[SourceHighWater | Mapping[str, Any]],
) -> tuple[SourceHighWater, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise OrchestrationValidationError("source_bindings must be a sequence")
    parsed = tuple(
        value if type(value) is SourceHighWater else SourceHighWater.from_dict(value)
        for value in values
    )
    if not parsed or len(parsed) > 8:
        raise OrchestrationValidationError("source_bindings count is invalid")
    ordered = tuple(sorted(parsed, key=lambda item: (item.source_kind.value, item.source_id)))
    keys = [(item.source_kind.value, item.source_id) for item in ordered]
    if len(keys) != len(set(keys)):
        raise OrchestrationValidationError("source_bindings contain duplicates")
    if parsed != ordered:
        raise OrchestrationValidationError("source_bindings are not canonical")
    return parsed


def source_bindings_sha256(
    values: Sequence[SourceHighWater | Mapping[str, Any]],
) -> str:
    """Return the canonical digest used to bind an exact source vector."""

    bindings = _source_bindings(values)
    return canonical_sha256(
        {
            "domain": "sunderkey.orchestration-source-bindings.v1",
            "source_bindings": [item.to_dict() for item in bindings],
        }
    )


def authentication_context_sha256(
    *, tenant_id: str, subject_id: str, authentication_ref: str
) -> str:
    """Bind non-secret ingress authentication context without storing the raw reference."""

    _identifier(tenant_id, "tenant_id")
    _identifier(subject_id, "subject_id")
    _identifier(authentication_ref, "authentication_ref")
    return canonical_sha256(
        {
            "authentication_ref": authentication_ref,
            "domain": "sunderkey.orchestration-authentication-context.v1",
            "subject_id": subject_id,
            "tenant_id": tenant_id,
        }
    )


def _require_bindings_not_after(
    bindings: Sequence[SourceHighWater], timestamp: str, label: str
) -> None:
    boundary = _instant(timestamp)
    if any(_instant(item.observed_at) > boundary for item in bindings):
        raise OrchestrationValidationError(f"{label} precedes a source observation")


@dataclass(frozen=True, slots=True)
class ActionExecutionIntent:
    intent_id: str
    intent_sha256: str
    tenant_id: str
    mission_id: str
    action_execution_envelope_ref: str
    action_execution_envelope_sha256: str
    command_sha256: str
    action_execution_request_id: str
    action_execution_request_sha256: str
    receipt_id: str
    receipt_sha256: str
    action_execute_intent_sha256: str
    assertion_id: str
    assertion_sha256: str
    authorization_sha256: str
    authorization_expires_at: str
    source_bindings_sha256: str
    source_bindings: tuple[SourceHighWater, ...]
    available_at: str
    requested_at: str
    idempotency_key_sha256: str
    requested_by_subject_id: str
    authentication_context_sha256: str

    KIND: ClassVar[str] = "sunderkey.action-execution-intent.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            "action_execute_intent_sha256": self.action_execute_intent_sha256,
            "action_execution_envelope_ref": self.action_execution_envelope_ref,
            "action_execution_envelope_sha256": self.action_execution_envelope_sha256,
            "action_execution_request_id": self.action_execution_request_id,
            "action_execution_request_sha256": self.action_execution_request_sha256,
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "authorization_expires_at": self.authorization_expires_at,
            "authorization_sha256": self.authorization_sha256,
            "available_at": self.available_at,
            "command_sha256": self.command_sha256,
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "intent_id": self.intent_id,
            "intent_sha256": self.intent_sha256,
            "mission_id": self.mission_id,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "requested_at": self.requested_at,
            "requested_by_subject_id": self.requested_by_subject_id,
            "authentication_context_sha256": self.authentication_context_sha256,
            "source_bindings": [item.to_dict() for item in self.source_bindings],
            "source_bindings_sha256": self.source_bindings_sha256,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ActionExecutionIntent:
        fields = {
            "action_execute_intent_sha256",
            "action_execution_envelope_ref",
            "action_execution_envelope_sha256",
            "action_execution_request_id",
            "action_execution_request_sha256",
            "assertion_id",
            "assertion_sha256",
            "authorization_expires_at",
            "authorization_sha256",
            "available_at",
            "command_sha256",
            "effects",
            "idempotency_key_sha256",
            "intent_id",
            "intent_sha256",
            "kind",
            "mission_id",
            "receipt_id",
            "receipt_sha256",
            "requested_at",
            "requested_by_subject_id",
            "authentication_context_sha256",
            "schema_version",
            "source_bindings",
            "source_bindings_sha256",
            "tenant_id",
        }
        value = _exact(raw, fields, "action execution intent")
        _verify_common(value, cls.KIND)
        rebuilt = build_action_execution_intent(
            tenant_id=value["tenant_id"],
            mission_id=value["mission_id"],
            action_execution_envelope_ref=value["action_execution_envelope_ref"],
            action_execution_envelope_sha256=value[
                "action_execution_envelope_sha256"
            ],
            command_sha256=value["command_sha256"],
            action_execution_request_id=value["action_execution_request_id"],
            action_execution_request_sha256=value[
                "action_execution_request_sha256"
            ],
            receipt_id=value["receipt_id"],
            receipt_sha256=value["receipt_sha256"],
            action_execute_intent_sha256=value["action_execute_intent_sha256"],
            assertion_id=value["assertion_id"],
            assertion_sha256=value["assertion_sha256"],
            authorization_sha256=value["authorization_sha256"],
            authorization_expires_at=value["authorization_expires_at"],
            source_bindings_sha256=value["source_bindings_sha256"],
            source_bindings=tuple(
                SourceHighWater.from_dict(item) for item in value["source_bindings"]
            ),
            available_at=value["available_at"],
            requested_at=value["requested_at"],
            idempotency_key_sha256=value["idempotency_key_sha256"],
            requested_by_subject_id=value["requested_by_subject_id"],
            authentication_context_sha256=value["authentication_context_sha256"],
        )
        if rebuilt.to_dict() != dict(value):
            raise OrchestrationValidationError("action execution intent identity is invalid")
        return rebuilt


def build_action_execution_intent(
    *,
    tenant_id: str,
    mission_id: str,
    action_execution_envelope_ref: str,
    action_execution_envelope_sha256: str,
    command_sha256: str,
    action_execution_request_id: str,
    action_execution_request_sha256: str,
    receipt_id: str,
    receipt_sha256: str,
    action_execute_intent_sha256: str,
    assertion_id: str,
    assertion_sha256: str,
    authorization_sha256: str,
    authorization_expires_at: str,
    source_bindings_sha256: str,
    source_bindings: Sequence[SourceHighWater | Mapping[str, Any]],
    available_at: str,
    requested_at: str,
    idempotency_key_sha256: str,
    requested_by_subject_id: str,
    authentication_context_sha256: str,
) -> ActionExecutionIntent:
    bindings = _source_bindings(source_bindings)
    for label, value in (
        ("tenant_id", tenant_id),
        ("mission_id", mission_id),
        ("action_execution_envelope_ref", action_execution_envelope_ref),
        ("action_execution_request_id", action_execution_request_id),
        ("receipt_id", receipt_id),
        ("assertion_id", assertion_id),
        ("requested_by_subject_id", requested_by_subject_id),
    ):
        _identifier(value, label)
    if re.fullmatch(r"AXR-[0-9A-F]{32}", action_execution_request_id) is None:
        raise OrchestrationValidationError("action_execution_request_id is invalid")
    if re.fullmatch(r"AARX-[0-9A-F]{32}", receipt_id) is None:
        raise OrchestrationValidationError("receipt_id is invalid")
    for label, value in (
        ("action_execution_envelope_sha256", action_execution_envelope_sha256),
        ("command_sha256", command_sha256),
        ("action_execution_request_sha256", action_execution_request_sha256),
        ("receipt_sha256", receipt_sha256),
        ("action_execute_intent_sha256", action_execute_intent_sha256),
        ("assertion_sha256", assertion_sha256),
        ("authorization_sha256", authorization_sha256),
        ("source_bindings_sha256", source_bindings_sha256),
        ("idempotency_key_sha256", idempotency_key_sha256),
        ("authentication_context_sha256", authentication_context_sha256),
    ):
        _digest(value, label)
    _timestamp(requested_at, "requested_at")
    _timestamp(available_at, "available_at")
    _timestamp(authorization_expires_at, "authorization_expires_at")
    _require_bindings_not_after(bindings, requested_at, "requested_at")
    if source_bindings_sha256 != globals()["source_bindings_sha256"](bindings):
        raise OrchestrationValidationError("source_bindings_sha256 is invalid")
    if not (
        _instant(requested_at)
        <= _instant(available_at)
        < _instant(authorization_expires_at)
    ):
        raise OrchestrationValidationError(
            "action execution scheduling is outside its authorization window"
        )
    body = {
        **_common(ActionExecutionIntent.KIND),
        "action_execute_intent_sha256": action_execute_intent_sha256,
        "action_execution_envelope_ref": action_execution_envelope_ref,
        "action_execution_envelope_sha256": action_execution_envelope_sha256,
        "action_execution_request_id": action_execution_request_id,
        "action_execution_request_sha256": action_execution_request_sha256,
        "assertion_id": assertion_id,
        "assertion_sha256": assertion_sha256,
        "authorization_expires_at": authorization_expires_at,
        "authorization_sha256": authorization_sha256,
        "available_at": available_at,
        "command_sha256": command_sha256,
        "idempotency_key_sha256": idempotency_key_sha256,
        "mission_id": mission_id,
        "receipt_id": receipt_id,
        "receipt_sha256": receipt_sha256,
        "requested_at": requested_at,
        "requested_by_subject_id": requested_by_subject_id,
        "authentication_context_sha256": authentication_context_sha256,
        "source_bindings": [item.to_dict() for item in bindings],
        "source_bindings_sha256": source_bindings_sha256,
        "tenant_id": tenant_id,
    }
    record_id, digest = _identity("AEI-", ActionExecutionIntent.KIND, body)
    return ActionExecutionIntent(
        record_id,
        digest,
        tenant_id,
        mission_id,
        action_execution_envelope_ref,
        action_execution_envelope_sha256,
        command_sha256,
        action_execution_request_id,
        action_execution_request_sha256,
        receipt_id,
        receipt_sha256,
        action_execute_intent_sha256,
        assertion_id,
        assertion_sha256,
        authorization_sha256,
        authorization_expires_at,
        source_bindings_sha256,
        bindings,
        available_at,
        requested_at,
        idempotency_key_sha256,
        requested_by_subject_id,
        authentication_context_sha256,
    )


@dataclass(frozen=True, slots=True)
class ActionExecutionHandoffQuarantine:
    quarantine_id: str
    quarantine_sha256: str
    job_id: str
    job_sha256: str
    message_id: str
    message_sha256: str
    intent_id: str
    intent_sha256: str
    tenant_id: str
    authorization_expires_at: str
    trusted_at: str
    reason: str = "authorization_window_ineligible_before_claim"
    custody_effect: str = "not_attempted_no_action_inference"

    KIND: ClassVar[str] = "sunderkey.action-execution-handoff-quarantine.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name != "KIND"
            },
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ActionExecutionHandoffQuarantine:
        fields = (set(cls.__dataclass_fields__) - {"KIND"}) | {
            "effects",
            "kind",
            "schema_version",
        }
        value = dict(_exact(raw, fields, "action execution handoff quarantine"))
        _verify_common(value, cls.KIND)
        for field in ("effects", "kind", "schema_version"):
            value.pop(field)
        rebuilt = _build_action_execution_handoff_quarantine(**value)
        if rebuilt.to_dict() != dict(raw):
            raise OrchestrationValidationError(
                "action execution handoff quarantine identity is invalid"
            )
        return rebuilt


def _build_action_execution_handoff_quarantine(
    **values: Any,
) -> ActionExecutionHandoffQuarantine:
    for label, prefix in (
        ("job_id", "JOB-"),
        ("message_id", "MSG-"),
        ("intent_id", "AEI-"),
    ):
        _record_id(values[label], prefix, label)
    _identifier(values["tenant_id"], "tenant_id")
    for label in ("job_sha256", "message_sha256", "intent_sha256"):
        _digest(values[label], label)
    _timestamp(values["authorization_expires_at"], "authorization_expires_at")
    _timestamp(values["trusted_at"], "trusted_at")
    if values["reason"] != "authorization_window_ineligible_before_claim":
        raise OrchestrationValidationError("handoff quarantine reason is invalid")
    if values["custody_effect"] != "not_attempted_no_action_inference":
        raise OrchestrationValidationError("handoff quarantine effect is invalid")
    body = {
        **_common(ActionExecutionHandoffQuarantine.KIND),
        **{
            key: value
            for key, value in values.items()
            if key not in {"quarantine_id", "quarantine_sha256"}
        },
    }
    quarantine_id, quarantine_sha256 = _identity(
        "AEQ-", ActionExecutionHandoffQuarantine.KIND, body
    )
    if values.get("quarantine_id", quarantine_id) != quarantine_id or values.get(
        "quarantine_sha256", quarantine_sha256
    ) != quarantine_sha256:
        raise OrchestrationValidationError("handoff quarantine identity is invalid")
    return ActionExecutionHandoffQuarantine(
        quarantine_id=quarantine_id,
        quarantine_sha256=quarantine_sha256,
        **{
            key: value
            for key, value in values.items()
            if key not in {"quarantine_id", "quarantine_sha256"}
        },
    )


@dataclass(frozen=True, slots=True)
class OrchestrationJob:
    job_id: str
    job_sha256: str
    tenant_id: str
    job_kind: JobKind
    subject_ref: str
    input_ref: str
    input_sha256: str
    source_bindings: tuple[SourceHighWater, ...]
    idempotency_key_sha256: str
    created_at: str
    available_at: str
    maximum_attempts: int
    lease_seconds: int

    KIND: ClassVar[str] = "sunderkey.orchestration-job.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            "available_at": self.available_at,
            "created_at": self.created_at,
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "input_ref": self.input_ref,
            "input_sha256": self.input_sha256,
            "job_id": self.job_id,
            "job_kind": self.job_kind.value,
            "job_sha256": self.job_sha256,
            "lease_seconds": self.lease_seconds,
            "maximum_attempts": self.maximum_attempts,
            "source_bindings": [item.to_dict() for item in self.source_bindings],
            "subject_ref": self.subject_ref,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OrchestrationJob:
        fields = {
            "available_at",
            "created_at",
            "effects",
            "idempotency_key_sha256",
            "input_ref",
            "input_sha256",
            "job_id",
            "job_kind",
            "job_sha256",
            "kind",
            "lease_seconds",
            "maximum_attempts",
            "schema_version",
            "source_bindings",
            "subject_ref",
            "tenant_id",
        }
        value = _exact(raw, fields, "orchestration job")
        _verify_common(value, cls.KIND)
        rebuilt = build_orchestration_job(
            tenant_id=value["tenant_id"],
            job_kind=value["job_kind"],
            subject_ref=value["subject_ref"],
            input_ref=value["input_ref"],
            input_sha256=value["input_sha256"],
            source_bindings=tuple(
                SourceHighWater.from_dict(item) for item in value["source_bindings"]
            ),
            idempotency_key_sha256=value["idempotency_key_sha256"],
            created_at=value["created_at"],
            available_at=value["available_at"],
            maximum_attempts=value["maximum_attempts"],
            lease_seconds=value["lease_seconds"],
        )
        if rebuilt.to_dict() != dict(value):
            raise OrchestrationValidationError("orchestration job identity is invalid")
        return rebuilt


def build_orchestration_job(
    *,
    tenant_id: str,
    job_kind: JobKind | str,
    subject_ref: str,
    input_ref: str,
    input_sha256: str,
    source_bindings: Sequence[SourceHighWater | Mapping[str, Any]],
    idempotency_key_sha256: str,
    created_at: str,
    available_at: str,
    maximum_attempts: int = 3,
    lease_seconds: int = 60,
) -> OrchestrationJob:
    kind = _enum(job_kind, JobKind, "job_kind")
    bindings = _source_bindings(source_bindings)
    _identifier(tenant_id, "tenant_id")
    _identifier(subject_ref, "subject_ref")
    _identifier(input_ref, "input_ref")
    _digest(input_sha256, "input_sha256")
    _digest(idempotency_key_sha256, "idempotency_key_sha256")
    _timestamp(created_at, "created_at")
    _timestamp(available_at, "available_at")
    _require_bindings_not_after(bindings, created_at, "created_at")
    if _instant(available_at) < _instant(created_at):
        raise OrchestrationValidationError("available_at cannot precede created_at")
    _integer(maximum_attempts, "maximum_attempts", 1, 32)
    _integer(lease_seconds, "lease_seconds", 5, 86_400)
    if kind in _RESERVED_EXTERNAL_EFFECT_JOBS and maximum_attempts != 1:
        raise OrchestrationValidationError(
            "reserved external-effect jobs require exactly one attempt"
        )
    body = {
        **_common(OrchestrationJob.KIND),
        "available_at": available_at,
        "created_at": created_at,
        "idempotency_key_sha256": idempotency_key_sha256,
        "input_ref": input_ref,
        "input_sha256": input_sha256,
        "job_kind": kind.value,
        "lease_seconds": lease_seconds,
        "maximum_attempts": maximum_attempts,
        "source_bindings": [item.to_dict() for item in bindings],
        "subject_ref": subject_ref,
        "tenant_id": tenant_id,
    }
    record_id, digest = _identity("JOB-", OrchestrationJob.KIND, body)
    return OrchestrationJob(
        record_id,
        digest,
        tenant_id,
        kind,
        subject_ref,
        input_ref,
        input_sha256,
        bindings,
        idempotency_key_sha256,
        created_at,
        available_at,
        maximum_attempts,
        lease_seconds,
    )


@dataclass(frozen=True, slots=True)
class JobClaim:
    claim_id: str
    claim_sha256: str
    job_id: str
    job_sha256: str
    tenant_id: str
    worker_id: str
    attempt_number: int
    fence_token: int
    lease_version: int
    claimed_at: str
    expires_at: str
    prior_claim_sha256: str | None

    KIND: ClassVar[str] = "sunderkey.orchestration-job-claim.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            "attempt_number": self.attempt_number,
            "claim_id": self.claim_id,
            "claim_sha256": self.claim_sha256,
            "claimed_at": self.claimed_at,
            "expires_at": self.expires_at,
            "fence_token": self.fence_token,
            "job_id": self.job_id,
            "job_sha256": self.job_sha256,
            "lease_version": self.lease_version,
            "prior_claim_sha256": self.prior_claim_sha256,
            "tenant_id": self.tenant_id,
            "worker_id": self.worker_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> JobClaim:
        fields = {
            "attempt_number",
            "claim_id",
            "claim_sha256",
            "claimed_at",
            "effects",
            "expires_at",
            "fence_token",
            "job_id",
            "job_sha256",
            "kind",
            "lease_version",
            "prior_claim_sha256",
            "schema_version",
            "tenant_id",
            "worker_id",
        }
        value = _exact(raw, fields, "job claim")
        _verify_common(value, cls.KIND)
        rebuilt = _build_job_claim(
            job_id=value["job_id"],
            job_sha256=value["job_sha256"],
            tenant_id=value["tenant_id"],
            worker_id=value["worker_id"],
            attempt_number=value["attempt_number"],
            fence_token=value["fence_token"],
            lease_version=value["lease_version"],
            claimed_at=value["claimed_at"],
            expires_at=value["expires_at"],
            prior_claim_sha256=value["prior_claim_sha256"],
        )
        if rebuilt.to_dict() != dict(value):
            raise OrchestrationValidationError("job claim identity is invalid")
        return rebuilt


def _build_job_claim(
    *,
    job_id: str,
    job_sha256: str,
    tenant_id: str,
    worker_id: str,
    attempt_number: int,
    fence_token: int,
    lease_version: int,
    claimed_at: str,
    expires_at: str,
    prior_claim_sha256: str | None,
) -> JobClaim:
    _record_id(job_id, "JOB-", "job_id")
    _digest(job_sha256, "job_sha256")
    _identifier(tenant_id, "tenant_id")
    _identifier(worker_id, "worker_id")
    _integer(attempt_number, "attempt_number", 1, 32)
    _integer(fence_token, "fence_token", 1, 2_147_483_647)
    _integer(lease_version, "lease_version", 1, 2_147_483_647)
    _timestamp(claimed_at, "claimed_at")
    _timestamp(expires_at, "expires_at")
    if _instant(expires_at) <= _instant(claimed_at):
        raise OrchestrationValidationError("job claim must expire after it is created")
    if prior_claim_sha256 is not None:
        _digest(prior_claim_sha256, "prior_claim_sha256")
    if (lease_version == 1) != (prior_claim_sha256 is None):
        raise OrchestrationValidationError("job claim predecessor is invalid")
    body = {
        **_common(JobClaim.KIND),
        "attempt_number": attempt_number,
        "claimed_at": claimed_at,
        "expires_at": expires_at,
        "fence_token": fence_token,
        "job_id": job_id,
        "job_sha256": job_sha256,
        "lease_version": lease_version,
        "prior_claim_sha256": prior_claim_sha256,
        "tenant_id": tenant_id,
        "worker_id": worker_id,
    }
    record_id, digest = _identity("JCL-", JobClaim.KIND, body)
    return JobClaim(
        record_id,
        digest,
        job_id,
        job_sha256,
        tenant_id,
        worker_id,
        attempt_number,
        fence_token,
        lease_version,
        claimed_at,
        expires_at,
        prior_claim_sha256,
    )


@dataclass(frozen=True, slots=True)
class JobOutcome:
    outcome_id: str
    outcome_sha256: str
    claim_id: str
    claim_sha256: str
    job_id: str
    tenant_id: str
    worker_id: str
    fence_token: int
    outcome_code: JobOutcomeCode
    result_ref: str
    result_sha256: str
    observed_at: str
    retry_available_at: str | None

    KIND: ClassVar[str] = "sunderkey.orchestration-job-outcome.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            "claim_id": self.claim_id,
            "claim_sha256": self.claim_sha256,
            "fence_token": self.fence_token,
            "job_id": self.job_id,
            "observed_at": self.observed_at,
            "outcome_code": self.outcome_code.value,
            "outcome_id": self.outcome_id,
            "outcome_sha256": self.outcome_sha256,
            "result_ref": self.result_ref,
            "result_sha256": self.result_sha256,
            "retry_available_at": self.retry_available_at,
            "tenant_id": self.tenant_id,
            "worker_id": self.worker_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> JobOutcome:
        fields = {
            "claim_id",
            "claim_sha256",
            "effects",
            "fence_token",
            "job_id",
            "kind",
            "observed_at",
            "outcome_code",
            "outcome_id",
            "outcome_sha256",
            "result_ref",
            "result_sha256",
            "retry_available_at",
            "schema_version",
            "tenant_id",
            "worker_id",
        }
        value = _exact(raw, fields, "job outcome")
        _verify_common(value, cls.KIND)
        rebuilt = _build_job_outcome(
            claim_id=value["claim_id"],
            claim_sha256=value["claim_sha256"],
            job_id=value["job_id"],
            tenant_id=value["tenant_id"],
            worker_id=value["worker_id"],
            fence_token=value["fence_token"],
            outcome_code=value["outcome_code"],
            result_ref=value["result_ref"],
            result_sha256=value["result_sha256"],
            observed_at=value["observed_at"],
            retry_available_at=value["retry_available_at"],
        )
        if rebuilt.to_dict() != dict(value):
            raise OrchestrationValidationError("job outcome identity is invalid")
        return rebuilt


def _build_job_outcome(
    *,
    claim_id: str,
    claim_sha256: str,
    job_id: str,
    tenant_id: str,
    worker_id: str,
    fence_token: int,
    outcome_code: JobOutcomeCode | str,
    result_ref: str,
    result_sha256: str,
    observed_at: str,
    retry_available_at: str | None,
) -> JobOutcome:
    _record_id(claim_id, "JCL-", "claim_id")
    _digest(claim_sha256, "claim_sha256")
    _record_id(job_id, "JOB-", "job_id")
    _identifier(tenant_id, "tenant_id")
    _identifier(worker_id, "worker_id")
    _integer(fence_token, "fence_token", 1, 2_147_483_647)
    code = _enum(outcome_code, JobOutcomeCode, "outcome_code")
    _identifier(result_ref, "result_ref")
    _digest(result_sha256, "result_sha256")
    _timestamp(observed_at, "observed_at")
    if retry_available_at is not None:
        _timestamp(retry_available_at, "retry_available_at")
    if (code is JobOutcomeCode.RETRYABLE_FAILURE_OBSERVATION) != (retry_available_at is not None):
        raise OrchestrationValidationError("retry availability does not match outcome")
    if retry_available_at is not None and _instant(retry_available_at) < _instant(observed_at):
        raise OrchestrationValidationError("retry_available_at precedes the outcome")
    body = {
        **_common(JobOutcome.KIND),
        "claim_id": claim_id,
        "claim_sha256": claim_sha256,
        "fence_token": fence_token,
        "job_id": job_id,
        "observed_at": observed_at,
        "outcome_code": code.value,
        "result_ref": result_ref,
        "result_sha256": result_sha256,
        "retry_available_at": retry_available_at,
        "tenant_id": tenant_id,
        "worker_id": worker_id,
    }
    record_id, digest = _identity("JOU-", JobOutcome.KIND, body)
    return JobOutcome(
        record_id,
        digest,
        claim_id,
        claim_sha256,
        job_id,
        tenant_id,
        worker_id,
        fence_token,
        code,
        result_ref,
        result_sha256,
        observed_at,
        retry_available_at,
    )


@dataclass(frozen=True, slots=True)
class ActionExecutionAttempt:
    attempt_id: str
    attempt_sha256: str
    job_id: str
    job_sha256: str
    message_id: str
    message_sha256: str
    intent_id: str
    intent_sha256: str
    claim_id: str
    claim_sha256: str
    tenant_id: str
    mission_id: str
    action_execution_envelope_ref: str
    action_execution_envelope_sha256: str
    command_sha256: str
    action_execution_request_id: str
    action_execution_request_sha256: str
    receipt_id: str
    receipt_sha256: str
    action_execute_intent_sha256: str
    assertion_id: str
    assertion_sha256: str
    authorization_sha256: str
    authorization_expires_at: str
    source_bindings_sha256: str
    source_bindings: tuple[SourceHighWater, ...]
    worker_id: str
    worker_assertion_id: str
    worker_assertion_sha256: str
    worker_trust_policy_id: str
    worker_trust_policy_sha256: str
    worker_scope_id: str
    worker_scope_sha256: str
    worker_session_id: str
    worker_session_sha256: str
    worker_lease_id: str
    worker_lease_sha256: str
    worker_capability_id: str
    worker_capability_sha256: str
    trusted_at: str
    expires_at: str
    attempt_number: int = 1

    KIND: ClassVar[str] = "sunderkey.action-execution-attempt.v1"

    def to_dict(self) -> dict[str, Any]:
        value = {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"KIND", "source_bindings"}
        }
        value["source_bindings"] = [item.to_dict() for item in self.source_bindings]
        return {**_common(self.KIND), **value}

    @classmethod
    def from_dict(cls, raw: Any) -> ActionExecutionAttempt:
        fields = (set(cls.__dataclass_fields__) - {"KIND"}) | {
            "effects",
            "kind",
            "schema_version",
        }
        value = dict(_exact(raw, fields, "action execution attempt"))
        _verify_common(value, cls.KIND)
        for field in ("effects", "kind", "schema_version"):
            value.pop(field)
        value["source_bindings"] = tuple(
            SourceHighWater.from_dict(item) for item in value["source_bindings"]
        )
        rebuilt = _build_action_execution_attempt(**value)
        if rebuilt.to_dict() != dict(raw):
            raise OrchestrationValidationError("action execution attempt identity is invalid")
        return rebuilt


def _build_action_execution_attempt(**values: Any) -> ActionExecutionAttempt:
    record_ids = {
        "job_id": "JOB-",
        "message_id": "MSG-",
        "intent_id": "AEI-",
        "claim_id": "JCL-",
    }
    for label, prefix in record_ids.items():
        _record_id(values[label], prefix, label)
    for label in (
        "tenant_id",
        "mission_id",
        "action_execution_envelope_ref",
        "action_execution_request_id",
        "receipt_id",
        "assertion_id",
        "worker_id",
        "worker_assertion_id",
        "worker_trust_policy_id",
        "worker_scope_id",
        "worker_session_id",
        "worker_lease_id",
        "worker_capability_id",
    ):
        _identifier(values[label], label)
    for label in (
        "job_sha256",
        "message_sha256",
        "intent_sha256",
        "claim_sha256",
        "action_execution_envelope_sha256",
        "command_sha256",
        "action_execution_request_sha256",
        "receipt_sha256",
        "action_execute_intent_sha256",
        "assertion_sha256",
        "authorization_sha256",
        "source_bindings_sha256",
        "worker_assertion_sha256",
        "worker_trust_policy_sha256",
        "worker_scope_sha256",
        "worker_session_sha256",
        "worker_lease_sha256",
        "worker_capability_sha256",
    ):
        _digest(values[label], label)
    bindings = _source_bindings(values["source_bindings"])
    if values["source_bindings_sha256"] != source_bindings_sha256(bindings):
        raise OrchestrationValidationError("attempt source bindings digest is invalid")
    _timestamp(values["authorization_expires_at"], "authorization_expires_at")
    _timestamp(values["trusted_at"], "trusted_at")
    _timestamp(values["expires_at"], "expires_at")
    _integer(values["attempt_number"], "attempt_number", 1, 1)
    if not (
        _instant(values["trusted_at"])
        < _instant(values["expires_at"])
        <= _instant(values["authorization_expires_at"])
    ):
        raise OrchestrationValidationError("attempt custody window is invalid")
    body = {
        **_common(ActionExecutionAttempt.KIND),
        **{
            key: ([item.to_dict() for item in bindings] if key == "source_bindings" else value)
            for key, value in values.items()
            if key not in {"attempt_id", "attempt_sha256"}
        },
    }
    attempt_id, attempt_sha256 = _identity("AEA-", ActionExecutionAttempt.KIND, body)
    if values.get("attempt_id", attempt_id) != attempt_id or values.get(
        "attempt_sha256", attempt_sha256
    ) != attempt_sha256:
        raise OrchestrationValidationError("action execution attempt identity is invalid")
    body_values = {
        key: value
        for key, value in values.items()
        if key not in {"attempt_id", "attempt_sha256", "source_bindings"}
    }
    return ActionExecutionAttempt(
        attempt_id=attempt_id,
        attempt_sha256=attempt_sha256,
        source_bindings=bindings,
        **body_values,
    )


@dataclass(frozen=True, slots=True)
class ActionExecutionTerminalObservation:
    observation_id: str
    observation_sha256: str
    attempt_id: str
    attempt_sha256: str
    job_id: str
    job_sha256: str
    message_id: str
    message_sha256: str
    intent_id: str
    intent_sha256: str
    claim_id: str
    claim_sha256: str
    tenant_id: str
    action_execution_request_id: str
    action_execution_request_sha256: str
    phase196_claim_id: str
    phase196_claim_sha256: str
    phase196_terminal_id: str
    phase196_terminal_sha256: str
    terminal_status: str
    action_outcome: str
    evidence_status: str
    cleanup_status: str
    restoration_status: str
    result_sha256: str
    settled_at: str
    adapter_call_count: int | None
    adapter_call_count_status: str
    automatic_retry_count: int
    observed_at: str
    journal_effect: str = "terminal_observed_not_action_success"

    KIND: ClassVar[str] = "sunderkey.action-execution-terminal-observation.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name != "KIND"
            },
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ActionExecutionTerminalObservation:
        fields = (set(cls.__dataclass_fields__) - {"KIND"}) | {
            "effects",
            "kind",
            "schema_version",
        }
        value = dict(_exact(raw, fields, "action execution terminal observation"))
        _verify_common(value, cls.KIND)
        for field in ("effects", "kind", "schema_version"):
            value.pop(field)
        rebuilt = _build_action_execution_terminal_observation(**value)
        if rebuilt.to_dict() != dict(raw):
            raise OrchestrationValidationError(
                "action execution terminal observation identity is invalid"
            )
        return rebuilt


def _build_action_execution_terminal_observation(
    **values: Any,
) -> ActionExecutionTerminalObservation:
    for label, prefix in (
        ("attempt_id", "AEA-"),
        ("job_id", "JOB-"),
        ("message_id", "MSG-"),
        ("intent_id", "AEI-"),
        ("claim_id", "JCL-"),
    ):
        _record_id(values[label], prefix, label)
    for label in (
        "tenant_id",
        "action_execution_request_id",
        "phase196_claim_id",
        "phase196_terminal_id",
    ):
        _identifier(values[label], label)
    for label in (
        "attempt_sha256",
        "job_sha256",
        "message_sha256",
        "intent_sha256",
        "claim_sha256",
        "action_execution_request_sha256",
        "phase196_claim_sha256",
        "phase196_terminal_sha256",
        "result_sha256",
    ):
        _digest(values[label], label)
    if values["terminal_status"] not in {
        "completed",
        "failed_known",
        "predispatch_aborted",
        "indeterminate_quarantined",
    }:
        raise OrchestrationValidationError("terminal_status is invalid")
    if values["action_outcome"] not in {"succeeded", "failed", "indeterminate"}:
        raise OrchestrationValidationError("action_outcome is invalid")
    if any(
        values[field] not in {"complete", "pending", "failed", "unknown"}
        for field in ("evidence_status", "cleanup_status", "restoration_status")
    ):
        raise OrchestrationValidationError("terminal axis is invalid")
    if values["adapter_call_count_status"] not in {
        "exactly_one",
        "exactly_zero",
        "unknown_zero_or_one",
    }:
        raise OrchestrationValidationError("adapter_call_count_status is invalid")
    count = values["adapter_call_count"]
    if count is not None:
        _integer(count, "adapter_call_count", 0, 1)
    _integer(values["automatic_retry_count"], "automatic_retry_count", 0, 0)
    _timestamp(values["settled_at"], "settled_at")
    _timestamp(values["observed_at"], "observed_at")
    if _instant(values["observed_at"]) < _instant(values["settled_at"]):
        raise OrchestrationValidationError("terminal observation predates settlement")
    if values["journal_effect"] != "terminal_observed_not_action_success":
        raise OrchestrationValidationError("terminal observation effect is invalid")
    body = {
        **_common(ActionExecutionTerminalObservation.KIND),
        **{
            key: value
            for key, value in values.items()
            if key not in {"observation_id", "observation_sha256"}
        },
    }
    observation_id, observation_sha256 = _identity(
        "AEO-", ActionExecutionTerminalObservation.KIND, body
    )
    if values.get("observation_id", observation_id) != observation_id or values.get(
        "observation_sha256", observation_sha256
    ) != observation_sha256:
        raise OrchestrationValidationError(
            "action execution terminal observation identity is invalid"
        )
    return ActionExecutionTerminalObservation(
        observation_id=observation_id,
        observation_sha256=observation_sha256,
        **{
            key: value
            for key, value in values.items()
            if key not in {"observation_id", "observation_sha256"}
        },
    )


@dataclass(frozen=True, slots=True)
class ActionExecutionReconciliation:
    reconciliation_id: str
    reconciliation_sha256: str
    attempt_id: str
    attempt_sha256: str
    job_id: str
    job_sha256: str
    message_id: str
    message_sha256: str
    intent_id: str
    intent_sha256: str
    claim_id: str
    claim_sha256: str
    tenant_id: str
    reconciler_subject_id: str
    reconciler_assertion_id: str
    reconciler_assertion_sha256: str
    reconciler_trust_policy_id: str
    reconciler_trust_policy_sha256: str
    reconciler_scope_id: str
    reconciler_scope_sha256: str
    reconciler_session_id: str
    reconciler_session_sha256: str
    reconciler_capability_id: str
    reconciler_capability_sha256: str
    reconciliation_lineage_sha256: str
    authority_issued_at: str
    authority_expires_at: str
    phase196_terminal_id: str | None
    phase196_terminal_sha256: str | None
    resolution_status: str
    resolved_at: str

    KIND: ClassVar[str] = "sunderkey.action-execution-reconciliation.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name != "KIND"
            },
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ActionExecutionReconciliation:
        fields = (set(cls.__dataclass_fields__) - {"KIND"}) | {
            "effects",
            "kind",
            "schema_version",
        }
        value = dict(_exact(raw, fields, "action execution reconciliation"))
        _verify_common(value, cls.KIND)
        for field in ("effects", "kind", "schema_version"):
            value.pop(field)
        rebuilt = _build_action_execution_reconciliation(**value)
        if rebuilt.to_dict() != dict(raw):
            raise OrchestrationValidationError(
                "action execution reconciliation identity is invalid"
            )
        return rebuilt


def _build_action_execution_reconciliation(
    **values: Any,
) -> ActionExecutionReconciliation:
    for label, prefix in (
        ("attempt_id", "AEA-"),
        ("job_id", "JOB-"),
        ("message_id", "MSG-"),
        ("intent_id", "AEI-"),
        ("claim_id", "JCL-"),
    ):
        _record_id(values[label], prefix, label)
    for label in (
        "tenant_id",
        "reconciler_subject_id",
        "reconciler_assertion_id",
        "reconciler_trust_policy_id",
        "reconciler_scope_id",
        "reconciler_session_id",
        "reconciler_capability_id",
    ):
        _identifier(values[label], label)
    for label in (
        "attempt_sha256",
        "job_sha256",
        "message_sha256",
        "intent_sha256",
        "claim_sha256",
        "reconciler_assertion_sha256",
        "reconciler_trust_policy_sha256",
        "reconciler_scope_sha256",
        "reconciler_session_sha256",
        "reconciler_capability_sha256",
        "reconciliation_lineage_sha256",
    ):
        _digest(values[label], label)
    for label in ("authority_issued_at", "authority_expires_at", "resolved_at"):
        _timestamp(values[label], label)
    if not (
        _instant(values["authority_issued_at"])
        <= _instant(values["resolved_at"])
        < _instant(values["authority_expires_at"])
    ):
        raise OrchestrationValidationError(
            "action reconciliation authority window is invalid"
        )
    terminal_id = values["phase196_terminal_id"]
    terminal_sha256 = values["phase196_terminal_sha256"]
    if (terminal_id is None) != (terminal_sha256 is None):
        raise OrchestrationValidationError(
            "action reconciliation terminal binding is incomplete"
        )
    if terminal_id is not None:
        _identifier(terminal_id, "phase196_terminal_id")
        _digest(terminal_sha256, "phase196_terminal_sha256")
    if values["resolution_status"] == "terminal_observed":
        if terminal_id is None:
            raise OrchestrationValidationError(
                "terminal reconciliation requires a terminal binding"
            )
    elif values["resolution_status"] == "indeterminate_quarantined":
        if terminal_id is not None:
            raise OrchestrationValidationError(
                "indeterminate reconciliation cannot bind a terminal"
            )
    else:
        raise OrchestrationValidationError(
            "action reconciliation resolution status is invalid"
        )
    body = {
        **_common(ActionExecutionReconciliation.KIND),
        **{
            key: value
            for key, value in values.items()
            if key not in {"reconciliation_id", "reconciliation_sha256"}
        },
    }
    reconciliation_id, reconciliation_sha256 = _identity(
        "AER-", ActionExecutionReconciliation.KIND, body
    )
    if values.get("reconciliation_id", reconciliation_id) != reconciliation_id or (
        values.get("reconciliation_sha256", reconciliation_sha256)
        != reconciliation_sha256
    ):
        raise OrchestrationValidationError(
            "action execution reconciliation identity is invalid"
        )
    return ActionExecutionReconciliation(
        reconciliation_id=reconciliation_id,
        reconciliation_sha256=reconciliation_sha256,
        **{
            key: value
            for key, value in values.items()
            if key not in {"reconciliation_id", "reconciliation_sha256"}
        },
    )


def action_execution_reconciliation_lineage_sha256(
    attempt: ActionExecutionAttempt,
) -> str:
    parsed = ActionExecutionAttempt.from_dict(attempt.to_dict())
    return canonical_sha256(
        {
            "attempt_id": parsed.attempt_id,
            "attempt_sha256": parsed.attempt_sha256,
            "claim_id": parsed.claim_id,
            "claim_sha256": parsed.claim_sha256,
            "domain": "sunderkey.action-execution-reconciliation-lineage.v1",
            "intent_id": parsed.intent_id,
            "intent_sha256": parsed.intent_sha256,
            "job_id": parsed.job_id,
            "job_sha256": parsed.job_sha256,
            "message_id": parsed.message_id,
            "message_sha256": parsed.message_sha256,
            "tenant_id": parsed.tenant_id,
            "worker_id": parsed.worker_id,
            "worker_session_id": parsed.worker_session_id,
            "worker_session_sha256": parsed.worker_session_sha256,
        }
    )


@dataclass(frozen=True, slots=True)
class OrchestrationMessage:
    message_id: str
    message_sha256: str
    tenant_id: str
    direction: MessageDirection
    topic: MessageTopic
    external_ref: str
    external_sha256: str
    source_bindings: tuple[SourceHighWater, ...]
    correlation_ref: str
    idempotency_key_sha256: str
    recorded_at: str

    KIND: ClassVar[str] = "sunderkey.orchestration-message.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            "correlation_ref": self.correlation_ref,
            "direction": self.direction.value,
            "external_ref": self.external_ref,
            "external_sha256": self.external_sha256,
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "message_id": self.message_id,
            "message_sha256": self.message_sha256,
            "recorded_at": self.recorded_at,
            "source_bindings": [item.to_dict() for item in self.source_bindings],
            "tenant_id": self.tenant_id,
            "topic": self.topic.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OrchestrationMessage:
        fields = {
            "correlation_ref",
            "direction",
            "effects",
            "external_ref",
            "external_sha256",
            "idempotency_key_sha256",
            "kind",
            "message_id",
            "message_sha256",
            "recorded_at",
            "schema_version",
            "source_bindings",
            "tenant_id",
            "topic",
        }
        value = _exact(raw, fields, "orchestration message")
        _verify_common(value, cls.KIND)
        rebuilt = build_orchestration_message(
            tenant_id=value["tenant_id"],
            direction=value["direction"],
            topic=value["topic"],
            external_ref=value["external_ref"],
            external_sha256=value["external_sha256"],
            source_bindings=tuple(
                SourceHighWater.from_dict(item) for item in value["source_bindings"]
            ),
            correlation_ref=value["correlation_ref"],
            idempotency_key_sha256=value["idempotency_key_sha256"],
            recorded_at=value["recorded_at"],
        )
        if rebuilt.to_dict() != dict(value):
            raise OrchestrationValidationError("orchestration message identity is invalid")
        return rebuilt


def build_orchestration_message(
    *,
    tenant_id: str,
    direction: MessageDirection | str,
    topic: MessageTopic | str,
    external_ref: str,
    external_sha256: str,
    source_bindings: Sequence[SourceHighWater | Mapping[str, Any]],
    correlation_ref: str,
    idempotency_key_sha256: str,
    recorded_at: str,
) -> OrchestrationMessage:
    parsed_direction = _enum(direction, MessageDirection, "direction")
    parsed_topic = _enum(topic, MessageTopic, "topic")
    bindings = _source_bindings(source_bindings)
    _identifier(tenant_id, "tenant_id")
    _identifier(external_ref, "external_ref")
    _digest(external_sha256, "external_sha256")
    _identifier(correlation_ref, "correlation_ref")
    _digest(idempotency_key_sha256, "idempotency_key_sha256")
    _timestamp(recorded_at, "recorded_at")
    _require_bindings_not_after(bindings, recorded_at, "recorded_at")
    body = {
        **_common(OrchestrationMessage.KIND),
        "correlation_ref": correlation_ref,
        "direction": parsed_direction.value,
        "external_ref": external_ref,
        "external_sha256": external_sha256,
        "idempotency_key_sha256": idempotency_key_sha256,
        "recorded_at": recorded_at,
        "source_bindings": [item.to_dict() for item in bindings],
        "tenant_id": tenant_id,
        "topic": parsed_topic.value,
    }
    record_id, digest = _identity("MSG-", OrchestrationMessage.KIND, body)
    return OrchestrationMessage(
        record_id,
        digest,
        tenant_id,
        parsed_direction,
        parsed_topic,
        external_ref,
        external_sha256,
        bindings,
        correlation_ref,
        idempotency_key_sha256,
        recorded_at,
    )


@dataclass(frozen=True, slots=True)
class SagaStep:
    step_id: str
    step_sha256: str
    tenant_id: str
    saga_id: str
    saga_kind: SagaKind
    sequence: int
    step_state: SagaStepState
    subject_ref: str
    observation_ref: str
    observation_sha256: str
    source_bindings: tuple[SourceHighWater, ...]
    prior_step_sha256: str | None
    recorded_at: str

    KIND: ClassVar[str] = "sunderkey.orchestration-saga-step.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            "observation_ref": self.observation_ref,
            "observation_sha256": self.observation_sha256,
            "prior_step_sha256": self.prior_step_sha256,
            "recorded_at": self.recorded_at,
            "saga_id": self.saga_id,
            "saga_kind": self.saga_kind.value,
            "sequence": self.sequence,
            "source_bindings": [item.to_dict() for item in self.source_bindings],
            "step_id": self.step_id,
            "step_sha256": self.step_sha256,
            "step_state": self.step_state.value,
            "subject_ref": self.subject_ref,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SagaStep:
        fields = {
            "effects",
            "kind",
            "observation_ref",
            "observation_sha256",
            "prior_step_sha256",
            "recorded_at",
            "saga_id",
            "saga_kind",
            "schema_version",
            "sequence",
            "source_bindings",
            "step_id",
            "step_sha256",
            "step_state",
            "subject_ref",
            "tenant_id",
        }
        value = _exact(raw, fields, "saga step")
        _verify_common(value, cls.KIND)
        rebuilt = build_saga_step(
            tenant_id=value["tenant_id"],
            saga_id=value["saga_id"],
            saga_kind=value["saga_kind"],
            sequence=value["sequence"],
            step_state=value["step_state"],
            subject_ref=value["subject_ref"],
            observation_ref=value["observation_ref"],
            observation_sha256=value["observation_sha256"],
            source_bindings=tuple(
                SourceHighWater.from_dict(item) for item in value["source_bindings"]
            ),
            prior_step_sha256=value["prior_step_sha256"],
            recorded_at=value["recorded_at"],
        )
        if rebuilt.to_dict() != dict(value):
            raise OrchestrationValidationError("saga step identity is invalid")
        return rebuilt


def build_saga_step(
    *,
    tenant_id: str,
    saga_id: str,
    saga_kind: SagaKind | str,
    sequence: int,
    step_state: SagaStepState | str,
    subject_ref: str,
    observation_ref: str,
    observation_sha256: str,
    source_bindings: Sequence[SourceHighWater | Mapping[str, Any]],
    prior_step_sha256: str | None,
    recorded_at: str,
) -> SagaStep:
    parsed_kind = _enum(saga_kind, SagaKind, "saga_kind")
    parsed_state = _enum(step_state, SagaStepState, "step_state")
    bindings = _source_bindings(source_bindings)
    for value, label in (
        (tenant_id, "tenant_id"),
        (saga_id, "saga_id"),
        (subject_ref, "subject_ref"),
        (observation_ref, "observation_ref"),
    ):
        _identifier(value, label)
    _integer(sequence, "sequence", 1, 2_147_483_647)
    _digest(observation_sha256, "observation_sha256")
    if prior_step_sha256 is not None:
        _digest(prior_step_sha256, "prior_step_sha256")
    if (sequence == 1) != (prior_step_sha256 is None):
        raise OrchestrationValidationError("saga predecessor is invalid")
    _timestamp(recorded_at, "recorded_at")
    _require_bindings_not_after(bindings, recorded_at, "recorded_at")
    body = {
        **_common(SagaStep.KIND),
        "observation_ref": observation_ref,
        "observation_sha256": observation_sha256,
        "prior_step_sha256": prior_step_sha256,
        "recorded_at": recorded_at,
        "saga_id": saga_id,
        "saga_kind": parsed_kind.value,
        "sequence": sequence,
        "source_bindings": [item.to_dict() for item in bindings],
        "step_state": parsed_state.value,
        "subject_ref": subject_ref,
        "tenant_id": tenant_id,
    }
    record_id, digest = _identity("SGS-", SagaStep.KIND, body)
    return SagaStep(
        record_id,
        digest,
        tenant_id,
        saga_id,
        parsed_kind,
        sequence,
        parsed_state,
        subject_ref,
        observation_ref,
        observation_sha256,
        bindings,
        prior_step_sha256,
        recorded_at,
    )


@dataclass(frozen=True, slots=True)
class DeliveryAttempt:
    attempt_id: str
    attempt_sha256: str
    tenant_id: str
    message_id: str
    message_sha256: str
    job_id: str
    claim_id: str
    claim_sha256: str
    fence_token: int
    attempt_number: int
    outcome: DeliveryOutcome
    remote_receipt_ref: str | None
    remote_receipt_sha256: str | None
    observed_at: str

    KIND: ClassVar[str] = "sunderkey.orchestration-delivery-attempt.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            "attempt_id": self.attempt_id,
            "attempt_number": self.attempt_number,
            "attempt_sha256": self.attempt_sha256,
            "claim_id": self.claim_id,
            "claim_sha256": self.claim_sha256,
            "fence_token": self.fence_token,
            "job_id": self.job_id,
            "message_id": self.message_id,
            "message_sha256": self.message_sha256,
            "observed_at": self.observed_at,
            "outcome": self.outcome.value,
            "remote_receipt_ref": self.remote_receipt_ref,
            "remote_receipt_sha256": self.remote_receipt_sha256,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DeliveryAttempt:
        fields = {
            "attempt_id",
            "attempt_number",
            "attempt_sha256",
            "claim_id",
            "claim_sha256",
            "effects",
            "fence_token",
            "job_id",
            "kind",
            "message_id",
            "message_sha256",
            "observed_at",
            "outcome",
            "remote_receipt_ref",
            "remote_receipt_sha256",
            "schema_version",
            "tenant_id",
        }
        value = _exact(raw, fields, "delivery attempt")
        _verify_common(value, cls.KIND)
        rebuilt = build_delivery_attempt(
            tenant_id=value["tenant_id"],
            message_id=value["message_id"],
            message_sha256=value["message_sha256"],
            job_id=value["job_id"],
            claim_id=value["claim_id"],
            claim_sha256=value["claim_sha256"],
            fence_token=value["fence_token"],
            attempt_number=value["attempt_number"],
            outcome=value["outcome"],
            remote_receipt_ref=value["remote_receipt_ref"],
            remote_receipt_sha256=value["remote_receipt_sha256"],
            observed_at=value["observed_at"],
        )
        if rebuilt.to_dict() != dict(value):
            raise OrchestrationValidationError("delivery attempt identity is invalid")
        return rebuilt


def build_delivery_attempt(
    *,
    tenant_id: str,
    message_id: str,
    message_sha256: str,
    job_id: str,
    claim_id: str,
    claim_sha256: str,
    fence_token: int,
    attempt_number: int,
    outcome: DeliveryOutcome | str,
    remote_receipt_ref: str | None,
    remote_receipt_sha256: str | None,
    observed_at: str,
) -> DeliveryAttempt:
    _identifier(tenant_id, "tenant_id")
    _record_id(message_id, "MSG-", "message_id")
    _digest(message_sha256, "message_sha256")
    _record_id(job_id, "JOB-", "job_id")
    _record_id(claim_id, "JCL-", "claim_id")
    _digest(claim_sha256, "claim_sha256")
    _integer(fence_token, "fence_token", 1, 2_147_483_647)
    _integer(attempt_number, "attempt_number", 1, 32)
    parsed_outcome = _enum(outcome, DeliveryOutcome, "outcome")
    if remote_receipt_ref is not None:
        _identifier(remote_receipt_ref, "remote_receipt_ref")
    if remote_receipt_sha256 is not None:
        _digest(remote_receipt_sha256, "remote_receipt_sha256")
    if (remote_receipt_ref is None) != (remote_receipt_sha256 is None):
        raise OrchestrationValidationError("remote receipt binding is incomplete")
    if parsed_outcome is DeliveryOutcome.ACKNOWLEDGED_OBSERVATION and remote_receipt_ref is None:
        raise OrchestrationValidationError("acknowledged observation requires a receipt")
    _timestamp(observed_at, "observed_at")
    body = {
        **_common(DeliveryAttempt.KIND),
        "attempt_number": attempt_number,
        "claim_id": claim_id,
        "claim_sha256": claim_sha256,
        "fence_token": fence_token,
        "job_id": job_id,
        "message_id": message_id,
        "message_sha256": message_sha256,
        "observed_at": observed_at,
        "outcome": parsed_outcome.value,
        "remote_receipt_ref": remote_receipt_ref,
        "remote_receipt_sha256": remote_receipt_sha256,
        "tenant_id": tenant_id,
    }
    record_id, digest = _identity("DLA-", DeliveryAttempt.KIND, body)
    return DeliveryAttempt(
        record_id,
        digest,
        tenant_id,
        message_id,
        message_sha256,
        job_id,
        claim_id,
        claim_sha256,
        fence_token,
        attempt_number,
        parsed_outcome,
        remote_receipt_ref,
        remote_receipt_sha256,
        observed_at,
    )


@dataclass(frozen=True, slots=True)
class OutboxDeliveryClaimCustody:
    custody_id: str
    custody_sha256: str
    job_id: str
    job_sha256: str
    message_id: str
    message_sha256: str
    claim_id: str
    claim_sha256: str
    tenant_id: str
    worker_id: str
    worker_assertion_id: str
    worker_assertion_sha256: str
    worker_session_id: str
    worker_session_sha256: str
    worker_capability_id: str
    worker_capability_sha256: str
    trusted_at: str
    expires_at: str
    attempt_number: int = 1

    KIND: ClassVar[str] = "sunderkey.outbox-delivery-claim-custody.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name != "KIND"
            },
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OutboxDeliveryClaimCustody:
        fields = (set(cls.__dataclass_fields__) - {"KIND"}) | {
            "effects",
            "kind",
            "schema_version",
        }
        value = dict(_exact(raw, fields, "outbox delivery claim custody"))
        _verify_common(value, cls.KIND)
        for field in ("effects", "kind", "schema_version"):
            value.pop(field)
        rebuilt = _build_outbox_delivery_claim_custody(**value)
        if rebuilt.to_dict() != dict(raw):
            raise OrchestrationValidationError("outbox delivery custody identity is invalid")
        return rebuilt


def _build_outbox_delivery_claim_custody(
    **values: Any,
) -> OutboxDeliveryClaimCustody:
    for label, prefix in (
        ("job_id", "JOB-"),
        ("message_id", "MSG-"),
        ("claim_id", "JCL-"),
    ):
        _record_id(values[label], prefix, label)
    for label in (
        "tenant_id",
        "worker_id",
        "worker_assertion_id",
        "worker_session_id",
        "worker_capability_id",
    ):
        _identifier(values[label], label)
    for label in (
        "job_sha256",
        "message_sha256",
        "claim_sha256",
        "worker_assertion_sha256",
        "worker_session_sha256",
        "worker_capability_sha256",
    ):
        _digest(values[label], label)
    _timestamp(values["trusted_at"], "trusted_at")
    _timestamp(values["expires_at"], "expires_at")
    _integer(values["attempt_number"], "attempt_number", 1, 1)
    if _instant(values["trusted_at"]) >= _instant(values["expires_at"]):
        raise OrchestrationValidationError("outbox delivery custody window is invalid")
    body = {
        **_common(OutboxDeliveryClaimCustody.KIND),
        **{
            key: value
            for key, value in values.items()
            if key not in {"custody_id", "custody_sha256"}
        },
    }
    custody_id, custody_sha256 = _identity(
        "ODC-", OutboxDeliveryClaimCustody.KIND, body
    )
    if values.get("custody_id", custody_id) != custody_id or values.get(
        "custody_sha256", custody_sha256
    ) != custody_sha256:
        raise OrchestrationValidationError("outbox delivery custody identity is invalid")
    return OutboxDeliveryClaimCustody(
        custody_id=custody_id,
        custody_sha256=custody_sha256,
        **{
            key: value
            for key, value in values.items()
            if key not in {"custody_id", "custody_sha256"}
        },
    )


@dataclass(frozen=True, slots=True)
class ReadModelProjection:
    projection_id: str
    projection_sha256: str
    tenant_id: str
    projection_kind: ProjectionKind
    subject_ref: str
    projection_version: int
    source_bindings: tuple[SourceHighWater, ...]
    payload: Mapping[str, Any]
    projected_at: str

    KIND: ClassVar[str] = "sunderkey.orchestration-read-model-projection.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            **_common(self.KIND),
            "payload": _thaw_json(self.payload),
            "projected_at": self.projected_at,
            "projection_id": self.projection_id,
            "projection_kind": self.projection_kind.value,
            "projection_sha256": self.projection_sha256,
            "projection_status": "source_bound_cache_only",
            "projection_version": self.projection_version,
            "source_bindings": [item.to_dict() for item in self.source_bindings],
            "subject_ref": self.subject_ref,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ReadModelProjection:
        fields = {
            "effects",
            "kind",
            "payload",
            "projected_at",
            "projection_id",
            "projection_kind",
            "projection_sha256",
            "projection_status",
            "projection_version",
            "schema_version",
            "source_bindings",
            "subject_ref",
            "tenant_id",
        }
        value = _exact(raw, fields, "read-model projection")
        _verify_common(value, cls.KIND)
        if value["projection_status"] != "source_bound_cache_only":
            raise OrchestrationValidationError("projection overclaims authority")
        rebuilt = build_read_model_projection(
            tenant_id=value["tenant_id"],
            projection_kind=value["projection_kind"],
            subject_ref=value["subject_ref"],
            projection_version=value["projection_version"],
            source_bindings=tuple(
                SourceHighWater.from_dict(item) for item in value["source_bindings"]
            ),
            payload=value["payload"],
            projected_at=value["projected_at"],
        )
        if rebuilt.to_dict() != dict(value):
            raise OrchestrationValidationError("read-model projection identity is invalid")
        return rebuilt


def build_read_model_projection(
    *,
    tenant_id: str,
    projection_kind: ProjectionKind | str,
    subject_ref: str,
    projection_version: int,
    source_bindings: Sequence[SourceHighWater | Mapping[str, Any]],
    payload: Mapping[str, Any],
    projected_at: str,
) -> ReadModelProjection:
    _identifier(tenant_id, "tenant_id")
    parsed_kind = _enum(projection_kind, ProjectionKind, "projection_kind")
    _identifier(subject_ref, "subject_ref")
    _integer(projection_version, "projection_version", 1, 2_147_483_647)
    bindings = _source_bindings(source_bindings)
    if not isinstance(payload, Mapping):
        raise OrchestrationValidationError("projection payload must be an object")
    if len(payload) > 256:
        raise OrchestrationValidationError(
            "projection payload exceeds the property limit"
        )
    _validate_projection_payload(payload)
    stable_payload = loads_json_without_duplicate_keys(canonical_json(dict(payload)))
    frozen_payload = _freeze_json(stable_payload)
    _timestamp(projected_at, "projected_at")
    _require_bindings_not_after(bindings, projected_at, "projected_at")
    body = {
        **_common(ReadModelProjection.KIND),
        "payload": stable_payload,
        "projected_at": projected_at,
        "projection_kind": parsed_kind.value,
        "projection_status": "source_bound_cache_only",
        "projection_version": projection_version,
        "source_bindings": [item.to_dict() for item in bindings],
        "subject_ref": subject_ref,
        "tenant_id": tenant_id,
    }
    record_id, digest = _identity("PRJ-", ReadModelProjection.KIND, body)
    return ReadModelProjection(
        record_id,
        digest,
        tenant_id,
        parsed_kind,
        subject_ref,
        projection_version,
        bindings,
        frozen_payload,
        projected_at,
    )


RecordT = TypeVar("RecordT")


@dataclass(frozen=True, slots=True)
class MutationResult(Generic[RecordT]):
    record: RecordT
    replayed: bool


@dataclass(frozen=True, slots=True)
class JobView:
    job: OrchestrationJob
    state: JobState
    revision: int
    attempt_number: int
    fence_token: int
    current_claim: JobClaim | None
    outcome: JobOutcome | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "authority_status": "not_authoritative",
            "current_claim": None if self.current_claim is None else self.current_claim.to_dict(),
            "fence_token": self.fence_token,
            "job": self.job.to_dict(),
            "outcome": None if self.outcome is None else self.outcome.to_dict(),
            "revision": self.revision,
            "state": self.state.value,
        }


_MIGRATION_1 = r"""
CREATE TABLE schema_migrations(
 version INTEGER PRIMARY KEY, migration_id TEXT NOT NULL UNIQUE,
 migration_sha256 TEXT NOT NULL UNIQUE, applied_at TEXT NOT NULL
) STRICT;
CREATE TABLE jobs(
 job_id TEXT PRIMARY KEY, job_sha256 TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL,
 job_kind TEXT NOT NULL CHECK(job_kind IN('source_reconciliation','projection_refresh',
 'inbox_processing','outbox_delivery','action_execution_handoff','saga_coordination')),
 idempotency_key_sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
 available_at TEXT NOT NULL, maximum_attempts INTEGER NOT NULL, lease_seconds INTEGER NOT NULL,
 job_json TEXT NOT NULL, UNIQUE(tenant_id,idempotency_key_sha256),
 CHECK(typeof(maximum_attempts)='integer'), CHECK(typeof(lease_seconds)='integer')
) STRICT;
CREATE TABLE job_heads(
 job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE RESTRICT,
 state TEXT NOT NULL CHECK(state IN('available','leased','worker_reported','dead_lettered')),
 revision INTEGER NOT NULL, attempt_number INTEGER NOT NULL, fence_token INTEGER NOT NULL,
 current_claim_id TEXT, current_claim_sha256 TEXT, current_outcome_id TEXT,
 current_outcome_sha256 TEXT, available_at TEXT NOT NULL,
 CHECK(typeof(revision)='integer'), CHECK(typeof(attempt_number)='integer'),
 CHECK(typeof(fence_token)='integer'),
 FOREIGN KEY(current_claim_id) REFERENCES job_claims(claim_id) ON DELETE RESTRICT,
 FOREIGN KEY(current_outcome_id) REFERENCES job_outcomes(outcome_id) ON DELETE RESTRICT
) STRICT;
CREATE TABLE job_claims(
 claim_id TEXT PRIMARY KEY, claim_sha256 TEXT NOT NULL UNIQUE,
 job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT, tenant_id TEXT NOT NULL,
 worker_id TEXT NOT NULL, attempt_number INTEGER NOT NULL, fence_token INTEGER NOT NULL,
 lease_version INTEGER NOT NULL, claimed_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 prior_claim_sha256 TEXT, claim_json TEXT NOT NULL,
 UNIQUE(job_id,fence_token,lease_version),
 CHECK(typeof(attempt_number)='integer'), CHECK(typeof(fence_token)='integer'),
 CHECK(typeof(lease_version)='integer')
) STRICT;
CREATE TABLE job_outcomes(
 outcome_id TEXT PRIMARY KEY, outcome_sha256 TEXT NOT NULL UNIQUE,
 claim_id TEXT NOT NULL REFERENCES job_claims(claim_id) ON DELETE RESTRICT,
 job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT, tenant_id TEXT NOT NULL,
 worker_id TEXT NOT NULL, fence_token INTEGER NOT NULL,
 outcome_code TEXT NOT NULL CHECK(outcome_code IN('handled_observation',
 'retryable_failure_observation','permanent_failure_observation','lease_exhausted_observation')),
 observed_at TEXT NOT NULL, outcome_json TEXT NOT NULL, UNIQUE(job_id,fence_token),
 CHECK(typeof(fence_token)='integer')
) STRICT;
CREATE TABLE messages(
 message_id TEXT PRIMARY KEY, message_sha256 TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL,
 direction TEXT NOT NULL CHECK(direction IN('inbox','outbox')),
 topic TEXT NOT NULL CHECK(topic IN('source_event','projection_change',
 'action_execution_handoff','worker_observation')),
 external_ref TEXT NOT NULL, external_sha256 TEXT NOT NULL,
 idempotency_key_sha256 TEXT NOT NULL, recorded_at TEXT NOT NULL, message_json TEXT NOT NULL,
 UNIQUE(tenant_id,direction,idempotency_key_sha256),
 UNIQUE(tenant_id,direction,external_ref)
) STRICT;
CREATE TABLE action_execution_intents(
 intent_id TEXT PRIMARY KEY, intent_sha256 TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL, mission_id TEXT NOT NULL,
 request_id TEXT NOT NULL UNIQUE, request_sha256 TEXT NOT NULL UNIQUE,
 envelope_ref TEXT NOT NULL, envelope_sha256 TEXT NOT NULL,
 idempotency_key_sha256 TEXT NOT NULL, authorization_expires_at TEXT NOT NULL,
 source_bindings_sha256 TEXT NOT NULL, requested_at TEXT NOT NULL,
 requested_by_subject_id TEXT NOT NULL, authentication_context_sha256 TEXT NOT NULL,
 intent_json TEXT NOT NULL, UNIQUE(tenant_id,idempotency_key_sha256),
 UNIQUE(tenant_id,envelope_ref)
) STRICT;
CREATE TABLE action_execution_attempts(
 attempt_id TEXT PRIMARY KEY, attempt_sha256 TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE RESTRICT,
 message_id TEXT NOT NULL UNIQUE REFERENCES messages(message_id) ON DELETE RESTRICT,
 intent_id TEXT NOT NULL UNIQUE REFERENCES action_execution_intents(intent_id) ON DELETE RESTRICT,
 claim_id TEXT NOT NULL UNIQUE REFERENCES job_claims(claim_id) ON DELETE RESTRICT,
 worker_id TEXT NOT NULL, worker_assertion_id TEXT NOT NULL,
 worker_assertion_sha256 TEXT NOT NULL, worker_session_id TEXT NOT NULL,
 worker_session_sha256 TEXT NOT NULL, worker_lease_id TEXT NOT NULL,
 worker_lease_sha256 TEXT NOT NULL, worker_capability_id TEXT NOT NULL,
 worker_capability_sha256 TEXT NOT NULL, trusted_at TEXT NOT NULL,
 expires_at TEXT NOT NULL, attempt_json TEXT NOT NULL
) STRICT;
CREATE TABLE action_execution_handoff_quarantines(
 quarantine_id TEXT PRIMARY KEY, quarantine_sha256 TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE RESTRICT,
 message_id TEXT NOT NULL UNIQUE REFERENCES messages(message_id) ON DELETE RESTRICT,
 intent_id TEXT NOT NULL UNIQUE REFERENCES action_execution_intents(intent_id) ON DELETE RESTRICT,
 authorization_expires_at TEXT NOT NULL, trusted_at TEXT NOT NULL,
 quarantine_json TEXT NOT NULL
) STRICT;
CREATE TABLE action_execution_terminal_observations(
 observation_id TEXT PRIMARY KEY, observation_sha256 TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE
 REFERENCES action_execution_attempts(attempt_id) ON DELETE RESTRICT,
 job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE RESTRICT,
 message_id TEXT NOT NULL UNIQUE REFERENCES messages(message_id) ON DELETE RESTRICT,
 intent_id TEXT NOT NULL UNIQUE REFERENCES action_execution_intents(intent_id) ON DELETE RESTRICT,
 claim_id TEXT NOT NULL UNIQUE REFERENCES job_claims(claim_id) ON DELETE RESTRICT,
 phase196_terminal_id TEXT NOT NULL UNIQUE,
 phase196_terminal_sha256 TEXT NOT NULL UNIQUE, terminal_status TEXT NOT NULL,
 action_outcome TEXT NOT NULL, settled_at TEXT NOT NULL, observed_at TEXT NOT NULL,
 observation_json TEXT NOT NULL
) STRICT;
CREATE TABLE action_execution_reconciliations(
 reconciliation_id TEXT PRIMARY KEY, reconciliation_sha256 TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE
 REFERENCES action_execution_attempts(attempt_id) ON DELETE RESTRICT,
 job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE RESTRICT,
 message_id TEXT NOT NULL UNIQUE REFERENCES messages(message_id) ON DELETE RESTRICT,
 intent_id TEXT NOT NULL UNIQUE REFERENCES action_execution_intents(intent_id) ON DELETE RESTRICT,
 claim_id TEXT NOT NULL UNIQUE REFERENCES job_claims(claim_id) ON DELETE RESTRICT,
 reconciler_subject_id TEXT NOT NULL, reconciler_session_id TEXT NOT NULL,
 reconciler_session_sha256 TEXT NOT NULL, reconciliation_lineage_sha256 TEXT NOT NULL,
 resolution_status TEXT NOT NULL CHECK(resolution_status IN(
 'terminal_observed','indeterminate_quarantined')),
 phase196_terminal_id TEXT, phase196_terminal_sha256 TEXT,
 authority_issued_at TEXT NOT NULL, authority_expires_at TEXT NOT NULL,
 resolved_at TEXT NOT NULL, reconciliation_json TEXT NOT NULL,
 CHECK((phase196_terminal_id IS NULL)=(phase196_terminal_sha256 IS NULL))
) STRICT;
CREATE TABLE saga_steps(
 step_id TEXT PRIMARY KEY, step_sha256 TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL,
 saga_id TEXT NOT NULL, sequence INTEGER NOT NULL, recorded_at TEXT NOT NULL,
 step_json TEXT NOT NULL, UNIQUE(tenant_id,saga_id,sequence),
 CHECK(typeof(sequence)='integer')
) STRICT;
CREATE TABLE delivery_attempts(
 attempt_id TEXT PRIMARY KEY, attempt_sha256 TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL,
 message_id TEXT NOT NULL REFERENCES messages(message_id) ON DELETE RESTRICT,
 job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT,
 claim_id TEXT NOT NULL REFERENCES job_claims(claim_id) ON DELETE RESTRICT,
 attempt_number INTEGER NOT NULL, observed_at TEXT NOT NULL, attempt_json TEXT NOT NULL,
 UNIQUE(message_id,attempt_number), CHECK(typeof(attempt_number)='integer')
) STRICT;
CREATE TABLE outbox_delivery_claim_custody(
 custody_id TEXT PRIMARY KEY, custody_sha256 TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE RESTRICT,
 message_id TEXT NOT NULL UNIQUE REFERENCES messages(message_id) ON DELETE RESTRICT,
 claim_id TEXT NOT NULL UNIQUE REFERENCES job_claims(claim_id) ON DELETE RESTRICT,
 worker_id TEXT NOT NULL, worker_assertion_id TEXT NOT NULL,
 worker_assertion_sha256 TEXT NOT NULL, worker_session_id TEXT NOT NULL,
 worker_session_sha256 TEXT NOT NULL, worker_capability_id TEXT NOT NULL,
 worker_capability_sha256 TEXT NOT NULL, trusted_at TEXT NOT NULL,
 expires_at TEXT NOT NULL, custody_json TEXT NOT NULL
) STRICT;
CREATE TABLE projections(
 projection_id TEXT PRIMARY KEY, projection_sha256 TEXT NOT NULL UNIQUE,
 tenant_id TEXT NOT NULL, projection_kind TEXT NOT NULL CHECK(projection_kind IN('mission','plan',
 'expert_work','review_queue','action_approval','action_execution','finding','evidence','health',
 'audit')), subject_ref TEXT NOT NULL,
 projection_version INTEGER NOT NULL, projected_at TEXT NOT NULL, projection_json TEXT NOT NULL,
 UNIQUE(tenant_id,projection_kind,subject_ref,projection_version),
 CHECK(typeof(projection_version)='integer')
) STRICT;
CREATE TABLE projection_heads(
 tenant_id TEXT NOT NULL, projection_kind TEXT NOT NULL, subject_ref TEXT NOT NULL,
 projection_id TEXT NOT NULL REFERENCES projections(projection_id) ON DELETE RESTRICT,
 projection_sha256 TEXT NOT NULL, projection_version INTEGER NOT NULL,
 PRIMARY KEY(tenant_id,projection_kind,subject_ref), CHECK(typeof(projection_version)='integer')
) STRICT;
CREATE TABLE journal_events(
 event_sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
 event_sha256 TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL, aggregate_type TEXT NOT NULL,
 aggregate_id TEXT NOT NULL, event_type TEXT NOT NULL, record_id TEXT NOT NULL,
 record_sha256 TEXT NOT NULL, prior_event_sha256 TEXT, occurred_at TEXT NOT NULL,
 event_json TEXT NOT NULL, UNIQUE(tenant_id,aggregate_type,aggregate_id,record_id),
 CHECK(typeof(event_sequence)='integer')
) STRICT;
CREATE TABLE event_heads(
 tenant_id TEXT NOT NULL, aggregate_type TEXT NOT NULL, aggregate_id TEXT NOT NULL,
 event_sequence INTEGER NOT NULL, event_sha256 TEXT NOT NULL,
 PRIMARY KEY(tenant_id,aggregate_type,aggregate_id),
 FOREIGN KEY(event_sequence) REFERENCES journal_events(event_sequence) ON DELETE RESTRICT,
 CHECK(typeof(event_sequence)='integer')
) STRICT;
CREATE INDEX jobs_available_idx ON jobs(tenant_id,available_at,job_id);
CREATE INDEX events_tenant_sequence_idx ON journal_events(tenant_id,event_sequence);
CREATE INDEX projections_subject_idx
 ON projections(tenant_id,projection_kind,subject_ref,projection_version);
CREATE TRIGGER schema_migrations_no_update BEFORE UPDATE ON schema_migrations
 BEGIN SELECT RAISE(ABORT,'migrations are immutable'); END;
CREATE TRIGGER schema_migrations_no_delete BEFORE DELETE ON schema_migrations
 BEGIN SELECT RAISE(ABORT,'migrations are immutable'); END;
CREATE TRIGGER jobs_no_update BEFORE UPDATE ON jobs
 BEGIN SELECT RAISE(ABORT,'jobs are immutable'); END;
CREATE TRIGGER jobs_no_delete BEFORE DELETE ON jobs
 BEGIN SELECT RAISE(ABORT,'jobs are immutable'); END;
CREATE TRIGGER job_claims_no_update BEFORE UPDATE ON job_claims
 BEGIN SELECT RAISE(ABORT,'claims are immutable'); END;
CREATE TRIGGER job_claims_no_delete BEFORE DELETE ON job_claims
 BEGIN SELECT RAISE(ABORT,'claims are immutable'); END;
CREATE TRIGGER job_outcomes_no_update BEFORE UPDATE ON job_outcomes
 BEGIN SELECT RAISE(ABORT,'outcomes are immutable'); END;
CREATE TRIGGER job_outcomes_no_delete BEFORE DELETE ON job_outcomes
 BEGIN SELECT RAISE(ABORT,'outcomes are immutable'); END;
CREATE TRIGGER messages_no_update BEFORE UPDATE ON messages
 BEGIN SELECT RAISE(ABORT,'messages are immutable'); END;
CREATE TRIGGER messages_no_delete BEFORE DELETE ON messages
 BEGIN SELECT RAISE(ABORT,'messages are immutable'); END;
CREATE TRIGGER action_execution_intents_no_update BEFORE UPDATE ON action_execution_intents
 BEGIN SELECT RAISE(ABORT,'action execution intents are immutable'); END;
CREATE TRIGGER action_execution_intents_no_delete BEFORE DELETE ON action_execution_intents
 BEGIN SELECT RAISE(ABORT,'action execution intents are immutable'); END;
CREATE TRIGGER action_execution_attempts_no_update BEFORE UPDATE ON action_execution_attempts
 BEGIN SELECT RAISE(ABORT,'action execution attempts are immutable'); END;
CREATE TRIGGER action_execution_attempts_no_delete BEFORE DELETE ON action_execution_attempts
 BEGIN SELECT RAISE(ABORT,'action execution attempts are immutable'); END;
CREATE TRIGGER action_execution_handoff_quarantines_no_update
 BEFORE UPDATE ON action_execution_handoff_quarantines
 BEGIN SELECT RAISE(ABORT,'action execution handoff quarantines are immutable'); END;
CREATE TRIGGER action_execution_handoff_quarantines_no_delete
 BEFORE DELETE ON action_execution_handoff_quarantines
 BEGIN SELECT RAISE(ABORT,'action execution handoff quarantines are immutable'); END;
CREATE TRIGGER action_execution_terminal_observations_no_update
 BEFORE UPDATE ON action_execution_terminal_observations
 BEGIN SELECT RAISE(ABORT,'action execution terminal observations are immutable'); END;
CREATE TRIGGER action_execution_terminal_observations_no_delete
 BEFORE DELETE ON action_execution_terminal_observations
 BEGIN SELECT RAISE(ABORT,'action execution terminal observations are immutable'); END;
CREATE TRIGGER action_execution_reconciliations_no_update
 BEFORE UPDATE ON action_execution_reconciliations
 BEGIN SELECT RAISE(ABORT,'action execution reconciliations are immutable'); END;
CREATE TRIGGER action_execution_reconciliations_no_delete
 BEFORE DELETE ON action_execution_reconciliations
 BEGIN SELECT RAISE(ABORT,'action execution reconciliations are immutable'); END;
CREATE TRIGGER saga_steps_no_update BEFORE UPDATE ON saga_steps
 BEGIN SELECT RAISE(ABORT,'saga steps are immutable'); END;
CREATE TRIGGER saga_steps_no_delete BEFORE DELETE ON saga_steps
 BEGIN SELECT RAISE(ABORT,'saga steps are immutable'); END;
CREATE TRIGGER delivery_attempts_no_update BEFORE UPDATE ON delivery_attempts
 BEGIN SELECT RAISE(ABORT,'delivery attempts are immutable'); END;
CREATE TRIGGER delivery_attempts_no_delete BEFORE DELETE ON delivery_attempts
 BEGIN SELECT RAISE(ABORT,'delivery attempts are immutable'); END;
CREATE TRIGGER outbox_delivery_claim_custody_no_update
 BEFORE UPDATE ON outbox_delivery_claim_custody
 BEGIN SELECT RAISE(ABORT,'outbox delivery claim custody is immutable'); END;
CREATE TRIGGER outbox_delivery_claim_custody_no_delete
 BEFORE DELETE ON outbox_delivery_claim_custody
 BEGIN SELECT RAISE(ABORT,'outbox delivery claim custody is immutable'); END;
CREATE TRIGGER projections_no_update BEFORE UPDATE ON projections
 BEGIN SELECT RAISE(ABORT,'projection history is immutable'); END;
CREATE TRIGGER projections_no_delete BEFORE DELETE ON projections
 BEGIN SELECT RAISE(ABORT,'projection history is immutable'); END;
CREATE TRIGGER journal_events_no_update BEFORE UPDATE ON journal_events
 BEGIN SELECT RAISE(ABORT,'events are immutable'); END;
CREATE TRIGGER journal_events_no_delete BEFORE DELETE ON journal_events
 BEGIN SELECT RAISE(ABORT,'events are immutable'); END;
""".strip()

MIGRATION_ID = "sunderkey.orchestration-journal.sqlite.v1"
MIGRATION_SHA256 = "sha256:" + hashlib.sha256(_MIGRATION_1.encode("utf-8")).hexdigest()


def _schema_manifest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    manifest = [
        {
            "name": row["name"],
            "sql": row["sql"],
            "table": row["tbl_name"],
            "type": row["type"],
        }
        for row in rows
    ]
    encoded = json.dumps(
        manifest,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _expected_schema_manifest() -> str:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_MIGRATION_1)
        return _schema_manifest(connection)
    finally:
        connection.close()


EXPECTED_SCHEMA_MANIFEST_SHA256 = _expected_schema_manifest()


class SQLiteOrchestrationJournal:
    """SQLite reference custody with no target or authority side effects."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_seconds: float = 2.0,
        trusted_clock: Callable[[], datetime] | None = None,
        phase196_terminal_resolver: Callable[[str], Any | None] | None = None,
    ) -> None:
        if str(path) == ":memory:":
            raise OrchestrationValidationError("file-backed SQLite is required")
        self.path = Path(os.path.abspath(path))
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or not 0 < busy_timeout_seconds <= 60
        ):
            raise OrchestrationValidationError("busy timeout is outside its allowed range")
        self.busy_timeout_seconds = float(busy_timeout_seconds)
        if trusted_clock is not None and not callable(trusted_clock):
            raise OrchestrationValidationError("trusted clock is not callable")
        if phase196_terminal_resolver is not None and not callable(
            phase196_terminal_resolver
        ):
            raise OrchestrationValidationError(
                "Phase196 terminal resolver is not callable"
            )
        self._trusted_clock = trusted_clock or (lambda: datetime.now(UTC))
        self._phase196_terminal_resolver = phase196_terminal_resolver
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _trusted_now(self) -> str:
        try:
            value = self._trusted_clock()
        except Exception as exc:
            raise OrchestrationIntegrityError("trusted clock failed") from exc
        if not isinstance(value, datetime):
            raise OrchestrationIntegrityError("trusted clock returned an invalid value")
        return format_timestamp(value)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            isolation_level=None,
            timeout=self.busy_timeout_seconds,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_seconds * 1000)}")
        return connection

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            yield connection
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise OrchestrationBusyError("orchestration journal is busy") from exc
            raise
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _migrate(self) -> None:
        with _MIGRATION_LOCK:
            self._migrate_locked()

    def _migrate_locked(self) -> None:
        connection = self._connect()
        try:
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            object_count = connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchone()[0]
            if version == 0:
                if application_id != 0 or object_count != 0:
                    raise OrchestrationIntegrityError(
                        "uninitialized orchestration database is not empty"
                    )
            elif version != SCHEMA_VERSION or application_id != APPLICATION_ID:
                raise OrchestrationIntegrityError("orchestration database identity is invalid")
            connection.execute("PRAGMA journal_mode = WAL")
            if version == 0:
                try:
                    connection.executescript("BEGIN IMMEDIATE;\n" + _MIGRATION_1)
                except sqlite3.OperationalError:
                    if connection.in_transaction:
                        connection.rollback()
                    application_id = connection.execute("PRAGMA application_id").fetchone()[0]
                    version = connection.execute("PRAGMA user_version").fetchone()[0]
                    if version != SCHEMA_VERSION or application_id != APPLICATION_ID:
                        raise
                else:
                    connection.execute(
                        "INSERT INTO schema_migrations VALUES(1,?,?,?)",
                        (MIGRATION_ID, MIGRATION_SHA256, "1970-01-01T00:00:00Z"),
                    )
                    connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    connection.commit()
            if (
                connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
            ):
                raise OrchestrationIntegrityError("orchestration database identity is invalid")
            self._verify_migration_identity(connection)
            if _schema_manifest(connection) != EXPECTED_SCHEMA_MANIFEST_SHA256:
                raise OrchestrationIntegrityError("orchestration schema manifest is invalid")
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _parse(document: str, parser: Any, label: str) -> Any:
        try:
            raw = loads_json_without_duplicate_keys(document)
            if canonical_json(raw) != document:
                raise OrchestrationValidationError("record JSON is not canonical")
            return parser(raw)
        except (KeyError, OrchestrationValidationError, TypeError, ValueError) as exc:
            raise OrchestrationIntegrityError(f"stored {label} is invalid") from exc

    @staticmethod
    def _verify_migration_identity(connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT version,migration_id,migration_sha256,applied_at "
            "FROM schema_migrations ORDER BY version"
        ).fetchall()
        expected = (1, MIGRATION_ID, MIGRATION_SHA256, "1970-01-01T00:00:00Z")
        if len(rows) != 1 or tuple(rows[0]) != expected:
            raise OrchestrationIntegrityError("orchestration migration identity is invalid")

    def submit_job(self, job: OrchestrationJob) -> MutationResult[OrchestrationJob]:
        parsed = OrchestrationJob.from_dict(job.to_dict())
        if parsed.job_kind is JobKind.ACTION_EXECUTION_HANDOFF:
            raise OrchestrationValidationError(
                "authoritative command handoffs require the atomic operator action path"
            )
        with self._write() as connection:
            if parsed.job_kind is JobKind.OUTBOX_DELIVERY:
                self._require_outbox_job_binding(connection, parsed)
                self._require_one_external_effect_job(connection, parsed)
            existing = connection.execute(
                "SELECT job_json FROM jobs WHERE tenant_id=? AND idempotency_key_sha256=?",
                (parsed.tenant_id, parsed.idempotency_key_sha256),
            ).fetchone()
            if existing is not None:
                stored = self._parse(existing["job_json"], OrchestrationJob.from_dict, "job")
                if stored != parsed:
                    raise OrchestrationConflictError("job idempotency key was rebound")
                return MutationResult(stored, True)
            self._insert_job(connection, parsed)
            self._append_event(
                connection,
                parsed.tenant_id,
                "job",
                parsed.job_id,
                "job.submitted",
                parsed.job_id,
                parsed.job_sha256,
                parsed.created_at,
            )
            return MutationResult(parsed, False)

    def _require_one_external_effect_job(
        self, connection: sqlite3.Connection, job: OrchestrationJob
    ) -> None:
        rows = connection.execute(
            "SELECT job_json FROM jobs WHERE tenant_id=? AND job_kind=?",
            (job.tenant_id, job.job_kind.value),
        ).fetchall()
        for row in rows:
            existing = self._parse(row["job_json"], OrchestrationJob.from_dict, "job")
            if existing.subject_ref == job.subject_ref and existing.job_id != job.job_id:
                raise OrchestrationConflictError(
                    "external-effect message already has a durable job"
                )

    def _require_outbox_job_binding(
        self, connection: sqlite3.Connection, job: OrchestrationJob
    ) -> OrchestrationMessage:
        row = connection.execute(
            "SELECT message_json FROM messages WHERE tenant_id=? AND message_id=?",
            (job.tenant_id, job.subject_ref),
        ).fetchone()
        if row is None:
            raise OrchestrationConflictError("outbox delivery message is unavailable")
        message = self._parse(row["message_json"], OrchestrationMessage.from_dict, "message")
        if (
            message.message_id != job.subject_ref
            or message.tenant_id != job.tenant_id
            or message.direction is not MessageDirection.OUTBOX
            or message.topic is MessageTopic.ACTION_EXECUTION_HANDOFF
            or job.input_ref != message.external_ref
            or job.input_sha256 != message.external_sha256
            or job.source_bindings != message.source_bindings
            or _instant(job.created_at) < _instant(message.recorded_at)
        ):
            raise OrchestrationConflictError("outbox delivery job binding is invalid")
        return message

    @staticmethod
    def _insert_job(connection: sqlite3.Connection, job: OrchestrationJob) -> None:
        document = canonical_json(job.to_dict())
        connection.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                job.job_id,
                job.job_sha256,
                job.tenant_id,
                job.job_kind.value,
                job.idempotency_key_sha256,
                job.created_at,
                job.available_at,
                job.maximum_attempts,
                job.lease_seconds,
                document,
            ),
        )
        connection.execute(
            "INSERT INTO job_heads VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                job.job_id,
                JobState.AVAILABLE.value,
                1,
                0,
                0,
                None,
                None,
                None,
                None,
                job.available_at,
            ),
        )

    def get_job(self, tenant_id: str, job_id: str) -> JobView | None:
        _identifier(tenant_id, "tenant_id")
        _record_id(job_id, "JOB-", "job_id")
        with self._read() as connection:
            return self._job_view(connection, tenant_id, job_id)

    def list_jobs(
        self,
        tenant_id: str,
        *,
        after_job_id: str | None = None,
        limit: int = 50,
    ) -> tuple[JobView, ...]:
        _identifier(tenant_id, "tenant_id")
        if after_job_id is not None:
            _record_id(after_job_id, "JOB-", "after_job_id")
        _integer(limit, "limit", 1, MAX_PAGE_SIZE)
        query = "SELECT job_id FROM jobs WHERE tenant_id=?"
        values: list[Any] = [tenant_id]
        if after_job_id is not None:
            query += " AND job_id>?"
            values.append(after_job_id)
        query += " ORDER BY job_id LIMIT ?"
        values.append(limit)
        with self._read() as connection:
            return tuple(
                self._require_job_view(connection, tenant_id, row["job_id"])
                for row in connection.execute(query, values).fetchall()
            )

    def _job_view(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        job_id: str,
    ) -> JobView | None:
        row = connection.execute(
            "SELECT jobs.job_json,job_heads.* FROM jobs JOIN job_heads USING(job_id) "
            "WHERE jobs.tenant_id=? AND jobs.job_id=?",
            (tenant_id, job_id),
        ).fetchone()
        if row is None:
            return None
        integer_fields = ("revision", "attempt_number", "fence_token")
        if any(type(row[field]) is not int or row[field] < 0 for field in integer_fields):
            raise OrchestrationIntegrityError("job head integer storage is invalid")
        if row["revision"] < 1 or row["state"] not in {item.value for item in JobState}:
            raise OrchestrationIntegrityError("job head state is invalid")
        for id_field, sha_field in (
            ("current_claim_id", "current_claim_sha256"),
            ("current_outcome_id", "current_outcome_sha256"),
        ):
            if (row[id_field] is None) != (row[sha_field] is None):
                raise OrchestrationIntegrityError("job head binding is incomplete")
            if row[id_field] is not None and (
                not isinstance(row[sha_field], str) or _SHA_RE.fullmatch(row[sha_field]) is None
            ):
                raise OrchestrationIntegrityError("job head digest is invalid")
        job = self._parse(row["job_json"], OrchestrationJob.from_dict, "job")
        if job.job_id != job_id or job.tenant_id != tenant_id:
            raise OrchestrationIntegrityError("job row crosses its requested boundary")
        claim = None
        if row["current_claim_id"] is not None:
            claim_row = connection.execute(
                "SELECT claim_json FROM job_claims WHERE claim_id=?",
                (row["current_claim_id"],),
            ).fetchone()
            if claim_row is None:
                raise OrchestrationIntegrityError("job head claim is missing")
            claim = self._parse(claim_row["claim_json"], JobClaim.from_dict, "job claim")
            if (
                claim.claim_sha256 != row["current_claim_sha256"]
                or claim.job_id != job.job_id
                or claim.job_sha256 != job.job_sha256
                or claim.tenant_id != job.tenant_id
                or claim.attempt_number != row["attempt_number"]
                or claim.fence_token != row["fence_token"]
            ):
                raise OrchestrationIntegrityError("job head claim binding is invalid")
            self._require_claim_custody(job, claim)
        outcome = None
        if row["current_outcome_id"] is not None:
            outcome_row = connection.execute(
                "SELECT outcome_json FROM job_outcomes WHERE outcome_id=?",
                (row["current_outcome_id"],),
            ).fetchone()
            if outcome_row is None:
                raise OrchestrationIntegrityError("job head outcome is missing")
            outcome = self._parse(outcome_row["outcome_json"], JobOutcome.from_dict, "job outcome")
            if (
                claim is None
                or outcome.outcome_sha256 != row["current_outcome_sha256"]
                or outcome.claim_id != claim.claim_id
                or outcome.claim_sha256 != claim.claim_sha256
                or outcome.job_id != job.job_id
                or outcome.tenant_id != job.tenant_id
                or outcome.worker_id != claim.worker_id
                or outcome.fence_token != row["fence_token"]
            ):
                raise OrchestrationIntegrityError("job head outcome binding is invalid")
        quarantine_row = connection.execute(
            "SELECT quarantine_json FROM action_execution_handoff_quarantines "
            "WHERE job_id=?",
            (job.job_id,),
        ).fetchone()
        quarantine = (
            None
            if quarantine_row is None
            else self._parse(
                quarantine_row["quarantine_json"],
                ActionExecutionHandoffQuarantine.from_dict,
                "action execution handoff quarantine",
            )
        )
        if quarantine is not None and (
            claim is not None
            or outcome is not None
            or job.job_kind is not JobKind.ACTION_EXECUTION_HANDOFF
            or quarantine.job_id != job.job_id
            or quarantine.job_sha256 != job.job_sha256
            or quarantine.tenant_id != job.tenant_id
        ):
            raise OrchestrationIntegrityError("job head quarantine binding is invalid")
        state = JobState(row["state"])
        expected_available = job.available_at
        if quarantine is not None:
            expected_state = JobState.DEAD_LETTERED
        elif claim is None:
            expected_state = JobState.AVAILABLE
        elif outcome is None:
            expected_state = JobState.LEASED
        elif outcome.outcome_code is JobOutcomeCode.HANDLED_OBSERVATION:
            expected_state = JobState.WORKER_REPORTED
        elif outcome.outcome_code in {
            JobOutcomeCode.PERMANENT_FAILURE_OBSERVATION,
            JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION,
        }:
            expected_state = JobState.DEAD_LETTERED
        else:
            expected_state = (
                JobState.AVAILABLE
                if claim.attempt_number < job.maximum_attempts
                else JobState.DEAD_LETTERED
            )
            expected_available = outcome.retry_available_at
        if state is not expected_state or row["available_at"] != expected_available:
            raise OrchestrationIntegrityError("job head state binding is invalid")
        return JobView(
            job,
            state,
            row["revision"],
            row["attempt_number"],
            row["fence_token"],
            claim,
            outcome,
        )

    def _require_job_view(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        job_id: str,
    ) -> JobView:
        view = self._job_view(connection, tenant_id, job_id)
        if view is None:
            raise OrchestrationConflictError("job is unavailable")
        return view

    @staticmethod
    def _require_claim_custody(job: OrchestrationJob, claim: JobClaim) -> None:
        expected_expiry = format_timestamp(
            _instant(claim.claimed_at) + timedelta(seconds=job.lease_seconds)
        )
        if (
            claim.job_id != job.job_id
            or claim.job_sha256 != job.job_sha256
            or claim.tenant_id != job.tenant_id
            or claim.attempt_number != claim.fence_token
            or claim.attempt_number > job.maximum_attempts
            or _instant(claim.claimed_at) < _instant(job.created_at)
            or claim.expires_at != expected_expiry
        ):
            raise OrchestrationIntegrityError("job claim custody is invalid")

    def claim_next_job(self, tenant_id: str, worker_id: str, *, now: str) -> JobClaim | None:
        _identifier(tenant_id, "tenant_id")
        _identifier(worker_id, "worker_id")
        _timestamp(now, "now")
        with self._write() as connection:
            trusted_at = self._trusted_now()
            row = connection.execute(
                "SELECT jobs.*,job_heads.state,job_heads.revision,job_heads.attempt_number,"
                "job_heads.fence_token,job_heads.current_claim_id,job_heads.current_claim_sha256 "
                "FROM jobs JOIN job_heads USING(job_id) WHERE jobs.tenant_id=? AND "
                "jobs.job_kind NOT IN(?,?) AND "
                "job_heads.attempt_number < jobs.maximum_attempts AND "
                "((job_heads.state='available' AND job_heads.available_at<=?) OR "
                "(job_heads.state='leased' AND EXISTS(SELECT 1 FROM job_claims c "
                "WHERE c.claim_id=job_heads.current_claim_id AND c.expires_at<=?) "
                "AND jobs.job_kind NOT IN(?,?))) "
                "ORDER BY job_heads.available_at,jobs.job_id LIMIT 1",
                (
                    tenant_id,
                    JobKind.OUTBOX_DELIVERY.value,
                    JobKind.ACTION_EXECUTION_HANDOFF.value,
                    trusted_at,
                    trusted_at,
                    JobKind.OUTBOX_DELIVERY.value,
                    JobKind.ACTION_EXECUTION_HANDOFF.value,
                ),
            ).fetchone()
            if row is None:
                return None
            job = self._parse(row["job_json"], OrchestrationJob.from_dict, "job")
            attempt = row["attempt_number"] + 1
            fence = row["fence_token"] + 1
            expires = format_timestamp(
                _instant(trusted_at) + timedelta(seconds=job.lease_seconds)
            )
            claim = _build_job_claim(
                job_id=job.job_id,
                job_sha256=job.job_sha256,
                tenant_id=tenant_id,
                worker_id=worker_id,
                attempt_number=attempt,
                fence_token=fence,
                lease_version=1,
                claimed_at=trusted_at,
                expires_at=expires,
                prior_claim_sha256=None,
            )
            self._insert_claim(connection, claim)
            changed = connection.execute(
                "UPDATE job_heads SET state='leased',revision=revision+1,attempt_number=?,"
                "fence_token=?,current_claim_id=?,current_claim_sha256=?,"
                "current_outcome_id=NULL,current_outcome_sha256=NULL,available_at=? "
                "WHERE job_id=? AND revision=?",
                (
                    attempt,
                    fence,
                    claim.claim_id,
                    claim.claim_sha256,
                    job.available_at,
                    job.job_id,
                    row["revision"],
                ),
            ).rowcount
            if changed != 1:
                raise OrchestrationConflictError("job claim lost its compare-and-swap race")
            self._append_event(
                connection,
                tenant_id,
                "job",
                job.job_id,
                "job.claimed",
                claim.claim_id,
                claim.claim_sha256,
                trusted_at,
            )
            return claim

    def claim_action_execution_handoff(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        worker_assertion_id: str,
        worker_assertion_sha256: str,
        worker_trust_policy_id: str,
        worker_trust_policy_sha256: str,
        worker_scope_id: str,
        worker_scope_sha256: str,
        worker_session_id: str,
        worker_session_sha256: str,
        worker_lease_id: str,
        worker_lease_sha256: str,
        worker_capability_id: str,
        worker_capability_sha256: str,
    ) -> ActionExecutionAttempt | None:
        """Claim one handoff with exact authenticated worker/session custody."""

        for label, value in (
            ("tenant_id", tenant_id),
            ("worker_id", worker_id),
            ("worker_assertion_id", worker_assertion_id),
            ("worker_trust_policy_id", worker_trust_policy_id),
            ("worker_scope_id", worker_scope_id),
            ("worker_session_id", worker_session_id),
            ("worker_lease_id", worker_lease_id),
            ("worker_capability_id", worker_capability_id),
        ):
            _identifier(value, label)
        for label, value in (
            ("worker_assertion_sha256", worker_assertion_sha256),
            ("worker_trust_policy_sha256", worker_trust_policy_sha256),
            ("worker_scope_sha256", worker_scope_sha256),
            ("worker_session_sha256", worker_session_sha256),
            ("worker_lease_sha256", worker_lease_sha256),
            ("worker_capability_sha256", worker_capability_sha256),
        ):
            _digest(value, label)
        with self._write() as connection:
            trusted_at = self._trusted_now()
            selected: tuple[
                sqlite3.Row,
                OrchestrationJob,
                OrchestrationMessage,
                ActionExecutionIntent,
                str,
            ] | None = None

            def quarantine_candidate(
                candidate: sqlite3.Row,
                candidate_job: OrchestrationJob,
                candidate_message: OrchestrationMessage,
                candidate_intent: ActionExecutionIntent,
                quarantined_at: str,
            ) -> None:
                quarantine = _build_action_execution_handoff_quarantine(
                    job_id=candidate_job.job_id,
                    job_sha256=candidate_job.job_sha256,
                    message_id=candidate_message.message_id,
                    message_sha256=candidate_message.message_sha256,
                    intent_id=candidate_intent.intent_id,
                    intent_sha256=candidate_intent.intent_sha256,
                    tenant_id=candidate_intent.tenant_id,
                    authorization_expires_at=(
                        candidate_intent.authorization_expires_at
                    ),
                    trusted_at=quarantined_at,
                    reason="authorization_window_ineligible_before_claim",
                    custody_effect="not_attempted_no_action_inference",
                )
                connection.execute(
                    "INSERT INTO action_execution_handoff_quarantines "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        quarantine.quarantine_id,
                        quarantine.quarantine_sha256,
                        quarantine.tenant_id,
                        quarantine.job_id,
                        quarantine.message_id,
                        quarantine.intent_id,
                        quarantine.authorization_expires_at,
                        quarantine.trusted_at,
                        canonical_json(quarantine.to_dict()),
                    ),
                )
                changed = connection.execute(
                    "UPDATE job_heads SET state='dead_lettered',"
                    "revision=revision+1 WHERE job_id=? AND revision=? "
                    "AND state='available' AND attempt_number=0",
                    (candidate_job.job_id, candidate["revision"]),
                ).rowcount
                if changed != 1:
                    raise OrchestrationConflictError(
                        "handoff quarantine lost its compare-and-swap race"
                    )
                self._append_event(
                    connection,
                    quarantine.tenant_id,
                    "job",
                    quarantine.job_id,
                    "action_execution.handoff_quarantined",
                    quarantine.quarantine_id,
                    quarantine.quarantine_sha256,
                    quarantined_at,
                )

            while selected is None:
                # Each bounded page removes ineligible rows before the next page is read.
                candidate_rows = connection.execute(
                    "SELECT jobs.job_json,job_heads.revision FROM jobs JOIN job_heads "
                    "USING(job_id) WHERE jobs.tenant_id=? AND jobs.job_kind=? "
                    "AND job_heads.state='available' AND job_heads.attempt_number=0 "
                    "AND job_heads.available_at<=? ORDER BY job_heads.available_at,"
                    "jobs.job_id LIMIT 200",
                    (tenant_id, JobKind.ACTION_EXECUTION_HANDOFF.value, trusted_at),
                ).fetchall()
                if not candidate_rows:
                    return None
                for candidate in candidate_rows:
                    candidate_job = self._parse(
                        candidate["job_json"], OrchestrationJob.from_dict, "job"
                    )
                    message_row = connection.execute(
                        "SELECT message_json FROM messages WHERE message_id=?",
                        (candidate_job.subject_ref,),
                    ).fetchone()
                    intent_row = connection.execute(
                        "SELECT intent_json FROM action_execution_intents "
                        "WHERE intent_id=?",
                        (candidate_job.input_ref,),
                    ).fetchone()
                    if message_row is None or intent_row is None:
                        raise OrchestrationIntegrityError(
                            "action execution handoff lineage is incomplete"
                        )
                    candidate_message = self._parse(
                        message_row["message_json"],
                        OrchestrationMessage.from_dict,
                        "message",
                    )
                    candidate_intent = self._parse(
                        intent_row["intent_json"],
                        ActionExecutionIntent.from_dict,
                        "action execution intent",
                    )
                    self._require_action_execution_handoff_binding(
                        candidate_message, candidate_job, candidate_intent
                    )
                    candidate_expires = format_timestamp(
                        _instant(trusted_at)
                        + timedelta(seconds=candidate_job.lease_seconds)
                    )
                    if _instant(candidate_expires) > _instant(
                        candidate_intent.authorization_expires_at
                    ):
                        quarantine_candidate(
                            candidate,
                            candidate_job,
                            candidate_message,
                            candidate_intent,
                            trusted_at,
                        )
                        continue
                    prior_trusted_at = trusted_at
                    fresh_trusted_at = self._trusted_now()
                    if (
                        _instant(fresh_trusted_at) < _instant(prior_trusted_at)
                        or _instant(fresh_trusted_at)
                        < _instant(candidate_job.available_at)
                    ):
                        raise OrchestrationIntegrityError(
                            "trusted clock regressed during action claim"
                        )
                    trusted_at = fresh_trusted_at
                    candidate_expires = format_timestamp(
                        _instant(trusted_at)
                        + timedelta(seconds=candidate_job.lease_seconds)
                    )
                    if _instant(candidate_expires) > _instant(
                        candidate_intent.authorization_expires_at
                    ):
                        quarantine_candidate(
                            candidate,
                            candidate_job,
                            candidate_message,
                            candidate_intent,
                            trusted_at,
                        )
                        continue
                    selected = (
                        candidate,
                        candidate_job,
                        candidate_message,
                        candidate_intent,
                        candidate_expires,
                    )
                    break
            row, job, message, intent, expires_at = selected
            claim = _build_job_claim(
                job_id=job.job_id,
                job_sha256=job.job_sha256,
                tenant_id=tenant_id,
                worker_id=worker_id,
                attempt_number=1,
                fence_token=1,
                lease_version=1,
                claimed_at=trusted_at,
                expires_at=expires_at,
                prior_claim_sha256=None,
            )
            attempt = _build_action_execution_attempt(
                job_id=job.job_id,
                job_sha256=job.job_sha256,
                message_id=message.message_id,
                message_sha256=message.message_sha256,
                intent_id=intent.intent_id,
                intent_sha256=intent.intent_sha256,
                claim_id=claim.claim_id,
                claim_sha256=claim.claim_sha256,
                tenant_id=intent.tenant_id,
                mission_id=intent.mission_id,
                action_execution_envelope_ref=intent.action_execution_envelope_ref,
                action_execution_envelope_sha256=(
                    intent.action_execution_envelope_sha256
                ),
                command_sha256=intent.command_sha256,
                action_execution_request_id=intent.action_execution_request_id,
                action_execution_request_sha256=(
                    intent.action_execution_request_sha256
                ),
                receipt_id=intent.receipt_id,
                receipt_sha256=intent.receipt_sha256,
                action_execute_intent_sha256=intent.action_execute_intent_sha256,
                assertion_id=intent.assertion_id,
                assertion_sha256=intent.assertion_sha256,
                authorization_sha256=intent.authorization_sha256,
                authorization_expires_at=intent.authorization_expires_at,
                source_bindings_sha256=intent.source_bindings_sha256,
                source_bindings=intent.source_bindings,
                worker_id=worker_id,
                worker_assertion_id=worker_assertion_id,
                worker_assertion_sha256=worker_assertion_sha256,
                worker_trust_policy_id=worker_trust_policy_id,
                worker_trust_policy_sha256=worker_trust_policy_sha256,
                worker_scope_id=worker_scope_id,
                worker_scope_sha256=worker_scope_sha256,
                worker_session_id=worker_session_id,
                worker_session_sha256=worker_session_sha256,
                worker_lease_id=worker_lease_id,
                worker_lease_sha256=worker_lease_sha256,
                worker_capability_id=worker_capability_id,
                worker_capability_sha256=worker_capability_sha256,
                trusted_at=trusted_at,
                expires_at=expires_at,
                attempt_number=1,
            )
            self._insert_claim(connection, claim)
            connection.execute(
                "INSERT INTO action_execution_attempts "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    attempt.attempt_id,
                    attempt.attempt_sha256,
                    attempt.tenant_id,
                    attempt.job_id,
                    attempt.message_id,
                    attempt.intent_id,
                    attempt.claim_id,
                    attempt.worker_id,
                    attempt.worker_assertion_id,
                    attempt.worker_assertion_sha256,
                    attempt.worker_session_id,
                    attempt.worker_session_sha256,
                    attempt.worker_lease_id,
                    attempt.worker_lease_sha256,
                    attempt.worker_capability_id,
                    attempt.worker_capability_sha256,
                    attempt.trusted_at,
                    attempt.expires_at,
                    canonical_json(attempt.to_dict()),
                ),
            )
            changed = connection.execute(
                "UPDATE job_heads SET state='leased',revision=revision+1,attempt_number=1,"
                "fence_token=1,current_claim_id=?,current_claim_sha256=?,"
                "current_outcome_id=NULL,current_outcome_sha256=NULL WHERE job_id=? "
                "AND revision=? AND state='available' AND attempt_number=0",
                (claim.claim_id, claim.claim_sha256, job.job_id, row["revision"]),
            ).rowcount
            if changed != 1:
                raise OrchestrationConflictError(
                    "action execution claim lost its compare-and-swap race"
                )
            self._append_event(
                connection,
                tenant_id,
                "job",
                job.job_id,
                "job.claimed",
                claim.claim_id,
                claim.claim_sha256,
                trusted_at,
            )
            self._append_event(
                connection,
                tenant_id,
                "job",
                job.job_id,
                "action_execution.attempt_claimed",
                attempt.attempt_id,
                attempt.attempt_sha256,
                trusted_at,
            )
            return attempt

    def claim_outbox_delivery(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        worker_assertion_id: str,
        worker_assertion_sha256: str,
        worker_session_id: str,
        worker_session_sha256: str,
        worker_capability_id: str,
        worker_capability_sha256: str,
    ) -> OutboxDeliveryClaimCustody | None:
        """Claim one outbox delivery with authenticated, single-attempt custody."""

        for label, value in (
            ("tenant_id", tenant_id),
            ("worker_id", worker_id),
            ("worker_assertion_id", worker_assertion_id),
            ("worker_session_id", worker_session_id),
            ("worker_capability_id", worker_capability_id),
        ):
            _identifier(value, label)
        for label, value in (
            ("worker_assertion_sha256", worker_assertion_sha256),
            ("worker_session_sha256", worker_session_sha256),
            ("worker_capability_sha256", worker_capability_sha256),
        ):
            _digest(value, label)
        with self._write() as connection:
            trusted_at = self._trusted_now()
            row = connection.execute(
                "SELECT jobs.job_json,job_heads.revision "
                "FROM jobs JOIN job_heads USING(job_id) WHERE jobs.tenant_id=? "
                "AND jobs.job_kind=? AND job_heads.state='available' "
                "AND job_heads.attempt_number=0 AND job_heads.available_at<=? "
                "ORDER BY job_heads.available_at,jobs.job_id LIMIT 1",
                (tenant_id, JobKind.OUTBOX_DELIVERY.value, trusted_at),
            ).fetchone()
            if row is None:
                return None
            job = self._parse(row["job_json"], OrchestrationJob.from_dict, "job")
            if job.maximum_attempts != 1:
                raise OrchestrationIntegrityError(
                    "outbox delivery attempt policy is invalid"
                )
            message = self._require_outbox_job_binding(connection, job)
            expires_at = format_timestamp(
                _instant(trusted_at) + timedelta(seconds=job.lease_seconds)
            )
            claim = _build_job_claim(
                job_id=job.job_id,
                job_sha256=job.job_sha256,
                tenant_id=tenant_id,
                worker_id=worker_id,
                attempt_number=1,
                fence_token=1,
                lease_version=1,
                claimed_at=trusted_at,
                expires_at=expires_at,
                prior_claim_sha256=None,
            )
            custody = _build_outbox_delivery_claim_custody(
                job_id=job.job_id,
                job_sha256=job.job_sha256,
                message_id=message.message_id,
                message_sha256=message.message_sha256,
                claim_id=claim.claim_id,
                claim_sha256=claim.claim_sha256,
                tenant_id=tenant_id,
                worker_id=worker_id,
                worker_assertion_id=worker_assertion_id,
                worker_assertion_sha256=worker_assertion_sha256,
                worker_session_id=worker_session_id,
                worker_session_sha256=worker_session_sha256,
                worker_capability_id=worker_capability_id,
                worker_capability_sha256=worker_capability_sha256,
                trusted_at=trusted_at,
                expires_at=expires_at,
                attempt_number=1,
            )
            self._insert_claim(connection, claim)
            connection.execute(
                "INSERT INTO outbox_delivery_claim_custody "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    custody.custody_id,
                    custody.custody_sha256,
                    custody.tenant_id,
                    custody.job_id,
                    custody.message_id,
                    custody.claim_id,
                    custody.worker_id,
                    custody.worker_assertion_id,
                    custody.worker_assertion_sha256,
                    custody.worker_session_id,
                    custody.worker_session_sha256,
                    custody.worker_capability_id,
                    custody.worker_capability_sha256,
                    custody.trusted_at,
                    custody.expires_at,
                    canonical_json(custody.to_dict()),
                ),
            )
            changed = connection.execute(
                "UPDATE job_heads SET state='leased',revision=revision+1,attempt_number=1,"
                "fence_token=1,current_claim_id=?,current_claim_sha256=? WHERE job_id=? "
                "AND revision=? AND state='available' AND attempt_number=0",
                (claim.claim_id, claim.claim_sha256, job.job_id, row["revision"]),
            ).rowcount
            if changed != 1:
                raise OrchestrationConflictError(
                    "outbox delivery claim lost its compare-and-swap race"
                )
            self._append_event(
                connection,
                tenant_id,
                "job",
                job.job_id,
                "job.claimed",
                claim.claim_id,
                claim.claim_sha256,
                trusted_at,
            )
            self._append_event(
                connection,
                tenant_id,
                "job",
                job.job_id,
                "outbox.delivery_claimed",
                custody.custody_id,
                custody.custody_sha256,
                trusted_at,
            )
            return custody

    def record_outbox_delivery_observation(
        self,
        custody: OutboxDeliveryClaimCustody,
        attempt: DeliveryAttempt,
    ) -> tuple[MutationResult[DeliveryAttempt], MutationResult[JobOutcome]]:
        """Atomically persist one delivery observation and conservatively settle its job."""

        parsed_custody = OutboxDeliveryClaimCustody.from_dict(custody.to_dict())
        parsed_attempt = DeliveryAttempt.from_dict(attempt.to_dict())
        with self._write() as connection:
            trusted_at = self._trusted_now()
            custody_row = connection.execute(
                "SELECT custody_json FROM outbox_delivery_claim_custody "
                "WHERE custody_id=?",
                (parsed_custody.custody_id,),
            ).fetchone()
            if custody_row is None:
                raise OrchestrationConflictError(
                    "outbox delivery custody is not durable"
                )
            stored_custody = self._parse(
                custody_row["custody_json"],
                OutboxDeliveryClaimCustody.from_dict,
                "outbox delivery claim custody",
            )
            if stored_custody != parsed_custody:
                raise OrchestrationConflictError(
                    "outbox delivery custody identity was substituted"
                )
            existing = connection.execute(
                "SELECT attempt_json FROM delivery_attempts WHERE claim_id=?",
                (parsed_custody.claim_id,),
            ).fetchone()
            if existing is not None:
                stored_attempt = self._parse(
                    existing["attempt_json"],
                    DeliveryAttempt.from_dict,
                    "delivery attempt",
                )
                if stored_attempt != parsed_attempt:
                    raise OrchestrationConflictError(
                        "outbox delivery claim has a different observation"
                    )
                outcome_row = connection.execute(
                    "SELECT outcome_json FROM job_outcomes WHERE job_id=? "
                    "AND fence_token=1",
                    (parsed_custody.job_id,),
                ).fetchone()
                if outcome_row is None:
                    raise OrchestrationIntegrityError(
                        "outbox delivery observation outcome is missing"
                    )
                stored_outcome = self._parse(
                    outcome_row["outcome_json"], JobOutcome.from_dict, "job outcome"
                )
                if (
                    stored_outcome.result_ref != stored_attempt.attempt_id
                    or stored_outcome.result_sha256 != stored_attempt.attempt_sha256
                    or stored_outcome.outcome_code
                    is not _DELIVERY_JOB_OUTCOME[stored_attempt.outcome]
                ):
                    raise OrchestrationIntegrityError(
                        "outbox delivery observation outcome is invalid"
                    )
                return MutationResult(stored_attempt, True), MutationResult(
                    stored_outcome, True
                )

            view = self._require_job_view(
                connection, parsed_custody.tenant_id, parsed_custody.job_id
            )
            if (
                view.job.job_kind is not JobKind.OUTBOX_DELIVERY
                or view.job.maximum_attempts != 1
                or view.state is not JobState.LEASED
                or view.current_claim is None
                or view.current_claim.claim_id != parsed_custody.claim_id
                or view.current_claim.claim_sha256 != parsed_custody.claim_sha256
                or view.current_claim.worker_id != parsed_custody.worker_id
                or view.current_claim.attempt_number != 1
                or view.current_claim.fence_token != 1
                or view.current_claim.lease_version != 1
                or view.current_claim.claimed_at != parsed_custody.trusted_at
                or view.current_claim.expires_at != parsed_custody.expires_at
            ):
                raise OrchestrationConflictError(
                    "outbox delivery custody does not own the current job"
                )
            message = self._require_outbox_job_binding(connection, view.job)
            if (
                parsed_attempt.tenant_id != parsed_custody.tenant_id
                or parsed_attempt.message_id != parsed_custody.message_id
                or parsed_attempt.message_sha256 != parsed_custody.message_sha256
                or parsed_attempt.message_id != message.message_id
                or parsed_attempt.message_sha256 != message.message_sha256
                or parsed_attempt.job_id != parsed_custody.job_id
                or parsed_attempt.claim_id != parsed_custody.claim_id
                or parsed_attempt.claim_sha256 != parsed_custody.claim_sha256
                or parsed_attempt.fence_token != 1
                or parsed_attempt.attempt_number != 1
            ):
                raise OrchestrationConflictError(
                    "delivery observation does not bind its authenticated custody"
                )
            if _instant(trusted_at) >= _instant(parsed_custody.expires_at):
                raise OrchestrationConflictError(
                    "expired outbox custody cannot settle a delivery observation"
                )
            if (
                _instant(parsed_attempt.observed_at)
                < _instant(parsed_custody.trusted_at)
                or _instant(parsed_attempt.observed_at) > _instant(trusted_at)
            ):
                raise OrchestrationConflictError(
                    "delivery observation is outside trusted custody time"
                )
            outcome_code = _DELIVERY_JOB_OUTCOME[parsed_attempt.outcome]
            outcome = _build_job_outcome(
                claim_id=parsed_custody.claim_id,
                claim_sha256=parsed_custody.claim_sha256,
                job_id=parsed_custody.job_id,
                tenant_id=parsed_custody.tenant_id,
                worker_id=parsed_custody.worker_id,
                fence_token=1,
                outcome_code=outcome_code,
                result_ref=parsed_attempt.attempt_id,
                result_sha256=parsed_attempt.attempt_sha256,
                observed_at=trusted_at,
                retry_available_at=(
                    trusted_at
                    if outcome_code
                    is JobOutcomeCode.RETRYABLE_FAILURE_OBSERVATION
                    else None
                ),
            )
            connection.execute(
                "INSERT INTO delivery_attempts VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    parsed_attempt.attempt_id,
                    parsed_attempt.attempt_sha256,
                    parsed_attempt.tenant_id,
                    parsed_attempt.message_id,
                    parsed_attempt.job_id,
                    parsed_attempt.claim_id,
                    parsed_attempt.attempt_number,
                    parsed_attempt.observed_at,
                    canonical_json(parsed_attempt.to_dict()),
                ),
            )
            connection.execute(
                "INSERT INTO job_outcomes VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    outcome.claim_id,
                    outcome.job_id,
                    outcome.tenant_id,
                    outcome.worker_id,
                    outcome.fence_token,
                    outcome.outcome_code.value,
                    outcome.observed_at,
                    canonical_json(outcome.to_dict()),
                ),
            )
            state = (
                JobState.WORKER_REPORTED
                if outcome_code is JobOutcomeCode.HANDLED_OBSERVATION
                else JobState.DEAD_LETTERED
            )
            available_at = (
                outcome.retry_available_at
                if outcome.retry_available_at is not None
                else view.job.available_at
            )
            changed = connection.execute(
                "UPDATE job_heads SET state=?,revision=revision+1,"
                "current_outcome_id=?,current_outcome_sha256=?,available_at=? "
                "WHERE job_id=? AND revision=? AND current_claim_id=? "
                "AND fence_token=1",
                (
                    state.value,
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    available_at,
                    parsed_custody.job_id,
                    view.revision,
                    parsed_custody.claim_id,
                ),
            ).rowcount
            if changed != 1:
                raise OrchestrationConflictError(
                    "outbox delivery settlement lost its compare-and-swap race"
                )
            self._append_event(
                connection,
                parsed_attempt.tenant_id,
                "message",
                parsed_attempt.message_id,
                "message.delivery_observed",
                parsed_attempt.attempt_id,
                parsed_attempt.attempt_sha256,
                parsed_attempt.observed_at,
            )
            self._append_event(
                connection,
                outcome.tenant_id,
                "job",
                outcome.job_id,
                "job.worker_observation",
                outcome.outcome_id,
                outcome.outcome_sha256,
                trusted_at,
            )
            return MutationResult(parsed_attempt, False), MutationResult(
                outcome, False
            )

    def record_action_execution_terminal_observation(
        self,
        attempt: ActionExecutionAttempt,
        terminal: Any,
    ) -> tuple[
        MutationResult[ActionExecutionTerminalObservation],
        MutationResult[JobOutcome],
    ]:
        """Atomically observe a typed Phase196 terminal and mark only journal handling."""

        parsed_attempt = ActionExecutionAttempt.from_dict(attempt.to_dict())
        try:
            from sunderkey.authenticated_action_executor import (
                parse_action_execution_terminal,
            )

            terminal_document = terminal.to_dict()
            parsed_terminal = parse_action_execution_terminal(terminal_document)
        except (AttributeError, TypeError, ValueError) as exc:
            raise OrchestrationValidationError(
                "Phase196 terminal observation is invalid"
            ) from exc
        terminal_document = parsed_terminal.to_dict()
        with self._write() as connection:
            trusted_at = self._trusted_now()
            stored_row = connection.execute(
                "SELECT attempt_json FROM action_execution_attempts WHERE attempt_id=?",
                (parsed_attempt.attempt_id,),
            ).fetchone()
            if stored_row is None:
                raise OrchestrationConflictError(
                    "action execution attempt is not durable"
                )
            stored_attempt = self._parse(
                stored_row["attempt_json"],
                ActionExecutionAttempt.from_dict,
                "action execution attempt",
            )
            if stored_attempt != parsed_attempt:
                raise OrchestrationConflictError(
                    "action execution attempt identity was substituted"
                )
            existing_row = connection.execute(
                "SELECT observation_json FROM action_execution_terminal_observations "
                "WHERE attempt_id=?",
                (parsed_attempt.attempt_id,),
            ).fetchone()
            if existing_row is not None:
                observation = self._parse(
                    existing_row["observation_json"],
                    ActionExecutionTerminalObservation.from_dict,
                    "action execution terminal observation",
                )
                if (
                    observation.phase196_terminal_id
                    != terminal_document["action_execution_terminal_id"]
                    or observation.phase196_terminal_sha256
                    != terminal_document["action_execution_terminal_sha256"]
                ):
                    raise OrchestrationConflictError(
                        "action execution attempt has a different terminal observation"
                    )
                outcome_row = connection.execute(
                    "SELECT outcome_json FROM job_outcomes WHERE job_id=? AND fence_token=1",
                    (parsed_attempt.job_id,),
                ).fetchone()
                if outcome_row is None:
                    raise OrchestrationIntegrityError(
                        "terminal observation journal outcome is missing"
                    )
                outcome = self._parse(
                    outcome_row["outcome_json"], JobOutcome.from_dict, "job outcome"
                )
                if (
                    outcome.result_ref != observation.observation_id
                    or outcome.result_sha256 != observation.observation_sha256
                    or outcome.outcome_code is not JobOutcomeCode.HANDLED_OBSERVATION
                ):
                    raise OrchestrationIntegrityError(
                        "terminal observation journal outcome is invalid"
                    )
                return MutationResult(observation, True), MutationResult(outcome, True)

            view = self._require_job_view(
                connection, parsed_attempt.tenant_id, parsed_attempt.job_id
            )
            if (
                view.job.job_kind is not JobKind.ACTION_EXECUTION_HANDOFF
                or view.state is not JobState.LEASED
                or view.current_claim is None
                or view.current_claim.claim_id != parsed_attempt.claim_id
                or view.current_claim.claim_sha256 != parsed_attempt.claim_sha256
                or view.current_claim.worker_id != parsed_attempt.worker_id
            ):
                raise OrchestrationConflictError(
                    "action execution attempt does not own the current handoff"
                )
            if _instant(trusted_at) >= _instant(parsed_attempt.expires_at):
                raise OrchestrationConflictError(
                    "expired action execution attempt requires authenticated reconciliation"
                )
            if (
                terminal_document["request_id"]
                != parsed_attempt.action_execution_request_id
                or terminal_document["request_sha256"]
                != parsed_attempt.action_execution_request_sha256
                or _instant(terminal_document["settled_at"])
                < _instant(parsed_attempt.trusted_at)
                or _instant(terminal_document["settled_at"]) > _instant(trusted_at)
            ):
                raise OrchestrationConflictError(
                    "Phase196 terminal does not bind the claimed request and trusted time"
                )
            observation = _build_action_execution_terminal_observation(
                attempt_id=parsed_attempt.attempt_id,
                attempt_sha256=parsed_attempt.attempt_sha256,
                job_id=parsed_attempt.job_id,
                job_sha256=parsed_attempt.job_sha256,
                message_id=parsed_attempt.message_id,
                message_sha256=parsed_attempt.message_sha256,
                intent_id=parsed_attempt.intent_id,
                intent_sha256=parsed_attempt.intent_sha256,
                claim_id=parsed_attempt.claim_id,
                claim_sha256=parsed_attempt.claim_sha256,
                tenant_id=parsed_attempt.tenant_id,
                action_execution_request_id=parsed_attempt.action_execution_request_id,
                action_execution_request_sha256=(
                    parsed_attempt.action_execution_request_sha256
                ),
                phase196_claim_id=terminal_document["claim_id"],
                phase196_claim_sha256=terminal_document["claim_sha256"],
                phase196_terminal_id=terminal_document[
                    "action_execution_terminal_id"
                ],
                phase196_terminal_sha256=terminal_document[
                    "action_execution_terminal_sha256"
                ],
                terminal_status=terminal_document["terminal_status"],
                action_outcome=terminal_document["action_outcome"],
                evidence_status=terminal_document["evidence_status"],
                cleanup_status=terminal_document["cleanup_status"],
                restoration_status=terminal_document["restoration_status"],
                result_sha256=terminal_document["result_sha256"],
                settled_at=terminal_document["settled_at"],
                adapter_call_count=terminal_document["adapter_call_count"],
                adapter_call_count_status=terminal_document[
                    "adapter_call_count_status"
                ],
                automatic_retry_count=terminal_document["automatic_retry_count"],
                observed_at=trusted_at,
                journal_effect="terminal_observed_not_action_success",
            )
            outcome = _build_job_outcome(
                claim_id=parsed_attempt.claim_id,
                claim_sha256=parsed_attempt.claim_sha256,
                job_id=parsed_attempt.job_id,
                tenant_id=parsed_attempt.tenant_id,
                worker_id=parsed_attempt.worker_id,
                fence_token=1,
                outcome_code=JobOutcomeCode.HANDLED_OBSERVATION,
                result_ref=observation.observation_id,
                result_sha256=observation.observation_sha256,
                observed_at=trusted_at,
                retry_available_at=None,
            )
            connection.execute(
                "INSERT INTO action_execution_terminal_observations "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    observation.observation_id,
                    observation.observation_sha256,
                    observation.tenant_id,
                    observation.attempt_id,
                    observation.job_id,
                    observation.message_id,
                    observation.intent_id,
                    observation.claim_id,
                    observation.phase196_terminal_id,
                    observation.phase196_terminal_sha256,
                    observation.terminal_status,
                    observation.action_outcome,
                    observation.settled_at,
                    observation.observed_at,
                    canonical_json(observation.to_dict()),
                ),
            )
            connection.execute(
                "INSERT INTO job_outcomes VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    outcome.claim_id,
                    outcome.job_id,
                    outcome.tenant_id,
                    outcome.worker_id,
                    outcome.fence_token,
                    outcome.outcome_code.value,
                    outcome.observed_at,
                    canonical_json(outcome.to_dict()),
                ),
            )
            changed = connection.execute(
                "UPDATE job_heads SET state='worker_reported',revision=revision+1,"
                "current_outcome_id=?,current_outcome_sha256=? WHERE job_id=? "
                "AND revision=? AND current_claim_id=? AND fence_token=1",
                (
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    parsed_attempt.job_id,
                    view.revision,
                    parsed_attempt.claim_id,
                ),
            ).rowcount
            if changed != 1:
                raise OrchestrationConflictError(
                    "terminal observation lost its compare-and-swap race"
                )
            self._append_event(
                connection,
                parsed_attempt.tenant_id,
                "job",
                parsed_attempt.job_id,
                "action_execution.terminal_observed",
                observation.observation_id,
                observation.observation_sha256,
                trusted_at,
            )
            self._append_event(
                connection,
                parsed_attempt.tenant_id,
                "job",
                parsed_attempt.job_id,
                "job.worker_observation",
                outcome.outcome_id,
                outcome.outcome_sha256,
                trusted_at,
            )
            return MutationResult(observation, False), MutationResult(outcome, False)

    def reconcile_expired_action_execution_attempt(
        self,
        attempt: ActionExecutionAttempt,
        *,
        reconciler_subject_id: str,
        reconciler_assertion_id: str,
        reconciler_assertion_sha256: str,
        reconciler_trust_policy_id: str,
        reconciler_trust_policy_sha256: str,
        reconciler_scope_id: str,
        reconciler_scope_sha256: str,
        reconciler_session_id: str,
        reconciler_session_sha256: str,
        reconciler_capability_id: str,
        reconciler_capability_sha256: str,
        reconciliation_lineage_sha256: str,
        authority_issued_at: str,
        authority_expires_at: str,
    ) -> tuple[
        MutationResult[ActionExecutionReconciliation],
        MutationResult[ActionExecutionTerminalObservation] | None,
        MutationResult[JobOutcome],
    ]:
        """Resolve an expired handoff from live, read-only Phase196 custody."""

        parsed_attempt = ActionExecutionAttempt.from_dict(attempt.to_dict())
        for label, value in (
            ("reconciler_subject_id", reconciler_subject_id),
            ("reconciler_assertion_id", reconciler_assertion_id),
            ("reconciler_trust_policy_id", reconciler_trust_policy_id),
            ("reconciler_scope_id", reconciler_scope_id),
            ("reconciler_session_id", reconciler_session_id),
            ("reconciler_capability_id", reconciler_capability_id),
        ):
            _identifier(value, label)
        for label, value in (
            ("reconciler_assertion_sha256", reconciler_assertion_sha256),
            ("reconciler_trust_policy_sha256", reconciler_trust_policy_sha256),
            ("reconciler_scope_sha256", reconciler_scope_sha256),
            ("reconciler_session_sha256", reconciler_session_sha256),
            ("reconciler_capability_sha256", reconciler_capability_sha256),
            ("reconciliation_lineage_sha256", reconciliation_lineage_sha256),
        ):
            _digest(value, label)
        _timestamp(authority_issued_at, "authority_issued_at")
        _timestamp(authority_expires_at, "authority_expires_at")
        expected_lineage = action_execution_reconciliation_lineage_sha256(
            parsed_attempt
        )
        if reconciliation_lineage_sha256 != expected_lineage:
            raise OrchestrationConflictError(
                "action reconciliation lineage does not bind the expired attempt"
            )
        if (
            reconciler_subject_id == parsed_attempt.worker_id
            or reconciler_session_id == parsed_attempt.worker_session_id
        ):
            raise OrchestrationConflictError(
                "action reconciler must be independent from the execution worker"
            )
        resolver = self._phase196_terminal_resolver
        if resolver is None:
            raise OrchestrationValidationError(
                "expired action reconciliation requires a trusted Phase196 resolver"
            )
        with self._write() as connection:
            trusted_at = self._trusted_now()
            if not (
                _instant(parsed_attempt.expires_at)
                <= _instant(authority_issued_at)
                <= _instant(trusted_at)
                < _instant(authority_expires_at)
            ):
                raise OrchestrationConflictError(
                    "action reconciliation authority is stale or premature"
                )
            attempt_row = connection.execute(
                "SELECT attempt_json FROM action_execution_attempts WHERE attempt_id=?",
                (parsed_attempt.attempt_id,),
            ).fetchone()
            if attempt_row is None:
                raise OrchestrationConflictError(
                    "action execution attempt is not durable"
                )
            stored_attempt = self._parse(
                attempt_row["attempt_json"],
                ActionExecutionAttempt.from_dict,
                "action execution attempt",
            )
            if stored_attempt != parsed_attempt:
                raise OrchestrationConflictError(
                    "action execution attempt identity was substituted"
                )
            view = self._require_job_view(
                connection, parsed_attempt.tenant_id, parsed_attempt.job_id
            )
            if (
                view.job.job_kind is not JobKind.ACTION_EXECUTION_HANDOFF
                or view.state
                not in {
                    JobState.LEASED,
                    JobState.WORKER_REPORTED,
                    JobState.DEAD_LETTERED,
                }
                or view.current_claim is None
                or view.current_claim.claim_id != parsed_attempt.claim_id
                or view.current_claim.claim_sha256 != parsed_attempt.claim_sha256
                or _instant(trusted_at) < _instant(parsed_attempt.expires_at)
            ):
                raise OrchestrationConflictError(
                    "action execution attempt is not eligible for expired reconciliation"
                )
            try:
                resolved_terminal = resolver(
                    parsed_attempt.action_execution_request_id
                )
            except Exception as exc:
                raise OrchestrationIntegrityError(
                    "trusted Phase196 terminal resolution failed"
                ) from exc
            trusted_at = self._trusted_now()
            if not (
                _instant(parsed_attempt.expires_at)
                <= _instant(authority_issued_at)
                <= _instant(trusted_at)
                < _instant(authority_expires_at)
            ):
                raise OrchestrationConflictError(
                    "action reconciliation authority expired during terminal resolution"
                )
            terminal_document: Mapping[str, Any] | None = None
            if resolved_terminal is not None:
                try:
                    from sunderkey.authenticated_action_executor import (
                        parse_action_execution_terminal,
                    )

                    raw_terminal = (
                        resolved_terminal.to_dict()
                        if callable(getattr(resolved_terminal, "to_dict", None))
                        else resolved_terminal
                    )
                    terminal_document = parse_action_execution_terminal(
                        raw_terminal
                    ).to_dict()
                except Exception as exc:
                    raise OrchestrationIntegrityError(
                        "trusted Phase196 resolver returned an invalid terminal"
                    ) from exc
                if (
                    terminal_document["request_id"]
                    != parsed_attempt.action_execution_request_id
                    or terminal_document["request_sha256"]
                    != parsed_attempt.action_execution_request_sha256
                    or _instant(terminal_document["settled_at"])
                    < _instant(parsed_attempt.trusted_at)
                    or _instant(terminal_document["settled_at"])
                    > _instant(trusted_at)
                ):
                    raise OrchestrationConflictError(
                        "durable Phase196 terminal does not bind the expired attempt"
                    )

            existing_row = connection.execute(
                "SELECT reconciliation_json FROM action_execution_reconciliations "
                "WHERE attempt_id=?",
                (parsed_attempt.attempt_id,),
            ).fetchone()
            if existing_row is not None:
                reconciliation = self._parse(
                    existing_row["reconciliation_json"],
                    ActionExecutionReconciliation.from_dict,
                    "action execution reconciliation",
                )
                expected_terminal_id = (
                    None
                    if terminal_document is None
                    else terminal_document["action_execution_terminal_id"]
                )
                expected_terminal_sha256 = (
                    None
                    if terminal_document is None
                    else terminal_document["action_execution_terminal_sha256"]
                )
                stable_authority = {
                    "reconciler_subject_id": reconciler_subject_id,
                    "reconciler_assertion_id": reconciler_assertion_id,
                    "reconciler_assertion_sha256": reconciler_assertion_sha256,
                    "reconciler_trust_policy_id": reconciler_trust_policy_id,
                    "reconciler_trust_policy_sha256": reconciler_trust_policy_sha256,
                    "reconciler_scope_id": reconciler_scope_id,
                    "reconciler_scope_sha256": reconciler_scope_sha256,
                    "reconciler_session_id": reconciler_session_id,
                    "reconciler_session_sha256": reconciler_session_sha256,
                    "reconciler_capability_id": reconciler_capability_id,
                    "reconciler_capability_sha256": reconciler_capability_sha256,
                    "reconciliation_lineage_sha256": reconciliation_lineage_sha256,
                    "authority_issued_at": authority_issued_at,
                    "authority_expires_at": authority_expires_at,
                }
                if (
                    any(
                        getattr(reconciliation, field) != value
                        for field, value in stable_authority.items()
                    )
                    or reconciliation.phase196_terminal_id != expected_terminal_id
                    or reconciliation.phase196_terminal_sha256
                    != expected_terminal_sha256
                ):
                    raise OrchestrationConflictError(
                        "action reconciliation replay changed authority or currentness"
                    )
                outcome_row = connection.execute(
                    "SELECT outcome_json FROM job_outcomes WHERE job_id=? "
                    "AND fence_token=1",
                    (parsed_attempt.job_id,),
                ).fetchone()
                if outcome_row is None:
                    raise OrchestrationIntegrityError(
                        "action reconciliation outcome is missing"
                    )
                outcome = self._parse(
                    outcome_row["outcome_json"], JobOutcome.from_dict, "job outcome"
                )
                observation_result: MutationResult[
                    ActionExecutionTerminalObservation
                ] | None = None
                if reconciliation.resolution_status == "terminal_observed":
                    observation_row = connection.execute(
                        "SELECT observation_json FROM "
                        "action_execution_terminal_observations WHERE attempt_id=?",
                        (parsed_attempt.attempt_id,),
                    ).fetchone()
                    if observation_row is None:
                        raise OrchestrationIntegrityError(
                            "reconciled terminal observation is missing"
                        )
                    observation_result = MutationResult(
                        self._parse(
                            observation_row["observation_json"],
                            ActionExecutionTerminalObservation.from_dict,
                            "action execution terminal observation",
                        ),
                        True,
                    )
                return (
                    MutationResult(reconciliation, True),
                    observation_result,
                    MutationResult(outcome, True),
                )

            existing_observation = connection.execute(
                "SELECT observation_id FROM action_execution_terminal_observations "
                "WHERE attempt_id=?",
                (parsed_attempt.attempt_id,),
            ).fetchone()
            existing_outcome = connection.execute(
                "SELECT outcome_id FROM job_outcomes WHERE job_id=? AND fence_token=1",
                (parsed_attempt.job_id,),
            ).fetchone()
            if existing_observation is not None or existing_outcome is not None:
                raise OrchestrationConflictError(
                    "settled action execution attempt cannot enter expired reconciliation"
                )

            terminal_id = (
                None
                if terminal_document is None
                else terminal_document["action_execution_terminal_id"]
            )
            terminal_sha256 = (
                None
                if terminal_document is None
                else terminal_document["action_execution_terminal_sha256"]
            )
            resolution_status = (
                "indeterminate_quarantined"
                if terminal_document is None
                else "terminal_observed"
            )
            reconciliation = _build_action_execution_reconciliation(
                attempt_id=parsed_attempt.attempt_id,
                attempt_sha256=parsed_attempt.attempt_sha256,
                job_id=parsed_attempt.job_id,
                job_sha256=parsed_attempt.job_sha256,
                message_id=parsed_attempt.message_id,
                message_sha256=parsed_attempt.message_sha256,
                intent_id=parsed_attempt.intent_id,
                intent_sha256=parsed_attempt.intent_sha256,
                claim_id=parsed_attempt.claim_id,
                claim_sha256=parsed_attempt.claim_sha256,
                tenant_id=parsed_attempt.tenant_id,
                reconciler_subject_id=reconciler_subject_id,
                reconciler_assertion_id=reconciler_assertion_id,
                reconciler_assertion_sha256=reconciler_assertion_sha256,
                reconciler_trust_policy_id=reconciler_trust_policy_id,
                reconciler_trust_policy_sha256=reconciler_trust_policy_sha256,
                reconciler_scope_id=reconciler_scope_id,
                reconciler_scope_sha256=reconciler_scope_sha256,
                reconciler_session_id=reconciler_session_id,
                reconciler_session_sha256=reconciler_session_sha256,
                reconciler_capability_id=reconciler_capability_id,
                reconciler_capability_sha256=reconciler_capability_sha256,
                reconciliation_lineage_sha256=reconciliation_lineage_sha256,
                authority_issued_at=authority_issued_at,
                authority_expires_at=authority_expires_at,
                phase196_terminal_id=terminal_id,
                phase196_terminal_sha256=terminal_sha256,
                resolution_status=resolution_status,
                resolved_at=trusted_at,
            )
            observation: ActionExecutionTerminalObservation | None = None
            if terminal_document is not None:
                observation = _build_action_execution_terminal_observation(
                    attempt_id=parsed_attempt.attempt_id,
                    attempt_sha256=parsed_attempt.attempt_sha256,
                    job_id=parsed_attempt.job_id,
                    job_sha256=parsed_attempt.job_sha256,
                    message_id=parsed_attempt.message_id,
                    message_sha256=parsed_attempt.message_sha256,
                    intent_id=parsed_attempt.intent_id,
                    intent_sha256=parsed_attempt.intent_sha256,
                    claim_id=parsed_attempt.claim_id,
                    claim_sha256=parsed_attempt.claim_sha256,
                    tenant_id=parsed_attempt.tenant_id,
                    action_execution_request_id=(
                        parsed_attempt.action_execution_request_id
                    ),
                    action_execution_request_sha256=(
                        parsed_attempt.action_execution_request_sha256
                    ),
                    phase196_claim_id=terminal_document["claim_id"],
                    phase196_claim_sha256=terminal_document["claim_sha256"],
                    phase196_terminal_id=terminal_id,
                    phase196_terminal_sha256=terminal_sha256,
                    terminal_status=terminal_document["terminal_status"],
                    action_outcome=terminal_document["action_outcome"],
                    evidence_status=terminal_document["evidence_status"],
                    cleanup_status=terminal_document["cleanup_status"],
                    restoration_status=terminal_document["restoration_status"],
                    result_sha256=terminal_document["result_sha256"],
                    settled_at=terminal_document["settled_at"],
                    adapter_call_count=terminal_document["adapter_call_count"],
                    adapter_call_count_status=terminal_document[
                        "adapter_call_count_status"
                    ],
                    automatic_retry_count=terminal_document[
                        "automatic_retry_count"
                    ],
                    observed_at=trusted_at,
                    journal_effect="terminal_observed_not_action_success",
                )
                outcome_code = JobOutcomeCode.HANDLED_OBSERVATION
                result_ref = observation.observation_id
                result_sha256 = observation.observation_sha256
                state = JobState.WORKER_REPORTED
            else:
                outcome_code = JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION
                result_ref = reconciliation.reconciliation_id
                result_sha256 = reconciliation.reconciliation_sha256
                state = JobState.DEAD_LETTERED
            outcome = _build_job_outcome(
                claim_id=parsed_attempt.claim_id,
                claim_sha256=parsed_attempt.claim_sha256,
                job_id=parsed_attempt.job_id,
                tenant_id=parsed_attempt.tenant_id,
                worker_id=parsed_attempt.worker_id,
                fence_token=1,
                outcome_code=outcome_code,
                result_ref=result_ref,
                result_sha256=result_sha256,
                observed_at=trusted_at,
                retry_available_at=None,
            )
            connection.execute(
                "INSERT INTO action_execution_reconciliations "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    reconciliation.reconciliation_id,
                    reconciliation.reconciliation_sha256,
                    reconciliation.tenant_id,
                    reconciliation.attempt_id,
                    reconciliation.job_id,
                    reconciliation.message_id,
                    reconciliation.intent_id,
                    reconciliation.claim_id,
                    reconciliation.reconciler_subject_id,
                    reconciliation.reconciler_session_id,
                    reconciliation.reconciler_session_sha256,
                    reconciliation.reconciliation_lineage_sha256,
                    reconciliation.resolution_status,
                    reconciliation.phase196_terminal_id,
                    reconciliation.phase196_terminal_sha256,
                    reconciliation.authority_issued_at,
                    reconciliation.authority_expires_at,
                    reconciliation.resolved_at,
                    canonical_json(reconciliation.to_dict()),
                ),
            )
            if observation is not None:
                connection.execute(
                    "INSERT INTO action_execution_terminal_observations "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        observation.observation_id,
                        observation.observation_sha256,
                        observation.tenant_id,
                        observation.attempt_id,
                        observation.job_id,
                        observation.message_id,
                        observation.intent_id,
                        observation.claim_id,
                        observation.phase196_terminal_id,
                        observation.phase196_terminal_sha256,
                        observation.terminal_status,
                        observation.action_outcome,
                        observation.settled_at,
                        observation.observed_at,
                        canonical_json(observation.to_dict()),
                    ),
                )
            connection.execute(
                "INSERT INTO job_outcomes VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    outcome.claim_id,
                    outcome.job_id,
                    outcome.tenant_id,
                    outcome.worker_id,
                    outcome.fence_token,
                    outcome.outcome_code.value,
                    outcome.observed_at,
                    canonical_json(outcome.to_dict()),
                ),
            )
            changed = connection.execute(
                "UPDATE job_heads SET state=?,revision=revision+1,"
                "current_outcome_id=?,current_outcome_sha256=? WHERE job_id=? "
                "AND revision=? AND state='leased' AND current_claim_id=? "
                "AND fence_token=1",
                (
                    state.value,
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    parsed_attempt.job_id,
                    view.revision,
                    parsed_attempt.claim_id,
                ),
            ).rowcount
            if changed != 1:
                raise OrchestrationConflictError(
                    "expired action reconciliation lost its compare-and-swap race"
                )
            self._append_event(
                connection,
                reconciliation.tenant_id,
                "job",
                reconciliation.job_id,
                "action_execution.reconciled",
                reconciliation.reconciliation_id,
                reconciliation.reconciliation_sha256,
                trusted_at,
            )
            observation_result: MutationResult[
                ActionExecutionTerminalObservation
            ] | None = None
            if observation is not None:
                self._append_event(
                    connection,
                    observation.tenant_id,
                    "job",
                    observation.job_id,
                    "action_execution.terminal_observed",
                    observation.observation_id,
                    observation.observation_sha256,
                    trusted_at,
                )
                observation_result = MutationResult(observation, False)
            self._append_event(
                connection,
                outcome.tenant_id,
                "job",
                outcome.job_id,
                (
                    "job.lease_exhausted"
                    if outcome.outcome_code
                    is JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION
                    else "job.worker_observation"
                ),
                outcome.outcome_id,
                outcome.outcome_sha256,
                trusted_at,
            )
            return (
                MutationResult(reconciliation, False),
                observation_result,
                MutationResult(outcome, False),
            )

    @staticmethod
    def _insert_claim(connection: sqlite3.Connection, claim: JobClaim) -> None:
        connection.execute(
            "INSERT INTO job_claims VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                claim.claim_id,
                claim.claim_sha256,
                claim.job_id,
                claim.tenant_id,
                claim.worker_id,
                claim.attempt_number,
                claim.fence_token,
                claim.lease_version,
                claim.claimed_at,
                claim.expires_at,
                claim.prior_claim_sha256,
                canonical_json(claim.to_dict()),
            ),
        )

    def renew_claim(self, claim: JobClaim, *, now: str) -> JobClaim:
        parsed = JobClaim.from_dict(claim.to_dict())
        _timestamp(now, "now")
        with self._write() as connection:
            trusted_at = self._trusted_now()
            view = self._require_job_view(connection, parsed.tenant_id, parsed.job_id)
            if view.job.job_kind in _RESERVED_EXTERNAL_EFFECT_JOBS:
                raise OrchestrationValidationError(
                    "reserved external-effect claims cannot be renewed"
                )
            if view.state is not JobState.LEASED or view.current_claim != parsed:
                raise OrchestrationConflictError("claim is no longer current")
            if _instant(trusted_at) >= _instant(parsed.expires_at):
                raise OrchestrationConflictError("expired claim cannot be renewed")
            if _instant(trusted_at) <= _instant(parsed.claimed_at):
                raise OrchestrationConflictError("claim renewal time did not advance")
            expires = format_timestamp(
                _instant(trusted_at) + timedelta(seconds=view.job.lease_seconds)
            )
            if _instant(expires) <= _instant(parsed.expires_at):
                raise OrchestrationConflictError("claim renewal did not extend the lease")
            renewed = _build_job_claim(
                job_id=parsed.job_id,
                job_sha256=parsed.job_sha256,
                tenant_id=parsed.tenant_id,
                worker_id=parsed.worker_id,
                attempt_number=parsed.attempt_number,
                fence_token=parsed.fence_token,
                lease_version=parsed.lease_version + 1,
                claimed_at=trusted_at,
                expires_at=expires,
                prior_claim_sha256=parsed.claim_sha256,
            )
            self._insert_claim(connection, renewed)
            changed = connection.execute(
                "UPDATE job_heads SET revision=revision+1,current_claim_id=?,"
                "current_claim_sha256=? "
                "WHERE job_id=? AND revision=? AND current_claim_id=? AND fence_token=?",
                (
                    renewed.claim_id,
                    renewed.claim_sha256,
                    parsed.job_id,
                    view.revision,
                    parsed.claim_id,
                    parsed.fence_token,
                ),
            ).rowcount
            if changed != 1:
                raise OrchestrationConflictError("claim renewal lost its compare-and-swap race")
            self._append_event(
                connection,
                parsed.tenant_id,
                "job",
                parsed.job_id,
                "job.claim_renewed",
                renewed.claim_id,
                renewed.claim_sha256,
                trusted_at,
            )
            return renewed

    def record_job_outcome(
        self,
        claim: JobClaim,
        *,
        outcome_code: JobOutcomeCode | str,
        result_ref: str,
        result_sha256: str,
        observed_at: str,
        retry_available_at: str | None = None,
    ) -> MutationResult[JobOutcome]:
        parsed = JobClaim.from_dict(claim.to_dict())
        code = _enum(outcome_code, JobOutcomeCode, "outcome_code")
        if code is JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION:
            raise OrchestrationValidationError(
                "lease exhaustion observations are created only by durable recovery"
            )
        outcome = _build_job_outcome(
            claim_id=parsed.claim_id,
            claim_sha256=parsed.claim_sha256,
            job_id=parsed.job_id,
            tenant_id=parsed.tenant_id,
            worker_id=parsed.worker_id,
            fence_token=parsed.fence_token,
            outcome_code=code,
            result_ref=result_ref,
            result_sha256=result_sha256,
            observed_at=observed_at,
            retry_available_at=retry_available_at,
        )
        with self._write() as connection:
            trusted_at = self._trusted_now()
            view = self._require_job_view(connection, parsed.tenant_id, parsed.job_id)
            if view.job.job_kind in _RESERVED_EXTERNAL_EFFECT_JOBS:
                raise OrchestrationValidationError(
                    "reserved external-effect outcomes require a typed processor path"
                )
            existing = connection.execute(
                "SELECT outcome_json FROM job_outcomes WHERE job_id=? AND fence_token=?",
                (parsed.job_id, parsed.fence_token),
            ).fetchone()
            if existing is not None:
                stored = self._parse(existing["outcome_json"], JobOutcome.from_dict, "job outcome")
                if stored != outcome:
                    raise OrchestrationConflictError("job fence has a different outcome")
                return MutationResult(stored, True)
            if view.state is not JobState.LEASED or view.current_claim != parsed:
                raise OrchestrationConflictError("stale claim cannot record an outcome")
            if view.job.job_kind is JobKind.OUTBOX_DELIVERY:
                delivery_row = connection.execute(
                    "SELECT attempt_json FROM delivery_attempts WHERE job_id=? AND claim_id=?",
                    (parsed.job_id, parsed.claim_id),
                ).fetchone()
                if delivery_row is None:
                    raise OrchestrationConflictError(
                        "delivery job outcome requires its delivery observation"
                    )
                delivery = self._parse(
                    delivery_row["attempt_json"], DeliveryAttempt.from_dict, "delivery attempt"
                )
                if _DELIVERY_JOB_OUTCOME[delivery.outcome] is not outcome.outcome_code:
                    raise OrchestrationConflictError(
                        "delivery and job outcome observations disagree"
                    )
            if _instant(observed_at) < _instant(parsed.claimed_at):
                raise OrchestrationConflictError("job outcome predates its claim")
            if _instant(observed_at) > _instant(trusted_at):
                raise OrchestrationConflictError("job outcome is future-dated")
            if _instant(trusted_at) >= _instant(parsed.expires_at):
                raise OrchestrationConflictError("expired claim cannot record an outcome")
            connection.execute(
                "INSERT INTO job_outcomes VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    outcome.claim_id,
                    outcome.job_id,
                    outcome.tenant_id,
                    outcome.worker_id,
                    outcome.fence_token,
                    outcome.outcome_code.value,
                    outcome.observed_at,
                    canonical_json(outcome.to_dict()),
                ),
            )
            if outcome.outcome_code is JobOutcomeCode.RETRYABLE_FAILURE_OBSERVATION:
                state = (
                    JobState.AVAILABLE
                    if view.attempt_number < view.job.maximum_attempts
                    else JobState.DEAD_LETTERED
                )
                available_at = outcome.retry_available_at or observed_at
            elif outcome.outcome_code is JobOutcomeCode.PERMANENT_FAILURE_OBSERVATION:
                state = JobState.DEAD_LETTERED
                available_at = view.job.available_at
            else:
                state = JobState.WORKER_REPORTED
                available_at = view.job.available_at
            changed = connection.execute(
                "UPDATE job_heads SET state=?,revision=revision+1,current_outcome_id=?,"
                "current_outcome_sha256=?,available_at=? WHERE job_id=? AND revision=? "
                "AND current_claim_id=? AND fence_token=?",
                (
                    state.value,
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    available_at,
                    parsed.job_id,
                    view.revision,
                    parsed.claim_id,
                    parsed.fence_token,
                ),
            ).rowcount
            if changed != 1:
                raise OrchestrationConflictError("job outcome lost its compare-and-swap race")
            self._append_event(
                connection,
                parsed.tenant_id,
                "job",
                parsed.job_id,
                "job.worker_observation",
                outcome.outcome_id,
                outcome.outcome_sha256,
                observed_at,
            )
            return MutationResult(outcome, False)

    def recover_expired_jobs(
        self,
        tenant_id: str,
        *,
        now: str,
        limit: int = 100,
    ) -> tuple[JobOutcome, ...]:
        """Dead-letter exhausted leases without asserting authoritative completion."""

        _identifier(tenant_id, "tenant_id")
        _timestamp(now, "now")
        _integer(limit, "limit", 1, MAX_PAGE_SIZE)
        recovered: list[JobOutcome] = []
        with self._write() as connection:
            trusted_at = self._trusted_now()
            rows = connection.execute(
                "SELECT jobs.job_json,job_heads.revision,job_heads.current_claim_id,"
                "job_heads.fence_token,job_claims.claim_json FROM jobs JOIN job_heads "
                "USING(job_id) JOIN job_claims ON job_claims.claim_id="
                "job_heads.current_claim_id WHERE jobs.tenant_id=? AND "
                "job_heads.state='leased' AND job_claims.expires_at<=? AND "
                "jobs.job_kind NOT IN(?,?) AND "
                "(job_heads.attempt_number >= jobs.maximum_attempts OR "
                "0) "
                "ORDER BY job_claims.expires_at,jobs.job_id LIMIT ?",
                (
                    tenant_id,
                    trusted_at,
                    JobKind.OUTBOX_DELIVERY.value,
                    JobKind.ACTION_EXECUTION_HANDOFF.value,
                    limit,
                ),
            ).fetchall()
            for row in rows:
                job = self._parse(row["job_json"], OrchestrationJob.from_dict, "job")
                claim = self._parse(row["claim_json"], JobClaim.from_dict, "job claim")
                reason = (
                    "non_retryable_job_lease_expired"
                    if job.job_kind in _INDETERMINATE_ON_EXPIRED_LEASE
                    else "attempt_limit_exhausted_after_lease_expiration"
                )
                result_body = {
                    "claim_id": claim.claim_id,
                    "claim_sha256": claim.claim_sha256,
                    "expired_at": claim.expires_at,
                    "job_id": job.job_id,
                    "job_sha256": job.job_sha256,
                    "reason": reason,
                }
                outcome = _build_job_outcome(
                    claim_id=claim.claim_id,
                    claim_sha256=claim.claim_sha256,
                    job_id=job.job_id,
                    tenant_id=job.tenant_id,
                    worker_id=claim.worker_id,
                    fence_token=claim.fence_token,
                    outcome_code=JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION,
                    result_ref=f"lease-expiration:{claim.claim_id}",
                    result_sha256=canonical_sha256(result_body),
                    observed_at=trusted_at,
                    retry_available_at=None,
                )
                connection.execute(
                    "INSERT INTO job_outcomes VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        outcome.outcome_id,
                        outcome.outcome_sha256,
                        outcome.claim_id,
                        outcome.job_id,
                        outcome.tenant_id,
                        outcome.worker_id,
                        outcome.fence_token,
                        outcome.outcome_code.value,
                        outcome.observed_at,
                        canonical_json(outcome.to_dict()),
                    ),
                )
                changed = connection.execute(
                    "UPDATE job_heads SET state='dead_lettered',revision=revision+1,"
                    "current_outcome_id=?,current_outcome_sha256=? WHERE job_id=? "
                    "AND state='leased' AND revision=? AND current_claim_id=? AND fence_token=?",
                    (
                        outcome.outcome_id,
                        outcome.outcome_sha256,
                        job.job_id,
                        row["revision"],
                        claim.claim_id,
                        claim.fence_token,
                    ),
                ).rowcount
                if changed != 1:
                    raise OrchestrationConflictError(
                        "expired job recovery lost its compare-and-swap race"
                    )
                self._append_event(
                    connection,
                    job.tenant_id,
                    "job",
                    job.job_id,
                    "job.lease_exhausted",
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    trusted_at,
                )
                recovered.append(outcome)
        return tuple(recovered)

    def record_message(
        self,
        message: OrchestrationMessage,
    ) -> MutationResult[OrchestrationMessage]:
        parsed = OrchestrationMessage.from_dict(message.to_dict())
        if parsed.topic is MessageTopic.ACTION_EXECUTION_HANDOFF:
            raise OrchestrationValidationError(
                "authenticated operator commands require the atomic operator action path"
            )
        with self._write() as connection:
            return self._record_message(connection, parsed)

    def _record_message(
        self,
        connection: sqlite3.Connection,
        message: OrchestrationMessage,
    ) -> MutationResult[OrchestrationMessage]:
        existing = connection.execute(
            "SELECT message_json FROM messages WHERE tenant_id=? AND direction=? "
            "AND idempotency_key_sha256=?",
            (message.tenant_id, message.direction.value, message.idempotency_key_sha256),
        ).fetchone()
        if existing is not None:
            stored = self._parse(
                existing["message_json"], OrchestrationMessage.from_dict, "message"
            )
            if stored != message:
                raise OrchestrationConflictError("message idempotency key was rebound")
            return MutationResult(stored, True)
        conflict = connection.execute(
            "SELECT message_json FROM messages WHERE tenant_id=? AND direction=? "
            "AND external_ref=?",
            (message.tenant_id, message.direction.value, message.external_ref),
        ).fetchone()
        if conflict is not None:
            stored = self._parse(
                conflict["message_json"], OrchestrationMessage.from_dict, "message"
            )
            if stored != message:
                raise OrchestrationConflictError("message external reference was rebound")
            return MutationResult(stored, True)
        connection.execute(
            "INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                message.message_id,
                message.message_sha256,
                message.tenant_id,
                message.direction.value,
                message.topic.value,
                message.external_ref,
                message.external_sha256,
                message.idempotency_key_sha256,
                message.recorded_at,
                canonical_json(message.to_dict()),
            ),
        )
        self._append_event(
            connection,
            message.tenant_id,
            "message",
            message.message_id,
            "message.recorded",
            message.message_id,
            message.message_sha256,
            message.recorded_at,
        )
        return MutationResult(message, False)

    def enqueue_action_execution_handoff(
        self,
        intent: ActionExecutionIntent,
    ) -> tuple[
        MutationResult[OrchestrationMessage],
        MutationResult[OrchestrationJob],
        MutationResult[ActionExecutionIntent],
    ]:
        """Atomically enqueue one typed, authority-neutral Phase196 handoff."""

        parsed_intent = ActionExecutionIntent.from_dict(intent.to_dict())
        with self._write() as connection:
            trusted_at = self._trusted_now()
            existing_row = connection.execute(
                "SELECT intent_json FROM action_execution_intents WHERE tenant_id=? "
                "AND idempotency_key_sha256=?",
                (parsed_intent.tenant_id, parsed_intent.idempotency_key_sha256),
            ).fetchone()
            if existing_row is not None:
                stored_intent = self._parse(
                    existing_row["intent_json"],
                    ActionExecutionIntent.from_dict,
                    "action execution intent",
                )
                if stored_intent != parsed_intent:
                    raise OrchestrationConflictError(
                        "action execution handoff idempotency key was rebound"
                    )
                message_row = connection.execute(
                    "SELECT message_json FROM messages WHERE tenant_id=? AND topic=? "
                    "AND external_ref=?",
                    (
                        stored_intent.tenant_id,
                        MessageTopic.ACTION_EXECUTION_HANDOFF.value,
                        stored_intent.action_execution_envelope_ref,
                    ),
                ).fetchone()
                if message_row is None:
                    raise OrchestrationIntegrityError(
                        "action execution handoff message is missing"
                    )
                message = self._parse(
                    message_row["message_json"], OrchestrationMessage.from_dict, "message"
                )
                job_row = connection.execute(
                    "SELECT job_json FROM jobs WHERE tenant_id=? AND job_kind=? "
                    "AND idempotency_key_sha256=?",
                    (
                        stored_intent.tenant_id,
                        JobKind.ACTION_EXECUTION_HANDOFF.value,
                        stored_intent.idempotency_key_sha256,
                    ),
                ).fetchone()
                if job_row is None:
                    raise OrchestrationIntegrityError(
                        "action execution handoff job is missing"
                    )
                job = self._parse(job_row["job_json"], OrchestrationJob.from_dict, "job")
                self._require_action_execution_handoff_binding(
                    message, job, stored_intent
                )
                return (
                    MutationResult(message, True),
                    MutationResult(job, True),
                    MutationResult(stored_intent, True),
                )

            effective_available_at = (
                parsed_intent.available_at
                if _instant(parsed_intent.available_at) > _instant(trusted_at)
                else trusted_at
            )
            remaining = int(
                (
                    _instant(parsed_intent.authorization_expires_at)
                    - _instant(effective_available_at)
                ).total_seconds()
            )
            if remaining < 5:
                raise OrchestrationConflictError(
                    "action execution authorization is not current for a safe lease"
                )
            lease_seconds = min(60, remaining)
            message = build_orchestration_message(
                tenant_id=parsed_intent.tenant_id,
                direction=MessageDirection.OUTBOX,
                topic=MessageTopic.ACTION_EXECUTION_HANDOFF,
                external_ref=parsed_intent.action_execution_envelope_ref,
                external_sha256=parsed_intent.action_execution_envelope_sha256,
                source_bindings=parsed_intent.source_bindings,
                correlation_ref=parsed_intent.action_execution_request_id,
                idempotency_key_sha256=parsed_intent.idempotency_key_sha256,
                recorded_at=trusted_at,
            )
            job = build_orchestration_job(
                tenant_id=parsed_intent.tenant_id,
                job_kind=JobKind.ACTION_EXECUTION_HANDOFF,
                subject_ref=message.message_id,
                input_ref=parsed_intent.intent_id,
                input_sha256=parsed_intent.intent_sha256,
                source_bindings=parsed_intent.source_bindings,
                idempotency_key_sha256=parsed_intent.idempotency_key_sha256,
                created_at=trusted_at,
                available_at=effective_available_at,
                maximum_attempts=1,
                lease_seconds=lease_seconds,
            )
            self._require_action_execution_handoff_binding(message, job, parsed_intent)
            connection.execute(
                "INSERT INTO action_execution_intents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    parsed_intent.intent_id,
                    parsed_intent.intent_sha256,
                    parsed_intent.tenant_id,
                    parsed_intent.mission_id,
                    parsed_intent.action_execution_request_id,
                    parsed_intent.action_execution_request_sha256,
                    parsed_intent.action_execution_envelope_ref,
                    parsed_intent.action_execution_envelope_sha256,
                    parsed_intent.idempotency_key_sha256,
                    parsed_intent.authorization_expires_at,
                    parsed_intent.source_bindings_sha256,
                    parsed_intent.requested_at,
                    parsed_intent.requested_by_subject_id,
                    parsed_intent.authentication_context_sha256,
                    canonical_json(parsed_intent.to_dict()),
                ),
            )
            self._append_event(
                connection,
                parsed_intent.tenant_id,
                "action_execution",
                parsed_intent.intent_id,
                "action_execution.intent_recorded",
                parsed_intent.intent_id,
                parsed_intent.intent_sha256,
                parsed_intent.requested_at,
            )
            message_result = self._record_message(connection, message)
            self._insert_job(connection, job)
            self._append_event(
                connection,
                job.tenant_id,
                "job",
                job.job_id,
                "job.submitted",
                job.job_id,
                job.job_sha256,
                job.created_at,
            )
            return (
                message_result,
                MutationResult(job, False),
                MutationResult(parsed_intent, False),
            )

    @staticmethod
    def _require_action_execution_handoff_binding(
        message: OrchestrationMessage,
        job: OrchestrationJob,
        intent: ActionExecutionIntent,
    ) -> None:
        expected_available_at = (
            intent.available_at
            if _instant(intent.available_at) > _instant(job.created_at)
            else job.created_at
        )
        remaining = int(
            (
                _instant(intent.authorization_expires_at)
                - _instant(expected_available_at)
            ).total_seconds()
        )
        expected_lease_seconds = min(60, remaining)
        if (
            message.direction is not MessageDirection.OUTBOX
            or message.topic is not MessageTopic.ACTION_EXECUTION_HANDOFF
            or job.job_kind is not JobKind.ACTION_EXECUTION_HANDOFF
            or message.tenant_id != intent.tenant_id
            or job.tenant_id != intent.tenant_id
            or message.external_ref != intent.action_execution_envelope_ref
            or message.external_sha256 != intent.action_execution_envelope_sha256
            or message.correlation_ref != intent.action_execution_request_id
            or message.idempotency_key_sha256 != intent.idempotency_key_sha256
            or job.idempotency_key_sha256 != intent.idempotency_key_sha256
            or job.subject_ref != message.message_id
            or job.input_ref != intent.intent_id
            or job.input_sha256 != intent.intent_sha256
            or message.source_bindings != intent.source_bindings
            or job.source_bindings != intent.source_bindings
            or job.maximum_attempts != 1
            or job.created_at != message.recorded_at
            or job.available_at != expected_available_at
            or remaining < 5
            or job.lease_seconds != expected_lease_seconds
        ):
            raise OrchestrationValidationError(
                "action execution handoff binding is invalid"
            )

    def append_saga_step(self, step: SagaStep) -> MutationResult[SagaStep]:
        parsed = SagaStep.from_dict(step.to_dict())
        with self._write() as connection:
            existing = connection.execute(
                "SELECT step_json FROM saga_steps WHERE tenant_id=? AND saga_id=? AND sequence=?",
                (parsed.tenant_id, parsed.saga_id, parsed.sequence),
            ).fetchone()
            if existing is not None:
                stored = self._parse(existing["step_json"], SagaStep.from_dict, "saga step")
                if stored != parsed:
                    raise OrchestrationConflictError("saga sequence was rebound")
                return MutationResult(stored, True)
            prior = connection.execute(
                "SELECT step_json FROM saga_steps WHERE tenant_id=? AND saga_id=? "
                "ORDER BY sequence DESC LIMIT 1",
                (parsed.tenant_id, parsed.saga_id),
            ).fetchone()
            prior_step = (
                None
                if prior is None
                else self._parse(prior["step_json"], SagaStep.from_dict, "saga step")
            )
            expected_prior = None if prior_step is None else prior_step.step_sha256
            expected_sequence = 1 if prior_step is None else prior_step.sequence + 1
            if parsed.sequence != expected_sequence or parsed.prior_step_sha256 != expected_prior:
                raise OrchestrationConflictError("saga step does not extend the durable head")
            if prior_step is not None:
                if (
                    parsed.saga_kind is not prior_step.saga_kind
                    or parsed.subject_ref != prior_step.subject_ref
                    or _instant(parsed.recorded_at) < _instant(prior_step.recorded_at)
                ):
                    raise OrchestrationConflictError("saga identity or chronology changed")
                self._require_source_not_regress(
                    prior_step.source_bindings, parsed.source_bindings, label="saga"
                )
            connection.execute(
                "INSERT INTO saga_steps VALUES(?,?,?,?,?,?,?)",
                (
                    parsed.step_id,
                    parsed.step_sha256,
                    parsed.tenant_id,
                    parsed.saga_id,
                    parsed.sequence,
                    parsed.recorded_at,
                    canonical_json(parsed.to_dict()),
                ),
            )
            self._append_event(
                connection,
                parsed.tenant_id,
                "saga",
                parsed.saga_id,
                "saga.step_recorded",
                parsed.step_id,
                parsed.step_sha256,
                parsed.recorded_at,
            )
            return MutationResult(parsed, False)

    def record_delivery_attempt(
        self,
        attempt: DeliveryAttempt,
    ) -> MutationResult[DeliveryAttempt]:
        parsed = DeliveryAttempt.from_dict(attempt.to_dict())
        raise OrchestrationValidationError(
            "outbox delivery requires an authenticated typed processor boundary"
        )
        # Retained unreachable reference logic documents the former unsafe generic path.
        with self._write() as connection:
            existing = connection.execute(
                "SELECT attempt_json FROM delivery_attempts WHERE message_id=? "
                "AND attempt_number=?",
                (parsed.message_id, parsed.attempt_number),
            ).fetchone()
            if existing is not None:
                stored = self._parse(
                    existing["attempt_json"], DeliveryAttempt.from_dict, "delivery attempt"
                )
                if stored != parsed:
                    raise OrchestrationConflictError("delivery attempt number was rebound")
                return MutationResult(stored, True)
            message_row = connection.execute(
                "SELECT message_json FROM messages WHERE message_id=?",
                (parsed.message_id,),
            ).fetchone()
            if message_row is None:
                raise OrchestrationConflictError("delivery message is unavailable")
            message = self._parse(
                message_row["message_json"], OrchestrationMessage.from_dict, "message"
            )
            if (
                message.message_id != parsed.message_id
                or message.direction is not MessageDirection.OUTBOX
                or message.tenant_id != parsed.tenant_id
                or message.message_sha256 != parsed.message_sha256
            ):
                raise OrchestrationConflictError("delivery message binding is invalid")
            view = self._require_job_view(connection, parsed.tenant_id, parsed.job_id)
            if (
                view.state is not JobState.LEASED
                or view.outcome is not None
                or view.current_claim is None
                or view.job.job_kind is not JobKind.OUTBOX_DELIVERY
                or view.job.subject_ref != message.message_id
                or view.job.input_ref != message.external_ref
                or view.job.input_sha256 != message.external_sha256
                or view.job.source_bindings != message.source_bindings
                or view.current_claim.claim_id != parsed.claim_id
                or view.current_claim.claim_sha256 != parsed.claim_sha256
                or view.current_claim.fence_token != parsed.fence_token
                or view.current_claim.attempt_number != parsed.attempt_number
            ):
                raise OrchestrationConflictError("delivery attempt uses a stale job fence")
            if _instant(parsed.observed_at) >= _instant(view.current_claim.expires_at):
                raise OrchestrationConflictError("expired delivery fence cannot record an attempt")
            if _instant(parsed.observed_at) < _instant(view.current_claim.claimed_at):
                raise OrchestrationConflictError("delivery attempt predates its claim")
            if _instant(parsed.observed_at) < _instant(message.recorded_at):
                raise OrchestrationConflictError("delivery attempt predates its message")
            connection.execute(
                "INSERT INTO delivery_attempts VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    parsed.attempt_id,
                    parsed.attempt_sha256,
                    parsed.tenant_id,
                    parsed.message_id,
                    parsed.job_id,
                    parsed.claim_id,
                    parsed.attempt_number,
                    parsed.observed_at,
                    canonical_json(parsed.to_dict()),
                ),
            )
            self._append_event(
                connection,
                parsed.tenant_id,
                "message",
                parsed.message_id,
                "message.delivery_observed",
                parsed.attempt_id,
                parsed.attempt_sha256,
                parsed.observed_at,
            )
            return MutationResult(parsed, False)

    def reconcile_projection(
        self,
        projection: ReadModelProjection,
    ) -> MutationResult[ReadModelProjection]:
        parsed = ReadModelProjection.from_dict(projection.to_dict())
        with self._write() as connection:
            existing = connection.execute(
                "SELECT projection_json FROM projections WHERE tenant_id=? AND projection_kind=? "
                "AND subject_ref=? AND projection_version=?",
                (
                    parsed.tenant_id,
                    parsed.projection_kind.value,
                    parsed.subject_ref,
                    parsed.projection_version,
                ),
            ).fetchone()
            if existing is not None:
                stored = self._parse(
                    existing["projection_json"], ReadModelProjection.from_dict, "projection"
                )
                if stored != parsed:
                    raise OrchestrationConflictError("projection version was rebound")
                return MutationResult(stored, True)
            head = connection.execute(
                "SELECT projections.projection_json,projection_heads.projection_id,"
                "projection_heads.projection_sha256,projection_heads.projection_version "
                "FROM projection_heads JOIN projections "
                "USING(projection_id) WHERE projection_heads.tenant_id=? AND "
                "projection_heads.projection_kind=? AND projection_heads.subject_ref=?",
                (parsed.tenant_id, parsed.projection_kind.value, parsed.subject_ref),
            ).fetchone()
            if head is None:
                if parsed.projection_version != 1:
                    raise OrchestrationConflictError("first projection version must be one")
            else:
                current = self._parse(
                    head["projection_json"], ReadModelProjection.from_dict, "projection"
                )
                if (
                    current.projection_id != head["projection_id"]
                    or current.projection_sha256 != head["projection_sha256"]
                    or current.projection_version != head["projection_version"]
                ):
                    raise OrchestrationIntegrityError("projection head binding is invalid")
                if parsed.projection_version != current.projection_version + 1:
                    raise OrchestrationConflictError("projection version is stale or skips")
                if _instant(parsed.projected_at) < _instant(current.projected_at):
                    raise OrchestrationConflictError("projection chronology regressed")
                self._require_source_advance(current.source_bindings, parsed.source_bindings)
            connection.execute(
                "INSERT INTO projections VALUES(?,?,?,?,?,?,?,?)",
                (
                    parsed.projection_id,
                    parsed.projection_sha256,
                    parsed.tenant_id,
                    parsed.projection_kind.value,
                    parsed.subject_ref,
                    parsed.projection_version,
                    parsed.projected_at,
                    canonical_json(parsed.to_dict()),
                ),
            )
            connection.execute(
                "INSERT INTO projection_heads VALUES(?,?,?,?,?,?) ON CONFLICT("
                "tenant_id,projection_kind,subject_ref) DO UPDATE SET "
                "projection_id=excluded.projection_id,"
                "projection_sha256=excluded.projection_sha256,"
                "projection_version=excluded.projection_version",
                (
                    parsed.tenant_id,
                    parsed.projection_kind.value,
                    parsed.subject_ref,
                    parsed.projection_id,
                    parsed.projection_sha256,
                    parsed.projection_version,
                ),
            )
            self._append_event(
                connection,
                parsed.tenant_id,
                "projection",
                f"{parsed.projection_kind.value}:{parsed.subject_ref}",
                "projection.reconciled",
                parsed.projection_id,
                parsed.projection_sha256,
                parsed.projected_at,
            )
            return MutationResult(parsed, False)

    @staticmethod
    def _require_source_advance(
        current: tuple[SourceHighWater, ...],
        proposed: tuple[SourceHighWater, ...],
    ) -> None:
        current_by_key = {(item.source_kind, item.source_id): item for item in current}
        proposed_by_key = {(item.source_kind, item.source_id): item for item in proposed}
        if set(current_by_key) != set(proposed_by_key):
            raise OrchestrationConflictError("projection source inventory changed")
        advanced = False
        for key, prior in current_by_key.items():
            next_item = proposed_by_key[key]
            if _instant(next_item.observed_at) < _instant(prior.observed_at):
                raise OrchestrationConflictError("projection source observation regressed")
            if next_item.source_revision < prior.source_revision:
                raise OrchestrationConflictError("projection source revision regressed")
            if next_item.source_revision == prior.source_revision:
                if next_item.source_head_sha256 != prior.source_head_sha256:
                    raise OrchestrationConflictError("projection source drift was detected")
            else:
                advanced = True
        if not advanced:
            raise OrchestrationConflictError("projection source high-water did not advance")

    @staticmethod
    def _require_source_not_regress(
        current: tuple[SourceHighWater, ...],
        proposed: tuple[SourceHighWater, ...],
        *,
        label: str,
    ) -> None:
        current_by_key = {(item.source_kind, item.source_id): item for item in current}
        proposed_by_key = {(item.source_kind, item.source_id): item for item in proposed}
        if set(current_by_key) != set(proposed_by_key):
            raise OrchestrationConflictError(f"{label} source inventory changed")
        for key, prior in current_by_key.items():
            next_item = proposed_by_key[key]
            if (
                next_item.source_revision < prior.source_revision
                or _instant(next_item.observed_at) < _instant(prior.observed_at)
                or (
                    next_item.source_revision == prior.source_revision
                    and next_item.source_head_sha256 != prior.source_head_sha256
                )
            ):
                raise OrchestrationConflictError(f"{label} source high-water regressed")

    def get_projection(
        self,
        tenant_id: str,
        projection_kind: ProjectionKind | str,
        subject_ref: str,
    ) -> ReadModelProjection | None:
        _identifier(tenant_id, "tenant_id")
        kind = _enum(projection_kind, ProjectionKind, "projection_kind")
        _identifier(subject_ref, "subject_ref")
        with self._read() as connection:
            row = connection.execute(
                "SELECT projections.projection_json,projection_heads.projection_id,"
                "projection_heads.projection_sha256,projection_heads.projection_version "
                "FROM projection_heads JOIN projections "
                "USING(projection_id) WHERE projection_heads.tenant_id=? AND "
                "projection_heads.projection_kind=? AND projection_heads.subject_ref=?",
                (tenant_id, kind.value, subject_ref),
            ).fetchone()
            if row is None:
                return None
            projection = self._parse(
                row["projection_json"], ReadModelProjection.from_dict, "projection"
            )
            if (
                projection.tenant_id != tenant_id
                or projection.projection_kind is not kind
                or projection.subject_ref != subject_ref
                or projection.projection_id != row["projection_id"]
                or projection.projection_sha256 != row["projection_sha256"]
                or projection.projection_version != row["projection_version"]
            ):
                raise OrchestrationIntegrityError("projection head binding is invalid")
            return projection

    def events_after(
        self,
        tenant_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        _identifier(tenant_id, "tenant_id")
        _integer(after_sequence, "after_sequence", 0, 9_223_372_036_854_775_807)
        _integer(limit, "limit", 1, MAX_PAGE_SIZE)
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM journal_events WHERE tenant_id=? "
                "AND event_sequence>? ORDER BY event_sequence LIMIT ?",
                (tenant_id, after_sequence, limit),
            ).fetchall()
        return self._event_rows(rows)

    def events_after_id(
        self,
        tenant_id: str,
        *,
        after_event_id: str | None = None,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        _identifier(tenant_id, "tenant_id")
        _integer(limit, "limit", 1, MAX_PAGE_SIZE)
        after_sequence = 0
        with self._read() as connection:
            if after_event_id is not None:
                _record_id(after_event_id, "JEV-", "after_event_id")
                cursor = connection.execute(
                    "SELECT event_sequence FROM journal_events WHERE tenant_id=? AND event_id=?",
                    (tenant_id, after_event_id),
                ).fetchone()
                if cursor is None:
                    raise OrchestrationValidationError("event cursor is not in the tenant chain")
                after_sequence = cursor["event_sequence"]
                if type(after_sequence) is not int or after_sequence < 1:
                    raise OrchestrationIntegrityError("event cursor storage is invalid")
            rows = connection.execute(
                "SELECT * FROM journal_events WHERE tenant_id=? "
                "AND event_sequence>? ORDER BY event_sequence LIMIT ?",
                (tenant_id, after_sequence, limit),
            ).fetchall()
        return self._event_rows(rows)

    def _event_rows(self, rows: Sequence[sqlite3.Row]) -> tuple[dict[str, Any], ...]:
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                raw = loads_json_without_duplicate_keys(row["event_json"])
                self._validate_event(raw)
                if canonical_json(raw) != row["event_json"]:
                    raise OrchestrationValidationError("journal event JSON is not canonical")
            except OrchestrationValidationError as exc:
                raise OrchestrationIntegrityError("stored journal event is invalid") from exc
            if type(row["event_sequence"]) is not int or row["event_sequence"] < 1:
                raise OrchestrationIntegrityError("event sequence storage type is invalid")
            self._require_columns(
                row,
                {
                    "event_id": raw["event_id"],
                    "event_sha256": raw["event_sha256"],
                    "tenant_id": raw["tenant_id"],
                    "aggregate_type": raw["aggregate_type"],
                    "aggregate_id": raw["aggregate_id"],
                    "event_type": raw["event_type"],
                    "record_id": raw["record_id"],
                    "record_sha256": raw["record_sha256"],
                    "prior_event_sha256": raw["prior_event_sha256"],
                    "occurred_at": raw["occurred_at"],
                },
                "journal event",
            )
            result.append({"event_sequence": row["event_sequence"], "event": raw})
        return tuple(result)

    def _append_event(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        record_id: str,
        record_sha256: str,
        occurred_at: str,
    ) -> None:
        head = connection.execute(
            "SELECT event_heads.event_sha256 AS head_sha256,"
            "journal_events.event_sha256 AS event_sha256,journal_events.tenant_id,"
            "journal_events.aggregate_type,journal_events.aggregate_id,"
            "journal_events.occurred_at FROM event_heads JOIN journal_events "
            "USING(event_sequence) WHERE event_heads.tenant_id=? AND "
            "event_heads.aggregate_type=? AND event_heads.aggregate_id=?",
            (tenant_id, aggregate_type, aggregate_id),
        ).fetchone()
        if head is not None and (
            head["head_sha256"] != head["event_sha256"]
            or head["tenant_id"] != tenant_id
            or head["aggregate_type"] != aggregate_type
            or head["aggregate_id"] != aggregate_id
        ):
            raise OrchestrationIntegrityError("journal event head binding is invalid")
        prior = None if head is None else head["head_sha256"]
        if head is not None and _instant(occurred_at) < _instant(head["occurred_at"]):
            raise OrchestrationConflictError("journal aggregate chronology regressed")
        body = {
            **_common("sunderkey.orchestration-journal-event.v1"),
            "aggregate_id": aggregate_id,
            "aggregate_type": aggregate_type,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "prior_event_sha256": prior,
            "record_id": record_id,
            "record_sha256": record_sha256,
            "tenant_id": tenant_id,
        }
        event_id, event_sha = _identity("JEV-", "sunderkey.orchestration-journal-event.v1", body)
        document = canonical_json({**body, "event_id": event_id, "event_sha256": event_sha})
        cursor = connection.execute(
            "INSERT INTO journal_events(event_id,event_sha256,tenant_id,aggregate_type,"
            "aggregate_id,"
            "event_type,record_id,record_sha256,prior_event_sha256,occurred_at,event_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                event_sha,
                tenant_id,
                aggregate_type,
                aggregate_id,
                event_type,
                record_id,
                record_sha256,
                prior,
                occurred_at,
                document,
            ),
        )
        sequence = cursor.lastrowid
        connection.execute(
            "INSERT INTO event_heads VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,aggregate_type,"
            "aggregate_id) "
            "DO UPDATE SET event_sequence=excluded.event_sequence,"
            "event_sha256=excluded.event_sha256",
            (tenant_id, aggregate_type, aggregate_id, sequence, event_sha),
        )

    @staticmethod
    def _validate_event(raw: Any) -> None:
        fields = {
            "aggregate_id",
            "aggregate_type",
            "effects",
            "event_id",
            "event_sha256",
            "event_type",
            "kind",
            "occurred_at",
            "prior_event_sha256",
            "record_id",
            "record_sha256",
            "schema_version",
            "tenant_id",
        }
        value = _exact(raw, fields, "journal event")
        _verify_common(value, "sunderkey.orchestration-journal-event.v1")
        for key in ("aggregate_id", "aggregate_type", "event_type", "tenant_id"):
            _identifier(value[key], key)
        contract = _EVENT_CONTRACTS.get(value["event_type"])
        if (
            contract is None
            or value["aggregate_type"] != contract[0]
            or not value["record_id"].startswith(contract[1])
        ):
            raise OrchestrationValidationError("journal event contract is invalid")
        _record_id(value["record_id"], contract[1], "record_id")
        _record_id(value["event_id"], "JEV-", "event_id")
        _digest(value["event_sha256"], "event_sha256")
        _digest(value["record_sha256"], "record_sha256")
        if value["prior_event_sha256"] is not None:
            _digest(value["prior_event_sha256"], "prior_event_sha256")
        _timestamp(value["occurred_at"], "occurred_at")
        body = {
            key: member for key, member in value.items() if key not in {"event_id", "event_sha256"}
        }
        event_id, digest = _identity("JEV-", "sunderkey.orchestration-journal-event.v1", body)
        if value["event_id"] != event_id or not hmac.compare_digest(value["event_sha256"], digest):
            raise OrchestrationValidationError("journal event identity is invalid")

    def verify(self) -> dict[str, Any]:
        with self._read() as connection:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise OrchestrationIntegrityError("SQLite quick_check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise OrchestrationIntegrityError("SQLite foreign-key check failed")
            if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
                raise OrchestrationIntegrityError("application_id is invalid")
            if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise OrchestrationIntegrityError("user_version is invalid")
            if _schema_manifest(connection) != EXPECTED_SCHEMA_MANIFEST_SHA256:
                raise OrchestrationIntegrityError("schema manifest is invalid")
            self._verify_migration_identity(connection)
            self._verify_records(connection)
            event_count = self._verify_events(connection)
            counts = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "jobs",
                    "job_claims",
                    "job_outcomes",
                    "messages",
                    "action_execution_intents",
                    "action_execution_attempts",
                    "action_execution_handoff_quarantines",
                    "action_execution_terminal_observations",
                    "action_execution_reconciliations",
                    "saga_steps",
                    "delivery_attempts",
                    "outbox_delivery_claim_custody",
                    "projections",
                )
            }
        return {
            "authority_effect": "none",
            "counts": counts,
            "event_count": event_count,
            "migration_sha256": MIGRATION_SHA256,
            "schema_manifest_sha256": EXPECTED_SCHEMA_MANIFEST_SHA256,
            "schema_version": SCHEMA_VERSION,
            "status": "valid",
        }

    def _verify_records(self, connection: sqlite3.Connection) -> None:
        jobs: dict[str, OrchestrationJob] = {}
        for row in connection.execute("SELECT * FROM jobs"):
            job = self._parse(row["job_json"], OrchestrationJob.from_dict, "job")
            self._require_columns(
                row,
                {
                    "job_id": job.job_id,
                    "job_sha256": job.job_sha256,
                    "tenant_id": job.tenant_id,
                    "job_kind": job.job_kind.value,
                    "idempotency_key_sha256": job.idempotency_key_sha256,
                    "created_at": job.created_at,
                    "available_at": job.available_at,
                    "maximum_attempts": job.maximum_attempts,
                    "lease_seconds": job.lease_seconds,
                },
                "job",
            )
            jobs[job.job_id] = job

        claims: dict[str, JobClaim] = {}
        claims_by_job: dict[str, list[JobClaim]] = {}
        for row in connection.execute(
            "SELECT * FROM job_claims ORDER BY job_id,fence_token,lease_version"
        ):
            claim = self._parse(row["claim_json"], JobClaim.from_dict, "job claim")
            self._require_columns(
                row,
                {
                    "claim_id": claim.claim_id,
                    "claim_sha256": claim.claim_sha256,
                    "job_id": claim.job_id,
                    "tenant_id": claim.tenant_id,
                    "worker_id": claim.worker_id,
                    "attempt_number": claim.attempt_number,
                    "fence_token": claim.fence_token,
                    "lease_version": claim.lease_version,
                    "claimed_at": claim.claimed_at,
                    "expires_at": claim.expires_at,
                    "prior_claim_sha256": claim.prior_claim_sha256,
                },
                "job claim",
            )
            job = jobs.get(claim.job_id)
            if job is None or claim.tenant_id != job.tenant_id:
                raise OrchestrationIntegrityError("job claim crosses its job boundary")
            claims[claim.claim_id] = claim
            claims_by_job.setdefault(claim.job_id, []).append(claim)

        outcomes: dict[str, JobOutcome] = {}
        outcomes_by_job: dict[str, list[JobOutcome]] = {}
        for row in connection.execute("SELECT * FROM job_outcomes ORDER BY job_id,fence_token"):
            outcome = self._parse(row["outcome_json"], JobOutcome.from_dict, "job outcome")
            self._require_columns(
                row,
                {
                    "outcome_id": outcome.outcome_id,
                    "outcome_sha256": outcome.outcome_sha256,
                    "claim_id": outcome.claim_id,
                    "job_id": outcome.job_id,
                    "tenant_id": outcome.tenant_id,
                    "worker_id": outcome.worker_id,
                    "fence_token": outcome.fence_token,
                    "outcome_code": outcome.outcome_code.value,
                    "observed_at": outcome.observed_at,
                },
                "job outcome",
            )
            claim = claims.get(outcome.claim_id)
            job = jobs.get(outcome.job_id)
            expired_recovery = outcome.outcome_code is JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION
            reconciled_action_terminal = (
                job is not None
                and job.job_kind is JobKind.ACTION_EXECUTION_HANDOFF
                and outcome.outcome_code is JobOutcomeCode.HANDLED_OBSERVATION
                and outcome.result_ref.startswith("AEO-")
            )
            if (
                claim is None
                or job is None
                or outcome.job_id != claim.job_id
                or outcome.tenant_id != claim.tenant_id
                or outcome.worker_id != claim.worker_id
                or outcome.fence_token != claim.fence_token
                or _instant(outcome.observed_at) < _instant(claim.claimed_at)
                or (expired_recovery and _instant(outcome.observed_at) < _instant(claim.expires_at))
                or (
                    not expired_recovery
                    and not reconciled_action_terminal
                    and _instant(outcome.observed_at) >= _instant(claim.expires_at)
                )
            ):
                raise OrchestrationIntegrityError("job outcome crosses its claim boundary")
            if expired_recovery:
                if job.job_kind is JobKind.OUTBOX_DELIVERY:
                    raise OrchestrationIntegrityError(
                        "outbox delivery cannot have a lease exhaustion outcome"
                    )
                if (
                    job.job_kind is JobKind.ACTION_EXECUTION_HANDOFF
                    and outcome.result_ref.startswith("AER-")
                ):
                    outcomes[outcome.outcome_id] = outcome
                    outcomes_by_job.setdefault(outcome.job_id, []).append(outcome)
                    continue
                expected_ref = f"lease-expiration:{claim.claim_id}"
                reason = (
                    "non_retryable_job_lease_expired"
                    if job.job_kind in _INDETERMINATE_ON_EXPIRED_LEASE
                    else "attempt_limit_exhausted_after_lease_expiration"
                )
                expected_result = canonical_sha256(
                    {
                        "claim_id": claim.claim_id,
                        "claim_sha256": claim.claim_sha256,
                        "expired_at": claim.expires_at,
                        "job_id": job.job_id,
                        "job_sha256": job.job_sha256,
                        "reason": reason,
                    }
                )
                if (
                    (
                        claim.attempt_number != job.maximum_attempts
                        and job.job_kind not in _INDETERMINATE_ON_EXPIRED_LEASE
                    )
                    or outcome.result_ref != expected_ref
                    or outcome.result_sha256 != expected_result
                ):
                    raise OrchestrationIntegrityError("lease exhaustion observation is invalid")
            outcomes[outcome.outcome_id] = outcome
            outcomes_by_job.setdefault(outcome.job_id, []).append(outcome)

        messages: dict[str, OrchestrationMessage] = {}
        for row in connection.execute("SELECT * FROM messages"):
            message = self._parse(row["message_json"], OrchestrationMessage.from_dict, "message")
            self._require_columns(
                row,
                {
                    "message_id": message.message_id,
                    "message_sha256": message.message_sha256,
                    "tenant_id": message.tenant_id,
                    "direction": message.direction.value,
                    "topic": message.topic.value,
                    "external_ref": message.external_ref,
                    "external_sha256": message.external_sha256,
                    "idempotency_key_sha256": message.idempotency_key_sha256,
                    "recorded_at": message.recorded_at,
                },
                "message",
            )
            messages[message.message_id] = message

        intents: dict[str, ActionExecutionIntent] = {}
        for row in connection.execute("SELECT * FROM action_execution_intents"):
            intent = self._parse(
                row["intent_json"],
                ActionExecutionIntent.from_dict,
                "action execution intent",
            )
            self._require_columns(
                row,
                {
                    "intent_id": intent.intent_id,
                    "intent_sha256": intent.intent_sha256,
                    "tenant_id": intent.tenant_id,
                    "mission_id": intent.mission_id,
                    "request_id": intent.action_execution_request_id,
                    "request_sha256": intent.action_execution_request_sha256,
                    "envelope_ref": intent.action_execution_envelope_ref,
                    "envelope_sha256": intent.action_execution_envelope_sha256,
                    "idempotency_key_sha256": intent.idempotency_key_sha256,
                    "authorization_expires_at": intent.authorization_expires_at,
                    "source_bindings_sha256": intent.source_bindings_sha256,
                    "requested_at": intent.requested_at,
                    "requested_by_subject_id": intent.requested_by_subject_id,
                    "authentication_context_sha256": (
                        intent.authentication_context_sha256
                    ),
                },
                "action execution intent",
            )
            intents[intent.intent_id] = intent

        external_effect_jobs: dict[str, OrchestrationJob] = {}
        handoff_intents: set[str] = set()
        for job in jobs.values():
            if job.job_kind not in {
                JobKind.OUTBOX_DELIVERY,
                JobKind.ACTION_EXECUTION_HANDOFF,
            }:
                continue
            message = messages.get(job.subject_ref)
            if message is None:
                raise OrchestrationIntegrityError("external-effect job message is missing")
            if job.job_kind is JobKind.ACTION_EXECUTION_HANDOFF:
                intent = intents.get(job.input_ref)
                if intent is None or job.input_sha256 != intent.intent_sha256:
                    raise OrchestrationIntegrityError(
                        "action execution intent binding is invalid"
                    )
                try:
                    self._require_action_execution_handoff_binding(message, job, intent)
                except OrchestrationValidationError as exc:
                    raise OrchestrationIntegrityError(
                        "action execution handoff binding is invalid"
                    ) from exc
                handoff_intents.add(intent.intent_id)
            elif (
                message.tenant_id != job.tenant_id
                or message.direction is not MessageDirection.OUTBOX
                or message.topic is MessageTopic.ACTION_EXECUTION_HANDOFF
                or job.input_ref != message.external_ref
                or job.input_sha256 != message.external_sha256
                or job.source_bindings != message.source_bindings
                or _instant(job.created_at) < _instant(message.recorded_at)
            ):
                raise OrchestrationIntegrityError("external-effect job binding is invalid")
            if message.message_id in external_effect_jobs:
                raise OrchestrationIntegrityError(
                    "external-effect message has multiple durable jobs"
                )
            external_effect_jobs[message.message_id] = job

        for message in messages.values():
            if message.topic is not MessageTopic.ACTION_EXECUTION_HANDOFF:
                continue
            job = external_effect_jobs.get(message.message_id)
            if (
                message.direction is not MessageDirection.OUTBOX
                or job is None
                or job.job_kind is not JobKind.ACTION_EXECUTION_HANDOFF
            ):
                raise OrchestrationIntegrityError(
                    "action execution message is outside its atomic handoff"
                )
        if handoff_intents != set(intents):
            raise OrchestrationIntegrityError(
                "action execution intent inventory is outside its atomic handoff"
            )

        quarantines: dict[str, ActionExecutionHandoffQuarantine] = {}
        for row in connection.execute(
            "SELECT * FROM action_execution_handoff_quarantines"
        ):
            quarantine = self._parse(
                row["quarantine_json"],
                ActionExecutionHandoffQuarantine.from_dict,
                "action execution handoff quarantine",
            )
            self._require_columns(
                row,
                {
                    "quarantine_id": quarantine.quarantine_id,
                    "quarantine_sha256": quarantine.quarantine_sha256,
                    "tenant_id": quarantine.tenant_id,
                    "job_id": quarantine.job_id,
                    "message_id": quarantine.message_id,
                    "intent_id": quarantine.intent_id,
                    "authorization_expires_at": (
                        quarantine.authorization_expires_at
                    ),
                    "trusted_at": quarantine.trusted_at,
                },
                "action execution handoff quarantine",
            )
            job = jobs.get(quarantine.job_id)
            message = messages.get(quarantine.message_id)
            intent = intents.get(quarantine.intent_id)
            if (
                job is None
                or message is None
                or intent is None
                or job.job_kind is not JobKind.ACTION_EXECUTION_HANDOFF
                or job.job_sha256 != quarantine.job_sha256
                or message.message_sha256 != quarantine.message_sha256
                or intent.intent_sha256 != quarantine.intent_sha256
                or quarantine.tenant_id != intent.tenant_id
                or quarantine.authorization_expires_at
                != intent.authorization_expires_at
                or _instant(quarantine.trusted_at)
                + timedelta(seconds=job.lease_seconds)
                <= _instant(intent.authorization_expires_at)
            ):
                raise OrchestrationIntegrityError(
                    "action execution handoff quarantine custody is invalid"
                )
            quarantines[quarantine.job_id] = quarantine

        action_attempts: dict[str, ActionExecutionAttempt] = {}
        for row in connection.execute("SELECT * FROM action_execution_attempts"):
            attempt = self._parse(
                row["attempt_json"],
                ActionExecutionAttempt.from_dict,
                "action execution attempt",
            )
            self._require_columns(
                row,
                {
                    "attempt_id": attempt.attempt_id,
                    "attempt_sha256": attempt.attempt_sha256,
                    "tenant_id": attempt.tenant_id,
                    "job_id": attempt.job_id,
                    "message_id": attempt.message_id,
                    "intent_id": attempt.intent_id,
                    "claim_id": attempt.claim_id,
                    "worker_id": attempt.worker_id,
                    "worker_assertion_id": attempt.worker_assertion_id,
                    "worker_assertion_sha256": attempt.worker_assertion_sha256,
                    "worker_session_id": attempt.worker_session_id,
                    "worker_session_sha256": attempt.worker_session_sha256,
                    "worker_lease_id": attempt.worker_lease_id,
                    "worker_lease_sha256": attempt.worker_lease_sha256,
                    "worker_capability_id": attempt.worker_capability_id,
                    "worker_capability_sha256": attempt.worker_capability_sha256,
                    "trusted_at": attempt.trusted_at,
                    "expires_at": attempt.expires_at,
                },
                "action execution attempt",
            )
            job = jobs.get(attempt.job_id)
            message = messages.get(attempt.message_id)
            intent = intents.get(attempt.intent_id)
            claim = claims.get(attempt.claim_id)
            expected_from_intent = {
                "tenant_id": "tenant_id",
                "mission_id": "mission_id",
                "action_execution_envelope_ref": "action_execution_envelope_ref",
                "action_execution_envelope_sha256": (
                    "action_execution_envelope_sha256"
                ),
                "command_sha256": "command_sha256",
                "action_execution_request_id": "action_execution_request_id",
                "action_execution_request_sha256": (
                    "action_execution_request_sha256"
                ),
                "receipt_id": "receipt_id",
                "receipt_sha256": "receipt_sha256",
                "action_execute_intent_sha256": "action_execute_intent_sha256",
                "assertion_id": "assertion_id",
                "assertion_sha256": "assertion_sha256",
                "authorization_sha256": "authorization_sha256",
                "authorization_expires_at": "authorization_expires_at",
                "source_bindings_sha256": "source_bindings_sha256",
                "source_bindings": "source_bindings",
            }
            if (
                job is None
                or message is None
                or intent is None
                or claim is None
                or job.job_kind is not JobKind.ACTION_EXECUTION_HANDOFF
                or job.job_sha256 != attempt.job_sha256
                or message.message_sha256 != attempt.message_sha256
                or intent.intent_sha256 != attempt.intent_sha256
                or claim.claim_sha256 != attempt.claim_sha256
                or claim.job_id != job.job_id
                or claim.worker_id != attempt.worker_id
                or claim.attempt_number != 1
                or claim.fence_token != 1
                or claim.lease_version != 1
                or claim.claimed_at != attempt.trusted_at
                or claim.expires_at != attempt.expires_at
                or attempt.attempt_number != 1
                or any(
                    getattr(attempt, attempt_field) != getattr(intent, intent_field)
                    for attempt_field, intent_field in expected_from_intent.items()
                )
            ):
                raise OrchestrationIntegrityError(
                    "action execution attempt custody is invalid"
                )
            action_attempts[attempt.claim_id] = attempt

        action_claims = {
            claim.claim_id
            for claim in claims.values()
            if jobs[claim.job_id].job_kind is JobKind.ACTION_EXECUTION_HANDOFF
        }
        if set(action_attempts) != action_claims:
            raise OrchestrationIntegrityError(
                "action execution claim and attempt inventory is invalid"
            )

        action_reconciliations: dict[str, ActionExecutionReconciliation] = {}
        for row in connection.execute("SELECT * FROM action_execution_reconciliations"):
            reconciliation = self._parse(
                row["reconciliation_json"],
                ActionExecutionReconciliation.from_dict,
                "action execution reconciliation",
            )
            self._require_columns(
                row,
                {
                    "reconciliation_id": reconciliation.reconciliation_id,
                    "reconciliation_sha256": reconciliation.reconciliation_sha256,
                    "tenant_id": reconciliation.tenant_id,
                    "attempt_id": reconciliation.attempt_id,
                    "job_id": reconciliation.job_id,
                    "message_id": reconciliation.message_id,
                    "intent_id": reconciliation.intent_id,
                    "claim_id": reconciliation.claim_id,
                    "reconciler_subject_id": reconciliation.reconciler_subject_id,
                    "reconciler_session_id": reconciliation.reconciler_session_id,
                    "reconciler_session_sha256": (
                        reconciliation.reconciler_session_sha256
                    ),
                    "reconciliation_lineage_sha256": (
                        reconciliation.reconciliation_lineage_sha256
                    ),
                    "resolution_status": reconciliation.resolution_status,
                    "phase196_terminal_id": reconciliation.phase196_terminal_id,
                    "phase196_terminal_sha256": (
                        reconciliation.phase196_terminal_sha256
                    ),
                    "authority_issued_at": reconciliation.authority_issued_at,
                    "authority_expires_at": reconciliation.authority_expires_at,
                    "resolved_at": reconciliation.resolved_at,
                },
                "action execution reconciliation",
            )
            attempt = action_attempts.get(reconciliation.claim_id)
            if (
                attempt is None
                or reconciliation.attempt_id != attempt.attempt_id
                or reconciliation.attempt_sha256 != attempt.attempt_sha256
                or reconciliation.job_id != attempt.job_id
                or reconciliation.job_sha256 != attempt.job_sha256
                or reconciliation.message_id != attempt.message_id
                or reconciliation.message_sha256 != attempt.message_sha256
                or reconciliation.intent_id != attempt.intent_id
                or reconciliation.intent_sha256 != attempt.intent_sha256
                or reconciliation.claim_id != attempt.claim_id
                or reconciliation.claim_sha256 != attempt.claim_sha256
                or reconciliation.tenant_id != attempt.tenant_id
                or reconciliation.reconciler_subject_id == attempt.worker_id
                or reconciliation.reconciler_session_id == attempt.worker_session_id
                or reconciliation.reconciliation_lineage_sha256
                != action_execution_reconciliation_lineage_sha256(attempt)
                or _instant(reconciliation.authority_issued_at)
                < _instant(attempt.expires_at)
                or not (
                    _instant(reconciliation.authority_issued_at)
                    <= _instant(reconciliation.resolved_at)
                    < _instant(reconciliation.authority_expires_at)
                )
            ):
                raise OrchestrationIntegrityError(
                    "action execution reconciliation custody is invalid"
                )
            action_reconciliations[reconciliation.claim_id] = reconciliation

        terminal_observations: dict[str, ActionExecutionTerminalObservation] = {}
        for row in connection.execute(
            "SELECT * FROM action_execution_terminal_observations"
        ):
            observation = self._parse(
                row["observation_json"],
                ActionExecutionTerminalObservation.from_dict,
                "action execution terminal observation",
            )
            self._require_columns(
                row,
                {
                    "observation_id": observation.observation_id,
                    "observation_sha256": observation.observation_sha256,
                    "tenant_id": observation.tenant_id,
                    "attempt_id": observation.attempt_id,
                    "job_id": observation.job_id,
                    "message_id": observation.message_id,
                    "intent_id": observation.intent_id,
                    "claim_id": observation.claim_id,
                    "phase196_terminal_id": observation.phase196_terminal_id,
                    "phase196_terminal_sha256": observation.phase196_terminal_sha256,
                    "terminal_status": observation.terminal_status,
                    "action_outcome": observation.action_outcome,
                    "settled_at": observation.settled_at,
                    "observed_at": observation.observed_at,
                },
                "action execution terminal observation",
            )
            attempt = action_attempts.get(observation.claim_id)
            reconciliation = action_reconciliations.get(observation.claim_id)
            reconciled_observation = (
                reconciliation is not None
                and reconciliation.resolution_status == "terminal_observed"
                and reconciliation.phase196_terminal_id
                == observation.phase196_terminal_id
                and reconciliation.phase196_terminal_sha256
                == observation.phase196_terminal_sha256
                and reconciliation.resolved_at == observation.observed_at
            )
            if (
                attempt is None
                or observation.attempt_id != attempt.attempt_id
                or observation.attempt_sha256 != attempt.attempt_sha256
                or observation.job_id != attempt.job_id
                or observation.job_sha256 != attempt.job_sha256
                or observation.message_id != attempt.message_id
                or observation.message_sha256 != attempt.message_sha256
                or observation.intent_id != attempt.intent_id
                or observation.intent_sha256 != attempt.intent_sha256
                or observation.claim_id != attempt.claim_id
                or observation.claim_sha256 != attempt.claim_sha256
                or observation.tenant_id != attempt.tenant_id
                or observation.action_execution_request_id
                != attempt.action_execution_request_id
                or observation.action_execution_request_sha256
                != attempt.action_execution_request_sha256
                or _instant(observation.settled_at) < _instant(attempt.trusted_at)
                or _instant(observation.observed_at) < _instant(observation.settled_at)
                or (
                    _instant(observation.observed_at) >= _instant(attempt.expires_at)
                    and not reconciled_observation
                )
                or (
                    _instant(observation.observed_at) < _instant(attempt.expires_at)
                    and reconciliation is not None
                )
            ):
                raise OrchestrationIntegrityError(
                    "action execution terminal observation custody is invalid"
                )
            terminal_observations[observation.claim_id] = observation

        for job_id, job_outcomes in outcomes_by_job.items():
            if jobs[job_id].job_kind is not JobKind.ACTION_EXECUTION_HANDOFF:
                continue
            if len(job_outcomes) > 1:
                raise OrchestrationIntegrityError(
                    "action execution handoff has multiple journal outcomes"
                )
            for outcome in job_outcomes:
                observation = terminal_observations.get(outcome.claim_id)
                reconciliation = action_reconciliations.get(outcome.claim_id)
                if reconciliation is not None and (
                    reconciliation.resolution_status == "indeterminate_quarantined"
                ):
                    valid = (
                        observation is None
                        and outcome.outcome_code
                        is JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION
                        and outcome.result_ref == reconciliation.reconciliation_id
                        and outcome.result_sha256
                        == reconciliation.reconciliation_sha256
                        and outcome.observed_at == reconciliation.resolved_at
                    )
                else:
                    valid = (
                        observation is not None
                        and outcome.outcome_code
                        is JobOutcomeCode.HANDLED_OBSERVATION
                        and outcome.result_ref == observation.observation_id
                        and outcome.result_sha256 == observation.observation_sha256
                        and outcome.observed_at == observation.observed_at
                        and (
                            reconciliation is None
                            or reconciliation.resolution_status
                            == "terminal_observed"
                        )
                    )
                if not valid:
                    raise OrchestrationIntegrityError(
                        "action execution journal handling does not bind its terminal observation"
                    )
        action_outcome_claims = {
            outcome.claim_id
            for job_outcomes in outcomes_by_job.values()
            for outcome in job_outcomes
            if jobs[outcome.job_id].job_kind is JobKind.ACTION_EXECUTION_HANDOFF
        }
        if set(action_reconciliations) - action_outcome_claims:
            raise OrchestrationIntegrityError(
                "action reconciliation and outcome inventory is invalid"
            )
        if set(terminal_observations) != {
            claim_id
            for claim_id in action_outcome_claims
            if (
                action_reconciliations.get(claim_id) is None
                or action_reconciliations[claim_id].resolution_status
                == "terminal_observed"
            )
        }:
            raise OrchestrationIntegrityError(
                "terminal observation and journal outcome inventory is invalid"
            )

        saga_rows = connection.execute(
            "SELECT * FROM saga_steps ORDER BY tenant_id,saga_id,sequence"
        )
        saga_heads: dict[tuple[str, str], SagaStep] = {}
        for row in saga_rows:
            step = self._parse(row["step_json"], SagaStep.from_dict, "saga step")
            self._require_columns(
                row,
                {
                    "step_id": step.step_id,
                    "step_sha256": step.step_sha256,
                    "tenant_id": step.tenant_id,
                    "saga_id": step.saga_id,
                    "sequence": step.sequence,
                    "recorded_at": step.recorded_at,
                },
                "saga step",
            )
            saga_key = (step.tenant_id, step.saga_id)
            prior = saga_heads.get(saga_key)
            expected_prior = None if prior is None else prior.step_sha256
            expected_sequence = 1 if prior is None else prior.sequence + 1
            if (
                step.prior_step_sha256 != expected_prior
                or step.sequence != expected_sequence
                or (
                    prior is not None
                    and (
                        step.saga_kind is not prior.saga_kind
                        or step.subject_ref != prior.subject_ref
                        or _instant(step.recorded_at) < _instant(prior.recorded_at)
                    )
                )
            ):
                raise OrchestrationIntegrityError("saga step chain is invalid")
            if prior is not None:
                try:
                    self._require_source_not_regress(
                        prior.source_bindings, step.source_bindings, label="saga"
                    )
                except OrchestrationConflictError as exc:
                    raise OrchestrationIntegrityError("saga source chain is invalid") from exc
            saga_heads[saga_key] = step

        outbox_custody_by_claim: dict[str, OutboxDeliveryClaimCustody] = {}
        for row in connection.execute("SELECT * FROM outbox_delivery_claim_custody"):
            custody = self._parse(
                row["custody_json"],
                OutboxDeliveryClaimCustody.from_dict,
                "outbox delivery claim custody",
            )
            self._require_columns(
                row,
                {
                    "custody_id": custody.custody_id,
                    "custody_sha256": custody.custody_sha256,
                    "tenant_id": custody.tenant_id,
                    "job_id": custody.job_id,
                    "message_id": custody.message_id,
                    "claim_id": custody.claim_id,
                    "worker_id": custody.worker_id,
                    "worker_assertion_id": custody.worker_assertion_id,
                    "worker_assertion_sha256": custody.worker_assertion_sha256,
                    "worker_session_id": custody.worker_session_id,
                    "worker_session_sha256": custody.worker_session_sha256,
                    "worker_capability_id": custody.worker_capability_id,
                    "worker_capability_sha256": custody.worker_capability_sha256,
                    "trusted_at": custody.trusted_at,
                    "expires_at": custody.expires_at,
                },
                "outbox delivery claim custody",
            )
            job = jobs.get(custody.job_id)
            message = messages.get(custody.message_id)
            claim = claims.get(custody.claim_id)
            if (
                job is None
                or message is None
                or claim is None
                or job.job_kind is not JobKind.OUTBOX_DELIVERY
                or job.maximum_attempts != 1
                or job.job_sha256 != custody.job_sha256
                or job.subject_ref != message.message_id
                or message.message_sha256 != custody.message_sha256
                or message.tenant_id != custody.tenant_id
                or message.direction is not MessageDirection.OUTBOX
                or claim.claim_sha256 != custody.claim_sha256
                or claim.job_id != job.job_id
                or claim.worker_id != custody.worker_id
                or claim.attempt_number != 1
                or claim.fence_token != 1
                or claim.lease_version != 1
                or claim.claimed_at != custody.trusted_at
                or claim.expires_at != custody.expires_at
                or custody.attempt_number != 1
            ):
                raise OrchestrationIntegrityError(
                    "outbox delivery claim custody is invalid"
                )
            outbox_custody_by_claim[custody.claim_id] = custody
        outbox_claims = {
            claim.claim_id
            for claim in claims.values()
            if jobs[claim.job_id].job_kind is JobKind.OUTBOX_DELIVERY
        }
        if set(outbox_custody_by_claim) != outbox_claims:
            raise OrchestrationIntegrityError(
                "outbox claim and authenticated custody inventory is invalid"
            )

        delivery_by_claim: dict[str, DeliveryAttempt] = {}
        for row in connection.execute("SELECT * FROM delivery_attempts"):
            attempt = self._parse(
                row["attempt_json"], DeliveryAttempt.from_dict, "delivery attempt"
            )
            self._require_columns(
                row,
                {
                    "attempt_id": attempt.attempt_id,
                    "attempt_sha256": attempt.attempt_sha256,
                    "tenant_id": attempt.tenant_id,
                    "message_id": attempt.message_id,
                    "job_id": attempt.job_id,
                    "claim_id": attempt.claim_id,
                    "attempt_number": attempt.attempt_number,
                    "observed_at": attempt.observed_at,
                },
                "delivery attempt",
            )
            message = messages.get(attempt.message_id)
            claim = claims.get(attempt.claim_id)
            job = jobs.get(attempt.job_id)
            custody = outbox_custody_by_claim.get(attempt.claim_id)
            if (
                message is None
                or claim is None
                or job is None
                or custody is None
                or message.direction is not MessageDirection.OUTBOX
                or job.job_kind is not JobKind.OUTBOX_DELIVERY
                or job.subject_ref != message.message_id
                or job.input_ref != message.external_ref
                or job.input_sha256 != message.external_sha256
                or job.source_bindings != message.source_bindings
                or attempt.message_sha256 != message.message_sha256
                or attempt.tenant_id != message.tenant_id
                or attempt.job_id != claim.job_id
                or attempt.claim_sha256 != claim.claim_sha256
                or attempt.fence_token != claim.fence_token
                or attempt.attempt_number != claim.attempt_number
                or attempt.message_id != custody.message_id
                or attempt.message_sha256 != custody.message_sha256
                or attempt.job_id != custody.job_id
                or attempt.claim_id != custody.claim_id
                or attempt.claim_sha256 != custody.claim_sha256
                or _instant(attempt.observed_at) < _instant(message.recorded_at)
                or _instant(attempt.observed_at) < _instant(claim.claimed_at)
                or _instant(attempt.observed_at) >= _instant(claim.expires_at)
            ):
                raise OrchestrationIntegrityError("delivery attempt binding is invalid")
            delivery_by_claim[attempt.claim_id] = attempt

        for job_id, job_outcomes in outcomes_by_job.items():
            if jobs[job_id].job_kind is not JobKind.OUTBOX_DELIVERY:
                continue
            for outcome in job_outcomes:
                delivery = delivery_by_claim.get(outcome.claim_id)
                if (
                    delivery is None
                    or _DELIVERY_JOB_OUTCOME[delivery.outcome] is not outcome.outcome_code
                    or outcome.result_ref != delivery.attempt_id
                    or outcome.result_sha256 != delivery.attempt_sha256
                ):
                    raise OrchestrationIntegrityError(
                        "delivery and job outcome observations disagree"
                    )
        outbox_outcome_claims = {
            outcome.claim_id
            for job_outcomes in outcomes_by_job.values()
            for outcome in job_outcomes
            if jobs[outcome.job_id].job_kind is JobKind.OUTBOX_DELIVERY
        }
        if set(delivery_by_claim) != outbox_outcome_claims:
            raise OrchestrationIntegrityError(
                "delivery observation and outcome inventory is invalid"
            )

        projections_by_key: dict[tuple[str, str, str], list[ReadModelProjection]] = {}
        for row in connection.execute(
            "SELECT * FROM projections ORDER BY tenant_id,projection_kind,subject_ref,"
            "projection_version"
        ):
            projection = self._parse(
                row["projection_json"], ReadModelProjection.from_dict, "projection"
            )
            self._require_columns(
                row,
                {
                    "projection_id": projection.projection_id,
                    "projection_sha256": projection.projection_sha256,
                    "tenant_id": projection.tenant_id,
                    "projection_kind": projection.projection_kind.value,
                    "subject_ref": projection.subject_ref,
                    "projection_version": projection.projection_version,
                    "projected_at": projection.projected_at,
                },
                "projection",
            )
            projections_by_key.setdefault(
                (
                    projection.tenant_id,
                    projection.projection_kind.value,
                    projection.subject_ref,
                ),
                [],
            ).append(projection)

        self._verify_job_heads(
            connection, jobs, claims_by_job, outcomes_by_job, quarantines
        )
        self._verify_projection_heads(connection, projections_by_key)

    @staticmethod
    def _require_columns(row: sqlite3.Row, expected: Mapping[str, Any], label: str) -> None:
        for column, value in expected.items():
            stored = row[column]
            if type(stored) is not type(value) or stored != value:
                raise OrchestrationIntegrityError(
                    f"stored {label} column {column} does not match content"
                )

    def _verify_job_heads(
        self,
        connection: sqlite3.Connection,
        jobs: Mapping[str, OrchestrationJob],
        claims_by_job: Mapping[str, list[JobClaim]],
        outcomes_by_job: Mapping[str, list[JobOutcome]],
        quarantines: Mapping[str, ActionExecutionHandoffQuarantine],
    ) -> None:
        head_rows = {row["job_id"]: row for row in connection.execute("SELECT * FROM job_heads")}
        if set(head_rows) != set(jobs):
            raise OrchestrationIntegrityError("job head inventory is invalid")
        for job_id, job in jobs.items():
            rows = claims_by_job.get(job_id, [])
            prior_by_fence: dict[int, JobClaim] = {}
            first_by_fence: dict[int, JobClaim] = {}
            for claim in rows:
                self._require_claim_custody(job, claim)
                if (
                    claim.attempt_number != claim.fence_token
                    or claim.attempt_number > job.maximum_attempts
                ):
                    raise OrchestrationIntegrityError("job attempt and fence diverge")
                prior = prior_by_fence.get(claim.fence_token)
                if prior is None:
                    first_by_fence[claim.fence_token] = claim
                    if claim.lease_version != 1 or claim.prior_claim_sha256 is not None:
                        raise OrchestrationIntegrityError("job claim chain does not start at one")
                    if claim.fence_token > 1:
                        previous_fence = prior_by_fence.get(claim.fence_token - 1)
                        if previous_fence is None:
                            raise OrchestrationIntegrityError("job fence sequence has a gap")
                    elif _instant(claim.claimed_at) < _instant(job.available_at):
                        raise OrchestrationIntegrityError(
                            "initial job claim predates availability"
                        )
                else:
                    if (
                        claim.lease_version != prior.lease_version + 1
                        or claim.prior_claim_sha256 != prior.claim_sha256
                        or claim.worker_id != prior.worker_id
                        or _instant(claim.claimed_at) <= _instant(prior.claimed_at)
                        or _instant(claim.expires_at) <= _instant(prior.expires_at)
                    ):
                        raise OrchestrationIntegrityError("job claim renewal chain is invalid")
                prior_by_fence[claim.fence_token] = claim
            latest_claim = None if not prior_by_fence else prior_by_fence[max(prior_by_fence)]
            outcomes = outcomes_by_job.get(job_id, [])
            outcomes_by_fence = {item.fence_token: item for item in outcomes}
            if len(outcomes_by_fence) != len(outcomes):
                raise OrchestrationIntegrityError("job fence has duplicate outcomes")
            for fence, outcome in outcomes_by_fence.items():
                if (
                    prior_by_fence.get(fence) is None
                    or outcome.claim_id != prior_by_fence[fence].claim_id
                ):
                    raise OrchestrationIntegrityError("job outcome does not bind the latest lease")
            for fence in range(2, len(prior_by_fence) + 1):
                prior_claim = prior_by_fence[fence - 1]
                next_claim = first_by_fence[fence]
                prior_outcome = outcomes_by_fence.get(fence - 1)
                if prior_outcome is None:
                    if job.job_kind in _INDETERMINATE_ON_EXPIRED_LEASE or _instant(
                        next_claim.claimed_at
                    ) < _instant(prior_claim.expires_at):
                        raise OrchestrationIntegrityError(
                            "job fence advanced without safe retry custody"
                        )
                elif (
                    prior_outcome.outcome_code is not JobOutcomeCode.RETRYABLE_FAILURE_OBSERVATION
                    or prior_outcome.retry_available_at is None
                    or _instant(next_claim.claimed_at) < _instant(prior_outcome.retry_available_at)
                ):
                    raise OrchestrationIntegrityError(
                        "job fence advanced after a non-retryable outcome"
                    )
            latest_outcome = (
                None if latest_claim is None else outcomes_by_fence.get(latest_claim.fence_token)
            )
            quarantine = quarantines.get(job_id)
            if quarantine is not None:
                if latest_claim is not None or outcomes:
                    raise OrchestrationIntegrityError(
                        "quarantined handoff has claim or outcome custody"
                    )
                expected_state = JobState.DEAD_LETTERED
                expected_available = job.available_at
            elif latest_claim is None:
                expected_state = JobState.AVAILABLE
                expected_available = job.available_at
            elif latest_outcome is None:
                expected_state = JobState.LEASED
                expected_available = job.available_at
            elif latest_outcome.outcome_code is JobOutcomeCode.HANDLED_OBSERVATION:
                expected_state = JobState.WORKER_REPORTED
                expected_available = job.available_at
            elif latest_outcome.outcome_code in {
                JobOutcomeCode.PERMANENT_FAILURE_OBSERVATION,
                JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION,
            }:
                expected_state = JobState.DEAD_LETTERED
                expected_available = job.available_at
            else:
                expected_state = (
                    JobState.AVAILABLE
                    if latest_claim.attempt_number < job.maximum_attempts
                    else JobState.DEAD_LETTERED
                )
                expected_available = latest_outcome.retry_available_at
            head = head_rows[job_id]
            expected = {
                "state": expected_state.value,
                "revision": 1 + len(rows) + len(outcomes) + (quarantine is not None),
                "attempt_number": 0 if latest_claim is None else latest_claim.attempt_number,
                "fence_token": 0 if latest_claim is None else latest_claim.fence_token,
                "current_claim_id": None if latest_claim is None else latest_claim.claim_id,
                "current_claim_sha256": (
                    None if latest_claim is None else latest_claim.claim_sha256
                ),
                "current_outcome_id": (
                    None if latest_outcome is None else latest_outcome.outcome_id
                ),
                "current_outcome_sha256": (
                    None if latest_outcome is None else latest_outcome.outcome_sha256
                ),
                "available_at": expected_available,
            }
            self._require_columns(head, expected, "job head")

    def _verify_projection_heads(
        self,
        connection: sqlite3.Connection,
        projections_by_key: Mapping[tuple[str, str, str], list[ReadModelProjection]],
    ) -> None:
        heads = {
            (row["tenant_id"], row["projection_kind"], row["subject_ref"]): row
            for row in connection.execute("SELECT * FROM projection_heads")
        }
        if set(heads) != set(projections_by_key):
            raise OrchestrationIntegrityError("projection head inventory is invalid")
        for key, versions in projections_by_key.items():
            for index, projection in enumerate(versions, start=1):
                if projection.projection_version != index:
                    raise OrchestrationIntegrityError("projection version chain has a gap")
                if index > 1:
                    if _instant(projection.projected_at) < _instant(
                        versions[index - 2].projected_at
                    ):
                        raise OrchestrationIntegrityError("projection chronology regressed")
                    try:
                        self._require_source_advance(
                            versions[index - 2].source_bindings, projection.source_bindings
                        )
                    except OrchestrationConflictError as exc:
                        raise OrchestrationIntegrityError(
                            "projection source chain is invalid"
                        ) from exc
            latest = versions[-1]
            self._require_columns(
                heads[key],
                {
                    "projection_id": latest.projection_id,
                    "projection_sha256": latest.projection_sha256,
                    "projection_version": latest.projection_version,
                },
                "projection head",
            )

    def _verify_events(self, connection: sqlite3.Connection) -> int:
        expected: dict[str, tuple[str, str, str, str, str, str]] = {}

        def expect(
            record_id: str,
            record_sha256: str,
            tenant_id: str,
            aggregate_type: str,
            aggregate_id: str,
            event_type: str,
            occurred_at: str,
        ) -> None:
            if record_id in expected:
                raise OrchestrationIntegrityError("journal record identity is duplicated")
            expected[record_id] = (
                record_sha256,
                tenant_id,
                aggregate_type,
                aggregate_id,
                event_type,
                occurred_at,
            )

        for row in connection.execute("SELECT * FROM jobs"):
            expect(
                row["job_id"],
                row["job_sha256"],
                row["tenant_id"],
                "job",
                row["job_id"],
                "job.submitted",
                row["created_at"],
            )
        for row in connection.execute("SELECT * FROM job_claims"):
            expect(
                row["claim_id"],
                row["claim_sha256"],
                row["tenant_id"],
                "job",
                row["job_id"],
                "job.claimed" if row["lease_version"] == 1 else "job.claim_renewed",
                row["claimed_at"],
            )
        for row in connection.execute("SELECT * FROM job_outcomes"):
            event_type = (
                "job.lease_exhausted"
                if row["outcome_code"] == JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION.value
                else "job.worker_observation"
            )
            expect(
                row["outcome_id"],
                row["outcome_sha256"],
                row["tenant_id"],
                "job",
                row["job_id"],
                event_type,
                row["observed_at"],
            )
        for row in connection.execute("SELECT * FROM messages"):
            expect(
                row["message_id"],
                row["message_sha256"],
                row["tenant_id"],
                "message",
                row["message_id"],
                "message.recorded",
                row["recorded_at"],
            )
        for row in connection.execute("SELECT * FROM action_execution_intents"):
            expect(
                row["intent_id"],
                row["intent_sha256"],
                row["tenant_id"],
                "action_execution",
                row["intent_id"],
                "action_execution.intent_recorded",
                row["requested_at"],
            )
        for row in connection.execute("SELECT * FROM action_execution_attempts"):
            expect(
                row["attempt_id"],
                row["attempt_sha256"],
                row["tenant_id"],
                "job",
                row["job_id"],
                "action_execution.attempt_claimed",
                row["trusted_at"],
            )
        for row in connection.execute("SELECT * FROM action_execution_reconciliations"):
            expect(
                row["reconciliation_id"],
                row["reconciliation_sha256"],
                row["tenant_id"],
                "job",
                row["job_id"],
                "action_execution.reconciled",
                row["resolved_at"],
            )
        for row in connection.execute(
            "SELECT * FROM action_execution_handoff_quarantines"
        ):
            expect(
                row["quarantine_id"],
                row["quarantine_sha256"],
                row["tenant_id"],
                "job",
                row["job_id"],
                "action_execution.handoff_quarantined",
                row["trusted_at"],
            )
        for row in connection.execute(
            "SELECT * FROM action_execution_terminal_observations"
        ):
            expect(
                row["observation_id"],
                row["observation_sha256"],
                row["tenant_id"],
                "job",
                row["job_id"],
                "action_execution.terminal_observed",
                row["observed_at"],
            )
        for row in connection.execute("SELECT * FROM saga_steps"):
            expect(
                row["step_id"],
                row["step_sha256"],
                row["tenant_id"],
                "saga",
                row["saga_id"],
                "saga.step_recorded",
                row["recorded_at"],
            )
        for row in connection.execute("SELECT * FROM delivery_attempts"):
            expect(
                row["attempt_id"],
                row["attempt_sha256"],
                row["tenant_id"],
                "message",
                row["message_id"],
                "message.delivery_observed",
                row["observed_at"],
            )
        for row in connection.execute("SELECT * FROM outbox_delivery_claim_custody"):
            expect(
                row["custody_id"],
                row["custody_sha256"],
                row["tenant_id"],
                "job",
                row["job_id"],
                "outbox.delivery_claimed",
                row["trusted_at"],
            )
        for row in connection.execute("SELECT * FROM projections"):
            expect(
                row["projection_id"],
                row["projection_sha256"],
                row["tenant_id"],
                "projection",
                f"{row['projection_kind']}:{row['subject_ref']}",
                "projection.reconciled",
                row["projected_at"],
            )

        heads: dict[tuple[str, str, str], tuple[int, str, str]] = {}
        count = 0
        for row in connection.execute("SELECT * FROM journal_events ORDER BY event_sequence"):
            if type(row["event_sequence"]) is not int or row["event_sequence"] != count + 1:
                raise OrchestrationIntegrityError("event sequence storage type is invalid")
            try:
                raw = loads_json_without_duplicate_keys(row["event_json"])
                self._validate_event(raw)
                if canonical_json(raw) != row["event_json"]:
                    raise OrchestrationValidationError("journal event JSON is not canonical")
            except OrchestrationValidationError as exc:
                raise OrchestrationIntegrityError("stored journal event is invalid") from exc
            reference = expected.pop(row["record_id"], None)
            if reference is None:
                raise OrchestrationIntegrityError("journal event references an unknown record")
            (
                expected_sha,
                expected_tenant,
                expected_aggregate_type,
                expected_aggregate_id,
                expected_event_type,
                expected_occurred_at,
            ) = reference
            key = (row["tenant_id"], row["aggregate_type"], row["aggregate_id"])
            expected_prior = None if key not in heads else heads[key][1]
            if key in heads and _instant(expected_occurred_at) < _instant(heads[key][2]):
                raise OrchestrationIntegrityError("journal aggregate chronology regressed")
            self._require_columns(
                row,
                {
                    "event_id": raw["event_id"],
                    "event_sha256": raw["event_sha256"],
                    "tenant_id": expected_tenant,
                    "aggregate_type": expected_aggregate_type,
                    "aggregate_id": expected_aggregate_id,
                    "event_type": expected_event_type,
                    "record_id": raw["record_id"],
                    "record_sha256": expected_sha,
                    "prior_event_sha256": expected_prior,
                    "occurred_at": expected_occurred_at,
                },
                "journal event",
            )
            if raw != {
                **_common("sunderkey.orchestration-journal-event.v1"),
                "aggregate_id": expected_aggregate_id,
                "aggregate_type": expected_aggregate_type,
                "event_id": row["event_id"],
                "event_sha256": row["event_sha256"],
                "event_type": expected_event_type,
                "occurred_at": expected_occurred_at,
                "prior_event_sha256": expected_prior,
                "record_id": row["record_id"],
                "record_sha256": expected_sha,
                "tenant_id": expected_tenant,
            }:
                raise OrchestrationIntegrityError("journal event chain is invalid")
            heads[key] = (
                row["event_sequence"],
                row["event_sha256"],
                expected_occurred_at,
            )
            count += 1
        if expected:
            raise OrchestrationIntegrityError("journal events are missing for durable records")
        sequence_row = connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='journal_events'"
        ).fetchone()
        if (sequence_row is None and count != 0) or (
            sequence_row is not None
            and (type(sequence_row["seq"]) is not int or sequence_row["seq"] != count)
        ):
            raise OrchestrationIntegrityError("journal event sequence head is invalid")
        stored_heads = {
            (row["tenant_id"], row["aggregate_type"], row["aggregate_id"]): (
                row["event_sequence"],
                row["event_sha256"],
            )
            for row in connection.execute("SELECT * FROM event_heads")
        }
        if {key: (value[0], value[1]) for key, value in heads.items()} != stored_heads:
            raise OrchestrationIntegrityError("journal event heads are invalid")
        return count


__all__ = [
    "APPLICATION_ID",
    "ActionExecutionAttempt",
    "ActionExecutionHandoffQuarantine",
    "ActionExecutionIntent",
    "ActionExecutionReconciliation",
    "ActionExecutionTerminalObservation",
    "DeliveryAttempt",
    "DeliveryOutcome",
    "EXPECTED_SCHEMA_MANIFEST_SHA256",
    "JobClaim",
    "JobKind",
    "JobOutcome",
    "JobOutcomeCode",
    "JobState",
    "JobView",
    "MAX_PAGE_SIZE",
    "MIGRATION_SHA256",
    "MessageDirection",
    "MessageTopic",
    "MutationResult",
    "NO_AUTHORITY_EFFECTS",
    "OrchestrationBusyError",
    "OrchestrationConflictError",
    "OrchestrationIntegrityError",
    "OrchestrationJob",
    "OrchestrationJournalError",
    "OrchestrationMessage",
    "OrchestrationValidationError",
    "OutboxDeliveryClaimCustody",
    "ProjectionKind",
    "ReadModelProjection",
    "SCHEMA_VERSION",
    "SQLiteOrchestrationJournal",
    "SagaKind",
    "SagaStep",
    "SagaStepState",
    "SourceHighWater",
    "SourceKind",
    "build_delivery_attempt",
    "build_action_execution_intent",
    "build_orchestration_job",
    "build_orchestration_message",
    "build_read_model_projection",
    "build_saga_step",
    "canonical_json",
    "canonical_sha256",
    "action_execution_reconciliation_lineage_sha256",
    "authentication_context_sha256",
    "format_timestamp",
    "loads_json_without_duplicate_keys",
    "source_bindings_sha256",
]
