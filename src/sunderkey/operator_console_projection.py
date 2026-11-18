"""Content-addressed operator console projections with no runtime effects.

The contracts in this module combine immutable mission summaries for display.
They do not authorize a principal, mutate a mission, control a worker, execute
an action, open a network connection, or expose credential values.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = 1
PROJECTION_DOMAIN = "sunderkey.operator-console-projection.v1"
INTENT_DOMAIN = "sunderkey.operator-console-intent.v1"

NO_EFFECTS = {
    "authorization": "external",
    "control": "none",
    "credentials": "none",
    "execution": "none",
    "mission_mutation": "none",
    "network": "none",
    "persistence": "none",
    "worker_mutation": "none",
}

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")
REFERENCE_RE = re.compile(
    r"(?:approvalref|assessmentref|evidref|findingref|graphref|reportref|"
    r"schedref|scoperef|statusref|taskref|workerref):"
    r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z"
)
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@)",
    re.IGNORECASE,
)


class OperatorConsoleError(ValueError):
    """Raised when an operator console contract fails closed."""


class ViewRole(StrEnum):
    ASSESSMENT_OPERATOR = "assessment_operator"
    INDEPENDENT_CONTROL = "independent_control"
    INDEPENDENT_ASSURANCE = "independent_assurance"
    EVIDENCE_CUSTODIAN = "evidence_custodian"
    EXECUTIVE_OBSERVER = "executive_observer"
    INCIDENT_RESPONDER = "incident_responder"


class MissionState(StrEnum):
    DRAFT = "draft"
    PENDING_SCOPE = "pending_scope"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class AttentionSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class OperatorIntentKind(StrEnum):
    REQUEST_PAUSE = "request_pause"
    REQUEST_RESUME = "request_resume"
    REQUEST_CANCEL = "request_cancel"
    REQUEST_EMERGENCY_STOP = "request_emergency_stop"
    REQUEST_APPROVAL_REVIEW = "request_approval_review"
    ACKNOWLEDGE_BLOCKER = "acknowledge_blocker"


class WorkerState(StrEnum):
    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    TERMINAL = "terminal"


@dataclass(frozen=True)
class Counter:
    """One bounded current value and limit."""

    consumed: int
    limit: int

    def __post_init__(self) -> None:
        _nonnegative_int(self.consumed, "counter consumed")
        _positive_int(self.limit, "counter limit")
        if self.consumed > self.limit:
            raise OperatorConsoleError("counter consumed exceeds limit")

    @property
    def remaining(self) -> int:
        return self.limit - self.consumed

    def to_dict(self) -> dict[str, int]:
        return {"consumed": self.consumed, "limit": self.limit, "remaining": self.remaining}

    @classmethod
    def from_dict(cls, raw: Any) -> Counter:
        _exact_fields(raw, {"consumed", "limit", "remaining"}, "counter")
        value = cls(raw["consumed"], raw["limit"])
        if raw["remaining"] != value.remaining:
            raise OperatorConsoleError("counter remaining is not derived")
        return value


@dataclass(frozen=True)
class BudgetSnapshot:
    requests: Counter
    cost_units: Counter
    tokens: Counter
    tool_calls: Counter
    worker_minutes: Counter
    storage_bytes: Counter

    def to_dict(self) -> dict[str, Any]:
        return {
            "cost_units": self.cost_units.to_dict(),
            "requests": self.requests.to_dict(),
            "storage_bytes": self.storage_bytes.to_dict(),
            "tokens": self.tokens.to_dict(),
            "tool_calls": self.tool_calls.to_dict(),
            "worker_minutes": self.worker_minutes.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> BudgetSnapshot:
        fields = {
            "cost_units",
            "requests",
            "storage_bytes",
            "tokens",
            "tool_calls",
            "worker_minutes",
        }
        _exact_fields(raw, fields, "budget")
        return cls(**{field: Counter.from_dict(raw[field]) for field in fields})


@dataclass(frozen=True)
class CoverageSnapshot:
    total: int
    completed: int
    running: int
    blocked: int
    queued: int

    def __post_init__(self) -> None:
        for name in ("total", "completed", "running", "blocked", "queued"):
            _nonnegative_int(getattr(self, name), f"coverage {name}")
        if self.total != self.completed + self.running + self.blocked + self.queued:
            raise OperatorConsoleError("coverage counts do not equal total")

    @property
    def completion_basis_points(self) -> int:
        return 0 if self.total == 0 else (self.completed * 10_000) // self.total

    def to_dict(self) -> dict[str, int]:
        return {
            "blocked": self.blocked,
            "completed": self.completed,
            "completion_basis_points": self.completion_basis_points,
            "queued": self.queued,
            "running": self.running,
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CoverageSnapshot:
        _exact_fields(
            raw,
            {"blocked", "completed", "completion_basis_points", "queued", "running", "total"},
            "coverage",
        )
        value = cls(raw["total"], raw["completed"], raw["running"], raw["blocked"], raw["queued"])
        if raw["completion_basis_points"] != value.completion_basis_points:
            raise OperatorConsoleError("coverage completion is not derived")
        return value


@dataclass(frozen=True)
class WorkerSummary:
    worker_ref: str
    specialist_profile_id: str
    state: WorkerState | str
    health: HealthState | str
    current_task_ref: str | None
    heartbeat_at: str

    def __post_init__(self) -> None:
        _reference(self.worker_ref, "worker_ref", "workerref:")
        _identifier(self.specialist_profile_id, "specialist_profile_id")
        _enum(self, "state", WorkerState)
        _enum(self, "health", HealthState)
        if self.current_task_ref is not None:
            _reference(self.current_task_ref, "current_task_ref", "taskref:")
        _utc(self.heartbeat_at, "heartbeat_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_task_ref": self.current_task_ref,
            "health": self.health.value,
            "heartbeat_at": self.heartbeat_at,
            "specialist_profile_id": self.specialist_profile_id,
            "state": self.state.value,
            "worker_ref": self.worker_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> WorkerSummary:
        _exact_fields(
            raw,
            {
                "current_task_ref",
                "health",
                "heartbeat_at",
                "specialist_profile_id",
                "state",
                "worker_ref",
            },
            "worker",
        )
        return cls(**raw)


@dataclass(frozen=True)
class ApprovalSummary:
    approval_ref: str
    action_kind: str
    action_tier: str
    state: str
    expires_at: str | None

    def __post_init__(self) -> None:
        _reference(self.approval_ref, "approval_ref", "approvalref:")
        _token(self.action_kind, "action_kind")
        if self.action_tier not in {"R0", "R1", "R2", "R3", "R4"}:
            raise OperatorConsoleError("approval action_tier is invalid")
        _token(self.state, "approval state")
        if self.expires_at is not None:
            _utc(self.expires_at, "approval expires_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_kind": self.action_kind,
            "action_tier": self.action_tier,
            "approval_ref": self.approval_ref,
            "expires_at": self.expires_at,
            "state": self.state,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ApprovalSummary:
        _exact_fields(
            raw, {"action_kind", "action_tier", "approval_ref", "expires_at", "state"}, "approval"
        )
        return cls(**raw)


@dataclass(frozen=True)
class BlockerSummary:
    blocker_id: str
    code: str
    severity: AttentionSeverity | str
    detail: str
    owner_role: str

    def __post_init__(self) -> None:
        _identifier(self.blocker_id, "blocker_id")
        _token(self.code, "blocker code")
        _enum(self, "severity", AttentionSeverity)
        _safe_text(self.detail, "blocker detail", 512)
        _token(self.owner_role, "blocker owner_role")

    def to_dict(self) -> dict[str, str]:
        return {
            "blocker_id": self.blocker_id,
            "code": self.code,
            "detail": self.detail,
            "owner_role": self.owner_role,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> BlockerSummary:
        _exact_fields(raw, {"blocker_id", "code", "detail", "owner_role", "severity"}, "blocker")
        return cls(**raw)


@dataclass(frozen=True)
class GraphChangeSummary:
    graph_ref: str
    nodes_added: int
    nodes_updated: int
    edges_added: int
    conflicts: int
    changed_at: str

    def __post_init__(self) -> None:
        _reference(self.graph_ref, "graph_ref", "graphref:")
        for name in ("nodes_added", "nodes_updated", "edges_added", "conflicts"):
            _nonnegative_int(getattr(self, name), f"graph {name}")
        _utc(self.changed_at, "graph changed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "changed_at": self.changed_at,
            "conflicts": self.conflicts,
            "edges_added": self.edges_added,
            "graph_ref": self.graph_ref,
            "nodes_added": self.nodes_added,
            "nodes_updated": self.nodes_updated,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GraphChangeSummary:
        _exact_fields(
            raw,
            {"changed_at", "conflicts", "edges_added", "graph_ref", "nodes_added", "nodes_updated"},
            "graph change",
        )
        return cls(**raw)


@dataclass(frozen=True)
class MissionProjectionInput:
    assessment_ref: str
    assessment_version: int
    mission_state: MissionState | str
    observed_at: str
    scope_sha256: str
    schedule_sha256: str
    status_sha256: str
    health: HealthState | str
    coverage: CoverageSnapshot
    budget: BudgetSnapshot
    workers: tuple[WorkerSummary, ...]
    approvals: tuple[ApprovalSummary, ...]
    blockers: tuple[BlockerSummary, ...]
    graph_changes: tuple[GraphChangeSummary, ...]
    finding_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    report_refs: tuple[str, ...]
    emergency_stop_recorded: bool

    def __post_init__(self) -> None:
        _reference(self.assessment_ref, "assessment_ref", "assessmentref:")
        _positive_int(self.assessment_version, "assessment_version")
        _enum(self, "mission_state", MissionState)
        _utc(self.observed_at, "observed_at")
        for name in ("scope_sha256", "schedule_sha256", "status_sha256"):
            _sha256(getattr(self, name), name)
        _enum(self, "health", HealthState)
        for name, values, key in (
            ("workers", self.workers, lambda value: value.worker_ref),
            ("approvals", self.approvals, lambda value: value.approval_ref),
            ("blockers", self.blockers, lambda value: value.blocker_id),
            ("graph_changes", self.graph_changes, lambda value: value.graph_ref),
        ):
            _bounded_unique(values, name, key, 4096)
        for name, refs, prefix in (
            ("finding_refs", self.finding_refs, "findingref:"),
            ("evidence_refs", self.evidence_refs, "evidref:"),
            ("report_refs", self.report_refs, "reportref:"),
        ):
            _bounded_unique(refs, name, lambda value: value, 8192)
            for ref in refs:
                _reference(ref, name, prefix)
        if not isinstance(self.emergency_stop_recorded, bool):
            raise OperatorConsoleError("emergency_stop_recorded must be a boolean")
        if self.emergency_stop_recorded and self.mission_state in {
            MissionState.RUNNING,
            MissionState.READY,
        }:
            raise OperatorConsoleError("a stopped mission cannot be ready or running")


@dataclass(frozen=True)
class OperatorConsoleProjection:
    projection_id: str
    projection_sha256: str
    view_role: ViewRole | str
    source: MissionProjectionInput
    visible_sections: tuple[str, ...]
    redacted_sections: tuple[str, ...]
    available_intents: tuple[OperatorIntentKind | str, ...]
    controls_require_external_authorization: bool = True

    def __post_init__(self) -> None:
        _enum(self, "view_role", ViewRole)
        intents = tuple(OperatorIntentKind(value) for value in self.available_intents)
        object.__setattr__(self, "available_intents", intents)
        for name, values in (
            ("visible_sections", self.visible_sections),
            ("redacted_sections", self.redacted_sections),
        ):
            _bounded_unique(values, name, lambda value: value, 32)
            for value in values:
                _token(value, name)
        if set(self.visible_sections) & set(self.redacted_sections):
            raise OperatorConsoleError("visible and redacted sections overlap")
        if not self.controls_require_external_authorization:
            raise OperatorConsoleError("operator controls must require external authorization")
        body = self._body()
        expected_id, expected_digest = _identity("OCP", PROJECTION_DOMAIN, body)
        if self.projection_id != expected_id or self.projection_sha256 != expected_digest:
            raise OperatorConsoleError("projection identity does not match content")

    def _body(self) -> dict[str, Any]:
        return {
            "available_intents": [value.value for value in self.available_intents],
            "controls_require_external_authorization": self.controls_require_external_authorization,
            "redacted_sections": list(self.redacted_sections),
            "source": _source_to_dict(self.source, self.view_role),
            "view_role": self.view_role.value,
            "visible_sections": list(self.visible_sections),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "no_effects": dict(NO_EFFECTS),
            "projection_id": self.projection_id,
            "projection_sha256": self.projection_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OperatorConsoleProjection:
        expected = {
            "available_intents",
            "controls_require_external_authorization",
            "no_effects",
            "projection_id",
            "projection_sha256",
            "redacted_sections",
            "schema_version",
            "source",
            "view_role",
            "visible_sections",
        }
        _exact_fields(raw, expected, "projection")
        _envelope(raw, "projection")
        role = ViewRole(raw["view_role"])
        source = _source_from_dict(raw["source"], role)
        return cls(
            projection_id=raw["projection_id"],
            projection_sha256=raw["projection_sha256"],
            view_role=role,
            source=source,
            visible_sections=tuple(raw["visible_sections"]),
            redacted_sections=tuple(raw["redacted_sections"]),
            available_intents=tuple(raw["available_intents"]),
            controls_require_external_authorization=raw["controls_require_external_authorization"],
        )


@dataclass(frozen=True)
class OperatorIntentRequest:
    intent_id: str
    intent_sha256: str
    assessment_ref: str
    expected_assessment_version: int
    intent_kind: OperatorIntentKind | str
    principal_id: str
    requested_at: str
    idempotency_key: str
    rationale: str
    authorization_status: str = "external_required"
    effect: str = "none"

    def __post_init__(self) -> None:
        _reference(self.assessment_ref, "assessment_ref", "assessmentref:")
        _positive_int(self.expected_assessment_version, "expected_assessment_version")
        _enum(self, "intent_kind", OperatorIntentKind)
        _identifier(self.principal_id, "principal_id")
        _utc(self.requested_at, "requested_at")
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise OperatorConsoleError("idempotency_key is invalid")
        _safe_text(self.rationale, "rationale", 1024)
        if self.authorization_status != "external_required" or self.effect != "none":
            raise OperatorConsoleError("operator intent cannot claim authorization or effects")
        expected_id, expected_digest = _identity("OCI", INTENT_DOMAIN, self._body())
        if self.intent_id != expected_id or self.intent_sha256 != expected_digest:
            raise OperatorConsoleError("intent identity does not match content")

    def _body(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "authorization_status": self.authorization_status,
            "effect": self.effect,
            "expected_assessment_version": self.expected_assessment_version,
            "idempotency_key": self.idempotency_key,
            "intent_kind": self.intent_kind.value,
            "principal_id": self.principal_id,
            "rationale": self.rationale,
            "requested_at": self.requested_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "intent_id": self.intent_id,
            "intent_sha256": self.intent_sha256,
            "no_effects": dict(NO_EFFECTS),
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OperatorIntentRequest:
        expected = {
            "assessment_ref",
            "authorization_status",
            "effect",
            "expected_assessment_version",
            "idempotency_key",
            "intent_id",
            "intent_kind",
            "intent_sha256",
            "no_effects",
            "principal_id",
            "rationale",
            "requested_at",
            "schema_version",
        }
        _exact_fields(raw, expected, "intent")
        _envelope(raw, "intent")
        return cls(
            **{key: raw[key] for key in expected if key not in {"no_effects", "schema_version"}}
        )


def build_operator_console_projection(
    source: MissionProjectionInput, view_role: ViewRole | str
) -> OperatorConsoleProjection:
    """Build a deterministic, role-specific display projection."""

    try:
        role = ViewRole(view_role)
    except (TypeError, ValueError) as exc:
        raise OperatorConsoleError("view_role is invalid") from exc
    visible, redacted = _sections(role)
    intents = _available_intents(role, source.mission_state, source.emergency_stop_recorded)
    projected_source = _source_from_dict(_source_to_dict(source, role), role)
    body = {
        "available_intents": [value.value for value in intents],
        "controls_require_external_authorization": True,
        "redacted_sections": list(redacted),
        "source": _source_to_dict(projected_source, role),
        "view_role": role.value,
        "visible_sections": list(visible),
    }
    identity, digest = _identity("OCP", PROJECTION_DOMAIN, body)
    return OperatorConsoleProjection(
        identity, digest, role, projected_source, visible, redacted, intents
    )


def build_operator_intent_request(
    *,
    assessment_ref: str,
    expected_assessment_version: int,
    intent_kind: OperatorIntentKind | str,
    principal_id: str,
    requested_at: str,
    idempotency_key: str,
    rationale: str,
) -> OperatorIntentRequest:
    """Create a request record that has no authority or runtime effect."""

    try:
        intent = OperatorIntentKind(intent_kind)
    except (TypeError, ValueError) as exc:
        raise OperatorConsoleError("intent_kind is invalid") from exc
    body = {
        "assessment_ref": assessment_ref,
        "authorization_status": "external_required",
        "effect": "none",
        "expected_assessment_version": expected_assessment_version,
        "idempotency_key": idempotency_key,
        "intent_kind": intent.value,
        "principal_id": principal_id,
        "rationale": rationale,
        "requested_at": requested_at,
    }
    identity, digest = _identity("OCI", INTENT_DOMAIN, body)
    return OperatorIntentRequest(
        identity,
        digest,
        assessment_ref,
        expected_assessment_version,
        intent,
        principal_id,
        requested_at,
        idempotency_key,
        rationale,
    )


def parse_operator_console_document(
    document: str,
) -> OperatorConsoleProjection | OperatorIntentRequest:
    """Parse a canonical serialized projection or intent and recheck identity."""

    try:
        raw = json.loads(document)
    except (TypeError, json.JSONDecodeError) as exc:
        raise OperatorConsoleError("document is not valid JSON") from exc
    if canonical_json(raw) != document:
        raise OperatorConsoleError("document JSON is not canonical")
    if "projection_id" in raw:
        return OperatorConsoleProjection.from_dict(raw)
    if "intent_id" in raw:
        return OperatorIntentRequest.from_dict(raw)
    raise OperatorConsoleError("document kind is unknown")


def canonical_json(value: Any) -> str:
    _validate_json(value, "value")
    try:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
    except (TypeError, ValueError) as exc:
        raise OperatorConsoleError("value cannot be canonicalized") from exc


def _source_to_dict(source: MissionProjectionInput, role: ViewRole) -> dict[str, Any]:
    workers = [
        value.to_dict() for value in sorted(source.workers, key=lambda value: value.worker_ref)
    ]
    approvals = [
        value.to_dict() for value in sorted(source.approvals, key=lambda value: value.approval_ref)
    ]
    blockers = [
        value.to_dict() for value in sorted(source.blockers, key=lambda value: value.blocker_id)
    ]
    graph_changes = [
        value.to_dict() for value in sorted(source.graph_changes, key=lambda value: value.graph_ref)
    ]
    finding_refs = sorted(source.finding_refs)
    evidence_refs = sorted(source.evidence_refs)
    report_refs = sorted(source.report_refs)
    if role is ViewRole.EXECUTIVE_OBSERVER:
        workers = []
        approvals = []
        blockers = []
        graph_changes = []
        finding_refs = []
        evidence_refs = []
        report_refs = []
    elif role is ViewRole.EVIDENCE_CUSTODIAN:
        workers = []
        approvals = []
        blockers = []
    elif role is ViewRole.INCIDENT_RESPONDER:
        approvals = []
        evidence_refs = []
        report_refs = []
    return {
        "approvals": approvals,
        "assessment_ref": source.assessment_ref,
        "assessment_version": source.assessment_version,
        "blockers": blockers,
        "budget": source.budget.to_dict(),
        "coverage": source.coverage.to_dict(),
        "emergency_stop_recorded": source.emergency_stop_recorded,
        "evidence_refs": evidence_refs,
        "finding_refs": finding_refs,
        "graph_changes": graph_changes,
        "health": source.health.value,
        "mission_state": source.mission_state.value,
        "observed_at": source.observed_at,
        "report_refs": report_refs,
        "schedule_sha256": source.schedule_sha256,
        "scope_sha256": source.scope_sha256,
        "status_sha256": source.status_sha256,
        "workers": workers,
    }


def _source_from_dict(raw: Any, role: ViewRole) -> MissionProjectionInput:
    fields = {
        "approvals",
        "assessment_ref",
        "assessment_version",
        "blockers",
        "budget",
        "coverage",
        "emergency_stop_recorded",
        "evidence_refs",
        "finding_refs",
        "graph_changes",
        "health",
        "mission_state",
        "observed_at",
        "report_refs",
        "schedule_sha256",
        "scope_sha256",
        "status_sha256",
        "workers",
    }
    _exact_fields(raw, fields, "source")
    source = MissionProjectionInput(
        assessment_ref=raw["assessment_ref"],
        assessment_version=raw["assessment_version"],
        mission_state=raw["mission_state"],
        observed_at=raw["observed_at"],
        scope_sha256=raw["scope_sha256"],
        schedule_sha256=raw["schedule_sha256"],
        status_sha256=raw["status_sha256"],
        health=raw["health"],
        coverage=CoverageSnapshot.from_dict(raw["coverage"]),
        budget=BudgetSnapshot.from_dict(raw["budget"]),
        workers=tuple(WorkerSummary.from_dict(value) for value in raw["workers"]),
        approvals=tuple(ApprovalSummary.from_dict(value) for value in raw["approvals"]),
        blockers=tuple(BlockerSummary.from_dict(value) for value in raw["blockers"]),
        graph_changes=tuple(GraphChangeSummary.from_dict(value) for value in raw["graph_changes"]),
        finding_refs=tuple(raw["finding_refs"]),
        evidence_refs=tuple(raw["evidence_refs"]),
        report_refs=tuple(raw["report_refs"]),
        emergency_stop_recorded=raw["emergency_stop_recorded"],
    )
    if _source_to_dict(source, role) != raw:
        raise OperatorConsoleError("source is not the canonical role projection")
    return source


def _sections(role: ViewRole) -> tuple[tuple[str, ...], tuple[str, ...]]:
    all_sections = (
        "approvals",
        "blockers",
        "budgets",
        "controls",
        "coverage",
        "evidence",
        "findings",
        "graph_changes",
        "health",
        "reports",
        "workers",
    )
    visible_by_role = {
        ViewRole.ASSESSMENT_OPERATOR: all_sections,
        ViewRole.INDEPENDENT_CONTROL: all_sections,
        ViewRole.INDEPENDENT_ASSURANCE: tuple(
            value for value in all_sections if value != "controls"
        ),
        ViewRole.EVIDENCE_CUSTODIAN: (
            "budgets",
            "coverage",
            "evidence",
            "findings",
            "graph_changes",
            "health",
            "reports",
        ),
        ViewRole.EXECUTIVE_OBSERVER: ("budgets", "coverage", "health"),
        ViewRole.INCIDENT_RESPONDER: (
            "blockers",
            "budgets",
            "controls",
            "coverage",
            "findings",
            "graph_changes",
            "health",
            "workers",
        ),
    }
    visible = visible_by_role[role]
    return visible, tuple(value for value in all_sections if value not in visible)


def _available_intents(
    role: ViewRole, state: MissionState, stopped: bool
) -> tuple[OperatorIntentKind, ...]:
    if role not in {
        ViewRole.ASSESSMENT_OPERATOR,
        ViewRole.INDEPENDENT_CONTROL,
        ViewRole.INCIDENT_RESPONDER,
    }:
        return ()
    values: list[OperatorIntentKind] = [OperatorIntentKind.ACKNOWLEDGE_BLOCKER]
    if state is MissionState.RUNNING:
        values.extend((OperatorIntentKind.REQUEST_PAUSE, OperatorIntentKind.REQUEST_CANCEL))
    elif state is MissionState.PAUSED:
        values.extend((OperatorIntentKind.REQUEST_RESUME, OperatorIntentKind.REQUEST_CANCEL))
    elif state in {MissionState.DRAFT, MissionState.PENDING_SCOPE, MissionState.READY}:
        values.extend(
            (OperatorIntentKind.REQUEST_APPROVAL_REVIEW, OperatorIntentKind.REQUEST_CANCEL)
        )
    if not stopped and state not in {
        MissionState.COMPLETED,
        MissionState.CANCELLED,
        MissionState.FAILED,
    }:
        values.append(OperatorIntentKind.REQUEST_EMERGENCY_STOP)
    return tuple(sorted(set(values), key=lambda value: value.value))


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = (
        "sha256:"
        + hashlib.sha256(
            canonical_json({"content": dict(body), "domain": domain}).encode("ascii")
        ).hexdigest()
    )
    return f"{prefix}-{digest[7:39].upper()}", digest


def _envelope(raw: Mapping[str, Any], label: str) -> None:
    if raw["schema_version"] != SCHEMA_VERSION:
        raise OperatorConsoleError(f"{label} schema_version is unsupported")
    if raw["no_effects"] != NO_EFFECTS:
        raise OperatorConsoleError(f"{label} no_effects is invalid")


def _exact_fields(raw: Any, expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise OperatorConsoleError(f"{label} fields are invalid")


def _enum(owner: Any, name: str, enum_type: type[StrEnum]) -> None:
    try:
        value = enum_type(getattr(owner, name))
    except (TypeError, ValueError) as exc:
        raise OperatorConsoleError(f"{name} is invalid") from exc
    object.__setattr__(owner, name, value)


def _sha256(value: Any, label: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise OperatorConsoleError(f"{label} must be a sha256 digest")


def _identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise OperatorConsoleError(f"{label} must be a safe identifier")


def _token(value: Any, label: str) -> None:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise OperatorConsoleError(f"{label} must be a token")


def _reference(value: Any, label: str, prefix: str) -> None:
    if (
        not isinstance(value, str)
        or REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(prefix)
    ):
        raise OperatorConsoleError(f"{label} is invalid")


def _utc(value: Any, label: str) -> None:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise OperatorConsoleError(f"{label} must be UTC second precision")


def _safe_text(value: Any, label: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
    ):
        raise OperatorConsoleError(f"{label} is invalid")
    if any(ord(character) < 32 for character in value) or SECRET_RE.search(value):
        raise OperatorConsoleError(f"{label} contains prohibited content")


def _positive_int(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise OperatorConsoleError(f"{label} must be a positive integer")


def _nonnegative_int(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OperatorConsoleError(f"{label} must be a nonnegative integer")


def _bounded_unique(values: Sequence[Any], label: str, key: Any, maximum: int) -> None:
    if not isinstance(values, tuple):
        raise OperatorConsoleError(f"{label} must be a tuple")
    if len(values) > maximum:
        raise OperatorConsoleError(f"{label} exceeds its limit")
    keys = [key(value) for value in values]
    if len(set(keys)) != len(keys):
        raise OperatorConsoleError(f"{label} contains duplicates")


def _validate_json(
    value: Any, label: str, *, depth: int = 0, count: list[int] | None = None
) -> None:
    if depth > 12:
        raise OperatorConsoleError(f"{label} exceeds the nesting limit")
    counter = [0] if count is None else count
    counter[0] += 1
    if counter[0] > 100_000:
        raise OperatorConsoleError(f"{label} exceeds the item limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1, count=counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise OperatorConsoleError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1, count=counter)
        return
    raise OperatorConsoleError(f"{label} contains an unsupported value")
