"""Deterministic text console client for verified local API projections.

The client only constructs read requests, consumes an injected transport, and
prepares no-effect intent request objects. It does not open sockets,
authenticate principals, persist records, publish intents, or execute actions.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from sunderkey.local_api_service import (
    AccessContext,
    Operation,
    ResourceKind,
    ResourceRecord,
    ResponseStatus,
    ServiceRequest,
    ServiceResponse,
)
from sunderkey.local_api_service import canonical_sha256 as service_sha256
from sunderkey.operator_console_projection import (
    OperatorConsoleError,
    OperatorConsoleProjection,
    OperatorIntentKind,
    OperatorIntentRequest,
    ViewRole,
    build_operator_intent_request,
)

SCHEMA_VERSION = 1
RECEIPT_DOMAIN = "sunderkey.operator-console-client-receipt.v1"
NO_EFFECTS = {
    "authentication": "external",
    "authorization": "external",
    "credential_access": "none",
    "execution": "none",
    "intent_publication": "none",
    "network": "none_by_client",
    "persistence": "none",
    "transport": "injected",
}

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
CONCURRENCY_RE = re.compile(r"ct:[0-9a-f]{64}\Z")
CURSOR_RE = re.compile(r"cursor:[A-Za-z0-9_-]+\.[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
RECEIPT_ID_RE = re.compile(r"OCC-[0-9A-F]{32}\Z")
MAX_RENDERED_TEXT = 1_000_000


class OperatorConsoleClientError(ValueError):
    """Raised when console input cannot be verified safely."""

    def __init__(self, code: str, message: str) -> None:
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None:
            raise ValueError("console error code is invalid")
        super().__init__(message)
        self.code = code


class OperatorConsoleTransport(Protocol):
    """Injected request transport. Implementations own all external effects."""

    def send(self, request: ServiceRequest) -> ServiceResponse: ...


@dataclass(frozen=True)
class ProjectionItemBinding:
    resource_id: str
    resource_version: int
    concurrency_token: str
    payload_sha256: str
    projection_id: str
    projection_sha256: str
    assessment_ref: str
    assessment_version: int

    def __post_init__(self) -> None:
        _identifier(self.resource_id, "binding resource_id")
        _positive_int(self.resource_version, "binding resource_version")
        if CONCURRENCY_RE.fullmatch(self.concurrency_token) is None:
            _error("receipt_invalid", "binding concurrency_token is invalid")
        _digest(self.payload_sha256, "binding payload_sha256")
        if self.resource_id != self.projection_id:
            _error("receipt_invalid", "binding resource and projection identities differ")
        if re.fullmatch(r"OCP-[0-9A-F]{32}", self.projection_id) is None:
            _error("receipt_invalid", "binding projection_id is invalid")
        _digest(self.projection_sha256, "binding projection_sha256")
        if not self.assessment_ref.startswith("assessmentref:"):
            _error("receipt_invalid", "binding assessment_ref is invalid")
        _identifier(self.assessment_ref, "binding assessment_ref")
        _positive_int(self.assessment_version, "binding assessment_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "assessment_version": self.assessment_version,
            "concurrency_token": self.concurrency_token,
            "payload_sha256": self.payload_sha256,
            "projection_id": self.projection_id,
            "projection_sha256": self.projection_sha256,
            "resource_id": self.resource_id,
            "resource_version": self.resource_version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ProjectionItemBinding:
        expected = {
            "assessment_ref",
            "assessment_version",
            "concurrency_token",
            "payload_sha256",
            "projection_id",
            "projection_sha256",
            "resource_id",
            "resource_version",
        }
        _exact_fields(raw, expected, "item binding")
        return cls(**raw)


@dataclass(frozen=True)
class OperatorConsoleInteractionReceipt:
    receipt_id: str
    receipt_sha256: str
    request_id: str
    request_sha256: str
    response_sha256: str
    operation: Operation | str
    tenant_id: str
    context_id: str
    principal_id: str
    view_role: ViewRole | str
    requested_at: str
    input_cursor: str | None
    page_size: int | None
    next_cursor: str | None
    authorization_ref: str
    authorization_audit_ref: str
    items: tuple[ProjectionItemBinding, ...]

    def __post_init__(self) -> None:
        try:
            operation = Operation(self.operation)
            role = ViewRole(self.view_role)
        except (TypeError, ValueError) as exc:
            raise OperatorConsoleClientError(
                "receipt_invalid", "receipt operation or role is invalid"
            ) from exc
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "view_role", role)
        if operation not in {Operation.GET_RESOURCE, Operation.LIST_RESOURCES}:
            _error("receipt_invalid", "receipt operation is not read-only")
        for name in ("request_id", "tenant_id", "context_id", "principal_id"):
            _identifier(getattr(self, name), f"receipt {name}")
        _digest(self.request_sha256, "receipt request_sha256")
        _digest(self.response_sha256, "receipt response_sha256")
        _utc(self.requested_at, "receipt requested_at")
        _optional_cursor(self.input_cursor, "receipt input_cursor")
        _optional_cursor(self.next_cursor, "receipt next_cursor")
        for name in ("authorization_ref", "authorization_audit_ref"):
            _identifier(getattr(self, name), f"receipt {name}")
        if not self.authorization_ref.startswith("authzref:"):
            _error("receipt_invalid", "receipt authorization_ref is invalid")
        if not self.authorization_audit_ref.startswith("auditref:"):
            _error("receipt_invalid", "receipt authorization_audit_ref is invalid")
        if not isinstance(self.items, tuple) or len(self.items) > 100:
            _error("receipt_invalid", "receipt items are invalid")
        ids = [item.resource_id for item in self.items]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            _error("receipt_invalid", "receipt items are not stable and unique")
        if operation is Operation.GET_RESOURCE:
            if self.input_cursor is not None or self.page_size is not None:
                _error("receipt_invalid", "get receipt carries pagination")
            if self.next_cursor is not None or len(self.items) != 1:
                _error("receipt_invalid", "get receipt must bind one item")
        else:
            if isinstance(self.page_size, bool) or not isinstance(self.page_size, int):
                _error("receipt_invalid", "list receipt page_size is invalid")
            if not 1 <= self.page_size <= 100 or len(self.items) > self.page_size:
                _error("receipt_invalid", "list receipt exceeds its page boundary")
            if self.next_cursor is not None and not self.items:
                _error("receipt_invalid", "empty receipt cannot advertise another page")
        expected_id, expected_sha256 = _receipt_identity(self._body())
        if self.receipt_id != expected_id or self.receipt_sha256 != expected_sha256:
            _error("receipt_invalid", "receipt identity does not match content")

    def _body(self) -> dict[str, Any]:
        return {
            "authorization_audit_ref": self.authorization_audit_ref,
            "authorization_ref": self.authorization_ref,
            "context_id": self.context_id,
            "input_cursor": self.input_cursor,
            "items": [item.to_dict() for item in self.items],
            "next_cursor": self.next_cursor,
            "operation": self.operation.value,
            "page_size": self.page_size,
            "principal_id": self.principal_id,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "requested_at": self.requested_at,
            "response_sha256": self.response_sha256,
            "tenant_id": self.tenant_id,
            "view_role": self.view_role.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "no_effects": dict(NO_EFFECTS),
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    @property
    def document(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> OperatorConsoleInteractionReceipt:
        expected = {
            "authorization_audit_ref",
            "authorization_ref",
            "context_id",
            "input_cursor",
            "items",
            "next_cursor",
            "no_effects",
            "operation",
            "page_size",
            "principal_id",
            "receipt_id",
            "receipt_sha256",
            "request_id",
            "request_sha256",
            "requested_at",
            "response_sha256",
            "schema_version",
            "tenant_id",
            "view_role",
        }
        _exact_fields(raw, expected, "receipt")
        if raw["schema_version"] != SCHEMA_VERSION or raw["no_effects"] != NO_EFFECTS:
            _error("receipt_invalid", "receipt envelope is invalid")
        values = {
            key: value
            for key, value in raw.items()
            if key not in {"schema_version", "no_effects", "items"}
        }
        return cls(
            **values,
            items=tuple(ProjectionItemBinding.from_dict(value) for value in raw["items"]),
        )


@dataclass(frozen=True)
class OperatorConsoleInteraction:
    projections: tuple[OperatorConsoleProjection, ...]
    next_cursor: str | None
    receipt: OperatorConsoleInteractionReceipt


class OperatorConsoleClient:
    """Read-only console client with in-memory replay detection."""

    def __init__(
        self,
        transport: OperatorConsoleTransport,
        access: AccessContext,
        view_role: ViewRole | str,
    ) -> None:
        try:
            role = ViewRole(view_role)
        except (TypeError, ValueError) as exc:
            raise OperatorConsoleClientError("role_invalid", "view role is invalid") from exc
        self._transport = transport
        self._access = access
        self._view_role = role
        self._request_ids: set[str] = set()
        self._response_sha256s: set[str] = set()
        self._accepted_projections: set[tuple[str, str]] = set()

    @property
    def view_role(self) -> ViewRole:
        return self._view_role

    def get_projection(
        self, *, resource_id: str, request_id: str, requested_at: str
    ) -> OperatorConsoleInteraction:
        request = ServiceRequest(
            request_id=request_id,
            operation=Operation.GET_RESOURCE,
            access=self._access,
            requested_at=requested_at,
            resource_kind=ResourceKind.OPERATOR_PROJECTION,
            resource_id=resource_id,
        )
        return self._send(request)

    def list_projections(
        self,
        *,
        request_id: str,
        requested_at: str,
        page_size: int,
        cursor: str | None = None,
    ) -> OperatorConsoleInteraction:
        request = ServiceRequest(
            request_id=request_id,
            operation=Operation.LIST_RESOURCES,
            access=self._access,
            requested_at=requested_at,
            resource_kind=ResourceKind.OPERATOR_PROJECTION,
            cursor=cursor,
            page_size=page_size,
        )
        return self._send(request)

    def prepare_intent(
        self,
        projection: OperatorConsoleProjection,
        *,
        intent_kind: OperatorIntentKind | str,
        requested_at: str,
        idempotency_key: str,
        rationale: str,
    ) -> OperatorIntentRequest:
        _validate_projection(projection, self._view_role)
        binding = (projection.projection_id, projection.projection_sha256)
        if binding not in self._accepted_projections:
            _error("projection_unverified", "projection was not accepted by this client")
        try:
            intent = OperatorIntentKind(intent_kind)
        except (TypeError, ValueError) as exc:
            raise OperatorConsoleClientError("intent_invalid", "intent kind is invalid") from exc
        if intent not in projection.available_intents:
            _error("intent_unadvertised", "projection does not advertise this intent")
        return build_operator_intent_request(
            assessment_ref=projection.source.assessment_ref,
            expected_assessment_version=projection.source.assessment_version,
            intent_kind=intent,
            principal_id=self._access.principal_id,
            requested_at=requested_at,
            idempotency_key=idempotency_key,
            rationale=rationale,
        )

    def _send(self, request: ServiceRequest) -> OperatorConsoleInteraction:
        if request.request_id in self._request_ids:
            _error("request_replay", "request_id was already consumed")
        self._request_ids.add(request.request_id)
        try:
            response = self._transport.send(request)
        except OperatorConsoleClientError:
            raise
        except Exception as exc:
            raise OperatorConsoleClientError(
                "transport_failed", "the injected transport did not return a response"
            ) from exc
        projections, records, next_cursor = _validate_response(request, response, self._view_role)
        response_sha256 = service_sha256(response.to_dict())
        if response_sha256 in self._response_sha256s:
            _error("response_replay", "response was already consumed")
        receipt = _build_receipt(
            request, response, records, projections, next_cursor, self._view_role
        )
        self._response_sha256s.add(response_sha256)
        for projection in projections:
            self._accepted_projections.add((projection.projection_id, projection.projection_sha256))
        return OperatorConsoleInteraction(projections, next_cursor, receipt)


def parse_operator_console_receipt(document: str) -> OperatorConsoleInteractionReceipt:
    """Parse canonical receipt JSON and reject altered or noncanonical input."""

    try:
        raw = json.loads(document)
    except (TypeError, json.JSONDecodeError) as exc:
        raise OperatorConsoleClientError("receipt_invalid", "receipt is not valid JSON") from exc
    if canonical_json(raw) != document:
        _error("receipt_invalid", "receipt JSON is not canonical")
    return OperatorConsoleInteractionReceipt.from_dict(raw)


def render_projection(projection: OperatorConsoleProjection) -> str:
    """Render one verified projection as deterministic plain text."""

    _validate_projection(projection, projection.view_role)
    source = projection.source
    lines = [
        "SUNDERKEY Operator Console",
        "==========================",
        f"Mission: {source.assessment_ref}",
        f"Version: {source.assessment_version}",
        f"Role: {projection.view_role.value}",
        f"State: {source.mission_state.value.upper()}",
        f"Health: {source.health.value.upper()}",
        f"Observed: {source.observed_at}",
        "Authorization: External approval required for every intent",
    ]
    visible = set(projection.visible_sections)
    if "coverage" in visible:
        value = source.coverage
        lines.extend(
            (
                "",
                "Coverage",
                "--------",
                f"Completed: {value.completed} of {value.total}",
                f"Running: {value.running}",
                f"Blocked: {value.blocked}",
                f"Queued: {value.queued}",
            )
        )
    if "budgets" in visible:
        lines.extend(("", "Budget", "------"))
        for label, counter in (
            ("Requests", source.budget.requests),
            ("Cost units", source.budget.cost_units),
            ("Tokens", source.budget.tokens),
            ("Tool calls", source.budget.tool_calls),
            ("Worker minutes", source.budget.worker_minutes),
            ("Storage bytes", source.budget.storage_bytes),
        ):
            lines.append(f"{label}: {counter.consumed} of {counter.limit}")
    if "workers" in visible:
        lines.extend(("", f"Workers [{len(source.workers)}]", "-------"))
        if not source.workers:
            lines.append("No workers are visible for this mission.")
        for worker in source.workers:
            lines.append(
                f"- {worker.worker_ref}: state={worker.state.value.upper()} "
                f"health={worker.health.value.upper()} profile={worker.specialist_profile_id}"
            )
    if "approvals" in visible:
        lines.extend(("", f"Approvals [{len(source.approvals)}]", "---------"))
        if not source.approvals:
            lines.append("No approvals are visible for this mission.")
        for approval in source.approvals:
            lines.append(
                f"- {approval.approval_ref}: state={approval.state.upper()} "
                f"tier={approval.action_tier} action={approval.action_kind}"
            )
    if "blockers" in visible:
        lines.extend(("", f"Attention [{len(source.blockers)}]", "---------"))
        if not source.blockers:
            lines.append("No blockers are reported.")
        for blocker in source.blockers:
            lines.append(
                f"- {blocker.severity.value.upper()} {blocker.code}: "
                f"{blocker.detail} [owner={blocker.owner_role}]"
            )
    if "graph_changes" in visible:
        lines.extend(("", f"Graph changes [{len(source.graph_changes)}]", "-------------"))
        if not source.graph_changes:
            lines.append("No graph changes are reported.")
        for change in source.graph_changes:
            lines.append(
                f"- {change.graph_ref}: +{change.nodes_added} nodes, "
                f"{change.nodes_updated} updated, +{change.edges_added} edges, "
                f"{change.conflicts} conflicts"
            )
    for section, values, label in (
        ("findings", source.finding_refs, "Findings"),
        ("evidence", source.evidence_refs, "Evidence"),
        ("reports", source.report_refs, "Reports"),
    ):
        if section in visible:
            lines.extend(("", f"{label} [{len(values)}]", "-" * len(label)))
            lines.extend(f"- {value}" for value in values)
            if not values:
                lines.append(f"No {label.lower()} are visible for this mission.")
    if "controls" in visible:
        lines.extend(("", "Intent requests", "---------------"))
        if not projection.available_intents:
            lines.append("No intent requests are available in the current state.")
        else:
            lines.extend(f"- {value.value}" for value in projection.available_intents)
        lines.append("Preparing an intent does not authorize, publish, or execute it.")
    lines.extend(
        (
            "",
            "Redacted sections: " + (", ".join(projection.redacted_sections) or "none"),
        )
    )
    rendered = "\n".join(lines) + "\n"
    _safe_display_text(rendered, "rendered projection", allow_newlines=True)
    return rendered


def render_empty_state(view_role: ViewRole | str) -> str:
    """Render an explicit empty state for an accessible text interface."""

    try:
        role = ViewRole(view_role)
    except (TypeError, ValueError) as exc:
        raise OperatorConsoleClientError("role_invalid", "view role is invalid") from exc
    return (
        "SUNDERKEY Operator Console\n"
        "==========================\n"
        "Status: EMPTY\n"
        f"Role: {role.value}\n"
        "Message: No verified mission projections are available.\n"
        "Action: Confirm tenant and context selection, then refresh with a new request ID.\n"
    )


def render_error_state(error: OperatorConsoleClientError) -> str:
    """Render a stable error state without reflecting untrusted input."""

    if not isinstance(error, OperatorConsoleClientError):
        _error("error_invalid", "error state requires a console client error")
    return (
        "SUNDERKEY Operator Console\n"
        "==========================\n"
        "Status: ERROR\n"
        f"Code: {error.code}\n"
        "Message: Operator data could not be verified.\n"
        "Action: Preserve the request receipt and retry with a new request ID.\n"
    )


def operator_console_client_manifest() -> dict[str, Any]:
    return {
        "capability_package_id": "P5.3",
        "effects": dict(NO_EFFECTS),
        "operations": [Operation.GET_RESOURCE.value, Operation.LIST_RESOURCES.value],
        "projection_resource_kind": ResourceKind.OPERATOR_PROJECTION.value,
        "schema_version": SCHEMA_VERSION,
        "work_queue_id": "WQ-008",
    }


def canonical_json(value: Any) -> str:
    _validate_json(value, "value")
    try:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
    except (TypeError, ValueError) as exc:
        raise OperatorConsoleClientError(
            "canonicalization_failed", "value cannot be canonicalized"
        ) from exc


def _validate_response(
    request: ServiceRequest, response: ServiceResponse, role: ViewRole
) -> tuple[tuple[OperatorConsoleProjection, ...], tuple[ResourceRecord, ...], str | None]:
    if not isinstance(response, ServiceResponse):
        _error("response_invalid", "transport returned an invalid response type")
    if (
        response.request_id != request.request_id
        or response.request_sha256 != request.request_sha256
    ):
        _error("response_rebound", "response is not bound to the request")
    if response.status is not ResponseStatus.COMPLETED:
        _error("response_replay", "read response must be newly completed")
    if response.mutation_audit_ref is not None or response.integration_event is not None:
        _error("response_effect", "read response reports a mutation effect")
    if request.operation is Operation.GET_RESOURCE:
        if response.resource is None or response.page is not None:
            _error("response_invalid", "get response shape is invalid")
        if response.resource.resource_id != request.resource_id:
            _error("response_rebound", "get response differs from the requested resource")
        records = (response.resource,)
        next_cursor = None
    else:
        if response.page is None or response.resource is not None:
            _error("response_invalid", "list response shape is invalid")
        records = response.page.items
        next_cursor = response.page.next_cursor
        if len(records) > (request.page_size or 0):
            _error("response_invalid", "list response exceeds requested page size")
        resource_ids = [record.resource_id for record in records]
        if resource_ids != sorted(resource_ids) or len(resource_ids) != len(set(resource_ids)):
            _error("response_invalid", "list response is not stable and unique")
        _optional_cursor(next_cursor, "response next_cursor")
        if next_cursor is not None and not records:
            _error("response_invalid", "empty response cannot advertise another page")
    projections: list[OperatorConsoleProjection] = []
    assessment_refs: set[str] = set()
    for record in records:
        projection = _parse_record(record, request, role)
        if projection.source.assessment_ref in assessment_refs:
            _error("response_invalid", "response repeats an assessment projection")
        assessment_refs.add(projection.source.assessment_ref)
        projections.append(projection)
    return tuple(projections), tuple(records), next_cursor


def _parse_record(
    record: ResourceRecord, request: ServiceRequest, role: ViewRole
) -> OperatorConsoleProjection:
    if (
        record.resource_kind is not ResourceKind.OPERATOR_PROJECTION
        or record.tenant_id != request.access.tenant_id
        or record.context_id != request.access.context_id
    ):
        _error("record_cross_context", "projection record is outside the request context")
    if service_sha256(dict(record.payload)) != record.payload_sha256:
        _error("record_tampered", "projection record payload digest is invalid")
    try:
        projection = OperatorConsoleProjection.from_dict(dict(record.payload))
    except (OperatorConsoleError, TypeError, ValueError) as exc:
        raise OperatorConsoleClientError(
            "projection_malformed", "projection payload is invalid"
        ) from exc
    _validate_projection(projection, role)
    if record.resource_id != projection.projection_id:
        _error("projection_rebound", "projection identity does not match its resource")
    return projection


def _validate_projection(projection: OperatorConsoleProjection, role: ViewRole) -> None:
    if not isinstance(projection, OperatorConsoleProjection):
        _error("projection_malformed", "projection type is invalid")
    if projection.view_role is not role:
        _error("projection_role_mismatch", "projection role does not match the client")
    try:
        rebuilt = OperatorConsoleProjection.from_dict(projection.to_dict())
    except (OperatorConsoleError, TypeError, ValueError) as exc:
        raise OperatorConsoleClientError(
            "projection_malformed", "projection cannot be revalidated"
        ) from exc
    if rebuilt != projection:
        _error("projection_malformed", "projection is not canonical")
    _safe_projection_strings(projection.to_dict())


def _safe_projection_strings(value: Any) -> None:
    if isinstance(value, str):
        _safe_display_text(value, "projection text")
        return
    if isinstance(value, list):
        for item in value:
            _safe_projection_strings(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _safe_display_text(key, "projection field")
            _safe_projection_strings(item)


def _safe_display_text(value: Any, label: str, *, allow_newlines: bool = False) -> None:
    if not isinstance(value, str) or len(value) > MAX_RENDERED_TEXT:
        _error("unsafe_text", f"{label} is invalid")
    if any(
        ord(character) < 32 and not (allow_newlines and character == "\n") for character in value
    ):
        _error("unsafe_text", f"{label} contains terminal control characters")
    if any(ord(character) > 126 for character in value):
        _error("unsafe_text", f"{label} must use printable ASCII")
    if "\x1b" in value or "\r" in value or "\t" in value:
        _error("unsafe_text", f"{label} contains terminal control characters")


def _build_receipt(
    request: ServiceRequest,
    response: ServiceResponse,
    records: Sequence[ResourceRecord],
    projections: Sequence[OperatorConsoleProjection],
    next_cursor: str | None,
    role: ViewRole,
) -> OperatorConsoleInteractionReceipt:
    items = tuple(
        ProjectionItemBinding(
            resource_id=record.resource_id,
            resource_version=record.version,
            concurrency_token=record.concurrency_token,
            payload_sha256=record.payload_sha256,
            projection_id=projection.projection_id,
            projection_sha256=projection.projection_sha256,
            assessment_ref=projection.source.assessment_ref,
            assessment_version=projection.source.assessment_version,
        )
        for record, projection in zip(records, projections, strict=True)
    )
    body = {
        "authorization_audit_ref": response.authorization_audit_ref,
        "authorization_ref": response.authorization_ref,
        "context_id": request.access.context_id,
        "input_cursor": request.cursor,
        "items": [item.to_dict() for item in items],
        "next_cursor": next_cursor,
        "operation": request.operation.value,
        "page_size": request.page_size,
        "principal_id": request.access.principal_id,
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "requested_at": request.requested_at,
        "response_sha256": service_sha256(response.to_dict()),
        "tenant_id": request.access.tenant_id,
        "view_role": role.value,
    }
    if any(projection.view_role is not role for projection in projections):
        _error("projection_role_mismatch", "response mixes projection roles")
    receipt_id, receipt_sha256 = _receipt_identity(body)
    return OperatorConsoleInteractionReceipt(
        receipt_id=receipt_id,
        receipt_sha256=receipt_sha256,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_sha256=body["response_sha256"],
        operation=request.operation,
        tenant_id=request.access.tenant_id,
        context_id=request.access.context_id,
        principal_id=request.access.principal_id,
        view_role=role,
        requested_at=request.requested_at,
        input_cursor=request.cursor,
        page_size=request.page_size,
        next_cursor=next_cursor,
        authorization_ref=response.authorization_ref,
        authorization_audit_ref=response.authorization_audit_ref,
        items=items,
    )


def _receipt_identity(body: Mapping[str, Any]) -> tuple[str, str]:
    digest = (
        "sha256:"
        + hashlib.sha256(
            canonical_json({"content": dict(body), "domain": RECEIPT_DOMAIN}).encode("ascii")
        ).hexdigest()
    )
    return "OCC-" + digest[7:39].upper(), digest


def _error(code: str, message: str) -> None:
    raise OperatorConsoleClientError(code, message)


def _identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        _error("receipt_invalid", f"{label} is invalid")


def _digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _error("receipt_invalid", f"{label} is invalid")


def _positive_int(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _error("receipt_invalid", f"{label} is invalid")


def _utc(value: Any, label: str) -> None:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        _error("receipt_invalid", f"{label} is invalid")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise OperatorConsoleClientError("receipt_invalid", f"{label} is invalid") from exc


def _optional_cursor(value: Any, label: str) -> None:
    if value is not None and (not isinstance(value, str) or CURSOR_RE.fullmatch(value) is None):
        _error("receipt_invalid", f"{label} is invalid")


def _exact_fields(raw: Any, expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        _error("receipt_invalid", f"{label} fields are invalid")


def _validate_json(
    value: Any, label: str, *, depth: int = 0, count: list[int] | None = None
) -> None:
    if depth > 12:
        _error("canonicalization_failed", f"{label} exceeds the nesting limit")
    counter = [0] if count is None else count
    counter[0] += 1
    if counter[0] > 100_000:
        _error("canonicalization_failed", f"{label} exceeds the item limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1, count=counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _error("canonicalization_failed", f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1, count=counter)
        return
    _error("canonicalization_failed", f"{label} has an unsupported value")
