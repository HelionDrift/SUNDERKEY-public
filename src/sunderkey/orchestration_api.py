"""Provider-neutral ASGI surface for the Phase197 orchestration journal.

The application opens no listener, performs no token verification, calls no
target, and dispatches no worker. A trusted host injects an authenticated
principal into the ASGI scope. The sole effect-adjacent mutation only stages a
content-addressed Phase196 action-execution handoff for a later authenticated
worker to resolve and verify.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qs

from .orchestration_journal import (
    MAX_PAGE_SIZE,
    JobKind,
    JobOutcomeCode,
    JobState,
    MessageDirection,
    MessageTopic,
    OrchestrationBusyError,
    OrchestrationConflictError,
    OrchestrationIntegrityError,
    OrchestrationValidationError,
    ProjectionKind,
    SourceHighWater,
    SourceKind,
    SQLiteOrchestrationJournal,
    build_action_execution_intent,
    build_orchestration_job,
    canonical_json,
    loads_json_without_duplicate_keys,
)

API_VERSION = "1.0.0"
MAX_REQUEST_BYTES = 131_072
MAX_HEADER_COUNT = 64
MAX_HEADER_BYTES = 16_384
MAX_BODY_FRAMES = 256
MAX_METHOD_LENGTH = 16
MAX_PATH_LENGTH = 2_048
MAX_QUERY_FIELDS = 64
PRINCIPAL_SCOPE_KEY = "sunderkey.principal"
_API_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_API_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]{0,18})\Z")
_METHOD_RE = re.compile(r"[A-Z]{1,16}\Z")
_PATH_RE = re.compile(r"/[\x20-\x7e]{0,2047}\Z")
_RAW_TOKEN_RE = re.compile(
    r"(?:\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b)"
)
_INLINE_MATERIAL_KEYS = frozenset(
    {
        "adapter",
        "adapter_input",
        "assertion",
        "authorization",
        "credential",
        "credentials",
        "envelope",
        "evidence",
        "key",
        "keys",
        "raw_evidence",
        "secret",
        "token",
        "tokens",
    }
)
_RESERVED_JOB_KINDS = frozenset({JobKind.ACTION_EXECUTION_HANDOFF, JobKind.OUTBOX_DELIVERY})


class AsgiReceive(Protocol):
    async def __call__(self) -> Mapping[str, Any]: ...


class AsgiSend(Protocol):
    async def __call__(self, message: Mapping[str, Any]) -> None: ...


class ApiPermission:
    JOB_SUBMIT = "orchestration.jobs.submit"
    JOB_READ = "orchestration.jobs.read"
    PROJECTION_READ = "orchestration.projections.read"
    ACTION_EXECUTION_HANDOFF_CREATE = "orchestration.action_execution_handoffs.create"
    EVENT_READ = "orchestration.events.read"

    ALL = frozenset(
        {
            JOB_SUBMIT,
            JOB_READ,
            PROJECTION_READ,
            ACTION_EXECUTION_HANDOFF_CREATE,
            EVENT_READ,
        }
    )


@dataclass(frozen=True, slots=True)
class ApiPrincipal:
    tenant_id: str
    subject_id: str
    authentication_context_sha256: str
    permissions: frozenset[str]

    @classmethod
    def from_scope(cls, scope: Mapping[str, Any]) -> ApiPrincipal:
        raw = scope.get(PRINCIPAL_SCOPE_KEY)
        if not isinstance(raw, Mapping) or set(raw) != {
            "authentication_context_sha256",
            "permissions",
            "subject_id",
            "tenant_id",
        }:
            raise OrchestrationApiError(
                401, "authentication_required", "authentication is required"
            )
        permissions = raw["permissions"]
        if (
            not isinstance(permissions, Sequence)
            or isinstance(permissions, (str, bytes))
            or not permissions
        ):
            raise OrchestrationApiError(401, "authentication_required", "authentication is invalid")
        if (
            any(not isinstance(item, str) for item in permissions)
            or len(set(permissions)) != len(permissions)
            or not set(permissions) <= ApiPermission.ALL
        ):
            raise OrchestrationApiError(401, "authentication_required", "authentication is invalid")
        normalized = frozenset(permissions)
        for key in ("tenant_id", "subject_id"):
            value = raw[key]
            if (
                not isinstance(value, str)
                or _API_IDENTIFIER_RE.fullmatch(value) is None
                or ".." in value
            ):
                raise OrchestrationApiError(
                    401, "authentication_required", "authentication is invalid"
                )
        authentication_context_sha256 = raw["authentication_context_sha256"]
        if (
            not isinstance(authentication_context_sha256, str)
            or _API_SHA256_RE.fullmatch(authentication_context_sha256) is None
        ):
            raise OrchestrationApiError(
                401, "authentication_required", "authentication is invalid"
            )
        return cls(
            tenant_id=raw["tenant_id"],
            subject_id=raw["subject_id"],
            authentication_context_sha256=authentication_context_sha256,
            permissions=normalized,
        )


class OrchestrationApiError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _closed_object(
    properties: Mapping[str, Any], required: Sequence[str] | None = None
) -> dict[str, Any]:
    return {
        "additionalProperties": False,
        "properties": dict(properties),
        "required": sorted(properties) if required is None else list(required),
        "type": "object",
    }


def _reject_inline_sensitive_material(value: Any) -> None:
    if isinstance(value, str):
        if _RAW_TOKEN_RE.search(value):
            raise OrchestrationValidationError("request contains raw token material")
        return
    if isinstance(value, list):
        for item in value:
            _reject_inline_sensitive_material(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = key.lower().replace("-", "_") if isinstance(key, str) else ""
            if normalized in _INLINE_MATERIAL_KEYS:
                raise OrchestrationValidationError("request contains inline protected material")
            _reject_inline_sensitive_material(item)


def openapi_document() -> dict[str, Any]:
    """Return deterministic OpenAPI without importing a web framework."""

    digest = {"pattern": r"^sha256:[0-9a-f]{64}$", "type": "string"}
    identifier = {
        "maxLength": 256,
        "minLength": 1,
        "pattern": r"^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$",
        "type": "string",
    }
    timestamp = {
        "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
        "type": "string",
    }
    action_execution_request_id = {
        "pattern": r"^AXR-[0-9A-F]{32}$",
        "type": "string",
    }
    admission_receipt_id = {
        "pattern": r"^AARX-[0-9A-F]{32}$",
        "type": "string",
    }
    source = _closed_object(
        {
            "observed_at": timestamp,
            "source_head_sha256": digest,
            "source_id": identifier,
            "source_kind": {"enum": [item.value for item in SourceKind], "type": "string"},
            "source_revision": {"maximum": 2_147_483_647, "minimum": 0, "type": "integer"},
        }
    )
    sources = {"items": source, "maxItems": 8, "minItems": 1, "type": "array"}
    submit_job = _closed_object(
        {
            "available_at": timestamp,
            "idempotency_key_sha256": digest,
            "input_ref": identifier,
            "input_sha256": digest,
            "job_kind": {
                "enum": [item.value for item in JobKind if item not in _RESERVED_JOB_KINDS],
                "type": "string",
            },
            "lease_seconds": {"maximum": 86_400, "minimum": 5, "type": "integer"},
            "maximum_attempts": {"maximum": 32, "minimum": 1, "type": "integer"},
            "requested_at": timestamp,
            "source_bindings": sources,
            "subject_ref": identifier,
            "tenant_id": identifier,
        }
    )
    action_execution_handoff = _closed_object(
        {
            "action_execute_intent_sha256": digest,
            "action_execution_envelope_ref": identifier,
            "action_execution_envelope_sha256": digest,
            "action_execution_request_id": action_execution_request_id,
            "action_execution_request_sha256": digest,
            "assertion_id": identifier,
            "assertion_sha256": digest,
            "authorization_expires_at": timestamp,
            "authorization_sha256": digest,
            "available_at": timestamp,
            "command_sha256": digest,
            "idempotency_key_sha256": digest,
            "mission_id": identifier,
            "receipt_id": admission_receipt_id,
            "receipt_sha256": digest,
            "requested_at": timestamp,
            "source_bindings": sources,
            "source_bindings_sha256": digest,
            "tenant_id": identifier,
        }
    )
    effects = _closed_object(
        {
            "action_authority": {"const": "none"},
            "authoritative_state": {"const": "unchanged"},
            "completion_inference": {"const": "forbidden"},
            "credential_access": {"const": "none"},
            "network": {"const": "none"},
            "target_interaction": {"const": "none"},
        }
    )
    record_metadata = {
        "effects": effects,
        "schema_version": {"const": 1, "type": "integer"},
    }
    job_record = _closed_object(
        {
            **record_metadata,
            "available_at": timestamp,
            "created_at": timestamp,
            "idempotency_key_sha256": digest,
            "input_ref": identifier,
            "input_sha256": digest,
            "job_id": {"pattern": r"^JOB-[0-9A-F]{32}$", "type": "string"},
            "job_kind": {"enum": [item.value for item in JobKind], "type": "string"},
            "job_sha256": digest,
            "kind": {"const": "sunderkey.orchestration-job.v1"},
            "lease_seconds": {"maximum": 86_400, "minimum": 5, "type": "integer"},
            "maximum_attempts": {"maximum": 32, "minimum": 1, "type": "integer"},
            "source_bindings": sources,
            "subject_ref": identifier,
            "tenant_id": identifier,
        }
    )
    claim_record = _closed_object(
        {
            **record_metadata,
            "attempt_number": {"maximum": 32, "minimum": 1, "type": "integer"},
            "claim_id": {"pattern": r"^JCL-[0-9A-F]{32}$", "type": "string"},
            "claim_sha256": digest,
            "claimed_at": timestamp,
            "expires_at": timestamp,
            "fence_token": {
                "maximum": 2_147_483_647,
                "minimum": 1,
                "type": "integer",
            },
            "job_id": {"pattern": r"^JOB-[0-9A-F]{32}$", "type": "string"},
            "job_sha256": digest,
            "kind": {"const": "sunderkey.orchestration-job-claim.v1"},
            "lease_version": {
                "maximum": 2_147_483_647,
                "minimum": 1,
                "type": "integer",
            },
            "prior_claim_sha256": {"oneOf": [digest, {"type": "null"}]},
            "tenant_id": identifier,
            "worker_id": identifier,
        }
    )
    outcome_record = _closed_object(
        {
            **record_metadata,
            "claim_id": {"pattern": r"^JCL-[0-9A-F]{32}$", "type": "string"},
            "claim_sha256": digest,
            "fence_token": {
                "maximum": 2_147_483_647,
                "minimum": 1,
                "type": "integer",
            },
            "job_id": {"pattern": r"^JOB-[0-9A-F]{32}$", "type": "string"},
            "kind": {"const": "sunderkey.orchestration-job-outcome.v1"},
            "observed_at": timestamp,
            "outcome_code": {
                "enum": [item.value for item in JobOutcomeCode],
                "type": "string",
            },
            "outcome_id": {"pattern": r"^JOU-[0-9A-F]{32}$", "type": "string"},
            "outcome_sha256": digest,
            "result_ref": identifier,
            "result_sha256": digest,
            "retry_available_at": {"oneOf": [timestamp, {"type": "null"}]},
            "tenant_id": identifier,
            "worker_id": identifier,
        }
    )
    message_record = _closed_object(
        {
            **record_metadata,
            "correlation_ref": identifier,
            "direction": {
                "enum": [item.value for item in MessageDirection],
                "type": "string",
            },
            "external_ref": identifier,
            "external_sha256": digest,
            "idempotency_key_sha256": digest,
            "kind": {"const": "sunderkey.orchestration-message.v1"},
            "message_id": {"pattern": r"^MSG-[0-9A-F]{32}$", "type": "string"},
            "message_sha256": digest,
            "recorded_at": timestamp,
            "source_bindings": sources,
            "tenant_id": identifier,
            "topic": {"enum": [item.value for item in MessageTopic], "type": "string"},
        }
    )
    action_execution_intent_record = _closed_object(
        {
            **record_metadata,
            "action_execute_intent_sha256": digest,
            "action_execution_envelope_ref": identifier,
            "action_execution_envelope_sha256": digest,
            "action_execution_request_id": action_execution_request_id,
            "action_execution_request_sha256": digest,
            "assertion_id": identifier,
            "assertion_sha256": digest,
            "authentication_context_sha256": digest,
            "authorization_expires_at": timestamp,
            "authorization_sha256": digest,
            "available_at": timestamp,
            "command_sha256": digest,
            "idempotency_key_sha256": digest,
            "intent_id": {"pattern": r"^AEI-[0-9A-F]{32}$", "type": "string"},
            "intent_sha256": digest,
            "kind": {"const": "sunderkey.action-execution-intent.v1"},
            "mission_id": identifier,
            "receipt_id": admission_receipt_id,
            "receipt_sha256": digest,
            "requested_at": timestamp,
            "requested_by_subject_id": identifier,
            "source_bindings": sources,
            "source_bindings_sha256": digest,
            "tenant_id": identifier,
        }
    )
    job_view = _closed_object(
        {
            "attempt_number": {"maximum": 32, "minimum": 0, "type": "integer"},
            "authority_status": {"const": "not_authoritative"},
            "current_claim": {"oneOf": [claim_record, {"type": "null"}]},
            "fence_token": {
                "maximum": 2_147_483_647,
                "minimum": 0,
                "type": "integer",
            },
            "job": job_record,
            "outcome": {"oneOf": [outcome_record, {"type": "null"}]},
            "revision": {"minimum": 1, "type": "integer"},
            "state": {"enum": [item.value for item in JobState], "type": "string"},
        }
    )
    projection_record = _closed_object(
        {
            **record_metadata,
            "kind": {"const": "sunderkey.orchestration-read-model-projection.v1"},
            "payload": {"maxProperties": 256, "type": "object"},
            "projected_at": timestamp,
            "projection_id": {"pattern": r"^PRJ-[0-9A-F]{32}$", "type": "string"},
            "projection_kind": {
                "enum": [item.value for item in ProjectionKind],
                "type": "string",
            },
            "projection_sha256": digest,
            "projection_status": {"const": "source_bound_cache_only"},
            "projection_version": {
                "maximum": 2_147_483_647,
                "minimum": 1,
                "type": "integer",
            },
            "source_bindings": sources,
            "subject_ref": identifier,
            "tenant_id": identifier,
        }
    )
    submit_response = _closed_object(
        {
            "authority_effect": {"const": "none"},
            "job": job_record,
            "replayed": {"type": "boolean"},
            "status": {"const": "accepted_for_orchestration_only"},
        }
    )
    list_response = _closed_object(
        {
            "items": {"items": job_view, "maxItems": MAX_PAGE_SIZE, "type": "array"},
            "next_after": {
                "oneOf": [
                    {"pattern": r"^JOB-[0-9A-F]{32}$", "type": "string"},
                    {"type": "null"},
                ]
            },
            "truth_source": {"const": "orchestration_journal_only"},
        }
    )
    handoff_response = _closed_object(
        {
            "authority_effect": {"const": "none"},
            "authoritative_reverification_required": {"const": True},
            "intent": action_execution_intent_record,
            "job": job_record,
            "message": message_record,
            "replayed": {"type": "boolean"},
            "status": {"const": "staged_for_authenticated_action_execution_handoff"},
        }
    )
    projection_response = _closed_object(
        {
            "authoritative": {"const": False},
            "projection": projection_record,
            "source_reconciliation_required_for_decisions": {"const": True},
        }
    )
    error = _closed_object(
        {"error": _closed_object({"code": {"type": "string"}, "message": {"type": "string"}})}
    )
    security = [{"injectedPrincipal": []}]

    def json_response(schema: Mapping[str, Any], description: str) -> dict[str, Any]:
        return {
            "content": {"application/json": {"schema": dict(schema)}},
            "description": description,
        }

    error_responses = {
        "400": {
            "content": {"application/json": {"schema": error}},
            "description": "Invalid request",
        },
        "401": {
            "content": {"application/json": {"schema": error}},
            "description": "Authentication required",
        },
        "403": {
            "content": {"application/json": {"schema": error}},
            "description": "Permission denied",
        },
        "409": {"content": {"application/json": {"schema": error}}, "description": "Conflict"},
        "413": {
            "content": {"application/json": {"schema": error}},
            "description": "Request body too large",
        },
        "415": {
            "content": {"application/json": {"schema": error}},
            "description": "Unsupported media type",
        },
        "503": {"content": {"application/json": {"schema": error}}, "description": "Unavailable"},
    }
    return {
        "components": {
            "schemas": {
                "Job": job_record,
                "JobClaim": claim_record,
                "JobOutcome": outcome_record,
                "JobView": job_view,
                "Message": message_record,
                "ActionExecutionHandoffRequest": action_execution_handoff,
                "ActionExecutionIntent": action_execution_intent_record,
                "Projection": projection_record,
                "SourceHighWater": source,
                "SubmitJobRequest": submit_job,
            },
            "securitySchemes": {
                "injectedPrincipal": {
                    "description": "Authenticated principal injected by the deployment host",
                    "scheme": "bearer",
                    "type": "http",
                }
            },
        },
        "info": {
            "description": (
                "Authority-neutral orchestration journal. Mutation endpoints enqueue or record "
                "coordination facts and never authorize actions or infer authoritative completion."
            ),
            "title": "SUNDERKEY Orchestration API",
            "version": API_VERSION,
        },
        "openapi": "3.1.0",
        "paths": {
            "/api/v1/events": {
                "get": {
                    "operationId": "streamOrchestrationEvents",
                    "parameters": [
                        {
                            "in": "header",
                            "name": "Last-Event-ID",
                            "required": False,
                            "schema": {
                                "pattern": r"^JEV-[0-9A-F]{32}$",
                                "type": "string",
                            },
                        },
                        {
                            "in": "query",
                            "name": "limit",
                            "required": False,
                            "schema": {
                                "maximum": MAX_PAGE_SIZE,
                                "minimum": 1,
                                "type": "integer",
                            },
                        },
                    ],
                    "responses": {
                        "200": {
                            "content": {"text/event-stream": {"schema": {"type": "string"}}},
                            "description": "Finite resumable SSE journal page",
                        },
                        **error_responses,
                    },
                    "security": security,
                }
            },
            "/api/v1/jobs": {
                "get": {
                    "operationId": "listOrchestrationJobs",
                    "parameters": [
                        {
                            "in": "query",
                            "name": "after",
                            "required": False,
                            "schema": {
                                "pattern": r"^JOB-[0-9A-F]{32}$",
                                "type": "string",
                            },
                        },
                        {
                            "in": "query",
                            "name": "limit",
                            "required": False,
                            "schema": {
                                "maximum": MAX_PAGE_SIZE,
                                "minimum": 1,
                                "type": "integer",
                            },
                        },
                    ],
                    "responses": {
                        "200": json_response(list_response, "Orchestration job page"),
                        **error_responses,
                    },
                    "security": security,
                },
                "post": {
                    "operationId": "submitOrchestrationJob",
                    "requestBody": {
                        "content": {"application/json": {"schema": submit_job}},
                        "required": True,
                    },
                    "responses": {
                        "200": json_response(submit_response, "Exact replay"),
                        "202": json_response(submit_response, "Accepted for orchestration"),
                        **error_responses,
                    },
                    "security": security,
                },
            },
            "/api/v1/jobs/{job_id}": {
                "get": {
                    "operationId": "getOrchestrationJob",
                    "parameters": [
                        {"in": "path", "name": "job_id", "required": True, "schema": identifier}
                    ],
                    "responses": {
                        "200": json_response(job_view, "Orchestration job view"),
                        "404": json_response(error, "Job not found"),
                        **error_responses,
                    },
                    "security": security,
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "operationId": "getOpenApi",
                    "responses": {"200": json_response({"type": "object"}, "OpenAPI document")},
                }
            },
            "/api/v1/action-execution-handoffs": {
                "post": {
                    "operationId": "createActionExecutionHandoff",
                    "requestBody": {
                        "content": {"application/json": {"schema": action_execution_handoff}},
                        "required": True,
                    },
                    "responses": {
                        "200": json_response(handoff_response, "Exact replay"),
                        "202": json_response(handoff_response, "Staged for handoff"),
                        **error_responses,
                    },
                    "security": security,
                }
            },
            "/api/v1/projections/{projection_kind}/{subject_ref}": {
                "get": {
                    "operationId": "getProjection",
                    "parameters": [
                        {
                            "in": "path",
                            "name": "projection_kind",
                            "required": True,
                            "schema": {
                                "enum": [item.value for item in ProjectionKind],
                                "type": "string",
                            },
                        },
                        {
                            "in": "path",
                            "name": "subject_ref",
                            "required": True,
                            "schema": identifier,
                        },
                    ],
                    "responses": {
                        "200": json_response(
                            projection_response, "Non-authoritative source-bound projection"
                        ),
                        "404": json_response(error, "Projection not found"),
                        **error_responses,
                    },
                    "security": security,
                }
            },
        },
        "servers": [],
    }


def openapi_json() -> str:
    return json.dumps(
        openapi_document(),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


class OrchestrationApiApp:
    """Small ASGI 3 application over an injected orchestration journal."""

    def __init__(
        self,
        journal: SQLiteOrchestrationJournal,
    ) -> None:
        if not isinstance(journal, SQLiteOrchestrationJournal):
            raise TypeError("journal must be a SQLiteOrchestrationJournal")
        self.journal = journal

    async def __call__(
        self, scope: Mapping[str, Any], receive: AsgiReceive, send: AsgiSend
    ) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("orchestration API supports HTTP scopes only")
        try:
            status, headers, body = await self._route(scope, receive)
        except OrchestrationApiError as exc:
            status, headers, body = self._error(exc.status, exc.code, exc.message)
        except OrchestrationConflictError:
            status, headers, body = self._error(
                409, "conflict", "request conflicts with durable state"
            )
        except OrchestrationValidationError:
            status, headers, body = self._error(400, "invalid_request", "request is invalid")
        except (OrchestrationBusyError, OrchestrationIntegrityError):
            status, headers, body = self._error(
                503, "service_unavailable", "service is unavailable"
            )
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def _route(
        self, scope: Mapping[str, Any], receive: AsgiReceive
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        method = scope.get("method")
        path = scope.get("path")
        if (
            not isinstance(method, str)
            or len(method) > MAX_METHOD_LENGTH
            or _METHOD_RE.fullmatch(method) is None
            or not isinstance(path, str)
            or len(path) > MAX_PATH_LENGTH
            or _PATH_RE.fullmatch(path) is None
        ):
            raise OrchestrationApiError(400, "invalid_request", "request metadata is invalid")
        headers = self._headers(scope)
        if path == "/api/v1/openapi.json" and method == "GET":
            return self._json_document(200, openapi_json())
        principal = ApiPrincipal.from_scope(scope)
        query = self._query(scope)
        if path == "/api/v1/jobs" and method == "POST":
            self._require(principal, ApiPermission.JOB_SUBMIT)
            body = await self._body(receive, headers)
            return self._submit_job(principal, body)
        if path == "/api/v1/jobs" and method == "GET":
            self._require(principal, ApiPermission.JOB_READ)
            return self._list_jobs(principal, query)
        if path.startswith("/api/v1/jobs/") and method == "GET":
            self._require(principal, ApiPermission.JOB_READ)
            return self._get_job(principal, path.removeprefix("/api/v1/jobs/"))
        if path == "/api/v1/action-execution-handoffs" and method == "POST":
            self._require(principal, ApiPermission.ACTION_EXECUTION_HANDOFF_CREATE)
            body = await self._body(receive, headers)
            return self._create_action_execution_handoff(principal, body)
        if path == "/api/v1/events" and method == "GET":
            self._require(principal, ApiPermission.EVENT_READ)
            return self._events(principal, headers, query)
        prefix = "/api/v1/projections/"
        if path.startswith(prefix) and method == "GET":
            self._require(principal, ApiPermission.PROJECTION_READ)
            parts = path.removeprefix(prefix).split("/", 1)
            if len(parts) != 2:
                raise OrchestrationApiError(404, "not_found", "resource was not found")
            return self._projection(principal, parts[0], parts[1])
        raise OrchestrationApiError(404, "not_found", "resource was not found")

    @staticmethod
    def _require(principal: ApiPrincipal, permission: str) -> None:
        if permission not in principal.permissions:
            raise OrchestrationApiError(403, "permission_denied", "permission is required")

    @staticmethod
    def _headers(scope: Mapping[str, Any]) -> dict[str, str]:
        raw = scope.get("headers", [])
        if not isinstance(raw, Sequence) or len(raw) > MAX_HEADER_COUNT:
            raise OrchestrationApiError(400, "invalid_request", "request headers are invalid")
        result: dict[str, str] = {}
        total = 0
        for pair in raw:
            if not isinstance(pair, Sequence) or len(pair) != 2:
                raise OrchestrationApiError(400, "invalid_request", "request headers are invalid")
            name, value = pair
            if not isinstance(name, bytes) or not isinstance(value, bytes):
                raise OrchestrationApiError(400, "invalid_request", "request headers are invalid")
            total += len(name) + len(value)
            try:
                key = name.decode("ascii").lower()
                text = value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise OrchestrationApiError(
                    400, "invalid_request", "request headers are invalid"
                ) from exc
            if _HEADER_NAME_RE.fullmatch(key) is None or any(
                ord(character) < 32 or ord(character) == 127 for character in text
            ):
                raise OrchestrationApiError(400, "invalid_request", "request headers are invalid")
            if key in result:
                raise OrchestrationApiError(400, "invalid_request", "duplicate header is invalid")
            result[key] = text
        if total > MAX_HEADER_BYTES:
            raise OrchestrationApiError(400, "invalid_request", "request headers are too large")
        return result

    @staticmethod
    def _query(scope: Mapping[str, Any]) -> dict[str, str]:
        raw = scope.get("query_string", b"")
        if not isinstance(raw, bytes) or len(raw) > 4096:
            raise OrchestrationApiError(400, "invalid_request", "query string is invalid")
        try:
            parsed = parse_qs(
                raw.decode("ascii"),
                keep_blank_values=True,
                max_num_fields=MAX_QUERY_FIELDS,
                strict_parsing=True,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise OrchestrationApiError(400, "invalid_request", "query string is invalid") from exc
        if any(len(values) != 1 for values in parsed.values()):
            raise OrchestrationApiError(400, "invalid_request", "duplicate query value is invalid")
        return {key: values[0] for key, values in parsed.items()}

    @staticmethod
    async def _body(receive: AsgiReceive, headers: Mapping[str, str]) -> Mapping[str, Any]:
        if headers.get("content-type") != "application/json":
            raise OrchestrationApiError(
                415, "unsupported_media_type", "application/json is required"
            )
        chunks = bytearray()
        frames = 0
        while True:
            message = await receive()
            frames += 1
            if frames > MAX_BODY_FRAMES:
                raise OrchestrationApiError(413, "body_too_large", "request body is too large")
            if not isinstance(message, Mapping):
                raise OrchestrationApiError(400, "invalid_request", "request body is invalid")
            if message.get("type") == "http.disconnect":
                raise OrchestrationApiError(400, "invalid_request", "request was disconnected")
            if message.get("type") != "http.request":
                raise OrchestrationApiError(400, "invalid_request", "request body is invalid")
            body = message.get("body", b"")
            more_body = message.get("more_body", False)
            if not isinstance(body, bytes) or not isinstance(more_body, bool):
                raise OrchestrationApiError(400, "invalid_request", "request body is invalid")
            chunks.extend(body)
            if len(chunks) > MAX_REQUEST_BYTES:
                raise OrchestrationApiError(413, "body_too_large", "request body is too large")
            if not more_body:
                break
        try:
            value = loads_json_without_duplicate_keys(bytes(chunks))
        except OrchestrationValidationError as exc:
            raise OrchestrationApiError(400, "invalid_request", "request body is invalid") from exc
        if not isinstance(value, Mapping):
            raise OrchestrationApiError(400, "invalid_request", "request body must be an object")
        try:
            canonical_json(value)
            _reject_inline_sensitive_material(value)
        except OrchestrationValidationError as exc:
            raise OrchestrationApiError(400, "invalid_request", "request body is invalid") from exc
        return value

    @staticmethod
    def _sources(raw: Any) -> tuple[SourceHighWater, ...]:
        if not isinstance(raw, list):
            raise OrchestrationValidationError("source_bindings must be an array")
        return tuple(SourceHighWater.from_dict(item) for item in raw)

    def _submit_job(
        self, principal: ApiPrincipal, body: Mapping[str, Any]
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        fields = {
            "available_at",
            "idempotency_key_sha256",
            "input_ref",
            "input_sha256",
            "job_kind",
            "lease_seconds",
            "maximum_attempts",
            "requested_at",
            "source_bindings",
            "subject_ref",
            "tenant_id",
        }
        if set(body) != fields or body["tenant_id"] != principal.tenant_id:
            raise OrchestrationValidationError("job submission fields are invalid")
        if not isinstance(body["job_kind"], str):
            raise OrchestrationValidationError("job kind is invalid")
        if body["job_kind"] in {item.value for item in _RESERVED_JOB_KINDS}:
            raise OrchestrationValidationError("reserved job kind requires a specialized path")
        job = build_orchestration_job(
            tenant_id=body["tenant_id"],
            job_kind=body["job_kind"],
            subject_ref=body["subject_ref"],
            input_ref=body["input_ref"],
            input_sha256=body["input_sha256"],
            source_bindings=self._sources(body["source_bindings"]),
            idempotency_key_sha256=body["idempotency_key_sha256"],
            created_at=body["requested_at"],
            available_at=body["available_at"],
            maximum_attempts=body["maximum_attempts"],
            lease_seconds=body["lease_seconds"],
        )
        result = self.journal.submit_job(job)
        return self._json(
            200 if result.replayed else 202,
            {
                "authority_effect": "none",
                "job": result.record.to_dict(),
                "replayed": result.replayed,
                "status": "accepted_for_orchestration_only",
            },
        )

    def _list_jobs(
        self, principal: ApiPrincipal, query: Mapping[str, str]
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        if set(query) - {"after", "limit"}:
            raise OrchestrationValidationError("job query fields are invalid")
        limit = self._decimal(query.get("limit", "50"), "job query limit", 1, MAX_PAGE_SIZE)
        jobs = self.journal.list_jobs(
            principal.tenant_id, after_job_id=query.get("after"), limit=limit
        )
        return self._json(
            200,
            {
                "items": [item.to_dict() for item in jobs],
                "next_after": None if len(jobs) < limit else jobs[-1].job.job_id,
                "truth_source": "orchestration_journal_only",
            },
        )

    def _get_job(
        self, principal: ApiPrincipal, job_id: str
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        view = self.journal.get_job(principal.tenant_id, job_id)
        if view is None:
            raise OrchestrationApiError(404, "not_found", "job was not found")
        return self._json(200, view.to_dict())

    def _create_action_execution_handoff(
        self, principal: ApiPrincipal, body: Mapping[str, Any]
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
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
            "idempotency_key_sha256",
            "mission_id",
            "receipt_id",
            "receipt_sha256",
            "requested_at",
            "source_bindings",
            "source_bindings_sha256",
            "tenant_id",
        }
        if set(body) != fields or body["tenant_id"] != principal.tenant_id:
            raise OrchestrationValidationError("action execution handoff fields are invalid")
        now = body["requested_at"]
        sources = self._sources(body["source_bindings"])
        intent = build_action_execution_intent(
            tenant_id=body["tenant_id"],
            mission_id=body["mission_id"],
            action_execution_envelope_ref=body["action_execution_envelope_ref"],
            action_execution_envelope_sha256=body["action_execution_envelope_sha256"],
            command_sha256=body["command_sha256"],
            action_execution_request_id=body["action_execution_request_id"],
            action_execution_request_sha256=body["action_execution_request_sha256"],
            receipt_id=body["receipt_id"],
            receipt_sha256=body["receipt_sha256"],
            action_execute_intent_sha256=body["action_execute_intent_sha256"],
            assertion_id=body["assertion_id"],
            assertion_sha256=body["assertion_sha256"],
            authorization_sha256=body["authorization_sha256"],
            authorization_expires_at=body["authorization_expires_at"],
            source_bindings_sha256=body["source_bindings_sha256"],
            source_bindings=sources,
            available_at=body["available_at"],
            requested_at=now,
            idempotency_key_sha256=body["idempotency_key_sha256"],
            requested_by_subject_id=principal.subject_id,
            authentication_context_sha256=principal.authentication_context_sha256,
        )
        message_result, job_result, intent_result = (
            self.journal.enqueue_action_execution_handoff(intent)
        )
        return self._json(
            200 if message_result.replayed else 202,
            {
                "authority_effect": "none",
                "authoritative_reverification_required": True,
                "intent": intent_result.record.to_dict(),
                "job": job_result.record.to_dict(),
                "message": message_result.record.to_dict(),
                "replayed": message_result.replayed,
                "status": "staged_for_authenticated_action_execution_handoff",
            },
        )

    def _projection(
        self, principal: ApiPrincipal, kind: str, subject_ref: str
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        projection = self.journal.get_projection(principal.tenant_id, kind, subject_ref)
        if projection is None:
            raise OrchestrationApiError(404, "not_found", "projection was not found")
        return self._json(
            200,
            {
                "authoritative": False,
                "projection": projection.to_dict(),
                "source_reconciliation_required_for_decisions": True,
            },
        )

    def _events(
        self, principal: ApiPrincipal, headers: Mapping[str, str], query: Mapping[str, str]
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        if set(query) - {"limit"}:
            raise OrchestrationValidationError("event query fields are invalid")
        last = headers.get("last-event-id")
        try:
            limit = self._decimal(query.get("limit", "100"), "event limit", 1, MAX_PAGE_SIZE)
            events = self.journal.events_after_id(
                principal.tenant_id, after_event_id=last, limit=limit
            )
        except OrchestrationValidationError as exc:
            raise OrchestrationApiError(
                400, "invalid_event_cursor", "event cursor is invalid"
            ) from exc
        chunks: list[str] = []
        for item in events:
            event = item["event"]
            chunks.append(
                f"id: {event['event_id']}\n"
                f"event: {event['event_type']}\n"
                f"data: {canonical_json(event)}\n\n"
            )
        if not chunks:
            chunks.append(": no-new-events\n\n")
        return (
            200,
            [
                (b"cache-control", b"no-store, no-cache, no-transform"),
                (b"content-type", b"text/event-stream; charset=utf-8"),
                (b"x-content-type-options", b"nosniff"),
            ],
            "".join(chunks).encode("ascii"),
        )

    @staticmethod
    def _json(status: int, value: Any) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        return OrchestrationApiApp._json_document(status, canonical_json(value))

    @staticmethod
    def _decimal(value: str, label: str, minimum: int, maximum: int) -> int:
        if not isinstance(value, str) or _DECIMAL_RE.fullmatch(value) is None:
            raise OrchestrationValidationError(f"{label} is invalid")
        parsed = int(value)
        if not minimum <= parsed <= maximum:
            raise OrchestrationValidationError(f"{label} is invalid")
        return parsed

    @staticmethod
    def _json_document(status: int, document: str) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        body = document.encode("ascii")
        return (
            status,
            [
                (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"content-type", b"application/json"),
                (b"x-content-type-options", b"nosniff"),
            ],
            body,
        )

    @staticmethod
    def _error(
        status: int, code: str, message: str
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        return OrchestrationApiApp._json(status, {"error": {"code": code, "message": message}})


OPENAPI_SHA256 = "sha256:" + hashlib.sha256(openapi_json().encode("ascii")).hexdigest()


__all__ = [
    "API_VERSION",
    "ApiPermission",
    "ApiPrincipal",
    "MAX_REQUEST_BYTES",
    "OPENAPI_SHA256",
    "OrchestrationApiApp",
    "OrchestrationApiError",
    "PRINCIPAL_SCOPE_KEY",
    "openapi_document",
    "openapi_json",
]
