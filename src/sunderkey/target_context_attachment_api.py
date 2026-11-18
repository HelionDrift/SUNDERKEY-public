"""Versioned local API operation for bounded target-context attachment.

Caller-owned bytes are admitted only through the offline target-context parser.
Only the resulting content-addressed bundle is handed to the injected local API
service. This module opens no network connection, accepts no filesystem path,
and supplies no authority, qualification, or target runtime.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .local_api_service import (
    AccessContext,
    LocalApiService,
    Operation,
    ResourceKind,
    ResponseStatus,
    ServiceRequest,
    ServiceResponse,
    canonical_json,
    canonical_sha256,
)
from .target_context import (
    TargetContextBundle,
    TargetContextError,
    TargetContextInput,
    TargetContextKind,
    TargetContextLimits,
    TargetContextProvenance,
    ingest_target_context_inputs,
)

SCHEMA_VERSION = 1
OPERATION = "attach_target_context"
REQUEST_DOMAIN = "sunderkey.target-context-attachment-request.v1"
RECEIPT_DOMAIN = "sunderkey.target-context-attachment-receipt.v1"
MAX_SOURCE_COUNT = 256
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 16 * 1024 * 1024

IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
RECEIPT_ID_RE = re.compile(r"TCR-[0-9A-F]{32}\Z")
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]*\Z")
AUTHORIZATION_REF_RE = re.compile(r"authzref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,246}\Z")
AUDIT_REF_RE = re.compile(r"auditref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z")

NO_CLAIMS = MappingProxyType(
    {
        "authority": "none",
        "execution": "none",
        "filesystem": "none",
        "network": "none",
        "qualification": "none",
        "repository_write": "injected",
        "runtime": "none",
    }
)


class TargetContextAttachmentError(ValueError):
    """Raised when an attachment request or receipt fails closed."""


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise TargetContextAttachmentError(f"{label} fields are invalid")
    return raw


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise TargetContextAttachmentError(f"{label} must be a safe identifier")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise TargetContextAttachmentError(f"{label} must be canonical UTC")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise TargetContextAttachmentError(f"{label} must be a SHA-256 content address")
    return value


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _encode_bytes(content: bytes) -> str:
    return base64.urlsafe_b64encode(content).decode("ascii").rstrip("=")


def _decode_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or BASE64URL_RE.fullmatch(value) is None:
        raise TargetContextAttachmentError("source content_base64url is invalid")
    try:
        content = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TargetContextAttachmentError("source content_base64url is invalid") from exc
    if _encode_bytes(content) != value:
        raise TargetContextAttachmentError("source content_base64url is not canonical")
    return content


@dataclass(frozen=True)
class TargetContextSourceAttachment:
    """One bounded caller-owned byte sequence for local ingestion."""

    name: str
    content: bytes = field(repr=False)
    media_type: str | None = None
    kind: TargetContextKind | str | None = None
    expected_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise TargetContextAttachmentError("source name must be nonempty text")
        if not isinstance(self.content, bytes):
            raise TargetContextAttachmentError("source content must be bytes")
        if len(self.content) > MAX_SOURCE_BYTES:
            raise TargetContextAttachmentError("source exceeds the hard byte limit")
        if self.media_type is not None and not isinstance(self.media_type, str):
            raise TargetContextAttachmentError("source media_type must be text")
        if self.kind is not None:
            try:
                object.__setattr__(self, "kind", TargetContextKind(self.kind))
            except (TypeError, ValueError) as exc:
                raise TargetContextAttachmentError("source kind is invalid") from exc
        if self.expected_sha256 is not None:
            _digest(self.expected_sha256, "source expected_sha256")

    @property
    def content_sha256(self) -> str:
        return "sha256:" + hashlib.sha256(self.content).hexdigest()

    def to_input(self) -> TargetContextInput:
        return TargetContextInput(
            name=self.name,
            content=self.content,
            media_type=self.media_type,
            kind=self.kind,
            expected_sha256=self.expected_sha256,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_base64url": _encode_bytes(self.content),
            "content_sha256": self.content_sha256,
            "expected_sha256": self.expected_sha256,
            "kind": None if self.kind is None else self.kind.value,
            "media_type": self.media_type,
            "name": self.name,
            "size_bytes": len(self.content),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TargetContextSourceAttachment:
        _exact(
            raw,
            {
                "content_base64url",
                "content_sha256",
                "expected_sha256",
                "kind",
                "media_type",
                "name",
                "size_bytes",
            },
            "source attachment",
        )
        content = _decode_bytes(raw["content_base64url"])
        if (
            isinstance(raw["size_bytes"], bool)
            or not isinstance(raw["size_bytes"], int)
            or raw["size_bytes"] != len(content)
        ):
            raise TargetContextAttachmentError("source size does not match its content")
        candidate = cls(
            name=raw["name"],
            content=content,
            media_type=raw["media_type"],
            kind=raw["kind"],
            expected_sha256=raw["expected_sha256"],
        )
        if raw["content_sha256"] != candidate.content_sha256:
            raise TargetContextAttachmentError("source content hash does not match")
        return candidate


@dataclass(frozen=True)
class TargetContextAttachmentRequest:
    """A versioned local request containing bytes or one validated bundle."""

    request_id: str
    access: AccessContext
    requested_at: str
    idempotency_key: str
    mission_id: str
    authority_ref: str
    expected_authorization_ref: str
    expected_authorization_audit_ref: str
    sources: tuple[TargetContextSourceAttachment, ...] = ()
    provenance: TargetContextProvenance | None = None
    limits: TargetContextLimits | None = None
    bundle: TargetContextBundle | None = None

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        if not isinstance(self.access, AccessContext):
            raise TargetContextAttachmentError("access must be an AccessContext")
        _timestamp(self.requested_at, "requested_at")
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise TargetContextAttachmentError("idempotency_key is invalid")
        _identifier(self.mission_id, "mission_id")
        _identifier(self.authority_ref, "authority_ref")
        if (
            not isinstance(self.expected_authorization_ref, str)
            or AUTHORIZATION_REF_RE.fullmatch(self.expected_authorization_ref) is None
        ):
            raise TargetContextAttachmentError("expected_authorization_ref is invalid")
        if (
            not isinstance(self.expected_authorization_audit_ref, str)
            or AUDIT_REF_RE.fullmatch(self.expected_authorization_audit_ref) is None
        ):
            raise TargetContextAttachmentError("expected_authorization_audit_ref is invalid")
        if not isinstance(self.sources, tuple) or not all(
            isinstance(item, TargetContextSourceAttachment) for item in self.sources
        ):
            raise TargetContextAttachmentError("sources must contain source attachments")
        has_sources = bool(self.sources)
        has_bundle = self.bundle is not None
        if has_sources == has_bundle:
            raise TargetContextAttachmentError("request requires exactly one input mode")
        if has_sources:
            if len(self.sources) > MAX_SOURCE_COUNT:
                raise TargetContextAttachmentError("source count exceeds the hard limit")
            if sum(len(item.content) for item in self.sources) > MAX_TOTAL_SOURCE_BYTES:
                raise TargetContextAttachmentError("source bytes exceed the hard total limit")
            if not isinstance(self.provenance, TargetContextProvenance):
                raise TargetContextAttachmentError("byte attachment requires provenance")
            if self.limits is not None and not isinstance(self.limits, TargetContextLimits):
                raise TargetContextAttachmentError("limits must be TargetContextLimits")
        else:
            if self.provenance is not None or self.limits is not None:
                raise TargetContextAttachmentError(
                    "bundle attachment must use the bundle provenance and limits"
                )
            if not isinstance(self.bundle, TargetContextBundle):
                raise TargetContextAttachmentError("bundle input is invalid")
            try:
                verified = TargetContextBundle.from_dict(
                    self.bundle.to_dict(),
                    mission_id=self.mission_id,
                    authority_ref=self.authority_ref,
                )
            except TargetContextError as exc:
                raise TargetContextAttachmentError("bundle binding is invalid") from exc
            object.__setattr__(self, "bundle", verified)

    @property
    def input_mode(self) -> str:
        return "caller_bytes" if self.sources else "context_bundle"

    @property
    def request_sha256(self) -> str:
        return canonical_sha256({"content": self.to_dict(), "domain": REQUEST_DOMAIN})

    def to_dict(self) -> dict[str, Any]:
        return {
            "access": {
                "context_id": self.access.context_id,
                "principal_id": self.access.principal_id,
                "session_ref": self.access.session_ref,
                "tenant_id": self.access.tenant_id,
            },
            "authority_ref": self.authority_ref,
            "bundle": None if self.bundle is None else self.bundle.to_dict(),
            "expected_authorization_audit_ref": self.expected_authorization_audit_ref,
            "expected_authorization_ref": self.expected_authorization_ref,
            "idempotency_key": self.idempotency_key,
            "input_mode": self.input_mode,
            "limits": None if self.limits is None else self.limits.to_dict(),
            "mission_id": self.mission_id,
            "operation": OPERATION,
            "provenance": (None if self.provenance is None else self.provenance.to_dict()),
            "request_id": self.request_id,
            "requested_at": self.requested_at,
            "schema_version": SCHEMA_VERSION,
            "sources": [item.to_dict() for item in self.sources],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TargetContextAttachmentRequest:
        _exact(
            raw,
            {
                "access",
                "authority_ref",
                "bundle",
                "expected_authorization_audit_ref",
                "expected_authorization_ref",
                "idempotency_key",
                "input_mode",
                "limits",
                "mission_id",
                "operation",
                "provenance",
                "request_id",
                "requested_at",
                "schema_version",
                "sources",
            },
            "target context attachment request",
        )
        if raw["schema_version"] != SCHEMA_VERSION or raw["operation"] != OPERATION:
            raise TargetContextAttachmentError("request operation or version is invalid")
        access_raw = _exact(
            raw["access"],
            {"context_id", "principal_id", "session_ref", "tenant_id"},
            "attachment access",
        )
        if not isinstance(raw["sources"], list):
            raise TargetContextAttachmentError("request sources must be a list")
        bundle = None
        if raw["bundle"] is not None:
            try:
                bundle = TargetContextBundle.from_dict(
                    raw["bundle"],
                    mission_id=raw["mission_id"],
                    authority_ref=raw["authority_ref"],
                )
            except TargetContextError as exc:
                raise TargetContextAttachmentError("request bundle is invalid") from exc
        try:
            candidate = cls(
                request_id=raw["request_id"],
                access=AccessContext(**access_raw),
                requested_at=raw["requested_at"],
                idempotency_key=raw["idempotency_key"],
                mission_id=raw["mission_id"],
                authority_ref=raw["authority_ref"],
                expected_authorization_ref=raw["expected_authorization_ref"],
                expected_authorization_audit_ref=raw["expected_authorization_audit_ref"],
                sources=tuple(
                    TargetContextSourceAttachment.from_dict(item) for item in raw["sources"]
                ),
                provenance=(
                    None
                    if raw["provenance"] is None
                    else TargetContextProvenance.from_dict(raw["provenance"])
                ),
                limits=(
                    None if raw["limits"] is None else TargetContextLimits.from_dict(raw["limits"])
                ),
                bundle=bundle,
            )
        except TargetContextError as exc:
            raise TargetContextAttachmentError("request context fields are invalid") from exc
        if candidate.input_mode != raw["input_mode"] or candidate.to_dict() != dict(raw):
            raise TargetContextAttachmentError("request content is not canonical")
        return candidate

    @classmethod
    def from_json(cls, document: str) -> TargetContextAttachmentRequest:
        try:
            raw = json.loads(document)
        except (TypeError, json.JSONDecodeError) as exc:
            raise TargetContextAttachmentError("request is not valid JSON") from exc
        if canonical_json(raw) != document:
            raise TargetContextAttachmentError("request JSON is not canonical")
        return cls.from_dict(raw)

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True)
class TargetContextAttachmentReceipt:
    """Deterministic receipt for one local attachment result."""

    receipt_id: str
    receipt_sha256: str
    attachment_request_sha256: str
    service_request_sha256: str
    idempotency_sha256: str
    request_id: str
    status: str
    bundle_id: str
    bundle_sha256: str
    bundle_status: str
    mission_id: str
    authority_ref: str
    provenance: TargetContextProvenance
    input_count: int
    artifact_count: int
    redaction_count: int
    quarantine_flag_count: int
    resource_version: int
    concurrency_token: str
    authorization_ref: str
    authorization_audit_ref: str
    mutation_audit_ref: str
    integration_event_id: str
    document_json: str = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise TargetContextAttachmentError("receipt document is invalid")
        return value

    def to_json(self) -> str:
        return self.document_json

    @classmethod
    def from_dict(cls, raw: Any) -> TargetContextAttachmentReceipt:
        fields = {
            "artifact_count",
            "attachment_request_sha256",
            "authority_ref",
            "authorization_audit_ref",
            "authorization_ref",
            "bundle_id",
            "bundle_sha256",
            "bundle_status",
            "concurrency_token",
            "effects",
            "idempotency_sha256",
            "input_count",
            "integration_event_id",
            "mission_id",
            "mutation_audit_ref",
            "operation",
            "provenance",
            "quarantine_flag_count",
            "receipt_id",
            "receipt_sha256",
            "redaction_count",
            "request_id",
            "resource_version",
            "schema_version",
            "service_request_sha256",
            "status",
        }
        _exact(raw, fields, "target context attachment receipt")
        if raw["schema_version"] != SCHEMA_VERSION or raw["operation"] != OPERATION:
            raise TargetContextAttachmentError("receipt operation or version is invalid")
        if raw["effects"] != dict(NO_CLAIMS):
            raise TargetContextAttachmentError("receipt effects are invalid")
        if raw["status"] not in {"completed", "replayed"}:
            raise TargetContextAttachmentError("receipt status is invalid")
        if raw["bundle_status"] not in {"accepted", "quarantined"}:
            raise TargetContextAttachmentError("receipt bundle_status is invalid")
        for field_name in (
            "attachment_request_sha256",
            "bundle_sha256",
            "idempotency_sha256",
            "receipt_sha256",
            "service_request_sha256",
        ):
            _digest(raw[field_name], field_name)
        for field_name in (
            "request_id",
            "bundle_id",
            "mission_id",
            "authority_ref",
            "concurrency_token",
            "authorization_ref",
            "authorization_audit_ref",
            "mutation_audit_ref",
            "integration_event_id",
        ):
            _identifier(raw[field_name], field_name)
        for field_name in (
            "input_count",
            "artifact_count",
            "redaction_count",
            "quarantine_flag_count",
            "resource_version",
        ):
            value = raw[field_name]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TargetContextAttachmentError(f"{field_name} is invalid")
        if raw["input_count"] < 1 or raw["artifact_count"] < 1:
            raise TargetContextAttachmentError("receipt counts are invalid")
        if raw["resource_version"] < 1:
            raise TargetContextAttachmentError("resource_version is invalid")
        provenance = TargetContextProvenance.from_dict(raw["provenance"])
        body = {
            key: value for key, value in raw.items() if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_id, expected_sha256 = _identity("TCR", RECEIPT_DOMAIN, body)
        if (
            RECEIPT_ID_RE.fullmatch(raw["receipt_id"]) is None
            or raw["receipt_id"] != expected_id
            or raw["receipt_sha256"] != expected_sha256
        ):
            raise TargetContextAttachmentError("receipt identity does not match content")
        return cls(
            receipt_id=raw["receipt_id"],
            receipt_sha256=raw["receipt_sha256"],
            attachment_request_sha256=raw["attachment_request_sha256"],
            service_request_sha256=raw["service_request_sha256"],
            idempotency_sha256=raw["idempotency_sha256"],
            request_id=raw["request_id"],
            status=raw["status"],
            bundle_id=raw["bundle_id"],
            bundle_sha256=raw["bundle_sha256"],
            bundle_status=raw["bundle_status"],
            mission_id=raw["mission_id"],
            authority_ref=raw["authority_ref"],
            provenance=provenance,
            input_count=raw["input_count"],
            artifact_count=raw["artifact_count"],
            redaction_count=raw["redaction_count"],
            quarantine_flag_count=raw["quarantine_flag_count"],
            resource_version=raw["resource_version"],
            concurrency_token=raw["concurrency_token"],
            authorization_ref=raw["authorization_ref"],
            authorization_audit_ref=raw["authorization_audit_ref"],
            mutation_audit_ref=raw["mutation_audit_ref"],
            integration_event_id=raw["integration_event_id"],
            document_json=canonical_json(dict(raw)),
        )


class TargetContextAttachmentApi:
    """Attach safe local context through an injected LocalApiService."""

    def __init__(self, service: LocalApiService) -> None:
        if not isinstance(service, LocalApiService):
            raise TargetContextAttachmentError("service must be a LocalApiService")
        self._service = service

    def attach(self, request: TargetContextAttachmentRequest) -> TargetContextAttachmentReceipt:
        if not isinstance(request, TargetContextAttachmentRequest):
            raise TargetContextAttachmentError("request is invalid")
        bundle = self._resolve_bundle(request)
        service_request = ServiceRequest(
            request_id=request.request_id,
            operation=Operation.ATTACH_TARGET_CONTEXT,
            access=request.access,
            requested_at=request.requested_at,
            resource_kind=ResourceKind.TARGET_CONTEXT,
            resource_id=bundle.bundle_id,
            payload={"bundle": bundle.to_dict()},
            idempotency_key=request.idempotency_key,
        )
        response = self._service.handle(service_request)
        return self._receipt(request, bundle, service_request, response)

    @staticmethod
    def _resolve_bundle(request: TargetContextAttachmentRequest) -> TargetContextBundle:
        if request.bundle is not None:
            return TargetContextBundle.from_dict(
                request.bundle.to_dict(),
                mission_id=request.mission_id,
                authority_ref=request.authority_ref,
            )
        assert request.provenance is not None
        try:
            return ingest_target_context_inputs(
                tuple(source.to_input() for source in request.sources),
                mission_id=request.mission_id,
                authority_ref=request.authority_ref,
                provenance=request.provenance,
                limits=request.limits,
            )
        except TargetContextError as exc:
            raise TargetContextAttachmentError("source attachment was rejected") from exc

    @staticmethod
    def _receipt(
        request: TargetContextAttachmentRequest,
        bundle: TargetContextBundle,
        service_request: ServiceRequest,
        response: ServiceResponse,
    ) -> TargetContextAttachmentReceipt:
        expected_request_sha256 = service_request.request_sha256
        expected_event_type = (
            f"{ResourceKind.TARGET_CONTEXT.value}.{Operation.ATTACH_TARGET_CONTEXT.value}"
        )
        if (
            not isinstance(response, ServiceResponse)
            or response.request_id != service_request.request_id
            or response.request_sha256 != expected_request_sha256
            or response.status not in {ResponseStatus.COMPLETED, ResponseStatus.REPLAYED}
            or response.resource is None
            or response.mutation_audit_ref is None
            or response.integration_event is None
            or response.authorization_ref != request.expected_authorization_ref
            or response.authorization_audit_ref != request.expected_authorization_audit_ref
            or AUDIT_REF_RE.fullmatch(response.mutation_audit_ref) is None
            or response.resource.resource_kind is not ResourceKind.TARGET_CONTEXT
            or response.resource.resource_id != bundle.bundle_id
            or response.resource.tenant_id != service_request.access.tenant_id
            or response.resource.context_id != service_request.access.context_id
            or dict(response.resource.payload) != {"bundle": bundle.to_dict()}
            or response.mutation_audit_ref not in response.resource.audit_refs
            or response.integration_event.event_type != expected_event_type
            or response.integration_event.tenant_id != service_request.access.tenant_id
            or response.integration_event.context_id != service_request.access.context_id
            or response.integration_event.resource_kind is not ResourceKind.TARGET_CONTEXT
            or response.integration_event.resource_id != bundle.bundle_id
            or response.integration_event.resource_version != response.resource.version
            or response.integration_event.resource_sha256
            != canonical_sha256(response.resource.to_dict())
            or response.integration_event.audit_ref != response.mutation_audit_ref
            or response.integration_event.occurred_at != service_request.requested_at
        ):
            raise TargetContextAttachmentError("local API returned an invalid attachment result")
        idempotency_sha256 = service_request.idempotency_sha256
        assert idempotency_sha256 is not None
        summary = bundle.to_dict()["summary"]
        body = {
            "artifact_count": summary["artifact_count"],
            "attachment_request_sha256": request.request_sha256,
            "authority_ref": bundle.authority_ref,
            "authorization_audit_ref": response.authorization_audit_ref,
            "authorization_ref": response.authorization_ref,
            "bundle_id": bundle.bundle_id,
            "bundle_sha256": bundle.bundle_sha256,
            "bundle_status": bundle.status,
            "concurrency_token": response.resource.concurrency_token,
            "effects": dict(NO_CLAIMS),
            "idempotency_sha256": idempotency_sha256,
            "input_count": summary["input_count"],
            "integration_event_id": response.integration_event.event_id,
            "mission_id": bundle.mission_id,
            "mutation_audit_ref": response.mutation_audit_ref,
            "operation": OPERATION,
            "provenance": bundle.provenance.to_dict(),
            "quarantine_flag_count": summary["quarantine_flag_count"],
            "redaction_count": summary["redaction_count"],
            "request_id": response.request_id,
            "resource_version": response.resource.version,
            "schema_version": SCHEMA_VERSION,
            "service_request_sha256": response.request_sha256,
            "status": response.status.value,
        }
        receipt_id, receipt_sha256 = _identity("TCR", RECEIPT_DOMAIN, body)
        return TargetContextAttachmentReceipt.from_dict(
            {**body, "receipt_id": receipt_id, "receipt_sha256": receipt_sha256}
        )


def target_context_attachment_capability_manifest() -> dict[str, Any]:
    """Return the deterministic local attachment boundary declaration."""

    return {
        "accepted_inputs": ["caller_bytes", "context_bundle"],
        "content_addressed_resource": True,
        "effects": dict(NO_CLAIMS),
        "hard_limits": {
            "max_source_bytes": MAX_SOURCE_BYTES,
            "max_source_count": MAX_SOURCE_COUNT,
            "max_total_source_bytes": MAX_TOTAL_SOURCE_BYTES,
        },
        "operation": OPERATION,
        "raw_content_persisted": False,
        "schema_version": SCHEMA_VERSION,
    }


__all__ = [
    "MAX_SOURCE_BYTES",
    "MAX_SOURCE_COUNT",
    "MAX_TOTAL_SOURCE_BYTES",
    "OPERATION",
    "TargetContextAttachmentApi",
    "TargetContextAttachmentError",
    "TargetContextAttachmentReceipt",
    "TargetContextAttachmentRequest",
    "TargetContextSourceAttachment",
    "target_context_attachment_capability_manifest",
]
