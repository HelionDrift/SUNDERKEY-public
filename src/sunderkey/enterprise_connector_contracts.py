"""Transport-injected Jira and Microsoft connector contracts.

The module builds vendor-specific, secret-safe requests and normalizes a caller
supplied transport response. It contains no network client, credential resolver,
timer, retry loop, or outbox mutation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar, Protocol

SCHEMA_VERSION = 1
NO_BUILTIN_NETWORK = True
SOURCE_SNAPSHOT_DATE = "2026-09-20"

_REF_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}:[A-Za-z0-9._~:/+-]{1,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_IDEMPOTENCY_RE = re.compile(r"^idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
_SECRET_RE = re.compile(
    r"(?:\b(?:authorization|cookie|password|passwd|secret|token|api[_-]?key)\b\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
_EXPLOIT_RE = re.compile(
    r"(?:<script\b|\bunion\s+select\b|\bcurl\s+https?://|\bwget\s+https?://|"
    r"\b(?:reverse|bind)\s+shell\b)",
    re.IGNORECASE,
)


class EnterpriseConnectorError(ValueError):
    """Raised when a connector record or delivery fails closed."""


class ConnectorKind(StrEnum):
    JIRA_CLOUD = "jira_cloud"
    MICROSOFT_SENTINEL = "microsoft_sentinel"
    SECURITY_COPILOT = "security_copilot"


class ConnectorOperation(StrEnum):
    JIRA_CREATE_ISSUE = "jira_create_issue"
    SENTINEL_SEND_DATA = "sentinel_send_data"
    COPILOT_PUBLISH_PLUGIN = "copilot_publish_plugin"


class DeliveryDisposition(StrEnum):
    SUCCEEDED = "succeeded"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"


_KIND_BY_OPERATION = {
    ConnectorOperation.JIRA_CREATE_ISSUE: ConnectorKind.JIRA_CLOUD,
    ConnectorOperation.SENTINEL_SEND_DATA: ConnectorKind.MICROSOFT_SENTINEL,
    ConnectorOperation.COPILOT_PUBLISH_PLUGIN: ConnectorKind.SECURITY_COPILOT,
}
_REQUIRED_ROUTE_KEYS = {
    ConnectorOperation.JIRA_CREATE_ISSUE: ("issue_type_ref", "project_ref"),
    ConnectorOperation.SENTINEL_SEND_DATA: ("dcr_immutable_ref", "stream_ref"),
    ConnectorOperation.COPILOT_PUBLISH_PLUGIN: (
        "openapi_spec_ref",
        "openapi_spec_sha256",
        "plugin_manifest_ref",
        "plugin_manifest_sha256",
    ),
}
_API_VERSIONS = {
    ConnectorOperation.JIRA_CREATE_ISSUE: "3",
    ConnectorOperation.SENTINEL_SEND_DATA: "2023-01-01",
    ConnectorOperation.COPILOT_PUBLISH_PLUGIN: "3.0.1",
}


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise EnterpriseConnectorError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"kind": kind, "body": dict(body)})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise EnterpriseConnectorError(f"{label} must be an opaque reference")
    _safe_text(value, label, 320)
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise EnterpriseConnectorError(f"{label} must be a sha256 digest")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _CODE_RE.fullmatch(value):
        raise EnterpriseConnectorError(f"{label} is invalid")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EnterpriseConnectorError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EnterpriseConnectorError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise EnterpriseConnectorError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _safe_text(value: Any, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
        or any(ord(character) < 32 for character in value)
    ):
        raise EnterpriseConnectorError(f"{label} must be bounded printable ASCII")
    if _SECRET_RE.search(value):
        raise EnterpriseConnectorError(f"{label} contains secret-like material")
    return value


def _safe_summary(value: Any) -> str:
    text = _safe_text(value, "summary", 500)
    if _EXPLOIT_RE.search(text):
        raise EnterpriseConnectorError("summary contains exploit material")
    return text


def _exact(raw: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise EnterpriseConnectorError(f"{label} fields are invalid")


@dataclass(frozen=True, slots=True)
class RouteParameter:
    name: str
    value: str

    def __post_init__(self) -> None:
        _code(self.name, "route parameter name")
        if self.name.endswith("_sha256"):
            _digest(self.value, self.name)
        else:
            _ref(self.value, self.name)

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> RouteParameter:
        _exact(raw, {"name", "value"}, "route parameter")
        return cls(raw["name"], raw["value"])


@dataclass(frozen=True, slots=True)
class ConnectorBinding:
    tenant_ref: str
    destination_ref: str
    connector_kind: ConnectorKind | str
    operation: ConnectorOperation | str
    endpoint_ref: str
    credential_ref: str
    api_version: str
    route_parameters: tuple[RouteParameter, ...]
    enabled_at: str
    expires_at: str
    binding_id: str = ""
    binding_sha256: str = ""

    KIND: ClassVar[str] = "enterprise_connector_binding"

    def __post_init__(self) -> None:
        for label in ("tenant_ref", "destination_ref", "endpoint_ref", "credential_ref"):
            _ref(getattr(self, label), label)
        try:
            kind = ConnectorKind(self.connector_kind)
            operation = ConnectorOperation(self.operation)
        except (TypeError, ValueError) as exc:
            raise EnterpriseConnectorError("connector kind or operation is invalid") from exc
        object.__setattr__(self, "connector_kind", kind)
        object.__setattr__(self, "operation", operation)
        if _KIND_BY_OPERATION[operation] is not kind:
            raise EnterpriseConnectorError("connector kind does not match operation")
        if self.api_version != _API_VERSIONS[operation]:
            raise EnterpriseConnectorError("connector API version is not the pinned version")
        parameters = tuple(sorted(self.route_parameters, key=lambda item: item.name))
        if len(parameters) != len({item.name for item in parameters}):
            raise EnterpriseConnectorError("route parameter names must be unique")
        if tuple(item.name for item in parameters) != _REQUIRED_ROUTE_KEYS[operation]:
            raise EnterpriseConnectorError("route parameters do not match the operation")
        object.__setattr__(self, "route_parameters", parameters)
        _time(self.enabled_at, "enabled_at")
        _time(self.expires_at, "expires_at")
        if _instant(self.expires_at) <= _instant(self.enabled_at):
            raise EnterpriseConnectorError("expires_at must be later than enabled_at")
        record_id, digest = _identity("ECB", self.KIND, self.body())
        if self.binding_id and self.binding_id != record_id:
            raise EnterpriseConnectorError("binding_id does not match content")
        if self.binding_sha256 and self.binding_sha256 != digest:
            raise EnterpriseConnectorError("binding_sha256 does not match content")
        object.__setattr__(self, "binding_id", record_id)
        object.__setattr__(self, "binding_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "api_version": self.api_version,
            "connector_kind": self.connector_kind.value,
            "credential_ref": self.credential_ref,
            "destination_ref": self.destination_ref,
            "enabled_at": self.enabled_at,
            "endpoint_ref": self.endpoint_ref,
            "expires_at": self.expires_at,
            "operation": self.operation.value,
            "route_parameters": [item.to_dict() for item in self.route_parameters],
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ConnectorBinding:
        fields = {
            "api_version",
            "binding_id",
            "binding_sha256",
            "connector_kind",
            "credential_ref",
            "destination_ref",
            "enabled_at",
            "endpoint_ref",
            "expires_at",
            "kind",
            "operation",
            "route_parameters",
            "schema_version",
            "tenant_ref",
        }
        _exact(raw, fields, cls.KIND)
        if (
            type(raw["schema_version"]) is not int
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["kind"] != cls.KIND
        ):
            raise EnterpriseConnectorError("connector binding metadata is invalid")
        candidate = cls(
            tenant_ref=raw["tenant_ref"],
            destination_ref=raw["destination_ref"],
            connector_kind=raw["connector_kind"],
            operation=raw["operation"],
            endpoint_ref=raw["endpoint_ref"],
            credential_ref=raw["credential_ref"],
            api_version=raw["api_version"],
            route_parameters=tuple(
                RouteParameter.from_dict(item) for item in raw["route_parameters"]
            ),
            enabled_at=raw["enabled_at"],
            expires_at=raw["expires_at"],
            binding_id=raw["binding_id"],
            binding_sha256=raw["binding_sha256"],
        )
        if canonical_json(candidate.to_dict()) != canonical_json(dict(raw)):
            raise EnterpriseConnectorError("connector binding identity is invalid")
        return candidate


@dataclass(frozen=True, slots=True)
class IntegrationProjection:
    event_id: str
    event_sha256: str
    event_type: str
    subject_ref: str
    state: str
    severity: str
    summary: str
    artifact_refs: tuple[str, ...]
    occurred_at: str

    def __post_init__(self) -> None:
        _ref(self.event_id, "event_id")
        _digest(self.event_sha256, "event_sha256")
        _code(self.event_type, "event_type")
        _ref(self.subject_ref, "subject_ref")
        _code(self.state, "state")
        _code(self.severity, "severity")
        object.__setattr__(self, "summary", _safe_summary(self.summary))
        refs = tuple(sorted(set(self.artifact_refs)))
        for item in refs:
            _ref(item, "artifact_ref")
        object.__setattr__(self, "artifact_refs", refs)
        _time(self.occurred_at, "occurred_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_refs": list(self.artifact_refs),
            "event_id": self.event_id,
            "event_sha256": self.event_sha256,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "severity": self.severity,
            "state": self.state,
            "subject_ref": self.subject_ref,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> IntegrationProjection:
        fields = {
            "artifact_refs",
            "event_id",
            "event_sha256",
            "event_type",
            "occurred_at",
            "severity",
            "state",
            "subject_ref",
            "summary",
        }
        _exact(raw, fields, "integration projection")
        return cls(
            event_id=raw["event_id"],
            event_sha256=raw["event_sha256"],
            event_type=raw["event_type"],
            subject_ref=raw["subject_ref"],
            state=raw["state"],
            severity=raw["severity"],
            summary=raw["summary"],
            artifact_refs=tuple(raw["artifact_refs"]),
            occurred_at=raw["occurred_at"],
        )


@dataclass(frozen=True, slots=True)
class ConnectorDeliveryRequest:
    binding_id: str
    binding_sha256: str
    tenant_ref: str
    destination_ref: str
    operation: ConnectorOperation | str
    event: IntegrationProjection
    idempotency_key: str
    method: str
    path_template: str
    body_json: str
    created_at: str
    expires_at: str
    request_id: str = ""
    request_sha256: str = ""

    KIND: ClassVar[str] = "enterprise_connector_delivery_request"

    def __post_init__(self) -> None:
        if not isinstance(self.binding_id, str) or not self.binding_id.startswith("ECB-"):
            raise EnterpriseConnectorError("binding_id is invalid")
        _digest(self.binding_sha256, "binding_sha256")
        _ref(self.tenant_ref, "tenant_ref")
        _ref(self.destination_ref, "destination_ref")
        try:
            operation = ConnectorOperation(self.operation)
        except (TypeError, ValueError) as exc:
            raise EnterpriseConnectorError("operation is invalid") from exc
        object.__setattr__(self, "operation", operation)
        if not isinstance(self.event, IntegrationProjection):
            raise EnterpriseConnectorError("event must be IntegrationProjection")
        if not isinstance(self.idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(
            self.idempotency_key
        ):
            raise EnterpriseConnectorError("idempotency_key is invalid")
        if self.method != "POST":
            raise EnterpriseConnectorError("connector method must be POST")
        _safe_text(self.path_template, "path_template", 256)
        if not self.path_template.startswith("/") or ".." in self.path_template:
            raise EnterpriseConnectorError("path_template is invalid")
        try:
            body = json.loads(self.body_json)
        except json.JSONDecodeError as exc:
            raise EnterpriseConnectorError("body_json is invalid") from exc
        if canonical_json(body) != self.body_json:
            raise EnterpriseConnectorError("body_json must be canonical")
        _reject_sensitive_structure(body)
        _time(self.created_at, "created_at")
        _time(self.expires_at, "expires_at")
        if _instant(self.expires_at) <= _instant(self.created_at):
            raise EnterpriseConnectorError("expires_at must be later than created_at")
        record_id, digest = _identity("ECD", self.KIND, self.body())
        if self.request_id and self.request_id != record_id:
            raise EnterpriseConnectorError("request_id does not match content")
        if self.request_sha256 and self.request_sha256 != digest:
            raise EnterpriseConnectorError("request_sha256 does not match content")
        object.__setattr__(self, "request_id", record_id)
        object.__setattr__(self, "request_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "body_json": self.body_json,
            "created_at": self.created_at,
            "destination_ref": self.destination_ref,
            "event": self.event.to_dict(),
            "expires_at": self.expires_at,
            "idempotency_key": self.idempotency_key,
            "method": self.method,
            "operation": self.operation.value,
            "path_template": self.path_template,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ConnectorDeliveryRequest:
        fields = {
            "binding_id",
            "binding_sha256",
            "body_json",
            "created_at",
            "destination_ref",
            "event",
            "expires_at",
            "idempotency_key",
            "kind",
            "method",
            "operation",
            "path_template",
            "request_id",
            "request_sha256",
            "schema_version",
            "tenant_ref",
        }
        _exact(raw, fields, cls.KIND)
        if (
            type(raw["schema_version"]) is not int
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["kind"] != cls.KIND
        ):
            raise EnterpriseConnectorError("connector request metadata is invalid")
        candidate = cls(
            binding_id=raw["binding_id"],
            binding_sha256=raw["binding_sha256"],
            tenant_ref=raw["tenant_ref"],
            destination_ref=raw["destination_ref"],
            operation=raw["operation"],
            event=IntegrationProjection.from_dict(raw["event"]),
            idempotency_key=raw["idempotency_key"],
            method=raw["method"],
            path_template=raw["path_template"],
            body_json=raw["body_json"],
            created_at=raw["created_at"],
            expires_at=raw["expires_at"],
            request_id=raw["request_id"],
            request_sha256=raw["request_sha256"],
        )
        if canonical_json(candidate.to_dict()) != canonical_json(dict(raw)):
            raise EnterpriseConnectorError("connector request identity is invalid")
        return candidate


def _reject_sensitive_structure(value: Any, label: str = "body") -> None:
    if isinstance(value, Mapping):
        for key, member in value.items():
            if not isinstance(key, str) or _SECRET_RE.search(key):
                raise EnterpriseConnectorError(f"{label} contains a sensitive field")
            _reject_sensitive_structure(member, f"{label}.{key}")
    elif isinstance(value, list):
        for index, member in enumerate(value):
            _reject_sensitive_structure(member, f"{label}[{index}]")
    elif isinstance(value, str):
        _safe_text(value, label, 1024)
        if _EXPLOIT_RE.search(value):
            raise EnterpriseConnectorError(f"{label} contains exploit material")


def _route_map(binding: ConnectorBinding) -> dict[str, str]:
    return {item.name: item.value for item in binding.route_parameters}


def build_connector_delivery_request(
    binding: ConnectorBinding,
    event: IntegrationProjection,
    *,
    idempotency_key: str,
    created_at: str,
    expires_at: str,
) -> ConnectorDeliveryRequest:
    """Build one vendor-specific request without resolving an endpoint or secret."""

    route = _route_map(binding)
    projection = event.to_dict()
    if binding.operation is ConnectorOperation.JIRA_CREATE_ISSUE:
        path = "/rest/api/3/issue"
        body = {
            "fields": {
                "description": {"artifact_refs": projection["artifact_refs"]},
                "issuetype": {"reference": route["issue_type_ref"]},
                "labels": ["sunderkey", projection["severity"]],
                "project": {"reference": route["project_ref"]},
                "summary": projection["summary"],
            },
            "sunderkey_event": {
                "event_id": projection["event_id"],
                "event_sha256": projection["event_sha256"],
                "subject_ref": projection["subject_ref"],
            },
        }
    elif binding.operation is ConnectorOperation.SENTINEL_SEND_DATA:
        path = "/dataCollectionRules/{dcr_immutable_ref}/streams/{stream_ref}"
        body = [
            {
                "ArtifactRefs": projection["artifact_refs"],
                "EventId": projection["event_id"],
                "EventSha256": projection["event_sha256"],
                "EventType": projection["event_type"],
                "Severity": projection["severity"],
                "State": projection["state"],
                "SubjectRef": projection["subject_ref"],
                "Summary": projection["summary"],
                "TimeGenerated": projection["occurred_at"],
            }
        ]
    else:
        path = "/security-copilot/plugins"
        body = {
            "api_version": binding.api_version,
            "event_projection": projection,
            "openapi_spec_ref": route["openapi_spec_ref"],
            "openapi_spec_sha256": route["openapi_spec_sha256"],
            "plugin_manifest_ref": route["plugin_manifest_ref"],
            "plugin_manifest_sha256": route["plugin_manifest_sha256"],
        }
    return ConnectorDeliveryRequest(
        binding_id=binding.binding_id,
        binding_sha256=binding.binding_sha256,
        tenant_ref=binding.tenant_ref,
        destination_ref=binding.destination_ref,
        operation=binding.operation,
        event=event,
        idempotency_key=idempotency_key,
        method="POST",
        path_template=path,
        body_json=canonical_json(body),
        created_at=created_at,
        expires_at=expires_at,
    )


@dataclass(frozen=True, slots=True)
class ConnectorTransportResponse:
    status_code: int
    response_sha256: str
    external_resource_ref: str | None = None
    retry_after_seconds: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status_code, int) or isinstance(self.status_code, bool):
            raise EnterpriseConnectorError("status_code is invalid")
        if not 100 <= self.status_code <= 599:
            raise EnterpriseConnectorError("status_code is out of range")
        _digest(self.response_sha256, "response_sha256")
        if self.external_resource_ref is not None:
            _ref(self.external_resource_ref, "external_resource_ref")
        if self.retry_after_seconds is not None and (
            not isinstance(self.retry_after_seconds, int)
            or isinstance(self.retry_after_seconds, bool)
            or not 1 <= self.retry_after_seconds <= 86_400
        ):
            raise EnterpriseConnectorError("retry_after_seconds is invalid")


class EnterpriseConnectorTransport(Protocol):
    """External boundary that resolves opaque endpoint and credential references."""

    def send(
        self,
        *,
        endpoint_ref: str,
        credential_ref: str,
        request: ConnectorDeliveryRequest,
    ) -> ConnectorTransportResponse: ...


@dataclass(frozen=True, slots=True)
class ConnectorDeliveryObservation:
    request_id: str
    request_sha256: str
    binding_id: str
    binding_sha256: str
    disposition: DeliveryDisposition | str
    status_code: int
    response_sha256: str
    external_resource_ref: str | None
    retry_after_seconds: int | None
    observed_at: str
    observation_id: str = ""
    observation_sha256: str = ""

    KIND: ClassVar[str] = "enterprise_connector_delivery_observation"

    def __post_init__(self) -> None:
        if not self.request_id.startswith("ECD-") or not self.binding_id.startswith("ECB-"):
            raise EnterpriseConnectorError("request or binding identity is invalid")
        _digest(self.request_sha256, "request_sha256")
        _digest(self.binding_sha256, "binding_sha256")
        try:
            disposition = DeliveryDisposition(self.disposition)
        except (TypeError, ValueError) as exc:
            raise EnterpriseConnectorError("delivery disposition is invalid") from exc
        object.__setattr__(self, "disposition", disposition)
        ConnectorTransportResponse(
            status_code=self.status_code,
            response_sha256=self.response_sha256,
            external_resource_ref=self.external_resource_ref,
            retry_after_seconds=self.retry_after_seconds,
        )
        if disposition is DeliveryDisposition.SUCCEEDED and self.external_resource_ref is None:
            raise EnterpriseConnectorError("successful delivery requires an external resource")
        _time(self.observed_at, "observed_at")
        record_id, digest = _identity("ECO", self.KIND, self.body())
        if self.observation_id and self.observation_id != record_id:
            raise EnterpriseConnectorError("observation_id does not match content")
        if self.observation_sha256 and self.observation_sha256 != digest:
            raise EnterpriseConnectorError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_id", record_id)
        object.__setattr__(self, "observation_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "disposition": self.disposition.value,
            "external_resource_ref": self.external_resource_ref,
            "observed_at": self.observed_at,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "retry_after_seconds": self.retry_after_seconds,
            "status_code": self.status_code,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": self.KIND,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            **self.body(),
        }


def _disposition(status_code: int) -> DeliveryDisposition:
    if 200 <= status_code <= 299:
        return DeliveryDisposition.SUCCEEDED
    if status_code in {408, 425, 429} or 500 <= status_code <= 599:
        return DeliveryDisposition.RETRYABLE_FAILURE
    return DeliveryDisposition.PERMANENT_FAILURE


def deliver_with_connector(
    binding: ConnectorBinding,
    request: ConnectorDeliveryRequest,
    transport: EnterpriseConnectorTransport,
    *,
    observed_at: str,
) -> ConnectorDeliveryObservation:
    """Invoke one supplied transport after rechecking all immutable bindings."""

    _time(observed_at, "observed_at")
    if type(binding) is not ConnectorBinding or type(request) is not ConnectorDeliveryRequest:
        raise EnterpriseConnectorError("connector delivery requires native binding and request")
    try:
        binding_document = binding.to_dict()
        request_document = request.to_dict()
        verified_binding = ConnectorBinding.from_dict(binding_document)
        verified_request = ConnectorDeliveryRequest.from_dict(request_document)
    except EnterpriseConnectorError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise EnterpriseConnectorError("connector delivery source replay failed") from exc
    expected_request = build_connector_delivery_request(
        verified_binding,
        verified_request.event,
        idempotency_key=verified_request.idempotency_key,
        created_at=verified_request.created_at,
        expires_at=verified_request.expires_at,
    )
    if canonical_json(request_document) != canonical_json(expected_request.to_dict()):
        raise EnterpriseConnectorError("connector request does not match pinned vendor mapping")
    if (request.binding_id, request.binding_sha256) != (
        binding.binding_id,
        binding.binding_sha256,
    ):
        raise EnterpriseConnectorError("request binding does not match connector")
    if (
        request.tenant_ref != binding.tenant_ref
        or request.destination_ref != binding.destination_ref
    ):
        raise EnterpriseConnectorError("request context does not match connector")
    if request.operation is not binding.operation:
        raise EnterpriseConnectorError("request operation does not match connector")
    now = _instant(observed_at)
    if now < _instant(binding.enabled_at) or now >= _instant(binding.expires_at):
        raise EnterpriseConnectorError("connector binding is not active")
    if now < _instant(request.created_at) or now >= _instant(request.expires_at):
        raise EnterpriseConnectorError("connector request is not active")
    response = transport.send(
        endpoint_ref=binding.endpoint_ref,
        credential_ref=binding.credential_ref,
        request=request,
    )
    if not isinstance(response, ConnectorTransportResponse):
        raise EnterpriseConnectorError("transport returned an invalid response")
    disposition = _disposition(response.status_code)
    if (
        disposition is not DeliveryDisposition.SUCCEEDED
        and response.external_resource_ref is not None
    ):
        raise EnterpriseConnectorError("failed delivery must not claim an external resource")
    return ConnectorDeliveryObservation(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        binding_id=binding.binding_id,
        binding_sha256=binding.binding_sha256,
        disposition=disposition,
        status_code=response.status_code,
        response_sha256=response.response_sha256,
        external_resource_ref=response.external_resource_ref,
        retry_after_seconds=response.retry_after_seconds,
        observed_at=observed_at,
    )


def parse_contract(raw: Mapping[str, Any] | str) -> ConnectorBinding | ConnectorDeliveryRequest:
    document = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(document, Mapping):
        raise EnterpriseConnectorError("connector contract must be an object")
    if document.get("kind") == ConnectorBinding.KIND:
        return ConnectorBinding.from_dict(document)
    if document.get("kind") == ConnectorDeliveryRequest.KIND:
        return ConnectorDeliveryRequest.from_dict(document)
    raise EnterpriseConnectorError("connector contract kind is unsupported")


__all__ = [
    "ConnectorBinding",
    "ConnectorDeliveryObservation",
    "ConnectorDeliveryRequest",
    "ConnectorKind",
    "ConnectorOperation",
    "ConnectorTransportResponse",
    "DeliveryDisposition",
    "EnterpriseConnectorError",
    "EnterpriseConnectorTransport",
    "IntegrationProjection",
    "NO_BUILTIN_NETWORK",
    "RouteParameter",
    "SOURCE_SNAPSHOT_DATE",
    "build_connector_delivery_request",
    "canonical_json",
    "canonical_sha256",
    "deliver_with_connector",
    "parse_contract",
]
