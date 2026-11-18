"""Fail-closed assessment transport contracts and deterministic offline mocks.

This module defines protocol boundaries. Its concrete classes only replay caller
supplied scripts. They do not open network connections, drive a browser, invoke
programs, or resolve credential references.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from .signed_scope_compiler import (
    ScopeBudgetState,
    ScopeDecision,
    SignedAssessmentScope,
    VerifiedAssessmentScope,
    evaluate_request,
)
from .types import ActionTier

SCHEMA_VERSION = 1
TRANSCRIPT_DOMAIN = "sunderkey.assessment-transport-transcript.v1"
STEP_DOMAIN = "sunderkey.assessment-transport-step.v1"

NO_EFFECTS = MappingProxyType(
    {
        "authority": "none",
        "browser": "none",
        "credential_values": "none",
        "deployment": "none",
        "execution": "none",
        "network": "none",
        "qualification": "none",
        "routing": "none",
        "shell": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
CREDENTIAL_REF_RE = re.compile(r"credref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z")
EVIDENCE_REF_RE = re.compile(
    r"(?:evidref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}|sha256:[0-9a-f]{64})\Z"
)
TRANSCRIPT_ID_RE = re.compile(r"ATT-[0-9A-F]{32}\Z")
HEADER_NAME_RE = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}\Z")
MIME_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bbasic\s+[A-Za-z0-9+/=]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"
    r")",
    re.IGNORECASE,
)

FORBIDDEN_SECRET_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    }
)

DEFAULT_REQUEST_HEADERS = (
    "accept",
    "accept-language",
    "content-type",
    "if-match",
    "if-none-match",
    "user-agent",
    "x-request-id",
)
DEFAULT_RESPONSE_HEADERS = (
    "cache-control",
    "content-language",
    "content-length",
    "content-type",
    "etag",
    "location",
    "x-request-id",
)


class TransportContractError(ValueError):
    """Raised when an adapter contract fails closed."""


class HttpMethod(StrEnum):
    """Closed HTTP method vocabulary."""

    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class BrowserAction(StrEnum):
    """Closed browser action vocabulary with no code evaluation or uploads."""

    NAVIGATE = "navigate"
    CLICK_SELECTOR = "click_selector"
    FILL_REFERENCE = "fill_reference"
    SUBMIT = "submit"
    WAIT_CONDITION = "wait_condition"
    READ_METADATA = "read_metadata"
    SCREENSHOT_REFERENCE = "screenshot_reference"


class AuthenticationMode(StrEnum):
    """Declared target authentication modes."""

    BASIC = "basic"
    BEARER = "bearer"
    FORM_LOGIN = "form_login"
    TOTP_REFERENCE = "totp_reference"
    MAGIC_LINK_REFERENCE = "magic_link_reference"
    SOCIAL_LOGIN_REFERENCE = "social_login_reference"
    MULTI_PRINCIPAL_TEST_ACCOUNTS = "multi_principal_test_accounts"


class AdapterHealthState(StrEnum):
    """States emitted by preflight and continuous health checks."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class TransportStepState(StrEnum):
    """Terminal state of one requested adapter step."""

    COMPLETED = "completed"
    CANCELLED = "cancelled"
    STOPPED = "stopped"
    HEALTH_PAUSED = "health_paused"


class IntentKind(StrEnum):
    """Typed transcript request kinds."""

    HTTP_EXCHANGE = "http_exchange"
    BROWSER_ACTION = "browser_action"
    TARGET_SESSION_ACQUISITION = "target_session_acquisition"


@dataclass(frozen=True)
class AdapterIdentity:
    """Stable adapter implementation identity."""

    adapter_id: str
    version: str

    def __post_init__(self) -> None:
        _identifier(self.adapter_id, "adapter_id")
        _version(self.version, "adapter version")

    def to_dict(self) -> dict[str, str]:
        return {"adapter_id": self.adapter_id, "version": self.version}


@dataclass(frozen=True)
class MimeLimit:
    """Per-MIME response byte ceiling."""

    mime_type: str
    max_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "mime_type", _mime(self.mime_type, "MIME limit mime_type"))
        _positive_int(self.max_bytes, "MIME limit max_bytes", 100_000_000)

    def to_dict(self) -> dict[str, Any]:
        return {"max_bytes": self.max_bytes, "mime_type": self.mime_type}


@dataclass(frozen=True)
class TransportBudget:
    """Request, byte, redirect, and scope-counter ceilings."""

    max_steps: int
    max_request_bytes: int
    max_response_bytes: int
    max_total_request_bytes: int
    max_total_response_bytes: int
    max_redirects: int
    mime_limits: tuple[MimeLimit, ...]
    requests_completed: int = 0
    requests_active: int = 0
    requests_in_current_minute: int = 0

    def __post_init__(self) -> None:
        _positive_int(self.max_steps, "budget max_steps", 100_000)
        _positive_int(self.max_request_bytes, "budget max_request_bytes", 100_000_000)
        _positive_int(self.max_response_bytes, "budget max_response_bytes", 100_000_000)
        _positive_int(
            self.max_total_request_bytes,
            "budget max_total_request_bytes",
            1_000_000_000,
        )
        _positive_int(
            self.max_total_response_bytes,
            "budget max_total_response_bytes",
            1_000_000_000,
        )
        _non_negative_int(self.max_redirects, "budget max_redirects", 32)
        for name in (
            "requests_completed",
            "requests_active",
            "requests_in_current_minute",
        ):
            _non_negative_int(getattr(self, name), f"budget {name}", 1_000_000_000)
        if not isinstance(self.mime_limits, tuple) or not self.mime_limits:
            raise TransportContractError("budget mime_limits must be a non-empty tuple")
        if not all(isinstance(item, MimeLimit) for item in self.mime_limits):
            raise TransportContractError("budget mime_limits entries must be MimeLimit values")
        ordered = tuple(sorted(self.mime_limits, key=lambda item: item.mime_type))
        if len({item.mime_type for item in ordered}) != len(ordered):
            raise TransportContractError("budget MIME types must be unique")
        object.__setattr__(self, "mime_limits", ordered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_redirects": self.max_redirects,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
            "max_steps": self.max_steps,
            "max_total_request_bytes": self.max_total_request_bytes,
            "max_total_response_bytes": self.max_total_response_bytes,
            "mime_limits": [item.to_dict() for item in self.mime_limits],
            "requests_active": self.requests_active,
            "requests_completed": self.requests_completed,
            "requests_in_current_minute": self.requests_in_current_minute,
        }

    def mime_ceiling(self, mime_type: str) -> int | None:
        normalized = _mime(mime_type, "response MIME type")
        for item in self.mime_limits:
            if item.mime_type == normalized:
                return item.max_bytes
        return None


@dataclass(frozen=True)
class HeaderPolicy:
    """Explicit request and response header allowlists and redaction set."""

    request_allowlist: tuple[str, ...] = DEFAULT_REQUEST_HEADERS
    response_allowlist: tuple[str, ...] = DEFAULT_RESPONSE_HEADERS
    response_redactions: tuple[str, ...] = ("etag", "x-request-id")

    def __post_init__(self) -> None:
        request = _header_names(self.request_allowlist, "request allowlist")
        response = _header_names(self.response_allowlist, "response allowlist")
        redactions = _header_names(self.response_redactions, "response redactions", empty=True)
        if FORBIDDEN_SECRET_HEADERS.intersection(request | response):
            raise TransportContractError("secret headers cannot appear in header allowlists")
        if not redactions <= response:
            raise TransportContractError("response redactions must be in the response allowlist")
        object.__setattr__(self, "request_allowlist", tuple(sorted(request)))
        object.__setattr__(self, "response_allowlist", tuple(sorted(response)))
        object.__setattr__(self, "response_redactions", tuple(sorted(redactions)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_allowlist": list(self.request_allowlist),
            "response_allowlist": list(self.response_allowlist),
            "response_redactions": list(self.response_redactions),
        }


@dataclass(frozen=True)
class AssessmentBinding:
    """Authority, task, technique, evidence, stop, budget, and adapter binding."""

    scope_id: str
    scope_sha256: str
    task_id: str
    technique_id: str
    authority_refs: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    impact_tier: ActionTier | str
    decision_at: str
    stop_conditions: tuple[str, ...]
    adapter: AdapterIdentity
    budget: TransportBudget

    def __post_init__(self) -> None:
        _identifier(self.scope_id, "binding scope_id")
        _sha256(self.scope_sha256, "binding scope_sha256")
        _identifier(self.task_id, "binding task_id")
        _identifier(self.technique_id, "binding technique_id")
        object.__setattr__(
            self,
            "authority_refs",
            _refs(self.authority_refs, "binding authority_refs", allow_empty=False),
        )
        evidence = _refs(self.evidence_hashes, "binding evidence_hashes", allow_empty=False)
        for item in evidence:
            _sha256(item, "binding evidence hash")
        object.__setattr__(self, "evidence_hashes", evidence)
        try:
            tier = ActionTier(self.impact_tier)
        except (TypeError, ValueError) as exc:
            raise TransportContractError("binding impact_tier is invalid") from exc
        object.__setattr__(self, "impact_tier", tier)
        _utc(self.decision_at, "binding decision_at")
        if not isinstance(self.stop_conditions, tuple) or not self.stop_conditions:
            raise TransportContractError("binding stop_conditions must be a non-empty tuple")
        stops = tuple(
            sorted({_safe_text(item, "stop condition", 256) for item in self.stop_conditions})
        )
        object.__setattr__(self, "stop_conditions", stops)
        if not isinstance(self.adapter, AdapterIdentity):
            raise TransportContractError("binding adapter must be an AdapterIdentity")
        if not isinstance(self.budget, TransportBudget):
            raise TransportContractError("binding budget must be a TransportBudget")

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter.to_dict(),
            "authority_refs": list(self.authority_refs),
            "budget": self.budget.to_dict(),
            "decision_at": self.decision_at,
            "evidence_hashes": list(self.evidence_hashes),
            "impact_tier": self.impact_tier.value,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "stop_conditions": list(self.stop_conditions),
            "task_id": self.task_id,
            "technique_id": self.technique_id,
        }


@dataclass(frozen=True)
class HeaderField:
    """One non-secret request header."""

    name: str
    value: str

    def __post_init__(self) -> None:
        normalized = _header_name(self.name, "header name")
        if normalized in FORBIDDEN_SECRET_HEADERS:
            raise TransportContractError("secret headers are forbidden")
        object.__setattr__(self, "name", normalized)
        object.__setattr__(self, "value", _safe_text(self.value, "header value", 2048))

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True)
class ObservedHeader:
    """One allowlisted response header, optionally value-redacted."""

    name: str
    value: str | None
    redacted: bool

    def __post_init__(self) -> None:
        normalized = _header_name(self.name, "observed header name")
        if normalized in FORBIDDEN_SECRET_HEADERS:
            raise TransportContractError("secret headers are forbidden")
        object.__setattr__(self, "name", normalized)
        if self.redacted:
            if self.value is not None:
                raise TransportContractError("redacted header must not retain its value")
        elif self.value is None:
            raise TransportContractError("unredacted header requires a value")
        else:
            object.__setattr__(self, "value", _safe_text(self.value, "observed header value", 2048))

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "redacted": self.redacted, "value": self.value}


@dataclass(frozen=True)
class CookieMetadata:
    """Cookie attributes without cookie values."""

    name: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str

    def __post_init__(self) -> None:
        _safe_text(self.name, "cookie name", 128)
        _safe_text(self.domain, "cookie domain", 255)
        _safe_text(self.path, "cookie path", 1024)
        if not isinstance(self.secure, bool) or not isinstance(self.http_only, bool):
            raise TransportContractError("cookie secure and http_only must be booleans")
        if self.same_site not in {"strict", "lax", "none", "unspecified"}:
            raise TransportContractError("cookie same_site is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "http_only": self.http_only,
            "name": self.name,
            "path": self.path,
            "same_site": self.same_site,
            "secure": self.secure,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CookieMetadata:
        _exact_fields(
            raw,
            {"domain", "http_only", "name", "path", "same_site", "secure"},
            "cookie metadata",
        )
        return cls(**raw)


@dataclass(frozen=True)
class SessionBinding:
    """An isolated target session and its required principal label."""

    session_id: str
    principal_label: str

    def __post_init__(self) -> None:
        _identifier(self.session_id, "session_id")
        _identifier(self.principal_label, "principal_label")

    def to_dict(self) -> dict[str, str]:
        return {"principal_label": self.principal_label, "session_id": self.session_id}


@dataclass(frozen=True)
class HttpRequestIntent:
    """A body-free, hash-bound HTTP exchange request."""

    binding: AssessmentBinding
    sequence: int
    method: HttpMethod | str
    url: str
    headers: tuple[HeaderField, ...] = ()
    request_size_bytes: int = 0
    body_sha256: str | None = None
    session: SessionBinding | None = None

    def __post_init__(self) -> None:
        _intent_common(self.binding, self.sequence)
        try:
            method = HttpMethod(self.method)
        except (TypeError, ValueError) as exc:
            raise TransportContractError("unknown HTTP method") from exc
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "url", _safe_url(self.url, "HTTP intent URL"))
        _non_negative_int(self.request_size_bytes, "request_size_bytes", 100_000_000)
        if self.request_size_bytes:
            if self.body_sha256 is None:
                raise TransportContractError("non-empty request requires body_sha256")
            _sha256(self.body_sha256, "request body_sha256")
        elif self.body_sha256 is not None:
            raise TransportContractError("empty request must not declare body_sha256")
        headers = _request_headers(self.headers)
        object.__setattr__(self, "headers", headers)
        if self.session is not None and not isinstance(self.session, SessionBinding):
            raise TransportContractError("HTTP session must be a SessionBinding")

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "body_sha256": self.body_sha256,
            "headers": [item.to_dict() for item in self.headers],
            "kind": IntentKind.HTTP_EXCHANGE.value,
            "method": self.method.value,
            "request_size_bytes": self.request_size_bytes,
            "sequence": self.sequence,
            "session": None if self.session is None else self.session.to_dict(),
            "url": self.url,
        }

    @property
    def intent_sha256(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True)
class BrowserActionIntent:
    """One safe browser action against an already isolated session."""

    binding: AssessmentBinding
    sequence: int
    action: BrowserAction | str
    page_url: str
    session: SessionBinding
    selector_or_condition: str | None = None
    value_reference: str | None = None
    evidence_reference: str | None = None

    def __post_init__(self) -> None:
        _intent_common(self.binding, self.sequence)
        try:
            action = BrowserAction(self.action)
        except (TypeError, ValueError) as exc:
            raise TransportContractError("unknown browser action") from exc
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "page_url", _safe_url(self.page_url, "browser page_url"))
        if not isinstance(self.session, SessionBinding):
            raise TransportContractError("browser session must be a SessionBinding")
        if self.selector_or_condition is not None:
            object.__setattr__(
                self,
                "selector_or_condition",
                _browser_text(self.selector_or_condition, "selector_or_condition"),
            )
        if self.value_reference is not None:
            _credential_ref(self.value_reference, "browser value_reference")
        if self.evidence_reference is not None:
            _evidence_ref(self.evidence_reference, "browser evidence_reference")
        if action is BrowserAction.NAVIGATE:
            _none_fields(
                self,
                "navigate",
                "selector_or_condition",
                "value_reference",
                "evidence_reference",
            )
        elif action is BrowserAction.FILL_REFERENCE:
            if self.selector_or_condition is None or self.value_reference is None:
                raise TransportContractError(
                    "fill_reference requires a selector and credential reference"
                )
            if self.evidence_reference is not None:
                raise TransportContractError("fill_reference does not accept evidence_reference")
        elif action is BrowserAction.SCREENSHOT_REFERENCE:
            if self.evidence_reference is None:
                raise TransportContractError("screenshot_reference requires an evidence reference")
            if self.value_reference is not None:
                raise TransportContractError("screenshot_reference does not accept value_reference")
        else:
            if self.selector_or_condition is None:
                raise TransportContractError(f"{action.value} requires selector_or_condition")
            if self.value_reference is not None or self.evidence_reference is not None:
                raise TransportContractError(
                    f"{action.value} accepts no value or evidence reference"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "binding": self.binding.to_dict(),
            "evidence_reference": self.evidence_reference,
            "kind": IntentKind.BROWSER_ACTION.value,
            "page_url": self.page_url,
            "selector_or_condition": self.selector_or_condition,
            "sequence": self.sequence,
            "session": self.session.to_dict(),
            "value_reference": self.value_reference,
        }

    @property
    def intent_sha256(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True)
class PrincipalCredentialReference:
    """A principal label paired only with an opaque credential reference."""

    principal_label: str
    credential_ref: str

    def __post_init__(self) -> None:
        _identifier(self.principal_label, "credential principal_label")
        _credential_ref(self.credential_ref, "credential_ref")

    def to_dict(self) -> dict[str, str]:
        return {"credential_ref": self.credential_ref, "principal_label": self.principal_label}


@dataclass(frozen=True)
class TargetSessionIntent:
    """A reference-only request for an isolated target session."""

    binding: AssessmentBinding
    sequence: int
    mode: AuthenticationMode | str
    login_url: str
    method: HttpMethod | str
    principal_label: str
    credential_references: tuple[PrincipalCredentialReference, ...]
    requested_session_id: str
    isolated: bool = True

    def __post_init__(self) -> None:
        _intent_common(self.binding, self.sequence)
        try:
            mode = AuthenticationMode(self.mode)
        except (TypeError, ValueError) as exc:
            raise TransportContractError("unknown target authentication mode") from exc
        object.__setattr__(self, "mode", mode)
        try:
            method = HttpMethod(self.method)
        except (TypeError, ValueError) as exc:
            raise TransportContractError("unknown HTTP method") from exc
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "login_url", _safe_url(self.login_url, "target login_url"))
        _identifier(self.principal_label, "target principal_label")
        _identifier(self.requested_session_id, "target requested_session_id")
        if self.isolated is not True:
            raise TransportContractError("target sessions must request isolation")
        refs = self.credential_references
        if not isinstance(refs, tuple) or not refs:
            raise TransportContractError("target authentication requires credential references")
        if not all(isinstance(item, PrincipalCredentialReference) for item in refs):
            raise TransportContractError("target credentials must be reference records")
        ordered = tuple(sorted(refs, key=lambda item: (item.principal_label, item.credential_ref)))
        labels = [item.principal_label for item in ordered]
        if len(set(labels)) != len(labels):
            raise TransportContractError("target principal labels must be unique")
        if self.principal_label not in labels:
            raise TransportContractError("selected principal label has no credential reference")
        if mode is AuthenticationMode.MULTI_PRINCIPAL_TEST_ACCOUNTS:
            if len(ordered) < 2:
                raise TransportContractError(
                    "multi-principal mode requires at least two labeled accounts"
                )
        elif len(ordered) != 1:
            raise TransportContractError(
                "single-principal authentication requires exactly one reference"
            )
        object.__setattr__(self, "credential_references", ordered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "credential_references": [item.to_dict() for item in self.credential_references],
            "isolated": self.isolated,
            "kind": IntentKind.TARGET_SESSION_ACQUISITION.value,
            "login_url": self.login_url,
            "method": self.method.value,
            "mode": self.mode.value,
            "principal_label": self.principal_label,
            "requested_session_id": self.requested_session_id,
            "sequence": self.sequence,
        }

    @property
    def intent_sha256(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True)
class ExecutionControl:
    """Caller-owned cancellation or stop signal."""

    cancel_requested: bool = False
    stop_requested: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.cancel_requested, bool) or not isinstance(self.stop_requested, bool):
            raise TransportContractError("control flags must be booleans")
        if self.cancel_requested and self.stop_requested:
            raise TransportContractError("control cannot request cancel and stop together")
        if self.cancel_requested or self.stop_requested:
            if self.reason is None:
                raise TransportContractError("cancel or stop control requires a reason")
            object.__setattr__(self, "reason", _safe_text(self.reason, "control reason", 256))
        elif self.reason is not None:
            raise TransportContractError("inactive control must not declare a reason")


@dataclass(frozen=True)
class HealthObservation:
    """Deterministic adapter health fact used at preflight and continuously."""

    adapter: AdapterIdentity
    sequence: int
    state: AdapterHealthState | str
    evidence_sha256: str
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.adapter, AdapterIdentity):
            raise TransportContractError("health adapter must be an AdapterIdentity")
        _non_negative_int(self.sequence, "health sequence", 1_000_000_000)
        try:
            state = AdapterHealthState(self.state)
        except (TypeError, ValueError) as exc:
            raise TransportContractError("health state is invalid") from exc
        object.__setattr__(self, "state", state)
        _sha256(self.evidence_sha256, "health evidence_sha256")
        object.__setattr__(self, "detail", _safe_text(self.detail, "health detail", 256))

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter.to_dict(),
            "detail": self.detail,
            "evidence_sha256": self.evidence_sha256,
            "sequence": self.sequence,
            "state": self.state.value,
        }


@dataclass(frozen=True)
class HttpResponseSpec:
    """Scripted HTTP response facts, still subject to adapter policy."""

    status_code: int
    mime_type: str
    response_size_bytes: int
    body_sha256: str | None
    headers: tuple[tuple[str, str], ...] = ()
    cookies: tuple[CookieMetadata, ...] = ()
    redirect_url: str | None = None
    is_download: bool = False
    effects: Mapping[str, str] = field(default_factory=lambda: dict(NO_EFFECTS))

    def __post_init__(self) -> None:
        _positive_int(self.status_code, "response status_code", 599)
        if self.status_code < 100:
            raise TransportContractError("response status_code must be between 100 and 599")
        object.__setattr__(self, "mime_type", _mime(self.mime_type, "response mime_type"))
        _non_negative_int(self.response_size_bytes, "response_size_bytes", 100_000_000)
        if self.response_size_bytes:
            if self.body_sha256 is None:
                raise TransportContractError("non-empty response requires body_sha256")
            _sha256(self.body_sha256, "response body_sha256")
        elif self.body_sha256 is not None:
            raise TransportContractError("empty response must not declare body_sha256")
        if not isinstance(self.headers, tuple):
            raise TransportContractError("response headers must be a tuple")
        for item in self.headers:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TransportContractError("response header entries must be name-value pairs")
            _header_name(item[0], "response header name")
            _safe_text(item[1], "response header value", 2048)
        if not isinstance(self.cookies, tuple) or not all(
            isinstance(item, CookieMetadata) for item in self.cookies
        ):
            raise TransportContractError("response cookies must contain CookieMetadata values")
        if self.redirect_url is not None:
            object.__setattr__(self, "redirect_url", _safe_url(self.redirect_url, "redirect_url"))
        if not isinstance(self.is_download, bool):
            raise TransportContractError("response is_download must be a boolean")
        if not isinstance(self.effects, Mapping):
            raise TransportContractError("response effects must be a mapping")
        object.__setattr__(self, "effects", MappingProxyType(dict(self.effects)))


@dataclass(frozen=True)
class BrowserResultSpec:
    """Scripted browser metadata and evidence references."""

    metadata: tuple[tuple[str, str], ...] = ()
    cookies: tuple[CookieMetadata, ...] = ()
    evidence_references: tuple[str, ...] = ()
    response_size_bytes: int = 0
    mime_type: str = "application/json"
    is_download: bool = False
    effects: Mapping[str, str] = field(default_factory=lambda: dict(NO_EFFECTS))

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, tuple):
            raise TransportContractError("browser metadata must be a tuple")
        keys: set[str] = set()
        for key, value in self.metadata:
            key = _token(key, "browser metadata key")
            if key in keys:
                raise TransportContractError("browser metadata keys must be unique")
            keys.add(key)
            _safe_text(value, "browser metadata value", 2048)
        if not isinstance(self.cookies, tuple) or not all(
            isinstance(item, CookieMetadata) for item in self.cookies
        ):
            raise TransportContractError("browser cookies must contain CookieMetadata values")
        object.__setattr__(
            self,
            "evidence_references",
            _evidence_refs(self.evidence_references, "browser evidence_references"),
        )
        _non_negative_int(self.response_size_bytes, "browser response_size_bytes", 100_000_000)
        object.__setattr__(self, "mime_type", _mime(self.mime_type, "browser mime_type"))
        if not isinstance(self.is_download, bool):
            raise TransportContractError("browser is_download must be a boolean")
        if not isinstance(self.effects, Mapping):
            raise TransportContractError("browser effects must be a mapping")
        object.__setattr__(self, "effects", MappingProxyType(dict(self.effects)))


@dataclass(frozen=True)
class SessionResultSpec:
    """Scripted isolated session metadata without credential or cookie values."""

    session_id: str
    principal_label: str
    cookies: tuple[CookieMetadata, ...] = ()
    isolated: bool = True
    effects: Mapping[str, str] = field(default_factory=lambda: dict(NO_EFFECTS))

    def __post_init__(self) -> None:
        _identifier(self.session_id, "session result session_id")
        _identifier(self.principal_label, "session result principal_label")
        if not isinstance(self.cookies, tuple) or not all(
            isinstance(item, CookieMetadata) for item in self.cookies
        ):
            raise TransportContractError("session cookies must contain CookieMetadata values")
        if not isinstance(self.isolated, bool):
            raise TransportContractError("session isolated must be a boolean")
        if not isinstance(self.effects, Mapping):
            raise TransportContractError("session effects must be a mapping")
        object.__setattr__(self, "effects", MappingProxyType(dict(self.effects)))


@dataclass(frozen=True)
class HttpResponseObservation:
    """Typed, intent-bound HTTP response observation."""

    intent_sha256: str
    status_code: int
    mime_type: str
    response_size_bytes: int
    body_sha256: str | None
    headers: tuple[ObservedHeader, ...]
    cookies: tuple[CookieMetadata, ...]
    redirect_url: str | None

    def __post_init__(self) -> None:
        _sha256(self.intent_sha256, "HTTP observation intent_sha256")
        _positive_int(self.status_code, "HTTP observation status_code", 599)
        if self.status_code < 100:
            raise TransportContractError("HTTP observation status_code is invalid")
        object.__setattr__(self, "mime_type", _mime(self.mime_type, "HTTP observation MIME type"))
        _non_negative_int(
            self.response_size_bytes,
            "HTTP observation response_size_bytes",
            100_000_000,
        )
        if self.response_size_bytes:
            if self.body_sha256 is None:
                raise TransportContractError("non-empty HTTP observation requires body_sha256")
            _sha256(self.body_sha256, "HTTP observation body_sha256")
        elif self.body_sha256 is not None:
            raise TransportContractError("empty HTTP observation cannot declare body_sha256")
        if not isinstance(self.headers, tuple) or not all(
            isinstance(item, ObservedHeader) for item in self.headers
        ):
            raise TransportContractError("HTTP observation headers are invalid")
        if not isinstance(self.cookies, tuple) or not all(
            isinstance(item, CookieMetadata) for item in self.cookies
        ):
            raise TransportContractError("HTTP observation cookies are invalid")
        if self.redirect_url is not None:
            object.__setattr__(
                self,
                "redirect_url",
                _safe_url(self.redirect_url, "HTTP observation redirect_url"),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "body_sha256": self.body_sha256,
            "cookies": [item.to_dict() for item in self.cookies],
            "effects": dict(NO_EFFECTS),
            "headers": [item.to_dict() for item in self.headers],
            "intent_sha256": self.intent_sha256,
            "kind": "http_response",
            "mime_type": self.mime_type,
            "redirect_url": self.redirect_url,
            "response_size_bytes": self.response_size_bytes,
            "status_code": self.status_code,
        }


@dataclass(frozen=True)
class BrowserObservation:
    """Typed browser metadata observation with no page content or cookie values."""

    intent_sha256: str
    session: SessionBinding
    metadata: tuple[tuple[str, str], ...]
    cookies: tuple[CookieMetadata, ...]
    evidence_references: tuple[str, ...]
    mime_type: str
    response_size_bytes: int

    def __post_init__(self) -> None:
        _sha256(self.intent_sha256, "browser observation intent_sha256")
        if not isinstance(self.session, SessionBinding):
            raise TransportContractError("browser observation session is invalid")
        if not isinstance(self.metadata, tuple):
            raise TransportContractError("browser observation metadata must be a tuple")
        keys: set[str] = set()
        for key, value in self.metadata:
            normalized = _token(key, "browser observation metadata key")
            if normalized in keys:
                raise TransportContractError("browser observation metadata keys must be unique")
            keys.add(normalized)
            _safe_text(value, "browser observation metadata value", 2048)
        if not isinstance(self.cookies, tuple) or not all(
            isinstance(item, CookieMetadata) for item in self.cookies
        ):
            raise TransportContractError("browser observation cookies are invalid")
        object.__setattr__(
            self,
            "evidence_references",
            _evidence_refs(self.evidence_references, "browser observation evidence references"),
        )
        object.__setattr__(
            self,
            "mime_type",
            _mime(self.mime_type, "browser observation MIME type"),
        )
        _non_negative_int(
            self.response_size_bytes,
            "browser observation response_size_bytes",
            100_000_000,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookies": [item.to_dict() for item in self.cookies],
            "effects": dict(NO_EFFECTS),
            "evidence_references": list(self.evidence_references),
            "intent_sha256": self.intent_sha256,
            "kind": "browser_observation",
            "metadata": {key: value for key, value in sorted(self.metadata)},
            "mime_type": self.mime_type,
            "response_size_bytes": self.response_size_bytes,
            "session": self.session.to_dict(),
        }


@dataclass(frozen=True)
class TargetSessionObservation:
    """Typed isolated session observation bound to exactly one principal."""

    intent_sha256: str
    session_id: str
    principal_label: str
    cookies: tuple[CookieMetadata, ...]
    isolated: bool = True

    def __post_init__(self) -> None:
        _sha256(self.intent_sha256, "session observation intent_sha256")
        _identifier(self.session_id, "session observation session_id")
        _identifier(self.principal_label, "session observation principal_label")
        if not isinstance(self.cookies, tuple) or not all(
            isinstance(item, CookieMetadata) for item in self.cookies
        ):
            raise TransportContractError("session observation cookies are invalid")
        if self.isolated is not True:
            raise TransportContractError("session observation must be isolated")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookies": [item.to_dict() for item in self.cookies],
            "effects": dict(NO_EFFECTS),
            "intent_sha256": self.intent_sha256,
            "isolated": True,
            "kind": "target_session_observation",
            "principal_label": self.principal_label,
            "session_id": self.session_id,
        }


ResponseObservation = HttpResponseObservation | BrowserObservation | TargetSessionObservation


@dataclass(frozen=True)
class ScriptedHttpExchange:
    """One exact request digest and its deterministic HTTP response."""

    expected_intent_sha256: str
    response: HttpResponseSpec

    def __post_init__(self) -> None:
        _sha256(self.expected_intent_sha256, "script expected_intent_sha256")
        if not isinstance(self.response, HttpResponseSpec):
            raise TransportContractError("HTTP script response must be HttpResponseSpec")


@dataclass(frozen=True)
class ScriptedBrowserAction:
    """One exact browser action digest and its deterministic result."""

    expected_intent_sha256: str
    result: BrowserResultSpec

    def __post_init__(self) -> None:
        _sha256(self.expected_intent_sha256, "script expected_intent_sha256")
        if not isinstance(self.result, BrowserResultSpec):
            raise TransportContractError("browser script result must be BrowserResultSpec")


@dataclass(frozen=True)
class ScriptedSessionAcquisition:
    """One exact target auth intent digest and deterministic isolated session."""

    expected_intent_sha256: str
    result: SessionResultSpec

    def __post_init__(self) -> None:
        _sha256(self.expected_intent_sha256, "script expected_intent_sha256")
        if not isinstance(self.result, SessionResultSpec):
            raise TransportContractError("session script result must be SessionResultSpec")


@dataclass(frozen=True)
class TransportStep:
    """One hash-chained transport request and observation."""

    sequence: int
    intent_kind: IntentKind | str
    intent_sha256: str
    intent: Mapping[str, Any]
    state: TransportStepState | str
    scope_decision: ScopeDecision
    health: HealthObservation
    observation: Mapping[str, Any] | None
    stop_reason: str | None
    previous_step_sha256: str | None
    step_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            **_step_body(
                sequence=self.sequence,
                intent_kind=self.intent_kind,
                intent_sha256=self.intent_sha256,
                intent=self.intent,
                state=self.state,
                scope_decision=self.scope_decision,
                health=self.health,
                observation=self.observation,
                stop_reason=self.stop_reason,
                previous_step_sha256=self.previous_step_sha256,
            ),
            "step_sha256": self.step_sha256,
        }


@dataclass(frozen=True)
class TransportResult:
    """Typed step result returned by every adapter interface."""

    state: TransportStepState
    observation: ResponseObservation | None
    step: TransportStep


@dataclass(frozen=True)
class TransportTranscript:
    """Content-addressed deterministic transcript."""

    transcript_id: str
    transcript_sha256: str
    binding: AssessmentBinding
    steps: tuple[TransportStep, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            **_transcript_body(self.binding, self.steps),
            "transcript_id": self.transcript_id,
            "transcript_sha256": self.transcript_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TransportTranscript:
        _exact_fields(
            raw,
            {
                "binding",
                "effects",
                "schema_version",
                "steps",
                "transcript_id",
                "transcript_sha256",
            },
            "transport transcript",
        )
        if raw["schema_version"] != SCHEMA_VERSION:
            raise TransportContractError("transcript schema_version is invalid")
        _require_no_effects(raw["effects"], "transcript")
        binding = _binding_from_dict(raw["binding"])
        if not isinstance(raw["steps"], list):
            raise TransportContractError("transcript steps must be a list")
        steps: list[TransportStep] = []
        previous: str | None = None
        for expected_sequence, item in enumerate(raw["steps"], start=1):
            step = _step_from_dict(item)
            if step.sequence != expected_sequence:
                raise TransportContractError("transcript step sequence is not contiguous")
            if step.previous_step_sha256 != previous:
                raise TransportContractError("transcript step chain is invalid")
            if step.intent.get("binding") != binding.to_dict():
                raise TransportContractError("transcript step binding does not match transcript")
            steps.append(step)
            previous = step.step_sha256
        candidate = build_transport_transcript(binding, tuple(steps))
        if raw != candidate.to_dict():
            raise TransportContractError("transcript identity, contents, or ordering is invalid")
        return candidate


@runtime_checkable
class HttpExchangeAdapter(Protocol):
    """Infrastructure-independent HTTP exchange interface."""

    def preflight(self, scope: VerifiedAssessmentScope) -> HealthObservation: ...

    def observe_health(self) -> HealthObservation: ...

    def exchange(
        self,
        scope: VerifiedAssessmentScope,
        intent: HttpRequestIntent,
        control: ExecutionControl | None = None,
    ) -> TransportResult: ...

    def transcript(self) -> TransportTranscript: ...


@runtime_checkable
class BrowserActionAdapter(Protocol):
    """Infrastructure-independent safe browser action interface."""

    def preflight(self, scope: VerifiedAssessmentScope) -> HealthObservation: ...

    def observe_health(self) -> HealthObservation: ...

    def perform(
        self,
        scope: VerifiedAssessmentScope,
        intent: BrowserActionIntent,
        control: ExecutionControl | None = None,
    ) -> TransportResult: ...

    def transcript(self) -> TransportTranscript: ...


@runtime_checkable
class TargetSessionAdapter(Protocol):
    """Infrastructure-independent target session acquisition interface."""

    def preflight(self, scope: VerifiedAssessmentScope) -> HealthObservation: ...

    def observe_health(self) -> HealthObservation: ...

    def acquire(
        self,
        scope: VerifiedAssessmentScope,
        intent: TargetSessionIntent,
        control: ExecutionControl | None = None,
    ) -> TransportResult: ...

    def transcript(self) -> TransportTranscript: ...


class _DeterministicTransport:
    def __init__(
        self,
        binding: AssessmentBinding,
        health_script: Sequence[HealthObservation],
    ) -> None:
        if not isinstance(binding, AssessmentBinding):
            raise TransportContractError("mock binding must be an AssessmentBinding")
        if not isinstance(health_script, Sequence) or not health_script:
            raise TransportContractError("mock health script must be non-empty")
        health = tuple(health_script)
        for index, item in enumerate(health):
            if not isinstance(item, HealthObservation):
                raise TransportContractError("mock health entries must be HealthObservation values")
            if item.adapter != binding.adapter:
                raise TransportContractError("health adapter identity does not match binding")
            if item.sequence != index:
                raise TransportContractError("health sequence must start at zero and be contiguous")
        self._binding = binding
        self._health = health
        self._records: list[TransportStep] = []
        self._script_cursor = 0
        self._request_bytes = 0
        self._response_bytes = 0
        self._redirects = 0
        self._session_principals: dict[str, str] = {}

    def preflight(self, scope: VerifiedAssessmentScope) -> HealthObservation:
        _verify_scope_binding(scope, self._binding)
        return self._health[0]

    def observe_health(self) -> HealthObservation:
        return self._health[min(len(self._records) + 1, len(self._health) - 1)]

    def transcript(self) -> TransportTranscript:
        return build_transport_transcript(self._binding, tuple(self._records))

    def _common(
        self,
        scope: VerifiedAssessmentScope,
        intent: HttpRequestIntent | BrowserActionIntent | TargetSessionIntent,
        control: ExecutionControl | None,
        *,
        url: str,
        method: HttpMethod,
        request_size: int,
    ) -> tuple[ScopeDecision, HealthObservation, TransportResult | None]:
        if control is None:
            control = ExecutionControl()
        if not isinstance(control, ExecutionControl):
            raise TransportContractError("control must be an ExecutionControl")
        _verify_scope_binding(scope, self._binding)
        if intent.binding != self._binding:
            raise TransportContractError("intent binding does not match adapter binding")
        if intent.sequence != len(self._records) + 1:
            raise TransportContractError("intent sequence is not the next transcript sequence")
        budget = self._binding.budget
        if len(self._records) >= budget.max_steps:
            raise TransportContractError("transport step budget exhausted")
        if request_size > budget.max_request_bytes:
            raise TransportContractError("request size exceeds per-step ceiling")
        if self._request_bytes + request_size > budget.max_total_request_bytes:
            raise TransportContractError("total request byte budget exhausted")
        scope_decision = evaluate_request(
            scope,
            url=url,
            method=method.value,
            technique_id=self._binding.technique_id,
            impact_tier=self._binding.impact_tier,
            budget_state=ScopeBudgetState(
                requests_completed=budget.requests_completed + len(self._records),
                requests_active=budget.requests_active,
                requests_in_current_minute=(budget.requests_in_current_minute + len(self._records)),
            ),
            at=_utc(self._binding.decision_at, "binding decision_at"),
        )
        if not scope_decision.allowed:
            raise TransportContractError(f"scope rejected intent: {scope_decision.reason}")
        health = self.observe_health()
        if control.cancel_requested:
            return (
                scope_decision,
                health,
                self._terminal_result(
                    intent,
                    scope_decision,
                    health,
                    TransportStepState.CANCELLED,
                    control.reason,
                ),
            )
        if control.stop_requested:
            return (
                scope_decision,
                health,
                self._terminal_result(
                    intent,
                    scope_decision,
                    health,
                    TransportStepState.STOPPED,
                    control.reason,
                ),
            )
        if health.state is not AdapterHealthState.HEALTHY:
            return (
                scope_decision,
                health,
                self._terminal_result(
                    intent,
                    scope_decision,
                    health,
                    TransportStepState.HEALTH_PAUSED,
                    f"adapter health is {health.state.value}",
                ),
            )
        return scope_decision, health, None

    def _terminal_result(
        self,
        intent: HttpRequestIntent | BrowserActionIntent | TargetSessionIntent,
        decision: ScopeDecision,
        health: HealthObservation,
        state: TransportStepState,
        reason: str | None,
    ) -> TransportResult:
        step = _build_step(
            intent,
            state,
            decision,
            health,
            None,
            reason,
            self._records[-1].step_sha256 if self._records else None,
        )
        self._records.append(step)
        return TransportResult(state, None, step)

    def _completed_result(
        self,
        intent: HttpRequestIntent | BrowserActionIntent | TargetSessionIntent,
        decision: ScopeDecision,
        health: HealthObservation,
        observation: ResponseObservation,
        request_size: int,
        response_size: int,
    ) -> TransportResult:
        if self._request_bytes + request_size > self._binding.budget.max_total_request_bytes:
            raise TransportContractError("total request byte budget exhausted")
        if self._response_bytes + response_size > self._binding.budget.max_total_response_bytes:
            raise TransportContractError("total response byte budget exhausted")
        self._request_bytes += request_size
        self._response_bytes += response_size
        step = _build_step(
            intent,
            TransportStepState.COMPLETED,
            decision,
            health,
            observation.to_dict(),
            None,
            self._records[-1].step_sha256 if self._records else None,
        )
        self._records.append(step)
        self._script_cursor += 1
        return TransportResult(TransportStepState.COMPLETED, observation, step)

    def _check_session(self, session: SessionBinding) -> None:
        previous = self._session_principals.get(session.session_id)
        if previous is not None and previous != session.principal_label:
            raise TransportContractError("cross-principal session reuse is forbidden")

    def _remember_session(self, session: SessionBinding) -> None:
        self._session_principals[session.session_id] = session.principal_label


class DeterministicHttpTransport(_DeterministicTransport):
    """Strict scripted HTTP mock with no external I/O."""

    def __init__(
        self,
        binding: AssessmentBinding,
        script: Sequence[ScriptedHttpExchange],
        *,
        health_script: Sequence[HealthObservation],
        header_policy: HeaderPolicy | None = None,
    ) -> None:
        super().__init__(binding, health_script)
        self._script = _typed_script(script, ScriptedHttpExchange, "HTTP")
        if header_policy is None:
            header_policy = HeaderPolicy()
        if not isinstance(header_policy, HeaderPolicy):
            raise TransportContractError("header_policy must be a HeaderPolicy")
        self._header_policy = header_policy

    def exchange(
        self,
        scope: VerifiedAssessmentScope,
        intent: HttpRequestIntent,
        control: ExecutionControl | None = None,
    ) -> TransportResult:
        if not isinstance(intent, HttpRequestIntent):
            raise TransportContractError("HTTP adapter requires HttpRequestIntent")
        _enforce_request_header_policy(intent.headers, self._header_policy)
        decision, health, terminal = self._common(
            scope,
            intent,
            control,
            url=intent.url,
            method=intent.method,
            request_size=intent.request_size_bytes,
        )
        if terminal is not None:
            return terminal
        scripted = self._script_item()
        _match_intent(scripted.expected_intent_sha256, intent.intent_sha256)
        response = scripted.response
        _require_no_effects(response.effects, "HTTP response")
        _enforce_response_limits(response, self._binding.budget)
        if response.is_download:
            raise TransportContractError("downloads are forbidden")
        headers = _observe_headers(response.headers, self._header_policy)
        next_redirects = self._redirects
        if response.redirect_url is not None:
            next_redirects = self._redirects + 1
            if next_redirects > self._binding.budget.max_redirects:
                raise TransportContractError("redirect limit exceeded")
        if intent.session is not None:
            self._check_session(intent.session)
        observation = HttpResponseObservation(
            intent_sha256=intent.intent_sha256,
            status_code=response.status_code,
            mime_type=response.mime_type,
            response_size_bytes=response.response_size_bytes,
            body_sha256=response.body_sha256,
            headers=headers,
            cookies=response.cookies,
            redirect_url=response.redirect_url,
        )
        completed = self._completed_result(
            intent,
            decision,
            health,
            observation,
            intent.request_size_bytes,
            response.response_size_bytes,
        )
        self._redirects = next_redirects
        if intent.session is not None:
            self._remember_session(intent.session)
        return completed

    def _script_item(self) -> ScriptedHttpExchange:
        if self._script_cursor >= len(self._script):
            raise TransportContractError("HTTP script exhausted")
        return self._script[self._script_cursor]


class DeterministicBrowserTransport(_DeterministicTransport):
    """Strict scripted safe browser mock with no browser driver."""

    def __init__(
        self,
        binding: AssessmentBinding,
        script: Sequence[ScriptedBrowserAction],
        *,
        health_script: Sequence[HealthObservation],
    ) -> None:
        super().__init__(binding, health_script)
        self._script = _typed_script(script, ScriptedBrowserAction, "browser")

    def perform(
        self,
        scope: VerifiedAssessmentScope,
        intent: BrowserActionIntent,
        control: ExecutionControl | None = None,
    ) -> TransportResult:
        if not isinstance(intent, BrowserActionIntent):
            raise TransportContractError("browser adapter requires BrowserActionIntent")
        method = HttpMethod.POST if intent.action is BrowserAction.SUBMIT else HttpMethod.GET
        decision, health, terminal = self._common(
            scope,
            intent,
            control,
            url=intent.page_url,
            method=method,
            request_size=0,
        )
        if terminal is not None:
            return terminal
        scripted = self._script_item()
        _match_intent(scripted.expected_intent_sha256, intent.intent_sha256)
        result = scripted.result
        _require_no_effects(result.effects, "browser result")
        _enforce_payload_limits(
            result.response_size_bytes,
            result.mime_type,
            self._binding.budget,
            "browser response",
        )
        if result.is_download:
            raise TransportContractError("downloads are forbidden")
        self._check_session(intent.session)
        observation = BrowserObservation(
            intent_sha256=intent.intent_sha256,
            session=intent.session,
            metadata=result.metadata,
            cookies=result.cookies,
            evidence_references=result.evidence_references,
            mime_type=result.mime_type,
            response_size_bytes=result.response_size_bytes,
        )
        completed = self._completed_result(
            intent,
            decision,
            health,
            observation,
            0,
            result.response_size_bytes,
        )
        self._remember_session(intent.session)
        return completed

    def _script_item(self) -> ScriptedBrowserAction:
        if self._script_cursor >= len(self._script):
            raise TransportContractError("browser script exhausted")
        return self._script[self._script_cursor]


class DeterministicTargetSessionTransport(_DeterministicTransport):
    """Strict reference-only target session mock with principal isolation."""

    def __init__(
        self,
        binding: AssessmentBinding,
        script: Sequence[ScriptedSessionAcquisition],
        *,
        health_script: Sequence[HealthObservation],
    ) -> None:
        super().__init__(binding, health_script)
        self._script = _typed_script(script, ScriptedSessionAcquisition, "session")

    def acquire(
        self,
        scope: VerifiedAssessmentScope,
        intent: TargetSessionIntent,
        control: ExecutionControl | None = None,
    ) -> TransportResult:
        if not isinstance(intent, TargetSessionIntent):
            raise TransportContractError("target adapter requires TargetSessionIntent")
        decision, health, terminal = self._common(
            scope,
            intent,
            control,
            url=intent.login_url,
            method=intent.method,
            request_size=0,
        )
        if terminal is not None:
            return terminal
        scripted = self._script_item()
        _match_intent(scripted.expected_intent_sha256, intent.intent_sha256)
        result = scripted.result
        _require_no_effects(result.effects, "session result")
        if result.isolated is not True:
            raise TransportContractError("target session result must be isolated")
        if result.session_id != intent.requested_session_id:
            raise TransportContractError("target session result substituted session identity")
        if result.principal_label != intent.principal_label:
            raise TransportContractError("target session result substituted principal identity")
        session = SessionBinding(result.session_id, result.principal_label)
        self._check_session(session)
        observation = TargetSessionObservation(
            intent_sha256=intent.intent_sha256,
            session_id=result.session_id,
            principal_label=result.principal_label,
            cookies=result.cookies,
        )
        completed = self._completed_result(intent, decision, health, observation, 0, 0)
        self._remember_session(session)
        return completed

    def _script_item(self) -> ScriptedSessionAcquisition:
        if self._script_cursor >= len(self._script):
            raise TransportContractError("session script exhausted")
        return self._script[self._script_cursor]


def build_transport_transcript(
    binding: AssessmentBinding,
    steps: Sequence[TransportStep] = (),
) -> TransportTranscript:
    """Build and verify a canonical hash-chained transcript."""

    if not isinstance(binding, AssessmentBinding):
        raise TransportContractError("transcript binding must be an AssessmentBinding")
    if not isinstance(steps, Sequence):
        raise TransportContractError("transcript steps must be a sequence")
    checked: list[TransportStep] = []
    previous: str | None = None
    for expected_sequence, step in enumerate(steps, start=1):
        if not isinstance(step, TransportStep):
            raise TransportContractError("transcript entries must be TransportStep values")
        if step.sequence != expected_sequence or step.previous_step_sha256 != previous:
            raise TransportContractError("transcript step sequence or chain is invalid")
        serialized = {key: value for key, value in step.to_dict().items() if key != "step_sha256"}
        expected_hash = canonical_sha256({"domain": STEP_DOMAIN, **serialized})
        if not hmac.compare_digest(step.step_sha256, expected_hash):
            raise TransportContractError("transcript step hash is invalid")
        if step.intent.get("binding") != binding.to_dict():
            raise TransportContractError("transcript step binding does not match transcript")
        if step.health.adapter != binding.adapter:
            raise TransportContractError("transcript health adapter does not match binding")
        checked.append(step)
        previous = step.step_sha256
    body = _transcript_body(binding, tuple(checked))
    digest = canonical_sha256({"domain": TRANSCRIPT_DOMAIN, **body})
    transcript_id = "ATT-" + digest.removeprefix("sha256:")[:32].upper()
    return TransportTranscript(transcript_id, digest, binding, tuple(checked))


def canonical_json(value: Any) -> str:
    """Return stable ASCII JSON for contract hashes."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise TransportContractError("value is not canonical JSON data") from exc


def canonical_sha256(value: Any) -> str:
    """Return the SHA-256 address of canonical JSON data."""

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _intent_common(binding: Any, sequence: Any) -> None:
    if not isinstance(binding, AssessmentBinding):
        raise TransportContractError("intent binding must be an AssessmentBinding")
    _positive_int(sequence, "intent sequence", 1_000_000_000)


def _request_headers(headers: Any) -> tuple[HeaderField, ...]:
    if not isinstance(headers, tuple):
        raise TransportContractError("request headers must be a tuple")
    if not all(isinstance(item, HeaderField) for item in headers):
        raise TransportContractError("request headers must contain HeaderField values")
    ordered = tuple(sorted(headers, key=lambda item: item.name))
    if len({item.name for item in ordered}) != len(ordered):
        raise TransportContractError("request header names must be unique")
    return ordered


def _enforce_request_header_policy(headers: tuple[HeaderField, ...], policy: HeaderPolicy) -> None:
    allowed = set(policy.request_allowlist)
    for header in headers:
        if header.name not in allowed:
            raise TransportContractError(f"request header is not allowlisted: {header.name}")


def _observe_headers(
    headers: tuple[tuple[str, str], ...],
    policy: HeaderPolicy,
) -> tuple[ObservedHeader, ...]:
    allowed = set(policy.response_allowlist)
    redacted = set(policy.response_redactions)
    result: list[ObservedHeader] = []
    names: set[str] = set()
    for raw_name, raw_value in headers:
        name = _header_name(raw_name, "response header name")
        if name in FORBIDDEN_SECRET_HEADERS:
            raise TransportContractError("secret response headers are forbidden")
        if name not in allowed:
            raise TransportContractError(f"response header is not allowlisted: {name}")
        if name in names:
            raise TransportContractError("response header names must be unique")
        names.add(name)
        value = _safe_text(raw_value, "response header value", 2048)
        result.append(ObservedHeader(name, None if name in redacted else value, name in redacted))
    return tuple(sorted(result, key=lambda item: item.name))


def _enforce_response_limits(response: HttpResponseSpec, budget: TransportBudget) -> None:
    _enforce_payload_limits(
        response.response_size_bytes,
        response.mime_type,
        budget,
        "HTTP response",
    )


def _enforce_payload_limits(size: int, mime: str, budget: TransportBudget, label: str) -> None:
    if size > budget.max_response_bytes:
        raise TransportContractError(f"{label} exceeds per-step size ceiling")
    ceiling = budget.mime_ceiling(mime)
    if ceiling is None:
        raise TransportContractError(f"{label} MIME type is not allowlisted")
    if size > ceiling:
        raise TransportContractError(f"{label} exceeds MIME size ceiling")


def _verify_scope_binding(scope: Any, binding: AssessmentBinding) -> None:
    if not isinstance(scope, VerifiedAssessmentScope):
        raise TransportContractError("scope must be a VerifiedAssessmentScope")
    if not isinstance(scope.signed_scope, SignedAssessmentScope):
        raise TransportContractError("verified scope contains an invalid signed scope")
    if scope.scope_id != binding.scope_id or scope.content_sha256 != binding.scope_sha256:
        raise TransportContractError("verified scope does not match the intent binding")


def _match_intent(expected: str, actual: str) -> None:
    if not hmac.compare_digest(expected, actual):
        raise TransportContractError("scripted result does not match intent hash")


def _require_no_effects(value: Any, label: str) -> None:
    if not isinstance(value, Mapping) or dict(value) != dict(NO_EFFECTS):
        raise TransportContractError(f"{label} effects must all be none")


def _typed_script(script: Any, expected_type: type, label: str) -> tuple[Any, ...]:
    if not isinstance(script, Sequence):
        raise TransportContractError(f"{label} script must be a sequence")
    result = tuple(script)
    if not all(isinstance(item, expected_type) for item in result):
        raise TransportContractError(f"{label} script contains an invalid entry")
    return result


def _build_step(
    intent: HttpRequestIntent | BrowserActionIntent | TargetSessionIntent,
    state: TransportStepState,
    scope_decision: ScopeDecision,
    health: HealthObservation,
    observation: Mapping[str, Any] | None,
    stop_reason: str | None,
    previous_step_sha256: str | None,
) -> TransportStep:
    kind = IntentKind(intent.to_dict()["kind"])
    body = _step_body(
        sequence=intent.sequence,
        intent_kind=kind,
        intent_sha256=intent.intent_sha256,
        intent=intent.to_dict(),
        state=state,
        scope_decision=scope_decision,
        health=health,
        observation=observation,
        stop_reason=stop_reason,
        previous_step_sha256=previous_step_sha256,
    )
    digest = canonical_sha256({"domain": STEP_DOMAIN, **body})
    return TransportStep(
        sequence=intent.sequence,
        intent_kind=kind,
        intent_sha256=intent.intent_sha256,
        intent=intent.to_dict(),
        state=state,
        scope_decision=scope_decision,
        health=health,
        observation=None if observation is None else dict(observation),
        stop_reason=stop_reason,
        previous_step_sha256=previous_step_sha256,
        step_sha256=digest,
    )


def _step_body(
    *,
    sequence: int,
    intent_kind: IntentKind | str,
    intent_sha256: str,
    intent: Mapping[str, Any],
    state: TransportStepState | str,
    scope_decision: ScopeDecision,
    health: HealthObservation,
    observation: Mapping[str, Any] | None,
    stop_reason: str | None,
    previous_step_sha256: str | None,
) -> dict[str, Any]:
    kind = IntentKind(intent_kind)
    state_value = TransportStepState(state)
    return {
        "effects": dict(NO_EFFECTS),
        "health": health.to_dict(),
        "intent": dict(intent),
        "intent_kind": kind.value,
        "intent_sha256": intent_sha256,
        "observation": None if observation is None else dict(observation),
        "previous_step_sha256": previous_step_sha256,
        "scope_decision": {"allowed": scope_decision.allowed, "reason": scope_decision.reason},
        "sequence": sequence,
        "state": state_value.value,
        "stop_reason": stop_reason,
    }


def _step_from_dict(raw: Any) -> TransportStep:
    _exact_fields(
        raw,
        {
            "effects",
            "health",
            "intent",
            "intent_kind",
            "intent_sha256",
            "observation",
            "previous_step_sha256",
            "scope_decision",
            "sequence",
            "state",
            "step_sha256",
            "stop_reason",
        },
        "transport step",
    )
    _require_no_effects(raw["effects"], "transport step")
    _positive_int(raw["sequence"], "transport step sequence", 1_000_000_000)
    try:
        kind = IntentKind(raw["intent_kind"])
        state = TransportStepState(raw["state"])
    except (TypeError, ValueError) as exc:
        raise TransportContractError("transport step kind or state is invalid") from exc
    _sha256(raw["intent_sha256"], "transport step intent_sha256")
    parsed_intent = _intent_from_dict(raw["intent"])
    if parsed_intent.to_dict().get("kind") != kind.value:
        raise TransportContractError("transport step intent kind is inconsistent")
    if parsed_intent.intent_sha256 != raw["intent_sha256"]:
        raise TransportContractError("transport step intent hash is invalid")
    if raw["observation"] is not None:
        parsed_observation = _observation_from_dict(raw["observation"])
        if parsed_observation.intent_sha256 != raw["intent_sha256"]:
            raise TransportContractError("transport observation was substituted")
        expected_observation_kind = {
            IntentKind.HTTP_EXCHANGE: HttpResponseObservation,
            IntentKind.BROWSER_ACTION: BrowserObservation,
            IntentKind.TARGET_SESSION_ACQUISITION: TargetSessionObservation,
        }[kind]
        if not isinstance(parsed_observation, expected_observation_kind):
            raise TransportContractError("transport observation kind does not match intent")
    _exact_fields(raw["scope_decision"], {"allowed", "reason"}, "scope decision")
    if raw["scope_decision"]["allowed"] is not True:
        raise TransportContractError("recorded transport scope decision must be allowed")
    reason = _safe_text(raw["scope_decision"]["reason"], "scope decision reason", 512)
    health = _health_from_dict(raw["health"])
    if raw["previous_step_sha256"] is not None:
        _sha256(raw["previous_step_sha256"], "previous_step_sha256")
    if raw["stop_reason"] is not None:
        _safe_text(raw["stop_reason"], "transport stop_reason", 256)
    if state is TransportStepState.COMPLETED:
        if raw["observation"] is None or raw["stop_reason"] is not None:
            raise TransportContractError("completed step requires observation and no stop reason")
    elif raw["observation"] is not None or raw["stop_reason"] is None:
        raise TransportContractError("non-completed step requires stop reason and no observation")
    _sha256(raw["step_sha256"], "transport step_sha256")
    body = {key: value for key, value in raw.items() if key != "step_sha256"}
    expected = canonical_sha256({"domain": STEP_DOMAIN, **body})
    if not hmac.compare_digest(raw["step_sha256"], expected):
        raise TransportContractError("transport step hash is invalid")
    return TransportStep(
        sequence=raw["sequence"],
        intent_kind=kind,
        intent_sha256=raw["intent_sha256"],
        intent=raw["intent"],
        state=state,
        scope_decision=ScopeDecision(True, reason),
        health=health,
        observation=raw["observation"],
        stop_reason=raw["stop_reason"],
        previous_step_sha256=raw["previous_step_sha256"],
        step_sha256=raw["step_sha256"],
    )


def _health_from_dict(raw: Any) -> HealthObservation:
    _exact_fields(
        raw,
        {"adapter", "detail", "evidence_sha256", "sequence", "state"},
        "health observation",
    )
    return HealthObservation(
        adapter=_adapter_from_dict(raw["adapter"]),
        sequence=raw["sequence"],
        state=raw["state"],
        evidence_sha256=raw["evidence_sha256"],
        detail=raw["detail"],
    )


def _transcript_body(binding: AssessmentBinding, steps: Sequence[TransportStep]) -> dict[str, Any]:
    return {
        "binding": binding.to_dict(),
        "effects": dict(NO_EFFECTS),
        "schema_version": SCHEMA_VERSION,
        "steps": [item.to_dict() for item in steps],
    }


def _binding_from_dict(raw: Any) -> AssessmentBinding:
    _exact_fields(
        raw,
        {
            "adapter",
            "authority_refs",
            "budget",
            "decision_at",
            "evidence_hashes",
            "impact_tier",
            "scope_id",
            "scope_sha256",
            "stop_conditions",
            "task_id",
            "technique_id",
        },
        "assessment binding",
    )
    return AssessmentBinding(
        scope_id=raw["scope_id"],
        scope_sha256=raw["scope_sha256"],
        task_id=raw["task_id"],
        technique_id=raw["technique_id"],
        authority_refs=_tuple_strings(raw["authority_refs"], "authority_refs"),
        evidence_hashes=_tuple_strings(raw["evidence_hashes"], "evidence_hashes"),
        impact_tier=raw["impact_tier"],
        stop_conditions=_tuple_strings(raw["stop_conditions"], "stop_conditions"),
        adapter=_adapter_from_dict(raw["adapter"]),
        budget=_budget_from_dict(raw["budget"]),
        decision_at=raw["decision_at"],
    )


def _intent_from_dict(
    raw: Any,
) -> HttpRequestIntent | BrowserActionIntent | TargetSessionIntent:
    if not isinstance(raw, dict):
        raise TransportContractError("transport step intent must be an object")
    kind = raw.get("kind")
    if kind == IntentKind.HTTP_EXCHANGE.value:
        _exact_fields(
            raw,
            {
                "binding",
                "body_sha256",
                "headers",
                "kind",
                "method",
                "request_size_bytes",
                "sequence",
                "session",
                "url",
            },
            "HTTP intent",
        )
        if not isinstance(raw["headers"], list):
            raise TransportContractError("HTTP intent headers must be a list")
        intent: HttpRequestIntent | BrowserActionIntent | TargetSessionIntent = HttpRequestIntent(
            binding=_binding_from_dict(raw["binding"]),
            sequence=raw["sequence"],
            method=raw["method"],
            url=raw["url"],
            headers=tuple(_header_field_from_dict(item) for item in raw["headers"]),
            request_size_bytes=raw["request_size_bytes"],
            body_sha256=raw["body_sha256"],
            session=(
                None if raw["session"] is None else _session_binding_from_dict(raw["session"])
            ),
        )
    elif kind == IntentKind.BROWSER_ACTION.value:
        _exact_fields(
            raw,
            {
                "action",
                "binding",
                "evidence_reference",
                "kind",
                "page_url",
                "selector_or_condition",
                "sequence",
                "session",
                "value_reference",
            },
            "browser intent",
        )
        intent = BrowserActionIntent(
            binding=_binding_from_dict(raw["binding"]),
            sequence=raw["sequence"],
            action=raw["action"],
            page_url=raw["page_url"],
            session=_session_binding_from_dict(raw["session"]),
            selector_or_condition=raw["selector_or_condition"],
            value_reference=raw["value_reference"],
            evidence_reference=raw["evidence_reference"],
        )
    elif kind == IntentKind.TARGET_SESSION_ACQUISITION.value:
        _exact_fields(
            raw,
            {
                "binding",
                "credential_references",
                "isolated",
                "kind",
                "login_url",
                "method",
                "mode",
                "principal_label",
                "requested_session_id",
                "sequence",
            },
            "target session intent",
        )
        if not isinstance(raw["credential_references"], list):
            raise TransportContractError("target credential_references must be a list")
        intent = TargetSessionIntent(
            binding=_binding_from_dict(raw["binding"]),
            sequence=raw["sequence"],
            mode=raw["mode"],
            login_url=raw["login_url"],
            method=raw["method"],
            principal_label=raw["principal_label"],
            credential_references=tuple(
                _principal_credential_from_dict(item) for item in raw["credential_references"]
            ),
            requested_session_id=raw["requested_session_id"],
            isolated=raw["isolated"],
        )
    else:
        raise TransportContractError("transport step intent kind is invalid")
    if raw != intent.to_dict():
        raise TransportContractError("transport step intent is not canonical")
    return intent


def _observation_from_dict(raw: Any) -> ResponseObservation:
    if not isinstance(raw, dict):
        raise TransportContractError("transport observation must be an object")
    _require_no_effects(raw.get("effects"), "transport observation")
    kind = raw.get("kind")
    if kind == "http_response":
        _exact_fields(
            raw,
            {
                "body_sha256",
                "cookies",
                "effects",
                "headers",
                "intent_sha256",
                "kind",
                "mime_type",
                "redirect_url",
                "response_size_bytes",
                "status_code",
            },
            "HTTP observation",
        )
        if not isinstance(raw["headers"], list) or not isinstance(raw["cookies"], list):
            raise TransportContractError("HTTP observation headers and cookies must be lists")
        observation: ResponseObservation = HttpResponseObservation(
            intent_sha256=raw["intent_sha256"],
            status_code=raw["status_code"],
            mime_type=raw["mime_type"],
            response_size_bytes=raw["response_size_bytes"],
            body_sha256=raw["body_sha256"],
            headers=tuple(_observed_header_from_dict(item) for item in raw["headers"]),
            cookies=tuple(CookieMetadata.from_dict(item) for item in raw["cookies"]),
            redirect_url=raw["redirect_url"],
        )
    elif kind == "browser_observation":
        _exact_fields(
            raw,
            {
                "cookies",
                "effects",
                "evidence_references",
                "intent_sha256",
                "kind",
                "metadata",
                "mime_type",
                "response_size_bytes",
                "session",
            },
            "browser observation",
        )
        if not isinstance(raw["cookies"], list):
            raise TransportContractError("browser observation cookies must be a list")
        if not isinstance(raw["metadata"], dict):
            raise TransportContractError("browser observation metadata must be an object")
        observation = BrowserObservation(
            intent_sha256=raw["intent_sha256"],
            session=_session_binding_from_dict(raw["session"]),
            metadata=tuple(raw["metadata"].items()),
            cookies=tuple(CookieMetadata.from_dict(item) for item in raw["cookies"]),
            evidence_references=_tuple_strings(
                raw["evidence_references"],
                "browser observation evidence_references",
            ),
            mime_type=raw["mime_type"],
            response_size_bytes=raw["response_size_bytes"],
        )
    elif kind == "target_session_observation":
        _exact_fields(
            raw,
            {
                "cookies",
                "effects",
                "intent_sha256",
                "isolated",
                "kind",
                "principal_label",
                "session_id",
            },
            "target session observation",
        )
        if not isinstance(raw["cookies"], list):
            raise TransportContractError("target session observation cookies must be a list")
        observation = TargetSessionObservation(
            intent_sha256=raw["intent_sha256"],
            session_id=raw["session_id"],
            principal_label=raw["principal_label"],
            cookies=tuple(CookieMetadata.from_dict(item) for item in raw["cookies"]),
            isolated=raw["isolated"],
        )
    else:
        raise TransportContractError("transport observation kind is invalid")
    if raw != observation.to_dict():
        raise TransportContractError("transport observation is not canonical")
    return observation


def _header_field_from_dict(raw: Any) -> HeaderField:
    _exact_fields(raw, {"name", "value"}, "request header")
    return HeaderField(raw["name"], raw["value"])


def _observed_header_from_dict(raw: Any) -> ObservedHeader:
    _exact_fields(raw, {"name", "redacted", "value"}, "observed header")
    return ObservedHeader(raw["name"], raw["value"], raw["redacted"])


def _session_binding_from_dict(raw: Any) -> SessionBinding:
    _exact_fields(raw, {"principal_label", "session_id"}, "session binding")
    return SessionBinding(raw["session_id"], raw["principal_label"])


def _principal_credential_from_dict(raw: Any) -> PrincipalCredentialReference:
    _exact_fields(raw, {"credential_ref", "principal_label"}, "credential reference")
    return PrincipalCredentialReference(raw["principal_label"], raw["credential_ref"])


def _adapter_from_dict(raw: Any) -> AdapterIdentity:
    _exact_fields(raw, {"adapter_id", "version"}, "adapter identity")
    return AdapterIdentity(raw["adapter_id"], raw["version"])


def _budget_from_dict(raw: Any) -> TransportBudget:
    _exact_fields(
        raw,
        {
            "max_redirects",
            "max_request_bytes",
            "max_response_bytes",
            "max_steps",
            "max_total_request_bytes",
            "max_total_response_bytes",
            "mime_limits",
            "requests_active",
            "requests_completed",
            "requests_in_current_minute",
        },
        "transport budget",
    )
    if not isinstance(raw["mime_limits"], list):
        raise TransportContractError("transport budget mime_limits must be a list")
    limits = []
    for item in raw["mime_limits"]:
        _exact_fields(item, {"max_bytes", "mime_type"}, "MIME limit")
        limits.append(MimeLimit(item["mime_type"], item["max_bytes"]))
    return TransportBudget(
        max_steps=raw["max_steps"],
        max_request_bytes=raw["max_request_bytes"],
        max_response_bytes=raw["max_response_bytes"],
        max_total_request_bytes=raw["max_total_request_bytes"],
        max_total_response_bytes=raw["max_total_response_bytes"],
        max_redirects=raw["max_redirects"],
        mime_limits=tuple(limits),
        requests_completed=raw["requests_completed"],
        requests_active=raw["requests_active"],
        requests_in_current_minute=raw["requests_in_current_minute"],
    )


def _none_fields(value: Any, label: str, *names: str) -> None:
    if any(getattr(value, name) is not None for name in names):
        raise TransportContractError(f"{label} accepts none of {', '.join(names)}")


def _browser_text(value: Any, label: str) -> str:
    text = _safe_text(value, label, 1024)
    folded = text.casefold()
    if "javascript:" in folded or "<script" in folded or "eval(" in folded:
        raise TransportContractError(f"{label} contains forbidden script syntax")
    if "input[type=file" in folded or "file://" in folded:
        raise TransportContractError(f"{label} contains forbidden file access")
    return text


def _safe_url(value: Any, label: str) -> str:
    text = _safe_text(value, label, 2048)
    if not text.startswith("https://"):
        raise TransportContractError(f"{label} must use HTTPS")
    if "#" in text:
        raise TransportContractError(f"{label} must not contain a fragment")
    return text


def _safe_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TransportContractError(
            f"{label} must be a non-empty string of at most {maximum} characters"
        )
    if any(ord(character) < 32 or ord(character) > 126 for character in value):
        raise TransportContractError(f"{label} must contain printable ASCII only")
    if SECRET_RE.search(value):
        raise TransportContractError(f"{label} contains raw credential or secret material")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise TransportContractError(f"{label} is not a canonical identifier")
    return value


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise TransportContractError(f"{label} is not a canonical token")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise TransportContractError(f"{label} is not a canonical version")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise TransportContractError(f"{label} must be a lowercase sha256 digest")
    return value


def _credential_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or CREDENTIAL_REF_RE.fullmatch(value) is None:
        raise TransportContractError(f"{label} must be an opaque credref reference")
    return value


def _evidence_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or EVIDENCE_REF_RE.fullmatch(value) is None:
        raise TransportContractError(f"{label} must be an evidence reference or sha256 digest")
    return value


def _evidence_refs(value: Any, label: str) -> tuple[str, ...]:
    refs = _refs(value, label, allow_empty=True)
    for item in refs:
        _evidence_ref(item, label)
    return refs


def _refs(value: Any, label: str, *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, tuple) or (not allow_empty and not value):
        qualifier = "non-empty " if not allow_empty else ""
        raise TransportContractError(f"{label} must be a {qualifier}tuple")
    for item in value:
        _identifier(item, label)
    if len(set(value)) != len(value):
        raise TransportContractError(f"{label} must not contain duplicates")
    return tuple(sorted(value))


def _tuple_strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TransportContractError(f"{label} must be a list of strings")
    return tuple(value)


def _header_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEADER_NAME_RE.fullmatch(value) is None:
        raise TransportContractError(f"{label} is invalid")
    return value.lower()


def _header_names(value: Any, label: str, *, empty: bool = False) -> set[str]:
    if not isinstance(value, tuple) or (not empty and not value):
        raise TransportContractError(f"{label} must be a tuple")
    names = {_header_name(item, label) for item in value}
    if len(names) != len(value):
        raise TransportContractError(f"{label} must not contain duplicates")
    return names


def _mime(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise TransportContractError(f"{label} must be a string")
    normalized = value.split(";", 1)[0].strip().lower()
    if MIME_RE.fullmatch(normalized) is None:
        raise TransportContractError(f"{label} is invalid")
    return normalized


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise TransportContractError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TransportContractError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.tzinfo != UTC:
        raise TransportContractError(f"{label} must use UTC")
    return parsed


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise TransportContractError(f"{label} must be an integer from 1 through {maximum}")
    return value


def _non_negative_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise TransportContractError(f"{label} must be an integer from 0 through {maximum}")
    return value


def _exact_fields(raw: Any, required: set[str], label: str) -> None:
    if not isinstance(raw, dict):
        raise TransportContractError(f"{label} must be an object")
    missing = required - set(raw)
    extra = set(raw) - required
    if missing or extra:
        raise TransportContractError(
            f"{label} fields are invalid: missing={sorted(missing)}, extra={sorted(extra)}"
        )


def _reject_secrets_in_json(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, member in value.items():
            if str(key).casefold() in {
                "password",
                "credential_value",
                "token_value",
                "cookie_value",
            }:
                raise TransportContractError(f"{label} contains a forbidden secret field")
            _reject_secrets_in_json(member, label)
    elif isinstance(value, list):
        for member in value:
            _reject_secrets_in_json(member, label)
    elif isinstance(value, str) and SECRET_RE.search(value):
        raise TransportContractError(f"{label} contains raw credential or secret material")


__all__ = [
    "AdapterHealthState",
    "AdapterIdentity",
    "AssessmentBinding",
    "AuthenticationMode",
    "BrowserAction",
    "BrowserActionAdapter",
    "BrowserActionIntent",
    "BrowserObservation",
    "BrowserResultSpec",
    "CookieMetadata",
    "DeterministicBrowserTransport",
    "DeterministicHttpTransport",
    "DeterministicTargetSessionTransport",
    "ExecutionControl",
    "HeaderField",
    "HeaderPolicy",
    "HealthObservation",
    "HttpExchangeAdapter",
    "HttpMethod",
    "HttpRequestIntent",
    "HttpResponseObservation",
    "HttpResponseSpec",
    "IntentKind",
    "MimeLimit",
    "NO_EFFECTS",
    "ObservedHeader",
    "PrincipalCredentialReference",
    "ResponseObservation",
    "ScriptedBrowserAction",
    "ScriptedHttpExchange",
    "ScriptedSessionAcquisition",
    "SessionBinding",
    "SessionResultSpec",
    "TargetSessionAdapter",
    "TargetSessionIntent",
    "TargetSessionObservation",
    "TransportBudget",
    "TransportContractError",
    "TransportResult",
    "TransportStep",
    "TransportStepState",
    "TransportTranscript",
    "build_transport_transcript",
    "canonical_json",
    "canonical_sha256",
]
