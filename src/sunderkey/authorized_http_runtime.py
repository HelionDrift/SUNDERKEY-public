"""Fail-closed authorized HTTP boundary with no built-in network client.

The boundary accepts only caller-supplied authority, policy, clock, resolver,
body, safety, and HTTP adapters. It does not resolve credentials, persist
secrets, follow redirects, retry requests, or grant assessment authority.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Protocol
from urllib.parse import parse_qsl, urlsplit

from .assessment_transport_contracts import (
    FORBIDDEN_SECRET_HEADERS,
    HeaderField,
    HttpRequestIntent,
    MimeLimit,
    canonical_json,
)
from .execution_control_runtime import (
    AdmissionReceipt,
    AdmissionStatus,
    ClockObservation,
    ExecutionBinding,
    ExecutionRequest,
    HealthState,
)
from .signed_scope_compiler import ScopeBudgetState, VerifiedAssessmentScope, evaluate_request

SCHEMA_VERSION = 1
NO_BUILTIN_IO = True
ENFORCEMENT_BOUNDARY = "injected_authorized_http_adapter_only"
MAX_BODY_BYTES = 100_000_000

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_.-]{1,63}\Z")
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}\Z")
_MIME = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\Z")
_SECRET = re.compile(
    rb"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    rb"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    rb"auth[_-]?token|id[_-]?token|client[_-]?secret|private[_-]?key|"
    rb"authorization|token)\b[\"']?\s*[:=]|"
    rb"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|\bbasic\s+[A-Za-z0-9+/=]{8,}|"
    rb"\bAKIA[0-9A-Z]{16}\b|\bgh[oprsu]_[A-Za-z0-9]{20,})",
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
        "credentials",
        "idtoken",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "token",
    }
)


class AuthorizedHttpRuntimeError(ValueError):
    """Raised when a runtime value is malformed or evidence is invalid."""


class StructuredPayloadScreeningError(AuthorizedHttpRuntimeError):
    """Raised when a structured body cannot be screened conclusively."""


class ExchangeStatus(StrEnum):
    REJECTED_BEFORE_SEND = "rejected_before_send"
    BACKEND_FAILED = "backend_failed"
    RESPONSE_REJECTED = "response_rejected"
    COMPLETED = "completed"


class HttpBackendFailure(RuntimeError):
    """A safe, coded failure raised by an injected HTTP backend."""

    def __init__(self, code: str) -> None:
        _code(code, "backend failure code")
        super().__init__(code)
        self.code = code


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_sha(value: Any) -> str:
    return _sha(canonical_json(value).encode("ascii"))


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise AuthorizedHttpRuntimeError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AuthorizedHttpRuntimeError(f"{label} must be a sha256 digest")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise AuthorizedHttpRuntimeError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AuthorizedHttpRuntimeError(f"{label} is invalid")
    return value


def _header_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEADER_NAME.fullmatch(value) is None:
        raise AuthorizedHttpRuntimeError(f"{label} is invalid")
    return value.lower()


def _mime(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AuthorizedHttpRuntimeError(f"{label} is invalid")
    normalized = value.split(";", 1)[0].strip().lower()
    if _MIME.fullmatch(normalized) is None:
        raise AuthorizedHttpRuntimeError(f"{label} is invalid")
    return normalized


def _safe_ascii(value: Any, label: str, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise AuthorizedHttpRuntimeError(f"{label} must be visible ASCII")
    return value


def _utc(value: Any, label: str) -> str:
    result = _safe_ascii(value, label, 20)
    if len(result) != 20 or not result.endswith("Z"):
        raise AuthorizedHttpRuntimeError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(result[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthorizedHttpRuntimeError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != result:
        raise AuthorizedHttpRuntimeError(f"{label} must be canonical UTC")
    return result


def _binding_sha(binding: ExecutionBinding) -> str:
    return _canonical_sha(binding.to_dict())


def _secret_field_name(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = "".join(character.lower() for character in value if character.isalnum())
    if normalized in _SECRET_FIELD_NAMES:
        return True
    components = tuple(
        "".join(character.lower() for character in item if character.isalnum())
        for item in re.split(r"[^A-Za-z0-9]+", value)
        if item
    )
    return any(item in _SECRET_FIELD_NAMES for item in components)


def _json_contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _secret_field_name(key) and item not in (None, "", [], {}):
                return True
            if _json_contains_secret(item):
                return True
    elif isinstance(value, list):
        return any(_json_contains_secret(item) for item in value)
    elif isinstance(value, str):
        return _SECRET.search(value.encode("utf-8")) is not None
    return False


def _contains_secret(data: bytes, mime_type: str) -> bool:
    if _SECRET.search(data):
        return True
    if mime_type == "application/json" or mime_type.endswith("+json"):
        try:
            value = json.loads(data.decode("utf-8", errors="strict"))
            return _json_contains_secret(value)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise StructuredPayloadScreeningError(
                "structured payload secret screening failed"
            ) from exc
    if mime_type == "application/x-www-form-urlencoded":
        try:
            values = parse_qsl(
                data.decode("utf-8", errors="strict"),
                keep_blank_values=True,
                strict_parsing=True,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise StructuredPayloadScreeningError(
                "structured payload secret screening failed"
            ) from exc
        return any(
            (_secret_field_name(name) and value != "")
            or _SECRET.search(value.encode("utf-8")) is not None
            for name, value in values
        )
    return False


@dataclass(frozen=True, slots=True)
class AuthorizedHttpPolicy:
    """Exact execution binding plus byte, MIME, and header ceilings."""

    binding: ExecutionBinding
    execution_policy_id: str
    execution_policy_sha256: str
    request_header_allowlist: tuple[str, ...]
    response_header_allowlist: tuple[str, ...]
    mime_limits: tuple[MimeLimit, ...]
    max_request_bytes: int
    max_response_bytes: int
    policy_id: str = ""
    policy_sha256: str = ""

    KIND: ClassVar[str] = "authorized_http_policy"

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ExecutionBinding):
            raise AuthorizedHttpRuntimeError("policy binding is invalid")
        _identifier(self.execution_policy_id, "execution_policy_id")
        _digest(self.execution_policy_sha256, "execution_policy_sha256")
        request = _header_allowlist(self.request_header_allowlist, "request header allowlist")
        response = _header_allowlist(self.response_header_allowlist, "response header allowlist")
        if FORBIDDEN_SECRET_HEADERS.intersection(request | response):
            raise AuthorizedHttpRuntimeError("secret headers cannot be allowlisted")
        object.__setattr__(self, "request_header_allowlist", tuple(sorted(request)))
        object.__setattr__(self, "response_header_allowlist", tuple(sorted(response)))
        if not isinstance(self.mime_limits, tuple) or not self.mime_limits:
            raise AuthorizedHttpRuntimeError("mime_limits must be a non-empty tuple")
        if not all(isinstance(item, MimeLimit) for item in self.mime_limits):
            raise AuthorizedHttpRuntimeError("mime_limits contains an invalid entry")
        mimes = tuple(sorted(self.mime_limits, key=lambda item: item.mime_type))
        if len({item.mime_type for item in mimes}) != len(mimes):
            raise AuthorizedHttpRuntimeError("mime_limits contains duplicate MIME types")
        object.__setattr__(self, "mime_limits", mimes)
        _integer(self.max_request_bytes, "max_request_bytes", 0, MAX_BODY_BYTES)
        _integer(self.max_response_bytes, "max_response_bytes", 1, MAX_BODY_BYTES)
        body = self.body()
        digest = _canonical_sha({"body": body, "kind": self.KIND})
        identity = "AHP-" + digest[7:39].upper()
        if self.policy_id and self.policy_id != identity:
            raise AuthorizedHttpRuntimeError("policy_id does not match content")
        if self.policy_sha256 and not hmac.compare_digest(self.policy_sha256, digest):
            raise AuthorizedHttpRuntimeError("policy_sha256 does not match content")
        object.__setattr__(self, "policy_id", identity)
        object.__setattr__(self, "policy_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "execution_policy_id": self.execution_policy_id,
            "execution_policy_sha256": self.execution_policy_sha256,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
            "mime_limits": [item.to_dict() for item in self.mime_limits],
            "request_header_allowlist": list(self.request_header_allowlist),
            "response_header_allowlist": list(self.response_header_allowlist),
        }

    def mime_ceiling(self, value: str) -> int | None:
        normalized = _mime(value, "MIME type")
        for limit in self.mime_limits:
            if limit.mime_type == normalized:
                return limit.max_bytes
        return None


def _header_allowlist(values: Any, label: str) -> set[str]:
    if not isinstance(values, tuple):
        raise AuthorizedHttpRuntimeError(f"{label} must be a tuple")
    normalized = {_header_name(item, label) for item in values}
    if len(normalized) != len(values):
        raise AuthorizedHttpRuntimeError(f"{label} contains duplicates")
    return normalized


@dataclass(frozen=True, slots=True)
class RuntimeSafetySnapshot:
    binding_sha256: str
    request_sha256: str
    health: HealthState
    canceled: bool
    emergency_stop: bool

    def __post_init__(self) -> None:
        _digest(self.binding_sha256, "safety binding_sha256")
        _digest(self.request_sha256, "safety request_sha256")
        if not isinstance(self.health, HealthState):
            raise AuthorizedHttpRuntimeError("safety health is invalid")
        if not isinstance(self.canceled, bool) or not isinstance(self.emergency_stop, bool):
            raise AuthorizedHttpRuntimeError("safety stop flags are invalid")


class RuntimeClock(Protocol):
    def observe(self) -> ClockObservation: ...


class RuntimeSafetyMonitor(Protocol):
    def observe(self) -> RuntimeSafetySnapshot: ...


@dataclass(frozen=True, slots=True)
class DnsResolution:
    host: str
    addresses: tuple[str, ...]
    resolver_id: str

    def __post_init__(self) -> None:
        host = _normalize_host(self.host)
        object.__setattr__(self, "host", host)
        _identifier(self.resolver_id, "resolver_id")
        if not isinstance(self.addresses, tuple) or not self.addresses:
            raise AuthorizedHttpRuntimeError("DNS addresses must be a non-empty tuple")
        addresses: list[str] = []
        for value in self.addresses:
            try:
                addresses.append(ipaddress.ip_address(value).compressed)
            except (TypeError, ValueError) as exc:
                raise AuthorizedHttpRuntimeError("DNS address is invalid") from exc
        normalized = tuple(sorted(set(addresses), key=lambda item: (":" in item, item)))
        if len(normalized) != len(self.addresses):
            raise AuthorizedHttpRuntimeError("DNS addresses must be unique and canonical")
        object.__setattr__(self, "addresses", normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "addresses": list(self.addresses),
            "host": self.host,
            "resolver_id": self.resolver_id,
        }

    @property
    def attestation_sha256(self) -> str:
        return _canonical_sha(self.to_dict())


class DnsResolver(Protocol):
    def resolve(self, host: str) -> DnsResolution: ...


class RequestBodyProvider(Protocol):
    def read(self, body_sha256: str, size_bytes: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class HttpBackendRequest:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    connect_addresses: tuple[str, ...]
    follow_redirects: bool = False
    maximum_attempts: int = 1
    max_response_bytes: int = 0


@dataclass(frozen=True, slots=True)
class HttpBackendResponse:
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    body_complete: bool
    limit_exceeded: bool
    redirected: bool
    attempts: int

    def __post_init__(self) -> None:
        _integer(self.status_code, "response status_code", 100, 599)
        if not isinstance(self.headers, tuple):
            raise AuthorizedHttpRuntimeError("response headers must be a tuple")
        if not isinstance(self.body, bytes):
            raise AuthorizedHttpRuntimeError("response body must be bytes")
        for value, label in (
            (self.body_complete, "body_complete"),
            (self.limit_exceeded, "limit_exceeded"),
            (self.redirected, "redirected"),
        ):
            if not isinstance(value, bool):
                raise AuthorizedHttpRuntimeError(f"{label} must be a boolean")
        _integer(self.attempts, "response attempts", 1, 1_000_000)


class HttpBackend(Protocol):
    def send(self, request: HttpBackendRequest) -> HttpBackendResponse: ...


@dataclass(frozen=True, slots=True)
class TranscriptEvent:
    sequence: int
    stage: str
    observed_at: str
    monotonic_tick: int
    detail_sha256: str
    previous_event_sha256: str | None
    event_sha256: str = ""

    def __post_init__(self) -> None:
        _integer(self.sequence, "event sequence", 1, 64)
        _code(self.stage, "event stage")
        _utc(self.observed_at, "event observed_at")
        _integer(self.monotonic_tick, "event monotonic_tick", 1, 2**63 - 1)
        _digest(self.detail_sha256, "event detail_sha256")
        if self.previous_event_sha256 is not None:
            _digest(self.previous_event_sha256, "event previous_event_sha256")
        digest = _canonical_sha(self.body())
        if self.event_sha256 and not hmac.compare_digest(self.event_sha256, digest):
            raise AuthorizedHttpRuntimeError("event_sha256 does not match content")
        object.__setattr__(self, "event_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "detail_sha256": self.detail_sha256,
            "monotonic_tick": self.monotonic_tick,
            "observed_at": self.observed_at,
            "previous_event_sha256": self.previous_event_sha256,
            "sequence": self.sequence,
            "stage": self.stage,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "event_sha256": self.event_sha256}


@dataclass(frozen=True, slots=True)
class HttpExchangeReceipt:
    status: ExchangeStatus
    reason: str
    scope_id: str
    scope_sha256: str
    intent_sha256: str
    execution_request_id: str
    execution_request_sha256: str
    admission_receipt_id: str
    admission_receipt_sha256: str
    policy_id: str
    policy_sha256: str
    binding: ExecutionBinding
    transport_called: bool
    request_body_sha256: str | None
    request_size_bytes: int
    response_status_code: int | None
    response_mime_type: str | None
    response_body_sha256: str | None
    response_size_bytes: int
    dns_attestation_sha256: tuple[str, ...]
    transcript: tuple[TranscriptEvent, ...]
    network_call_performed: bool
    authority_effect: str = "none"
    qualification_effect: str = "none"
    enforcement_boundary: str = ENFORCEMENT_BOUNDARY
    transcript_id: str = ""
    transcript_sha256: str = ""
    receipt_id: str = ""
    receipt_sha256: str = ""

    KIND: ClassVar[str] = "authorized_http_exchange_receipt"

    def __post_init__(self) -> None:
        if not isinstance(self.status, ExchangeStatus):
            raise AuthorizedHttpRuntimeError("receipt status is invalid")
        _code(self.reason, "receipt reason")
        for value, label in (
            (self.scope_id, "scope_id"),
            (self.execution_request_id, "execution_request_id"),
            (self.admission_receipt_id, "admission_receipt_id"),
            (self.policy_id, "policy_id"),
        ):
            _identifier(value, label)
        for value, label in (
            (self.scope_sha256, "scope_sha256"),
            (self.intent_sha256, "intent_sha256"),
            (self.execution_request_sha256, "execution_request_sha256"),
            (self.admission_receipt_sha256, "admission_receipt_sha256"),
            (self.policy_sha256, "policy_sha256"),
        ):
            _digest(value, label)
        if not isinstance(self.binding, ExecutionBinding):
            raise AuthorizedHttpRuntimeError("receipt binding is invalid")
        if self.transport_called != self.network_call_performed:
            raise AuthorizedHttpRuntimeError("network call evidence is inconsistent")
        if self.status is ExchangeStatus.REJECTED_BEFORE_SEND and self.transport_called:
            raise AuthorizedHttpRuntimeError("pre-send rejection cannot report transport")
        if self.status is not ExchangeStatus.REJECTED_BEFORE_SEND and not self.transport_called:
            raise AuthorizedHttpRuntimeError("post-send receipt requires transport")
        if self.status is ExchangeStatus.COMPLETED and not self.transport_called:
            raise AuthorizedHttpRuntimeError("completed receipt requires transport")
        if self.status is ExchangeStatus.COMPLETED and (
            self.reason != "completed"
            or self.response_status_code is None
            or self.response_mime_type is None
            or self.response_body_sha256 is None
        ):
            raise AuthorizedHttpRuntimeError(
                "completed receipt requires status, MIME, and body digest"
            )
        if self.status is not ExchangeStatus.COMPLETED and self.response_body_sha256 is not None:
            raise AuthorizedHttpRuntimeError(
                "non-completed receipt cannot carry a response body digest"
            )
        if self.authority_effect != "none" or self.qualification_effect != "none":
            raise AuthorizedHttpRuntimeError("receipt cannot grant authority or qualification")
        if self.enforcement_boundary != ENFORCEMENT_BOUNDARY:
            raise AuthorizedHttpRuntimeError("enforcement boundary is invalid")
        if self.request_body_sha256 is not None:
            _digest(self.request_body_sha256, "request_body_sha256")
        _integer(self.request_size_bytes, "request_size_bytes", 0, MAX_BODY_BYTES)
        if not self.request_size_bytes and self.request_body_sha256 is not None:
            raise AuthorizedHttpRuntimeError("empty request cannot carry a body digest")
        if self.transport_called and self.request_size_bytes and self.request_body_sha256 is None:
            raise AuthorizedHttpRuntimeError("sent request requires a body digest")
        if self.response_status_code is not None:
            _integer(self.response_status_code, "response_status_code", 100, 599)
        if self.response_mime_type is not None:
            _mime(self.response_mime_type, "response_mime_type")
        if self.response_body_sha256 is not None:
            _digest(self.response_body_sha256, "response_body_sha256")
        _integer(self.response_size_bytes, "response_size_bytes", 0, MAX_BODY_BYTES)
        for item in self.dns_attestation_sha256:
            _digest(item, "dns attestation")
        _validate_transcript(self.transcript)
        transcript_body = [item.to_dict() for item in self.transcript]
        transcript_digest = _canonical_sha(transcript_body)
        transcript_identity = "AHT-" + transcript_digest[7:39].upper()
        if self.transcript_id and self.transcript_id != transcript_identity:
            raise AuthorizedHttpRuntimeError("transcript_id does not match content")
        if self.transcript_sha256 and not hmac.compare_digest(
            self.transcript_sha256, transcript_digest
        ):
            raise AuthorizedHttpRuntimeError("transcript_sha256 does not match content")
        object.__setattr__(self, "transcript_id", transcript_identity)
        object.__setattr__(self, "transcript_sha256", transcript_digest)
        digest = _canonical_sha({"body": self.body(), "kind": self.KIND})
        identity = "AHR-" + digest[7:39].upper()
        if self.receipt_id and self.receipt_id != identity:
            raise AuthorizedHttpRuntimeError("receipt_id does not match content")
        if self.receipt_sha256 and not hmac.compare_digest(self.receipt_sha256, digest):
            raise AuthorizedHttpRuntimeError("receipt_sha256 does not match content")
        object.__setattr__(self, "receipt_id", identity)
        object.__setattr__(self, "receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "admission_receipt_id": self.admission_receipt_id,
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "authority_effect": self.authority_effect,
            "binding": self.binding.to_dict(),
            "dns_attestation_sha256": list(self.dns_attestation_sha256),
            "enforcement_boundary": self.enforcement_boundary,
            "execution_request_id": self.execution_request_id,
            "execution_request_sha256": self.execution_request_sha256,
            "intent_sha256": self.intent_sha256,
            "network_call_performed": self.network_call_performed,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "qualification_effect": self.qualification_effect,
            "reason": self.reason,
            "request_body_sha256": self.request_body_sha256,
            "request_size_bytes": self.request_size_bytes,
            "response_body_sha256": self.response_body_sha256,
            "response_mime_type": self.response_mime_type,
            "response_size_bytes": self.response_size_bytes,
            "response_status_code": self.response_status_code,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "status": self.status.value,
            "transcript": [item.to_dict() for item in self.transcript],
            "transcript_id": self.transcript_id,
            "transcript_sha256": self.transcript_sha256,
            "transport_called": self.transport_called,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
        }


def _validate_transcript(events: tuple[TranscriptEvent, ...]) -> None:
    if not isinstance(events, tuple) or not events:
        raise AuthorizedHttpRuntimeError("transcript must be a non-empty tuple")
    previous: str | None = None
    last_tick = 0
    for index, event in enumerate(events, start=1):
        if not isinstance(event, TranscriptEvent):
            raise AuthorizedHttpRuntimeError("transcript contains an invalid event")
        if event.sequence != index or event.previous_event_sha256 != previous:
            raise AuthorizedHttpRuntimeError("transcript chain is invalid")
        if event.monotonic_tick <= last_tick:
            raise AuthorizedHttpRuntimeError("transcript clock did not advance")
        previous = event.event_sha256
        last_tick = event.monotonic_tick


@dataclass(slots=True)
class _Evidence:
    events: list[TranscriptEvent] = field(default_factory=list)
    last_tick: int = 0

    def add(self, stage: str, detail: Any, observation: ClockObservation) -> None:
        if not isinstance(observation, ClockObservation):
            raise AuthorizedHttpRuntimeError("clock returned an invalid observation")
        if observation.monotonic_tick <= self.last_tick:
            raise AuthorizedHttpRuntimeError("clock monotonic tick did not advance")
        previous = None if not self.events else self.events[-1].event_sha256
        self.events.append(
            TranscriptEvent(
                len(self.events) + 1,
                stage,
                observation.observed_at,
                observation.monotonic_tick,
                _canonical_sha(detail),
                previous,
            )
        )
        self.last_tick = observation.monotonic_tick


def _normalize_host(value: str) -> str:
    if not isinstance(value, str) or not value or value.endswith("."):
        raise AuthorizedHttpRuntimeError("host is invalid")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        host = value.lower()
        if (
            len(host) > 253
            or "." not in host
            or any(
                not label
                or len(label) > 63
                or label[0] == "-"
                or label[-1] == "-"
                or not all(
                    character.isascii() and (character.isalnum() or character == "-")
                    for character in label
                )
                for label in host.split(".")
            )
        ):
            raise AuthorizedHttpRuntimeError("host is not a canonical DNS name") from exc
        return host


def _url(value: str) -> tuple[str, int]:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or any(character in value for character in "\\%#\t\r\n ")
    ):
        raise AuthorizedHttpRuntimeError("URL contains ambiguous syntax")
    try:
        parts = urlsplit(value)
        port = parts.port or 443
    except ValueError as exc:
        raise AuthorizedHttpRuntimeError("URL is invalid") from exc
    if parts.scheme != "https" or parts.hostname is None or not parts.netloc:
        raise AuthorizedHttpRuntimeError("URL must use HTTPS")
    if parts.username is not None or parts.password is not None:
        raise AuthorizedHttpRuntimeError("URL userinfo is forbidden")
    if parts.fragment or parts.query:
        raise AuthorizedHttpRuntimeError("URL query and fragment are forbidden")
    if not parts.path.startswith("/") or "//" in parts.path:
        raise AuthorizedHttpRuntimeError("URL path is not canonical")
    return _normalize_host(parts.hostname), port


def _check_scope_addresses(
    scope: VerifiedAssessmentScope, host: str, addresses: tuple[str, ...]
) -> None:
    document = scope.to_dict()
    targets = document["targets"]
    networks = tuple(ipaddress.ip_network(item) for item in targets["cidrs"])
    exclusions = tuple(
        ipaddress.ip_network(item) for rule in document["exclusions"] for item in rule["cidrs"]
    )
    literal = None
    with suppress(ValueError):
        literal = ipaddress.ip_address(host)
    if literal is not None and tuple(addresses) != (literal.compressed,):
        raise AuthorizedHttpRuntimeError("literal IP attestation mismatch")
    for text in addresses:
        address = ipaddress.ip_address(text)
        if any(address in network for network in exclusions):
            raise AuthorizedHttpRuntimeError("resolved address matches a scope exclusion")
        if networks and not any(address in network for network in networks):
            raise AuthorizedHttpRuntimeError("resolved address is outside signed scope CIDRs")


def _check_admission(
    scope: VerifiedAssessmentScope,
    intent: HttpRequestIntent,
    execution_request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedHttpPolicy,
) -> None:
    if not isinstance(scope, VerifiedAssessmentScope):
        raise AuthorizedHttpRuntimeError("scope must be a VerifiedAssessmentScope")
    if not isinstance(intent, HttpRequestIntent):
        raise AuthorizedHttpRuntimeError("intent must be an HttpRequestIntent")
    if not isinstance(execution_request, ExecutionRequest):
        raise AuthorizedHttpRuntimeError("execution_request is invalid")
    if (
        not isinstance(admission, AdmissionReceipt)
        or admission.status is not AdmissionStatus.ADMITTED
    ):
        raise AuthorizedHttpRuntimeError("execution admission is not allowed")
    if not isinstance(policy, AuthorizedHttpPolicy):
        raise AuthorizedHttpRuntimeError("authorized HTTP policy is invalid")
    if (
        scope.scope_id != intent.binding.scope_id
        or scope.content_sha256 != intent.binding.scope_sha256
    ):
        raise AuthorizedHttpRuntimeError("intent scope binding mismatch")
    if execution_request.binding != policy.binding:
        raise AuthorizedHttpRuntimeError("execution binding mismatch")
    if (
        execution_request.binding.scope_id != scope.scope_id
        or execution_request.binding.scope_sha256 != scope.content_sha256
    ):
        raise AuthorizedHttpRuntimeError("execution scope binding mismatch")
    if intent.binding.task_id != execution_request.binding.context_id:
        raise AuthorizedHttpRuntimeError("intent context binding mismatch")
    if intent.session is None or intent.session.session_id != execution_request.binding.session_id:
        raise AuthorizedHttpRuntimeError("intent session binding mismatch")
    if execution_request.policy_id != policy.execution_policy_id or not hmac.compare_digest(
        execution_request.policy_sha256, policy.execution_policy_sha256
    ):
        raise AuthorizedHttpRuntimeError("execution policy binding mismatch")
    if (
        admission.request_id != execution_request.request_id
        or not hmac.compare_digest(admission.request_sha256, execution_request.request_sha256)
        or admission.policy_id != execution_request.policy_id
        or not hmac.compare_digest(admission.policy_sha256, execution_request.policy_sha256)
    ):
        raise AuthorizedHttpRuntimeError("admission receipt binding mismatch")
    if not hmac.compare_digest(execution_request.payload_sha256, intent.intent_sha256):
        raise AuthorizedHttpRuntimeError("execution request does not bind the HTTP intent")
    exact_intent_size = len(canonical_json(intent.to_dict()).encode("ascii"))
    if execution_request.payload_size_bytes != exact_intent_size:
        raise AuthorizedHttpRuntimeError("execution request payload size mismatch")


def _check_current_scope(
    scope: VerifiedAssessmentScope,
    intent: HttpRequestIntent,
    observation: ClockObservation,
) -> str:
    decision = evaluate_request(
        scope,
        url=intent.url,
        method=intent.method.value,
        technique_id=intent.binding.technique_id,
        impact_tier=intent.binding.impact_tier,
        budget_state=ScopeBudgetState(
            intent.binding.budget.requests_completed,
            intent.binding.budget.requests_active,
            intent.binding.budget.requests_in_current_minute,
        ),
        at=datetime.fromisoformat(observation.observed_at[:-1] + "+00:00"),
    )
    if not decision.allowed:
        raise AuthorizedHttpRuntimeError(f"scope rejected: {decision.reason}")
    return decision.reason


def _check_safety(
    monitor: RuntimeSafetyMonitor,
    binding: ExecutionBinding,
    request_sha256: str,
) -> RuntimeSafetySnapshot:
    snapshot = monitor.observe()
    if not isinstance(snapshot, RuntimeSafetySnapshot):
        raise AuthorizedHttpRuntimeError("safety monitor returned an invalid snapshot")
    if (
        snapshot.binding_sha256 != _binding_sha(binding)
        or snapshot.request_sha256 != request_sha256
    ):
        raise AuthorizedHttpRuntimeError("safety snapshot binding mismatch")
    if snapshot.canceled:
        raise AuthorizedHttpRuntimeError("canceled")
    if snapshot.emergency_stop:
        raise AuthorizedHttpRuntimeError("emergency_stop")
    if snapshot.health is not HealthState.HEALTHY:
        raise AuthorizedHttpRuntimeError("health_not_healthy")
    return snapshot


def _headers(
    values: tuple[HeaderField, ...] | tuple[tuple[str, str], ...],
    allowlist: tuple[str, ...],
    *,
    response: bool,
) -> tuple[tuple[str, str], ...]:
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in values:
        if isinstance(item, HeaderField):
            name, value = item.name, item.value
        elif isinstance(item, tuple) and len(item) == 2:
            name, value = item
        else:
            raise AuthorizedHttpRuntimeError("header entry is invalid")
        normalized = _header_name(name, "header name")
        if normalized in seen:
            raise AuthorizedHttpRuntimeError("duplicate header is forbidden")
        if normalized in FORBIDDEN_SECRET_HEADERS:
            raise AuthorizedHttpRuntimeError("secret or cookie header is forbidden")
        if normalized not in allowlist:
            raise AuthorizedHttpRuntimeError("header is not allowlisted")
        safe_value = _safe_ascii(value, "header value")
        if _SECRET.search(safe_value.encode("ascii")):
            raise AuthorizedHttpRuntimeError("probable secret material is forbidden")
        seen.add(normalized)
        result.append((normalized, safe_value))
    if response and any(name == "set-cookie" for name, _ in result):
        raise AuthorizedHttpRuntimeError("response cookies are forbidden")
    return tuple(sorted(result))


def _reason(exc: Exception) -> str:
    message = str(exc)
    known = {
        "canceled": "canceled",
        "emergency_stop": "emergency_stop",
        "health_not_healthy": "health_not_healthy",
    }
    if message in known:
        return known[message]
    if "DNS" in message or "resolved address" in message or "literal IP" in message:
        return "dns_rejected"
    if "scope" in message or "outside" in message or "protected" in message:
        return "scope_rejected"
    if (
        "secret material in request body" in message
        or "secret material in response body" in message
        or "secret screening" in message
    ):
        return "payload_rejected"
    if "header" in message or "secret" in message or "cookie" in message:
        return "header_rejected"
    if "body" in message or "MIME" in message or "size" in message:
        return "payload_rejected"
    if "admission" in message or "binding" in message or "policy" in message:
        return "binding_rejected"
    if "clock" in message:
        return "clock_rejected"
    return "validation_rejected"


def execute_authorized_http_exchange(
    *,
    scope: VerifiedAssessmentScope,
    intent: HttpRequestIntent,
    execution_request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedHttpPolicy,
    clock: RuntimeClock,
    safety_monitor: RuntimeSafetyMonitor,
    resolver: DnsResolver,
    body_provider: RequestBodyProvider,
    backend: HttpBackend,
) -> HttpExchangeReceipt:
    """Execute at most one injected HTTP send after exact fail-closed checks."""

    evidence = _Evidence()
    attestations: list[str] = []
    body = b""
    request_sha: str | None = None
    response_status: int | None = None
    response_mime: str | None = None
    response_sha: str | None = None
    response_size = 0
    transport_called = False

    def finish(status: ExchangeStatus, reason: str) -> HttpExchangeReceipt:
        if not evidence.events:
            observation = clock.observe()
            evidence.add("rejected", {"reason": reason}, observation)
        return HttpExchangeReceipt(
            status=status,
            reason=reason,
            scope_id=scope.scope_id,
            scope_sha256=scope.content_sha256,
            intent_sha256=intent.intent_sha256,
            execution_request_id=execution_request.request_id,
            execution_request_sha256=execution_request.request_sha256,
            admission_receipt_id=admission.receipt_id,
            admission_receipt_sha256=admission.receipt_sha256,
            policy_id=policy.policy_id,
            policy_sha256=policy.policy_sha256,
            binding=execution_request.binding,
            transport_called=transport_called,
            request_body_sha256=request_sha,
            request_size_bytes=len(body),
            response_status_code=response_status,
            response_mime_type=response_mime,
            response_body_sha256=response_sha,
            response_size_bytes=response_size,
            dns_attestation_sha256=tuple(attestations),
            transcript=tuple(evidence.events),
            network_call_performed=transport_called,
        )

    try:
        _check_admission(scope, intent, execution_request, admission, policy)
        host, _ = _url(intent.url)
        observation = clock.observe()
        decision_reason = _check_current_scope(scope, intent, observation)
        _check_safety(safety_monitor, execution_request.binding, execution_request.request_sha256)
        evidence.add("validated", {"decision": decision_reason}, observation)
        request_headers = _headers(intent.headers, policy.request_header_allowlist, response=False)
        binding_budget = intent.binding.budget
        request_ceiling = min(
            policy.max_request_bytes,
            binding_budget.max_request_bytes,
            binding_budget.max_total_request_bytes,
        )
        if intent.request_size_bytes > request_ceiling:
            raise AuthorizedHttpRuntimeError("request body exceeds size ceiling")
        if intent.request_size_bytes:
            material = body_provider.read(intent.body_sha256 or "", intent.request_size_bytes)
            if not isinstance(material, bytes):
                raise AuthorizedHttpRuntimeError("body provider returned non-bytes")
            body = material
            if len(body) != intent.request_size_bytes or _sha(body) != intent.body_sha256:
                raise AuthorizedHttpRuntimeError("request body size or digest mismatch")
            content_types = [value for name, value in request_headers if name == "content-type"]
            if (
                len(content_types) != 1
                or policy.mime_ceiling(content_types[0]) is None
                or binding_budget.mime_ceiling(content_types[0]) is None
            ):
                raise AuthorizedHttpRuntimeError("request MIME type is not allowlisted")
            request_mime = _mime(content_types[0], "request MIME type")
            if _contains_secret(body, request_mime):
                raise AuthorizedHttpRuntimeError("probable secret material in request body")
            request_sha = _sha(body)
        elif any(name == "content-type" for name, _ in request_headers):
            raise AuthorizedHttpRuntimeError("empty request must not declare content-type")
        try:
            literal = ipaddress.ip_address(host).compressed
        except ValueError:
            literal = None
        if literal is None:
            first = resolver.resolve(host)
            if first.host != host:
                raise AuthorizedHttpRuntimeError("DNS response host mismatch")
        else:
            first = DnsResolution(host, (literal,), "literal_ip")
        _check_scope_addresses(scope, host, first.addresses)
        attestations.append(first.attestation_sha256)
        evidence.add("dns_preflight", first.to_dict(), clock.observe())
        _check_safety(safety_monitor, execution_request.binding, execution_request.request_sha256)
        if literal is None:
            second = resolver.resolve(host)
            if second.host != host or second.addresses != first.addresses:
                raise AuthorizedHttpRuntimeError("DNS rebinding detected")
        else:
            second = first
        _check_scope_addresses(scope, host, second.addresses)
        attestations.append(second.attestation_sha256)
        evidence.add("dns_recheck", second.to_dict(), clock.observe())
        _check_safety(safety_monitor, execution_request.binding, execution_request.request_sha256)
        final_observation = clock.observe()
        _check_current_scope(scope, intent, final_observation)
        evidence.add("send_authorized", {"maximum_attempts": 1}, final_observation)
    except Exception as exc:
        with suppress(Exception):
            evidence.add("rejected", {"reason": _reason(exc)}, clock.observe())
        return finish(ExchangeStatus.REJECTED_BEFORE_SEND, _reason(exc))

    request = HttpBackendRequest(
        method=intent.method.value,
        url=intent.url,
        headers=request_headers,
        body=body,
        connect_addresses=second.addresses,
        follow_redirects=False,
        maximum_attempts=1,
        max_response_bytes=min(
            policy.max_response_bytes,
            intent.binding.budget.max_response_bytes,
            intent.binding.budget.max_total_response_bytes,
        ),
    )
    try:
        transport_called = True
        response = backend.send(request)
        if not isinstance(response, HttpBackendResponse):
            raise HttpBackendFailure("invalid_backend_response")
    except HttpBackendFailure as exc:
        with suppress(Exception):
            evidence.add("backend_failed", {"failure_code": exc.code}, clock.observe())
        return finish(ExchangeStatus.BACKEND_FAILED, exc.code)
    except Exception:
        with suppress(Exception):
            evidence.add("backend_failed", {"failure_code": "backend_exception"}, clock.observe())
        return finish(ExchangeStatus.BACKEND_FAILED, "backend_exception")

    try:
        if response.attempts != 1:
            raise AuthorizedHttpRuntimeError("backend retry evidence is forbidden")
        if response.redirected or 300 <= response.status_code < 400:
            raise AuthorizedHttpRuntimeError("redirect response is forbidden")
        if response.limit_exceeded or not response.body_complete:
            raise AuthorizedHttpRuntimeError("response truncation or byte limit detected")
        response_size = len(response.body)
        response_ceiling = min(
            policy.max_response_bytes,
            intent.binding.budget.max_response_bytes,
            intent.binding.budget.max_total_response_bytes,
        )
        if response_size > response_ceiling:
            raise AuthorizedHttpRuntimeError("response body exceeds size ceiling")
        response_headers = _headers(
            response.headers, policy.response_header_allowlist, response=True
        )
        content_types = [value for name, value in response_headers if name == "content-type"]
        if len(content_types) != 1:
            raise AuthorizedHttpRuntimeError("response requires one content-type")
        response_mime = _mime(content_types[0], "response MIME type")
        ceilings = (
            policy.mime_ceiling(response_mime),
            intent.binding.budget.mime_ceiling(response_mime),
        )
        if None in ceilings or response_size > min(item for item in ceilings if item is not None):
            raise AuthorizedHttpRuntimeError("response MIME size ceiling exceeded")
        declared = [value for name, value in response_headers if name == "content-length"]
        if declared and (not declared[0].isdigit() or int(declared[0]) != response_size):
            raise AuthorizedHttpRuntimeError("response content-length mismatch")
        try:
            response_contains_secret = _contains_secret(response.body, response_mime)
        except Exception as exc:
            raise AuthorizedHttpRuntimeError("response secret screening failed") from exc
        if response_contains_secret:
            raise AuthorizedHttpRuntimeError("probable secret material in response body")
        response_status = response.status_code
        response_sha = _sha(response.body)
        evidence.add(
            "response_validated",
            {
                "header_sha256": _canonical_sha(response_headers),
                "response_body_sha256": response_sha,
                "response_size_bytes": response_size,
                "status_code": response_status,
            },
            clock.observe(),
        )
        return finish(ExchangeStatus.COMPLETED, "completed")
    except Exception as exc:
        response_status = response.status_code
        response_size = len(response.body)
        response_sha = None
        with suppress(Exception):
            evidence.add("response_rejected", {"reason": _reason(exc)}, clock.observe())
        return finish(ExchangeStatus.RESPONSE_REJECTED, _reason(exc))


_RECEIPT_FIELDS = {
    "admission_receipt_id",
    "admission_receipt_sha256",
    "authority_effect",
    "binding",
    "dns_attestation_sha256",
    "enforcement_boundary",
    "execution_request_id",
    "execution_request_sha256",
    "intent_sha256",
    "kind",
    "network_call_performed",
    "policy_id",
    "policy_sha256",
    "qualification_effect",
    "reason",
    "receipt_id",
    "receipt_sha256",
    "request_body_sha256",
    "request_size_bytes",
    "response_body_sha256",
    "response_mime_type",
    "response_size_bytes",
    "response_status_code",
    "schema_version",
    "scope_id",
    "scope_sha256",
    "status",
    "transcript",
    "transcript_id",
    "transcript_sha256",
    "transport_called",
}


def verify_exchange_receipt(raw: bytes | str | dict[str, Any]) -> MappingProxyType:
    """Strictly parse and verify a canonical exchange receipt without effects."""

    if isinstance(raw, bytes):
        try:
            text = raw.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise AuthorizedHttpRuntimeError("receipt must use ASCII JSON") from exc
    elif isinstance(raw, str):
        text = raw
    elif isinstance(raw, dict):
        text = canonical_json(raw)
    else:
        raise AuthorizedHttpRuntimeError("receipt must be JSON or an object")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise AuthorizedHttpRuntimeError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=lambda item: (_ for _ in ()).throw(
                AuthorizedHttpRuntimeError(f"floating-point value is forbidden: {item}")
            ),
            parse_constant=lambda item: (_ for _ in ()).throw(
                AuthorizedHttpRuntimeError(f"non-finite value is forbidden: {item}")
            ),
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise AuthorizedHttpRuntimeError("receipt is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != _RECEIPT_FIELDS:
        raise AuthorizedHttpRuntimeError("receipt fields are not exact")
    if text != canonical_json(value):
        raise AuthorizedHttpRuntimeError("receipt JSON is not canonical")
    if value["schema_version"] != SCHEMA_VERSION or value["kind"] != HttpExchangeReceipt.KIND:
        raise AuthorizedHttpRuntimeError("receipt version or kind is invalid")
    transcript = value["transcript"]
    if not isinstance(transcript, list) or not transcript:
        raise AuthorizedHttpRuntimeError("receipt transcript is invalid")
    previous: str | None = None
    for index, event in enumerate(transcript, start=1):
        if not isinstance(event, dict) or set(event) != {
            "detail_sha256",
            "event_sha256",
            "monotonic_tick",
            "observed_at",
            "previous_event_sha256",
            "sequence",
            "stage",
        }:
            raise AuthorizedHttpRuntimeError("transcript event fields are not exact")
        supplied = event["event_sha256"]
        body = {key: item for key, item in event.items() if key != "event_sha256"}
        if event["sequence"] != index or event["previous_event_sha256"] != previous:
            raise AuthorizedHttpRuntimeError("transcript event chain is invalid")
        if not hmac.compare_digest(supplied, _canonical_sha(body)):
            raise AuthorizedHttpRuntimeError("transcript event hash is invalid")
        previous = supplied
    transcript_digest = _canonical_sha(transcript)
    if value["transcript_sha256"] != transcript_digest:
        raise AuthorizedHttpRuntimeError("transcript digest is invalid")
    if value["transcript_id"] != "AHT-" + transcript_digest[7:39].upper():
        raise AuthorizedHttpRuntimeError("transcript identity is invalid")
    receipt_body = {
        key: item
        for key, item in value.items()
        if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
    }
    digest = _canonical_sha({"body": receipt_body, "kind": value["kind"]})
    if value["receipt_sha256"] != digest or value["receipt_id"] != "AHR-" + digest[7:39].upper():
        raise AuthorizedHttpRuntimeError("receipt content address is invalid")
    try:
        checked_events = tuple(
            TranscriptEvent(
                sequence=event["sequence"],
                stage=event["stage"],
                observed_at=event["observed_at"],
                monotonic_tick=event["monotonic_tick"],
                detail_sha256=event["detail_sha256"],
                previous_event_sha256=event["previous_event_sha256"],
                event_sha256=event["event_sha256"],
            )
            for event in transcript
        )
        checked_binding = ExecutionBinding(**value["binding"])
        checked = HttpExchangeReceipt(
            status=ExchangeStatus(value["status"]),
            reason=value["reason"],
            scope_id=value["scope_id"],
            scope_sha256=value["scope_sha256"],
            intent_sha256=value["intent_sha256"],
            execution_request_id=value["execution_request_id"],
            execution_request_sha256=value["execution_request_sha256"],
            admission_receipt_id=value["admission_receipt_id"],
            admission_receipt_sha256=value["admission_receipt_sha256"],
            policy_id=value["policy_id"],
            policy_sha256=value["policy_sha256"],
            binding=checked_binding,
            transport_called=value["transport_called"],
            request_body_sha256=value["request_body_sha256"],
            request_size_bytes=value["request_size_bytes"],
            response_status_code=value["response_status_code"],
            response_mime_type=value["response_mime_type"],
            response_body_sha256=value["response_body_sha256"],
            response_size_bytes=value["response_size_bytes"],
            dns_attestation_sha256=tuple(value["dns_attestation_sha256"]),
            transcript=checked_events,
            network_call_performed=value["network_call_performed"],
            authority_effect=value["authority_effect"],
            qualification_effect=value["qualification_effect"],
            enforcement_boundary=value["enforcement_boundary"],
            transcript_id=value["transcript_id"],
            transcript_sha256=value["transcript_sha256"],
            receipt_id=value["receipt_id"],
            receipt_sha256=value["receipt_sha256"],
        )
    except (AuthorizedHttpRuntimeError, TypeError, ValueError) as exc:
        raise AuthorizedHttpRuntimeError("receipt semantic validation failed") from exc
    if checked.to_dict() != value:
        raise AuthorizedHttpRuntimeError("receipt canonical object does not round trip")
    return MappingProxyType(value)


__all__ = [
    "ENFORCEMENT_BOUNDARY",
    "NO_BUILTIN_IO",
    "AuthorizedHttpPolicy",
    "AuthorizedHttpRuntimeError",
    "DnsResolution",
    "DnsResolver",
    "ExchangeStatus",
    "HttpBackend",
    "HttpBackendFailure",
    "HttpBackendRequest",
    "HttpBackendResponse",
    "HttpExchangeReceipt",
    "RequestBodyProvider",
    "RuntimeClock",
    "RuntimeSafetyMonitor",
    "RuntimeSafetySnapshot",
    "TranscriptEvent",
    "execute_authorized_http_exchange",
    "verify_exchange_receipt",
]
