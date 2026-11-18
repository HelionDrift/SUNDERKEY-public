"""Offline reference adapters for the authorized HTTP runtime.

All network behavior is supplied through an injected transport. The adapter
does not open sockets, resolve names, grant authority, follow redirects, or
retry requests.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from .assessment_transport_contracts import HttpRequestIntent
from .authorized_http_runtime import (
    AuthorizedHttpPolicy,
    DnsResolution,
    HttpBackendFailure,
    HttpBackendRequest,
    HttpBackendResponse,
    HttpExchangeReceipt,
    RuntimeClock,
    RuntimeSafetyMonitor,
    execute_authorized_http_exchange,
)
from .execution_control_runtime import AdmissionReceipt, ExecutionRequest
from .signed_scope_compiler import VerifiedAssessmentScope
from .target_adapter_conformance import AdapterStopRequested, AdapterStopState

NO_BUILTIN_IO = True
AUTHORITY_EFFECT = "none"
QUALIFICATION_EFFECT = "none"


class ReferenceHttpAdapterError(ValueError):
    """Raised when injected HTTP evidence fails the reference contract."""


def _digest(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ReferenceHttpAdapterError(f"{label} must be a sha256 digest")
    return value


def _origin(value: str) -> tuple[str, str, int]:
    if not isinstance(value, str) or not value.isascii():
        raise ReferenceHttpAdapterError("origin is invalid")
    parts = urlsplit(value)
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise ReferenceHttpAdapterError("origin port is invalid") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
        or port != 443
    ):
        raise ReferenceHttpAdapterError("origin must be canonical HTTPS port 443")
    host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    canonical = f"https://{host}"
    if value.rstrip("/") != canonical:
        raise ReferenceHttpAdapterError("origin is not canonical")
    return canonical, host, port


@dataclass(frozen=True, slots=True)
class ReferenceTlsPeerEvidence:
    """Exact TLS and connection evidence returned by an injected transport."""

    origin: str
    sni_hostname: str
    connected_address: str
    certificate_sha256: str
    tls_verified: bool

    def __post_init__(self) -> None:
        canonical, host, _ = _origin(self.origin)
        object.__setattr__(self, "origin", canonical)
        if self.sni_hostname != host:
            raise ReferenceHttpAdapterError("TLS SNI does not match origin host")
        try:
            address = ipaddress.ip_address(self.connected_address).compressed
        except (TypeError, ValueError) as exc:
            raise ReferenceHttpAdapterError("connected address is invalid") from exc
        object.__setattr__(self, "connected_address", address)
        _digest(self.certificate_sha256, "certificate_sha256")
        if self.tls_verified is not True:
            raise ReferenceHttpAdapterError("TLS peer is not verified")


@dataclass(frozen=True, slots=True)
class ReferenceHttpTransportResponse:
    """Bounded response and TLS evidence from an injected transport."""

    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    body_complete: bool
    attempts: int
    tls_peer: ReferenceTlsPeerEvidence

    def __post_init__(self) -> None:
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int):
            raise ReferenceHttpAdapterError("status_code is invalid")
        if not 100 <= self.status_code <= 599:
            raise ReferenceHttpAdapterError("status_code is invalid")
        if not isinstance(self.headers, tuple) or not all(
            isinstance(item, tuple)
            and len(item) == 2
            and all(isinstance(value, str) for value in item)
            for item in self.headers
        ):
            raise ReferenceHttpAdapterError("headers are invalid")
        if not isinstance(self.body, bytes):
            raise ReferenceHttpAdapterError("body must be bytes")
        if not isinstance(self.body_complete, bool):
            raise ReferenceHttpAdapterError("body_complete must be a boolean")
        if self.attempts != 1:
            raise ReferenceHttpAdapterError("transport attempts must equal one")
        if not isinstance(self.tls_peer, ReferenceTlsPeerEvidence):
            raise ReferenceHttpAdapterError("TLS evidence is invalid")


class ReferenceHttpTransport(Protocol):
    """Injected transport that must honor the exact backend request limits."""

    def exchange(self, request: HttpBackendRequest) -> ReferenceHttpTransportResponse: ...


class ScriptedDnsResolver:
    """Deterministic resolver for tests and offline conformance fixtures."""

    def __init__(self, host: str, answers: Sequence[Sequence[str]], resolver_id: str) -> None:
        if not isinstance(answers, Sequence) or len(answers) < 2:
            raise ReferenceHttpAdapterError("at least two DNS answers are required")
        self._values = tuple(
            DnsResolution(host=host, addresses=tuple(answer), resolver_id=resolver_id)
            for answer in answers
        )
        self._index = 0

    @property
    def calls(self) -> int:
        return self._index

    def resolve(self, host: str) -> DnsResolution:
        if self._index >= len(self._values):
            raise ReferenceHttpAdapterError("DNS script is exhausted")
        value = self._values[self._index]
        self._index += 1
        if host != value.host:
            raise ReferenceHttpAdapterError("DNS query host substitution detected")
        return value


class DigestBoundBodyProvider:
    """In-memory request material indexed only by digest and exact length."""

    def __init__(self, bodies: Sequence[bytes] = ()) -> None:
        self._bodies = {
            "sha256:" + hashlib.sha256(value).hexdigest(): value for value in bodies
        }

    def read(self, body_sha256: str, size_bytes: int) -> bytes:
        value = self._bodies.get(body_sha256)
        if value is None or len(value) != size_bytes:
            raise ReferenceHttpAdapterError("request body binding is unavailable")
        return value


class ReferenceHttpBackend:
    """Exact-origin, one-attempt backend over an injected transport."""

    def __init__(
        self,
        *,
        expected_origin: str,
        expected_certificate_sha256: str,
        maximum_request_bytes: int,
        maximum_response_bytes: int,
        transport: ReferenceHttpTransport,
        stop_state: AdapterStopState,
    ) -> None:
        origin, host, port = _origin(expected_origin)
        _digest(expected_certificate_sha256, "expected_certificate_sha256")
        for value, label in (
            (maximum_request_bytes, "maximum_request_bytes"),
            (maximum_response_bytes, "maximum_response_bytes"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ReferenceHttpAdapterError(f"{label} is invalid")
        self.expected_origin = origin
        self.expected_host = host
        self.expected_port = port
        self.expected_certificate_sha256 = expected_certificate_sha256
        self.maximum_request_bytes = maximum_request_bytes
        self.maximum_response_bytes = maximum_response_bytes
        self.transport = transport
        self.stop_state = stop_state
        self.calls = 0

    def send(self, request: HttpBackendRequest) -> HttpBackendResponse:
        try:
            self.stop_state.check()
        except AdapterStopRequested as exc:
            raise HttpBackendFailure(exc.code) from exc
        if request.follow_redirects is not False or request.maximum_attempts != 1:
            raise HttpBackendFailure("unsafe_transport_controls")
        if len(request.body) > self.maximum_request_bytes:
            raise HttpBackendFailure("request_limit_exceeded")
        if (
            isinstance(request.max_response_bytes, bool)
            or not 0 < request.max_response_bytes <= self.maximum_response_bytes
        ):
            raise HttpBackendFailure("response_limit_invalid")
        parts = urlsplit(request.url)
        request_origin = f"https://{parts.hostname}"
        if request_origin != self.expected_origin or (parts.port or 443) != self.expected_port:
            raise HttpBackendFailure("origin_binding_mismatch")
        if not request.connect_addresses:
            raise HttpBackendFailure("connection_address_missing")
        self.calls += 1
        response = self.transport.exchange(request)
        try:
            self.stop_state.check()
        except AdapterStopRequested as exc:
            raise HttpBackendFailure(exc.code) from exc
        peer = response.tls_peer
        if (
            peer.origin != self.expected_origin
            or peer.sni_hostname != self.expected_host
            or peer.connected_address not in request.connect_addresses
            or peer.certificate_sha256 != self.expected_certificate_sha256
            or peer.tls_verified is not True
        ):
            raise HttpBackendFailure("tls_origin_binding_mismatch")
        limit_exceeded = len(response.body) > request.max_response_bytes
        redirect = 300 <= response.status_code < 400
        return HttpBackendResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=(b"" if limit_exceeded else response.body),
            body_complete=response.body_complete and not limit_exceeded,
            limit_exceeded=limit_exceeded,
            redirected=redirect,
            attempts=response.attempts,
        )


class ReferenceAuthorizedHttpAdapter:
    """Composition root that delegates authorization to the existing runtime."""

    def __init__(
        self,
        *,
        resolver: ScriptedDnsResolver,
        body_provider: DigestBoundBodyProvider,
        backend: ReferenceHttpBackend,
    ) -> None:
        self.resolver = resolver
        self.body_provider = body_provider
        self.backend = backend

    def execute(
        self,
        *,
        scope: VerifiedAssessmentScope,
        intent: HttpRequestIntent,
        execution_request: ExecutionRequest,
        admission: AdmissionReceipt,
        policy: AuthorizedHttpPolicy,
        clock: RuntimeClock,
        safety_monitor: RuntimeSafetyMonitor,
    ) -> HttpExchangeReceipt:
        """Run only through the authorized HTTP enforcement boundary."""

        return execute_authorized_http_exchange(
            scope=scope,
            intent=intent,
            execution_request=execution_request,
            admission=admission,
            policy=policy,
            clock=clock,
            safety_monitor=safety_monitor,
            resolver=self.resolver,
            body_provider=self.body_provider,
            backend=self.backend,
        )


__all__ = [
    "AUTHORITY_EFFECT",
    "NO_BUILTIN_IO",
    "QUALIFICATION_EFFECT",
    "DigestBoundBodyProvider",
    "ReferenceAuthorizedHttpAdapter",
    "ReferenceHttpAdapterError",
    "ReferenceHttpBackend",
    "ReferenceHttpTransport",
    "ReferenceHttpTransportResponse",
    "ReferenceTlsPeerEvidence",
    "ScriptedDnsResolver",
]
