"""Opt-in, staging-only HTTPS transport for an already authorized HTTP request.

This module neither grants action authority nor resolves a target name. The
caller must supply an exact origin, certificate pin, and previously authorized
literal connection addresses. No transport is installed by default.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit

from .assessment_transport_contracts import FORBIDDEN_SECRET_HEADERS, HttpMethod
from .authorized_http_runtime import HttpBackendFailure, HttpBackendRequest
from .reference_http_adapter import (
    ReferenceHttpTransportResponse,
    ReferenceTlsPeerEvidence,
)
from .target_adapter_conformance import AdapterStopRequested, AdapterStopState

AUTHORITY_EFFECT = "none"
QUALIFICATION_EFFECT = "none"
STAGING_ONLY = True
MAX_STAGING_REQUEST_BYTES = 1024 * 1024
MAX_STAGING_RESPONSE_BYTES = 8 * 1024 * 1024

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FORBIDDEN_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-authorization",
        "proxy-connection",
        "upgrade",
        "expect",
        "te",
        "trailer",
    }
)


def _address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("connection address must be a literal IP address") from exc
    if str(address) != value:
        raise ValueError("connection address must be canonical")
    return value


def _origin(value: str) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("origin must be canonical HTTPS")
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.netloc != parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError("origin must be canonical HTTPS port 443")
    return value


class PinnedHttpsStagingTransport:
    """One-attempt HTTPS/1.1 transport pinned to a literal IP and TLS peer.

    A certificate mismatch is rejected before any HTTP request bytes are sent.
    Failures after request transmission are uncertain and are never retried.
    """

    def __init__(
        self,
        *,
        expected_origin: str,
        expected_certificate_sha256: str,
        connect_addresses: tuple[str, ...],
        maximum_request_bytes: int,
        maximum_response_bytes: int,
        stop_state: AdapterStopState,
        connect_timeout_seconds: float = 5.0,
        read_timeout_seconds: float = 5.0,
    ) -> None:
        self.expected_origin = _origin(expected_origin)
        self.host = urlsplit(expected_origin).hostname
        if not isinstance(expected_certificate_sha256, str) or not _DIGEST.fullmatch(
            expected_certificate_sha256
        ):
            raise ValueError("certificate pin must be a sha256 digest")
        if (
            not isinstance(connect_addresses, tuple)
            or not 1 <= len(connect_addresses) <= 8
            or not all(isinstance(value, str) for value in connect_addresses)
            or len(set(connect_addresses)) != len(connect_addresses)
        ):
            raise ValueError("one to eight distinct connection addresses are required")
        self.connect_addresses = tuple(_address(value) for value in connect_addresses)
        for value, hard_limit, label in (
            (maximum_request_bytes, MAX_STAGING_REQUEST_BYTES, "maximum_request_bytes"),
            (maximum_response_bytes, MAX_STAGING_RESPONSE_BYTES, "maximum_response_bytes"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= hard_limit
            ):
                raise ValueError(f"{label} is outside the staging limit")
        if not isinstance(stop_state, AdapterStopState):
            raise ValueError("stop_state is required")
        for value, label in (
            (connect_timeout_seconds, "connect_timeout_seconds"),
            (read_timeout_seconds, "read_timeout_seconds"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0 < value <= 10
            ):
                raise ValueError(f"{label} must be in (0, 10]")
        self.expected_certificate_sha256 = expected_certificate_sha256
        self.maximum_request_bytes = maximum_request_bytes
        self.maximum_response_bytes = maximum_response_bytes
        self.stop_state = stop_state
        self.connect_timeout_seconds = float(connect_timeout_seconds)
        self.read_timeout_seconds = float(read_timeout_seconds)

    def _check_stop(self) -> None:
        try:
            self.stop_state.check()
        except AdapterStopRequested as exc:
            raise HttpBackendFailure(exc.code) from exc

    def _validate_request(self, request: HttpBackendRequest) -> tuple[str, dict[str, str]]:
        if not isinstance(request, HttpBackendRequest):
            raise HttpBackendFailure("invalid_transport_request")
        if request.follow_redirects is not False or request.maximum_attempts != 1:
            raise HttpBackendFailure("unsafe_transport_controls")
        if not isinstance(request.method, str) or request.method not in {
            method.value for method in HttpMethod
        }:
            raise HttpBackendFailure("invalid_http_method")
        if not isinstance(request.body, bytes) or len(request.body) > self.maximum_request_bytes:
            raise HttpBackendFailure("request_limit_exceeded")
        if (
            isinstance(request.max_response_bytes, bool)
            or not isinstance(request.max_response_bytes, int)
            or not 0 < request.max_response_bytes <= self.maximum_response_bytes
        ):
            raise HttpBackendFailure("response_limit_invalid")
        if not isinstance(request.url, str) or len(request.url) > 8192:
            raise HttpBackendFailure("origin_binding_mismatch")
        try:
            parts = urlsplit(request.url)
        except ValueError as exc:
            raise HttpBackendFailure("origin_binding_mismatch") from exc
        if (
            parts.scheme != "https"
            or parts.netloc != self.host
            or parts.fragment
            or (parts.path and not parts.path.startswith("/"))
            or any(ord(char) < 33 or ord(char) > 126 for char in request.url)
        ):
            raise HttpBackendFailure("origin_binding_mismatch")
        if (
            not isinstance(request.connect_addresses, tuple)
            or len(request.connect_addresses) != len(self.connect_addresses)
            or not all(isinstance(value, str) for value in request.connect_addresses)
            or set(request.connect_addresses) != set(self.connect_addresses)
        ):
            raise HttpBackendFailure("connection_address_mismatch")
        if not isinstance(request.headers, tuple) or len(request.headers) > 64:
            raise HttpBackendFailure("invalid_request_headers")
        headers: dict[str, str] = {}
        names: set[str] = set()
        total_bytes = 0
        for item in request.headers:
            if not isinstance(item, tuple) or len(item) != 2:
                raise HttpBackendFailure("invalid_request_headers")
            name, value = item
            if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
                raise HttpBackendFailure("invalid_request_headers")
            if not isinstance(value, str) or any(
                ord(char) < 32 or ord(char) > 126 for char in value
            ):
                raise HttpBackendFailure("invalid_request_headers")
            lowered = name.lower()
            if (
                lowered in _FORBIDDEN_HEADERS
                or lowered in FORBIDDEN_SECRET_HEADERS
                or lowered in names
            ):
                raise HttpBackendFailure("invalid_request_headers")
            names.add(lowered)
            headers[name] = value
            total_bytes += len(name) + len(value) + 4
        if total_bytes > 16384:
            raise HttpBackendFailure("invalid_request_headers")
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        return path, headers

    def exchange(self, request: HttpBackendRequest) -> ReferenceHttpTransportResponse:
        self._check_stop()
        path, headers = self._validate_request(request)
        address = self.connect_addresses[0]
        parsed_address = ipaddress.ip_address(address)
        family = socket.AF_INET6 if parsed_address.version == 6 else socket.AF_INET
        raw_socket: socket.socket | None = None
        tls_socket: ssl.SSLSocket | None = None
        connection: http.client.HTTPSConnection | None = None
        sent = False
        try:
            raw_socket = socket.socket(family, socket.SOCK_STREAM)
            raw_socket.settimeout(self.connect_timeout_seconds)
            target = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
            self._check_stop()
            raw_socket.connect(target)
            if raw_socket.getpeername()[0] != address:
                raise HttpBackendFailure("connection_address_mismatch")
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            tls_socket = context.wrap_socket(raw_socket, server_hostname=self.host)
            raw_socket = None
            if tls_socket.selected_alpn_protocol() not in (None, "http/1.1"):
                raise HttpBackendFailure("tls_protocol_mismatch")
            certificate = tls_socket.getpeercert(binary_form=True)
            if not certificate:
                raise HttpBackendFailure("tls_certificate_missing")
            fingerprint = "sha256:" + hashlib.sha256(certificate).hexdigest()
            if not hmac.compare_digest(fingerprint, self.expected_certificate_sha256):
                raise HttpBackendFailure("tls_certificate_mismatch")
            tls_socket.settimeout(self.read_timeout_seconds)
            connection = http.client.HTTPSConnection(
                self.host, 443, timeout=self.read_timeout_seconds, context=context
            )
            connection.sock = tls_socket
            self._check_stop()
            sent = True
            connection.request(request.method, path, body=request.body, headers=headers)
            response = connection.getresponse()
            if response.status == 101:
                raise HttpBackendFailure("unsupported_protocol_upgrade")
            response_headers = tuple(response.getheaders())
            if (
                len(response_headers) > 100
                or sum(len(name) + len(value) + 4 for name, value in response_headers) > 32768
            ):
                raise HttpBackendFailure("response_headers_limit_exceeded")
            body = bytearray()
            limit = request.max_response_bytes
            while len(body) <= limit:
                self._check_stop()
                chunk = response.read(min(16384, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            self._check_stop()
            return ReferenceHttpTransportResponse(
                status_code=response.status,
                headers=response_headers,
                body=bytes(body),
                body_complete=len(body) <= limit,
                attempts=1,
                tls_peer=ReferenceTlsPeerEvidence(
                    origin=self.expected_origin,
                    sni_hostname=self.host,
                    connected_address=address,
                    certificate_sha256=fingerprint,
                    tls_verified=True,
                ),
            )
        except HttpBackendFailure:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            code = "transport_after_send_uncertain" if sent else "transport_before_send_failed"
            raise HttpBackendFailure(code) from exc
        finally:
            if connection is not None:
                connection.close()
            elif tls_socket is not None:
                tls_socket.close()
            elif raw_socket is not None:
                raw_socket.close()
