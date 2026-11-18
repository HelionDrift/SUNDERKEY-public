"""Inert Cloud KMS request descriptions and strict response-byte verification."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType

from .gcp_kms_ed25519 import (
    GcpKmsEd25519Error,
    GcpKmsEd25519KeyVersionBinding,
    GcpKmsEd25519SigningRequest,
    _capture_binding,
    _capture_request,
    verify_gcp_ed25519_public_key_response,
    verify_gcp_ed25519_sign_response,
)

ORIGIN = "https://cloudkms.googleapis.com"
DOMAIN = "sunderkey.gcp-kms-wire-request.v1"
MAX_RESPONSE_BYTES = 16_384
MAX_JSON_DEPTH = 4
MAX_JSON_NODES = 64
MAX_JSON_FIELDS = 16
MAX_JSON_STRING_CHARS = 4096
_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credential_access": "none",
        "deployment": "none",
        "network": "none",
        "provider_calls": "none",
        "qualification": "none",
        "signature_generation": "none",
        "storage_mutation": "none",
        "target_action": "none",
    }
)


class GcpKmsWireError(ValueError):
    """A local wire description or supplied byte response is invalid."""


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


@dataclass(frozen=True, slots=True)
class GcpKmsWireRequest:
    """Owned request description, not a dispatch command or provider receipt."""

    operation: str
    binding: GcpKmsEd25519KeyVersionBinding = field(repr=False)
    signing_request: GcpKmsEd25519SigningRequest | None = field(default=None, repr=False)
    method: str = field(init=False)
    origin: str = field(init=False)
    path: str = field(init=False)
    body_bytes: bytes = field(init=False, repr=False)
    body_sha256: str = field(init=False)
    wire_request_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.operation) is not str or self.operation not in {
            "get_public_key",
            "asymmetric_sign",
        }:
            raise GcpKmsWireError("Wire operation is outside the closed codec")
        try:
            binding = _capture_binding(self.binding)
            if self.operation == "get_public_key":
                if self.signing_request is not None:
                    raise GcpKmsWireError("Default public-key GET cannot contain signing material")
                signing_request = None
                method, suffix, body = "GET", "/publicKey", b""
            else:
                signing_request = _capture_request(self.signing_request)
                if signing_request.binding.to_dict() != binding.to_dict():
                    raise GcpKmsWireError("Wire and signing-request bindings differ")
                method, suffix = "POST", ":asymmetricSign"
                body = _json_bytes(signing_request.to_rest_body())
        except (GcpKmsEd25519Error, AttributeError, TypeError) as exc:
            raise GcpKmsWireError("Wire source no longer matches its exact local binding") from exc
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "signing_request", signing_request)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "origin", ORIGIN)
        object.__setattr__(self, "path", "/v1/" + binding.key_version_name + suffix)
        object.__setattr__(self, "body_bytes", body)
        object.__setattr__(self, "body_sha256", _sha256(body))
        object.__setattr__(
            self,
            "wire_request_sha256",
            _sha256(_json_bytes({"domain": DOMAIN, "request": _document(self)})),
        )

    def to_dict(self) -> dict[str, object]:
        """Export detached public pins and body bytes, never credentials or execution."""
        captured = _capture_wire_request(self)
        return {**_document(captured), "wire_request_sha256": captured.wire_request_sha256}


def _document(request: GcpKmsWireRequest) -> dict[str, object]:
    signing = request.signing_request
    headers = {"Accept": "application/json"}
    if request.operation == "asymmetric_sign":
        headers["Content-Type"] = "application/json"
    return {
        "kind": DOMAIN,
        "schema_version": 1,
        "operation": request.operation,
        "method": request.method,
        "origin": request.origin,
        "path": request.path,
        "url": request.origin + request.path,
        "headers": headers,
        "query_parameters": {},
        "body_base64": base64.b64encode(request.body_bytes).decode("ascii"),
        "body_sha256": request.body_sha256,
        "binding": request.binding.to_dict(),
        "signing_request_sha256": None if signing is None else signing.request_sha256,
        "signing_input_sha256": None if signing is None else signing.signing_input_sha256,
        "validation_scope": "local_request_and_supplied_response_consistency_only",
        "identity_assurance": "caller_pinned_not_provider_authenticated",
        "dispatch_performed": False,
        "effects": dict(_EFFECTS),
    }


def _capture_wire_request(request: GcpKmsWireRequest) -> GcpKmsWireRequest:
    if type(request) is not GcpKmsWireRequest:
        raise GcpKmsWireError("An exact GcpKmsWireRequest is required")
    try:
        captured = GcpKmsWireRequest(request.operation, request.binding, request.signing_request)
        for name, primitive in (
            ("method", str),
            ("origin", str),
            ("path", str),
            ("body_bytes", bytes),
            ("body_sha256", str),
            ("wire_request_sha256", str),
        ):
            if type(getattr(request, name)) is not primitive or getattr(request, name) != getattr(
                captured, name
            ):
                raise GcpKmsWireError("Wire request no longer matches its captured sources")
    except (AttributeError, TypeError) as exc:
        raise GcpKmsWireError("Wire request is missing its exact captured fields") from exc
    return captured


def encode_gcp_kms_public_key_request(
    binding: GcpKmsEd25519KeyVersionBinding,
) -> GcpKmsWireRequest:
    """Describe the default-format publicKey GET with an empty body and query."""
    return GcpKmsWireRequest("get_public_key", binding)


def encode_gcp_kms_sign_request(request: GcpKmsEd25519SigningRequest) -> GcpKmsWireRequest:
    """Describe raw-data POST bytes without dispatching or changing signing input."""
    try:
        captured = _capture_request(request)
    except (GcpKmsEd25519Error, AttributeError, TypeError) as exc:
        raise GcpKmsWireError("Signing source failed exact request revalidation") from exc
    return GcpKmsWireRequest("asymmetric_sign", captured.binding, captured)


def _check_depth(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "{[":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise GcpKmsWireError("Response JSON exceeds the nesting bound")
        elif char in "}]":
            depth -= 1
            if depth < 0:
                raise GcpKmsWireError("Response JSON structure is invalid")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len(pairs) > MAX_JSON_FIELDS:
        raise GcpKmsWireError("Response object exceeds the field bound")
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GcpKmsWireError("Response JSON contains duplicate keys")
        result[key] = value
    return result


def _integer(text: str) -> int:
    if len(text) > 20:
        raise GcpKmsWireError("Response integer exceeds its bound")
    value = int(text)
    if not -(2**63 - 1) <= value <= 2**63 - 1:
        raise GcpKmsWireError("Response integer exceeds its bound")
    return value


def _reject_number(_: str) -> object:
    raise GcpKmsWireError("Response floats and nonfinite values are prohibited")


def _native_tree(value: object, count: list[int]) -> None:
    count[0] += 1
    if count[0] > MAX_JSON_NODES:
        raise GcpKmsWireError("Response JSON exceeds its node bound")
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is str:
        if len(value) > MAX_JSON_STRING_CHARS or not value.isascii():
            raise GcpKmsWireError("Response strings exceed their ASCII bounds")
        return
    if type(value) is list:
        for item in value:
            _native_tree(item, count)
        return
    if type(value) is dict:
        for key, item in value.items():
            _native_tree(key, count)
            _native_tree(item, count)
        return
    raise GcpKmsWireError("Response contains an unsupported primitive")


def _response_object(response_bytes: bytes) -> dict[str, object]:
    if type(response_bytes) is not bytes or not 1 <= len(response_bytes) <= MAX_RESPONSE_BYTES:
        raise GcpKmsWireError("Response must be bounded nonempty native bytes")
    try:
        text = response_bytes.decode("utf-8", errors="strict")
        _check_depth(text)
        raw = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, GcpKmsWireError):
            raise
        raise GcpKmsWireError("Response is not valid bounded UTF-8 JSON") from exc
    _native_tree(raw, [0])
    if type(raw) is not dict:
        raise GcpKmsWireError("Response must contain one JSON object")
    return raw


def _require_success(status_code: int) -> None:
    if type(status_code) is not int or status_code != 200:
        raise GcpKmsWireError("Local KMS wire verification requires HTTP status 200")


def verify_gcp_kms_public_key_from_bytes(
    request: GcpKmsWireRequest,
    *,
    status_code: int,
    response_bytes: bytes,
) -> bytes:
    """Verify supplied default public-key bytes against the request's independent pin."""
    captured = _capture_wire_request(request)
    if captured.operation != "get_public_key":
        raise GcpKmsWireError("Public-key response requires a default public-key GET description")
    _require_success(status_code)
    raw = _response_object(response_bytes)
    try:
        return verify_gcp_ed25519_public_key_response(captured.binding, raw)
    except GcpKmsEd25519Error as exc:
        raise GcpKmsWireError("Supplied public-key response failed local verification") from exc


def verify_gcp_kms_signature_from_bytes(
    request: GcpKmsWireRequest,
    *,
    status_code: int,
    response_bytes: bytes,
) -> str:
    """Verify a supplied signature over the original raw input, never current authority."""
    captured = _capture_wire_request(request)
    if captured.operation != "asymmetric_sign":
        raise GcpKmsWireError("Signature response requires a raw-data POST description")
    _require_success(status_code)
    raw = _response_object(response_bytes)
    try:
        return verify_gcp_ed25519_sign_response(captured.signing_request, raw)
    except GcpKmsEd25519Error as exc:
        raise GcpKmsWireError("Supplied signature response failed local verification") from exc


__all__ = [
    "GcpKmsWireError",
    "GcpKmsWireRequest",
    "MAX_RESPONSE_BYTES",
    "MAX_JSON_DEPTH",
    "encode_gcp_kms_public_key_request",
    "encode_gcp_kms_sign_request",
    "verify_gcp_kms_public_key_from_bytes",
    "verify_gcp_kms_signature_from_bytes",
]
