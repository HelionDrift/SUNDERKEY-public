"""Offline raw Ed25519 request mapping and response verification for Cloud KMS."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import PrincipalAuthenticationError
from .identity import _strict_ed25519_public_key, _verify_ed25519

MAX_SIGNING_BYTES = 65_536
MAX_KEY_VERSION_NAME_CHARS = 640
MAX_PUBLIC_KEY_PEM_CHARS = 4096
REQUEST_DOMAIN = "sunderkey.gcp-kms-ed25519-signing-request.v1"
_ALGORITHM = "EC_SIGN_ED25519"
_PROTECTION_LEVEL = "SOFTWARE"
_UINT32_MAX = (1 << 32) - 1
_PROJECT = r"(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[1-9][0-9]{0,29})"
_KEY_SEGMENT = r"[A-Za-z0-9_-]{1,63}"
_VERSION_NAME = re.compile(
    rf"projects/{_PROJECT}/locations/[a-z][a-z0-9-]{{0,62}}/"
    rf"keyRings/{_KEY_SEGMENT}/cryptoKeys/{_KEY_SEGMENT}/"
    r"cryptoKeyVersions/[1-9][0-9]{0,9}"
)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_DECIMAL_CRC = re.compile(r"0|[1-9][0-9]{0,9}")
_PUBLIC_KEY_FIELDS = frozenset({"pem", "pemCrc32c", "name", "algorithm", "protectionLevel"})
_SIGNATURE_FIELDS = frozenset(
    {"signature", "signatureCrc32c", "verifiedDataCrc32c", "name", "protectionLevel"}
)


class GcpKmsEd25519Error(ValueError):
    """An offline request or response fails its exact local binding."""


def _text(value: object, label: str, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or not value.isascii():
        raise GcpKmsEd25519Error(f"{label} must be bounded native ASCII text")
    return value


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _crc_table() -> tuple[int, ...]:
    entries = []
    for initial in range(256):
        remainder = initial
        for _ in range(8):
            remainder = (remainder >> 1) ^ (0x82F63B78 if remainder & 1 else 0)
        entries.append(remainder)
    return tuple(entries)


_CRC32C_TABLE = _crc_table()


def _crc32c(data: bytes) -> int:
    remainder = _UINT32_MAX
    for byte in data:
        remainder = (remainder >> 8) ^ _CRC32C_TABLE[(remainder ^ byte) & 0xFF]
    return remainder ^ _UINT32_MAX


def _wire_crc(value: object, label: str) -> int:
    text = _text(value, label, 10)
    if _DECIMAL_CRC.fullmatch(text) is None or int(text) > _UINT32_MAX:
        raise GcpKmsEd25519Error(f"{label} must be a canonical uint32 decimal string")
    return int(text)


def _exact_response(
    value: object, required: frozenset[str], optional: frozenset[str]
) -> dict[str, object]:
    if type(value) is not dict or not len(required) <= len(value) <= len(required | optional):
        raise GcpKmsEd25519Error("response must be an exact bounded JSON object")
    if any(type(key) is not str or key not in required | optional for key in value):
        raise GcpKmsEd25519Error("response contains an unknown or non-native field")
    if not required <= value.keys():
        raise GcpKmsEd25519Error("response is missing a required field")
    return dict(value)


@dataclass(frozen=True, slots=True)
class GcpKmsEd25519KeyVersionBinding:
    """Caller-pinned public metadata, not a cloud state or authority assertion."""

    key_version_name: str
    algorithm: str
    protection_level: str
    public_key: bytes
    public_key_sha256: str

    def __post_init__(self) -> None:
        name = _text(self.key_version_name, "key_version_name", MAX_KEY_VERSION_NAME_CHARS)
        if _VERSION_NAME.fullmatch(name) is None:
            raise GcpKmsEd25519Error("key_version_name must name one explicit numeric version")
        if _text(self.algorithm, "algorithm", 32) != _ALGORITHM:
            raise GcpKmsEd25519Error("algorithm must be EC_SIGN_ED25519")
        if _text(self.protection_level, "protection_level", 32) != _PROTECTION_LEVEL:
            raise GcpKmsEd25519Error("protection_level must be SOFTWARE")
        if type(self.public_key) is not bytes or len(self.public_key) != 32:
            raise GcpKmsEd25519Error("public_key must be 32 native raw public bytes")
        fingerprint = _text(self.public_key_sha256, "public_key_sha256", 71)
        if _SHA256.fullmatch(fingerprint) is None or fingerprint != _sha256(self.public_key):
            raise GcpKmsEd25519Error("public_key_sha256 does not match the pinned raw public key")
        try:
            _strict_ed25519_public_key(self.public_key, "KMS pinned public key")
        except PrincipalAuthenticationError as exc:
            raise GcpKmsEd25519Error(str(exc)) from exc

    def to_dict(self) -> dict[str, str]:
        return _binding_document(_capture_binding(self))


def _capture_binding(binding: GcpKmsEd25519KeyVersionBinding) -> GcpKmsEd25519KeyVersionBinding:
    if type(binding) is not GcpKmsEd25519KeyVersionBinding:
        raise GcpKmsEd25519Error("binding must be an exact GcpKmsEd25519KeyVersionBinding")
    return GcpKmsEd25519KeyVersionBinding(
        binding.key_version_name,
        binding.algorithm,
        binding.protection_level,
        binding.public_key,
        binding.public_key_sha256,
    )


def _binding_document(binding: GcpKmsEd25519KeyVersionBinding) -> dict[str, str]:
    return {
        "key_version_name": binding.key_version_name,
        "algorithm": binding.algorithm,
        "protection_level": binding.protection_level,
        "public_key": base64.urlsafe_b64encode(binding.public_key).rstrip(b"=").decode("ascii"),
        "public_key_sha256": binding.public_key_sha256,
    }


@dataclass(frozen=True, slots=True)
class GcpKmsEd25519SigningRequest:
    """Owned raw signing input with an exact local content address."""

    binding: GcpKmsEd25519KeyVersionBinding
    signing_bytes: bytes = field(repr=False)
    data_crc32c: int = field(init=False)
    signing_input_sha256: str = field(init=False)
    request_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        owned_binding = _capture_binding(self.binding)
        if (
            type(self.signing_bytes) is not bytes
            or not 1 <= len(self.signing_bytes) <= MAX_SIGNING_BYTES
        ):
            raise GcpKmsEd25519Error("signing_bytes must be 1..65536 native raw bytes")
        object.__setattr__(self, "binding", owned_binding)
        object.__setattr__(self, "data_crc32c", _crc32c(self.signing_bytes))
        object.__setattr__(self, "signing_input_sha256", _sha256(self.signing_bytes))
        material = {
            "domain": REQUEST_DOMAIN,
            "binding": _binding_document(owned_binding),
            "request": _request_document(self),
        }
        encoded = json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
        object.__setattr__(self, "request_sha256", _sha256(encoded))

    def to_dict(self) -> dict[str, str]:
        """Return name and raw-data fields, with no digest-signing alternative."""
        return _request_document(_capture_request(self))

    def to_rest_body(self) -> dict[str, str]:
        """Return only the REST body; the version name remains the path parameter."""
        document = self.to_dict()
        return {"data": document["data"], "dataCrc32c": document["dataCrc32c"]}


def _request_document(request: GcpKmsEd25519SigningRequest) -> dict[str, str]:
    return {
        "name": request.binding.key_version_name,
        "data": base64.b64encode(request.signing_bytes).decode("ascii"),
        "dataCrc32c": str(request.data_crc32c),
    }


def _capture_request(request: GcpKmsEd25519SigningRequest) -> GcpKmsEd25519SigningRequest:
    if type(request) is not GcpKmsEd25519SigningRequest:
        raise GcpKmsEd25519Error("request must be an exact GcpKmsEd25519SigningRequest")
    captured = GcpKmsEd25519SigningRequest(request.binding, request.signing_bytes)
    if (
        type(request.data_crc32c) is not int
        or request.data_crc32c != captured.data_crc32c
        or type(request.signing_input_sha256) is not str
        or request.signing_input_sha256 != captured.signing_input_sha256
        or type(request.request_sha256) is not str
        or request.request_sha256 != captured.request_sha256
    ):
        raise GcpKmsEd25519Error("request no longer matches its captured bytes and binding")
    return captured


def build_gcp_ed25519_sign_request(
    binding: GcpKmsEd25519KeyVersionBinding, signing_bytes: bytes
) -> GcpKmsEd25519SigningRequest:
    """Map existing canonical signing bytes without hashing or reserialization."""
    return GcpKmsEd25519SigningRequest(binding, signing_bytes)


def _response_binding(binding: GcpKmsEd25519KeyVersionBinding, response: dict[str, object]) -> None:
    if (
        _text(response["name"], "response.name", MAX_KEY_VERSION_NAME_CHARS)
        != binding.key_version_name
    ):
        raise GcpKmsEd25519Error("response.name does not match the pinned key version")
    if (
        _text(response["protectionLevel"], "response.protectionLevel", 32)
        != binding.protection_level
    ):
        raise GcpKmsEd25519Error("response.protectionLevel does not match SOFTWARE")


def verify_gcp_ed25519_public_key_response(
    binding: GcpKmsEd25519KeyVersionBinding, response: object
) -> bytes:
    """Verify default PEM/SPKI response consistency against an independent key pin."""
    binding = _capture_binding(binding)
    value = _exact_response(response, _PUBLIC_KEY_FIELDS, frozenset({"publicKeyFormat"}))
    _response_binding(binding, value)
    if _text(value["algorithm"], "response.algorithm", 32) != binding.algorithm:
        raise GcpKmsEd25519Error("response.algorithm does not match EC_SIGN_ED25519")
    if "publicKeyFormat" in value and (
        type(value["publicKeyFormat"]) is not str
        or value["publicKeyFormat"] != "PUBLIC_KEY_FORMAT_UNSPECIFIED"
    ):
        raise GcpKmsEd25519Error("only the default PEM public key response is supported")
    pem = _text(value["pem"], "response.pem", MAX_PUBLIC_KEY_PEM_CHARS)
    if _crc32c(pem.encode("ascii")) != _wire_crc(value["pemCrc32c"], "response.pemCrc32c"):
        raise GcpKmsEd25519Error("response.pem CRC32C mismatch")
    normalized = pem.replace("\r\n", "\n")
    lines = normalized.split("\n")
    if lines[-1] == "":
        lines.pop()
    if (
        "\r" in normalized
        or not 3 <= len(lines)
        or lines[0] != "-----BEGIN PUBLIC KEY-----"
        or lines[-1] != "-----END PUBLIC KEY-----"
        or any(re.fullmatch(r"[A-Za-z0-9+/=]{1,64}", line) is None for line in lines[1:-1])
    ):
        raise GcpKmsEd25519Error("response.pem must contain exactly one public SPKI block")
    encoded_der = "".join(lines[1:-1])
    try:
        der = base64.b64decode(encoded_der, validate=True)
        if base64.b64encode(der).decode("ascii") != encoded_der:
            raise ValueError("noncanonical DER base64")
        key = serialization.load_der_public_key(der)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("not an Ed25519 public key")
        if (
            key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            != der
        ):
            raise ValueError("noncanonical or trailing DER")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except (ValueError, TypeError, binascii.Error, UnsupportedAlgorithm) as exc:
        raise GcpKmsEd25519Error("response.pem is not one canonical Ed25519 SPKI key") from exc
    if raw != binding.public_key or _sha256(raw) != binding.public_key_sha256:
        raise GcpKmsEd25519Error("response.pem does not match the independent public key pin")
    return raw


def verify_gcp_ed25519_sign_response(request: GcpKmsEd25519SigningRequest, response: object) -> str:
    """Return a locally verified signature, never current authority or cloud evidence."""
    request = _capture_request(request)
    value = _exact_response(response, _SIGNATURE_FIELDS, frozenset({"verifiedDigestCrc32c"}))
    _response_binding(request.binding, value)
    if type(value["verifiedDataCrc32c"]) is not bool or value["verifiedDataCrc32c"] is not True:
        raise GcpKmsEd25519Error("response.verifiedDataCrc32c must be exactly true")
    if "verifiedDigestCrc32c" in value and (
        type(value["verifiedDigestCrc32c"]) is not bool
        or value["verifiedDigestCrc32c"] is not False
    ):
        raise GcpKmsEd25519Error("response cannot claim digest signing for a raw-data request")
    encoded = _text(value["signature"], "response.signature", 88)
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GcpKmsEd25519Error("response.signature must use canonical standard base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise GcpKmsEd25519Error("response.signature must be 64 bytes in canonical standard base64")
    if _crc32c(signature) != _wire_crc(value["signatureCrc32c"], "response.signatureCrc32c"):
        raise GcpKmsEd25519Error("response.signature CRC32C mismatch")
    repository_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    try:
        _verify_ed25519(
            request.binding.public_key, repository_signature, request.signing_bytes, "KMS response"
        )
    except PrincipalAuthenticationError as exc:
        raise GcpKmsEd25519Error(str(exc)) from exc
    return repository_signature


__all__ = [
    "GcpKmsEd25519Error",
    "GcpKmsEd25519KeyVersionBinding",
    "GcpKmsEd25519SigningRequest",
    "MAX_KEY_VERSION_NAME_CHARS",
    "MAX_PUBLIC_KEY_PEM_CHARS",
    "MAX_SIGNING_BYTES",
    "build_gcp_ed25519_sign_request",
    "verify_gcp_ed25519_public_key_response",
    "verify_gcp_ed25519_sign_response",
]
