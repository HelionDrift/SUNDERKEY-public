"""Fail-closed compilation of signed authorized-assessment scopes."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .identity import _strict_ed25519_public_key, _verify_ed25519
from .types import ActionTier

SCHEMA_VERSION = 1
SCOPE_KIND = "sunderkey.signed-assessment-scope.v1"
SIGNING_DOMAIN = b"SUNDERKEY\x00SIGNED-ASSESSMENT-SCOPE\x00V1\x00"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_SCOPE_LIFETIME_SECONDS = 31 * 24 * 60 * 60
MAX_REQUESTS = 1_000_000
MAX_CONCURRENCY = 256
MAX_REQUESTS_PER_MINUTE = 60_000

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,128}")
_METHOD = re.compile(r"[A-Z][A-Z0-9_-]{0,31}")
_TECHNIQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SECRET_FIELD = re.compile(
    r"(?:^|_)(?:api_key|authorization|bearer|cookie|credential|password|private_key|secret|token)(?:$|_)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~-]{12,}|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[opsu]_[A-Za-z0-9]{20,}\b)",
    re.IGNORECASE,
)
_COMMON_MULTIPART_PUBLIC_SUFFIXES = frozenset(
    {
        "ac.uk",
        "co.jp",
        "co.nz",
        "co.uk",
        "com.au",
        "com.br",
        "com.cn",
        "com.mx",
        "com.sg",
        "net.au",
        "org.au",
        "org.uk",
    }
)
_SOURCE_FIELDS = {
    "schema_version",
    "issuer",
    "key_id",
    "nonce",
    "sequence_number",
    "issued_at",
    "expires_at",
    "assessment_window",
    "targets",
    "exclusions",
    "protected_endpoints",
    "budgets",
    "impact_tier_ceiling",
    "allowed_technique_ids",
    "data_handling",
    "emergency_stop_contact_id",
}
_DOCUMENT_FIELDS = _SOURCE_FIELDS | {
    "kind",
    "scope_id",
    "effects",
    "content_sha256",
    "signature_algorithm",
    "signature",
}
_TARGET_FIELDS = {
    "https_origins",
    "exact_hosts",
    "wildcard_subdomains",
    "cidrs",
    "ports",
    "http_methods",
    "path_prefixes",
}
_EXCLUSION_FIELDS = _TARGET_FIELDS | {"exclusion_id"}
_IMPACT_RANK = {tier.value: tier.rank for tier in ActionTier}


class SignedScopeError(ValueError):
    """Raised when a scope is ambiguous, unsafe, invalid, or unverifiable."""


@dataclass(frozen=True)
class SignedAssessmentScope:
    """One canonical signed scope without retained signing key material."""

    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def scope_id(self) -> str:
        return str(self.to_dict()["scope_id"])

    @property
    def content_sha256(self) -> str:
        return str(self.to_dict()["content_sha256"])

    @property
    def issuer(self) -> str:
        return str(self.to_dict()["issuer"])

    @property
    def key_id(self) -> str:
        return str(self.to_dict()["key_id"])

    @property
    def sequence_number(self) -> int:
        return int(self.to_dict()["sequence_number"])


@dataclass(frozen=True)
class VerifiedAssessmentScope:
    """A signed scope checked against out-of-band authority pins."""

    signed_scope: SignedAssessmentScope
    verified_at: str
    verification_key_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return self.signed_scope.to_dict()

    @property
    def scope_id(self) -> str:
        return self.signed_scope.scope_id

    @property
    def content_sha256(self) -> str:
        return self.signed_scope.content_sha256


@dataclass(frozen=True)
class ScopeBudgetState:
    """Caller-supplied counters used for a fail-closed request decision."""

    requests_completed: int
    requests_active: int
    requests_in_current_minute: int

    def validate(self) -> None:
        for name, value in (
            ("requests_completed", self.requests_completed),
            ("requests_active", self.requests_active),
            ("requests_in_current_minute", self.requests_in_current_minute),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SignedScopeError(f"budget state {name} must be a non-negative integer")


@dataclass(frozen=True)
class ScopeDecision:
    """Deterministic request containment result."""

    allowed: bool
    reason: str


def canonical_json(value: Any) -> str:
    """Return the repository's stable ASCII JSON representation."""

    _validate_json_value(value, "value")
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise SignedScopeError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    """Return the prefixed SHA-256 of canonical JSON."""

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _validate_json_value(value: Any, label: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**63 - 1:
            raise SignedScopeError(f"{label} integer is outside the signed 64-bit range")
        return
    if isinstance(value, float):
        raise SignedScopeError(f"{label} must not contain floating-point numbers")
    if isinstance(value, str):
        if (
            len(value) > 65_536
            or not value.isascii()
            or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
        ):
            raise SignedScopeError(f"{label} must contain printable ASCII text")
        return
    if isinstance(value, list | tuple):
        for index, member in enumerate(value):
            _validate_json_value(member, f"{label}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, member in value.items():
            if not isinstance(key, str) or not key.isascii() or not key:
                raise SignedScopeError(f"{label} has an invalid object key")
            _validate_json_value(member, f"{label}.{key}")
        return
    raise SignedScopeError(f"{label} contains an unsupported JSON value")


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SignedScopeError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    raise SignedScopeError(f"floating-point JSON numbers are not permitted: {value}")


def _reject_constant(value: str) -> Any:
    raise SignedScopeError(f"non-finite JSON numbers are not permitted: {value}")


def _parse_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise SignedScopeError("invalid JSON integer") from exc
    if not -(2**63) <= parsed <= 2**63 - 1:
        raise SignedScopeError("JSON integer is outside the signed 64-bit range")
    return parsed


def _load_object(raw: Any, label: str) -> tuple[dict[str, Any], str | None]:
    original: str | None = None
    if isinstance(raw, SignedAssessmentScope):
        original = raw.document_json
    elif isinstance(raw, bytes):
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise SignedScopeError(f"{label} exceeds {MAX_DOCUMENT_BYTES} bytes")
        if raw.startswith(b"\xef\xbb\xbf"):
            raise SignedScopeError(f"{label} must not contain a UTF-8 BOM")
        try:
            original = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SignedScopeError(f"{label} must use UTF-8") from exc
    elif isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise SignedScopeError(f"{label} exceeds {MAX_DOCUMENT_BYTES} bytes")
        original = raw
    elif isinstance(raw, Mapping):
        value = copy.deepcopy(dict(raw))
        _validate_json_value(value, label)
        return value, None
    else:
        raise SignedScopeError(f"{label} must be an object or strict JSON object")
    try:
        value = json.loads(
            original,
            object_pairs_hook=_json_pairs,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except SignedScopeError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SignedScopeError(f"{label} is not valid strict JSON") from exc
    if not isinstance(value, dict):
        raise SignedScopeError(f"{label} must contain one JSON object")
    _validate_json_value(value, label)
    return value, original


def _object(value: Any, label: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SignedScopeError(f"{label} must be an object")
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if unknown:
        raise SignedScopeError(f"{label} contains unknown fields: {', '.join(unknown)}")
    if missing:
        raise SignedScopeError(f"{label} is missing required fields: {', '.join(missing)}")
    return value


def _reject_secret_material(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, member in value.items():
            if _SECRET_FIELD.search(str(key)) and key not in {"key_id"}:
                raise SignedScopeError(f"{label} contains forbidden secret field: {key}")
            _reject_secret_material(member, f"{label}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for index, member in enumerate(value):
            _reject_secret_material(member, f"{label}[{index}]")
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise SignedScopeError(f"{label} contains probable secret material")


def _ascii(value: Any, label: str, *, minimum: int = 1, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or not value.isascii()
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise SignedScopeError(f"{label} must be {minimum} to {maximum} visible ASCII characters")
    return value


def _identifier(value: Any, label: str) -> str:
    result = _ascii(value, label, minimum=3, maximum=128)
    if _ID.fullmatch(result) is None:
        raise SignedScopeError(f"{label} is not a valid identifier")
    return result


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SignedScopeError(f"{label} must be an integer from {minimum} through {maximum}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise SignedScopeError(f"{label} must be a boolean")
    return value


def _timestamp(value: Any, label: str) -> str:
    result = _ascii(value, label, minimum=20, maximum=20)
    if _TIMESTAMP.fullmatch(result) is None:
        raise SignedScopeError(f"{label} must use YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SignedScopeError(f"{label} is not a valid UTC timestamp") from exc
    return result


def _parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _clock(now: datetime | None) -> datetime:
    current = datetime.now(UTC) if now is None else now
    if current.tzinfo is None or current.utcoffset() is None:
        raise SignedScopeError("now must be timezone-aware")
    return current.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_dns_name(value: str, label: str) -> str:
    if value.endswith("."):
        raise SignedScopeError(f"{label} must not use a trailing root dot")
    host = value.lower()
    if all(character in "0123456789." for character in host):
        raise SignedScopeError(f"{label} is an ambiguous non-canonical IPv4 address")
    if len(host) > 253 or "." not in host:
        raise SignedScopeError(f"{label} must be a bounded fully qualified DNS name")
    labels = host.split(".")
    if any(_DNS_LABEL.fullmatch(item) is None for item in labels):
        raise SignedScopeError(f"{label} is not a canonical DNS name")
    return host


def _normalize_host(value: Any, label: str) -> str:
    host = _ascii(value, label, maximum=253)
    if any(character in host for character in "%/\\@[]"):
        raise SignedScopeError(f"{label} contains ambiguous host syntax")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return _normalize_dns_name(host, label)


def _normalize_wildcard(value: Any, label: str) -> str:
    wildcard = _ascii(value, label, minimum=5, maximum=255).lower()
    if not wildcard.startswith("*.") or "*" in wildcard[2:]:
        raise SignedScopeError(f"{label} must contain one leftmost wildcard label")
    suffix = _normalize_dns_name(wildcard[2:], f"{label} suffix")
    if suffix in _COMMON_MULTIPART_PUBLIC_SUFFIXES:
        raise SignedScopeError(f"{label} is an overbroad public-suffix wildcard")
    return "*." + suffix


def _normalize_cidr(value: Any, label: str) -> str:
    text = _ascii(value, label, minimum=3, maximum=64)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise SignedScopeError(f"{label} must be a canonical CIDR network") from exc
    if network.prefixlen == 0:
        raise SignedScopeError(f"{label} must not authorize a default-route CIDR")
    return network.with_prefixlen


def _url_parts(value: Any, label: str, *, endpoint: bool) -> tuple[str, str, int, str]:
    text = _ascii(value, label, minimum=9, maximum=2048)
    if any(character in text for character in "\\%?#\t\r\n "):
        raise SignedScopeError(f"{label} contains ambiguous or encoded URL syntax")
    try:
        parts = urlsplit(text)
        host_value = parts.hostname
        port = 443 if parts.port is None else parts.port
    except ValueError as exc:
        raise SignedScopeError(f"{label} is not an unambiguous URL") from exc
    if parts.scheme.lower() != "https" or not parts.netloc or host_value is None:
        raise SignedScopeError(f"{label} must be an absolute HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise SignedScopeError(f"{label} must not contain userinfo")
    if parts.fragment:
        raise SignedScopeError(f"{label} must not contain a fragment")
    if parts.query:
        raise SignedScopeError(f"{label} must not contain a query")
    if text.split("//", 1)[1].split("/", 1)[0].endswith(":"):
        raise SignedScopeError(f"{label} contains an empty port")
    host = _normalize_host(host_value, f"{label} host")
    port = _integer(port, f"{label} port", 1, 65_535)
    origin_host = f"[{host}]" if ":" in host else host
    origin = f"https://{origin_host}" + ("" if port == 443 else f":{port}")
    if endpoint:
        path = _normalize_path(parts.path or "/", f"{label} path")
    else:
        if parts.path not in {"", "/"}:
            raise SignedScopeError(f"{label} must not contain a path")
        path = "/"
    return origin, host, port, path


def _normalize_path(value: Any, label: str) -> str:
    path = _ascii(value, label, maximum=2048)
    if not path.startswith("/") or any(character in path for character in "%\\?#"):
        raise SignedScopeError(f"{label} must be an unencoded absolute path")
    if "//" in path:
        raise SignedScopeError(f"{label} must not contain repeated separators")
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise SignedScopeError(f"{label} must not contain traversal segments")
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return path


def _normalize_origin(value: Any, label: str) -> str:
    return _url_parts(value, label, endpoint=False)[0]


def _normalize_endpoint(value: Any, label: str) -> str:
    origin, _, _, path = _url_parts(value, label, endpoint=True)
    return origin + path


def _array(value: Any, label: str, *, maximum: int = 256) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise SignedScopeError(f"{label} must be an array with at most {maximum} values")
    return value


def _normalized_strings(
    value: Any,
    label: str,
    normalizer: Any,
    *,
    allow_empty: bool = True,
    maximum: int = 256,
) -> list[str]:
    raw = _array(value, label, maximum=maximum)
    if not allow_empty and not raw:
        raise SignedScopeError(f"{label} must not be empty")
    result = [normalizer(item, f"{label}[{index}]") for index, item in enumerate(raw)]
    if len(result) != len(set(result)):
        raise SignedScopeError(f"{label} contains duplicate values after normalization")
    return sorted(result)


def _ports(value: Any, label: str, *, allow_empty: bool) -> list[int]:
    raw = _array(value, label)
    if not allow_empty and not raw:
        raise SignedScopeError(f"{label} must not be empty")
    result = [_integer(item, f"{label}[{index}]", 1, 65_535) for index, item in enumerate(raw)]
    if len(result) != len(set(result)):
        raise SignedScopeError(f"{label} contains duplicate ports")
    return sorted(result)


def _methods(value: Any, label: str, *, allow_empty: bool) -> list[str]:
    def normalize(item: Any, item_label: str) -> str:
        method = _ascii(item, item_label, maximum=32).upper()
        if _METHOD.fullmatch(method) is None:
            raise SignedScopeError(f"{item_label} is not a canonical HTTP method")
        return method

    return _normalized_strings(value, label, normalize, allow_empty=allow_empty, maximum=32)


def _normalize_targets(value: Any, label: str, *, allow_empty: bool) -> dict[str, Any]:
    raw = _object(value, label, _TARGET_FIELDS)
    result = {
        "https_origins": _normalized_strings(
            raw["https_origins"], f"{label}.https_origins", _normalize_origin
        ),
        "exact_hosts": _normalized_strings(
            raw["exact_hosts"], f"{label}.exact_hosts", _normalize_host
        ),
        "wildcard_subdomains": _normalized_strings(
            raw["wildcard_subdomains"],
            f"{label}.wildcard_subdomains",
            _normalize_wildcard,
        ),
        "cidrs": _normalized_strings(raw["cidrs"], f"{label}.cidrs", _normalize_cidr),
        "ports": _ports(raw["ports"], f"{label}.ports", allow_empty=allow_empty),
        "http_methods": _methods(
            raw["http_methods"], f"{label}.http_methods", allow_empty=allow_empty
        ),
        "path_prefixes": _normalized_strings(
            raw["path_prefixes"],
            f"{label}.path_prefixes",
            _normalize_path,
            allow_empty=allow_empty,
        ),
    }
    if not allow_empty and not any(
        result[field] for field in ("https_origins", "exact_hosts", "wildcard_subdomains", "cidrs")
    ):
        raise SignedScopeError(f"{label} must contain at least one network target")
    if not allow_empty:
        target_ports = set(result["ports"])
        for index, origin in enumerate(result["https_origins"]):
            _, _, port, _ = _url_parts(origin, f"{label}.https_origins[{index}]", endpoint=False)
            if port not in target_ports:
                raise SignedScopeError(f"{label} origin port is not in the allowed port set")
    return result


def _normalize_exclusion(value: Any, index: int) -> dict[str, Any]:
    label = f"scope specification.exclusions[{index}]"
    raw = _object(value, label, _EXCLUSION_FIELDS)
    target = _normalize_targets(
        {field: raw[field] for field in _TARGET_FIELDS},
        label,
        allow_empty=True,
    )
    if not any(target.values()):
        raise SignedScopeError(f"{label} must constrain at least one request dimension")
    return {"exclusion_id": _identifier(raw["exclusion_id"], f"{label}.exclusion_id"), **target}


def _normalize_window(value: Any) -> dict[str, str]:
    raw = _object(
        value,
        "scope specification.assessment_window",
        {"starts_at", "ends_at"},
    )
    return {
        "starts_at": _timestamp(raw["starts_at"], "assessment_window.starts_at"),
        "ends_at": _timestamp(raw["ends_at"], "assessment_window.ends_at"),
    }


def _normalize_budgets(value: Any) -> dict[str, int]:
    raw = _object(
        value,
        "scope specification.budgets",
        {"max_requests", "max_concurrency", "max_requests_per_minute"},
    )
    result = {
        "max_requests": _integer(raw["max_requests"], "budgets.max_requests", 1, MAX_REQUESTS),
        "max_concurrency": _integer(
            raw["max_concurrency"], "budgets.max_concurrency", 1, MAX_CONCURRENCY
        ),
        "max_requests_per_minute": _integer(
            raw["max_requests_per_minute"],
            "budgets.max_requests_per_minute",
            1,
            MAX_REQUESTS_PER_MINUTE,
        ),
    }
    if result["max_concurrency"] > result["max_requests"]:
        raise SignedScopeError("budgets.max_concurrency must not exceed max_requests")
    return result


def _normalize_data_handling(value: Any) -> dict[str, Any]:
    raw = _object(
        value,
        "scope specification.data_handling",
        {"classification", "collection", "storage", "retention_days", "redaction_required"},
    )
    classification = _ascii(raw["classification"], "data_handling.classification", maximum=32)
    if classification not in {"public", "internal", "confidential", "restricted"}:
        raise SignedScopeError("data_handling.classification is invalid")
    collection = _ascii(raw["collection"], "data_handling.collection", maximum=32)
    if collection not in {"metadata_only", "minimized_content", "authorized_content"}:
        raise SignedScopeError("data_handling.collection is invalid")
    storage = _ascii(raw["storage"], "data_handling.storage", maximum=64)
    if storage not in {"none", "ephemeral_encrypted", "approved_encrypted_repository"}:
        raise SignedScopeError("data_handling.storage is invalid")
    retention_days = _integer(raw["retention_days"], "data_handling.retention_days", 0, 365)
    if storage == "none" and retention_days != 0:
        raise SignedScopeError("data_handling retention must be zero when storage is none")
    return {
        "classification": classification,
        "collection": collection,
        "storage": storage,
        "retention_days": retention_days,
        "redaction_required": _boolean(
            raw["redaction_required"], "data_handling.redaction_required"
        ),
    }


def _normalize_technique(value: Any, label: str) -> str:
    result = _ascii(value, label, minimum=3, maximum=128)
    if _TECHNIQUE_ID.fullmatch(result) is None:
        raise SignedScopeError(f"{label} is not a valid technique ID")
    return result


def _normalize_source(raw: dict[str, Any]) -> dict[str, Any]:
    _reject_secret_material(raw, "scope specification")
    value = _object(raw, "scope specification", _SOURCE_FIELDS)
    if value["schema_version"] != SCHEMA_VERSION:
        raise SignedScopeError("scope specification schema_version must be 1")
    nonce = _ascii(value["nonce"], "scope specification.nonce", minimum=16, maximum=128)
    if _NONCE.fullmatch(nonce) is None:
        raise SignedScopeError("scope specification.nonce must use unpadded base64url characters")
    impact = _ascii(value["impact_tier_ceiling"], "impact_tier_ceiling", maximum=2)
    if impact not in _IMPACT_RANK:
        raise SignedScopeError("impact_tier_ceiling must be an ActionTier from R0 through R5")
    exclusions_raw = _array(value["exclusions"], "scope specification.exclusions", maximum=128)
    exclusions = [_normalize_exclusion(item, index) for index, item in enumerate(exclusions_raw)]
    exclusions.sort(key=lambda item: item["exclusion_id"])
    exclusion_ids = [item["exclusion_id"] for item in exclusions]
    if len(exclusion_ids) != len(set(exclusion_ids)):
        raise SignedScopeError("scope specification.exclusions repeats an exclusion ID")
    source = {
        "schema_version": SCHEMA_VERSION,
        "issuer": _identifier(value["issuer"], "scope specification.issuer"),
        "key_id": _identifier(value["key_id"], "scope specification.key_id"),
        "nonce": nonce,
        "sequence_number": _integer(
            value["sequence_number"], "scope specification.sequence_number", 1, 2_147_483_647
        ),
        "issued_at": _timestamp(value["issued_at"], "scope specification.issued_at"),
        "expires_at": _timestamp(value["expires_at"], "scope specification.expires_at"),
        "assessment_window": _normalize_window(value["assessment_window"]),
        "targets": _normalize_targets(
            value["targets"], "scope specification.targets", allow_empty=False
        ),
        "exclusions": exclusions,
        "protected_endpoints": _normalized_strings(
            value["protected_endpoints"],
            "scope specification.protected_endpoints",
            _normalize_endpoint,
            maximum=256,
        ),
        "budgets": _normalize_budgets(value["budgets"]),
        "impact_tier_ceiling": impact,
        "allowed_technique_ids": _normalized_strings(
            value["allowed_technique_ids"],
            "scope specification.allowed_technique_ids",
            _normalize_technique,
            allow_empty=False,
            maximum=512,
        ),
        "data_handling": _normalize_data_handling(value["data_handling"]),
        "emergency_stop_contact_id": _identifier(
            value["emergency_stop_contact_id"], "scope specification.emergency_stop_contact_id"
        ),
    }
    _validate_temporal_structure(source)
    _validate_exclusions(source)
    _validate_protected_endpoints(source)
    return source


def _validate_temporal_structure(source: Mapping[str, Any]) -> None:
    issued = _parse_timestamp(str(source["issued_at"]))
    expires = _parse_timestamp(str(source["expires_at"]))
    window = source["assessment_window"]
    starts = _parse_timestamp(str(window["starts_at"]))
    ends = _parse_timestamp(str(window["ends_at"]))
    if not issued <= starts < ends <= expires:
        raise SignedScopeError(
            "issued_at, assessment window, and expires_at must be ordered without gaps in authority"
        )
    if int((expires - issued).total_seconds()) > MAX_SCOPE_LIFETIME_SECONDS:
        raise SignedScopeError("scope lifetime exceeds the v1 maximum")


def _validate_active(source: Mapping[str, Any], now: datetime) -> None:
    issued = _parse_timestamp(str(source["issued_at"]))
    expires = _parse_timestamp(str(source["expires_at"]))
    window = source["assessment_window"]
    starts = _parse_timestamp(str(window["starts_at"]))
    ends = _parse_timestamp(str(window["ends_at"]))
    if now < issued or now < starts:
        raise SignedScopeError("scope is future-dated or its assessment window has not started")
    if now >= expires or now >= ends:
        raise SignedScopeError("scope or its assessment window has expired")


def _build_content(source: dict[str, Any]) -> dict[str, Any]:
    base = {
        **source,
        "kind": SCOPE_KIND,
        "effects": {
            "authority": "none",
            "qualification": "none",
            "routing": "none",
            "deployment": "none",
            "network": "none",
            "execution": "none",
        },
    }
    scope_id = "SAS-" + canonical_sha256(base).split(":", 1)[1][:32].upper()
    return {**base, "scope_id": scope_id}


def _private_key(value: Any) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes) and len(value) == 32:
        try:
            return Ed25519PrivateKey.from_private_bytes(value)
        except ValueError as exc:
            raise SignedScopeError("signing key is not a valid raw Ed25519 private key") from exc
    raise SignedScopeError("signing key must be an Ed25519PrivateKey or 32 raw private bytes")


def _public_key(value: Any) -> tuple[Ed25519PublicKey, bytes]:
    try:
        key = _strict_ed25519_public_key(value, "scope verification key")
    except Exception as exc:
        raise SignedScopeError(
            "verification key must be a strict out-of-band Ed25519 public key"
        ) from exc
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, raw


def compile_signed_scope(
    specification: Mapping[str, Any] | str | bytes,
    signing_key: Ed25519PrivateKey | bytes,
    *,
    now: datetime | None = None,
    authority_ceiling: VerifiedAssessmentScope | None = None,
) -> SignedAssessmentScope:
    """Normalize, content-address, and sign one already-ingested scope."""

    raw, _ = _load_object(specification, "scope specification")
    source = _normalize_source(raw)
    current = _clock(now)
    _validate_active(source, current)
    content = _build_content(source)
    if authority_ceiling is not None:
        _require_verified(authority_ceiling, "authority_ceiling")
        if not _content_contains(authority_ceiling.to_dict(), content):
            raise SignedScopeError("scope exceeds the supplied verified authority ceiling")
    content_sha256 = canonical_sha256(content)
    unsigned = {
        **content,
        "content_sha256": content_sha256,
        "signature_algorithm": "Ed25519",
    }
    private_key = _private_key(signing_key)
    signature = private_key.sign(SIGNING_DOMAIN + canonical_json(unsigned).encode("ascii"))
    document = {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }
    return SignedAssessmentScope(canonical_json(document))


def _parse_signed_document(raw_document: Any) -> tuple[dict[str, Any], str | None]:
    raw, original = _load_object(raw_document, "signed assessment scope")
    value = _object(raw, "signed assessment scope", _DOCUMENT_FIELDS)
    if original is not None and canonical_json(value) != original:
        raise SignedScopeError("signed assessment scope JSON is not canonical")
    source = {field: value[field] for field in _SOURCE_FIELDS}
    normalized_source = _normalize_source(source)
    expected_content = _build_content(normalized_source)
    content = {
        key: value[key]
        for key in value
        if key not in {"content_sha256", "signature_algorithm", "signature"}
    }
    if content != expected_content:
        raise SignedScopeError("signed assessment scope content is not canonical")
    digest = value["content_sha256"]
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise SignedScopeError("content_sha256 is not canonical")
    if not hmac.compare_digest(digest, canonical_sha256(content)):
        raise SignedScopeError("content_sha256 does not match signed scope content")
    if value["signature_algorithm"] != "Ed25519":
        raise SignedScopeError("signature_algorithm must be Ed25519")
    signature = value["signature"]
    if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
        raise SignedScopeError("signature must be unpadded base64url Ed25519 material")
    return value, original


def verify_signed_scope(
    document: SignedAssessmentScope | Mapping[str, Any] | str | bytes,
    public_key: Ed25519PublicKey | bytes,
    *,
    expected_issuer: str,
    expected_key_id: str,
    now: datetime | None = None,
    minimum_sequence_number: int | None = None,
) -> VerifiedAssessmentScope:
    """Verify a canonical scope against an out-of-band key and identity pins."""

    value, _ = _parse_signed_document(document)
    issuer = _identifier(expected_issuer, "expected_issuer")
    key_id = _identifier(expected_key_id, "expected_key_id")
    if not hmac.compare_digest(value["issuer"], issuer):
        raise SignedScopeError("scope issuer does not match the out-of-band issuer pin")
    if not hmac.compare_digest(value["key_id"], key_id):
        raise SignedScopeError("scope key_id does not match the out-of-band key pin")
    if minimum_sequence_number is not None:
        minimum = _integer(minimum_sequence_number, "minimum_sequence_number", 1, 2_147_483_647)
        if value["sequence_number"] < minimum:
            raise SignedScopeError("scope sequence number is below the required floor")
    current = _clock(now)
    _validate_active(value, current)
    verifier, raw_public_key = _public_key(public_key)
    unsigned = {key: member for key, member in value.items() if key != "signature"}
    try:
        _verify_ed25519(
            verifier,
            value["signature"],
            SIGNING_DOMAIN + canonical_json(unsigned).encode("ascii"),
            "Signed assessment scope",
        )
    except Exception as exc:
        raise SignedScopeError("signed assessment scope signature verification failed") from exc
    signed = SignedAssessmentScope(canonical_json(value))
    return VerifiedAssessmentScope(
        signed_scope=signed,
        verified_at=_format_timestamp(current),
        verification_key_sha256="sha256:" + hashlib.sha256(raw_public_key).hexdigest(),
    )


def _path_matches(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def _paths_overlap(left: str, right: str) -> bool:
    return _path_matches(left, right) or _path_matches(right, left)


def _wildcard_matches(host: str, wildcard: str) -> bool:
    if ":" in host or host.replace(".", "").isdigit():
        return False
    suffix_labels = wildcard[2:].split(".")
    host_labels = host.split(".")
    return len(host_labels) == len(suffix_labels) + 1 and host_labels[1:] == suffix_labels


def _host_selector_matches(host: str, kind: str, value: str) -> bool:
    if kind == "exact":
        return host == value
    if kind == "wildcard":
        return _wildcard_matches(host, value)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address in ipaddress.ip_network(value)


def _selector_contains(
    parent_kind: str,
    parent_value: str,
    child_kind: str,
    child_value: str,
) -> bool:
    if child_kind == "exact":
        return _host_selector_matches(child_value, parent_kind, parent_value)
    if parent_kind == "wildcard" and child_kind == "wildcard":
        return parent_value == child_value
    if parent_kind == "cidr" and child_kind == "cidr":
        parent = ipaddress.ip_network(parent_value)
        child = ipaddress.ip_network(child_value)
        return parent.version == child.version and child.subnet_of(parent)
    return False


def _selectors_overlap(
    left_kind: str,
    left_value: str,
    right_kind: str,
    right_value: str,
) -> bool:
    if left_kind == "exact":
        return _host_selector_matches(left_value, right_kind, right_value)
    if right_kind == "exact":
        return _host_selector_matches(right_value, left_kind, left_value)
    if left_kind == right_kind == "wildcard":
        return left_value == right_value
    if left_kind == right_kind == "cidr":
        left = ipaddress.ip_network(left_value)
        right = ipaddress.ip_network(right_value)
        return left.version == right.version and left.overlaps(right)
    return False


def _target_atoms(targets: Mapping[str, Any]) -> list[tuple[str, str, frozenset[int]]]:
    ports = frozenset(int(port) for port in targets["ports"])
    atoms: list[tuple[str, str, frozenset[int]]] = []
    for origin in targets["https_origins"]:
        _, host, port, _ = _url_parts(origin, "canonical origin", endpoint=False)
        atoms.append(("exact", host, frozenset({port})))
    atoms.extend(("exact", host, ports) for host in targets["exact_hosts"])
    atoms.extend(("wildcard", value, ports) for value in targets["wildcard_subdomains"])
    atoms.extend(("cidr", value, ports) for value in targets["cidrs"])
    return atoms


def _target_matches(targets: Mapping[str, Any], origin: str, host: str, port: int) -> bool:
    if port not in targets["ports"]:
        return False
    if origin in targets["https_origins"]:
        return True
    for kind, value, atom_ports in _target_atoms(targets):
        if port in atom_ports and _host_selector_matches(host, kind, value):
            return True
    return False


def _exclusion_matches(
    rule: Mapping[str, Any],
    *,
    origin: str,
    host: str,
    port: int,
    method: str,
    path: str,
) -> bool:
    host_constrained = any(
        rule[field] for field in ("https_origins", "exact_hosts", "wildcard_subdomains", "cidrs")
    )
    if host_constrained:
        origin_match = origin in rule["https_origins"]
        selector_match = any(
            _host_selector_matches(host, kind, value)
            for kind, field in (
                ("exact", "exact_hosts"),
                ("wildcard", "wildcard_subdomains"),
                ("cidr", "cidrs"),
            )
            for value in rule[field]
        )
        if not origin_match and not selector_match:
            return False
    return (
        (not rule["ports"] or port in rule["ports"])
        and (not rule["http_methods"] or method in rule["http_methods"])
        and (
            not rule["path_prefixes"]
            or any(_path_matches(path, prefix) for prefix in rule["path_prefixes"])
        )
    )


def _rule_dimension_contains(parent: list[Any], child: list[Any]) -> bool:
    return not parent or (bool(child) and set(child) <= set(parent))


def _exclusion_contains(parent: Mapping[str, Any], child: Mapping[str, Any]) -> bool:
    for field in ("ports", "http_methods"):
        if not _rule_dimension_contains(parent[field], child[field]):
            return False
    if parent["path_prefixes"] and (
        not child["path_prefixes"]
        or not all(
            any(_path_matches(path, candidate) for candidate in parent["path_prefixes"])
            for path in child["path_prefixes"]
        )
    ):
        return False
    parent_hosts = _target_atoms({**parent, "ports": list(range(1, 2))})
    child_hosts = _target_atoms({**child, "ports": list(range(1, 2))})
    if parent_hosts:
        if not child_hosts:
            return False
        for child_kind, child_value, _ in child_hosts:
            if not any(
                _selector_contains(parent_kind, parent_value, child_kind, child_value)
                for parent_kind, parent_value, _ in parent_hosts
            ):
                return False
    return True


def _rule_intersects_targets(rule: Mapping[str, Any], targets: Mapping[str, Any]) -> bool:
    if rule["ports"] and not set(rule["ports"]) & set(targets["ports"]):
        return False
    if rule["http_methods"] and not set(rule["http_methods"]) & set(targets["http_methods"]):
        return False
    if rule["path_prefixes"] and not any(
        _paths_overlap(left, right)
        for left in rule["path_prefixes"]
        for right in targets["path_prefixes"]
    ):
        return False
    rule_atoms = _target_atoms({**rule, "ports": rule["ports"] or targets["ports"]})
    if not rule_atoms:
        return True
    rule_port_filter = set(rule["ports"] or targets["ports"])
    return any(
        bool(left_ports & rule_port_filter & right_ports)
        and _selectors_overlap(left_kind, left_value, right_kind, right_value)
        for left_kind, left_value, left_ports in rule_atoms
        for right_kind, right_value, right_ports in _target_atoms(targets)
    )


def _validate_exclusions(source: Mapping[str, Any]) -> None:
    exclusions = source["exclusions"]
    for rule in exclusions:
        if not _rule_intersects_targets(rule, source["targets"]):
            raise SignedScopeError(
                f"exclusion {rule['exclusion_id']} cannot match an allowed target"
            )
    for index, left in enumerate(exclusions):
        for right in exclusions[index + 1 :]:
            if _exclusion_contains(left, right):
                raise SignedScopeError(
                    f"exclusion {right['exclusion_id']} is shadowed by {left['exclusion_id']}"
                )
            if _exclusion_contains(right, left):
                raise SignedScopeError(
                    f"exclusion {left['exclusion_id']} is shadowed by {right['exclusion_id']}"
                )


def _validate_protected_endpoints(source: Mapping[str, Any]) -> None:
    targets = source["targets"]
    for index, endpoint in enumerate(source["protected_endpoints"]):
        origin, host, port, path = _url_parts(
            endpoint, f"protected_endpoints[{index}]", endpoint=True
        )
        if not _target_matches(targets, origin, host, port) or not any(
            _path_matches(path, prefix) for prefix in targets["path_prefixes"]
        ):
            raise SignedScopeError("protected endpoint must fall within an allowed target")


def _require_verified(value: Any, label: str) -> VerifiedAssessmentScope:
    if not isinstance(value, VerifiedAssessmentScope):
        raise SignedScopeError(f"{label} must be a VerifiedAssessmentScope")
    return value


def evaluate_request(
    scope: VerifiedAssessmentScope,
    *,
    url: str,
    method: str,
    technique_id: str,
    impact_tier: ActionTier | str,
    budget_state: ScopeBudgetState,
    at: datetime | None = None,
) -> ScopeDecision:
    """Decide whether one proposed HTTPS request is inside a verified scope."""

    try:
        verified = _require_verified(scope, "scope")
        if not isinstance(budget_state, ScopeBudgetState):
            raise SignedScopeError("budget_state must be a ScopeBudgetState")
        budget_state.validate()
        current = _clock(at)
        document = verified.to_dict()
        _validate_active(document, current)
        origin, host, port, path = _url_parts(url, "proposed request URL", endpoint=True)
        request_method = _ascii(method, "proposed request method", maximum=32).upper()
        if _METHOD.fullmatch(request_method) is None:
            raise SignedScopeError("proposed request method is invalid")
        requested_technique = _normalize_technique(technique_id, "proposed request technique_id")
        try:
            requested_impact = (
                impact_tier if isinstance(impact_tier, ActionTier) else ActionTier(impact_tier)
            )
        except (TypeError, ValueError) as exc:
            raise SignedScopeError("proposed request impact_tier is invalid") from exc
        budgets = document["budgets"]
        if budget_state.requests_completed >= budgets["max_requests"]:
            return ScopeDecision(False, "request budget exhausted")
        if budget_state.requests_active >= budgets["max_concurrency"]:
            return ScopeDecision(False, "concurrency budget exhausted")
        if budget_state.requests_in_current_minute >= budgets["max_requests_per_minute"]:
            return ScopeDecision(False, "rate budget exhausted")
        targets = document["targets"]
        if not _target_matches(targets, origin, host, port):
            return ScopeDecision(False, "network target or port is outside scope")
        if request_method not in targets["http_methods"]:
            return ScopeDecision(False, "HTTP method is outside scope")
        if not any(_path_matches(path, prefix) for prefix in targets["path_prefixes"]):
            return ScopeDecision(False, "path is outside scope")
        if requested_technique not in document["allowed_technique_ids"]:
            return ScopeDecision(False, "technique is outside scope")
        if requested_impact.rank > _IMPACT_RANK[document["impact_tier_ceiling"]]:
            return ScopeDecision(False, "impact tier exceeds the scope ceiling")
        if origin + path in document["protected_endpoints"]:
            return ScopeDecision(False, "endpoint is protected")
        for rule in document["exclusions"]:
            if _exclusion_matches(
                rule,
                origin=origin,
                host=host,
                port=port,
                method=request_method,
                path=path,
            ):
                return ScopeDecision(False, f"request matches exclusion {rule['exclusion_id']}")
        return ScopeDecision(True, "request is contained by the verified scope")
    except SignedScopeError as exc:
        return ScopeDecision(False, str(exc))


def request_is_in_scope(
    scope: VerifiedAssessmentScope,
    *,
    url: str,
    method: str,
    technique_id: str,
    impact_tier: ActionTier | str,
    budget_state: ScopeBudgetState,
    at: datetime | None = None,
) -> bool:
    """Return only the boolean portion of :func:`evaluate_request`."""

    return evaluate_request(
        scope,
        url=url,
        method=method,
        technique_id=technique_id,
        impact_tier=impact_tier,
        budget_state=budget_state,
        at=at,
    ).allowed


def scopes_overlap(left: VerifiedAssessmentScope, right: VerifiedAssessmentScope) -> bool:
    """Return whether two verified allow regions have a deterministic overlap."""

    left_doc = _require_verified(left, "left").to_dict()
    right_doc = _require_verified(right, "right").to_dict()
    left_window = left_doc["assessment_window"]
    right_window = right_doc["assessment_window"]
    if not (
        _parse_timestamp(left_window["starts_at"]) < _parse_timestamp(right_window["ends_at"])
        and _parse_timestamp(right_window["starts_at"]) < _parse_timestamp(left_window["ends_at"])
    ):
        return False
    if not set(left_doc["allowed_technique_ids"]) & set(right_doc["allowed_technique_ids"]):
        return False
    left_targets = left_doc["targets"]
    right_targets = right_doc["targets"]
    if not set(left_targets["http_methods"]) & set(right_targets["http_methods"]):
        return False
    if not any(
        _paths_overlap(left_path, right_path)
        for left_path in left_targets["path_prefixes"]
        for right_path in right_targets["path_prefixes"]
    ):
        return False
    return any(
        bool(left_ports & right_ports)
        and _selectors_overlap(left_kind, left_value, right_kind, right_value)
        for left_kind, left_value, left_ports in _target_atoms(left_targets)
        for right_kind, right_value, right_ports in _target_atoms(right_targets)
    )


def _content_contains(container: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
    if (
        candidate["issuer"] != container["issuer"]
        or candidate["key_id"] != container["key_id"]
        or candidate["sequence_number"] < container["sequence_number"]
    ):
        return False
    outer_window = container["assessment_window"]
    inner_window = candidate["assessment_window"]
    if not (
        _parse_timestamp(container["issued_at"]) <= _parse_timestamp(candidate["issued_at"])
        and _parse_timestamp(outer_window["starts_at"])
        <= _parse_timestamp(inner_window["starts_at"])
        and _parse_timestamp(inner_window["ends_at"]) <= _parse_timestamp(outer_window["ends_at"])
        and _parse_timestamp(candidate["expires_at"]) <= _parse_timestamp(container["expires_at"])
    ):
        return False
    outer_targets = container["targets"]
    inner_targets = candidate["targets"]
    if not set(inner_targets["http_methods"]) <= set(outer_targets["http_methods"]):
        return False
    if not all(
        any(_path_matches(path, prefix) for prefix in outer_targets["path_prefixes"])
        for path in inner_targets["path_prefixes"]
    ):
        return False
    outer_atoms = _target_atoms(outer_targets)
    for inner_kind, inner_value, inner_ports in _target_atoms(inner_targets):
        for port in inner_ports:
            if not any(
                port in outer_ports
                and _selector_contains(outer_kind, outer_value, inner_kind, inner_value)
                for outer_kind, outer_value, outer_ports in outer_atoms
            ):
                return False
    if not set(candidate["allowed_technique_ids"]) <= set(container["allowed_technique_ids"]):
        return False
    if (
        _IMPACT_RANK[candidate["impact_tier_ceiling"]]
        > _IMPACT_RANK[container["impact_tier_ceiling"]]
    ):
        return False
    if any(
        candidate["budgets"][field] > container["budgets"][field]
        for field in ("max_requests", "max_concurrency", "max_requests_per_minute")
    ):
        return False
    for endpoint in container["protected_endpoints"]:
        origin, host, port, path = _url_parts(endpoint, "protected endpoint", endpoint=True)
        inside_candidate = _target_matches(inner_targets, origin, host, port) and any(
            _path_matches(path, prefix) for prefix in inner_targets["path_prefixes"]
        )
        if inside_candidate and endpoint not in candidate["protected_endpoints"]:
            return False
    outer_exclusions = [
        {key: value for key, value in item.items() if key != "exclusion_id"}
        for item in container["exclusions"]
    ]
    inner_exclusions = [
        {key: value for key, value in item.items() if key != "exclusion_id"}
        for item in candidate["exclusions"]
    ]
    relevant_outer_exclusions = [
        item for item in outer_exclusions if _rule_intersects_targets(item, inner_targets)
    ]
    if any(item not in inner_exclusions for item in relevant_outer_exclusions):
        return False
    classification = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
    collection = {"metadata_only": 0, "minimized_content": 1, "authorized_content": 2}
    outer_data = container["data_handling"]
    inner_data = candidate["data_handling"]
    if classification[inner_data["classification"]] > classification[outer_data["classification"]]:
        return False
    if collection[inner_data["collection"]] > collection[outer_data["collection"]]:
        return False
    if inner_data["retention_days"] > outer_data["retention_days"]:
        return False
    if outer_data["redaction_required"] and not inner_data["redaction_required"]:
        return False
    if inner_data["storage"] != "none" and inner_data["storage"] != outer_data["storage"]:
        return False
    return candidate["emergency_stop_contact_id"] == container["emergency_stop_contact_id"]


def scope_contains_scope(
    container: VerifiedAssessmentScope,
    candidate: VerifiedAssessmentScope,
) -> bool:
    """Return whether candidate cannot exceed container's verified authority."""

    return _content_contains(
        _require_verified(container, "container").to_dict(),
        _require_verified(candidate, "candidate").to_dict(),
    )


__all__ = [
    "MAX_CONCURRENCY",
    "MAX_REQUESTS",
    "MAX_REQUESTS_PER_MINUTE",
    "MAX_SCOPE_LIFETIME_SECONDS",
    "SCHEMA_VERSION",
    "SIGNING_DOMAIN",
    "SCOPE_KIND",
    "ScopeBudgetState",
    "ScopeDecision",
    "SignedAssessmentScope",
    "SignedScopeError",
    "VerifiedAssessmentScope",
    "canonical_json",
    "canonical_sha256",
    "compile_signed_scope",
    "evaluate_request",
    "request_is_in_scope",
    "scope_contains_scope",
    "scopes_overlap",
    "verify_signed_scope",
]
