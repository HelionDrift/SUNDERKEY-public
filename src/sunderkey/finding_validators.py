"""Deterministic offline finding validation over captured evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from .errors import QualificationError

SCHEMA_VERSION = 1
RESULT_DOMAIN = "sunderkey.finding-validation-result.v1"
EVIDENCE_DOMAIN = "sunderkey.finding-validation-evidence.v1"
DESCRIPTOR_DOMAIN = "sunderkey.finding-validator-descriptor.v1"
REGISTRY_DOMAIN = "sunderkey.finding-validator-registry.v1"
INPUT_DOMAIN = "sunderkey.finding-validation-input.v1"
OPAQUE_ID_DOMAIN = "sunderkey.finding-validation-opaque-id.v1"

HARD_MAX_EVIDENCE_RECORDS = 64
HARD_MAX_EVIDENCE_BYTES = 1_048_576
HARD_MAX_TOTAL_EVIDENCE_BYTES = 4_194_304
HARD_MAX_HEADERS = 128
HARD_MAX_HEADER_VALUE_LENGTH = 8_192
HARD_MAX_MARKERS = 32
HARD_MAX_MARKER_LENGTH = 128
HARD_MAX_OPTIONS_ITEMS = 256
HARD_MAX_OPTIONS_DEPTH = 8
HARD_MAX_OUTPUT_BYTES = 131_072

SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VALIDATOR_ID_PATTERN = re.compile(r"validator\.[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
MARKER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}\Z")
RESULT_ID_PATTERN = re.compile(r"FVR-[0-9A-F]{32}\Z")
HEADER_NAME_PATTERN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
ABSOLUTE_HTTP_URL_PATTERN = re.compile(
    r"(?i)(https?)://(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::([0-9]{1,5}))?(?:[/?#]|\Z)"
)

STATES = frozenset({"verified", "negative", "hypothesis", "inconclusive", "abstained"})
IMPACT_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})
ROLES = frozenset({"request", "response", "control", "artifact", "restoration"})
SENSITIVE_METADATA_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "cookie",
        "credential",
        "password",
        "private_key",
        "secret",
        "set_cookie",
        "token",
    }
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"),
)


class FindingValidationError(QualificationError):
    """Raised when evidence or a finding validation result fails closed."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(domain: str, label: str, value: Any) -> str:
    document = _canonical_json({"domain": domain, label: value}).encode("utf-8")
    return f"sha256:{hashlib.sha256(document).hexdigest()}"


def _bytes_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise FindingValidationError(f"{label} must be a safe identifier")
    if _contains_secret_text(value):
        raise FindingValidationError(f"{label} must not contain secret material")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or CODE_PATTERN.fullmatch(value) is None:
        raise FindingValidationError(f"{label} must be a reason code")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise FindingValidationError(f"{label} must be a SHA-256 content address")
    return value


def _safe_marker(value: Any, label: str) -> str:
    if not isinstance(value, str) or MARKER_PATTERN.fullmatch(value) is None:
        raise FindingValidationError(f"{label} must be an inert opaque identifier")
    if len(value) > HARD_MAX_MARKER_LENGTH:
        raise FindingValidationError(f"{label} exceeds the marker limit")
    return value


def _contains_secret_text(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS)


def _copy_safe_value(
    value: Any,
    label: str,
    *,
    depth: int = 0,
    counter: list[int] | None = None,
    output: bool = False,
) -> Any:
    if counter is None:
        counter = [0]
    if depth > HARD_MAX_OPTIONS_DEPTH:
        raise FindingValidationError(f"{label} exceeds the nesting limit")
    counter[0] += 1
    if counter[0] > HARD_MAX_OPTIONS_ITEMS:
        raise FindingValidationError(f"{label} exceeds the item limit")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise FindingValidationError(f"{label} contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > HARD_MAX_HEADER_VALUE_LENGTH or any(
            ord(character) < 32 and character not in "\t" for character in value
        ):
            raise FindingValidationError(f"{label} contains unsafe text")
        if output and _contains_secret_text(value):
            raise FindingValidationError(f"{label} contains secret-like text")
        return value
    if isinstance(value, Mapping):
        copied: dict[str, Any] = {}
        for raw_key, child in value.items():
            if not isinstance(raw_key, str) or CODE_PATTERN.fullmatch(raw_key) is None:
                raise FindingValidationError(f"{label} has an unsafe key")
            if raw_key.lower() in SENSITIVE_METADATA_KEYS:
                raise FindingValidationError(f"{label} contains a sensitive field")
            copied[raw_key] = _copy_safe_value(
                child,
                f"{label}.{raw_key}",
                depth=depth + 1,
                counter=counter,
                output=output,
            )
        return copied
    if isinstance(value, (list, tuple)):
        return [
            _copy_safe_value(
                child,
                f"{label} item",
                depth=depth + 1,
                counter=counter,
                output=output,
            )
            for child in value
        ]
    raise FindingValidationError(f"{label} contains an unsupported value")


def _freeze_safe_value(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_safe_value(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_safe_value(child) for child in value)
    return value


def _header_pairs(value: Any) -> tuple[tuple[str, str], ...]:
    if isinstance(value, Mapping):
        items: Iterable[tuple[Any, Any]] = value.items()
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = value
    else:
        raise FindingValidationError("evidence headers must be a mapping or sequence")
    normalized: list[tuple[str, str]] = []
    for item in items:
        if not isinstance(item, Sequence) or isinstance(item, (str, bytes)) or len(item) != 2:
            raise FindingValidationError("evidence header entry is invalid")
        name, header_value = item
        if not isinstance(name, str) or HEADER_NAME_PATTERN.fullmatch(name) is None:
            raise FindingValidationError("evidence header name is invalid")
        if not isinstance(header_value, str) or len(header_value) > HARD_MAX_HEADER_VALUE_LENGTH:
            raise FindingValidationError("evidence header value is invalid")
        if "\r" in header_value or "\n" in header_value or "\x00" in header_value:
            raise FindingValidationError("evidence header value contains control characters")
        normalized.append((name.lower(), header_value))
        if len(normalized) > HARD_MAX_HEADERS:
            raise FindingValidationError("evidence exceeds the header count limit")
    return tuple(sorted(normalized, key=lambda item: (item[0], item[1])))


@dataclass(frozen=True)
class FindingValidationLimits:
    """Configurable ceilings that may only reduce the hard limits."""

    max_evidence_records: int = HARD_MAX_EVIDENCE_RECORDS
    max_evidence_bytes: int = HARD_MAX_EVIDENCE_BYTES
    max_total_evidence_bytes: int = HARD_MAX_TOTAL_EVIDENCE_BYTES
    max_headers: int = HARD_MAX_HEADERS
    max_markers: int = HARD_MAX_MARKERS

    def __post_init__(self) -> None:
        ceilings = {
            "max_evidence_records": HARD_MAX_EVIDENCE_RECORDS,
            "max_evidence_bytes": HARD_MAX_EVIDENCE_BYTES,
            "max_total_evidence_bytes": HARD_MAX_TOTAL_EVIDENCE_BYTES,
            "max_headers": HARD_MAX_HEADERS,
            "max_markers": HARD_MAX_MARKERS,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= ceiling:
                raise FindingValidationError(f"{name} must be between 1 and {ceiling}")


@dataclass(frozen=True)
class EvidenceRecord:
    """One immutable, content-addressed request, response, or restoration artifact."""

    evidence_id: str
    content: bytes
    content_sha256: str = ""
    media_type: str = "application/octet-stream"
    role: str = "response"
    status_code: int | None = None
    headers: tuple[tuple[str, str], ...] | Mapping[str, str] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)
    evidence_sha256: str = ""

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence ID")
        if not isinstance(self.content, bytes):
            raise FindingValidationError("evidence content must be bytes")
        if len(self.content) > HARD_MAX_EVIDENCE_BYTES:
            raise FindingValidationError("evidence exceeds the hard byte limit")
        actual = _bytes_digest(self.content)
        if self.content_sha256 and self.content_sha256 != actual:
            raise FindingValidationError("evidence content hash does not match bytes")
        if not isinstance(self.media_type, str) or not self.media_type.isascii():
            raise FindingValidationError("evidence media type must be ASCII text")
        if len(self.media_type) > 128 or "/" not in self.media_type:
            raise FindingValidationError("evidence media type is invalid")
        if self.role not in ROLES:
            raise FindingValidationError("evidence role is invalid")
        if self.status_code is not None and (
            not isinstance(self.status_code, int)
            or isinstance(self.status_code, bool)
            or not 100 <= self.status_code <= 599
        ):
            raise FindingValidationError("evidence status code is invalid")
        normalized_headers = _header_pairs(self.headers)
        copied_attributes = _copy_safe_value(self.attributes, "evidence attributes")
        record_body = {
            "evidence_id": self.evidence_id,
            "content_sha256": actual,
            "media_type": self.media_type,
            "role": self.role,
            "status_code": self.status_code,
            "headers": [
                {
                    "name": name,
                    "value_sha256": _bytes_digest(value.encode("utf-8")),
                }
                for name, value in normalized_headers
            ],
            "attributes": copied_attributes,
        }
        record_digest = _digest(EVIDENCE_DOMAIN, "evidence", record_body)
        if self.evidence_sha256 and self.evidence_sha256 != record_digest:
            raise FindingValidationError("evidence record hash does not match typed content")
        object.__setattr__(self, "content_sha256", actual)
        object.__setattr__(self, "headers", normalized_headers)
        object.__setattr__(self, "attributes", _freeze_safe_value(copied_attributes))
        object.__setattr__(self, "evidence_sha256", record_digest)

    @classmethod
    def from_bytes(
        cls,
        evidence_id: str,
        content: bytes,
        *,
        content_sha256: str | None = None,
        evidence_sha256: str | None = None,
        media_type: str = "application/octet-stream",
        role: str = "response",
        status_code: int | None = None,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] = (),
        attributes: Mapping[str, Any] | None = None,
    ) -> EvidenceRecord:
        return cls(
            evidence_id=evidence_id,
            content=content,
            content_sha256=content_sha256 or "",
            media_type=media_type,
            role=role,
            status_code=status_code,
            headers=headers,
            attributes=attributes or {},
            evidence_sha256=evidence_sha256 or "",
        )

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceRecord:
        required = {
            "evidence_id",
            "content",
            "content_sha256",
            "media_type",
            "role",
            "status_code",
            "headers",
            "attributes",
        }
        if (
            not isinstance(raw, Mapping)
            or not required <= set(raw)
            or set(raw) - required not in (set(), {"evidence_sha256"})
        ):
            raise FindingValidationError("evidence record fields are invalid")
        content = raw["content"]
        if not isinstance(content, bytes):
            raise FindingValidationError("evidence dictionary content must be bytes")
        return cls(
            evidence_id=raw["evidence_id"],
            content=content,
            content_sha256=raw["content_sha256"],
            media_type=raw["media_type"],
            role=raw["role"],
            status_code=raw["status_code"],
            headers=raw["headers"],
            attributes=raw["attributes"],
            evidence_sha256=raw.get("evidence_sha256", ""),
        )

    def header_values(self, name: str) -> tuple[str, ...]:
        lowered = name.lower()
        return tuple(value for header_name, value in self.headers if header_name == lowered)

    def manifest(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "content_sha256": self.content_sha256,
            "evidence_sha256": self.evidence_sha256,
            "media_type": self.media_type,
            "role": self.role,
            "status_code": self.status_code,
            "size_bytes": len(self.content),
        }


CapturedEvidence = EvidenceRecord
HttpEvidenceRecord = EvidenceRecord


def _coerce_records(
    values: Iterable[EvidenceRecord | bytes],
    label: str,
) -> tuple[EvidenceRecord, ...]:
    if isinstance(values, (bytes, bytearray, str)):
        values = (values,)  # type: ignore[assignment]
    records: list[EvidenceRecord] = []
    for index, value in enumerate(values):
        if isinstance(value, bytes):
            value = EvidenceRecord.from_bytes(f"{label}-{index + 1}", value)
        if not isinstance(value, EvidenceRecord):
            raise FindingValidationError(f"{label} must contain bytes or EvidenceRecord values")
        records.append(value)
    return tuple(records)


@dataclass(frozen=True)
class FindingValidationRequest:
    """Pure input to one exact validator version."""

    scope_id: str
    technique_id: str
    validator_id: str
    validator_version: str
    evidence: tuple[EvidenceRecord | bytes, ...]
    finding_impact: str = "medium"
    markers: tuple[str, ...] = ()
    canary_ids: tuple[str, ...] = ()
    options: Mapping[str, Any] = field(default_factory=dict)
    expected_evidence_hashes: tuple[str, ...] = ()
    restoration_evidence: tuple[EvidenceRecord | bytes, ...] = ()
    expected_restoration_hashes: tuple[str, ...] = ()
    restoration_required: bool = False
    registry_sha256: str | None = None
    limits: FindingValidationLimits = field(default_factory=FindingValidationLimits)
    input_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _identifier(self.scope_id, "scope ID")
        _identifier(self.technique_id, "technique ID")
        if (
            not isinstance(self.validator_id, str)
            or VALIDATOR_ID_PATTERN.fullmatch(self.validator_id) is None
        ):
            raise FindingValidationError("validator ID is invalid")
        if (
            not isinstance(self.validator_version, str)
            or VERSION_PATTERN.fullmatch(self.validator_version) is None
        ):
            raise FindingValidationError("validator version is invalid")
        if self.finding_impact not in IMPACT_LEVELS:
            raise FindingValidationError("finding impact is invalid")
        if not isinstance(self.limits, FindingValidationLimits):
            raise FindingValidationError("validation limits are invalid")
        records = _coerce_records(self.evidence, "evidence")
        restoration = _coerce_records(self.restoration_evidence, "restoration")
        if not records:
            raise FindingValidationError("at least one evidence record is required")
        if len(records) + len(restoration) > self.limits.max_evidence_records:
            raise FindingValidationError("evidence exceeds the record count limit")
        all_records = (*records, *restoration)
        record_ids = [item.evidence_id for item in all_records]
        record_hashes = [item.evidence_sha256 for item in all_records]
        if len(record_ids) != len(set(record_ids)):
            raise FindingValidationError("evidence IDs must be unique")
        if len(record_hashes) != len(set(record_hashes)):
            raise FindingValidationError("evidence records must be unique")
        if any(
            len(item.content) > self.limits.max_evidence_bytes for item in (*records, *restoration)
        ):
            raise FindingValidationError("evidence exceeds the configured record byte limit")
        total = sum(len(item.content) for item in (*records, *restoration))
        if total > self.limits.max_total_evidence_bytes:
            raise FindingValidationError("evidence exceeds the configured total byte limit")
        if any(len(item.headers) > self.limits.max_headers for item in (*records, *restoration)):
            raise FindingValidationError("evidence exceeds the configured header limit")
        if (
            len(self.markers) > self.limits.max_markers
            or len(self.canary_ids) > self.limits.max_markers
        ):
            raise FindingValidationError("opaque identifiers exceed the configured marker limit")
        markers = tuple(sorted(_safe_marker(value, "marker") for value in self.markers))
        canary_ids = tuple(sorted(_safe_marker(value, "canary ID") for value in self.canary_ids))
        if len(markers) != len(set(markers)) or len(canary_ids) != len(set(canary_ids)):
            raise FindingValidationError("opaque identifiers must be unique")
        options = _copy_safe_value(self.options, "validator options")
        expected = tuple(
            _sha256(value, "expected evidence hash") for value in self.expected_evidence_hashes
        )
        expected_restoration = tuple(
            _sha256(value, "expected restoration hash")
            for value in self.expected_restoration_hashes
        )
        actual = tuple(sorted(item.evidence_sha256 for item in records))
        actual_restoration = tuple(sorted(item.evidence_sha256 for item in restoration))
        if expected and tuple(sorted(expected)) != actual:
            raise FindingValidationError("expected evidence hashes do not match supplied evidence")
        if expected_restoration and tuple(sorted(expected_restoration)) != actual_restoration:
            raise FindingValidationError(
                "expected restoration hashes do not match supplied evidence"
            )
        if any(item.role != "restoration" for item in restoration):
            raise FindingValidationError("restoration evidence must use the restoration role")
        if self.registry_sha256 is not None:
            _sha256(self.registry_sha256, "registry hash")
        if not isinstance(self.restoration_required, bool):
            raise FindingValidationError("restoration_required must be boolean")
        input_body = {
            "scope_id": self.scope_id,
            "technique_id": self.technique_id,
            "validator_id": self.validator_id,
            "validator_version": self.validator_version,
            "finding_impact": self.finding_impact,
            "evidence_hashes": list(actual),
            "restoration_evidence_hashes": list(actual_restoration),
            "marker_hashes": [_digest(OPAQUE_ID_DOMAIN, "marker", marker) for marker in markers],
            "canary_id_hashes": [
                _digest(OPAQUE_ID_DOMAIN, "canary_id", canary_id) for canary_id in canary_ids
            ],
            "options_sha256": _digest(INPUT_DOMAIN, "options", options),
            "restoration_required": self.restoration_required,
            "limits": {
                "max_evidence_records": self.limits.max_evidence_records,
                "max_evidence_bytes": self.limits.max_evidence_bytes,
                "max_total_evidence_bytes": self.limits.max_total_evidence_bytes,
                "max_headers": self.limits.max_headers,
                "max_markers": self.limits.max_markers,
            },
        }
        object.__setattr__(self, "evidence", records)
        object.__setattr__(self, "restoration_evidence", restoration)
        object.__setattr__(self, "markers", markers)
        object.__setattr__(self, "canary_ids", canary_ids)
        object.__setattr__(self, "options", _freeze_safe_value(options))
        object.__setattr__(self, "expected_evidence_hashes", expected)
        object.__setattr__(self, "expected_restoration_hashes", expected_restoration)
        object.__setattr__(self, "input_sha256", _digest(INPUT_DOMAIN, "input", input_body))


ValidationContext = FindingValidationRequest


@dataclass(frozen=True)
class ValidatorDescriptor:
    validator_id: str
    version: str
    evidence_kind: str
    required_signal_codes: tuple[str, ...]
    minimum_corroboration: int
    descriptor_sha256: str = ""

    def __post_init__(self) -> None:
        if VALIDATOR_ID_PATTERN.fullmatch(self.validator_id) is None:
            raise FindingValidationError("validator descriptor ID is invalid")
        if VERSION_PATTERN.fullmatch(self.version) is None:
            raise FindingValidationError("validator descriptor version is invalid")
        _code(self.evidence_kind, "validator evidence kind")
        signals = tuple(_code(item, "validator signal code") for item in self.required_signal_codes)
        if len(signals) < 2 or len(signals) != len(set(signals)):
            raise FindingValidationError("validator corroboration rules are incomplete")
        if not isinstance(
            self.minimum_corroboration, int
        ) or not 2 <= self.minimum_corroboration <= len(signals):
            raise FindingValidationError("validator minimum corroboration is invalid")
        body = {
            "validator_id": self.validator_id,
            "version": self.version,
            "evidence_kind": self.evidence_kind,
            "required_signal_codes": list(signals),
            "minimum_corroboration": self.minimum_corroboration,
        }
        digest = _digest(DESCRIPTOR_DOMAIN, "descriptor", body)
        if self.descriptor_sha256 and self.descriptor_sha256 != digest:
            raise FindingValidationError("validator descriptor hash does not match content")
        object.__setattr__(self, "required_signal_codes", signals)
        object.__setattr__(self, "descriptor_sha256", digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "validator_id": self.validator_id,
            "version": self.version,
            "evidence_kind": self.evidence_kind,
            "required_signal_codes": list(self.required_signal_codes),
            "minimum_corroboration": self.minimum_corroboration,
            "descriptor_sha256": self.descriptor_sha256,
        }


@dataclass(frozen=True)
class _Assessment:
    state: str
    confidence: float
    reason_codes: tuple[str, ...]
    observed_signals: tuple[str, ...]
    observations: tuple[Mapping[str, Any], ...]
    false_positive_checks: tuple[Mapping[str, Any], ...]


def _observation(
    code: str,
    evidence: Iterable[EvidenceRecord],
    **attributes: Any,
) -> dict[str, Any]:
    return {
        "code": _code(code, "observation code"),
        "evidence_hashes": sorted({item.evidence_sha256 for item in evidence}),
        "attributes": _copy_safe_value(attributes, "observation attributes", output=True),
    }


def _check(code: str, passed: bool, evidence: Iterable[EvidenceRecord] = ()) -> dict[str, Any]:
    return {
        "code": _code(code, "false-positive check code"),
        "passed": bool(passed),
        "evidence_hashes": sorted({item.evidence_sha256 for item in evidence}),
    }


def _response_statuses(records: Iterable[EvidenceRecord]) -> tuple[int, ...]:
    return tuple(item.status_code for item in records if item.status_code is not None)


def _status_success(status: int | None) -> bool:
    return status is not None and 200 <= status <= 299


def _attribute(record: EvidenceRecord, name: str, expected: type | tuple[type, ...]) -> Any:
    value = record.attributes.get(name)
    if isinstance(value, bool) and expected is int:
        return None
    return value if isinstance(value, expected) else None


def _safe_body_lower(record: EvidenceRecord) -> bytes:
    return record.content[:HARD_MAX_EVIDENCE_BYTES].lower()


def _html_context(content: bytes, marker: bytes) -> str:
    lower = content.lower()
    position = content.find(marker)
    if position < 0:
        return "absent"
    script_start = lower.rfind(b"<script", 0, position)
    script_end = lower.rfind(b"</script", 0, position)
    if script_start > script_end:
        return "script_data"
    tag_start = lower.rfind(b"<", 0, position)
    tag_end = lower.rfind(b">", 0, position)
    if tag_start > tag_end:
        prefix = lower[tag_start:position]
        if re.search(rb"\bon[a-z0-9_-]*\s*=\s*['\"]?[^'\"]*$", prefix):
            return "event_handler_attribute"
        return "html_attribute"
    return "html_text"


def _origin(value: str) -> tuple[str, str, int] | None:
    match = ABSOLUTE_HTTP_URL_PATTERN.match(value)
    if match is None:
        return None
    scheme = match.group(1).lower()
    host = match.group(2).lower().rstrip(".")
    if "@" in host or ".." in host or not host:
        return None
    port_text = match.group(3)
    port = int(port_text) if port_text else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        return None
    return scheme, host, port


def _destination_origin(source: tuple[str, str, int], location: str) -> tuple[str, str, int] | None:
    if location.startswith("//"):
        return _origin(f"{source[0]}:{location}")
    if location.startswith("/") and not location.startswith("//"):
        return source
    if "://" not in location:
        if re.match(r"(?i)[a-z][a-z0-9+.-]*:", location):
            return None
        return source
    return _origin(location)


VALIDATOR_OPTION_KEYS = {
    "validator.web.authorization-differential": frozenset({"restored_object_id"}),
    "validator.web.input-reflection-context": frozenset({"restored_object_id"}),
    "validator.api.error-oracle-differential": frozenset({"restored_object_id"}),
    "validator.web.security-header-cookie-policy": frozenset(
        {"required_headers", "restored_object_id"}
    ),
    "validator.web.redirect-boundary": frozenset({"allowed_origins", "restored_object_id"}),
    "validator.web.canary-observation": frozenset({"restored_object_id"}),
}


def _validate_request_contract(
    request: FindingValidationRequest,
    descriptor: ValidatorDescriptor,
) -> None:
    allowed_options = VALIDATOR_OPTION_KEYS.get(descriptor.validator_id, frozenset())
    unknown = set(request.options) - allowed_options
    if unknown:
        raise FindingValidationError(
            f"validator options contain unsupported fields: {', '.join(sorted(unknown))}"
        )
    accepts_markers = descriptor.validator_id == "validator.web.input-reflection-context"
    accepts_canaries = descriptor.validator_id == "validator.web.canary-observation"
    if request.markers and not accepts_markers:
        raise FindingValidationError("this validator does not accept markers")
    if request.canary_ids and not accepts_canaries:
        raise FindingValidationError("this validator does not accept canary IDs")


class _BaseValidator:
    descriptor: ValidatorDescriptor

    def assess(self, request: FindingValidationRequest) -> _Assessment:
        raise NotImplementedError

    def validate(self, request: FindingValidationRequest) -> FindingValidationResult:
        _validate_request_contract(request, self.descriptor)
        registry_hash = _digest(
            REGISTRY_DOMAIN,
            "registry",
            {"validators": [self.descriptor.to_dict()]},
        )
        return _build_result(request, self.descriptor, registry_hash, self.assess(request))


@runtime_checkable
class FindingValidator(Protocol):
    """Protocol for deterministic validators with exact descriptors."""

    descriptor: ValidatorDescriptor

    def assess(self, request: FindingValidationRequest) -> _Assessment:
        """Assess already captured evidence without producing external effects."""


class AuthorizationDifferentialValidator(_BaseValidator):
    descriptor = ValidatorDescriptor(
        "validator.web.authorization-differential",
        "1.0.1",
        "authorization_differential",
        ("unauthorized_success", "authorized_control", "representation_match"),
        3,
    )

    def assess(self, request: FindingValidationRequest) -> _Assessment:
        responses = tuple(item for item in request.evidence if item.role in {"response", "control"})
        if len(responses) < 2 or any(item.status_code is None for item in responses):
            return _Assessment(
                "abstained",
                0.0,
                ("insufficient_typed_responses",),
                (),
                (),
                (_check("typed_status_available", False, responses),),
            )
        bindings = {
            (
                _attribute(item, "object_id", str),
                _attribute(item, "action", str),
            )
            for item in responses
        }
        same_binding = len(bindings) == 1 and None not in next(iter(bindings))
        authorized = tuple(
            item for item in responses if _attribute(item, "expected_access", bool) is True
        )
        unauthorized = tuple(
            item for item in responses if _attribute(item, "expected_access", bool) is False
        )
        principals = {
            value
            for item in responses
            if (value := _attribute(item, "principal_id", str)) is not None
        }
        principal_identities_present = all(
            (value := _attribute(item, "principal_id", str)) is not None
            and IDENTIFIER_PATTERN.fullmatch(value) is not None
            for item in responses
        )
        access_polarity_complete = len(authorized) + len(unauthorized) == len(responses)
        polarity_by_principal: dict[str, set[bool]] = {}
        for item in (*authorized, *unauthorized):
            principal = _attribute(item, "principal_id", str)
            if principal is not None:
                polarity_by_principal.setdefault(principal, set()).add(
                    item.attributes["expected_access"]
                )
        principal_access_consistent = all(
            len(polarities) == 1 for polarities in polarity_by_principal.values()
        )
        distinct_principals = len(principals) >= 2
        checks = (
            _check("same_object_action", same_binding, responses),
            _check("distinct_principals", distinct_principals, responses),
            _check("principal_identities_present", principal_identities_present, responses),
            _check("access_polarity_complete", access_polarity_complete, responses),
            _check("principal_access_consistent", principal_access_consistent, responses),
            _check("access_polarity_present", bool(authorized and unauthorized), responses),
        )
        if (
            not same_binding
            or not distinct_principals
            or not principal_identities_present
            or not access_polarity_complete
            or not principal_access_consistent
            or not authorized
            or not unauthorized
        ):
            return _Assessment(
                "abstained",
                0.0,
                ("comparison_binding_ambiguous",),
                (),
                (),
                checks,
            )
        authorized_success = tuple(item for item in authorized if _status_success(item.status_code))
        unauthorized_success = tuple(
            item for item in unauthorized if _status_success(item.status_code)
        )
        unauthorized_denied = tuple(
            item for item in unauthorized if item.status_code in {401, 403, 404}
        )
        matching = tuple(
            item
            for item in unauthorized_success
            if item.content
            and any(
                item.content_sha256 == control.content_sha256
                and item.attributes["principal_id"] != control.attributes["principal_id"]
                for control in authorized_success
            )
        )
        signals: list[str] = []
        if unauthorized_success:
            signals.append("unauthorized_success")
        if authorized_success:
            signals.append("authorized_control")
        if matching:
            signals.append("representation_match")
        observations = (
            _observation(
                "authorization_outcomes",
                responses,
                authorized_success_count=len(authorized_success),
                unauthorized_success_count=len(unauthorized_success),
                unauthorized_denial_count=len(unauthorized_denied),
                matching_representation_count=len(matching),
            ),
        )
        if matching and len(signals) == 3:
            return _Assessment(
                "verified",
                0.98,
                ("unauthorized_equivalent_access",),
                tuple(signals),
                observations,
                checks,
            )
        if unauthorized_denied and authorized_success and not unauthorized_success:
            return _Assessment(
                "negative",
                0.98,
                ("authorization_boundary_enforced",),
                ("authorized_control", "unauthorized_denial"),
                observations,
                checks,
            )
        if unauthorized_success and authorized_success:
            return _Assessment(
                "hypothesis",
                0.62,
                ("unauthorized_success_requires_corroboration",),
                tuple(signals),
                observations,
                checks,
            )
        return _Assessment(
            "inconclusive",
            0.25,
            ("authorization_outcome_ambiguous",),
            tuple(signals),
            observations,
            checks,
        )


class InputReflectionContextValidator(_BaseValidator):
    descriptor = ValidatorDescriptor(
        "validator.web.input-reflection-context",
        "1.0.0",
        "input_reflection_context",
        ("request_marker_bound", "response_reflection", "active_context", "control_absence"),
        4,
    )

    def assess(self, request: FindingValidationRequest) -> _Assessment:
        if not request.markers:
            return _Assessment(
                "abstained", 0.0, ("marker_required",), (), (), (_check("marker_inert", False),)
            )
        requests = tuple(item for item in request.evidence if item.role == "request")
        responses = tuple(item for item in request.evidence if item.role == "response")
        controls = tuple(item for item in request.evidence if item.role == "control")
        if not requests or not responses or any(item.status_code is None for item in responses):
            return _Assessment(
                "abstained",
                0.0,
                ("request_response_pair_required",),
                (),
                (),
                (_check("typed_request_response_present", False, request.evidence),),
            )
        request_transaction_ids = {
            value
            for item in requests
            if (value := _attribute(item, "transaction_id", str)) is not None
        }
        response_transaction_ids = {
            value
            for item in responses
            if (value := _attribute(item, "transaction_id", str)) is not None
        }
        if request_transaction_ids or response_transaction_ids:
            transaction_ids = request_transaction_ids & response_transaction_ids
            pair_bound = (
                bool(transaction_ids)
                and request_transaction_ids == transaction_ids
                and response_transaction_ids == transaction_ids
            )
            paired_requests = tuple(
                item
                for item in requests
                if _attribute(item, "transaction_id", str) in transaction_ids
            )
            paired_responses = tuple(
                item
                for item in responses
                if _attribute(item, "transaction_id", str) in transaction_ids
            )
        else:
            pair_bound = len(requests) == 1 and len(responses) == 1
            paired_requests = requests
            paired_responses = responses
        if not pair_bound:
            return _Assessment(
                "abstained",
                0.0,
                ("request_response_binding_ambiguous",),
                (),
                (),
                (_check("request_response_binding", False, (*requests, *responses)),),
            )
        bound_markers = [
            marker
            for marker in request.markers
            if any(marker.encode("ascii") in item.content for item in paired_requests)
        ]
        reflected: list[tuple[str, EvidenceRecord, str]] = []
        for marker in bound_markers:
            encoded = marker.encode("ascii")
            for response in paired_responses:
                if encoded not in response.content:
                    continue
                if response.media_type.split(";", 1)[0].strip().lower() == "text/html":
                    context = _html_context(response.content, encoded)
                elif "json" in response.media_type.lower():
                    context = "json_string"
                else:
                    context = "plain_text"
                reflected.append((marker, response, context))
        active = tuple(
            item
            for _, item, context in reflected
            if context in {"script_data", "event_handler_attribute"}
        )
        control_absence = bool(controls) and all(
            marker.encode("ascii") not in item.content
            for marker in bound_markers
            for item in controls
        )
        signals: list[str] = []
        if bound_markers:
            signals.append("request_marker_bound")
        if reflected:
            signals.append("response_reflection")
        if active:
            signals.append("active_context")
        if control_absence:
            signals.append("control_absence")
        contexts = sorted({context for _, _, context in reflected})
        relevant = tuple({item.content_sha256: item for _, item, _ in reflected}.values())
        observations = (
            _observation(
                "reflection_contexts",
                relevant,
                bound_marker_count=len(bound_markers),
                reflection_count=len(reflected),
                active_context_count=len(active),
                contexts=contexts,
            ),
        )
        checks = (
            _check("request_response_binding", True, (*paired_requests, *paired_responses)),
            _check("marker_originates_in_request", bool(bound_markers), paired_requests),
            _check("control_excludes_marker", control_absence, controls),
        )
        if active and control_absence and len(signals) >= 4:
            return _Assessment(
                "verified",
                0.96,
                ("inert_marker_reflected_in_active_context",),
                tuple(signals),
                observations,
                checks,
            )
        if not reflected and bound_markers:
            return _Assessment(
                "negative",
                0.94,
                ("inert_marker_not_reflected",),
                tuple(signals),
                observations,
                checks,
            )
        if reflected:
            return _Assessment(
                "hypothesis",
                0.58,
                ("reflection_requires_active_context_corroboration",),
                tuple(signals),
                observations,
                checks,
            )
        return _Assessment(
            "abstained",
            0.0,
            ("marker_not_bound_to_request",),
            tuple(signals),
            observations,
            checks,
        )


class ErrorOracleDifferentialValidator(_BaseValidator):
    descriptor = ValidatorDescriptor(
        "validator.api.error-oracle-differential",
        "1.0.0",
        "error_oracle_differential",
        ("baseline_control", "status_class_differential", "body_differential", "error_family"),
        4,
    )
    _ERROR_FAMILIES = {
        "exception_trace": (b"traceback", b"stack trace", b"exception in thread"),
        "database_diagnostic": (b"sqlstate", b"sql syntax", b"database error"),
        "runtime_location": (b" line ", b" at /", b" at c:\\"),
    }

    def assess(self, request: FindingValidationRequest) -> _Assessment:
        baseline = tuple(
            item
            for item in request.evidence
            if _attribute(item, "variant", str) in {"baseline", "control"}
        )
        probes = tuple(
            item for item in request.evidence if _attribute(item, "variant", str) == "probe"
        )
        if not baseline or not probes:
            return _Assessment(
                "abstained",
                0.0,
                ("baseline_and_probe_required",),
                (),
                (),
                (_check("baseline_probe_present", False, request.evidence),),
            )
        if any(item.status_code is None for item in (*baseline, *probes)):
            return _Assessment(
                "inconclusive",
                0.1,
                ("ambiguous_status",),
                ("baseline_control",),
                (),
                (_check("typed_status_available", False, (*baseline, *probes)),),
            )
        comparison_ids = {
            value
            for item in (*baseline, *probes)
            if (value := _attribute(item, "comparison_id", str)) is not None
        }
        comparable = len(comparison_ids) == 1
        if not comparable:
            return _Assessment(
                "abstained",
                0.0,
                ("comparison_binding_ambiguous",),
                (),
                (),
                (_check("same_comparison_id", False, (*baseline, *probes)),),
            )
        status_diff = any(
            (base.status_code or 0) < 400 <= (probe.status_code or 0)
            for base in baseline
            for probe in probes
        )
        body_diff = any(
            base.content_sha256 != probe.content_sha256 for base in baseline for probe in probes
        )
        families = sorted(
            family
            for family, needles in self._ERROR_FAMILIES.items()
            if any(any(needle in _safe_body_lower(item) for needle in needles) for item in probes)
            and not any(
                any(needle in _safe_body_lower(item) for needle in needles) for item in baseline
            )
        )
        signals = ["baseline_control"]
        if status_diff:
            signals.append("status_class_differential")
        if body_diff:
            signals.append("body_differential")
        if families:
            signals.append("error_family")
        observations = (
            _observation(
                "error_oracle_comparison",
                (*baseline, *probes),
                baseline_count=len(baseline),
                probe_count=len(probes),
                status_class_changed=status_diff,
                body_changed=body_diff,
                error_families=families,
            ),
        )
        checks = (
            _check("same_comparison_id", True, (*baseline, *probes)),
            _check("diagnostic_absent_from_baseline", bool(families), baseline),
        )
        if status_diff and body_diff and families:
            return _Assessment(
                "verified",
                0.96,
                ("differential_error_oracle_observed",),
                tuple(signals),
                observations,
                checks,
            )
        if not status_diff and not body_diff and not families:
            return _Assessment(
                "negative",
                0.95,
                ("no_error_oracle_differential",),
                tuple(signals),
                observations,
                checks,
            )
        return _Assessment(
            "hypothesis",
            0.55,
            ("partial_error_differential",),
            tuple(signals),
            observations,
            checks,
        )


class SecurityHeaderCookiePolicyValidator(_BaseValidator):
    descriptor = ValidatorDescriptor(
        "validator.web.security-header-cookie-policy",
        "1.0.0",
        "security_header_cookie_policy",
        ("missing_security_headers", "insecure_cookie_policy", "successful_response"),
        3,
    )
    DEFAULT_REQUIRED_HEADERS = (
        "content-security-policy",
        "referrer-policy",
        "strict-transport-security",
        "x-content-type-options",
    )

    def assess(self, request: FindingValidationRequest) -> _Assessment:
        responses = tuple(item for item in request.evidence if item.role == "response")
        if not responses or any(item.status_code is None for item in responses):
            return _Assessment(
                "inconclusive",
                0.0,
                ("ambiguous_status",),
                (),
                (),
                (_check("typed_response_status", False, responses),),
            )
        configured = request.options.get("required_headers", self.DEFAULT_REQUIRED_HEADERS)
        if (
            not isinstance(configured, Sequence)
            or isinstance(configured, (str, bytes))
            or not configured
        ):
            raise FindingValidationError("required_headers must be a nonempty list")
        required: list[str] = []
        for value in configured:
            if not isinstance(value, str) or HEADER_NAME_PATTERN.fullmatch(value) is None:
                raise FindingValidationError("required_headers contains an invalid name")
            lowered = value.lower()
            if lowered in {"authorization", "cookie", "set-cookie"}:
                raise FindingValidationError("required_headers cannot name credential headers")
            required.append(lowered)
        if len(required) != len(set(required)):
            raise FindingValidationError("required_headers contains duplicates")
        successful = tuple(item for item in responses if _status_success(item.status_code))
        if not successful:
            return _Assessment(
                "abstained",
                0.0,
                ("successful_response_required",),
                (),
                (),
                (_check("successful_response", False, responses),),
            )
        ambiguous_names = sorted(
            name
            for name in required
            if any(len(set(item.header_values(name))) > 1 for item in successful)
        )
        if ambiguous_names:
            return _Assessment(
                "inconclusive",
                0.1,
                ("ambiguous_policy_headers",),
                ("successful_response",),
                (
                    _observation(
                        "ambiguous_header_count",
                        successful,
                        count=len(ambiguous_names),
                    ),
                ),
                (_check("unambiguous_policy_headers", False, successful),),
            )
        missing = sorted(
            {
                name
                for item in successful
                for name in required
                if not item.header_values(name) or not item.header_values(name)[0].strip()
            }
        )
        cookie_counts = {"missing_httponly": 0, "missing_samesite": 0, "missing_secure": 0}
        cookie_header_count = 0
        for item in successful:
            for header in item.header_values("set-cookie"):
                cookie_header_count += 1
                attributes = {
                    part.strip().split("=", 1)[0].lower() for part in header.split(";")[1:]
                }
                if "secure" not in attributes:
                    cookie_counts["missing_secure"] += 1
                if "httponly" not in attributes:
                    cookie_counts["missing_httponly"] += 1
                if "samesite" not in attributes:
                    cookie_counts["missing_samesite"] += 1
        insecure_cookie = any(cookie_counts.values())
        signals = ["successful_response"]
        if missing:
            signals.append("missing_security_headers")
        if insecure_cookie:
            signals.append("insecure_cookie_policy")
        observations = (
            _observation(
                "response_policy_summary",
                successful,
                missing_headers=missing,
                cookie_header_count=cookie_header_count,
                cookie_issue_counts=cookie_counts,
            ),
        )
        checks = (
            _check("unambiguous_policy_headers", True, successful),
            _check("credential_values_not_emitted", True),
        )
        if missing and insecure_cookie:
            return _Assessment(
                "verified",
                0.95,
                ("multiple_response_policy_failures",),
                tuple(signals),
                observations,
                checks,
            )
        if not missing and not insecure_cookie:
            return _Assessment(
                "negative",
                0.97,
                ("response_policy_satisfied",),
                tuple(signals),
                observations,
                checks,
            )
        return _Assessment(
            "hypothesis",
            0.6,
            ("single_response_policy_signal",),
            tuple(signals),
            observations,
            checks,
        )


class RedirectBoundaryValidator(_BaseValidator):
    descriptor = ValidatorDescriptor(
        "validator.web.redirect-boundary",
        "1.0.0",
        "redirect_boundary",
        ("redirect_status", "boundary_crossing", "destination_not_allowed"),
        3,
    )

    def assess(self, request: FindingValidationRequest) -> _Assessment:
        responses = tuple(item for item in request.evidence if item.role == "response")
        if not responses or any(item.status_code is None for item in responses):
            return _Assessment(
                "inconclusive",
                0.0,
                ("ambiguous_status",),
                (),
                (),
                (_check("typed_redirect_status", False, responses),),
            )
        allowed_raw = request.options.get("allowed_origins", [])
        if not isinstance(allowed_raw, Sequence) or isinstance(allowed_raw, (str, bytes)):
            raise FindingValidationError("allowed_origins must be a list")
        allowed: set[tuple[str, str, int]] = set()
        for value in allowed_raw:
            if not isinstance(value, str) or (parsed := _origin(value)) is None:
                raise FindingValidationError("allowed_origins contains an invalid origin")
            allowed.add(parsed)
        redirects = tuple(
            item
            for item in responses
            if item.status_code is not None
            and 300 <= item.status_code <= 399
            and item.status_code != 304
        )
        if not redirects:
            return _Assessment(
                "negative",
                0.96,
                ("no_redirect_observed",),
                (),
                (_observation("redirect_summary", responses, redirect_count=0),),
                (_check("redirect_present", False, responses),),
            )
        crossings: list[tuple[EvidenceRecord, str]] = []
        ambiguous: list[EvidenceRecord] = []
        allowed_destinations = 0
        for item in redirects:
            locations = tuple(dict.fromkeys(item.header_values("location")))
            source_value = _attribute(item, "request_url", str)
            source = _origin(source_value) if source_value is not None else None
            if len(locations) != 1 or source is None:
                ambiguous.append(item)
                continue
            destination = _destination_origin(source, locations[0])
            if destination is None:
                ambiguous.append(item)
                continue
            if destination in allowed:
                allowed_destinations += 1
                continue
            if source[0] == "https" and destination[0] == "http":
                crossings.append((item, "scheme_downgrade"))
            elif source != destination:
                crossings.append((item, "cross_origin"))
        if ambiguous:
            return _Assessment(
                "inconclusive",
                0.15,
                ("redirect_location_ambiguous",),
                ("redirect_status",),
                (
                    _observation(
                        "redirect_summary",
                        redirects,
                        redirect_count=len(redirects),
                        ambiguous_count=len(ambiguous),
                    ),
                ),
                (_check("single_absolute_location", False, ambiguous),),
            )
        boundary_types = sorted({boundary for _, boundary in crossings})
        crossing_records = tuple(item for item, _ in crossings)
        observations = (
            _observation(
                "redirect_summary",
                redirects,
                redirect_count=len(redirects),
                crossing_count=len(crossings),
                allowed_destination_count=allowed_destinations,
                boundary_types=boundary_types,
            ),
        )
        checks = (
            _check("single_absolute_location", True, redirects),
            _check("destination_not_allowed", bool(crossings), crossing_records),
        )
        if crossings:
            return _Assessment(
                "verified",
                0.96,
                ("redirect_crosses_declared_boundary",),
                ("redirect_status", "boundary_crossing", "destination_not_allowed"),
                observations,
                checks,
            )
        return _Assessment(
            "negative",
            0.96,
            ("redirect_remains_within_boundary",),
            ("redirect_status",),
            observations,
            checks,
        )


class CanaryObservationValidator(_BaseValidator):
    descriptor = ValidatorDescriptor(
        "validator.web.canary-observation",
        "1.0.0",
        "canary_observation",
        ("exact_canary_match", "distinct_evidence", "independent_sources"),
        3,
    )

    def assess(self, request: FindingValidationRequest) -> _Assessment:
        if not request.canary_ids:
            return _Assessment(
                "abstained",
                0.0,
                ("canary_id_required",),
                (),
                (),
                (_check("caller_canary_supplied", False),),
            )
        matched: list[EvidenceRecord] = []
        matched_canary_count = 0
        for canary_id in request.canary_ids:
            encoded = canary_id.encode("ascii")
            current = [item for item in request.evidence if encoded in item.content]
            if current:
                matched_canary_count += 1
                matched.extend(current)
        unique_records = {item.evidence_sha256: item for item in matched}
        source_ids = {
            value
            for item in unique_records.values()
            if (value := _attribute(item, "source_id", str)) is not None
        }
        distinct_evidence = len(unique_records) >= 2
        independent_sources = len(source_ids) >= 2
        signals: list[str] = []
        if matched:
            signals.append("exact_canary_match")
        if distinct_evidence:
            signals.append("distinct_evidence")
        if independent_sources:
            signals.append("independent_sources")
        observations = (
            _observation(
                "canary_match_summary",
                unique_records.values(),
                supplied_canary_count=len(request.canary_ids),
                matched_canary_count=matched_canary_count,
                matching_evidence_count=len(unique_records),
                independent_source_count=len(source_ids),
            ),
        )
        checks = (
            _check("distinct_evidence", distinct_evidence, unique_records.values()),
            _check("independent_sources", independent_sources, unique_records.values()),
            _check("canary_grants_no_authority", True),
        )
        if matched and distinct_evidence and independent_sources:
            return _Assessment(
                "verified",
                0.97,
                ("canary_observed_with_independent_corroboration",),
                tuple(signals),
                observations,
                checks,
            )
        if not matched:
            return _Assessment(
                "negative",
                0.94,
                ("canary_not_observed",),
                tuple(signals),
                observations,
                checks,
            )
        return _Assessment(
            "hypothesis",
            0.55,
            ("canary_observation_requires_independent_corroboration",),
            tuple(signals),
            observations,
            checks,
        )


@dataclass(frozen=True)
class FindingValidationResult:
    schema_version: int
    result_id: str
    result_sha256: str
    registry_sha256: str
    input_sha256: str
    scope_id: str
    technique_id: str
    finding_impact: str
    validator_id: str
    validator_version: str
    validator_descriptor_sha256: str
    state: str
    confidence: float
    reason_codes: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    restoration_evidence_hashes: tuple[str, ...]
    observations: tuple[Mapping[str, Any], ...]
    false_positive_checks: tuple[Mapping[str, Any], ...]
    required_corroboration: int
    observed_signals: tuple[str, ...]
    corroboration_satisfied: bool
    restoration: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> FindingValidationResult:
        expected = {
            "schema_version",
            "result_id",
            "result_sha256",
            "registry_sha256",
            "input_sha256",
            "scope_id",
            "technique_id",
            "finding_impact",
            "validator",
            "state",
            "confidence",
            "reason_codes",
            "evidence_hashes",
            "restoration_evidence_hashes",
            "observations",
            "false_positive_checks",
            "corroboration",
            "restoration",
            "effects",
        }
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise FindingValidationError("finding validation result fields are invalid")
        validator = raw.get("validator")
        corroboration = raw.get("corroboration")
        effects = raw.get("effects")
        if not isinstance(validator, Mapping) or set(validator) != {
            "id",
            "version",
            "descriptor_sha256",
        }:
            raise FindingValidationError("result validator binding is invalid")
        validator_id = validator.get("id")
        validator_version = validator.get("version")
        if (
            not isinstance(validator_id, str)
            or VALIDATOR_ID_PATTERN.fullmatch(validator_id) is None
            or not isinstance(validator_version, str)
            or VERSION_PATTERN.fullmatch(validator_version) is None
        ):
            raise FindingValidationError("result validator ID or version is invalid")
        if not isinstance(corroboration, Mapping) or set(corroboration) != {
            "required",
            "observed_signals",
            "satisfied",
        }:
            raise FindingValidationError("result corroboration is invalid")
        if effects != {
            "authority": "none",
            "credentials": "none",
            "deployment": "none",
            "execution": "none",
            "network": "none",
            "qualification": "none",
            "routing": "none",
        }:
            raise FindingValidationError("result effects must be none")
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise FindingValidationError("result schema version is invalid")
        if raw.get("state") not in STATES:
            raise FindingValidationError("result state is invalid")
        if raw.get("finding_impact") not in IMPACT_LEVELS:
            raise FindingValidationError("result finding impact is invalid")
        confidence = raw.get("confidence")
        if (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not math.isfinite(float(confidence))
            or not 0 <= float(confidence) <= 1
        ):
            raise FindingValidationError("result confidence is invalid")
        reason_codes_raw = raw.get("reason_codes")
        evidence_hashes_raw = raw.get("evidence_hashes")
        restoration_hashes_raw = raw.get("restoration_evidence_hashes")
        observations_raw = raw.get("observations")
        checks_raw = raw.get("false_positive_checks")
        signals_raw = corroboration.get("observed_signals")
        if not all(
            isinstance(value, list)
            for value in (
                reason_codes_raw,
                evidence_hashes_raw,
                restoration_hashes_raw,
                observations_raw,
                checks_raw,
                signals_raw,
            )
        ):
            raise FindingValidationError("result collections are invalid")
        reasons = tuple(_code(value, "result reason code") for value in reason_codes_raw)
        signals = tuple(_code(value, "result signal code") for value in signals_raw)
        hashes = tuple(_sha256(value, "result evidence hash") for value in evidence_hashes_raw)
        restoration_hashes = tuple(
            _sha256(value, "result restoration hash") for value in restoration_hashes_raw
        )
        if (
            list(reasons) != sorted(set(reasons))
            or list(signals) != sorted(set(signals))
            or list(hashes) != sorted(set(hashes))
            or list(restoration_hashes) != sorted(set(restoration_hashes))
        ):
            raise FindingValidationError("result collections must be sorted and unique")
        observations = tuple(
            _validate_observation(value, "observation") for value in observations_raw
        )
        checks = tuple(_validate_check(value) for value in checks_raw)
        required = corroboration.get("required")
        satisfied = corroboration.get("satisfied")
        if not isinstance(required, int) or isinstance(required, bool) or not 2 <= required <= 8:
            raise FindingValidationError("required corroboration is invalid")
        if not isinstance(satisfied, bool) or satisfied != (len(signals) >= required):
            raise FindingValidationError("corroboration satisfaction is inconsistent")
        if raw.get("state") == "verified" and not satisfied:
            raise FindingValidationError("verified result lacks corroboration")
        restoration = raw.get("restoration")
        if restoration not in {"not_applicable", "verified", "missing", "invalid"}:
            raise FindingValidationError("result restoration state is invalid")
        body = {
            key: value for key, value in raw.items() if key not in {"result_id", "result_sha256"}
        }
        digest = _digest(RESULT_DOMAIN, "result", body)
        expected_id = f"FVR-{digest.removeprefix('sha256:')[:32].upper()}"
        if raw.get("result_sha256") != digest or raw.get("result_id") != expected_id:
            raise FindingValidationError("finding validation result hash does not match content")
        document = _canonical_json(dict(raw))
        if len(document.encode("utf-8")) > HARD_MAX_OUTPUT_BYTES:
            raise FindingValidationError("finding validation result exceeds the output limit")
        return cls(
            SCHEMA_VERSION,
            expected_id,
            digest,
            _sha256(raw.get("registry_sha256"), "registry hash"),
            _sha256(raw.get("input_sha256"), "validation input hash"),
            _identifier(raw.get("scope_id"), "scope ID"),
            _identifier(raw.get("technique_id"), "technique ID"),
            raw["finding_impact"],
            validator_id,
            validator_version,
            _sha256(validator["descriptor_sha256"], "validator descriptor hash"),
            raw["state"],
            float(confidence),
            reasons,
            hashes,
            restoration_hashes,
            observations,
            checks,
            required,
            signals,
            satisfied,
            restoration,
            document,
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


ValidationResult = FindingValidationResult


def _validate_observation(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"code", "evidence_hashes", "attributes"}:
        raise FindingValidationError(f"{label} fields are invalid")
    hashes = value["evidence_hashes"]
    if not isinstance(hashes, list):
        raise FindingValidationError(f"{label} evidence hashes are invalid")
    normalized_hashes = sorted({_sha256(item, f"{label} evidence hash") for item in hashes})
    if normalized_hashes != hashes:
        raise FindingValidationError(f"{label} evidence hashes must be sorted and unique")
    copied = _copy_safe_value(value["attributes"], f"{label} attributes", output=True)
    return MappingProxyType(
        {
            "code": _code(value["code"], f"{label} code"),
            "evidence_hashes": normalized_hashes,
            "attributes": copied,
        }
    )


def _validate_check(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"code", "passed", "evidence_hashes"}:
        raise FindingValidationError("false-positive check fields are invalid")
    if not isinstance(value["passed"], bool) or not isinstance(value["evidence_hashes"], list):
        raise FindingValidationError("false-positive check values are invalid")
    hashes = sorted(
        {_sha256(item, "false-positive check evidence hash") for item in value["evidence_hashes"]}
    )
    if hashes != value["evidence_hashes"]:
        raise FindingValidationError("false-positive check hashes must be sorted and unique")
    return MappingProxyType(
        {
            "code": _code(value["code"], "false-positive check code"),
            "passed": value["passed"],
            "evidence_hashes": hashes,
        }
    )


def _restoration_state(request: FindingValidationRequest) -> tuple[str, tuple[str, ...]]:
    records = request.restoration_evidence
    hashes = tuple(sorted({item.evidence_sha256 for item in records}))
    if not records:
        return ("missing" if request.restoration_required else "not_applicable"), hashes
    valid = all(item.attributes.get("restoration_status") == "verified" for item in records)
    restored_object = request.options.get("restored_object_id")
    if restored_object is not None:
        if not isinstance(restored_object, str):
            raise FindingValidationError("restored_object_id must be text")
        valid = valid and all(
            item.attributes.get("restored_object_id") == restored_object for item in records
        )
    return ("verified" if valid else "invalid"), hashes


def _build_result(
    request: FindingValidationRequest,
    descriptor: ValidatorDescriptor,
    registry_sha256: str,
    assessment: _Assessment,
) -> FindingValidationResult:
    if (
        request.validator_id != descriptor.validator_id
        or request.validator_version != descriptor.version
    ):
        raise FindingValidationError("request does not match the exact validator version")
    if assessment.state not in STATES:
        raise FindingValidationError("validator returned an invalid state")
    if not 0 <= assessment.confidence <= 1:
        raise FindingValidationError("validator returned invalid confidence")
    reason_codes = tuple(sorted({_code(value, "reason code") for value in assessment.reason_codes}))
    signals = tuple(sorted({_code(value, "signal code") for value in assessment.observed_signals}))
    allowed_signals = set(descriptor.required_signal_codes) | {
        "unauthorized_denial",
    }
    if not set(signals) <= allowed_signals:
        raise FindingValidationError("validator emitted an undeclared signal")
    required = descriptor.minimum_corroboration
    if request.finding_impact in {"high", "critical"}:
        required = max(2, required)
    satisfied = len(signals) >= required
    state = assessment.state
    confidence = float(assessment.confidence)
    if state == "verified" and not satisfied:
        state = "hypothesis"
        confidence = min(confidence, 0.64)
        reason_codes = tuple(sorted({*reason_codes, "independent_corroboration_required"}))
    restoration, restoration_hashes = _restoration_state(request)
    if state == "verified" and request.restoration_required and restoration != "verified":
        state = "inconclusive"
        confidence = min(confidence, 0.4)
        reason_codes = tuple(sorted({*reason_codes, "restoration_evidence_required"}))
    observations = [
        dict(_validate_observation(dict(value), "observation")) for value in assessment.observations
    ]
    checks = [dict(_validate_check(dict(value))) for value in assessment.false_positive_checks]
    if request.restoration_required or request.restoration_evidence:
        checks.append(
            _check(
                "restoration_binding_verified",
                restoration == "verified",
                request.restoration_evidence,
            )
        )
    body = {
        "schema_version": SCHEMA_VERSION,
        "registry_sha256": registry_sha256,
        "input_sha256": request.input_sha256,
        "scope_id": request.scope_id,
        "technique_id": request.technique_id,
        "finding_impact": request.finding_impact,
        "validator": {
            "id": descriptor.validator_id,
            "version": descriptor.version,
            "descriptor_sha256": descriptor.descriptor_sha256,
        },
        "state": state,
        "confidence": confidence,
        "reason_codes": list(reason_codes),
        "evidence_hashes": sorted({item.evidence_sha256 for item in request.evidence}),
        "restoration_evidence_hashes": list(restoration_hashes),
        "observations": observations,
        "false_positive_checks": checks,
        "corroboration": {
            "required": required,
            "observed_signals": list(signals),
            "satisfied": satisfied,
        },
        "restoration": restoration,
        "effects": {
            "authority": "none",
            "credentials": "none",
            "deployment": "none",
            "execution": "none",
            "network": "none",
            "qualification": "none",
            "routing": "none",
        },
    }
    digest = _digest(RESULT_DOMAIN, "result", body)
    result_id = f"FVR-{digest.removeprefix('sha256:')[:32].upper()}"
    return FindingValidationResult.from_dict(
        {**body, "result_id": result_id, "result_sha256": digest}
    )


BUILTIN_VALIDATOR_TYPES = (
    AuthorizationDifferentialValidator,
    InputReflectionContextValidator,
    ErrorOracleDifferentialValidator,
    SecurityHeaderCookiePolicyValidator,
    RedirectBoundaryValidator,
    CanaryObservationValidator,
)
BUILTIN_DESCRIPTORS = {
    validator_type.descriptor.validator_id: validator_type.descriptor
    for validator_type in BUILTIN_VALIDATOR_TYPES
}


class FindingValidatorRegistry:
    """Exact-version validator lookup and result verification."""

    def __init__(self, validators: Iterable[FindingValidator]) -> None:
        registered: dict[tuple[str, str], FindingValidator] = {}
        for validator in validators:
            if not isinstance(validator, FindingValidator):
                raise FindingValidationError("registry entry does not implement FindingValidator")
            descriptor = validator.descriptor
            built_in = BUILTIN_DESCRIPTORS.get(descriptor.validator_id)
            if built_in is not None and descriptor.to_dict() != built_in.to_dict():
                raise FindingValidationError("built-in validator descriptor drift detected")
            key = (descriptor.validator_id, descriptor.version)
            if key in registered:
                raise FindingValidationError("duplicate validator ID and version")
            registered[key] = validator
        if not registered:
            raise FindingValidationError("validator registry must not be empty")
        self._validators = MappingProxyType(registered)
        descriptor_documents = [registered[key].descriptor.to_dict() for key in sorted(registered)]
        self.registry_sha256 = _digest(
            REGISTRY_DOMAIN,
            "registry",
            {"validators": descriptor_documents},
        )

    @property
    def descriptors(self) -> tuple[ValidatorDescriptor, ...]:
        return tuple(self._validators[key].descriptor for key in sorted(self._validators))

    def get(self, validator_id: str, version: str) -> FindingValidator:
        key = (validator_id, version)
        try:
            return self._validators[key]
        except KeyError as exc:
            raise FindingValidationError(
                "exact validator ID and version are not registered"
            ) from exc

    def validate(self, request: FindingValidationRequest) -> FindingValidationResult:
        if not isinstance(request, FindingValidationRequest):
            raise FindingValidationError("validation request type is invalid")
        if request.registry_sha256 is not None and request.registry_sha256 != self.registry_sha256:
            raise FindingValidationError("validator registry hash does not match the request")
        validator = self.get(request.validator_id, request.validator_version)
        _validate_request_contract(request, validator.descriptor)
        return _build_result(
            request,
            validator.descriptor,
            self.registry_sha256,
            validator.assess(request),
        )

    def verify_result(
        self,
        value: FindingValidationResult | Mapping[str, Any],
    ) -> FindingValidationResult:
        result = (
            value
            if isinstance(value, FindingValidationResult)
            else FindingValidationResult.from_dict(value)
        )
        if result.registry_sha256 != self.registry_sha256:
            raise FindingValidationError("finding result registry drift detected")
        validator = self.get(result.validator_id, result.validator_version)
        if result.validator_descriptor_sha256 != validator.descriptor.descriptor_sha256:
            raise FindingValidationError("finding result validator descriptor drift detected")
        if result.required_corroboration != validator.descriptor.minimum_corroboration:
            raise FindingValidationError("finding result corroboration rule drift detected")
        if result.state == "verified" and not set(
            validator.descriptor.required_signal_codes
        ).issubset(result.observed_signals):
            raise FindingValidationError("finding result lacks validator-specific corroboration")
        return result


def build_default_registry() -> FindingValidatorRegistry:
    return FindingValidatorRegistry(validator_type() for validator_type in BUILTIN_VALIDATOR_TYPES)


DEFAULT_REGISTRY = build_default_registry()


def validate_finding(
    *,
    scope_id: str,
    technique_id: str,
    validator_id: str,
    validator_version: str,
    evidence: Iterable[EvidenceRecord | bytes],
    finding_impact: str = "medium",
    markers: Iterable[str] = (),
    canary_ids: Iterable[str] = (),
    options: Mapping[str, Any] | None = None,
    expected_evidence_hashes: Iterable[str] = (),
    restoration_evidence: Iterable[EvidenceRecord | bytes] = (),
    expected_restoration_hashes: Iterable[str] = (),
    restoration_required: bool = False,
    registry_sha256: str | None = None,
    limits: FindingValidationLimits | None = None,
    registry: FindingValidatorRegistry | None = None,
) -> FindingValidationResult:
    """Validate captured evidence without network, execution, or authority effects."""

    selected = registry or DEFAULT_REGISTRY
    request = FindingValidationRequest(
        scope_id=scope_id,
        technique_id=technique_id,
        validator_id=validator_id,
        validator_version=validator_version,
        evidence=tuple(evidence),
        finding_impact=finding_impact,
        markers=tuple(markers),
        canary_ids=tuple(canary_ids),
        options=options or {},
        expected_evidence_hashes=tuple(expected_evidence_hashes),
        restoration_evidence=tuple(restoration_evidence),
        expected_restoration_hashes=tuple(expected_restoration_hashes),
        restoration_required=restoration_required,
        registry_sha256=registry_sha256,
        limits=limits or FindingValidationLimits(),
    )
    return selected.validate(request)


ValidatorRegistry = FindingValidatorRegistry
EvidenceLimits = FindingValidationLimits
ValidatorAssessment = _Assessment

__all__ = [
    "AuthorizationDifferentialValidator",
    "BUILTIN_DESCRIPTORS",
    "CanaryObservationValidator",
    "CapturedEvidence",
    "DEFAULT_REGISTRY",
    "ErrorOracleDifferentialValidator",
    "EvidenceLimits",
    "EvidenceRecord",
    "FindingValidationError",
    "FindingValidationLimits",
    "FindingValidationRequest",
    "FindingValidationResult",
    "FindingValidator",
    "FindingValidatorRegistry",
    "HttpEvidenceRecord",
    "InputReflectionContextValidator",
    "RedirectBoundaryValidator",
    "SecurityHeaderCookiePolicyValidator",
    "ValidationContext",
    "ValidationResult",
    "ValidatorDescriptor",
    "ValidatorAssessment",
    "ValidatorRegistry",
    "build_default_registry",
    "validate_finding",
]
