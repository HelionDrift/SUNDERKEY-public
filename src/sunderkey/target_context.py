"""Typed, offline-only target context ingestion contracts.

The boundary accepts caller-supplied bytes or a local directory. It never fetches
references, expands files onto disk, executes content, or preserves supplied text
in the resulting bundle. Only hashes, provenance, redaction evidence, quarantine
flags, and conservative structural facts cross the boundary.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import stat
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree

BUNDLE_DOMAIN = "sunderkey.target-context-bundle.v1"
DIRECTORY_MANIFEST_DOMAIN = "sunderkey.target-context-directory-manifest.v1"
SCHEMA_VERSION = 1
PARSER_POLICY = "metadata_and_safe_structure_only"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
BUNDLE_ID_PATTERN = re.compile(r"TCB-[0-9A-F]{32}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){1,2}(?:[-.][A-Za-z0-9]+)*")
WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
HTTP_METHODS = ("delete", "get", "head", "options", "patch", "post", "put", "trace")
XML_DANGEROUS_RE = re.compile(r"<!\s*(?:doctype|entity)\b", re.IGNORECASE)
MAX_XML_ELEMENTS = 65_536
YAML_UNSAFE_RE = re.compile(
    r"(?:^|[\s\[{,])(?:!!|![A-Za-z<]|&[A-Za-z0-9_-]+|\*[A-Za-z0-9_-]+)",
    re.MULTILINE,
)
HARD_LIMITS = {
    "max_compression_ratio": 100,
    "max_file_bytes": 2 * 1024 * 1024,
    "max_files": 256,
    "max_findings": 256,
    "max_input_bytes": 8 * 1024 * 1024,
    "max_path_length": 240,
    "max_structural_depth": 32,
    "max_total_bytes": 16 * 1024 * 1024,
}

SOURCE_MEDIA_BY_SUFFIX = {
    ".c": "text/x-c",
    ".cc": "text/x-c++",
    ".cfg": "text/plain",
    ".conf": "text/plain",
    ".cpp": "text/x-c++",
    ".cs": "text/x-csharp",
    ".css": "text/css",
    ".env": "text/plain",
    ".go": "text/x-go",
    ".h": "text/x-c",
    ".hpp": "text/x-c++",
    ".ini": "text/plain",
    ".java": "text/x-java-source",
    ".js": "text/javascript",
    ".json": "application/json",
    ".jsx": "text/javascript",
    ".kt": "text/x-kotlin",
    ".kts": "text/x-kotlin",
    ".php": "text/x-php",
    ".properties": "text/plain",
    ".proto": "text/plain",
    ".py": "text/x-python",
    ".rb": "text/x-ruby",
    ".rs": "text/x-rust",
    ".sh": "text/x-shellscript",
    ".sql": "text/x-sql",
    ".toml": "application/toml",
    ".ts": "text/typescript",
    ".tsx": "text/typescript",
    ".xml": "application/xml",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
}
DOCUMENT_MEDIA_BY_SUFFIX = {
    ".adoc": "text/asciidoc",
    ".htm": "text/html",
    ".html": "text/html",
    ".markdown": "text/markdown",
    ".md": "text/markdown",
    ".rst": "text/x-rst",
    ".txt": "text/plain",
}
OPENAPI_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/openapi+json",
        "application/openapi+yaml",
        "application/x-yaml",
        "application/yaml",
        "text/yaml",
    }
)
WSDL_MEDIA_TYPES = frozenset({"application/wsdl+xml", "application/xml", "text/xml"})
ARCHIVE_MEDIA_TYPES = frozenset({"application/zip"})
DOCUMENT_MEDIA_TYPES = frozenset(DOCUMENT_MEDIA_BY_SUFFIX.values())
SOURCE_MEDIA_TYPES = frozenset(SOURCE_MEDIA_BY_SUFFIX.values())
ALLOWED_MEDIA_TYPES = (
    OPENAPI_MEDIA_TYPES
    | WSDL_MEDIA_TYPES
    | ARCHIVE_MEDIA_TYPES
    | DOCUMENT_MEDIA_TYPES
    | SOURCE_MEDIA_TYPES
    | {"text/plain"}
)


class TargetContextError(ValueError):
    """Raised when target context cannot safely cross the boundary."""


class TargetContextKind(StrEnum):
    """Supported context classes."""

    OPENAPI = "openapi"
    WSDL = "wsdl"
    SOURCE_ARCHIVE = "source_archive"
    SOURCE_FILE = "source_file"
    DOCUMENTATION = "documentation"
    FREE_TEXT = "free_text"


@dataclass(frozen=True)
class TargetContextLimits:
    """Resource limits enforced before and during parsing."""

    max_input_bytes: int = 8 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024
    max_files: int = 256
    max_compression_ratio: int = 100
    max_path_length: int = 240
    max_structural_depth: int = 32
    max_findings: int = 256

    def __post_init__(self) -> None:
        for field_name, value in self.to_dict().items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise TargetContextError(f"{field_name} must be a positive integer")
            if value > HARD_LIMITS[field_name]:
                raise TargetContextError(f"{field_name} exceeds the hard safety limit")
        if self.max_file_bytes > self.max_total_bytes:
            raise TargetContextError("max_file_bytes cannot exceed max_total_bytes")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_compression_ratio": self.max_compression_ratio,
            "max_file_bytes": self.max_file_bytes,
            "max_files": self.max_files,
            "max_findings": self.max_findings,
            "max_input_bytes": self.max_input_bytes,
            "max_path_length": self.max_path_length,
            "max_structural_depth": self.max_structural_depth,
            "max_total_bytes": self.max_total_bytes,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TargetContextLimits:
        expected = {
            "max_compression_ratio",
            "max_file_bytes",
            "max_files",
            "max_findings",
            "max_input_bytes",
            "max_path_length",
            "max_structural_depth",
            "max_total_bytes",
        }
        _require_exact_fields(raw, expected, "target context limits")
        return cls(**raw)


@dataclass(frozen=True)
class TargetContextProvenance:
    """Caller-supplied provenance for an ingestion event."""

    source_id: str
    supplied_by: str
    collected_at: str

    def __post_init__(self) -> None:
        _identifier(self.source_id, "provenance source_id")
        _identifier(self.supplied_by, "provenance supplied_by")
        _utc(self.collected_at, "provenance collected_at")

    def to_dict(self) -> dict[str, str]:
        return {
            "collected_at": self.collected_at,
            "source_id": self.source_id,
            "supplied_by": self.supplied_by,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TargetContextProvenance:
        _require_exact_fields(
            raw,
            {"collected_at", "source_id", "supplied_by"},
            "target context provenance",
        )
        return cls(
            source_id=raw["source_id"],
            supplied_by=raw["supplied_by"],
            collected_at=raw["collected_at"],
        )


@dataclass(frozen=True)
class TargetContextInput:
    """An immutable caller-owned byte input."""

    name: str
    content: bytes
    media_type: str | None = None
    kind: TargetContextKind | str | None = None
    expected_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            raise TargetContextError("target context input content must be bytes")
        if self.media_type is not None and not isinstance(self.media_type, str):
            raise TargetContextError("target context input media_type must be text")
        if self.expected_sha256 is not None:
            _sha256(self.expected_sha256, "target context expected hash")

    @classmethod
    def from_bytes(
        cls,
        name: str,
        content: bytes,
        *,
        media_type: str | None = None,
        kind: TargetContextKind | str | None = None,
        expected_sha256: str | None = None,
    ) -> TargetContextInput:
        return cls(name, content, media_type, kind, expected_sha256)


@dataclass(frozen=True)
class TargetInputRecord:
    """A hash-bound record for one supplied file or archive."""

    path: str
    kind: str
    media_type: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "media_type": self.media_type,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        limits: TargetContextLimits,
    ) -> TargetInputRecord:
        _require_exact_fields(
            raw,
            {"kind", "media_type", "path", "sha256", "size_bytes"},
            "target context input record",
        )
        path = _normalize_path(raw["path"], limits)
        kind = _kind(raw["kind"]).value
        media_type = _media_type(raw["media_type"])
        _validate_kind_media(TargetContextKind(kind), media_type)
        digest = _sha256(raw["sha256"], "target context input hash")
        size_bytes = _nonnegative_integer(raw["size_bytes"], "target context input size")
        if size_bytes > limits.max_input_bytes:
            raise TargetContextError("target context input exceeds max_input_bytes")
        return cls(path, kind, media_type, digest, size_bytes)


@dataclass(frozen=True)
class RedactionRecord:
    """Evidence that a secret was detected without retaining the secret."""

    path: str
    detector: str
    line: int
    column: int
    secret_sha256: str
    replacement: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "column": self.column,
            "detector": self.detector,
            "line": self.line,
            "path": self.path,
            "replacement": self.replacement,
            "secret_sha256": self.secret_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any, limits: TargetContextLimits) -> RedactionRecord:
        _require_exact_fields(
            raw,
            {"column", "detector", "line", "path", "replacement", "secret_sha256"},
            "target context redaction",
        )
        path = _normalize_path(raw["path"], limits)
        detector = _ascii_token(raw["detector"], "target context redaction detector")
        line = _positive_integer(raw["line"], "target context redaction line")
        column = _positive_integer(raw["column"], "target context redaction column")
        digest = _sha256(raw["secret_sha256"], "target context redaction hash")
        replacement = raw["replacement"]
        if replacement != f"[REDACTED:{detector}]":
            raise TargetContextError("target context redaction replacement is invalid")
        return cls(path, detector, line, column, digest, replacement)


@dataclass(frozen=True)
class QuarantineFlag:
    """A content risk marker that is safe to serialize."""

    path: str
    code: str
    severity: str = "high"

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "severity": self.severity}

    @classmethod
    def from_dict(cls, raw: Any, limits: TargetContextLimits) -> QuarantineFlag:
        _require_exact_fields(raw, {"code", "path", "severity"}, "target context flag")
        path = _normalize_path(raw["path"], limits)
        code = _ascii_token(raw["code"], "target context flag code")
        severity = raw["severity"]
        if severity not in {"high", "critical"}:
            raise TargetContextError("target context flag severity is invalid")
        return cls(path, code, severity)


@dataclass(frozen=True)
class TargetArtifact:
    """Metadata and structural facts for one logical artifact."""

    path: str
    kind: str
    media_type: str
    sha256: str
    size_bytes: int
    quarantined: bool
    structural_facts_json: str

    @property
    def structural_facts(self) -> dict[str, Any]:
        value = json.loads(self.structural_facts_json)
        if not isinstance(value, dict):
            raise TargetContextError("target context structural facts are invalid")
        return value

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "media_type": self.media_type,
            "path": self.path,
            "quarantined": self.quarantined,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "structural_facts": self.structural_facts,
        }

    @classmethod
    def from_dict(cls, raw: Any, limits: TargetContextLimits) -> TargetArtifact:
        _require_exact_fields(
            raw,
            {
                "kind",
                "media_type",
                "path",
                "quarantined",
                "sha256",
                "size_bytes",
                "structural_facts",
            },
            "target context artifact",
        )
        path = _normalize_path(raw["path"], limits)
        kind_value = _kind(raw["kind"])
        if kind_value is TargetContextKind.SOURCE_ARCHIVE:
            raise TargetContextError("archives cannot be logical artifacts")
        media_type = _media_type(raw["media_type"])
        _validate_kind_media(kind_value, media_type)
        digest = _sha256(raw["sha256"], "target context artifact hash")
        size_bytes = _nonnegative_integer(raw["size_bytes"], "target context artifact size")
        if size_bytes > limits.max_file_bytes:
            raise TargetContextError("target context artifact exceeds max_file_bytes")
        if not isinstance(raw["quarantined"], bool):
            raise TargetContextError("target context artifact quarantine state is invalid")
        facts = raw["structural_facts"]
        if not isinstance(facts, dict):
            raise TargetContextError("target context structural facts must be an object")
        _validate_json_depth(facts, limits.max_structural_depth)
        facts_json = _canonical_json(facts)
        return cls(
            path,
            kind_value.value,
            media_type,
            digest,
            size_bytes,
            raw["quarantined"],
            facts_json,
        )


@dataclass(frozen=True)
class TargetContextBundle:
    """A validated, content-addressed target context bundle."""

    bundle_id: str
    bundle_sha256: str
    mission_id: str
    authority_ref: str
    status: str
    provenance: TargetContextProvenance
    ingestion_method: str
    limits: TargetContextLimits
    inputs: tuple[TargetInputRecord, ...]
    artifacts: tuple[TargetArtifact, ...]
    redactions: tuple[RedactionRecord, ...]
    quarantine_flags: tuple[QuarantineFlag, ...]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise TargetContextError("target context bundle document is invalid")
        return value

    def verify_input_bytes(self, path: str, content: bytes) -> None:
        """Reject content that no longer matches a bundle input record."""

        normalized = _normalize_path(path, self.limits)
        record = next((item for item in self.inputs if item.path == normalized), None)
        if record is None:
            raise TargetContextError("target context input is not present in the bundle")
        if not isinstance(content, bytes):
            raise TargetContextError("target context verification content must be bytes")
        if len(content) != record.size_bytes or _content_sha256(content) != record.sha256:
            raise TargetContextError("target context input hash drift detected")

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        mission_id: str | None = None,
        authority_ref: str | None = None,
    ) -> TargetContextBundle:
        expected = {
            "artifacts",
            "authority_ref",
            "bundle_id",
            "bundle_sha256",
            "effects",
            "ingestion_method",
            "inputs",
            "limits",
            "mission_id",
            "parser_policy",
            "provenance",
            "quarantine_flags",
            "redactions",
            "schema_version",
            "status",
            "summary",
        }
        _require_exact_fields(raw, expected, "target context bundle")
        if raw["schema_version"] != SCHEMA_VERSION:
            raise TargetContextError("target context schema_version is invalid")
        document_mission_id = _identifier(raw["mission_id"], "target context mission_id")
        document_authority_ref = _identifier(raw["authority_ref"], "target context authority_ref")
        if (
            mission_id is not None
            and _identifier(mission_id, "expected target context mission_id") != document_mission_id
        ):
            raise TargetContextError("target context mission binding is invalid")
        if (
            authority_ref is not None
            and _identifier(authority_ref, "expected target context authority_ref")
            != document_authority_ref
        ):
            raise TargetContextError("target context authority binding is invalid")
        if raw["parser_policy"] != PARSER_POLICY:
            raise TargetContextError("target context parser policy is invalid")
        ingestion_method = raw["ingestion_method"]
        if ingestion_method not in {"injected_bytes", "local_directory"}:
            raise TargetContextError("target context ingestion method is invalid")
        provenance = TargetContextProvenance.from_dict(raw["provenance"])
        limits = TargetContextLimits.from_dict(raw["limits"])
        inputs_raw = raw["inputs"]
        artifacts_raw = raw["artifacts"]
        redactions_raw = raw["redactions"]
        flags_raw = raw["quarantine_flags"]
        if not isinstance(inputs_raw, list) or not inputs_raw:
            raise TargetContextError("target context inputs must be a nonempty list")
        if not isinstance(artifacts_raw, list) or not artifacts_raw:
            raise TargetContextError("target context artifacts must be a nonempty list")
        if not isinstance(redactions_raw, list) or not isinstance(flags_raw, list):
            raise TargetContextError("target context findings must be lists")
        inputs = tuple(TargetInputRecord.from_dict(item, limits) for item in inputs_raw)
        artifacts = tuple(TargetArtifact.from_dict(item, limits) for item in artifacts_raw)
        redactions = tuple(RedactionRecord.from_dict(item, limits) for item in redactions_raw)
        flags = tuple(QuarantineFlag.from_dict(item, limits) for item in flags_raw)
        _require_path_order(tuple(item.path for item in inputs), "target context inputs")
        _require_path_order(tuple(item.path for item in artifacts), "target context artifacts")
        _require_finding_order(redactions, flags)
        if len(inputs) > limits.max_files or len(artifacts) > limits.max_files:
            raise TargetContextError("target context file count exceeds the limit")
        if sum(item.size_bytes for item in inputs) > limits.max_total_bytes:
            raise TargetContextError("target context input bytes exceed the total limit")
        if sum(item.size_bytes for item in artifacts) > limits.max_total_bytes:
            raise TargetContextError("target context artifact bytes exceed the total limit")
        artifact_paths = {item.path for item in artifacts}
        if any(item.path not in artifact_paths for item in (*redactions, *flags)):
            raise TargetContextError("target context finding references an unknown artifact")
        quarantined_paths = {item.path for item in redactions} | {item.path for item in flags}
        if any(item.quarantined != (item.path in quarantined_paths) for item in artifacts):
            raise TargetContextError("target context artifact quarantine binding is invalid")
        if len(redactions) + len(flags) > limits.max_findings:
            raise TargetContextError("target context finding count exceeds the limit")
        status = raw["status"]
        expected_status = "quarantined" if quarantined_paths else "accepted"
        if status != expected_status:
            raise TargetContextError("target context status is inconsistent")
        expected_effects = {
            "authority": "none",
            "execution": "none",
            "network": "none",
            "operational": "none",
        }
        if raw["effects"] != expected_effects:
            raise TargetContextError("target context effects must all be none")
        summary = _summary(inputs, artifacts, redactions, flags)
        if raw["summary"] != summary:
            raise TargetContextError("target context summary is inconsistent")
        bundle_sha256 = _sha256(raw["bundle_sha256"], "target context bundle hash")
        bundle_id = raw["bundle_id"]
        if not isinstance(bundle_id, str) or BUNDLE_ID_PATTERN.fullmatch(bundle_id) is None:
            raise TargetContextError("target context bundle ID is invalid")
        body = {
            key: value for key, value in raw.items() if key not in {"bundle_id", "bundle_sha256"}
        }
        expected_sha256 = _canonical_sha256({"bundle": body, "domain": BUNDLE_DOMAIN})
        expected_id = f"TCB-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if bundle_sha256 != expected_sha256 or bundle_id != expected_id:
            raise TargetContextError("target context bundle identity does not match content")
        return cls(
            bundle_id,
            bundle_sha256,
            document_mission_id,
            document_authority_ref,
            status,
            provenance,
            ingestion_method,
            limits,
            inputs,
            artifacts,
            redactions,
            flags,
            _canonical_json(raw),
        )


@dataclass
class _Budget:
    limits: TargetContextLimits
    artifact_count: int = 0
    artifact_bytes: int = 0

    def consume(self, size_bytes: int) -> None:
        self.artifact_count += 1
        self.artifact_bytes += size_bytes
        if self.artifact_count > self.limits.max_files:
            raise TargetContextError("target context file count exceeds the limit")
        if size_bytes > self.limits.max_file_bytes:
            raise TargetContextError("target context file exceeds max_file_bytes")
        if self.artifact_bytes > self.limits.max_total_bytes:
            raise TargetContextError("target context expanded bytes exceed the total limit")


@dataclass(frozen=True)
class _ArtifactResult:
    artifact: TargetArtifact
    redactions: tuple[RedactionRecord, ...]
    flags: tuple[QuarantineFlag, ...]


SECRET_PATTERNS = (
    (
        "private_key",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
        None,
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), None),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
        None,
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        None,
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer[ \t]+(?P<secret>[A-Za-z0-9._~+/=-]{12,})"),
        "secret",
    ),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|password|secret|token)\b"
            r"[ \t]*[:=][ \t]*[\"']?(?P<secret>[A-Za-z0-9._~+/=-]{8,})"
        ),
        "secret",
    ),
    (
        "credential_url",
        re.compile(
            r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]{1,128}:"
            r"(?P<secret>[^\s/@]{4,128})@"
        ),
        "secret",
    ),
)
HOSTILE_PATTERNS = (
    (
        "instruction_override",
        re.compile(
            r"(?i)\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|system|developer)\s+instructions?\b"
        ),
    ),
    ("role_impersonation", re.compile(r"(?i)\b(?:you are now|act as)\s+(?:the\s+)?system\b")),
    (
        "credential_exfiltration_request",
        re.compile(
            r"(?i)\b(?:reveal|exfiltrate|send|upload)\b.{0,40}"
            r"\b(?:credential|password|secret|token)s?\b"
        ),
    ),
    ("active_content", re.compile(r"(?i)<\s*(?:script|iframe|object)\b|\bonload\s*=")),
    ("dangerous_uri_scheme", re.compile(r"(?i)\b(?:javascript|data\s*:\s*text/html)\s*:")),
)


def ingest_target_context_bytes(
    content: bytes,
    *,
    name: str,
    mission_id: str,
    authority_ref: str,
    provenance: TargetContextProvenance | Mapping[str, Any],
    media_type: str | None = None,
    kind: TargetContextKind | str | None = None,
    expected_sha256: str | None = None,
    limits: TargetContextLimits | None = None,
) -> TargetContextBundle:
    """Ingest one caller-supplied byte sequence without external effects."""

    return ingest_target_context_inputs(
        (
            TargetContextInput(
                name=name,
                content=content,
                media_type=media_type,
                kind=kind,
                expected_sha256=expected_sha256,
            ),
        ),
        mission_id=mission_id,
        authority_ref=authority_ref,
        provenance=provenance,
        limits=limits,
    )


def ingest_target_context_inputs(
    inputs: Sequence[TargetContextInput],
    *,
    mission_id: str,
    authority_ref: str,
    provenance: TargetContextProvenance | Mapping[str, Any],
    limits: TargetContextLimits | None = None,
) -> TargetContextBundle:
    """Ingest a deterministic sequence of byte inputs."""

    return _ingest_inputs(
        inputs,
        mission_id=mission_id,
        authority_ref=authority_ref,
        provenance=_provenance(provenance),
        ingestion_method="injected_bytes",
        limits=_limits(limits),
    )


def ingest_target_context_directory(
    directory: str | Path,
    *,
    mission_id: str,
    authority_ref: str,
    provenance: TargetContextProvenance | Mapping[str, Any],
    expected_manifest_sha256: str | None = None,
    limits: TargetContextLimits | None = None,
) -> TargetContextBundle:
    """Read a local directory without following links or writing extracted data."""

    active_limits = _limits(limits)
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise TargetContextError("target context directory must be a real directory")
    records: list[TargetContextInput] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        for directory_name in directory_names:
            candidate = current_path / directory_name
            if candidate.is_symlink():
                raise TargetContextError("target context directory contains a symlink")
            _normalize_path(candidate.relative_to(root).as_posix(), active_limits)
        for file_name in file_names:
            candidate = current_path / file_name
            relative = _normalize_path(candidate.relative_to(root).as_posix(), active_limits)
            before = candidate.stat(follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                raise TargetContextError("target context directory contains a non-regular file")
            if before.st_size > active_limits.max_input_bytes:
                raise TargetContextError("target context input exceeds max_input_bytes")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(candidate, flags)
                try:
                    opened = os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode):
                        raise TargetContextError(
                            "target context directory contains a non-regular file"
                        )
                    if opened.st_size > active_limits.max_input_bytes:
                        raise TargetContextError("target context input exceeds max_input_bytes")
                    opened_state = (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_size,
                        opened.st_mtime_ns,
                    )
                    if opened_state != (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                    ):
                        raise TargetContextError(
                            "target context directory file changed while opening"
                        )
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        content = stream.read(active_limits.max_input_bytes + 1)
                    after_open = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                after = candidate.stat(follow_symlinks=False)
            except OSError as exc:
                raise TargetContextError(
                    "target context directory file could not be read safely"
                ) from exc
            after_open_state = (
                after_open.st_dev,
                after_open.st_ino,
                after_open.st_size,
                after_open.st_mtime_ns,
            )
            after_path_state = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            if (
                len(content) > active_limits.max_input_bytes
                or before.st_size != len(content)
                or not stat.S_ISREG(after.st_mode)
                or after_open_state != opened_state
                or after_path_state != opened_state
            ):
                raise TargetContextError("target context directory file changed while reading")
            suffix = PurePosixPath(relative).suffix.lower()
            basename = PurePosixPath(relative).name.lower()
            kind_hint = (
                TargetContextKind.SOURCE_FILE
                if suffix in {".json", ".yaml", ".yml"}
                and not any(marker in basename for marker in ("openapi", "swagger"))
                else None
            )
            records.append(TargetContextInput(relative, content, kind=kind_hint))
            if len(records) > active_limits.max_files:
                raise TargetContextError("target context input file count exceeds the limit")
    if not records:
        raise TargetContextError("target context directory is empty")
    manifest_sha256 = _directory_manifest_sha256(records, active_limits)
    if expected_manifest_sha256 is not None:
        _sha256(expected_manifest_sha256, "target context expected directory manifest hash")
        if expected_manifest_sha256 != manifest_sha256:
            raise TargetContextError("target context directory manifest hash drift detected")
    return _ingest_inputs(
        records,
        mission_id=mission_id,
        authority_ref=authority_ref,
        provenance=_provenance(provenance),
        ingestion_method="local_directory",
        limits=active_limits,
    )


build_target_context_bundle = ingest_target_context_inputs


def _ingest_inputs(
    inputs: Sequence[TargetContextInput],
    *,
    mission_id: str,
    authority_ref: str,
    provenance: TargetContextProvenance,
    ingestion_method: str,
    limits: TargetContextLimits,
) -> TargetContextBundle:
    mission_id = _identifier(mission_id, "target context mission_id")
    authority_ref = _identifier(authority_ref, "target context authority_ref")
    if isinstance(inputs, (str, bytes)) or not isinstance(inputs, Sequence) or not inputs:
        raise TargetContextError("target context inputs must be a nonempty sequence")
    if len(inputs) > limits.max_files:
        raise TargetContextError("target context input file count exceeds the limit")
    normalized_inputs: list[tuple[str, TargetContextInput, TargetContextKind, str]] = []
    identities: set[str] = set()
    total_input_bytes = 0
    for value in inputs:
        if not isinstance(value, TargetContextInput):
            raise TargetContextError("target context inputs must be TargetContextInput values")
        if not isinstance(value.content, bytes):
            raise TargetContextError("target context input content must be bytes")
        path = _normalize_path(value.name, limits)
        identity = path.casefold()
        if identity in identities:
            raise TargetContextError("target context input paths are duplicated")
        identities.add(identity)
        total_input_bytes += len(value.content)
        if len(value.content) > limits.max_input_bytes:
            raise TargetContextError("target context input exceeds max_input_bytes")
        if total_input_bytes > limits.max_total_bytes:
            raise TargetContextError("target context input bytes exceed the total limit")
        digest = _content_sha256(value.content)
        if value.expected_sha256 is not None and value.expected_sha256 != digest:
            raise TargetContextError("target context input hash drift detected")
        kind_value, media_type = _classify(path, value.kind, value.media_type)
        normalized_inputs.append((path, value, kind_value, media_type))
    normalized_inputs.sort(key=lambda item: item[0])
    input_records: list[TargetInputRecord] = []
    artifacts: list[TargetArtifact] = []
    redactions: list[RedactionRecord] = []
    flags: list[QuarantineFlag] = []
    budget = _Budget(limits)
    artifact_identities: set[str] = set()
    for path, value, kind_value, media_type in normalized_inputs:
        input_records.append(
            TargetInputRecord(
                path,
                kind_value.value,
                media_type,
                _content_sha256(value.content),
                len(value.content),
            )
        )
        if kind_value is TargetContextKind.SOURCE_ARCHIVE:
            results = _ingest_zip(path, value.content, limits, budget)
        else:
            budget.consume(len(value.content))
            results = (_build_artifact(path, value.content, kind_value, media_type, limits),)
        for result in results:
            identity = result.artifact.path.casefold()
            if identity in artifact_identities:
                raise TargetContextError("target context artifact paths are duplicated")
            artifact_identities.add(identity)
            artifacts.append(result.artifact)
            redactions.extend(result.redactions)
            flags.extend(result.flags)
    artifacts.sort(key=lambda item: item.path)
    redactions.sort(key=lambda item: (item.path, item.line, item.column, item.detector))
    flags = sorted(set(flags), key=lambda item: (item.path, item.code, item.severity))
    if len(redactions) + len(flags) > limits.max_findings:
        raise TargetContextError("target context finding count exceeds the limit")
    redaction_paths = {item.path for item in redactions}
    flag_paths = {item.path for item in flags}
    quarantine_paths = redaction_paths | flag_paths
    artifacts = [
        TargetArtifact(
            item.path,
            item.kind,
            item.media_type,
            item.sha256,
            item.size_bytes,
            item.path in quarantine_paths,
            item.structural_facts_json,
        )
        for item in artifacts
    ]
    if not artifacts:
        raise TargetContextError("target context produced no supported artifacts")
    return _assemble_bundle(
        mission_id=mission_id,
        authority_ref=authority_ref,
        provenance=provenance,
        ingestion_method=ingestion_method,
        limits=limits,
        inputs=tuple(input_records),
        artifacts=tuple(artifacts),
        redactions=tuple(redactions),
        flags=tuple(flags),
    )


def _assemble_bundle(
    *,
    mission_id: str,
    authority_ref: str,
    provenance: TargetContextProvenance,
    ingestion_method: str,
    limits: TargetContextLimits,
    inputs: tuple[TargetInputRecord, ...],
    artifacts: tuple[TargetArtifact, ...],
    redactions: tuple[RedactionRecord, ...],
    flags: tuple[QuarantineFlag, ...],
) -> TargetContextBundle:
    status = "quarantined" if redactions or flags else "accepted"
    body = {
        "artifacts": [item.to_dict() for item in artifacts],
        "authority_ref": authority_ref,
        "effects": {
            "authority": "none",
            "execution": "none",
            "network": "none",
            "operational": "none",
        },
        "ingestion_method": ingestion_method,
        "inputs": [item.to_dict() for item in inputs],
        "limits": limits.to_dict(),
        "mission_id": mission_id,
        "parser_policy": PARSER_POLICY,
        "provenance": provenance.to_dict(),
        "quarantine_flags": [item.to_dict() for item in flags],
        "redactions": [item.to_dict() for item in redactions],
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "summary": _summary(inputs, artifacts, redactions, flags),
    }
    digest = _canonical_sha256({"bundle": body, "domain": BUNDLE_DOMAIN})
    return TargetContextBundle.from_dict(
        {
            **body,
            "bundle_id": f"TCB-{digest.removeprefix('sha256:')[:32].upper()}",
            "bundle_sha256": digest,
        }
    )


def _build_artifact(
    path: str,
    content: bytes,
    kind: TargetContextKind,
    media_type: str,
    limits: TargetContextLimits,
) -> _ArtifactResult:
    text = _decode_text(content, path)
    redactions = _scan_secrets(path, text, limits.max_findings)
    flags = list(_scan_hostile(path, text))
    if redactions:
        flags.append(QuarantineFlag(path, "secret_material_detected", "critical"))
    if kind is TargetContextKind.OPENAPI:
        facts, format_flags = _openapi_facts(path, text, media_type, limits)
        flags.extend(format_flags)
    elif kind is TargetContextKind.WSDL:
        facts, format_flags = _wsdl_facts(path, text, limits)
        flags.extend(format_flags)
    elif kind is TargetContextKind.DOCUMENTATION:
        facts = _documentation_facts(path, text, media_type)
    elif kind is TargetContextKind.FREE_TEXT:
        facts = _text_facts(path, text, "free_text")
    elif kind is TargetContextKind.SOURCE_FILE:
        facts = _source_facts(path, text)
    else:
        raise TargetContextError("source archives must be expanded before artifact parsing")
    unique_flags = tuple(sorted(set(flags), key=lambda item: (item.path, item.code)))
    artifact = TargetArtifact(
        path=path,
        kind=kind.value,
        media_type=media_type,
        sha256=_content_sha256(content),
        size_bytes=len(content),
        quarantined=bool(redactions or unique_flags),
        structural_facts_json=_canonical_json(facts),
    )
    return _ArtifactResult(artifact, redactions, unique_flags)


def _ingest_zip(
    archive_path: str,
    content: bytes,
    limits: TargetContextLimits,
    budget: _Budget,
) -> tuple[_ArtifactResult, ...]:
    results: list[_ArtifactResult] = []
    seen: set[str] = set()
    try:
        _validate_raw_zip_paths(content, limits)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            infos = archive.infolist()
            file_infos: list[tuple[str, zipfile.ZipInfo]] = []
            total_compressed = 0
            total_expanded = 0
            for info in infos:
                raw_name = info.filename.rstrip("/") if info.is_dir() else info.filename
                normalized = _normalize_path(raw_name, limits)
                identity = normalized.casefold()
                if identity in seen:
                    raise TargetContextError("source archive contains duplicate paths")
                seen.add(identity)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise TargetContextError("source archive contains a symbolic link")
                file_type = stat.S_IFMT(mode)
                if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise TargetContextError("source archive contains a special file")
                if info.flag_bits & 0x1:
                    raise TargetContextError("encrypted source archive members are not allowed")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise TargetContextError("source archive compression method is not allowed")
                if info.is_dir():
                    continue
                if info.file_size > limits.max_file_bytes:
                    raise TargetContextError("source archive member exceeds max_file_bytes")
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > limits.max_compression_ratio:
                    raise TargetContextError("source archive decompression ratio exceeds the limit")
                total_compressed += info.compress_size
                total_expanded += info.file_size
                if total_expanded > limits.max_total_bytes:
                    raise TargetContextError("source archive expanded bytes exceed the total limit")
                file_infos.append((normalized, info))
                if len(file_infos) > limits.max_files:
                    raise TargetContextError("source archive file count exceeds the limit")
            if not file_infos:
                raise TargetContextError("source archive contains no files")
            if total_expanded / max(total_compressed, 1) > limits.max_compression_ratio:
                raise TargetContextError("source archive aggregate ratio exceeds the limit")
            for member_path, info in sorted(file_infos, key=lambda item: item[0]):
                logical_path = _normalize_path(f"{archive_path}/{member_path}", limits)
                kind, media_type = _classify(member_path, None, None, sniff=False)
                if kind is TargetContextKind.SOURCE_ARCHIVE:
                    raise TargetContextError("nested source archives are not allowed")
                budget.consume(info.file_size)
                with archive.open(info, "r") as stream:
                    member = stream.read(limits.max_file_bytes + 1)
                if len(member) != info.file_size or len(member) > limits.max_file_bytes:
                    raise TargetContextError("source archive member size is inconsistent")
                results.append(_build_artifact(logical_path, member, kind, media_type, limits))
    except TargetContextError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise TargetContextError("source archive is malformed") from exc
    return tuple(results)


def _validate_raw_zip_paths(content: bytes, limits: TargetContextLimits) -> None:
    """Validate central-directory names before the platform can normalize them."""

    end_signature = b"PK\x05\x06"
    end_offset = content.rfind(end_signature)
    if end_offset < 0 or end_offset + 22 > len(content):
        raise TargetContextError("source archive central directory is malformed")
    disk_number = int.from_bytes(content[end_offset + 4 : end_offset + 6], "little")
    central_disk = int.from_bytes(content[end_offset + 6 : end_offset + 8], "little")
    disk_entries = int.from_bytes(content[end_offset + 8 : end_offset + 10], "little")
    total_entries = int.from_bytes(content[end_offset + 10 : end_offset + 12], "little")
    central_offset = int.from_bytes(content[end_offset + 16 : end_offset + 20], "little")
    comment_length = int.from_bytes(content[end_offset + 20 : end_offset + 22], "little")
    if (
        disk_number
        or central_disk
        or disk_entries != total_entries
        or total_entries == 0xFFFF
        or central_offset == 0xFFFFFFFF
        or end_offset + 22 + comment_length != len(content)
    ):
        raise TargetContextError("multi-disk and ZIP64 source archives are not allowed")
    offset = central_offset
    identities: set[str] = set()
    for _ in range(total_entries):
        if offset + 46 > end_offset or content[offset : offset + 4] != b"PK\x01\x02":
            raise TargetContextError("source archive central directory is malformed")
        flags = int.from_bytes(content[offset + 8 : offset + 10], "little")
        name_length = int.from_bytes(content[offset + 28 : offset + 30], "little")
        extra_length = int.from_bytes(content[offset + 30 : offset + 32], "little")
        member_comment_length = int.from_bytes(content[offset + 32 : offset + 34], "little")
        name_start = offset + 46
        name_end = name_start + name_length
        record_end = name_end + extra_length + member_comment_length
        if record_end > end_offset:
            raise TargetContextError("source archive central directory is malformed")
        try:
            raw_name = content[name_start:name_end].decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeDecodeError as exc:
            raise TargetContextError("source archive path encoding is invalid") from exc
        if "\\" in raw_name:
            raise TargetContextError("source archive path uses a backslash")
        normalized = _normalize_path(raw_name.rstrip("/"), limits)
        identity = normalized.casefold()
        if identity in identities:
            raise TargetContextError("source archive contains duplicate paths")
        identities.add(identity)
        offset = record_end
    if offset != end_offset:
        raise TargetContextError("source archive central directory is inconsistent")


def _classify(
    path: str,
    kind: TargetContextKind | str | None,
    media_type: str | None,
    *,
    sniff: bool = True,
) -> tuple[TargetContextKind, str]:
    suffix = PurePosixPath(path).suffix.lower()
    basename = PurePosixPath(path).name.lower()
    kind_value = _kind(kind) if kind is not None else None
    inferred_media = _infer_media_type(suffix)
    selected_media = _media_type(media_type) if media_type is not None else inferred_media
    if selected_media is None:
        raise TargetContextError("target context file type is not allowed")
    if kind_value is None:
        if suffix == ".zip":
            kind_value = TargetContextKind.SOURCE_ARCHIVE
        elif suffix == ".wsdl":
            kind_value = TargetContextKind.WSDL
        elif suffix in DOCUMENT_MEDIA_BY_SUFFIX:
            kind_value = (
                TargetContextKind.FREE_TEXT if suffix == ".txt" else TargetContextKind.DOCUMENTATION
            )
        elif suffix in {".json", ".yaml", ".yml"}:
            if sniff or any(marker in basename for marker in ("openapi", "swagger")):
                kind_value = TargetContextKind.OPENAPI
            else:
                kind_value = TargetContextKind.SOURCE_FILE
        elif suffix in SOURCE_MEDIA_BY_SUFFIX:
            kind_value = TargetContextKind.SOURCE_FILE
        else:
            raise TargetContextError("target context file type is not allowed")
    _validate_kind_media(kind_value, selected_media)
    return kind_value, selected_media


def _infer_media_type(suffix: str) -> str | None:
    if suffix == ".zip":
        return "application/zip"
    if suffix == ".wsdl":
        return "application/wsdl+xml"
    if suffix in DOCUMENT_MEDIA_BY_SUFFIX:
        return DOCUMENT_MEDIA_BY_SUFFIX[suffix]
    return SOURCE_MEDIA_BY_SUFFIX.get(suffix)


def _validate_kind_media(kind: TargetContextKind, media_type: str) -> None:
    allowed = {
        TargetContextKind.OPENAPI: OPENAPI_MEDIA_TYPES,
        TargetContextKind.WSDL: WSDL_MEDIA_TYPES,
        TargetContextKind.SOURCE_ARCHIVE: ARCHIVE_MEDIA_TYPES,
        TargetContextKind.SOURCE_FILE: SOURCE_MEDIA_TYPES,
        TargetContextKind.DOCUMENTATION: DOCUMENT_MEDIA_TYPES,
        TargetContextKind.FREE_TEXT: frozenset({"text/plain"}),
    }[kind]
    if media_type not in allowed:
        raise TargetContextError(
            f"media type {media_type!r} is not allowed for {kind.value} context"
        )


def _openapi_facts(
    path: str,
    text: str,
    media_type: str,
    limits: TargetContextLimits,
) -> tuple[dict[str, Any], tuple[QuarantineFlag, ...]]:
    if media_type in {"application/json", "application/openapi+json"}:
        value = _load_json(text)
        serialization = "json"
    else:
        if YAML_UNSAFE_RE.search(text):
            return (
                {"format": "openapi", "parse_status": "quarantined_unparsed"},
                (QuarantineFlag(path, "yaml_unsafe_feature", "critical"),),
            )
        value = _load_yaml(text, limits.max_structural_depth)
        serialization = "yaml"
    _validate_json_depth(value, limits.max_structural_depth)
    if not isinstance(value, dict):
        raise TargetContextError("OpenAPI document root must be an object")
    openapi_version = value.get("openapi")
    swagger_version = value.get("swagger")
    if isinstance(openapi_version, str) and swagger_version is None:
        format_name = "openapi"
        version = openapi_version
    elif isinstance(swagger_version, str) and openapi_version is None:
        format_name = "swagger"
        version = swagger_version
    else:
        raise TargetContextError("document is not an unambiguous OpenAPI or Swagger document")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise TargetContextError("OpenAPI or Swagger version is invalid")
    paths = value.get("paths", {})
    if not isinstance(paths, dict):
        raise TargetContextError("OpenAPI paths must be an object")
    method_counts: Counter[str] = Counter()
    for endpoint, path_item in paths.items():
        if not isinstance(endpoint, str) or not endpoint.startswith("/"):
            if isinstance(endpoint, str) and endpoint.startswith("x-"):
                continue
            raise TargetContextError("OpenAPI path keys must start with a slash")
        if not isinstance(path_item, dict):
            raise TargetContextError("OpenAPI path items must be objects")
        for method in HTTP_METHODS:
            if method in path_item:
                if not isinstance(path_item[method], dict):
                    raise TargetContextError("OpenAPI operations must be objects")
                method_counts[method] += 1
    components = value.get("components", {})
    if components is None:
        components = {}
    if not isinstance(components, dict):
        raise TargetContextError("OpenAPI components must be an object")
    definitions = value.get("definitions", {})
    if definitions is None:
        definitions = {}
    if not isinstance(definitions, dict):
        raise TargetContextError("Swagger definitions must be an object")
    schemas = components.get("schemas", definitions)
    security_schemes = components.get("securitySchemes", value.get("securityDefinitions", {}))
    if not isinstance(schemas, dict) or not isinstance(security_schemes, dict):
        raise TargetContextError("OpenAPI component collections must be objects")
    servers = value.get("servers", [])
    if not isinstance(servers, list):
        raise TargetContextError("OpenAPI servers must be a list")
    references = _reference_counts(value)
    flags = (
        (QuarantineFlag(path, "external_reference_not_resolved", "high"),)
        if references["external"]
        else ()
    )
    facts = {
        "external_reference_count": references["external"],
        "format": format_name,
        "internal_reference_count": references["internal"],
        "method_counts": dict(sorted(method_counts.items())),
        "operation_count": sum(method_counts.values()),
        "parse_status": "parsed",
        "path_count": sum(
            1 for endpoint in paths if isinstance(endpoint, str) and endpoint.startswith("/")
        ),
        "schema_count": len(schemas),
        "security_scheme_count": len(security_schemes),
        "serialization": serialization,
        "server_count": len(servers),
        "version": version,
    }
    return facts, flags


def _wsdl_facts(
    path: str,
    text: str,
    limits: TargetContextLimits,
) -> tuple[dict[str, Any], tuple[QuarantineFlag, ...]]:
    if XML_DANGEROUS_RE.search(text):
        return (
            {"format": "wsdl", "parse_status": "quarantined_unparsed"},
            (QuarantineFlag(path, "xml_doctype_or_entity", "critical"),),
        )
    counts: Counter[str] = Counter()
    external = 0
    root_name: str | None = None
    depth = 0
    element_count = 0
    maximum_elements = max(1, min(MAX_XML_ELEMENTS, limits.max_file_bytes // 16))
    parser = ElementTree.XMLPullParser(events=("start", "end"))
    try:
        for offset in range(0, len(text), 65_536):
            parser.feed(text[offset : offset + 65_536])
            for event, element in parser.read_events():
                if event == "end":
                    depth -= 1
                    element.clear()
                    continue
                depth += 1
                element_count += 1
                if depth > limits.max_structural_depth:
                    raise TargetContextError("WSDL XML nesting exceeds the structural limit")
                if element_count > maximum_elements:
                    raise TargetContextError("WSDL XML element count exceeds the structural limit")
                local_name = _xml_local_name(element.tag)
                if root_name is None:
                    root_name = local_name
                if local_name in {
                    "binding",
                    "endpoint",
                    "import",
                    "include",
                    "message",
                    "operation",
                    "port",
                    "service",
                    "types",
                }:
                    counts[local_name] += 1
                if local_name in {"import", "include"} and any(
                    key in element.attrib for key in {"location", "schemaLocation"}
                ):
                    external += 1
        parser.close()
    except ElementTree.ParseError as exc:
        raise TargetContextError("WSDL XML is malformed") from exc
    if root_name not in {"definitions", "description"}:
        raise TargetContextError("WSDL root element is invalid")
    if depth != 0:
        raise TargetContextError("WSDL XML event depth is invalid")
    flags = (QuarantineFlag(path, "external_reference_not_resolved", "high"),) if external else ()
    facts = {
        "binding_count": counts["binding"],
        "endpoint_count": counts["endpoint"] + counts["port"],
        "external_reference_count": external,
        "format": "wsdl",
        "message_count": counts["message"],
        "operation_count": counts["operation"],
        "parse_status": "parsed",
        "service_count": counts["service"],
        "types_count": counts["types"],
        "version": "2.0" if root_name == "description" else "1.1",
    }
    return facts, flags


def _documentation_facts(path: str, text: str, media_type: str) -> dict[str, Any]:
    base = _text_facts(path, text, "documentation")
    if media_type == "text/markdown":
        base["heading_count"] = sum(
            1 for line in text.splitlines() if re.match(r"^\s{0,3}#{1,6}\s+", line)
        )
        base["link_count"] = len(re.findall(r"\[[^\]\r\n]*\]\([^\)\r\n]+\)", text))
    elif media_type == "text/html":
        base["heading_count"] = len(re.findall(r"(?i)<h[1-6](?:\s|>)", text))
        base["link_count"] = len(re.findall(r"(?i)<a(?:\s|>)", text))
    else:
        base["heading_count"] = 0
        base["link_count"] = len(re.findall(r"https?://[^\s<>'\"]+", text))
    base["format"] = PurePosixPath(path).suffix.lower().lstrip(".") or "text"
    return base


def _source_facts(path: str, text: str) -> dict[str, Any]:
    facts = _text_facts(path, text, "source")
    facts["extension"] = PurePosixPath(path).suffix.lower()
    return facts


def _text_facts(path: str, text: str, format_name: str) -> dict[str, Any]:
    del path
    lines = text.splitlines()
    return {
        "character_count": len(text),
        "format": format_name,
        "line_count": len(lines),
        "nonblank_line_count": sum(1 for line in lines if line.strip()),
        "word_count": len(re.findall(r"\S+", text)),
    }


def _scan_secrets(path: str, text: str, maximum: int) -> tuple[RedactionRecord, ...]:
    records: list[RedactionRecord] = []
    seen: set[tuple[str, int, int]] = set()
    for detector, pattern, group_name in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            start = match.start(group_name) if group_name else match.start()
            secret = match.group(group_name) if group_name else match.group(0)
            line = text.count("\n", 0, start) + 1
            last_newline = text.rfind("\n", 0, start)
            column = start - last_newline
            identity = (detector, line, column)
            if identity in seen:
                continue
            seen.add(identity)
            records.append(
                RedactionRecord(
                    path=path,
                    detector=detector,
                    line=line,
                    column=column,
                    secret_sha256=_content_sha256(secret.encode("utf-8")),
                    replacement=f"[REDACTED:{detector}]",
                )
            )
            if len(records) > maximum:
                raise TargetContextError("target context redaction count exceeds the limit")
    return tuple(
        sorted(records, key=lambda item: (item.path, item.line, item.column, item.detector))
    )


def _scan_hostile(path: str, text: str) -> tuple[QuarantineFlag, ...]:
    return tuple(
        QuarantineFlag(path, code, "high")
        for code, pattern in HOSTILE_PATTERNS
        if pattern.search(text)
    )


def _reference_counts(value: Any) -> dict[str, int]:
    internal = 0
    external = 0
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            reference = current.get("$ref")
            if isinstance(reference, str):
                if reference.startswith("#"):
                    internal += 1
                else:
                    external += 1
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return {"external": external, "internal": internal}


def _load_json(text: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise TargetContextError("JSON object contains a duplicate key")
            value[key] = item
        return value

    try:
        return json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_float=_json_float,
            parse_constant=lambda value: _raise_invalid_number(value),
        )
    except TargetContextError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise TargetContextError("JSON target context is malformed") from exc


def _raise_invalid_number(value: str) -> None:
    raise TargetContextError(f"JSON number {value!r} is not allowed")


def _json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise TargetContextError("non-finite JSON numbers are not allowed")
    return parsed


@dataclass(frozen=True)
class _YamlLine:
    indent: int
    text: str
    line_number: int


class _YamlParser:
    def __init__(self, text: str, max_depth: int) -> None:
        self.max_depth = max_depth
        self.lines = self._prepare(text)

    @staticmethod
    def _prepare(text: str) -> list[_YamlLine]:
        lines: list[_YamlLine] = []
        document_markers = 0
        for line_number, raw in enumerate(text.splitlines(), 1):
            if "\t" in raw[: len(raw) - len(raw.lstrip(" \t"))]:
                raise TargetContextError("YAML indentation cannot contain tabs")
            stripped = _strip_yaml_comment(raw).rstrip()
            if not stripped.strip():
                continue
            content = stripped.lstrip(" ")
            if content == "---":
                document_markers += 1
                if lines or document_markers > 1:
                    raise TargetContextError("multiple YAML documents are not allowed")
                continue
            if content == "...":
                continue
            if content.startswith("%"):
                raise TargetContextError("YAML directives are not allowed")
            lines.append(_YamlLine(len(stripped) - len(content), content, line_number))
        return lines

    def parse(self) -> Any:
        if not self.lines:
            raise TargetContextError("YAML target context is empty")
        if self.lines[0].indent != 0:
            raise TargetContextError("YAML root indentation is invalid")
        value, index = self._block(0, 0, 0)
        if index != len(self.lines):
            raise TargetContextError("YAML indentation is inconsistent")
        return value

    def _block(self, index: int, indent: int, depth: int) -> tuple[Any, int]:
        if depth > self.max_depth:
            raise TargetContextError("YAML structural depth exceeds the limit")
        if index >= len(self.lines) or self.lines[index].indent != indent:
            raise TargetContextError("YAML indentation is inconsistent")
        if self.lines[index].text == "-" or self.lines[index].text.startswith("- "):
            return self._sequence(index, indent, depth)
        return self._mapping(index, indent, depth)

    def _mapping(self, index: int, indent: int, depth: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            if line.indent > indent or line.text == "-" or line.text.startswith("- "):
                raise TargetContextError(f"YAML indentation is invalid at line {line.line_number}")
            key_text, value_text = _split_yaml_mapping(line.text, line.line_number)
            key = _yaml_key(key_text, line.line_number)
            if key in result:
                raise TargetContextError(
                    f"YAML mapping contains a duplicate key at line {line.line_number}"
                )
            index += 1
            value, index = self._value_after_mapping(
                value_text,
                index,
                indent,
                depth,
            )
            result[key] = value
        return result, index

    def _sequence(self, index: int, indent: int, depth: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            if line.indent != indent or not (line.text == "-" or line.text.startswith("- ")):
                raise TargetContextError(
                    f"YAML sequence indentation is invalid at line {line.line_number}"
                )
            item_text = line.text[1:].lstrip()
            index += 1
            if not item_text:
                if index >= len(self.lines) or self.lines[index].indent <= indent:
                    result.append(None)
                else:
                    child_indent = self.lines[index].indent
                    item, index = self._block(index, child_indent, depth + 1)
                    result.append(item)
                continue
            if _has_yaml_mapping_separator(item_text):
                item, index = self._sequence_mapping_item(
                    item_text,
                    line.line_number,
                    index,
                    indent,
                    depth + 1,
                )
                result.append(item)
            else:
                result.append(_yaml_scalar(item_text, line.line_number, depth + 1, self.max_depth))
                if index < len(self.lines) and self.lines[index].indent > indent:
                    raise TargetContextError("YAML scalar sequence item cannot have children")
        return result, index

    def _sequence_mapping_item(
        self,
        item_text: str,
        line_number: int,
        index: int,
        sequence_indent: int,
        depth: int,
    ) -> tuple[dict[str, Any], int]:
        key_text, value_text = _split_yaml_mapping(item_text, line_number)
        key = _yaml_key(key_text, line_number)
        result: dict[str, Any] = {}
        value, index = self._value_after_mapping(
            value_text,
            index,
            sequence_indent,
            depth,
            continuation=True,
        )
        result[key] = value
        if index >= len(self.lines) or self.lines[index].indent <= sequence_indent:
            return result, index
        mapping_indent = self.lines[index].indent
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent <= sequence_indent:
                break
            if line.indent != mapping_indent or line.text.startswith("-"):
                raise TargetContextError(
                    f"YAML mapping indentation is invalid at line {line.line_number}"
                )
            key_text, value_text = _split_yaml_mapping(line.text, line.line_number)
            key = _yaml_key(key_text, line.line_number)
            if key in result:
                raise TargetContextError(
                    f"YAML mapping contains a duplicate key at line {line.line_number}"
                )
            index += 1
            value, index = self._value_after_mapping(
                value_text,
                index,
                mapping_indent,
                depth,
            )
            result[key] = value
        return result, index

    def _value_after_mapping(
        self,
        value_text: str,
        index: int,
        parent_indent: int,
        depth: int,
        *,
        continuation: bool = False,
    ) -> tuple[Any, int]:
        if value_text in {"|", ">", "|-", ">-", "|+", ">+"}:
            pieces: list[str] = []
            while index < len(self.lines) and self.lines[index].indent > parent_indent:
                pieces.append(self.lines[index].text)
                index += 1
            separator = " " if value_text.startswith(">") else "\n"
            return separator.join(pieces), index
        if value_text:
            return _yaml_scalar(value_text, 0, depth, self.max_depth), index
        if index >= len(self.lines) or self.lines[index].indent <= parent_indent:
            return None, index
        child_indent = self.lines[index].indent
        if continuation and _has_yaml_mapping_separator(self.lines[index].text):
            return None, index
        return self._block(index, child_indent, depth + 1)


def _load_yaml(text: str, max_depth: int) -> Any:
    if YAML_UNSAFE_RE.search(text):
        raise TargetContextError("YAML tags, anchors, and aliases are not allowed")
    return _YamlParser(text, max_depth).parse()


def _strip_yaml_comment(value: str) -> str:
    single = False
    double = False
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and double:
            escaped = True
            continue
        if character == "'" and not double:
            single = not single
        elif character == '"' and not single:
            double = not double
        elif (
            character == "#"
            and not single
            and not double
            and (index == 0 or value[index - 1].isspace())
        ):
            return value[:index]
    if single or double:
        raise TargetContextError("YAML contains an unterminated quoted scalar")
    return value


def _has_yaml_mapping_separator(value: str) -> bool:
    try:
        _split_yaml_mapping(value, 0)
    except TargetContextError:
        return False
    return True


def _split_yaml_mapping(value: str, line_number: int) -> tuple[str, str]:
    single = False
    double = False
    square = 0
    curly = 0
    for index, character in enumerate(value):
        if character == "'" and not double:
            single = not single
        elif character == '"' and not single and (index == 0 or value[index - 1] != "\\"):
            double = not double
        elif not single and not double:
            if character == "[":
                square += 1
            elif character == "]":
                square -= 1
            elif character == "{":
                curly += 1
            elif character == "}":
                curly -= 1
            elif (
                character == ":"
                and square == 0
                and curly == 0
                and (index + 1 == len(value) or value[index + 1].isspace())
            ):
                key = value[:index].strip()
                if not key:
                    raise TargetContextError(f"YAML key is empty at line {line_number}")
                return key, value[index + 1 :].strip()
    raise TargetContextError(f"YAML mapping entry is malformed at line {line_number}")


def _yaml_key(value: str, line_number: int) -> str:
    parsed = _yaml_scalar(value, line_number, 0, 4)
    if not isinstance(parsed, str) or not parsed or parsed == "<<":
        raise TargetContextError(f"YAML mapping key is invalid at line {line_number}")
    return parsed


def _yaml_scalar(value: str, line_number: int, depth: int, max_depth: int) -> Any:
    if depth > max_depth:
        raise TargetContextError("YAML structural depth exceeds the limit")
    if value.startswith(("!", "&", "*")):
        raise TargetContextError("YAML tags, anchors, and aliases are not allowed")
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise TargetContextError(
                f"YAML quoted scalar is malformed at line {line_number}"
            ) from exc
        if not isinstance(parsed, str):
            raise TargetContextError("YAML quoted scalar must be text")
        return parsed
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise TargetContextError(f"YAML quoted scalar is malformed at line {line_number}")
        return value[1:-1].replace("''", "'")
    if value.startswith("[") or value.startswith("{"):
        return _yaml_flow(value, line_number, depth + 1, max_depth)
    lowered = value.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered in {"true", "false"}:
        return lowered == "true"
    if re.fullmatch(r"[-+]?(?:0|[1-9][0-9]*)", value):
        return int(value)
    if re.fullmatch(r"[-+]?(?:[0-9]+\.[0-9]*|[0-9]*\.[0-9]+)(?:e[-+]?[0-9]+)?", value, re.I):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise TargetContextError("non-finite YAML numbers are not allowed")
        return parsed
    return value


def _yaml_flow(value: str, line_number: int, depth: int, max_depth: int) -> Any:
    if depth > max_depth:
        raise TargetContextError("YAML structural depth exceeds the limit")
    if value.startswith("["):
        if not value.endswith("]"):
            raise TargetContextError(f"YAML flow sequence is malformed at line {line_number}")
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [
            _yaml_scalar(item.strip(), line_number, depth + 1, max_depth)
            for item in _split_flow_items(inner, line_number)
        ]
    if not value.endswith("}"):
        raise TargetContextError(f"YAML flow mapping is malformed at line {line_number}")
    inner = value[1:-1].strip()
    if not inner:
        return {}
    result: dict[str, Any] = {}
    for item in _split_flow_items(inner, line_number):
        key_text, value_text = _split_yaml_mapping(item.strip(), line_number)
        key = _yaml_key(key_text, line_number)
        if key in result:
            raise TargetContextError(f"YAML flow mapping has a duplicate key at line {line_number}")
        result[key] = _yaml_scalar(value_text, line_number, depth + 1, max_depth)
    return result


def _split_flow_items(value: str, line_number: int) -> list[str]:
    items: list[str] = []
    start = 0
    square = 0
    curly = 0
    single = False
    double = False
    for index, character in enumerate(value):
        if character == "'" and not double:
            single = not single
        elif character == '"' and not single and (index == 0 or value[index - 1] != "\\"):
            double = not double
        elif not single and not double:
            if character == "[":
                square += 1
            elif character == "]":
                square -= 1
            elif character == "{":
                curly += 1
            elif character == "}":
                curly -= 1
            elif character == "," and square == 0 and curly == 0:
                items.append(value[start:index])
                start = index + 1
        if square < 0 or curly < 0:
            raise TargetContextError(f"YAML flow collection is malformed at line {line_number}")
    if single or double or square or curly:
        raise TargetContextError(f"YAML flow collection is malformed at line {line_number}")
    items.append(value[start:])
    if any(not item.strip() for item in items):
        raise TargetContextError(f"YAML flow collection is malformed at line {line_number}")
    return items


def _decode_text(content: bytes, path: str) -> str:
    if b"\x00" in content:
        raise TargetContextError(f"target context text contains a NUL byte: {path}")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise TargetContextError(f"target context text is not valid UTF-8: {path}") from exc


def _normalize_path(value: Any, limits: TargetContextLimits) -> str:
    if not isinstance(value, str) or not value:
        raise TargetContextError("target context path must be nonempty text")
    if len(value) > limits.max_path_length or not value.isascii():
        raise TargetContextError("target context path must be short portable ASCII text")
    if "\\" in value or "\x00" in value or ":" in value:
        raise TargetContextError("target context path must use portable separators")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts:
        raise TargetContextError("target context path must be relative")
    for part in path.parts:
        if part in {"", ".", ".."} or part.endswith((" ", ".")):
            raise TargetContextError("target context path contains an unsafe segment")
        if any(character in '<>"|?*' or ord(character) < 32 for character in part):
            raise TargetContextError("target context path contains an unsafe character")
        if part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES:
            raise TargetContextError("target context path contains a reserved name")
    normalized = path.as_posix()
    if normalized != value:
        raise TargetContextError("target context path is not normalized")
    return normalized


def _directory_manifest_sha256(
    records: Sequence[TargetContextInput],
    limits: TargetContextLimits,
) -> str:
    manifest = [
        {
            "path": _normalize_path(item.name, limits),
            "sha256": _content_sha256(item.content),
            "size_bytes": len(item.content),
        }
        for item in records
    ]
    manifest.sort(key=lambda item: item["path"])
    return _canonical_sha256({"domain": DIRECTORY_MANIFEST_DOMAIN, "files": manifest})


def _summary(
    inputs: Sequence[TargetInputRecord],
    artifacts: Sequence[TargetArtifact],
    redactions: Sequence[RedactionRecord],
    flags: Sequence[QuarantineFlag],
) -> dict[str, Any]:
    kind_counts = Counter(item.kind for item in artifacts)
    return {
        "artifact_bytes": sum(item.size_bytes for item in artifacts),
        "artifact_count": len(artifacts),
        "input_bytes": sum(item.size_bytes for item in inputs),
        "input_count": len(inputs),
        "kind_counts": dict(sorted(kind_counts.items())),
        "quarantine_flag_count": len(flags),
        "quarantined_artifact_count": sum(item.quarantined for item in artifacts),
        "redaction_count": len(redactions),
    }


def _require_path_order(paths: tuple[str, ...], label: str) -> None:
    if paths != tuple(sorted(paths)) or len({item.casefold() for item in paths}) != len(paths):
        raise TargetContextError(f"{label} must have unique sorted paths")


def _require_finding_order(
    redactions: tuple[RedactionRecord, ...],
    flags: tuple[QuarantineFlag, ...],
) -> None:
    expected_redactions = tuple(
        sorted(redactions, key=lambda item: (item.path, item.line, item.column, item.detector))
    )
    expected_flags = tuple(sorted(flags, key=lambda item: (item.path, item.code, item.severity)))
    if (
        redactions != expected_redactions
        or flags != expected_flags
        or len(set(flags)) != len(flags)
    ):
        raise TargetContextError("target context findings must be unique and sorted")


def _validate_json_depth(value: Any, maximum: int) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise TargetContextError("target context structural depth exceeds the limit")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _xml_local_name(tag: Any) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _provenance(
    value: TargetContextProvenance | Mapping[str, Any],
) -> TargetContextProvenance:
    if isinstance(value, TargetContextProvenance):
        return TargetContextProvenance.from_dict(value.to_dict())
    if isinstance(value, Mapping):
        return TargetContextProvenance.from_dict(dict(value))
    raise TargetContextError("target context provenance is required")


def _limits(value: TargetContextLimits | None) -> TargetContextLimits:
    if value is None:
        return TargetContextLimits()
    if not isinstance(value, TargetContextLimits):
        raise TargetContextError("target context limits must be TargetContextLimits")
    return TargetContextLimits.from_dict(value.to_dict())


def _kind(value: Any) -> TargetContextKind:
    if isinstance(value, TargetContextKind):
        return value
    try:
        return TargetContextKind(value)
    except (TypeError, ValueError) as exc:
        raise TargetContextError("target context kind is invalid") from exc


def _media_type(value: Any) -> str:
    if not isinstance(value, str):
        raise TargetContextError("target context media type must be text")
    normalized = value.split(";", 1)[0].strip().lower()
    if normalized not in ALLOWED_MEDIA_TYPES:
        raise TargetContextError("target context media type is not allowed")
    return normalized


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise TargetContextError(f"{label} is invalid")
    return value


def _ascii_token(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) is None
    ):
        raise TargetContextError(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TargetContextError(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise TargetContextError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise TargetContextError(f"{label} must be whole-second UTC")
    return parsed


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TargetContextError(f"{label} must be a positive integer")
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TargetContextError(f"{label} must be a nonnegative integer")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise TargetContextError(f"{label} must be a SHA-256 digest")
    return value


def _content_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise TargetContextError("target context data is not canonically serializable") from exc


def _canonical_sha256(value: Any) -> str:
    return _content_sha256(_canonical_json(value).encode("ascii"))


def _require_exact_fields(raw: Any, expected: set[str], label: str) -> None:
    if not isinstance(raw, dict) or set(raw) != expected:
        raise TargetContextError(f"{label} fields are invalid")


__all__ = [
    "BUNDLE_DOMAIN",
    "PARSER_POLICY",
    "RedactionRecord",
    "QuarantineFlag",
    "TargetArtifact",
    "TargetContextBundle",
    "TargetContextError",
    "TargetContextInput",
    "TargetContextKind",
    "TargetContextLimits",
    "TargetContextProvenance",
    "TargetInputRecord",
    "build_target_context_bundle",
    "ingest_target_context_bytes",
    "ingest_target_context_directory",
    "ingest_target_context_inputs",
]
