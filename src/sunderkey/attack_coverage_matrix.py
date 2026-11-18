"""Deterministic, effect-free attack coverage matrix contracts.

The module classifies caller-supplied catalog and specialist references. It
does not inspect targets, execute techniques, authorize actions, or claim live
validation, production readiness, or competitive parity.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MATRIX_DOMAIN = "sunderkey.attack-coverage-matrix.v1"
MAX_ROWS = 10_000

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credential_access": "none",
        "deployment": "none",
        "execution": "none",
        "filesystem_write": "none",
        "live_validation": "none",
        "network": "none",
        "qualification": "none",
        "target_interaction": "none",
    }
)

NO_CLAIMS = MappingProxyType(
    {
        "authorization": "not_claimed",
        "competitive_parity": "not_claimed",
        "live_validation": "not_claimed",
        "production_readiness": "not_claimed",
    }
)

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTENT_ID_RE = re.compile(r"[A-Z]{3}-[0-9A-F]{32}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z")
_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[+.-][A-Za-z0-9.]+)?\Z")
_MOVING_VERSIONS = frozenset(
    {"current", "head", "latest", "main", "master", "rolling", "stable", "tip", "trunk"}
)
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:authorization|cookie|password|passwd|secret|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|client[_-]?secret)\b\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)
_PAYLOAD_RE = re.compile(
    r"(?:<script\b|javascript:|powershell(?:\.exe)?\b|cmd(?:\.exe)?\s+/c\b|"
    r"\b(?:curl|wget|nc|ncat|netcat)\s+|\brm\s+-[a-z]*r[a-z]*f\b|"
    r"(?:;|&&|\|\||\|)\s*[A-Za-z0-9./\\])",
    re.IGNORECASE,
)


class AttackCoverageMatrixError(ValueError):
    """Raised when matrix inputs or serialized documents fail closed."""


class AttackDomain(StrEnum):
    WEB = "web"
    API = "api"
    IDENTITY = "identity"
    CLOUD = "cloud"
    CONTAINERS = "containers"
    KUBERNETES = "kubernetes"
    CI_CD = "ci_cd"
    SOURCE_DEPENDENCY_SUPPLY_CHAIN = "source_dependency_supply_chain"
    MOBILE = "mobile"
    DESKTOP_THICK_CLIENT = "desktop_thick_client"
    NETWORK = "network"
    WIRELESS = "wireless"
    HARDWARE_FIRMWARE = "hardware_firmware"
    OT_ICS = "ot_ics"
    AI_ML = "ai_ml"
    BLOCKCHAIN = "blockchain"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL = "physical"
    CRYPTOGRAPHIC_PKI = "cryptographic_pki"
    MULTI_STAGE_CHAINING = "multi_stage_chaining"


class EvidenceGrade(StrEnum):
    NONE = "none"
    CATALOG_ONLY = "catalog_only"
    REPOSITORY_CONTRACT = "repository_contract"
    OFFLINE_DETERMINISTIC = "offline_deterministic"


class CoverageStatus(StrEnum):
    REPOSITORY_COVERED = "repository_covered"
    PARTIAL = "partial"
    GAP = "gap"
    BLOCKED = "blocked"


class BlockedReason(StrEnum):
    CAPABILITY_MISSING = "capability_missing"
    EVIDENCE_MISSING = "evidence_missing"
    EXTERNAL_IDENTITY_REQUIRED = "external_identity_required"
    INDEPENDENT_REVIEW_REQUIRED = "independent_review_required"
    INFRASTRUCTURE_REQUIRED = "infrastructure_required"
    LIVE_TARGET_REQUIRED = "live_target_required"
    POLICY_DECISION_REQUIRED = "policy_decision_required"


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 18:
        raise AttackCoverageMatrixError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AttackCoverageMatrixError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise AttackCoverageMatrixError(f"{label} contains an unsupported value")


def canonical_json(value: Any) -> str:
    """Return printable ASCII JSON with stable ordering and no secret material."""

    _validate_json(value, "value")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise AttackCoverageMatrixError("value is not canonical JSON") from exc
    if _SECRET_RE.search(encoded):
        raise AttackCoverageMatrixError("secret-like material is forbidden")
    if _PAYLOAD_RE.search(encoded):
        raise AttackCoverageMatrixError("executable payload material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise AttackCoverageMatrixError(f"{label} fields do not match the contract")
    return raw


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttackCoverageMatrixError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise AttackCoverageMatrixError(f"{label} must be a sequence")
    return value


def _safe_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 500:
        raise AttackCoverageMatrixError(f"{label} must be nonempty text")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AttackCoverageMatrixError(f"{label} must be ASCII") from exc
    if _SECRET_RE.search(value):
        raise AttackCoverageMatrixError(f"{label} contains secret-like material")
    if _PAYLOAD_RE.search(value) or "\n" in value or "\r" in value:
        raise AttackCoverageMatrixError(f"{label} contains executable payload material")
    return value


def _identifier(value: Any, label: str, *, namespace: str | None = None) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise AttackCoverageMatrixError(f"{label} must be a safe identifier")
    _safe_text(value, label)
    if namespace is not None and not value.startswith(namespace + ":"):
        raise AttackCoverageMatrixError(f"{label} must use the {namespace} namespace")
    return value


def _version(value: Any, label: str) -> str:
    text = _safe_text(value, label)
    if text.lower() in _MOVING_VERSIONS or _VERSION_RE.fullmatch(text) is None:
        raise AttackCoverageMatrixError(f"{label} must be an exact version")
    return text


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AttackCoverageMatrixError(f"{label} must be a sha256 digest")
    return value


def _content_id(value: Any, label: str, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or _CONTENT_ID_RE.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        raise AttackCoverageMatrixError(f"{label} is invalid")
    return value


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise AttackCoverageMatrixError(f"{label} is unknown") from exc


def _unique_text_tuple(
    value: Any,
    label: str,
    *,
    identifier: bool = False,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    items = tuple(_sequence(value, label))
    converted = tuple(
        _identifier(item, label) if identifier else _safe_text(item, label) for item in items
    )
    if not allow_empty and not converted:
        raise AttackCoverageMatrixError(f"{label} must not be empty")
    if len(converted) != len(set(converted)):
        raise AttackCoverageMatrixError(f"{label} contains duplicates")
    return tuple(sorted(converted))


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


@dataclass(frozen=True, slots=True)
class TechniqueReference:
    tenant_ref: str
    context_ref: str
    scope_sha256: str
    catalog_ref: str
    catalog_version: str
    technique_ref: str
    technique_version: str
    domain: AttackDomain | str
    asset_types: tuple[str, ...]
    reference_id: str = field(init=False)
    reference_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.attack-technique-reference.v1"

    def __post_init__(self) -> None:
        _identifier(self.tenant_ref, "tenant_ref", namespace="tenantref")
        _identifier(self.context_ref, "context_ref", namespace="contextref")
        _sha256(self.scope_sha256, "scope_sha256")
        _identifier(self.catalog_ref, "catalog_ref", namespace="catalogref")
        _version(self.catalog_version, "catalog_version")
        _identifier(self.technique_ref, "technique_ref", namespace="techniqueref")
        _version(self.technique_version, "technique_version")
        object.__setattr__(self, "domain", _enum(AttackDomain, self.domain, "domain"))
        asset_types = _unique_text_tuple(
            self.asset_types, "asset_types", identifier=True, allow_empty=False
        )
        for asset_type in asset_types:
            _identifier(asset_type, "asset_type", namespace="assettype")
        object.__setattr__(self, "asset_types", asset_types)
        identity, digest = _identity("ATR", self.KIND, self.body())
        object.__setattr__(self, "reference_id", identity)
        object.__setattr__(self, "reference_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "asset_types": list(self.asset_types),
            "catalog_ref": self.catalog_ref,
            "catalog_version": self.catalog_version,
            "context_ref": self.context_ref,
            "domain": self.domain.value,
            "scope_sha256": self.scope_sha256,
            "technique_ref": self.technique_ref,
            "technique_version": self.technique_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "reference_id": self.reference_id,
            "reference_sha256": self.reference_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TechniqueReference:
        item = dict(
            _exact(
                raw,
                {
                    "asset_types",
                    "catalog_ref",
                    "catalog_version",
                    "context_ref",
                    "domain",
                    "reference_id",
                    "reference_sha256",
                    "scope_sha256",
                    "technique_ref",
                    "technique_version",
                    "tenant_ref",
                },
                "technique reference",
            )
        )
        identity = _content_id(item.pop("reference_id"), "reference_id", "ATR")
        digest = _sha256(item.pop("reference_sha256"), "reference_sha256")
        item["asset_types"] = tuple(_sequence(item["asset_types"], "asset_types"))
        result = cls(**item)
        if result.reference_id != identity or result.reference_sha256 != digest:
            raise AttackCoverageMatrixError("technique reference content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class SpecialistCapabilityReference:
    tenant_ref: str
    context_ref: str
    scope_sha256: str
    specialist_ref: str
    specialist_version: str
    capability_ref: str
    capability_version: str
    domains: tuple[AttackDomain | str, ...]
    evidence_grade: EvidenceGrade | str
    evidence_sha256: str | None
    reference_id: str = field(init=False)
    reference_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.specialist-capability-reference.v1"

    def __post_init__(self) -> None:
        _identifier(self.tenant_ref, "tenant_ref", namespace="tenantref")
        _identifier(self.context_ref, "context_ref", namespace="contextref")
        _sha256(self.scope_sha256, "scope_sha256")
        _identifier(self.specialist_ref, "specialist_ref", namespace="specialistref")
        _version(self.specialist_version, "specialist_version")
        _identifier(self.capability_ref, "capability_ref", namespace="capabilityref")
        _version(self.capability_version, "capability_version")
        domains = tuple(
            sorted(
                (_enum(AttackDomain, item, "domains") for item in self.domains),
                key=lambda item: item.value,
            )
        )
        if not domains or len(domains) != len(set(domains)):
            raise AttackCoverageMatrixError("domains must be nonempty and unique")
        object.__setattr__(self, "domains", domains)
        grade = _enum(EvidenceGrade, self.evidence_grade, "evidence_grade")
        object.__setattr__(self, "evidence_grade", grade)
        if grade is EvidenceGrade.NONE:
            if self.evidence_sha256 is not None:
                raise AttackCoverageMatrixError("none evidence grade cannot bind evidence")
        elif self.evidence_sha256 is None:
            raise AttackCoverageMatrixError("graded capability requires evidence digest")
        else:
            _sha256(self.evidence_sha256, "evidence_sha256")
        identity, digest = _identity("SCR", self.KIND, self.body())
        object.__setattr__(self, "reference_id", identity)
        object.__setattr__(self, "reference_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "capability_ref": self.capability_ref,
            "capability_version": self.capability_version,
            "context_ref": self.context_ref,
            "domains": [item.value for item in self.domains],
            "evidence_grade": self.evidence_grade.value,
            "evidence_sha256": self.evidence_sha256,
            "scope_sha256": self.scope_sha256,
            "specialist_ref": self.specialist_ref,
            "specialist_version": self.specialist_version,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "reference_id": self.reference_id,
            "reference_sha256": self.reference_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SpecialistCapabilityReference:
        item = dict(
            _exact(
                raw,
                {
                    "capability_ref",
                    "capability_version",
                    "context_ref",
                    "domains",
                    "evidence_grade",
                    "evidence_sha256",
                    "reference_id",
                    "reference_sha256",
                    "scope_sha256",
                    "specialist_ref",
                    "specialist_version",
                    "tenant_ref",
                },
                "specialist capability reference",
            )
        )
        identity = _content_id(item.pop("reference_id"), "reference_id", "SCR")
        digest = _sha256(item.pop("reference_sha256"), "reference_sha256")
        item["domains"] = tuple(_sequence(item["domains"], "domains"))
        result = cls(**item)
        if result.reference_id != identity or result.reference_sha256 != digest:
            raise AttackCoverageMatrixError("specialist reference content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class CoverageMapping:
    mapping_key: str
    technique_reference_id: str
    specialist_reference_ids: tuple[str, ...]
    status: CoverageStatus | str
    prerequisite_refs: tuple[str, ...]
    negative_space_gaps: tuple[str, ...]
    blocked_reasons: tuple[BlockedReason | str, ...]

    def __post_init__(self) -> None:
        _identifier(self.mapping_key, "mapping_key", namespace="mapping")
        _content_id(self.technique_reference_id, "technique_reference_id", "ATR")
        specialist_ids = _unique_text_tuple(
            self.specialist_reference_ids,
            "specialist_reference_ids",
            identifier=True,
        )
        for reference_id in specialist_ids:
            _content_id(reference_id, "specialist_reference_id", "SCR")
        object.__setattr__(self, "specialist_reference_ids", specialist_ids)
        status = _enum(CoverageStatus, self.status, "status")
        object.__setattr__(self, "status", status)
        object.__setattr__(
            self,
            "prerequisite_refs",
            _unique_text_tuple(self.prerequisite_refs, "prerequisite_refs", identifier=True),
        )
        object.__setattr__(
            self,
            "negative_space_gaps",
            _unique_text_tuple(self.negative_space_gaps, "negative_space_gaps"),
        )
        reasons = tuple(
            sorted(
                (_enum(BlockedReason, item, "blocked_reasons") for item in self.blocked_reasons),
                key=lambda item: item.value,
            )
        )
        if len(reasons) != len(set(reasons)):
            raise AttackCoverageMatrixError("blocked_reasons contains duplicates")
        object.__setattr__(self, "blocked_reasons", reasons)
        self._validate_state()

    def _validate_state(self) -> None:
        if self.status is CoverageStatus.REPOSITORY_COVERED:
            if (
                not self.specialist_reference_ids
                or self.negative_space_gaps
                or self.blocked_reasons
            ):
                raise AttackCoverageMatrixError("repository covered mapping is inconsistent")
        elif self.status is CoverageStatus.PARTIAL:
            if not self.specialist_reference_ids or not self.negative_space_gaps:
                raise AttackCoverageMatrixError("partial mapping is inconsistent")
        elif self.status is CoverageStatus.GAP:
            if self.specialist_reference_ids or not self.negative_space_gaps:
                raise AttackCoverageMatrixError("gap mapping is inconsistent")
            if not set(self.blocked_reasons).intersection(
                {BlockedReason.CAPABILITY_MISSING, BlockedReason.EVIDENCE_MISSING}
            ):
                raise AttackCoverageMatrixError("gap mapping requires a missing reason")
        elif self.status is CoverageStatus.BLOCKED and (
            not self.negative_space_gaps or not self.blocked_reasons
        ):
            raise AttackCoverageMatrixError("blocked mapping is inconsistent")


_GRADE_RANK = {
    EvidenceGrade.NONE: 0,
    EvidenceGrade.CATALOG_ONLY: 1,
    EvidenceGrade.REPOSITORY_CONTRACT: 2,
    EvidenceGrade.OFFLINE_DETERMINISTIC: 3,
}


@dataclass(frozen=True, slots=True)
class CoverageRow:
    mapping_key: str
    domain: AttackDomain
    asset_types: tuple[str, ...]
    technique_reference: TechniqueReference
    specialist_references: tuple[SpecialistCapabilityReference, ...]
    status: CoverageStatus
    evidence_grade: EvidenceGrade
    prerequisite_refs: tuple[str, ...]
    negative_space_gaps: tuple[str, ...]
    blocked_reasons: tuple[BlockedReason, ...]
    row_id: str = field(init=False)
    row_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.attack-coverage-row.v1"

    def __post_init__(self) -> None:
        identity, digest = _identity("ACR", self.KIND, self.body())
        object.__setattr__(self, "row_id", identity)
        object.__setattr__(self, "row_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "asset_types": list(self.asset_types),
            "blocked_reasons": [item.value for item in self.blocked_reasons],
            "domain": self.domain.value,
            "evidence_grade": self.evidence_grade.value,
            "mapping_key": self.mapping_key,
            "negative_space_gaps": list(self.negative_space_gaps),
            "prerequisite_refs": list(self.prerequisite_refs),
            "specialist_references": [item.to_dict() for item in self.specialist_references],
            "status": self.status.value,
            "technique_reference": self.technique_reference.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "row_id": self.row_id, "row_sha256": self.row_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> CoverageRow:
        item = dict(
            _exact(
                raw,
                {
                    "asset_types",
                    "blocked_reasons",
                    "domain",
                    "evidence_grade",
                    "mapping_key",
                    "negative_space_gaps",
                    "prerequisite_refs",
                    "row_id",
                    "row_sha256",
                    "specialist_references",
                    "status",
                    "technique_reference",
                },
                "coverage row",
            )
        )
        identity = _content_id(item.pop("row_id"), "row_id", "ACR")
        digest = _sha256(item.pop("row_sha256"), "row_sha256")
        technique = TechniqueReference.from_dict(item.pop("technique_reference"))
        specialists = tuple(
            SpecialistCapabilityReference.from_dict(value)
            for value in _sequence(item.pop("specialist_references"), "specialist_references")
        )
        mapping = CoverageMapping(
            mapping_key=item["mapping_key"],
            technique_reference_id=technique.reference_id,
            specialist_reference_ids=tuple(value.reference_id for value in specialists),
            status=item["status"],
            prerequisite_refs=tuple(_sequence(item["prerequisite_refs"], "prerequisite_refs")),
            negative_space_gaps=tuple(
                _sequence(item["negative_space_gaps"], "negative_space_gaps")
            ),
            blocked_reasons=tuple(_sequence(item["blocked_reasons"], "blocked_reasons")),
        )
        result = _build_row(technique, specialists, mapping)
        if list(result.asset_types) != item["asset_types"]:
            raise AttackCoverageMatrixError("coverage row asset types do not match")
        if (
            result.domain.value != item["domain"]
            or result.evidence_grade.value != item["evidence_grade"]
        ):
            raise AttackCoverageMatrixError("coverage row derived values do not match")
        if result.row_id != identity or result.row_sha256 != digest:
            raise AttackCoverageMatrixError("coverage row content address is invalid")
        return result


def _build_row(
    technique: TechniqueReference,
    specialists: tuple[SpecialistCapabilityReference, ...],
    mapping: CoverageMapping,
) -> CoverageRow:
    if technique.reference_id != mapping.technique_reference_id:
        raise AttackCoverageMatrixError("mapping technique reference does not match")
    specialists = tuple(sorted(specialists, key=lambda item: item.reference_id))
    if tuple(item.reference_id for item in specialists) != mapping.specialist_reference_ids:
        raise AttackCoverageMatrixError("mapping specialist references do not match")
    for specialist in specialists:
        if technique.domain not in specialist.domains:
            raise AttackCoverageMatrixError("specialist does not cover the mapped domain")
    grade = (
        min((item.evidence_grade for item in specialists), key=_GRADE_RANK.__getitem__)
        if specialists
        else EvidenceGrade.NONE
    )
    if mapping.status is CoverageStatus.REPOSITORY_COVERED and grade not in {
        EvidenceGrade.REPOSITORY_CONTRACT,
        EvidenceGrade.OFFLINE_DETERMINISTIC,
    }:
        raise AttackCoverageMatrixError("repository covered mapping lacks repository evidence")
    return CoverageRow(
        mapping.mapping_key,
        technique.domain,
        technique.asset_types,
        technique,
        specialists,
        mapping.status,
        grade,
        mapping.prerequisite_refs,
        mapping.negative_space_gaps,
        mapping.blocked_reasons,
    )


@dataclass(frozen=True, slots=True)
class AttackCoverageMatrix:
    tenant_ref: str
    context_ref: str
    scope_sha256: str
    rows: tuple[CoverageRow, ...]
    summary: Mapping[str, Any]
    matrix_id: str
    matrix_sha256: str
    document_json: str = field(repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> AttackCoverageMatrix:
        document = dict(
            _exact(
                raw,
                {
                    "claims",
                    "context_ref",
                    "effects",
                    "matrix_id",
                    "matrix_sha256",
                    "rows",
                    "schema_version",
                    "scope_sha256",
                    "summary",
                    "tenant_ref",
                },
                "attack coverage matrix",
            )
        )
        if document["schema_version"] != SCHEMA_VERSION:
            raise AttackCoverageMatrixError("schema_version is unsupported")
        if document["effects"] != dict(NO_EFFECTS) or document["claims"] != dict(NO_CLAIMS):
            raise AttackCoverageMatrixError("matrix boundary fields are invalid")
        rows = tuple(CoverageRow.from_dict(value) for value in _sequence(document["rows"], "rows"))
        result = _assemble_matrix(rows)
        if (
            result.tenant_ref != document["tenant_ref"]
            or result.context_ref != document["context_ref"]
            or result.scope_sha256 != document["scope_sha256"]
            or result.summary != document["summary"]
            or result.matrix_id != document["matrix_id"]
            or result.matrix_sha256 != document["matrix_sha256"]
        ):
            raise AttackCoverageMatrixError("matrix content address or derived values are invalid")
        return result

    @classmethod
    def from_json(cls, value: str) -> AttackCoverageMatrix:
        if not isinstance(value, str):
            raise AttackCoverageMatrixError("matrix JSON must be text")
        try:
            raw = json.loads(value, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AttackCoverageMatrixError("matrix JSON is invalid") from exc
        result = cls.from_dict(raw)
        if value != result.document_json:
            raise AttackCoverageMatrixError("matrix JSON is not canonical")
        return result


def _summary(rows: tuple[CoverageRow, ...]) -> dict[str, Any]:
    domain_counts = Counter(row.domain.value for row in rows)
    status_counts = Counter(row.status.value for row in rows)
    grade_counts = Counter(row.evidence_grade.value for row in rows)
    reasons = Counter(reason.value for row in rows for reason in row.blocked_reasons)
    return {
        "asset_type_count": len({asset for row in rows for asset in row.asset_types}),
        "blocked_reason_counts": dict(sorted(reasons.items())),
        "domain_counts": dict(sorted(domain_counts.items())),
        "evidence_grade_counts": dict(sorted(grade_counts.items())),
        "negative_space_gap_count": sum(len(row.negative_space_gaps) for row in rows),
        "row_count": len(rows),
        "specialist_reference_count": len(
            {item.reference_id for row in rows for item in row.specialist_references}
        ),
        "status_counts": dict(sorted(status_counts.items())),
        "technique_reference_count": len({row.technique_reference.reference_id for row in rows}),
    }


def _assemble_matrix(rows: tuple[CoverageRow, ...]) -> AttackCoverageMatrix:
    rows = tuple(sorted(rows, key=lambda row: (row.domain.value, row.mapping_key)))
    if not rows or len(rows) > MAX_ROWS:
        raise AttackCoverageMatrixError("matrix row count is outside the supported range")
    if len(rows) != len({row.mapping_key for row in rows}):
        raise AttackCoverageMatrixError("mapping keys must be unique")
    if len(rows) != len({row.technique_reference.reference_id for row in rows}):
        raise AttackCoverageMatrixError("technique references must map exactly once")
    scopes = {
        (
            row.technique_reference.tenant_ref,
            row.technique_reference.context_ref,
            row.technique_reference.scope_sha256,
        )
        for row in rows
    }
    scopes.update(
        (item.tenant_ref, item.context_ref, item.scope_sha256)
        for row in rows
        for item in row.specialist_references
    )
    if len(scopes) != 1:
        raise AttackCoverageMatrixError("references cross tenant, context, or scope boundaries")
    tenant_ref, context_ref, scope_sha256 = next(iter(scopes))
    summary = _summary(rows)
    unsigned = {
        "claims": dict(NO_CLAIMS),
        "context_ref": context_ref,
        "effects": dict(NO_EFFECTS),
        "rows": [row.to_dict() for row in rows],
        "schema_version": SCHEMA_VERSION,
        "scope_sha256": scope_sha256,
        "summary": summary,
        "tenant_ref": tenant_ref,
    }
    matrix_id, digest = _identity("ACM", MATRIX_DOMAIN, unsigned)
    document = {**unsigned, "matrix_id": matrix_id, "matrix_sha256": digest}
    document_json = canonical_json(document)
    return AttackCoverageMatrix(
        tenant_ref,
        context_ref,
        scope_sha256,
        rows,
        MappingProxyType(summary),
        matrix_id,
        digest,
        document_json,
    )


def build_attack_coverage_matrix(
    *,
    technique_references: Sequence[TechniqueReference],
    specialist_references: Sequence[SpecialistCapabilityReference],
    mappings: Sequence[CoverageMapping],
) -> AttackCoverageMatrix:
    """Build one matrix after validating every key, reference, and boundary."""

    techniques = tuple(technique_references)
    specialists = tuple(specialist_references)
    mappings = tuple(mappings)
    if len(techniques) != len({item.reference_id for item in techniques}):
        raise AttackCoverageMatrixError("duplicate technique reference")
    if len(specialists) != len({item.reference_id for item in specialists}):
        raise AttackCoverageMatrixError("duplicate specialist reference")
    if len(mappings) != len({item.mapping_key for item in mappings}):
        raise AttackCoverageMatrixError("duplicate mapping key")
    if len(mappings) != len({item.technique_reference_id for item in mappings}):
        raise AttackCoverageMatrixError("duplicate technique mapping")
    technique_index = {item.reference_id: item for item in techniques}
    specialist_index = {item.reference_id: item for item in specialists}
    if set(technique_index) != {item.technique_reference_id for item in mappings}:
        raise AttackCoverageMatrixError("technique references and mappings differ")
    used_specialists = {ref for item in mappings for ref in item.specialist_reference_ids}
    if set(specialist_index) != used_specialists:
        raise AttackCoverageMatrixError("specialist references and mappings differ")
    rows: list[CoverageRow] = []
    for mapping in mappings:
        try:
            technique = technique_index[mapping.technique_reference_id]
            selected = tuple(specialist_index[key] for key in mapping.specialist_reference_ids)
        except KeyError as exc:
            raise AttackCoverageMatrixError("mapping references an unknown key") from exc
        rows.append(_build_row(technique, selected, mapping))
    return _assemble_matrix(tuple(rows))


def verify_attack_coverage_matrix(
    value: AttackCoverageMatrix | Mapping[str, Any] | str,
) -> AttackCoverageMatrix:
    """Strictly parse and verify an in-memory or serialized matrix."""

    if isinstance(value, AttackCoverageMatrix):
        return AttackCoverageMatrix.from_json(value.document_json)
    if isinstance(value, str):
        return AttackCoverageMatrix.from_json(value)
    return AttackCoverageMatrix.from_dict(value)


_DOMAIN_TEMPLATES: tuple[
    tuple[AttackDomain, str, str, tuple[str, ...], CoverageStatus, str, BlockedReason | None],
    ...,
] = (
    (
        AttackDomain.WEB,
        "web-input-boundaries",
        "web-testing",
        ("assettype:web-application",),
        CoverageStatus.PARTIAL,
        "Live browser and target validation remain unobserved.",
        BlockedReason.LIVE_TARGET_REQUIRED,
    ),
    (
        AttackDomain.API,
        "api-contract-abuse",
        "api-testing",
        ("assettype:http-api", "assettype:graphql-api"),
        CoverageStatus.PARTIAL,
        "Live service behavior remains unobserved.",
        BlockedReason.LIVE_TARGET_REQUIRED,
    ),
    (
        AttackDomain.IDENTITY,
        "identity-boundary-abuse",
        "identity-testing",
        ("assettype:identity-provider",),
        CoverageStatus.PARTIAL,
        "External identity integration remains unobserved.",
        BlockedReason.EXTERNAL_IDENTITY_REQUIRED,
    ),
    (
        AttackDomain.CLOUD,
        "cloud-control-plane",
        "cloud-testing",
        ("assettype:cloud-account",),
        CoverageStatus.PARTIAL,
        "Provider control plane behavior remains unobserved.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.CONTAINERS,
        "container-boundaries",
        "container-testing",
        ("assettype:container-image",),
        CoverageStatus.PARTIAL,
        "Runtime isolation behavior remains unobserved.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.KUBERNETES,
        "orchestrator-boundaries",
        "kubernetes-testing",
        ("assettype:kubernetes-cluster",),
        CoverageStatus.PARTIAL,
        "Cluster admission and runtime behavior remain unobserved.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.CI_CD,
        "pipeline-trust-boundaries",
        "pipeline-testing",
        ("assettype:ci-cd-pipeline",),
        CoverageStatus.PARTIAL,
        "Hosted pipeline behavior remains unobserved.",
        BlockedReason.EXTERNAL_IDENTITY_REQUIRED,
    ),
    (
        AttackDomain.SOURCE_DEPENDENCY_SUPPLY_CHAIN,
        "dependency-trust-boundaries",
        "supply-chain-testing",
        ("assettype:source-repository", "assettype:software-package"),
        CoverageStatus.PARTIAL,
        "Registry and build provenance remain unobserved.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.MOBILE,
        "mobile-client-boundaries",
        "mobile-testing",
        ("assettype:mobile-application",),
        CoverageStatus.PARTIAL,
        "Device and application runtime behavior remain unobserved.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.DESKTOP_THICK_CLIENT,
        "desktop-client-boundaries",
        "desktop-testing",
        ("assettype:desktop-application",),
        CoverageStatus.PARTIAL,
        "Desktop runtime behavior remains unobserved.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.NETWORK,
        "network-service-boundaries",
        "network-testing",
        ("assettype:network-service",),
        CoverageStatus.PARTIAL,
        "Live network service behavior remains unobserved.",
        BlockedReason.LIVE_TARGET_REQUIRED,
    ),
    (
        AttackDomain.WIRELESS,
        "wireless-boundaries",
        "wireless-testing",
        ("assettype:wireless-network",),
        CoverageStatus.BLOCKED,
        "Radio hardware and isolated spectrum remain unavailable.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.HARDWARE_FIRMWARE,
        "firmware-trust-boundaries",
        "firmware-testing",
        ("assettype:firmware-image", "assettype:hardware-device"),
        CoverageStatus.BLOCKED,
        "Representative hardware and isolated instrumentation remain unavailable.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.OT_ICS,
        "industrial-control-boundaries",
        "ot-ics-testing",
        ("assettype:industrial-control-system",),
        CoverageStatus.BLOCKED,
        "A safety-governed industrial test environment remains unavailable.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.AI_ML,
        "model-and-agent-boundaries",
        "ai-ml-testing",
        ("assettype:model-endpoint", "assettype:agent-workflow"),
        CoverageStatus.PARTIAL,
        "Deployed model and tool behavior remain unobserved.",
        BlockedReason.LIVE_TARGET_REQUIRED,
    ),
    (
        AttackDomain.BLOCKCHAIN,
        "smart-contract-boundaries",
        "blockchain-testing",
        ("assettype:smart-contract",),
        CoverageStatus.PARTIAL,
        "Chain state and deployed contract behavior remain unobserved.",
        BlockedReason.INFRASTRUCTURE_REQUIRED,
    ),
    (
        AttackDomain.SOCIAL_ENGINEERING,
        "human-trust-boundaries",
        "social-engineering-governance",
        ("assettype:workforce-process",),
        CoverageStatus.BLOCKED,
        "Human interaction requires an explicit approved policy decision.",
        BlockedReason.POLICY_DECISION_REQUIRED,
    ),
    (
        AttackDomain.PHYSICAL,
        "physical-access-boundaries",
        "physical-testing-governance",
        ("assettype:physical-facility",),
        CoverageStatus.BLOCKED,
        "Physical access testing requires an explicit approved policy decision.",
        BlockedReason.POLICY_DECISION_REQUIRED,
    ),
    (
        AttackDomain.CRYPTOGRAPHIC_PKI,
        "cryptographic-trust-boundaries",
        "cryptographic-testing",
        ("assettype:pki-service", "assettype:cryptographic-protocol"),
        CoverageStatus.PARTIAL,
        "External key custody and live protocol behavior remain unobserved.",
        BlockedReason.EXTERNAL_IDENTITY_REQUIRED,
    ),
    (
        AttackDomain.MULTI_STAGE_CHAINING,
        "multi-stage-attack-paths",
        "attack-path-chaining",
        ("assettype:multi-system-path",),
        CoverageStatus.PARTIAL,
        "End-to-end live traversal remains unobserved.",
        BlockedReason.LIVE_TARGET_REQUIRED,
    ),
)


def build_default_attack_coverage_matrix(
    *, tenant_ref: str, context_ref: str, scope_sha256: str
) -> AttackCoverageMatrix:
    """Build the explicit twenty-domain repository classification baseline."""

    techniques: list[TechniqueReference] = []
    specialists: list[SpecialistCapabilityReference] = []
    mappings: list[CoverageMapping] = []
    for domain, technique_name, specialist_name, assets, status, gap, reason in _DOMAIN_TEMPLATES:
        technique = TechniqueReference(
            tenant_ref,
            context_ref,
            scope_sha256,
            "catalogref:sunder-governed-attack-vectors",
            "1.0.0",
            f"techniqueref:{technique_name}",
            "1.0.0",
            domain,
            assets,
        )
        specialist = SpecialistCapabilityReference(
            tenant_ref,
            context_ref,
            scope_sha256,
            f"specialistref:{specialist_name}",
            "1.0.0",
            f"capabilityref:{technique_name}",
            "1.0.0",
            (domain,),
            EvidenceGrade.CATALOG_ONLY,
            canonical_sha256({"domain": domain.value, "mapping": "catalog-only"}),
        )
        mapping = CoverageMapping(
            f"mapping:{domain.value}",
            technique.reference_id,
            (specialist.reference_id,),
            status,
            ("prerequisite:explicit-scope", "prerequisite:independent-review"),
            (gap,),
            (reason,) if reason is not None else (),
        )
        techniques.append(technique)
        specialists.append(specialist)
        mappings.append(mapping)
    return build_attack_coverage_matrix(
        technique_references=techniques,
        specialist_references=specialists,
        mappings=mappings,
    )


__all__ = [
    "MATRIX_DOMAIN",
    "NO_CLAIMS",
    "NO_EFFECTS",
    "AttackCoverageMatrix",
    "AttackCoverageMatrixError",
    "AttackDomain",
    "BlockedReason",
    "CoverageMapping",
    "CoverageRow",
    "CoverageStatus",
    "EvidenceGrade",
    "SpecialistCapabilityReference",
    "TechniqueReference",
    "build_attack_coverage_matrix",
    "build_default_attack_coverage_matrix",
    "canonical_json",
    "canonical_sha256",
    "verify_attack_coverage_matrix",
]
