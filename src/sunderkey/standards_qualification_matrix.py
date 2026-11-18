"""Deterministic, offline standards and technique qualification coverage records."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any

from .errors import QualificationError

SCHEMA_VERSION = 1
PIN_DOMAIN = "sunderkey.standard-release-pin.v1"
MAPPING_DOMAIN = "sunderkey.technique-qualification-mapping.v1"
MATRIX_DOMAIN = "sunderkey.standards-qualification-matrix.v1"

HARD_MAX_PINS = 256
HARD_MAX_MAPPINGS = 4096
HARD_MAX_ITEMS = 128
HARD_MAX_SCENARIOS = 128
HARD_MAX_DOCUMENT_BYTES = 8_388_608
HARD_MAX_REVIEW_AGE_DAYS = 3650

IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
PIN_ID_PATTERN = re.compile(r"SRP-[0-9A-F]{32}\Z")
MAPPING_ID_PATTERN = re.compile(r"TQM-[0-9A-F]{32}\Z")
MATRIX_ID_PATTERN = re.compile(r"SQM-[0-9A-F]{32}\Z")

FLOATING_RELEASE_IDS = frozenset({"current", "head", "latest", "rolling", "stable", "trunk"})
COVERAGE_STATUSES = frozenset({"complete", "partial", "gap"})
DIMENSIONS = (
    "standard_controls",
    "prerequisites",
    "safe_proof",
    "negative_controls",
    "restoration",
    "evidence",
    "validators",
    "scenarios",
)
EFFECTS = {
    "authority": "none",
    "execution": "none",
    "network": "none",
    "qualification": "none",
    "routing": "none",
}

# These identifiers describe coverage domains only. They intentionally contain no release pins.
RECOMMENDED_STANDARD_IDS = (
    "capec",
    "cloud.aws.security-guidance",
    "cloud.azure.security-guidance",
    "cloud.gcp.security-guidance",
    "crest.penetration-testing-guidance",
    "cwe",
    "iec.62443",
    "mitre.attack.enterprise",
    "mitre.attack.ics",
    "mitre.attack.mobile",
    "nist.sp.800-53.assessment",
    "nist.sp.800-115",
    "osstmm",
    "owasp.api-security-top-10",
    "owasp.asvs",
    "owasp.top-10",
    "owasp.wstg",
    "pci.dss.testing",
    "ptes",
)


class StandardsQualificationMatrixError(QualificationError):
    """Raised when a matrix input or serialized matrix fails closed."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(domain: str, label: str, value: Any) -> str:
    encoded = _canonical_json({"domain": domain, label: value}).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _content_id(prefix: str, digest: str) -> str:
    return f"{prefix}-{digest.removeprefix('sha256:')[:32].upper()}"


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise StandardsQualificationMatrixError(f"{label} must be a safe identifier")
    return value


def _exact_release(value: Any, label: str) -> str:
    release = _identifier(value, label)
    if release.casefold() in FLOATING_RELEASE_IDS:
        raise StandardsQualificationMatrixError(f"{label} must be an exact release identifier")
    return release


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise StandardsQualificationMatrixError(f"{label} must be a SHA-256 content address")
    return value


def _date(value: Any, label: str) -> date:
    if not isinstance(value, str):
        raise StandardsQualificationMatrixError(f"{label} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise StandardsQualificationMatrixError(f"{label} must be an ISO date") from exc
    if parsed.isoformat() != value:
        raise StandardsQualificationMatrixError(f"{label} must be a canonical ISO date")
    return parsed


def _identifiers(values: Sequence[str], label: str, limit: int = HARD_MAX_ITEMS) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise StandardsQualificationMatrixError(f"{label} must be a sequence")
    normalized = tuple(sorted(_identifier(value, label) for value in values))
    if len(normalized) > limit:
        raise StandardsQualificationMatrixError(f"{label} exceeds the item limit")
    if len(set(normalized)) != len(normalized):
        raise StandardsQualificationMatrixError(f"{label} contains duplicate identifiers")
    return normalized


def _require_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise StandardsQualificationMatrixError(f"{label} fields do not match the schema")


@dataclass(frozen=True)
class MatrixLimits:
    """Ceilings that may only reduce the built-in hard limits."""

    max_pins: int = HARD_MAX_PINS
    max_mappings: int = HARD_MAX_MAPPINGS
    max_items: int = HARD_MAX_ITEMS
    max_scenarios: int = HARD_MAX_SCENARIOS
    max_document_bytes: int = HARD_MAX_DOCUMENT_BYTES

    def __post_init__(self) -> None:
        ceilings = {
            "max_pins": HARD_MAX_PINS,
            "max_mappings": HARD_MAX_MAPPINGS,
            "max_items": HARD_MAX_ITEMS,
            "max_scenarios": HARD_MAX_SCENARIOS,
            "max_document_bytes": HARD_MAX_DOCUMENT_BYTES,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= ceiling:
                raise StandardsQualificationMatrixError(f"{name} must be between 1 and {ceiling}")


@dataclass(frozen=True)
class StandardReleasePin:
    """An exact, caller-supplied standard release and its immutable artifact hash."""

    standard_id: str
    release_id: str
    publication_date: str
    reviewed_on: str
    artifact_sha256: str
    pin_id: str = ""
    pin_sha256: str = ""

    def __post_init__(self) -> None:
        standard_id = _identifier(self.standard_id, "standard_id")
        release_id = _exact_release(self.release_id, "release_id")
        publication = _date(self.publication_date, "publication_date")
        reviewed = _date(self.reviewed_on, "reviewed_on")
        if reviewed < publication:
            raise StandardsQualificationMatrixError("reviewed_on cannot precede publication_date")
        artifact = _sha256(self.artifact_sha256, "artifact_sha256")
        body = {
            "standard_id": standard_id,
            "release_id": release_id,
            "publication_date": publication.isoformat(),
            "reviewed_on": reviewed.isoformat(),
            "artifact_sha256": artifact,
        }
        digest = _digest(PIN_DOMAIN, "pin", body)
        expected_id = _content_id("SRP", digest)
        if self.pin_sha256 and self.pin_sha256 != digest:
            raise StandardsQualificationMatrixError("standard release pin hash mismatch")
        if self.pin_id and self.pin_id != expected_id:
            raise StandardsQualificationMatrixError("standard release pin identifier mismatch")
        object.__setattr__(self, "standard_id", standard_id)
        object.__setattr__(self, "release_id", release_id)
        object.__setattr__(self, "publication_date", publication.isoformat())
        object.__setattr__(self, "reviewed_on", reviewed.isoformat())
        object.__setattr__(self, "artifact_sha256", artifact)
        object.__setattr__(self, "pin_id", expected_id)
        object.__setattr__(self, "pin_sha256", digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pin_id": self.pin_id,
            "pin_sha256": self.pin_sha256,
            "standard_id": self.standard_id,
            "release_id": self.release_id,
            "publication_date": self.publication_date,
            "reviewed_on": self.reviewed_on,
            "artifact_sha256": self.artifact_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StandardReleasePin:
        _require_keys(
            value,
            {
                "pin_id",
                "pin_sha256",
                "standard_id",
                "release_id",
                "publication_date",
                "reviewed_on",
                "artifact_sha256",
            },
            "standard release pin",
        )
        if (
            not isinstance(value["pin_id"], str)
            or PIN_ID_PATTERN.fullmatch(value["pin_id"]) is None
        ):
            raise StandardsQualificationMatrixError("pin_id is invalid")
        return cls(**dict(value))


@dataclass(frozen=True)
class StandardControlReference:
    """A mapping to exact controls in one pinned standard."""

    standard_id: str
    control_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "standard_id", _identifier(self.standard_id, "standard_id"))
        controls = _identifiers(self.control_ids, "control_ids")
        if not controls:
            raise StandardsQualificationMatrixError("control_ids cannot be empty")
        object.__setattr__(self, "control_ids", controls)

    def to_dict(self) -> dict[str, Any]:
        return {"standard_id": self.standard_id, "control_ids": list(self.control_ids)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StandardControlReference:
        _require_keys(value, {"standard_id", "control_ids"}, "standard control reference")
        return cls(standard_id=value["standard_id"], control_ids=tuple(value["control_ids"]))


@dataclass(frozen=True)
class QualificationScenario:
    """An inert scenario contract expressed only as identifiers."""

    scenario_id: str
    prerequisite_ids: tuple[str, ...]
    safe_proof_ids: tuple[str, ...]
    negative_control_ids: tuple[str, ...]
    restoration_ids: tuple[str, ...]
    evidence_requirement_ids: tuple[str, ...]
    validator_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id", _identifier(self.scenario_id, "scenario_id"))
        for name in (
            "prerequisite_ids",
            "safe_proof_ids",
            "negative_control_ids",
            "restoration_ids",
            "evidence_requirement_ids",
            "validator_ids",
        ):
            normalized = _identifiers(getattr(self, name), name)
            if not normalized:
                raise StandardsQualificationMatrixError(
                    f"qualification scenario {name} cannot be empty"
                )
            object.__setattr__(self, name, normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "prerequisite_ids": list(self.prerequisite_ids),
            "safe_proof_ids": list(self.safe_proof_ids),
            "negative_control_ids": list(self.negative_control_ids),
            "restoration_ids": list(self.restoration_ids),
            "evidence_requirement_ids": list(self.evidence_requirement_ids),
            "validator_ids": list(self.validator_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> QualificationScenario:
        fields = {
            "scenario_id",
            "prerequisite_ids",
            "safe_proof_ids",
            "negative_control_ids",
            "restoration_ids",
            "evidence_requirement_ids",
            "validator_ids",
        }
        _require_keys(value, fields, "qualification scenario")
        return cls(
            scenario_id=value["scenario_id"],
            prerequisite_ids=tuple(value["prerequisite_ids"]),
            safe_proof_ids=tuple(value["safe_proof_ids"]),
            negative_control_ids=tuple(value["negative_control_ids"]),
            restoration_ids=tuple(value["restoration_ids"]),
            evidence_requirement_ids=tuple(value["evidence_requirement_ids"]),
            validator_ids=tuple(value["validator_ids"]),
        )


@dataclass(frozen=True)
class TechniqueQualificationMapping:
    """One explicit technique and specialist qualification coverage mapping."""

    technique_id: str
    specialist_profile_ids: tuple[str, ...]
    standard_controls: tuple[StandardControlReference, ...] = ()
    prerequisite_ids: tuple[str, ...] = ()
    safe_proof_ids: tuple[str, ...] = ()
    negative_control_ids: tuple[str, ...] = ()
    restoration_ids: tuple[str, ...] = ()
    evidence_requirement_ids: tuple[str, ...] = ()
    validator_ids: tuple[str, ...] = ()
    scenarios: tuple[QualificationScenario, ...] = ()
    coverage_status: str = "gap"
    missing_dimensions: tuple[str, ...] = DIMENSIONS
    mapping_id: str = ""
    mapping_sha256: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "technique_id", _identifier(self.technique_id, "technique_id"))
        specialists = _identifiers(self.specialist_profile_ids, "specialist_profile_ids")
        if not specialists:
            raise StandardsQualificationMatrixError("specialist_profile_ids cannot be empty")
        object.__setattr__(self, "specialist_profile_ids", specialists)
        controls = tuple(sorted(self.standard_controls, key=lambda item: item.standard_id))
        if len(controls) > HARD_MAX_ITEMS:
            raise StandardsQualificationMatrixError("standard_controls exceeds the item limit")
        if len({item.standard_id for item in controls}) != len(controls):
            raise StandardsQualificationMatrixError(
                "standard_controls contains duplicate standards"
            )
        object.__setattr__(self, "standard_controls", controls)
        for name in (
            "prerequisite_ids",
            "safe_proof_ids",
            "negative_control_ids",
            "restoration_ids",
            "evidence_requirement_ids",
            "validator_ids",
        ):
            object.__setattr__(self, name, _identifiers(getattr(self, name), name))
        scenarios = tuple(sorted(self.scenarios, key=lambda item: item.scenario_id))
        if len(scenarios) > HARD_MAX_SCENARIOS:
            raise StandardsQualificationMatrixError("scenarios exceeds the item limit")
        if len({item.scenario_id for item in scenarios}) != len(scenarios):
            raise StandardsQualificationMatrixError("scenarios contains duplicate identifiers")
        object.__setattr__(self, "scenarios", scenarios)
        if self.coverage_status not in COVERAGE_STATUSES:
            raise StandardsQualificationMatrixError("coverage_status is invalid")
        missing = _identifiers(self.missing_dimensions, "missing_dimensions", len(DIMENSIONS))
        if any(item not in DIMENSIONS for item in missing):
            raise StandardsQualificationMatrixError(
                "missing_dimensions contains an invalid dimension"
            )
        observed_missing = tuple(
            dimension
            for dimension, value in (
                ("standard_controls", controls),
                ("prerequisites", self.prerequisite_ids),
                ("safe_proof", self.safe_proof_ids),
                ("negative_controls", self.negative_control_ids),
                ("restoration", self.restoration_ids),
                ("evidence", self.evidence_requirement_ids),
                ("validators", self.validator_ids),
                ("scenarios", scenarios),
            )
            if not value
        )
        if missing != tuple(sorted(observed_missing)):
            raise StandardsQualificationMatrixError(
                "missing_dimensions must exactly describe absent mapping dimensions"
            )
        if self.coverage_status == "complete" and missing:
            raise StandardsQualificationMatrixError("complete mapping has missing dimensions")
        if self.coverage_status == "partial" and (not missing or len(missing) == len(DIMENSIONS)):
            raise StandardsQualificationMatrixError("partial mapping must have partial coverage")
        if self.coverage_status == "gap" and len(missing) != len(DIMENSIONS):
            raise StandardsQualificationMatrixError("gap mapping must not claim coverage")
        if self.coverage_status == "gap" and any(
            (
                controls,
                self.prerequisite_ids,
                self.safe_proof_ids,
                self.negative_control_ids,
                self.restoration_ids,
                self.evidence_requirement_ids,
                self.validator_ids,
                scenarios,
            )
        ):
            raise StandardsQualificationMatrixError("gap mapping must not invent mapping content")
        for scenario in scenarios:
            pairs = (
                (scenario.prerequisite_ids, self.prerequisite_ids),
                (scenario.safe_proof_ids, self.safe_proof_ids),
                (scenario.negative_control_ids, self.negative_control_ids),
                (scenario.restoration_ids, self.restoration_ids),
                (scenario.evidence_requirement_ids, self.evidence_requirement_ids),
                (scenario.validator_ids, self.validator_ids),
            )
            if any(not set(selected).issubset(available) for selected, available in pairs):
                raise StandardsQualificationMatrixError(
                    "qualification scenario references an undeclared mapping requirement"
                )
        object.__setattr__(self, "missing_dimensions", missing)
        body = self._body_dict()
        digest = _digest(MAPPING_DOMAIN, "mapping", body)
        expected_id = _content_id("TQM", digest)
        if self.mapping_sha256 and self.mapping_sha256 != digest:
            raise StandardsQualificationMatrixError("technique mapping hash mismatch")
        if self.mapping_id and self.mapping_id != expected_id:
            raise StandardsQualificationMatrixError("technique mapping identifier mismatch")
        object.__setattr__(self, "mapping_sha256", digest)
        object.__setattr__(self, "mapping_id", expected_id)

    def _body_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "specialist_profile_ids": list(self.specialist_profile_ids),
            "standard_controls": [item.to_dict() for item in self.standard_controls],
            "prerequisite_ids": list(self.prerequisite_ids),
            "safe_proof_ids": list(self.safe_proof_ids),
            "negative_control_ids": list(self.negative_control_ids),
            "restoration_ids": list(self.restoration_ids),
            "evidence_requirement_ids": list(self.evidence_requirement_ids),
            "validator_ids": list(self.validator_ids),
            "scenarios": [item.to_dict() for item in self.scenarios],
            "coverage_status": self.coverage_status,
            "missing_dimensions": list(self.missing_dimensions),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "mapping_sha256": self.mapping_sha256,
            **self._body_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> TechniqueQualificationMapping:
        fields = {
            "mapping_id",
            "mapping_sha256",
            "technique_id",
            "specialist_profile_ids",
            "standard_controls",
            "prerequisite_ids",
            "safe_proof_ids",
            "negative_control_ids",
            "restoration_ids",
            "evidence_requirement_ids",
            "validator_ids",
            "scenarios",
            "coverage_status",
            "missing_dimensions",
        }
        _require_keys(value, fields, "technique qualification mapping")
        if (
            not isinstance(value["mapping_id"], str)
            or MAPPING_ID_PATTERN.fullmatch(value["mapping_id"]) is None
        ):
            raise StandardsQualificationMatrixError("mapping_id is invalid")
        return cls(
            technique_id=value["technique_id"],
            specialist_profile_ids=tuple(value["specialist_profile_ids"]),
            standard_controls=tuple(
                StandardControlReference.from_dict(item) for item in value["standard_controls"]
            ),
            prerequisite_ids=tuple(value["prerequisite_ids"]),
            safe_proof_ids=tuple(value["safe_proof_ids"]),
            negative_control_ids=tuple(value["negative_control_ids"]),
            restoration_ids=tuple(value["restoration_ids"]),
            evidence_requirement_ids=tuple(value["evidence_requirement_ids"]),
            validator_ids=tuple(value["validator_ids"]),
            scenarios=tuple(QualificationScenario.from_dict(item) for item in value["scenarios"]),
            coverage_status=value["coverage_status"],
            missing_dimensions=tuple(value["missing_dimensions"]),
            mapping_id=value["mapping_id"],
            mapping_sha256=value["mapping_sha256"],
        )


@dataclass(frozen=True)
class CoverageGap:
    """A deterministic gap record that makes no substitute mapping claim."""

    gap_type: str
    subject_id: str
    reason_code: str
    missing_dimensions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_type": self.gap_type,
            "subject_id": self.subject_id,
            "reason_code": self.reason_code,
            "missing_dimensions": list(self.missing_dimensions),
        }


@dataclass(frozen=True)
class CoverageMetrics:
    """Integer-only deterministic coverage metrics."""

    expected_standard_count: int
    pinned_standard_count: int
    fresh_standard_count: int
    expected_technique_count: int
    complete_technique_count: int
    partial_technique_count: int
    gap_technique_count: int
    expected_specialist_count: int
    covered_specialist_count: int
    technique_coverage_basis_points: int

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class StandardsQualificationMatrix:
    """A content-addressed standards coverage release with no runtime effects."""

    release_id: str
    as_of_date: str
    max_review_age_days: int
    pins: tuple[StandardReleasePin, ...]
    mappings: tuple[TechniqueQualificationMapping, ...]
    expected_standard_ids: tuple[str, ...]
    expected_technique_ids: tuple[str, ...]
    expected_specialist_profile_ids: tuple[str, ...]
    coverage_metrics: CoverageMetrics
    gaps: tuple[CoverageGap, ...]
    matrix_id: str
    matrix_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "matrix_id": self.matrix_id,
            "matrix_sha256": self.matrix_sha256,
            "release_id": self.release_id,
            "as_of_date": self.as_of_date,
            "max_review_age_days": self.max_review_age_days,
            "pins": [item.to_dict() for item in self.pins],
            "mappings": [item.to_dict() for item in self.mappings],
            "expected": {
                "standard_ids": list(self.expected_standard_ids),
                "technique_ids": list(self.expected_technique_ids),
                "specialist_profile_ids": list(self.expected_specialist_profile_ids),
            },
            "coverage_metrics": self.coverage_metrics.to_dict(),
            "gaps": [item.to_dict() for item in self.gaps],
            "effects": dict(EFFECTS),
        }

    @property
    def document_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StandardsQualificationMatrix:
        _require_keys(
            value,
            {
                "schema_version",
                "matrix_id",
                "matrix_sha256",
                "release_id",
                "as_of_date",
                "max_review_age_days",
                "pins",
                "mappings",
                "expected",
                "coverage_metrics",
                "gaps",
                "effects",
            },
            "standards qualification matrix",
        )
        if value["schema_version"] != SCHEMA_VERSION:
            raise StandardsQualificationMatrixError("schema_version is unsupported")
        if (
            not isinstance(value["matrix_id"], str)
            or MATRIX_ID_PATTERN.fullmatch(value["matrix_id"]) is None
        ):
            raise StandardsQualificationMatrixError("matrix_id is invalid")
        if value["effects"] != EFFECTS:
            raise StandardsQualificationMatrixError("matrix effects must all be none")
        expected = value["expected"]
        if not isinstance(expected, Mapping):
            raise StandardsQualificationMatrixError("expected must be an object")
        _require_keys(
            expected,
            {"standard_ids", "technique_ids", "specialist_profile_ids"},
            "expected",
        )
        rebuilt = build_standards_qualification_matrix(
            release_id=value["release_id"],
            as_of_date=value["as_of_date"],
            max_review_age_days=value["max_review_age_days"],
            pins=tuple(StandardReleasePin.from_dict(item) for item in value["pins"]),
            mappings=tuple(
                TechniqueQualificationMapping.from_dict(item) for item in value["mappings"]
            ),
            expected_standard_ids=tuple(expected["standard_ids"]),
            expected_technique_ids=tuple(expected["technique_ids"]),
            expected_specialist_profile_ids=tuple(expected["specialist_profile_ids"]),
        )
        if rebuilt.to_dict() != dict(value):
            raise StandardsQualificationMatrixError("matrix content or hash mismatch")
        return rebuilt

    @classmethod
    def from_json(cls, value: str) -> StandardsQualificationMatrix:
        if not isinstance(value, str) or len(value.encode("utf-8")) > HARD_MAX_DOCUMENT_BYTES:
            raise StandardsQualificationMatrixError("matrix document exceeds the byte limit")
        try:
            document = json.loads(value)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise StandardsQualificationMatrixError("matrix document is not valid JSON") from exc
        if not isinstance(document, Mapping):
            raise StandardsQualificationMatrixError("matrix document must be an object")
        return cls.from_dict(document)


def build_standards_qualification_matrix(
    *,
    release_id: str,
    as_of_date: str,
    pins: Sequence[StandardReleasePin],
    mappings: Sequence[TechniqueQualificationMapping],
    expected_standard_ids: Sequence[str],
    expected_technique_ids: Sequence[str],
    expected_specialist_profile_ids: Sequence[str],
    max_review_age_days: int = 365,
    limits: MatrixLimits | None = None,
) -> StandardsQualificationMatrix:
    """Build a deterministic matrix without fetching, executing, or qualifying anything."""

    limits = limits or MatrixLimits()
    release = _exact_release(release_id, "release_id")
    reference_date = _date(as_of_date, "as_of_date")
    if (
        not isinstance(max_review_age_days, int)
        or isinstance(max_review_age_days, bool)
        or not 1 <= max_review_age_days <= HARD_MAX_REVIEW_AGE_DAYS
    ):
        raise StandardsQualificationMatrixError(
            f"max_review_age_days must be between 1 and {HARD_MAX_REVIEW_AGE_DAYS}"
        )
    normalized_pins = tuple(sorted(pins, key=lambda item: item.standard_id))
    normalized_mappings = tuple(
        sorted(mappings, key=lambda item: (item.technique_id, item.specialist_profile_ids))
    )
    if len(normalized_pins) > limits.max_pins:
        raise StandardsQualificationMatrixError("pins exceeds the configured limit")
    if len(normalized_mappings) > limits.max_mappings:
        raise StandardsQualificationMatrixError("mappings exceeds the configured limit")
    pin_ids = [item.standard_id for item in normalized_pins]
    if len(set(pin_ids)) != len(pin_ids):
        raise StandardsQualificationMatrixError("pins contains duplicate standard identifiers")
    semantic_keys = [
        (item.technique_id, item.specialist_profile_ids) for item in normalized_mappings
    ]
    if len(set(semantic_keys)) != len(semantic_keys):
        raise StandardsQualificationMatrixError("mappings contains duplicate technique bindings")
    if len({item.mapping_id for item in normalized_mappings}) != len(normalized_mappings):
        raise StandardsQualificationMatrixError("mappings contains duplicate mapping identifiers")
    expected_standards = _identifiers(
        expected_standard_ids, "expected_standard_ids", limits.max_items
    )
    expected_techniques = _identifiers(
        expected_technique_ids, "expected_technique_ids", limits.max_items
    )
    expected_specialists = _identifiers(
        expected_specialist_profile_ids,
        "expected_specialist_profile_ids",
        limits.max_items,
    )
    pin_by_standard = {item.standard_id: item for item in normalized_pins}
    for pin in normalized_pins:
        if _date(pin.publication_date, "publication_date") > reference_date:
            raise StandardsQualificationMatrixError("publication_date cannot follow as_of_date")
        if _date(pin.reviewed_on, "reviewed_on") > reference_date:
            raise StandardsQualificationMatrixError("reviewed_on cannot follow as_of_date")
    for mapping in normalized_mappings:
        for reference in mapping.standard_controls:
            if reference.standard_id not in pin_by_standard:
                raise StandardsQualificationMatrixError(
                    "technique mapping references a missing standard release pin"
                )

    stale_ids = {
        pin.standard_id
        for pin in normalized_pins
        if (reference_date - _date(pin.reviewed_on, "reviewed_on")).days > max_review_age_days
    }
    gaps: list[CoverageGap] = []
    for standard_id in expected_standards:
        if standard_id not in pin_by_standard:
            gaps.append(CoverageGap("standard", standard_id, "missing_release_pin"))
        elif standard_id in stale_ids:
            gaps.append(CoverageGap("standard", standard_id, "stale_release_review"))

    mappings_by_technique: dict[str, list[TechniqueQualificationMapping]] = {}
    covered_specialists: set[str] = set()
    for mapping in normalized_mappings:
        mappings_by_technique.setdefault(mapping.technique_id, []).append(mapping)
        covered_specialists.update(mapping.specialist_profile_ids)
        if mapping.coverage_status != "complete":
            gaps.append(
                CoverageGap(
                    "technique",
                    mapping.technique_id,
                    "explicit_mapping_gap"
                    if mapping.coverage_status == "gap"
                    else "incomplete_mapping",
                    mapping.missing_dimensions,
                )
            )

    technique_statuses: dict[str, str] = {}
    for technique_id in expected_techniques:
        candidates = mappings_by_technique.get(technique_id, [])
        if not candidates:
            technique_statuses[technique_id] = "gap"
            gaps.append(CoverageGap("technique", technique_id, "missing_mapping", DIMENSIONS))
        elif any(item.coverage_status == "complete" for item in candidates):
            technique_statuses[technique_id] = "complete"
        elif any(item.coverage_status == "partial" for item in candidates):
            technique_statuses[technique_id] = "partial"
        else:
            technique_statuses[technique_id] = "gap"
    for specialist_id in expected_specialists:
        if specialist_id not in covered_specialists:
            gaps.append(CoverageGap("specialist", specialist_id, "missing_mapping"))

    complete_count = sum(value == "complete" for value in technique_statuses.values())
    partial_count = sum(value == "partial" for value in technique_statuses.values())
    gap_count = sum(value == "gap" for value in technique_statuses.values())
    technique_basis_points = (
        complete_count * 10_000 // len(expected_techniques) if expected_techniques else 0
    )
    metrics = CoverageMetrics(
        expected_standard_count=len(expected_standards),
        pinned_standard_count=sum(item in pin_by_standard for item in expected_standards),
        fresh_standard_count=sum(
            item in pin_by_standard and item not in stale_ids for item in expected_standards
        ),
        expected_technique_count=len(expected_techniques),
        complete_technique_count=complete_count,
        partial_technique_count=partial_count,
        gap_technique_count=gap_count,
        expected_specialist_count=len(expected_specialists),
        covered_specialist_count=sum(item in covered_specialists for item in expected_specialists),
        technique_coverage_basis_points=technique_basis_points,
    )
    normalized_gaps = tuple(
        sorted(gaps, key=lambda item: (item.gap_type, item.subject_id, item.reason_code))
    )
    body = {
        "schema_version": SCHEMA_VERSION,
        "release_id": release,
        "as_of_date": reference_date.isoformat(),
        "max_review_age_days": max_review_age_days,
        "pins": [item.to_dict() for item in normalized_pins],
        "mappings": [item.to_dict() for item in normalized_mappings],
        "expected": {
            "standard_ids": list(expected_standards),
            "technique_ids": list(expected_techniques),
            "specialist_profile_ids": list(expected_specialists),
        },
        "coverage_metrics": metrics.to_dict(),
        "gaps": [item.to_dict() for item in normalized_gaps],
        "effects": dict(EFFECTS),
    }
    digest = _digest(MATRIX_DOMAIN, "matrix", body)
    matrix = StandardsQualificationMatrix(
        release_id=release,
        as_of_date=reference_date.isoformat(),
        max_review_age_days=max_review_age_days,
        pins=normalized_pins,
        mappings=normalized_mappings,
        expected_standard_ids=expected_standards,
        expected_technique_ids=expected_techniques,
        expected_specialist_profile_ids=expected_specialists,
        coverage_metrics=metrics,
        gaps=normalized_gaps,
        matrix_id=_content_id("SQM", digest),
        matrix_sha256=digest,
    )
    if len(matrix.document_json.encode("utf-8")) > limits.max_document_bytes:
        raise StandardsQualificationMatrixError("matrix document exceeds the configured byte limit")
    return matrix
