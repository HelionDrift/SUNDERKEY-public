"""Offline contracts for reproducible instrumented security ranges.

The module validates caller-supplied declarations and observations only. It
never starts containers, resolves secrets, performs network access, executes
an exploit, resets a range, or establishes live readiness.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

SCHEMA_VERSION = 1
APPLICATION_DOMAIN = "sunderkey.instrumented-range-application.v1"
SCENARIO_DOMAIN = "sunderkey.instrumented-range-scenario.v1"
OBSERVATION_DOMAIN = "sunderkey.instrumented-range-observation.v1"
ASSESSMENT_DOMAIN = "sunderkey.instrumented-range-assessment.v1"
MAX_ITEMS = 512
MAX_AGE_SECONDS = 86_400

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
IMAGE_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,254}@[s]ha256:[0-9a-f]{64}\Z")
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|cookie)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)

NO_EFFECTS = MappingProxyType(
    {
        "container_start": "none",
        "exploit_execution": "none",
        "live_readiness_claim": "none",
        "network": "none",
        "secret_resolution": "none",
        "state_change": "none",
    }
)


class InstrumentedRangeContractError(ValueError):
    """Raised when an instrumented range contract fails closed."""


class VulnerabilityDisposition(StrEnum):
    EXPLOITABLE = "exploitable"
    NOT_EXPLOITABLE = "not_exploitable"


class ReferenceKind(StrEnum):
    SEEDED_SECRET = "seeded_secret"
    CANARY = "canary"


class BoundaryDirection(StrEnum):
    INGRESS = "ingress"
    EGRESS = "egress"
    INTERNAL = "internal"


class TelemetryKind(StrEnum):
    APPLICATION = "application"
    AUDIT = "audit"
    IDENTITY = "identity"
    NETWORK = "network"
    SYSTEM = "system"


class ReadinessStatus(StrEnum):
    READY = "ready"
    NOT_READY = "not_ready"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError) as exc:
        raise InstrumentedRangeContractError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise InstrumentedRangeContractError(f"{label} must be a safe identifier")
    if SECRET_RE.search(value):
        raise InstrumentedRangeContractError(f"{label} appears to contain secret material")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise InstrumentedRangeContractError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise InstrumentedRangeContractError(f"{label} must be a UTC timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise InstrumentedRangeContractError(f"{label} must be between 1 and {maximum}")
    return value


def _bounded_unique(values: Sequence[Any], label: str) -> tuple[Any, ...]:
    result = tuple(values)
    if not result or len(result) > MAX_ITEMS or len(set(result)) != len(result):
        raise InstrumentedRangeContractError(f"{label} must be a bounded unique sequence")
    return result


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise InstrumentedRangeContractError(f"{label} fields do not match the contract")
    return raw


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise InstrumentedRangeContractError(f"{label} is invalid") from exc


def _effects(raw: Any) -> None:
    if not isinstance(raw, Mapping) or dict(raw) != dict(NO_EFFECTS):
        raise InstrumentedRangeContractError("effects are invalid")


@dataclass(frozen=True)
class ImageBinding:
    component_id: str
    image_reference: str
    build_sha256: str
    source_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.component_id, "component_id")
        if IMAGE_RE.fullmatch(self.image_reference) is None:
            raise InstrumentedRangeContractError("image_reference must use an exact image digest")
        _sha256(self.build_sha256, "build_sha256")
        _sha256(self.source_sha256, "source_sha256")

    def to_dict(self) -> dict[str, Any]:
        return vars(self).copy()

    @classmethod
    def from_dict(cls, raw: Any) -> ImageBinding:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "image binding"))


@dataclass(frozen=True)
class GroundTruthVulnerability:
    vulnerability_id: str
    component_id: str
    weakness_id: str
    disposition: VulnerabilityDisposition | str
    ground_truth_sha256: str

    def __post_init__(self) -> None:
        for name in ("vulnerability_id", "component_id", "weakness_id"):
            _identifier(getattr(self, name), name)
        object.__setattr__(
            self,
            "disposition",
            _enum(VulnerabilityDisposition, self.disposition, "disposition"),
        )
        _sha256(self.ground_truth_sha256, "ground_truth_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "disposition": self.disposition.value,
            "ground_truth_sha256": self.ground_truth_sha256,
            "vulnerability_id": self.vulnerability_id,
            "weakness_id": self.weakness_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> GroundTruthVulnerability:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "ground truth vulnerability"))


@dataclass(frozen=True)
class NegativeControl:
    control_id: str
    component_id: str
    claim_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.control_id, "control_id")
        _identifier(self.component_id, "component_id")
        _sha256(self.claim_sha256, "claim_sha256")

    def to_dict(self) -> dict[str, Any]:
        return vars(self).copy()

    @classmethod
    def from_dict(cls, raw: Any) -> NegativeControl:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "negative control"))


@dataclass(frozen=True)
class SeededDataSet:
    data_set_id: str
    fixture_sha256: str
    record_count: int

    def __post_init__(self) -> None:
        _identifier(self.data_set_id, "data_set_id")
        _sha256(self.fixture_sha256, "fixture_sha256")
        _positive_int(self.record_count, "record_count", 10_000_000)

    def to_dict(self) -> dict[str, Any]:
        return vars(self).copy()

    @classmethod
    def from_dict(cls, raw: Any) -> SeededDataSet:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "seeded data set"))


@dataclass(frozen=True)
class OpaqueReference:
    reference_id: str
    kind: ReferenceKind | str
    provider_id: str
    version_id: str

    def __post_init__(self) -> None:
        for name in ("reference_id", "provider_id", "version_id"):
            _identifier(getattr(self, name), name)
        object.__setattr__(self, "kind", _enum(ReferenceKind, self.kind, "kind"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "provider_id": self.provider_id,
            "reference_id": self.reference_id,
            "version_id": self.version_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> OpaqueReference:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "opaque reference"))


@dataclass(frozen=True)
class NetworkBoundary:
    boundary_id: str
    direction: BoundaryDirection | str
    source_zone: str
    destination_zone: str
    policy_sha256: str

    def __post_init__(self) -> None:
        for name in ("boundary_id", "source_zone", "destination_zone"):
            _identifier(getattr(self, name), name)
        object.__setattr__(self, "direction", _enum(BoundaryDirection, self.direction, "direction"))
        _sha256(self.policy_sha256, "policy_sha256")
        if (
            self.source_zone == self.destination_zone
            and self.direction != BoundaryDirection.INTERNAL
        ):
            raise InstrumentedRangeContractError("same-zone boundary must be internal")

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "destination_zone": self.destination_zone,
            "direction": self.direction.value,
            "policy_sha256": self.policy_sha256,
            "source_zone": self.source_zone,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> NetworkBoundary:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "network boundary"))


@dataclass(frozen=True)
class ResourceQuota:
    cpu_millicores: int
    memory_mebibytes: int
    storage_mebibytes: int
    process_limit: int

    def __post_init__(self) -> None:
        _positive_int(self.cpu_millicores, "cpu_millicores", 1_000_000)
        _positive_int(self.memory_mebibytes, "memory_mebibytes", 100_000_000)
        _positive_int(self.storage_mebibytes, "storage_mebibytes", 1_000_000_000)
        _positive_int(self.process_limit, "process_limit", 1_000_000)

    def to_dict(self) -> dict[str, Any]:
        return vars(self).copy()

    @classmethod
    def from_dict(cls, raw: Any) -> ResourceQuota:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "resource quota"))


@dataclass(frozen=True)
class TelemetryChannel:
    channel_id: str
    kind: TelemetryKind | str
    collector_id: str
    correlation_fields: tuple[str, ...]
    schema_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.channel_id, "channel_id")
        _identifier(self.collector_id, "collector_id")
        object.__setattr__(self, "kind", _enum(TelemetryKind, self.kind, "kind"))
        fields = _bounded_unique(self.correlation_fields, "correlation_fields")
        for value in fields:
            _identifier(value, "correlation_field")
        object.__setattr__(self, "correlation_fields", fields)
        _sha256(self.schema_sha256, "schema_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel_id": self.channel_id,
            "collector_id": self.collector_id,
            "correlation_fields": list(self.correlation_fields),
            "kind": self.kind.value,
            "schema_sha256": self.schema_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TelemetryChannel:
        values = dict(_exact(raw, set(cls.__dataclass_fields__), "telemetry channel"))
        values["correlation_fields"] = tuple(values["correlation_fields"])
        return cls(**values)


@dataclass(frozen=True)
class HealthProbe:
    probe_id: str
    component_id: str
    probe_kind: str
    expectation_sha256: str

    def __post_init__(self) -> None:
        for name in ("probe_id", "component_id", "probe_kind"):
            _identifier(getattr(self, name), name)
        _sha256(self.expectation_sha256, "expectation_sha256")

    def to_dict(self) -> dict[str, Any]:
        return vars(self).copy()

    @classmethod
    def from_dict(cls, raw: Any) -> HealthProbe:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "health probe"))


@dataclass(frozen=True)
class SnapshotManifest:
    snapshot_id: str
    snapshot_sha256: str
    application_state_sha256: str
    data_state_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.snapshot_id, "snapshot_id")
        for name in ("snapshot_sha256", "application_state_sha256", "data_state_sha256"):
            _sha256(getattr(self, name), name)

    def to_dict(self) -> dict[str, Any]:
        return vars(self).copy()

    @classmethod
    def from_dict(cls, raw: Any) -> SnapshotManifest:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "snapshot manifest"))


@dataclass(frozen=True)
class ResetManifest:
    reset_id: str
    procedure_sha256: str
    baseline_snapshot_id: str
    baseline_snapshot_sha256: str
    required_restoration_check_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.reset_id, "reset_id")
        _identifier(self.baseline_snapshot_id, "baseline_snapshot_id")
        _sha256(self.procedure_sha256, "procedure_sha256")
        _sha256(self.baseline_snapshot_sha256, "baseline_snapshot_sha256")
        checks = _bounded_unique(
            self.required_restoration_check_ids, "required_restoration_check_ids"
        )
        for check_id in checks:
            _identifier(check_id, "restoration_check_id")
        object.__setattr__(self, "required_restoration_check_ids", checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_snapshot_id": self.baseline_snapshot_id,
            "baseline_snapshot_sha256": self.baseline_snapshot_sha256,
            "procedure_sha256": self.procedure_sha256,
            "required_restoration_check_ids": list(self.required_restoration_check_ids),
            "reset_id": self.reset_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ResetManifest:
        values = dict(_exact(raw, set(cls.__dataclass_fields__), "reset manifest"))
        values["required_restoration_check_ids"] = tuple(values["required_restoration_check_ids"])
        return cls(**values)


def _unique_by(values: Sequence[Any], attribute: str, label: str) -> tuple[Any, ...]:
    result = tuple(values)
    if not result or len(result) > MAX_ITEMS:
        raise InstrumentedRangeContractError(f"{label} must be a bounded nonempty sequence")
    identities = [getattr(value, attribute) for value in result]
    if len(set(identities)) != len(identities):
        raise InstrumentedRangeContractError(f"{label} identities must be unique")
    return result


@dataclass(frozen=True)
class SyntheticApplicationManifest:
    application_id: str
    source_sha256: str
    build_sha256: str
    images: tuple[ImageBinding, ...]
    ground_truth_vulnerabilities: tuple[GroundTruthVulnerability, ...]
    negative_controls: tuple[NegativeControl, ...]
    seeded_data_sets: tuple[SeededDataSet, ...]
    opaque_references: tuple[OpaqueReference, ...]
    network_boundaries: tuple[NetworkBoundary, ...]
    resource_quota: ResourceQuota
    telemetry_channels: tuple[TelemetryChannel, ...]
    health_probes: tuple[HealthProbe, ...]
    baseline_snapshot: SnapshotManifest

    def __post_init__(self) -> None:
        _identifier(self.application_id, "application_id")
        _sha256(self.source_sha256, "source_sha256")
        _sha256(self.build_sha256, "build_sha256")
        object.__setattr__(self, "images", _unique_by(self.images, "component_id", "images"))
        object.__setattr__(
            self,
            "ground_truth_vulnerabilities",
            _unique_by(
                self.ground_truth_vulnerabilities,
                "vulnerability_id",
                "ground_truth_vulnerabilities",
            ),
        )
        object.__setattr__(
            self,
            "negative_controls",
            _unique_by(self.negative_controls, "control_id", "negative_controls"),
        )
        object.__setattr__(
            self,
            "seeded_data_sets",
            _unique_by(self.seeded_data_sets, "data_set_id", "seeded_data_sets"),
        )
        object.__setattr__(
            self,
            "opaque_references",
            _unique_by(self.opaque_references, "reference_id", "opaque_references"),
        )
        object.__setattr__(
            self,
            "network_boundaries",
            _unique_by(self.network_boundaries, "boundary_id", "network_boundaries"),
        )
        object.__setattr__(
            self,
            "telemetry_channels",
            _unique_by(self.telemetry_channels, "channel_id", "telemetry_channels"),
        )
        object.__setattr__(
            self, "health_probes", _unique_by(self.health_probes, "probe_id", "health_probes")
        )
        component_ids = {item.component_id for item in self.images}
        for item in (
            *self.ground_truth_vulnerabilities,
            *self.negative_controls,
            *self.health_probes,
        ):
            if item.component_id not in component_ids:
                raise InstrumentedRangeContractError(
                    "component reference is outside the application"
                )
        if not any(item.kind == ReferenceKind.SEEDED_SECRET for item in self.opaque_references):
            raise InstrumentedRangeContractError("a seeded secret reference is required")
        if not any(item.kind == ReferenceKind.CANARY for item in self.opaque_references):
            raise InstrumentedRangeContractError("a canary reference is required")

    def _body(self) -> dict[str, Any]:
        return {
            "application_id": self.application_id,
            "baseline_snapshot": self.baseline_snapshot.to_dict(),
            "build_sha256": self.build_sha256,
            "ground_truth_vulnerabilities": [
                item.to_dict() for item in self.ground_truth_vulnerabilities
            ],
            "health_probes": [item.to_dict() for item in self.health_probes],
            "images": [item.to_dict() for item in self.images],
            "negative_controls": [item.to_dict() for item in self.negative_controls],
            "network_boundaries": [item.to_dict() for item in self.network_boundaries],
            "opaque_references": [item.to_dict() for item in self.opaque_references],
            "resource_quota": self.resource_quota.to_dict(),
            "seeded_data_sets": [item.to_dict() for item in self.seeded_data_sets],
            "source_sha256": self.source_sha256,
            "telemetry_channels": [item.to_dict() for item in self.telemetry_channels],
        }

    @property
    def manifest_id(self) -> str:
        return _identity("IRA", APPLICATION_DOMAIN, self._body())[0]

    @property
    def manifest_sha256(self) -> str:
        return _identity("IRA", APPLICATION_DOMAIN, self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "effects": dict(NO_EFFECTS),
            "manifest_id": self.manifest_id,
            "manifest_sha256": self.manifest_sha256,
            "manifest_type": "synthetic_application",
            "schema_version": SCHEMA_VERSION,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SyntheticApplicationManifest:
        fields = set(cls.__dataclass_fields__) | {
            "effects",
            "manifest_id",
            "manifest_sha256",
            "manifest_type",
            "schema_version",
        }
        values = dict(_exact(raw, fields, "synthetic application manifest"))
        if (
            values.pop("schema_version") != SCHEMA_VERSION
            or values.pop("manifest_type") != "synthetic_application"
        ):
            raise InstrumentedRangeContractError("application manifest metadata is invalid")
        _effects(values.pop("effects"))
        manifest_id = values.pop("manifest_id")
        manifest_sha256 = values.pop("manifest_sha256")
        conversions: tuple[tuple[str, type[Any]], ...] = (
            ("images", ImageBinding),
            ("ground_truth_vulnerabilities", GroundTruthVulnerability),
            ("negative_controls", NegativeControl),
            ("seeded_data_sets", SeededDataSet),
            ("opaque_references", OpaqueReference),
            ("network_boundaries", NetworkBoundary),
            ("telemetry_channels", TelemetryChannel),
            ("health_probes", HealthProbe),
        )
        for name, item_type in conversions:
            values[name] = tuple(item_type.from_dict(item) for item in values[name])
        values["resource_quota"] = ResourceQuota.from_dict(values["resource_quota"])
        values["baseline_snapshot"] = SnapshotManifest.from_dict(values["baseline_snapshot"])
        result = cls(**values)
        if manifest_id != result.manifest_id or manifest_sha256 != result.manifest_sha256:
            raise InstrumentedRangeContractError("application manifest content address is invalid")
        return result


@dataclass(frozen=True)
class RangeScenarioManifest:
    scenario_id: str
    application_id: str
    application_manifest_sha256: str
    expected_vulnerability_ids: tuple[str, ...]
    expected_negative_control_ids: tuple[str, ...]
    required_telemetry_channel_ids: tuple[str, ...]
    required_health_probe_ids: tuple[str, ...]
    reset_manifest: ResetManifest
    scenario_source_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.scenario_id, "scenario_id")
        _identifier(self.application_id, "application_id")
        _sha256(self.application_manifest_sha256, "application_manifest_sha256")
        _sha256(self.scenario_source_sha256, "scenario_source_sha256")
        for name in (
            "expected_vulnerability_ids",
            "expected_negative_control_ids",
            "required_telemetry_channel_ids",
            "required_health_probe_ids",
        ):
            values = _bounded_unique(getattr(self, name), name)
            for value in values:
                _identifier(value, name[:-1])
            object.__setattr__(self, name, values)

    def _body(self) -> dict[str, Any]:
        return {
            "application_id": self.application_id,
            "application_manifest_sha256": self.application_manifest_sha256,
            "expected_negative_control_ids": list(self.expected_negative_control_ids),
            "expected_vulnerability_ids": list(self.expected_vulnerability_ids),
            "required_health_probe_ids": list(self.required_health_probe_ids),
            "required_telemetry_channel_ids": list(self.required_telemetry_channel_ids),
            "reset_manifest": self.reset_manifest.to_dict(),
            "scenario_id": self.scenario_id,
            "scenario_source_sha256": self.scenario_source_sha256,
        }

    @property
    def manifest_id(self) -> str:
        return _identity("IRS", SCENARIO_DOMAIN, self._body())[0]

    @property
    def manifest_sha256(self) -> str:
        return _identity("IRS", SCENARIO_DOMAIN, self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "effects": dict(NO_EFFECTS),
            "manifest_id": self.manifest_id,
            "manifest_sha256": self.manifest_sha256,
            "manifest_type": "range_scenario",
            "schema_version": SCHEMA_VERSION,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RangeScenarioManifest:
        fields = set(cls.__dataclass_fields__) | {
            "effects",
            "manifest_id",
            "manifest_sha256",
            "manifest_type",
            "schema_version",
        }
        values = dict(_exact(raw, fields, "range scenario manifest"))
        if (
            values.pop("schema_version") != SCHEMA_VERSION
            or values.pop("manifest_type") != "range_scenario"
        ):
            raise InstrumentedRangeContractError("scenario manifest metadata is invalid")
        _effects(values.pop("effects"))
        manifest_id = values.pop("manifest_id")
        manifest_sha256 = values.pop("manifest_sha256")
        for name in (
            "expected_vulnerability_ids",
            "expected_negative_control_ids",
            "required_telemetry_channel_ids",
            "required_health_probe_ids",
        ):
            values[name] = tuple(values[name])
        values["reset_manifest"] = ResetManifest.from_dict(values["reset_manifest"])
        result = cls(**values)
        if manifest_id != result.manifest_id or manifest_sha256 != result.manifest_sha256:
            raise InstrumentedRangeContractError("scenario manifest content address is invalid")
        return result


@dataclass(frozen=True)
class RestorationCheck:
    check_id: str
    expected_sha256: str
    observed_sha256: str
    matched: bool

    def __post_init__(self) -> None:
        _identifier(self.check_id, "check_id")
        _sha256(self.expected_sha256, "expected_sha256")
        _sha256(self.observed_sha256, "observed_sha256")
        if not isinstance(self.matched, bool):
            raise InstrumentedRangeContractError("matched must be boolean")
        if self.matched != (self.expected_sha256 == self.observed_sha256):
            raise InstrumentedRangeContractError("restoration check match is inconsistent")

    def to_dict(self) -> dict[str, Any]:
        return vars(self).copy()

    @classmethod
    def from_dict(cls, raw: Any) -> RestorationCheck:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "restoration check"))


@dataclass(frozen=True)
class RangeReadinessObservation:
    scenario_id: str
    scenario_manifest_sha256: str
    application_id: str
    application_manifest_sha256: str
    observed_at: str
    reset_id: str
    reset_completed_at: str
    observed_snapshot_id: str
    observed_snapshot_sha256: str
    contamination_detected: bool
    health_probe_results: tuple[tuple[str, bool], ...]
    telemetry_channel_results: tuple[tuple[str, bool], ...]
    restoration_checks: tuple[RestorationCheck, ...]
    evidence_sha256: str

    def __post_init__(self) -> None:
        for name in ("scenario_id", "application_id", "reset_id", "observed_snapshot_id"):
            _identifier(getattr(self, name), name)
        for name in (
            "scenario_manifest_sha256",
            "application_manifest_sha256",
            "observed_snapshot_sha256",
            "evidence_sha256",
        ):
            _sha256(getattr(self, name), name)
        observed = _timestamp(self.observed_at, "observed_at")
        reset = _timestamp(self.reset_completed_at, "reset_completed_at")
        if reset > observed:
            raise InstrumentedRangeContractError("reset completion follows observation")
        if not isinstance(self.contamination_detected, bool):
            raise InstrumentedRangeContractError("contamination_detected must be boolean")
        for name in ("health_probe_results", "telemetry_channel_results"):
            values = tuple(getattr(self, name))
            if not values or len(values) > MAX_ITEMS:
                raise InstrumentedRangeContractError(f"{name} must be bounded and nonempty")
            keys: list[str] = []
            for key, result in values:
                _identifier(key, name)
                if not isinstance(result, bool):
                    raise InstrumentedRangeContractError(f"{name} results must be boolean")
                keys.append(key)
            if len(keys) != len(set(keys)):
                raise InstrumentedRangeContractError(f"{name} keys must be unique")
            object.__setattr__(self, name, values)
        object.__setattr__(
            self,
            "restoration_checks",
            _unique_by(self.restoration_checks, "check_id", "restoration_checks"),
        )

    def _body(self) -> dict[str, Any]:
        return {
            "application_id": self.application_id,
            "application_manifest_sha256": self.application_manifest_sha256,
            "contamination_detected": self.contamination_detected,
            "evidence_sha256": self.evidence_sha256,
            "health_probe_results": dict(self.health_probe_results),
            "observed_at": self.observed_at,
            "observed_snapshot_id": self.observed_snapshot_id,
            "observed_snapshot_sha256": self.observed_snapshot_sha256,
            "reset_completed_at": self.reset_completed_at,
            "reset_id": self.reset_id,
            "restoration_checks": [item.to_dict() for item in self.restoration_checks],
            "scenario_id": self.scenario_id,
            "scenario_manifest_sha256": self.scenario_manifest_sha256,
            "telemetry_channel_results": dict(self.telemetry_channel_results),
        }

    @property
    def observation_id(self) -> str:
        return _identity("IRO", OBSERVATION_DOMAIN, self._body())[0]

    @property
    def observation_sha256(self) -> str:
        return _identity("IRO", OBSERVATION_DOMAIN, self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "effects": dict(NO_EFFECTS),
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "schema_version": SCHEMA_VERSION,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RangeReadinessObservation:
        fields = set(cls.__dataclass_fields__) | {
            "effects",
            "observation_id",
            "observation_sha256",
            "schema_version",
        }
        values = dict(_exact(raw, fields, "range readiness observation"))
        if values.pop("schema_version") != SCHEMA_VERSION:
            raise InstrumentedRangeContractError("observation schema version is invalid")
        _effects(values.pop("effects"))
        observation_id = values.pop("observation_id")
        observation_sha256 = values.pop("observation_sha256")
        values["health_probe_results"] = tuple(values["health_probe_results"].items())
        values["telemetry_channel_results"] = tuple(values["telemetry_channel_results"].items())
        values["restoration_checks"] = tuple(
            RestorationCheck.from_dict(item) for item in values["restoration_checks"]
        )
        result = cls(**values)
        if (
            observation_id != result.observation_id
            or observation_sha256 != result.observation_sha256
        ):
            raise InstrumentedRangeContractError("observation content address is invalid")
        return result


@dataclass(frozen=True)
class RangeReadinessAssessment:
    application_manifest_sha256: str
    scenario_manifest_sha256: str
    observation_sha256: str
    evaluated_at: str
    maximum_observation_age_seconds: int
    status: ReadinessStatus | str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in (
            "application_manifest_sha256",
            "scenario_manifest_sha256",
            "observation_sha256",
        ):
            _sha256(getattr(self, name), name)
        _timestamp(self.evaluated_at, "evaluated_at")
        _positive_int(
            self.maximum_observation_age_seconds,
            "maximum_observation_age_seconds",
            MAX_AGE_SECONDS,
        )
        object.__setattr__(self, "status", _enum(ReadinessStatus, self.status, "status"))
        reasons = tuple(self.reason_codes)
        if len(reasons) > MAX_ITEMS or len(reasons) != len(set(reasons)):
            raise InstrumentedRangeContractError("reason_codes must be bounded and unique")
        for reason in reasons:
            _identifier(reason, "reason_code")
        if (self.status == ReadinessStatus.READY) != (not reasons):
            raise InstrumentedRangeContractError("readiness status and reasons are inconsistent")
        object.__setattr__(self, "reason_codes", reasons)

    def _body(self) -> dict[str, Any]:
        return {
            "application_manifest_sha256": self.application_manifest_sha256,
            "evaluated_at": self.evaluated_at,
            "maximum_observation_age_seconds": self.maximum_observation_age_seconds,
            "observation_sha256": self.observation_sha256,
            "reason_codes": list(self.reason_codes),
            "scenario_manifest_sha256": self.scenario_manifest_sha256,
            "status": self.status.value,
        }

    @property
    def assessment_id(self) -> str:
        return _identity("IRD", ASSESSMENT_DOMAIN, self._body())[0]

    @property
    def assessment_sha256(self) -> str:
        return _identity("IRD", ASSESSMENT_DOMAIN, self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            "effects": dict(NO_EFFECTS),
            "schema_version": SCHEMA_VERSION,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RangeReadinessAssessment:
        fields = set(cls.__dataclass_fields__) | {
            "assessment_id",
            "assessment_sha256",
            "effects",
            "schema_version",
        }
        values = dict(_exact(raw, fields, "range readiness assessment"))
        if values.pop("schema_version") != SCHEMA_VERSION:
            raise InstrumentedRangeContractError("assessment schema version is invalid")
        _effects(values.pop("effects"))
        assessment_id = values.pop("assessment_id")
        assessment_sha256 = values.pop("assessment_sha256")
        values["reason_codes"] = tuple(values["reason_codes"])
        result = cls(**values)
        if assessment_id != result.assessment_id or assessment_sha256 != result.assessment_sha256:
            raise InstrumentedRangeContractError("assessment content address is invalid")
        return result


def assess_range_readiness(
    application: SyntheticApplicationManifest,
    scenario: RangeScenarioManifest,
    observation: RangeReadinessObservation,
    *,
    evaluated_at: str,
    maximum_observation_age_seconds: int = 900,
) -> RangeReadinessAssessment:
    """Evaluate supplied evidence without inspecting or changing a live range."""

    evaluated = _timestamp(evaluated_at, "evaluated_at")
    observed = _timestamp(observation.observed_at, "observed_at")
    _positive_int(
        maximum_observation_age_seconds,
        "maximum_observation_age_seconds",
        MAX_AGE_SECONDS,
    )
    reasons: list[str] = []
    if (
        evaluated < observed
        or (evaluated - observed).total_seconds() > maximum_observation_age_seconds
    ):
        reasons.append("stale_observation")
    if scenario.application_id != application.application_id:
        reasons.append("scenario_application_mismatch")
    if scenario.application_manifest_sha256 != application.manifest_sha256:
        reasons.append("scenario_application_hash_mismatch")
    if observation.scenario_id != scenario.scenario_id:
        reasons.append("observation_scenario_mismatch")
    if observation.scenario_manifest_sha256 != scenario.manifest_sha256:
        reasons.append("observation_scenario_hash_mismatch")
    if observation.application_id != application.application_id:
        reasons.append("observation_application_mismatch")
    if observation.application_manifest_sha256 != application.manifest_sha256:
        reasons.append("observation_application_hash_mismatch")

    vulnerability_ids = {item.vulnerability_id for item in application.ground_truth_vulnerabilities}
    if set(scenario.expected_vulnerability_ids) != vulnerability_ids:
        reasons.append("ground_truth_incomplete")
    control_ids = {item.control_id for item in application.negative_controls}
    if set(scenario.expected_negative_control_ids) != control_ids:
        reasons.append("negative_controls_incomplete")
    telemetry_ids = {item.channel_id for item in application.telemetry_channels}
    if set(scenario.required_telemetry_channel_ids) - telemetry_ids:
        reasons.append("telemetry_definition_mismatch")
    probe_ids = {item.probe_id for item in application.health_probes}
    if set(scenario.required_health_probe_ids) - probe_ids:
        reasons.append("health_probe_definition_mismatch")

    reset = scenario.reset_manifest
    snapshot = application.baseline_snapshot
    if (
        reset.baseline_snapshot_id != snapshot.snapshot_id
        or reset.baseline_snapshot_sha256 != snapshot.snapshot_sha256
    ):
        reasons.append("reset_baseline_mismatch")
    if observation.reset_id != reset.reset_id:
        reasons.append("range_unreset")
    if (
        observation.observed_snapshot_id != snapshot.snapshot_id
        or observation.observed_snapshot_sha256 != snapshot.snapshot_sha256
    ):
        reasons.append("baseline_not_restored")
    if observation.contamination_detected:
        reasons.append("range_contaminated")

    health = dict(observation.health_probe_results)
    required_health = set(scenario.required_health_probe_ids)
    if set(health) != required_health:
        reasons.append("health_evidence_incomplete")
    if any(not health.get(probe_id, False) for probe_id in required_health):
        reasons.append("range_unhealthy")
    telemetry = dict(observation.telemetry_channel_results)
    required_telemetry = set(scenario.required_telemetry_channel_ids)
    if set(telemetry) != required_telemetry:
        reasons.append("telemetry_evidence_incomplete")
    if any(not telemetry.get(channel_id, False) for channel_id in required_telemetry):
        reasons.append("telemetry_blind")
    restoration = {item.check_id: item for item in observation.restoration_checks}
    required_checks = set(reset.required_restoration_check_ids)
    if set(restoration) != required_checks:
        reasons.append("restoration_evidence_incomplete")
    if any(not restoration[check_id].matched for check_id in required_checks & set(restoration)):
        reasons.append("restoration_check_failed")

    ordered_reasons = tuple(dict.fromkeys(reasons))
    return RangeReadinessAssessment(
        application_manifest_sha256=application.manifest_sha256,
        scenario_manifest_sha256=scenario.manifest_sha256,
        observation_sha256=observation.observation_sha256,
        evaluated_at=evaluated_at,
        maximum_observation_age_seconds=maximum_observation_age_seconds,
        status=ReadinessStatus.READY if not ordered_reasons else ReadinessStatus.NOT_READY,
        reason_codes=ordered_reasons,
    )


def parse_application_manifest(raw: Mapping[str, Any]) -> SyntheticApplicationManifest:
    return SyntheticApplicationManifest.from_dict(raw)


def parse_scenario_manifest(raw: Mapping[str, Any]) -> RangeScenarioManifest:
    return RangeScenarioManifest.from_dict(raw)


def parse_readiness_observation(raw: Mapping[str, Any]) -> RangeReadinessObservation:
    return RangeReadinessObservation.from_dict(raw)


def parse_readiness_assessment(raw: Mapping[str, Any]) -> RangeReadinessAssessment:
    return RangeReadinessAssessment.from_dict(raw)
