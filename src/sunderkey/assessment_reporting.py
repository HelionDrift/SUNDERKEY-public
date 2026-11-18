"""Deterministic, infrastructure-independent assessment reporting contracts.

The values in this module are immutable reporting projections. They do not
perform target interaction, execution, network access, qualification, routing,
deployment, or authority changes.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar

SCHEMA_VERSION = 1
BUNDLE_KIND = "sunderkey.assessment-report-bundle.v1"

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
CWE_RE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
CVSS_RE = re.compile(r"CVSS:3\.[01](?:/[A-Z]{1,3}:[A-Z]){8}\Z")
SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|authorization|cookie|set-cookie)\s*[:=]|"
    r"\b(?:password|passwd|api[_ -]?key|client[_ -]?secret)\s+(?:is|was)\s+"
    r"(?=\S{6,})(?=\S*[0-9=+/_-])\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
    r"\bsk-[A-Za-z0-9_-]{20,}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"
    r")",
    re.IGNORECASE,
)
PAYLOAD_RE = re.compile(
    r"(?:<script\b|\bunion\s+select\b|\$\{jndi:|\.\./\.\./|"
    r"\b(?:curl|wget|powershell|cmd\.exe)\s+https?://)",
    re.IGNORECASE,
)
RESPONSE_BODY_RE = re.compile(
    r"^\s*(?:HTTP/[0-9.]|\{|\[|<!DOCTYPE\s+html|<html\b|<\?xml\b)",
    re.IGNORECASE,
)

NO_EFFECTS = {
    "authority": "none",
    "browser": "none",
    "credential_values": "none",
    "deployment": "none",
    "execution": "none",
    "integrations": "none",
    "network": "none",
    "payload_generation": "none",
    "qualification": "none",
    "requests": "none",
    "routing": "none",
    "target_authority": "none",
    "tools": "none",
}

SEVERITIES = ("informational", "low", "medium", "high", "critical", "unrated")
FINDING_STATUSES = (
    "new",
    "triaged",
    "validated",
    "accepted",
    "remediation_in_progress",
    "retest_pending",
    "resolved",
    "risk_accepted",
    "false_positive",
    "reopened",
)
TASK_STATUSES = ("tested", "negative", "abstained", "blocked", "untested", "not_determined")
VALIDATION_STATUSES = ("validated", "negative", "inconclusive", "abstained")
RETEST_STATUSES = ("not_planned", "pending", "fixed", "persists", "inconclusive", "abstained")
RESTORATION_STATUSES = ("not_required", "verified", "incomplete", "failed", "not_determined")
RISK_RATINGS = ("informational", "low", "medium", "high", "critical", "not_determined")
ATTESTATION_ROLES = frozenset({"independent_control", "independent_assurance", "attestor"})
REPORT_ROLES = frozenset({"report_author", "technical_reviewer"})


class AssessmentReportingError(ValueError):
    """Raised when a reporting contract is unsafe, stale, or inconsistent."""


class CoverageStatus(StrEnum):
    TESTED = "tested"
    NEGATIVE = "negative"
    ABSTAINED = "abstained"
    BLOCKED = "blocked"
    UNTESTED = "untested"
    NOT_DETERMINED = "not_determined"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

    _validate_json(value, "value")
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise AssessmentReportingError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    seed = {"domain": kind, "content": dict(body)}
    digest = canonical_sha256(seed)
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise AssessmentReportingError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AssessmentReportingError(f"{label} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AssessmentReportingError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise AssessmentReportingError(f"{label} contains an unsupported value")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise AssessmentReportingError(f"{label} must be a safe identifier")
    _safe_text(value, label, maximum=256)
    return value


def _token(value: Any, label: str, allowed: Sequence[str] | None = None) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise AssessmentReportingError(f"{label} must be a token")
    if allowed is not None and value not in allowed:
        raise AssessmentReportingError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise AssessmentReportingError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise AssessmentReportingError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AssessmentReportingError(f"{label} must be a valid timestamp") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _safe_text(value: Any, label: str, *, maximum: int = 4000, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise AssessmentReportingError(f"{label} must be non-empty text")
    if len(value) > maximum or any(
        ord(character) < 32 and character not in "\t\n" for character in value
    ):
        raise AssessmentReportingError(f"{label} contains unsafe text")
    if SECRET_RE.search(value):
        raise AssessmentReportingError(f"{label} contains secret-like material")
    return value


def _narrative(value: Any, label: str, *, maximum: int = 4000) -> str:
    text = _safe_text(value, label, maximum=maximum)
    if PAYLOAD_RE.search(text):
        raise AssessmentReportingError(f"{label} contains payload-like material")
    if RESPONSE_BODY_RE.search(text):
        raise AssessmentReportingError(f"{label} resembles an unredacted response body")
    return text


def _ordered_unique(values: Sequence[str], label: str, validator: Any) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise AssessmentReportingError(f"{label} must be a sequence")
    normalized = tuple(validator(item, f"{label} item") for item in values)
    if len(normalized) != len(set(normalized)):
        raise AssessmentReportingError(f"{label} must not contain duplicates")
    if normalized != tuple(sorted(normalized)):
        normalized = tuple(sorted(normalized))
    return normalized


def _digests(values: Sequence[str], label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    result = _ordered_unique(values, label, _digest)
    if not result and not allow_empty:
        raise AssessmentReportingError(f"{label} must not be empty")
    return result


def _identifiers(values: Sequence[str], label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    result = _ordered_unique(values, label, _identifier)
    if not result and not allow_empty:
        raise AssessmentReportingError(f"{label} must not be empty")
    return result


def _exact_fields(raw: Any, expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise AssessmentReportingError(f"{label} fields are invalid")


def _list(raw: Any, label: str) -> list[Any]:
    if not isinstance(raw, list):
        raise AssessmentReportingError(f"{label} must be a JSON array")
    return raw


def _no_effects(raw: Any, label: str) -> None:
    if not isinstance(raw, Mapping) or dict(raw) != NO_EFFECTS:
        raise AssessmentReportingError(f"{label} attempts effect escalation")


def _verify_raw(raw: Mapping[str, Any], candidate: Any, label: str) -> Any:
    if canonical_json(dict(raw)) != canonical_json(candidate.to_dict()):
        raise AssessmentReportingError(f"{label} identity or contents are invalid")
    return candidate


@dataclass(frozen=True)
class AssetRecord:
    """One scoped asset and its reportable operations."""

    asset_id: str
    asset_type: str
    display_name: str
    operation_ids: tuple[str, ...]
    signed_scope_sha256: str
    evidence_digests: tuple[str, ...]
    asset_record_id: str = field(init=False)
    asset_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.asset-record.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "asset_id", _identifier(self.asset_id, "asset_id"))
        object.__setattr__(self, "asset_type", _token(self.asset_type, "asset_type"))
        object.__setattr__(
            self, "display_name", _safe_text(self.display_name, "display_name", maximum=256)
        )
        object.__setattr__(
            self,
            "operation_ids",
            _identifiers(self.operation_ids, "operation_ids", allow_empty=False),
        )
        object.__setattr__(
            self, "signed_scope_sha256", _digest(self.signed_scope_sha256, "signed_scope_sha256")
        )
        object.__setattr__(
            self,
            "evidence_digests",
            _digests(self.evidence_digests, "evidence_digests", allow_empty=False),
        )
        record_id, digest = _identity("AST", self.KIND, self._body())
        object.__setattr__(self, "asset_record_id", record_id)
        object.__setattr__(self, "asset_sha256", digest)

    @property
    def coverage_area_ids(self) -> tuple[str, ...]:
        return tuple(f"{self.asset_id}::{operation_id}" for operation_id in self.operation_ids)

    def _body(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "display_name": self.display_name,
            "evidence_digests": list(self.evidence_digests),
            "operation_ids": list(self.operation_ids),
            "signed_scope_sha256": self.signed_scope_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "asset_record_id": self.asset_record_id,
            "asset_sha256": self.asset_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AssetRecord:
        fields = set(
            cls(
                "asset",
                "service",
                "Asset",
                ("read",),
                "sha256:" + "0" * 64,
                ("sha256:" + "1" * 64,),
            ).to_dict()
        )
        _exact_fields(raw, fields, "asset record")
        _no_effects(raw["effects"], "asset record")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise AssessmentReportingError("asset record kind or schema_version is invalid")
        candidate = cls(
            asset_id=raw["asset_id"],
            asset_type=raw["asset_type"],
            display_name=raw["display_name"],
            operation_ids=tuple(_list(raw["operation_ids"], "operation_ids")),
            signed_scope_sha256=raw["signed_scope_sha256"],
            evidence_digests=tuple(_list(raw["evidence_digests"], "evidence_digests")),
        )
        return _verify_raw(raw, candidate, "asset record")


@dataclass(frozen=True)
class TaskTranscript:
    """Digest-only task transcript binding with an explicit coverage outcome."""

    task_id: str
    transcript_sha256: str
    coverage_area_id: str
    technique_id: str
    profile_id: str
    status: CoverageStatus | str
    started_at: str
    ended_at: str
    signed_scope_sha256: str
    world_snapshot_sha256: str
    schedule_sha256: str
    evidence_digests: tuple[str, ...] = ()
    blocker_code: str | None = None
    restoration_required: bool = False
    restoration_status: str = "not_required"
    transcript_record_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for name in ("task_id", "coverage_area_id", "technique_id", "profile_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(
            self, "transcript_sha256", _digest(self.transcript_sha256, "transcript_sha256")
        )
        try:
            status = CoverageStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise AssessmentReportingError("task status is invalid") from exc
        object.__setattr__(self, "status", status)
        started = _timestamp(self.started_at, "started_at")
        ended = _timestamp(self.ended_at, "ended_at")
        if _instant(started) > _instant(ended):
            raise AssessmentReportingError("task ends before it starts")
        for name in ("signed_scope_sha256", "world_snapshot_sha256", "schedule_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        object.__setattr__(
            self, "evidence_digests", _digests(self.evidence_digests, "task evidence_digests")
        )
        if self.blocker_code is not None:
            object.__setattr__(self, "blocker_code", _token(self.blocker_code, "blocker_code"))
        if status is CoverageStatus.BLOCKED and self.blocker_code is None:
            raise AssessmentReportingError("blocked task requires blocker_code")
        if status is not CoverageStatus.BLOCKED and self.blocker_code is not None:
            raise AssessmentReportingError("only blocked tasks may carry blocker_code")
        if not isinstance(self.restoration_required, bool):
            raise AssessmentReportingError("restoration_required must be boolean")
        _token(self.restoration_status, "restoration_status", RESTORATION_STATUSES)
        if not self.restoration_required and self.restoration_status != "not_required":
            raise AssessmentReportingError("unneeded restoration must be not_required")
        if self.restoration_required and self.restoration_status == "not_required":
            raise AssessmentReportingError("required restoration needs an explicit status")
        object.__setattr__(self, "transcript_record_sha256", canonical_sha256(self._body()))

    def _body(self) -> dict[str, Any]:
        return {
            "blocker_code": self.blocker_code,
            "coverage_area_id": self.coverage_area_id,
            "ended_at": self.ended_at,
            "evidence_digests": list(self.evidence_digests),
            "profile_id": self.profile_id,
            "restoration_required": self.restoration_required,
            "restoration_status": self.restoration_status,
            "schedule_sha256": self.schedule_sha256,
            "signed_scope_sha256": self.signed_scope_sha256,
            "started_at": self.started_at,
            "status": self.status.value,
            "task_id": self.task_id,
            "technique_id": self.technique_id,
            "transcript_sha256": self.transcript_sha256,
            "world_snapshot_sha256": self.world_snapshot_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "transcript_record_sha256": self.transcript_record_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> TaskTranscript:
        fields = {
            "blocker_code",
            "coverage_area_id",
            "ended_at",
            "evidence_digests",
            "profile_id",
            "restoration_required",
            "restoration_status",
            "schedule_sha256",
            "signed_scope_sha256",
            "started_at",
            "status",
            "task_id",
            "technique_id",
            "transcript_record_sha256",
            "transcript_sha256",
            "world_snapshot_sha256",
        }
        _exact_fields(raw, fields, "task transcript")
        candidate = cls(
            task_id=raw["task_id"],
            transcript_sha256=raw["transcript_sha256"],
            coverage_area_id=raw["coverage_area_id"],
            technique_id=raw["technique_id"],
            profile_id=raw["profile_id"],
            status=raw["status"],
            started_at=raw["started_at"],
            ended_at=raw["ended_at"],
            signed_scope_sha256=raw["signed_scope_sha256"],
            world_snapshot_sha256=raw["world_snapshot_sha256"],
            schedule_sha256=raw["schedule_sha256"],
            evidence_digests=tuple(_list(raw["evidence_digests"], "task evidence_digests")),
            blocker_code=raw["blocker_code"],
            restoration_required=raw["restoration_required"],
            restoration_status=raw["restoration_status"],
        )
        if candidate.to_dict() != dict(raw):
            raise AssessmentReportingError("task transcript digest or contents are invalid")
        return candidate


@dataclass(frozen=True)
class ValidatorResultReference:
    validator_id: str
    task_id: str
    result_sha256: str
    outcome: str
    evidence_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "validator_id", _identifier(self.validator_id, "validator_id"))
        object.__setattr__(self, "task_id", _identifier(self.task_id, "validator task_id"))
        object.__setattr__(
            self, "result_sha256", _digest(self.result_sha256, "validator result_sha256")
        )
        object.__setattr__(
            self, "outcome", _token(self.outcome, "validator outcome", VALIDATION_STATUSES)
        )
        object.__setattr__(
            self,
            "evidence_digests",
            _digests(self.evidence_digests, "validator evidence_digests", allow_empty=False),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_digests": list(self.evidence_digests),
            "outcome": self.outcome,
            "result_sha256": self.result_sha256,
            "task_id": self.task_id,
            "validator_id": self.validator_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ValidatorResultReference:
        _exact_fields(
            raw,
            {"evidence_digests", "outcome", "result_sha256", "task_id", "validator_id"},
            "validator result reference",
        )
        return cls(
            raw["validator_id"],
            raw["task_id"],
            raw["result_sha256"],
            raw["outcome"],
            tuple(_list(raw["evidence_digests"], "validator evidence_digests")),
        )


@dataclass(frozen=True)
class FindingLifecycleReference:
    finding_id: str
    snapshot_sha256: str
    state: str
    updated_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", _identifier(self.finding_id, "finding_id"))
        object.__setattr__(
            self, "snapshot_sha256", _digest(self.snapshot_sha256, "finding snapshot_sha256")
        )
        object.__setattr__(self, "state", _token(self.state, "finding state", FINDING_STATUSES))
        object.__setattr__(self, "updated_at", _timestamp(self.updated_at, "finding updated_at"))

    def to_dict(self) -> dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "snapshot_sha256": self.snapshot_sha256,
            "state": self.state,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> FindingLifecycleReference:
        _exact_fields(
            raw,
            {"finding_id", "snapshot_sha256", "state", "updated_at"},
            "finding lifecycle reference",
        )
        return cls(**raw)


@dataclass(frozen=True)
class CoverageMetrics:
    total_areas: int
    tested: int
    negative_results: int
    abstentions: int
    blocked: int
    untested: int
    not_determined: int
    coverage_basis_points: int = field(init=False)

    def __post_init__(self) -> None:
        for name in (
            "total_areas",
            "tested",
            "negative_results",
            "abstentions",
            "blocked",
            "untested",
            "not_determined",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise AssessmentReportingError(f"{name} must be a non-negative integer")
        parts = (
            self.tested
            + self.negative_results
            + self.abstentions
            + self.blocked
            + self.untested
            + self.not_determined
        )
        if self.total_areas <= 0 or parts != self.total_areas:
            raise AssessmentReportingError("coverage counts must exactly partition total_areas")
        covered = self.tested + self.negative_results
        object.__setattr__(self, "coverage_basis_points", (covered * 10_000) // self.total_areas)

    @classmethod
    def from_tasks(cls, tasks: Sequence[TaskTranscript]) -> CoverageMetrics:
        counts = {status: 0 for status in TASK_STATUSES}
        for task in tasks:
            counts[task.status.value] += 1
        return cls(
            len(tasks),
            counts["tested"],
            counts["negative"],
            counts["abstained"],
            counts["blocked"],
            counts["untested"],
            counts["not_determined"],
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "abstentions": self.abstentions,
            "blocked": self.blocked,
            "coverage_basis_points": self.coverage_basis_points,
            "negative_results": self.negative_results,
            "not_determined": self.not_determined,
            "tested": self.tested,
            "total_areas": self.total_areas,
            "untested": self.untested,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CoverageMetrics:
        _exact_fields(
            raw,
            {
                "abstentions",
                "blocked",
                "coverage_basis_points",
                "negative_results",
                "not_determined",
                "tested",
                "total_areas",
                "untested",
            },
            "coverage metrics",
        )
        candidate = cls(
            raw["total_areas"],
            raw["tested"],
            raw["negative_results"],
            raw["abstentions"],
            raw["blocked"],
            raw["untested"],
            raw["not_determined"],
        )
        if canonical_json(candidate.to_dict()) != canonical_json(dict(raw)):
            raise AssessmentReportingError("coverage metrics are inflated or inconsistent")
        return candidate


def _restoration_status(tasks: Sequence[TaskTranscript]) -> str:
    required = [task.restoration_status for task in tasks if task.restoration_required]
    if not required:
        return "not_required"
    for status in ("failed", "incomplete", "not_determined"):
        if status in required:
            return status
    return "verified"


@dataclass(frozen=True)
class AssessmentRecord:
    """Complete source binding for one bounded assessment."""

    assets: tuple[AssetRecord, ...]
    signed_scope_sha256: str
    world_snapshot_sha256: str
    schedule_sha256: str
    task_transcripts: tuple[TaskTranscript, ...]
    validator_results: tuple[ValidatorResultReference, ...]
    finding_lifecycle: tuple[FindingLifecycleReference, ...]
    started_at: str
    ended_at: str
    source_observed_at: str
    generated_at: str
    max_source_age_seconds: int
    residual_risk: str
    residual_risk_rating: str
    scope_limits: tuple[str, ...]
    assessment_id: str = field(init=False)
    assessment_sha256: str = field(init=False)
    completeness: str = field(init=False)
    coverage_metrics: CoverageMetrics = field(init=False)
    restoration_status: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.assessment-record.v1"

    def __post_init__(self) -> None:
        assets = tuple(self.assets)
        tasks = tuple(self.task_transcripts)
        validators = tuple(self.validator_results)
        lifecycle = tuple(self.finding_lifecycle)
        if not assets or not tasks:
            raise AssessmentReportingError("assets and complete task coverage are required")
        if not all(isinstance(item, AssetRecord) for item in assets):
            raise AssessmentReportingError("assets must contain AssetRecord values")
        if not all(isinstance(item, TaskTranscript) for item in tasks):
            raise AssessmentReportingError("task_transcripts must contain TaskTranscript values")
        if not all(isinstance(item, ValidatorResultReference) for item in validators):
            raise AssessmentReportingError("validator_results contain an invalid value")
        if not all(isinstance(item, FindingLifecycleReference) for item in lifecycle):
            raise AssessmentReportingError("finding_lifecycle contains an invalid value")
        for name, values, key in (
            ("asset IDs", assets, lambda item: item.asset_id),
            ("task IDs", tasks, lambda item: item.task_id),
            ("coverage areas", tasks, lambda item: item.coverage_area_id),
            ("validator result digests", validators, lambda item: item.result_sha256),
            ("finding IDs", lifecycle, lambda item: item.finding_id),
        ):
            members = [key(item) for item in values]
            if len(members) != len(set(members)):
                raise AssessmentReportingError(f"{name} must be unique")
        object.__setattr__(self, "assets", tuple(sorted(assets, key=lambda item: item.asset_id)))
        object.__setattr__(
            self, "task_transcripts", tuple(sorted(tasks, key=lambda item: item.coverage_area_id))
        )
        object.__setattr__(
            self,
            "validator_results",
            tuple(sorted(validators, key=lambda item: (item.task_id, item.validator_id))),
        )
        object.__setattr__(
            self, "finding_lifecycle", tuple(sorted(lifecycle, key=lambda item: item.finding_id))
        )
        for name in ("signed_scope_sha256", "world_snapshot_sha256", "schedule_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        expected_area_ids = tuple(area for asset in assets for area in asset.coverage_area_ids)
        expected_areas = set(expected_area_ids)
        if len(expected_area_ids) != len(expected_areas):
            raise AssessmentReportingError("asset operation coverage area identities are ambiguous")
        actual_areas = {task.coverage_area_id for task in tasks}
        if actual_areas != expected_areas:
            raise AssessmentReportingError(
                "task transcripts must exactly cover every asset operation"
            )
        if any(asset.signed_scope_sha256 != self.signed_scope_sha256 for asset in assets):
            raise AssessmentReportingError("asset scope digest does not match assessment")
        if any(
            task.signed_scope_sha256 != self.signed_scope_sha256
            or task.world_snapshot_sha256 != self.world_snapshot_sha256
            or task.schedule_sha256 != self.schedule_sha256
            for task in tasks
        ):
            raise AssessmentReportingError("task source digest does not match assessment")
        task_by_id = {task.task_id: task for task in tasks}
        expected_outcome = {
            CoverageStatus.TESTED: "validated",
            CoverageStatus.NEGATIVE: "negative",
            CoverageStatus.ABSTAINED: "abstained",
            CoverageStatus.NOT_DETERMINED: "inconclusive",
        }
        for result in validators:
            if result.task_id not in task_by_id:
                raise AssessmentReportingError("validator result references an unknown task")
            task = task_by_id[result.task_id]
            if task.status not in expected_outcome:
                raise AssessmentReportingError(
                    "blocked or untested task cannot have a validator result"
                )
            if result.outcome != expected_outcome[task.status]:
                raise AssessmentReportingError(
                    "validator outcome does not match task coverage status"
                )
            if not set(result.evidence_digests) <= set(task.evidence_digests):
                raise AssessmentReportingError("validator evidence is not bound by its task")
        judged = {item.task_id for item in validators}
        required_judgment = {
            task.task_id
            for task in tasks
            if task.status
            in {
                CoverageStatus.TESTED,
                CoverageStatus.NEGATIVE,
                CoverageStatus.ABSTAINED,
                CoverageStatus.NOT_DETERMINED,
            }
        }
        if not required_judgment <= judged:
            raise AssessmentReportingError("tested or uncertain task lacks a validator result")
        started = _timestamp(self.started_at, "assessment started_at")
        ended = _timestamp(self.ended_at, "assessment ended_at")
        observed = _timestamp(self.source_observed_at, "source_observed_at")
        generated = _timestamp(self.generated_at, "generated_at")
        if (
            not isinstance(self.max_source_age_seconds, int)
            or isinstance(self.max_source_age_seconds, bool)
            or not 0 <= self.max_source_age_seconds <= 31_536_000
        ):
            raise AssessmentReportingError("max_source_age_seconds is invalid")
        if _instant(started) > _instant(ended) or any(
            _instant(task.started_at) < _instant(started)
            or _instant(task.ended_at) > _instant(ended)
            for task in tasks
        ):
            raise AssessmentReportingError("assessment or task time range is invalid")
        if _instant(ended) > _instant(generated):
            raise AssessmentReportingError("report generation precedes assessment completion")
        age = (_instant(generated) - _instant(observed)).total_seconds()
        if age < 0 or age > self.max_source_age_seconds:
            raise AssessmentReportingError("assessment inputs are stale or future-dated")
        if any(_instant(item.updated_at) > _instant(generated) for item in lifecycle):
            raise AssessmentReportingError("finding lifecycle input is future-dated")
        object.__setattr__(
            self, "residual_risk", _narrative(self.residual_risk, "residual_risk", maximum=2000)
        )
        object.__setattr__(
            self,
            "residual_risk_rating",
            _token(self.residual_risk_rating, "residual_risk_rating", RISK_RATINGS),
        )
        limits = tuple(_narrative(item, "scope limit", maximum=500) for item in self.scope_limits)
        if not limits or len(limits) != len(set(limits)):
            raise AssessmentReportingError("scope_limits must be non-empty and unique")
        object.__setattr__(self, "scope_limits", tuple(sorted(limits)))
        metrics = CoverageMetrics.from_tasks(tasks)
        completeness = (
            "complete"
            if not (
                metrics.abstentions or metrics.blocked or metrics.untested or metrics.not_determined
            )
            else "partial"
        )
        object.__setattr__(self, "coverage_metrics", metrics)
        object.__setattr__(self, "completeness", completeness)
        object.__setattr__(self, "restoration_status", _restoration_status(tasks))
        record_id, digest = _identity("ASM", self.KIND, self._body())
        object.__setattr__(self, "assessment_id", record_id)
        object.__setattr__(self, "assessment_sha256", digest)

    @property
    def tested_areas(self) -> tuple[str, ...]:
        return tuple(
            task.coverage_area_id
            for task in self.task_transcripts
            if task.status in {CoverageStatus.TESTED, CoverageStatus.NEGATIVE}
        )

    @property
    def blocked_areas(self) -> tuple[str, ...]:
        return tuple(
            task.coverage_area_id
            for task in self.task_transcripts
            if task.status is CoverageStatus.BLOCKED
        )

    @property
    def untested_areas(self) -> tuple[str, ...]:
        return tuple(
            task.coverage_area_id
            for task in self.task_transcripts
            if task.status is CoverageStatus.UNTESTED
        )

    @property
    def not_determined_areas(self) -> tuple[str, ...]:
        return tuple(
            task.coverage_area_id
            for task in self.task_transcripts
            if task.status in {CoverageStatus.NOT_DETERMINED, CoverageStatus.ABSTAINED}
        )

    def _body(self) -> dict[str, Any]:
        return {
            "assets": [item.to_dict() for item in self.assets],
            "blocked_areas": list(self.blocked_areas),
            "completeness": self.completeness,
            "coverage_metrics": self.coverage_metrics.to_dict(),
            "ended_at": self.ended_at,
            "finding_lifecycle": [item.to_dict() for item in self.finding_lifecycle],
            "generated_at": self.generated_at,
            "max_source_age_seconds": self.max_source_age_seconds,
            "not_determined_areas": list(self.not_determined_areas),
            "residual_risk": self.residual_risk,
            "residual_risk_rating": self.residual_risk_rating,
            "restoration_status": self.restoration_status,
            "schedule_sha256": self.schedule_sha256,
            "scope_limits": list(self.scope_limits),
            "signed_scope_sha256": self.signed_scope_sha256,
            "source_observed_at": self.source_observed_at,
            "started_at": self.started_at,
            "task_transcripts": [item.to_dict() for item in self.task_transcripts],
            "tested_areas": list(self.tested_areas),
            "untested_areas": list(self.untested_areas),
            "validator_results": [item.to_dict() for item in self.validator_results],
            "world_snapshot_sha256": self.world_snapshot_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentRecord:
        expected = {
            "assessment_id",
            "assessment_sha256",
            "assets",
            "blocked_areas",
            "completeness",
            "coverage_metrics",
            "effects",
            "ended_at",
            "finding_lifecycle",
            "generated_at",
            "kind",
            "max_source_age_seconds",
            "not_determined_areas",
            "residual_risk",
            "residual_risk_rating",
            "restoration_status",
            "schedule_sha256",
            "schema_version",
            "scope_limits",
            "signed_scope_sha256",
            "source_observed_at",
            "started_at",
            "task_transcripts",
            "tested_areas",
            "untested_areas",
            "validator_results",
            "world_snapshot_sha256",
        }
        _exact_fields(raw, expected, "assessment record")
        _no_effects(raw["effects"], "assessment record")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise AssessmentReportingError("assessment record kind or schema_version is invalid")
        candidate = cls(
            assets=tuple(AssetRecord.from_dict(item) for item in _list(raw["assets"], "assets")),
            signed_scope_sha256=raw["signed_scope_sha256"],
            world_snapshot_sha256=raw["world_snapshot_sha256"],
            schedule_sha256=raw["schedule_sha256"],
            task_transcripts=tuple(
                TaskTranscript.from_dict(item)
                for item in _list(raw["task_transcripts"], "task_transcripts")
            ),
            validator_results=tuple(
                ValidatorResultReference.from_dict(item)
                for item in _list(raw["validator_results"], "validator_results")
            ),
            finding_lifecycle=tuple(
                FindingLifecycleReference.from_dict(item)
                for item in _list(raw["finding_lifecycle"], "finding_lifecycle")
            ),
            started_at=raw["started_at"],
            ended_at=raw["ended_at"],
            source_observed_at=raw["source_observed_at"],
            generated_at=raw["generated_at"],
            max_source_age_seconds=raw["max_source_age_seconds"],
            residual_risk=raw["residual_risk"],
            residual_risk_rating=raw["residual_risk_rating"],
            scope_limits=tuple(_list(raw["scope_limits"], "scope_limits")),
        )
        return _verify_raw(raw, candidate, "assessment record")


_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss_score(vector: str) -> float:
    if CVSS_RE.fullmatch(vector) is None:
        raise AssessmentReportingError(
            "cvss_vector must be a complete CVSS v3.0 or v3.1 base vector"
        )
    parts = vector.split("/")
    version = parts[0]
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, value = part.split(":", 1)
        if key in metrics:
            raise AssessmentReportingError("cvss_vector contains duplicate metrics")
        metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if set(metrics) != required or metrics["S"] not in {"U", "C"}:
        raise AssessmentReportingError("cvss_vector base metrics are invalid")
    try:
        av = _CVSS_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS_WEIGHTS["AC"][metrics["AC"]]
        ui = _CVSS_WEIGHTS["UI"][metrics["UI"]]
        cia = [_CVSS_WEIGHTS[key][metrics[key]] for key in ("C", "I", "A")]
    except KeyError as exc:
        raise AssessmentReportingError("cvss_vector metric value is invalid") from exc
    pr_values = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
    try:
        pr = pr_values[metrics["S"]][metrics["PR"]]
    except KeyError as exc:
        raise AssessmentReportingError("cvss_vector privilege metric is invalid") from exc
    iss = 1 - math.prod(1 - item for item in cia)
    if metrics["S"] == "U":
        impact = 6.42 * iss
    elif version == "CVSS:3.1":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss * 0.9731 - 0.02) ** 13
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = (
        min(impact + exploitability, 10)
        if metrics["S"] == "U"
        else min(1.08 * (impact + exploitability), 10)
    )
    return math.ceil((raw - 1e-10) * 10) / 10


def _severity_for_score(score: float) -> str:
    if score == 0:
        return "informational"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


@dataclass(frozen=True)
class FindingReport:
    """Redacted finding projection with caller-supplied, validated CVSS data."""

    finding_id: str
    lifecycle_snapshot_sha256: str
    title: str
    affected_asset_id: str
    affected_operation_id: str
    vulnerability_class: str
    cwe_ref: str
    severity: str
    confidence: str
    status: str
    evidence_digests: tuple[str, ...]
    impact_description: str
    reproduction_summary: tuple[str, ...]
    remediation_guidance: str
    validation_status: str
    validation_result_sha256: str
    retest_status: str
    cvss_vector: str | None = None
    cvss_score: float | None = None
    finding_report_id: str = field(init=False)
    finding_report_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.finding-report.v1"

    def __post_init__(self) -> None:
        for name in (
            "finding_id",
            "affected_asset_id",
            "affected_operation_id",
            "vulnerability_class",
        ):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        object.__setattr__(
            self,
            "lifecycle_snapshot_sha256",
            _digest(self.lifecycle_snapshot_sha256, "lifecycle_snapshot_sha256"),
        )
        object.__setattr__(self, "title", _narrative(self.title, "title", maximum=256))
        if not isinstance(self.cwe_ref, str) or CWE_RE.fullmatch(self.cwe_ref) is None:
            raise AssessmentReportingError("cwe_ref is invalid")
        object.__setattr__(self, "severity", _token(self.severity, "severity", SEVERITIES))
        object.__setattr__(
            self, "confidence", _token(self.confidence, "confidence", ("low", "medium", "high"))
        )
        object.__setattr__(self, "status", _token(self.status, "status", FINDING_STATUSES))
        object.__setattr__(
            self,
            "evidence_digests",
            _digests(self.evidence_digests, "finding evidence_digests", allow_empty=False),
        )
        object.__setattr__(
            self, "impact_description", _narrative(self.impact_description, "impact_description")
        )
        steps = tuple(
            _narrative(step, "reproduction step", maximum=500) for step in self.reproduction_summary
        )
        if not steps or len(steps) > 12:
            raise AssessmentReportingError(
                "reproduction_summary must contain 1 to 12 high-level steps"
            )
        object.__setattr__(self, "reproduction_summary", steps)
        object.__setattr__(
            self,
            "remediation_guidance",
            _narrative(self.remediation_guidance, "remediation_guidance"),
        )
        object.__setattr__(
            self,
            "validation_status",
            _token(self.validation_status, "validation_status", VALIDATION_STATUSES),
        )
        object.__setattr__(
            self,
            "validation_result_sha256",
            _digest(self.validation_result_sha256, "validation_result_sha256"),
        )
        object.__setattr__(
            self, "retest_status", _token(self.retest_status, "retest_status", RETEST_STATUSES)
        )
        if (self.cvss_vector is None) != (self.cvss_score is None):
            raise AssessmentReportingError("cvss_vector and cvss_score must be supplied together")
        if self.cvss_vector is not None:
            if (
                not isinstance(self.cvss_score, (int, float))
                or isinstance(self.cvss_score, bool)
                or not math.isfinite(float(self.cvss_score))
                or not 0 <= float(self.cvss_score) <= 10
            ):
                raise AssessmentReportingError("cvss_score is invalid")
            supplied = float(self.cvss_score)
            expected = _cvss_score(self.cvss_vector)
            if supplied != expected:
                raise AssessmentReportingError("cvss_score does not match cvss_vector")
            if self.severity != _severity_for_score(supplied):
                raise AssessmentReportingError("severity does not match caller-supplied CVSS score")
            object.__setattr__(self, "cvss_score", supplied)
        report_id, digest = _identity("FRP", self.KIND, self._body())
        object.__setattr__(self, "finding_report_id", report_id)
        object.__setattr__(self, "finding_report_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "affected_asset_id": self.affected_asset_id,
            "affected_operation_id": self.affected_operation_id,
            "confidence": self.confidence,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_ref": self.cwe_ref,
            "evidence_digests": list(self.evidence_digests),
            "finding_id": self.finding_id,
            "impact_description": self.impact_description,
            "lifecycle_snapshot_sha256": self.lifecycle_snapshot_sha256,
            "remediation_guidance": self.remediation_guidance,
            "reproduction_summary": list(self.reproduction_summary),
            "retest_status": self.retest_status,
            "severity": self.severity,
            "status": self.status,
            "title": self.title,
            "validation_result_sha256": self.validation_result_sha256,
            "validation_status": self.validation_status,
            "vulnerability_class": self.vulnerability_class,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "effects": dict(NO_EFFECTS),
            "finding_report_id": self.finding_report_id,
            "finding_report_sha256": self.finding_report_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> FindingReport:
        fields = {
            "affected_asset_id",
            "affected_operation_id",
            "confidence",
            "cvss_score",
            "cvss_vector",
            "cwe_ref",
            "effects",
            "evidence_digests",
            "finding_id",
            "finding_report_id",
            "finding_report_sha256",
            "impact_description",
            "kind",
            "lifecycle_snapshot_sha256",
            "remediation_guidance",
            "reproduction_summary",
            "retest_status",
            "schema_version",
            "severity",
            "status",
            "title",
            "validation_result_sha256",
            "validation_status",
            "vulnerability_class",
        }
        _exact_fields(raw, fields, "finding report")
        _no_effects(raw["effects"], "finding report")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise AssessmentReportingError("finding report kind or schema_version is invalid")
        candidate = cls(
            finding_id=raw["finding_id"],
            lifecycle_snapshot_sha256=raw["lifecycle_snapshot_sha256"],
            title=raw["title"],
            affected_asset_id=raw["affected_asset_id"],
            affected_operation_id=raw["affected_operation_id"],
            vulnerability_class=raw["vulnerability_class"],
            cwe_ref=raw["cwe_ref"],
            severity=raw["severity"],
            confidence=raw["confidence"],
            status=raw["status"],
            evidence_digests=tuple(_list(raw["evidence_digests"], "finding evidence_digests")),
            impact_description=raw["impact_description"],
            reproduction_summary=tuple(_list(raw["reproduction_summary"], "reproduction_summary")),
            remediation_guidance=raw["remediation_guidance"],
            validation_status=raw["validation_status"],
            validation_result_sha256=raw["validation_result_sha256"],
            retest_status=raw["retest_status"],
            cvss_vector=raw["cvss_vector"],
            cvss_score=raw["cvss_score"],
        )
        return _verify_raw(raw, candidate, "finding report")


@dataclass(frozen=True)
class ReviewerRole:
    reviewer_id: str
    role: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "reviewer_id", _identifier(self.reviewer_id, "reviewer_id"))
        object.__setattr__(
            self,
            "role",
            _token(self.role, "reviewer role", tuple(REPORT_ROLES | ATTESTATION_ROLES)),
        )

    def to_dict(self) -> dict[str, str]:
        return {"reviewer_id": self.reviewer_id, "role": self.role}

    @classmethod
    def from_dict(cls, raw: Any) -> ReviewerRole:
        _exact_fields(raw, {"reviewer_id", "role"}, "reviewer role")
        return cls(**raw)


def _reviewers(
    values: Sequence[ReviewerRole], expected_roles: frozenset[str], label: str
) -> tuple[ReviewerRole, ...]:
    result = tuple(values)
    if not all(isinstance(item, ReviewerRole) for item in result):
        raise AssessmentReportingError(f"{label} contains an invalid reviewer")
    if {item.role for item in result} != expected_roles or len(result) != len(expected_roles):
        raise AssessmentReportingError(f"{label} must assign every required role exactly once")
    if len({item.reviewer_id for item in result}) != len(result):
        raise AssessmentReportingError(f"{label} violates separation of duty")
    return tuple(sorted(result, key=lambda item: item.role))


def _count_pairs(
    findings: Sequence[FindingReport], attribute: str, values: Sequence[str]
) -> tuple[tuple[str, int], ...]:
    return tuple(
        (value, sum(getattr(item, attribute) == value for item in findings)) for value in values
    )


@dataclass(frozen=True)
class ExecutiveSummary:
    assessment_id: str
    assessment_sha256: str
    completeness: str
    coverage_metrics: CoverageMetrics
    severity_counts: tuple[tuple[str, int], ...]
    status_counts: tuple[tuple[str, int], ...]
    negative_result_task_ids: tuple[str, ...]
    abstained_task_ids: tuple[str, ...]
    blocked_areas: tuple[str, ...]
    untested_areas: tuple[str, ...]
    blind_spots: tuple[str, ...]
    scope_limits: tuple[str, ...]
    residual_risk: str
    residual_risk_rating: str
    restoration_status: str
    incomplete_restoration_task_ids: tuple[str, ...]
    executive_summary_id: str = field(init=False)
    executive_summary_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.executive-summary.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "assessment_id", _identifier(self.assessment_id, "assessment_id"))
        object.__setattr__(
            self, "assessment_sha256", _digest(self.assessment_sha256, "assessment_sha256")
        )
        object.__setattr__(
            self, "completeness", _token(self.completeness, "completeness", ("complete", "partial"))
        )
        if not isinstance(self.coverage_metrics, CoverageMetrics):
            raise AssessmentReportingError("coverage_metrics is invalid")
        for name, pairs, expected in (
            ("severity_counts", self.severity_counts, SEVERITIES),
            ("status_counts", self.status_counts, FINDING_STATUSES),
        ):
            normalized = tuple(pairs)
            if tuple(key for key, _ in normalized) != tuple(expected) or any(
                not isinstance(count, int) or isinstance(count, bool) or count < 0
                for _, count in normalized
            ):
                raise AssessmentReportingError(f"{name} is incomplete or invalid")
            object.__setattr__(self, name, normalized)
        for name in (
            "negative_result_task_ids",
            "abstained_task_ids",
            "blocked_areas",
            "untested_areas",
            "blind_spots",
            "incomplete_restoration_task_ids",
        ):
            object.__setattr__(self, name, _identifiers(getattr(self, name), name))
        limits = tuple(_narrative(item, "scope limit", maximum=500) for item in self.scope_limits)
        if not limits or len(limits) != len(set(limits)):
            raise AssessmentReportingError("scope limits cannot be omitted")
        object.__setattr__(self, "scope_limits", tuple(sorted(limits)))
        object.__setattr__(
            self, "residual_risk", _narrative(self.residual_risk, "residual_risk", maximum=2000)
        )
        object.__setattr__(
            self,
            "residual_risk_rating",
            _token(self.residual_risk_rating, "residual_risk_rating", RISK_RATINGS),
        )
        object.__setattr__(
            self,
            "restoration_status",
            _token(self.restoration_status, "restoration_status", RESTORATION_STATUSES),
        )
        summary_id, digest = _identity("EXS", self.KIND, self._body())
        object.__setattr__(self, "executive_summary_id", summary_id)
        object.__setattr__(self, "executive_summary_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "abstained_task_ids": list(self.abstained_task_ids),
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            "blind_spots": list(self.blind_spots),
            "blocked_areas": list(self.blocked_areas),
            "completeness": self.completeness,
            "coverage_metrics": self.coverage_metrics.to_dict(),
            "incomplete_restoration_task_ids": list(self.incomplete_restoration_task_ids),
            "negative_result_task_ids": list(self.negative_result_task_ids),
            "residual_risk": self.residual_risk,
            "residual_risk_rating": self.residual_risk_rating,
            "restoration_status": self.restoration_status,
            "scope_limits": list(self.scope_limits),
            "severity_counts": [
                {"count": count, "severity": key} for key, count in self.severity_counts
            ],
            "status_counts": [{"count": count, "status": key} for key, count in self.status_counts],
            "untested_areas": list(self.untested_areas),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "effects": dict(NO_EFFECTS),
            "executive_summary_id": self.executive_summary_id,
            "executive_summary_sha256": self.executive_summary_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ExecutiveSummary:
        expected = {
            "abstained_task_ids",
            "assessment_id",
            "assessment_sha256",
            "blind_spots",
            "blocked_areas",
            "completeness",
            "coverage_metrics",
            "effects",
            "executive_summary_id",
            "executive_summary_sha256",
            "incomplete_restoration_task_ids",
            "kind",
            "negative_result_task_ids",
            "residual_risk",
            "residual_risk_rating",
            "restoration_status",
            "schema_version",
            "scope_limits",
            "severity_counts",
            "status_counts",
            "untested_areas",
        }
        _exact_fields(raw, expected, "executive summary")
        _no_effects(raw["effects"], "executive summary")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise AssessmentReportingError("executive summary kind or schema_version is invalid")
        severity_pairs = tuple(
            (item["severity"], item["count"])
            for item in _list(raw["severity_counts"], "severity_counts")
            if isinstance(item, Mapping) and set(item) == {"severity", "count"}
        )
        status_pairs = tuple(
            (item["status"], item["count"])
            for item in _list(raw["status_counts"], "status_counts")
            if isinstance(item, Mapping) and set(item) == {"status", "count"}
        )
        candidate = cls(
            assessment_id=raw["assessment_id"],
            assessment_sha256=raw["assessment_sha256"],
            completeness=raw["completeness"],
            coverage_metrics=CoverageMetrics.from_dict(raw["coverage_metrics"]),
            severity_counts=severity_pairs,
            status_counts=status_pairs,
            negative_result_task_ids=tuple(
                _list(raw["negative_result_task_ids"], "negative_result_task_ids")
            ),
            abstained_task_ids=tuple(_list(raw["abstained_task_ids"], "abstained_task_ids")),
            blocked_areas=tuple(_list(raw["blocked_areas"], "blocked_areas")),
            untested_areas=tuple(_list(raw["untested_areas"], "untested_areas")),
            blind_spots=tuple(_list(raw["blind_spots"], "blind_spots")),
            scope_limits=tuple(_list(raw["scope_limits"], "scope_limits")),
            residual_risk=raw["residual_risk"],
            residual_risk_rating=raw["residual_risk_rating"],
            restoration_status=raw["restoration_status"],
            incomplete_restoration_task_ids=tuple(
                _list(raw["incomplete_restoration_task_ids"], "incomplete_restoration_task_ids")
            ),
        )
        return _verify_raw(raw, candidate, "executive summary")


@dataclass(frozen=True)
class PentestReport:
    assessment: AssessmentRecord
    executive_summary: ExecutiveSummary
    findings: tuple[FindingReport, ...]
    reviewer_roles: tuple[ReviewerRole, ...]
    report_id: str = field(init=False)
    report_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.pentest-report.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.assessment, AssessmentRecord) or not isinstance(
            self.executive_summary, ExecutiveSummary
        ):
            raise AssessmentReportingError("report assessment or executive summary is invalid")
        findings = tuple(sorted(self.findings, key=lambda item: item.finding_id))
        if not all(isinstance(item, FindingReport) for item in findings) or len(
            {item.finding_id for item in findings}
        ) != len(findings):
            raise AssessmentReportingError("findings are invalid or duplicated")
        lifecycle = {item.finding_id: item for item in self.assessment.finding_lifecycle}
        validators = {item.result_sha256: item for item in self.assessment.validator_results}
        task_by_id = {item.task_id: item for item in self.assessment.task_transcripts}
        assets = {item.asset_id: set(item.operation_ids) for item in self.assessment.assets}
        if {item.finding_id for item in findings} != set(lifecycle):
            raise AssessmentReportingError(
                "report findings must exactly match finding lifecycle inputs"
            )
        bound_evidence = {
            digest for task in self.assessment.task_transcripts for digest in task.evidence_digests
        }
        bound_evidence.update(
            digest for asset in self.assessment.assets for digest in asset.evidence_digests
        )
        for finding in findings:
            if (
                finding.finding_id not in lifecycle
                or lifecycle[finding.finding_id].snapshot_sha256
                != finding.lifecycle_snapshot_sha256
                or lifecycle[finding.finding_id].state != finding.status
            ):
                raise AssessmentReportingError(
                    "finding lifecycle binding does not match assessment"
                )
            if finding.validation_result_sha256 not in validators:
                raise AssessmentReportingError(
                    "finding validator result is not bound by assessment"
                )
            validator = validators[finding.validation_result_sha256]
            task = task_by_id[validator.task_id]
            if (
                task.coverage_area_id
                != f"{finding.affected_asset_id}::{finding.affected_operation_id}"
            ):
                raise AssessmentReportingError(
                    "finding validator task does not match affected asset operation"
                )
            if finding.validation_status != validator.outcome:
                raise AssessmentReportingError(
                    "finding validation status does not match validator result"
                )
            if not set(finding.evidence_digests) <= bound_evidence:
                raise AssessmentReportingError("finding evidence is not bound by assessment")
            if (
                finding.affected_asset_id not in assets
                or finding.affected_operation_id not in assets[finding.affected_asset_id]
            ):
                raise AssessmentReportingError(
                    "finding asset or operation is outside assessment coverage"
                )
        object.__setattr__(self, "findings", findings)
        object.__setattr__(
            self,
            "reviewer_roles",
            _reviewers(self.reviewer_roles, REPORT_ROLES, "report reviewer_roles"),
        )
        expected = _executive_summary(self.assessment, findings)
        if self.executive_summary != expected:
            raise AssessmentReportingError("executive summary omits or inflates report facts")
        report_id, digest = _identity("PTR", self.KIND, self._body())
        object.__setattr__(self, "report_id", report_id)
        object.__setattr__(self, "report_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "assessment": self.assessment.to_dict(),
            "executive_summary": self.executive_summary.to_dict(),
            "findings": [item.to_dict() for item in self.findings],
            "reviewer_roles": [item.to_dict() for item in self.reviewer_roles],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> PentestReport:
        expected = {
            "assessment",
            "effects",
            "executive_summary",
            "findings",
            "kind",
            "report_id",
            "report_sha256",
            "reviewer_roles",
            "schema_version",
        }
        _exact_fields(raw, expected, "pentest report")
        _no_effects(raw["effects"], "pentest report")
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise AssessmentReportingError("pentest report kind or schema_version is invalid")
        candidate = cls(
            assessment=AssessmentRecord.from_dict(raw["assessment"]),
            executive_summary=ExecutiveSummary.from_dict(raw["executive_summary"]),
            findings=tuple(
                FindingReport.from_dict(item) for item in _list(raw["findings"], "findings")
            ),
            reviewer_roles=tuple(
                ReviewerRole.from_dict(item)
                for item in _list(raw["reviewer_roles"], "reviewer_roles")
            ),
        )
        return _verify_raw(raw, candidate, "pentest report")


@dataclass(frozen=True)
class AssessmentAttestation:
    report_id: str
    report_sha256: str
    assessment_id: str
    assessment_sha256: str
    tested_areas: tuple[str, ...]
    not_tested_areas: tuple[str, ...]
    not_determined_areas: tuple[str, ...]
    negative_result_task_ids: tuple[str, ...]
    abstained_task_ids: tuple[str, ...]
    scope_limits: tuple[str, ...]
    restoration_status: str
    reviewer_roles: tuple[ReviewerRole, ...]
    attested_at: str
    attestation_id: str = field(init=False)
    attestation_sha256: str = field(init=False)
    compliance_claim: str = field(init=False, default="not_assessed")
    conclusion: str = field(init=False, default="evidence_only_no_compliance_determination")

    KIND: ClassVar[str] = "sunderkey.assessment-attestation.v1"

    def __post_init__(self) -> None:
        for name in ("report_id", "assessment_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        for name in ("report_sha256", "assessment_sha256"):
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        tested = _identifiers(self.tested_areas, "tested_areas")
        not_tested = _identifiers(self.not_tested_areas, "not_tested_areas")
        not_determined = _identifiers(self.not_determined_areas, "not_determined_areas")
        if (
            set(tested) & set(not_tested)
            or set(tested) & set(not_determined)
            or set(not_tested) & set(not_determined)
        ):
            raise AssessmentReportingError("attestation coverage categories overlap")
        object.__setattr__(self, "tested_areas", tested)
        object.__setattr__(self, "not_tested_areas", not_tested)
        object.__setattr__(self, "not_determined_areas", not_determined)
        object.__setattr__(
            self,
            "negative_result_task_ids",
            _identifiers(self.negative_result_task_ids, "negative_result_task_ids"),
        )
        object.__setattr__(
            self, "abstained_task_ids", _identifiers(self.abstained_task_ids, "abstained_task_ids")
        )
        limits = tuple(_narrative(item, "scope limit", maximum=500) for item in self.scope_limits)
        if not limits or len(limits) != len(set(limits)):
            raise AssessmentReportingError("attestation scope limits cannot be omitted")
        object.__setattr__(self, "scope_limits", tuple(sorted(limits)))
        object.__setattr__(
            self,
            "restoration_status",
            _token(self.restoration_status, "restoration_status", RESTORATION_STATUSES),
        )
        object.__setattr__(
            self,
            "reviewer_roles",
            _reviewers(self.reviewer_roles, ATTESTATION_ROLES, "attestation reviewer_roles"),
        )
        object.__setattr__(self, "attested_at", _timestamp(self.attested_at, "attested_at"))
        attestation_id, digest = _identity("ATT", self.KIND, self._body())
        object.__setattr__(self, "attestation_id", attestation_id)
        object.__setattr__(self, "attestation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "abstained_task_ids": list(self.abstained_task_ids),
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
            "attested_at": self.attested_at,
            "compliance_claim": self.compliance_claim,
            "conclusion": self.conclusion,
            "negative_result_task_ids": list(self.negative_result_task_ids),
            "not_determined_areas": list(self.not_determined_areas),
            "not_tested_areas": list(self.not_tested_areas),
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
            "restoration_status": self.restoration_status,
            "reviewer_roles": [item.to_dict() for item in self.reviewer_roles],
            "scope_limits": list(self.scope_limits),
            "tested_areas": list(self.tested_areas),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "attestation_id": self.attestation_id,
            "attestation_sha256": self.attestation_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentAttestation:
        expected = {
            "abstained_task_ids",
            "assessment_id",
            "assessment_sha256",
            "attestation_id",
            "attestation_sha256",
            "attested_at",
            "compliance_claim",
            "conclusion",
            "effects",
            "kind",
            "negative_result_task_ids",
            "not_determined_areas",
            "not_tested_areas",
            "report_id",
            "report_sha256",
            "restoration_status",
            "reviewer_roles",
            "schema_version",
            "scope_limits",
            "tested_areas",
        }
        _exact_fields(raw, expected, "assessment attestation")
        _no_effects(raw["effects"], "assessment attestation")
        if (
            raw["kind"] != cls.KIND
            or raw["schema_version"] != SCHEMA_VERSION
            or raw["compliance_claim"] != "not_assessed"
            or raw["conclusion"] != "evidence_only_no_compliance_determination"
        ):
            raise AssessmentReportingError("attestation overclaims or has an invalid kind")
        candidate = cls(
            report_id=raw["report_id"],
            report_sha256=raw["report_sha256"],
            assessment_id=raw["assessment_id"],
            assessment_sha256=raw["assessment_sha256"],
            tested_areas=tuple(_list(raw["tested_areas"], "tested_areas")),
            not_tested_areas=tuple(_list(raw["not_tested_areas"], "not_tested_areas")),
            not_determined_areas=tuple(_list(raw["not_determined_areas"], "not_determined_areas")),
            negative_result_task_ids=tuple(
                _list(raw["negative_result_task_ids"], "negative_result_task_ids")
            ),
            abstained_task_ids=tuple(_list(raw["abstained_task_ids"], "abstained_task_ids")),
            scope_limits=tuple(_list(raw["scope_limits"], "scope_limits")),
            restoration_status=raw["restoration_status"],
            reviewer_roles=tuple(
                ReviewerRole.from_dict(item)
                for item in _list(raw["reviewer_roles"], "reviewer_roles")
            ),
            attested_at=raw["attested_at"],
        )
        return _verify_raw(raw, candidate, "assessment attestation")


@dataclass(frozen=True)
class AssessmentReportBundle:
    report: PentestReport
    attestation: AssessmentAttestation
    bundle_id: str = field(init=False)
    bundle_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.report, PentestReport) or not isinstance(
            self.attestation, AssessmentAttestation
        ):
            raise AssessmentReportingError("bundle members are invalid")
        if (
            self.attestation.report_id != self.report.report_id
            or self.attestation.report_sha256 != self.report.report_sha256
            or self.attestation.assessment_id != self.report.assessment.assessment_id
            or self.attestation.assessment_sha256 != self.report.assessment.assessment_sha256
        ):
            raise AssessmentReportingError(
                "attestation does not bind the exact report and assessment"
            )
        if _instant(self.attestation.attested_at) < _instant(self.report.assessment.generated_at):
            raise AssessmentReportingError("attestation predates report generation")
        expected_attestation = _attestation(
            self.report, self.attestation.reviewer_roles, self.attestation.attested_at
        )
        if self.attestation != expected_attestation:
            raise AssessmentReportingError(
                "attestation omits, changes, or overclaims assessment facts"
            )
        report_ids = {item.reviewer_id for item in self.report.reviewer_roles}
        attestation_ids = {item.reviewer_id for item in self.attestation.reviewer_roles}
        if report_ids & attestation_ids:
            raise AssessmentReportingError("report and attestation reviewers must be independent")
        participant_ids = {task.profile_id for task in self.report.assessment.task_transcripts}
        participant_ids.update(
            result.validator_id for result in self.report.assessment.validator_results
        )
        if (report_ids | attestation_ids) & participant_ids:
            raise AssessmentReportingError(
                "reviewers must be independent of task profiles and validators"
            )
        bundle_id, digest = _identity("ARB", BUNDLE_KIND, self._body())
        object.__setattr__(self, "bundle_id", bundle_id)
        object.__setattr__(self, "bundle_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {"attestation": self.attestation.to_dict(), "report": self.report.to_dict()}

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "bundle_id": self.bundle_id,
            "bundle_sha256": self.bundle_sha256,
            "effects": dict(NO_EFFECTS),
            "kind": BUNDLE_KIND,
            "schema_version": SCHEMA_VERSION,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    def to_sarif_dict(self) -> dict[str, Any]:
        findings = self.report.findings
        rules = [
            {
                "id": finding.cwe_ref,
                "name": finding.vulnerability_class,
                "shortDescription": {"text": finding.title},
                "properties": {"severity": finding.severity},
            }
            for finding in findings
        ]
        level = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "informational": "note",
            "unrated": "none",
        }
        results = [
            {
                "level": level[finding.severity],
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": (
                                    f"asset:{finding.affected_asset_id}/"
                                    f"{finding.affected_operation_id}"
                                )
                            }
                        }
                    }
                ],
                "message": {"text": finding.impact_description},
                "properties": {
                    "confidence": finding.confidence,
                    "evidenceDigests": list(finding.evidence_digests),
                    "findingId": finding.finding_id,
                    "findingReportSha256": finding.finding_report_sha256,
                    "lifecycleStatus": finding.status,
                    "retestStatus": finding.retest_status,
                    "validationStatus": finding.validation_status,
                },
                "ruleId": finding.cwe_ref,
            }
            for finding in findings
        ]
        summary = self.report.executive_summary
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "artifacts": [
                        {
                            "location": {"uri": f"asset:{asset.asset_id}"},
                            "properties": {"assetSha256": asset.asset_sha256},
                        }
                        for asset in self.report.assessment.assets
                    ],
                    "invocations": [
                        {
                            "endTimeUtc": self.report.assessment.ended_at,
                            "executionSuccessful": self.report.assessment.completeness
                            == "complete",
                            "properties": {
                                "abstainedTaskIds": list(summary.abstained_task_ids),
                                "assessmentSha256": self.report.assessment.assessment_sha256,
                                "blockedAreas": list(summary.blocked_areas),
                                "bundleSha256": self.bundle_sha256,
                                "completeness": summary.completeness,
                                "negativeResultTaskIds": list(summary.negative_result_task_ids),
                                "notDeterminedAreas": list(self.attestation.not_determined_areas),
                                "notTestedAreas": list(self.attestation.not_tested_areas),
                                "restorationStatus": summary.restoration_status,
                                "scopeLimits": list(summary.scope_limits),
                            },
                            "startTimeUtc": self.report.assessment.started_at,
                        }
                    ],
                    "results": results,
                    "tool": {
                        "driver": {
                            "name": "SUNDERKEY",
                            "rules": rules,
                            "semanticVersion": "1.0.0",
                        }
                    },
                }
            ],
            "version": "2.1.0",
        }

    def to_sarif_json(self) -> str:
        return canonical_json(self.to_sarif_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentReportBundle:
        expected = {
            "attestation",
            "bundle_id",
            "bundle_sha256",
            "effects",
            "kind",
            "report",
            "schema_version",
        }
        _exact_fields(raw, expected, "assessment report bundle")
        _no_effects(raw["effects"], "assessment report bundle")
        if raw["kind"] != BUNDLE_KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise AssessmentReportingError("bundle kind or schema_version is invalid")
        candidate = cls(
            PentestReport.from_dict(raw["report"]),
            AssessmentAttestation.from_dict(raw["attestation"]),
        )
        return _verify_raw(raw, candidate, "assessment report bundle")

    @classmethod
    def from_json(cls, document: str) -> AssessmentReportBundle:
        if not isinstance(document, str):
            raise AssessmentReportingError("bundle JSON must be text")
        try:
            raw = json.loads(document)
        except json.JSONDecodeError as exc:
            raise AssessmentReportingError("bundle JSON is invalid") from exc
        candidate = cls.from_dict(raw)
        if document != candidate.to_json():
            raise AssessmentReportingError("bundle JSON is not canonical")
        return candidate


def _executive_summary(
    assessment: AssessmentRecord, findings: Sequence[FindingReport]
) -> ExecutiveSummary:
    tasks = assessment.task_transcripts
    return ExecutiveSummary(
        assessment_id=assessment.assessment_id,
        assessment_sha256=assessment.assessment_sha256,
        completeness=assessment.completeness,
        coverage_metrics=assessment.coverage_metrics,
        severity_counts=_count_pairs(findings, "severity", SEVERITIES),
        status_counts=_count_pairs(findings, "status", FINDING_STATUSES),
        negative_result_task_ids=tuple(
            task.task_id for task in tasks if task.status is CoverageStatus.NEGATIVE
        ),
        abstained_task_ids=tuple(
            task.task_id for task in tasks if task.status is CoverageStatus.ABSTAINED
        ),
        blocked_areas=assessment.blocked_areas,
        untested_areas=assessment.untested_areas,
        blind_spots=tuple(sorted((*assessment.untested_areas, *assessment.not_determined_areas))),
        scope_limits=assessment.scope_limits,
        residual_risk=assessment.residual_risk,
        residual_risk_rating=assessment.residual_risk_rating,
        restoration_status=assessment.restoration_status,
        incomplete_restoration_task_ids=tuple(
            task.task_id
            for task in tasks
            if task.restoration_required and task.restoration_status != "verified"
        ),
    )


def _attestation(
    report: PentestReport, reviewers: Sequence[ReviewerRole], attested_at: str
) -> AssessmentAttestation:
    assessment = report.assessment
    tasks = assessment.task_transcripts
    return AssessmentAttestation(
        report_id=report.report_id,
        report_sha256=report.report_sha256,
        assessment_id=assessment.assessment_id,
        assessment_sha256=assessment.assessment_sha256,
        tested_areas=assessment.tested_areas,
        not_tested_areas=tuple(sorted((*assessment.blocked_areas, *assessment.untested_areas))),
        not_determined_areas=assessment.not_determined_areas,
        negative_result_task_ids=tuple(
            task.task_id for task in tasks if task.status is CoverageStatus.NEGATIVE
        ),
        abstained_task_ids=tuple(
            task.task_id for task in tasks if task.status is CoverageStatus.ABSTAINED
        ),
        scope_limits=assessment.scope_limits,
        restoration_status=assessment.restoration_status,
        reviewer_roles=tuple(reviewers),
        attested_at=attested_at,
    )


def build_assessment_report_bundle(
    assessment: AssessmentRecord,
    findings: Sequence[FindingReport],
    *,
    report_reviewers: Sequence[ReviewerRole],
    attestation_reviewers: Sequence[ReviewerRole],
    attested_at: str,
) -> AssessmentReportBundle:
    """Assemble and cross-check one immutable report and attestation bundle."""

    if not isinstance(assessment, AssessmentRecord):
        raise AssessmentReportingError("assessment must be an AssessmentRecord")
    finding_values = tuple(findings)
    summary = _executive_summary(assessment, finding_values)
    report = PentestReport(assessment, summary, finding_values, tuple(report_reviewers))
    if _instant(_timestamp(attested_at, "attested_at")) < _instant(assessment.generated_at):
        raise AssessmentReportingError("attestation predates report generation")
    attestation = _attestation(report, tuple(attestation_reviewers), attested_at)
    return AssessmentReportBundle(report, attestation)


def export_report_bundle_json(bundle: AssessmentReportBundle) -> str:
    """Return the canonical lossless JSON view of a verified bundle."""

    if not isinstance(bundle, AssessmentReportBundle):
        raise AssessmentReportingError("bundle must be an AssessmentReportBundle")
    AssessmentReportBundle.from_dict(bundle.to_dict())
    return bundle.to_json()


def export_report_bundle_sarif(bundle: AssessmentReportBundle) -> str:
    """Return the deterministic redacted SARIF-like view of a verified bundle."""

    if not isinstance(bundle, AssessmentReportBundle):
        raise AssessmentReportingError("bundle must be an AssessmentReportBundle")
    AssessmentReportBundle.from_dict(bundle.to_dict())
    return bundle.to_sarif_json()


ReportBundle = AssessmentReportBundle


__all__ = [
    "NO_EFFECTS",
    "AssessmentAttestation",
    "AssessmentRecord",
    "AssessmentReportBundle",
    "AssessmentReportingError",
    "AssetRecord",
    "CoverageMetrics",
    "CoverageStatus",
    "ExecutiveSummary",
    "FindingLifecycleReference",
    "FindingReport",
    "PentestReport",
    "ReportBundle",
    "ReviewerRole",
    "TaskTranscript",
    "ValidatorResultReference",
    "build_assessment_report_bundle",
    "canonical_json",
    "canonical_sha256",
    "export_report_bundle_json",
    "export_report_bundle_sarif",
]
