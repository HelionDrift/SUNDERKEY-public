"""Deterministic attack-surface drift and revalidation planning contracts.

This module consumes already admitted observations. It performs no discovery,
network access, scheduling, notification, execution, or authority operation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

SCHEMA_VERSION = 1
SNAPSHOT_DOMAIN = "sunderkey.surface-drift-snapshot.v1"
ASSESSMENT_DOMAIN = "sunderkey.surface-drift-assessment.v1"
PLAN_DOMAIN = "sunderkey.surface-drift-plan.v1"

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
SNAPSHOT_ID_RE = re.compile(r"SDS-[0-9A-F]{32}\Z")
ASSESSMENT_ID_RE = re.compile(r"SDA-[0-9A-F]{32}\Z")
TRIGGER_ID_RE = re.compile(r"SDT-[0-9A-F]{32}\Z")
PLAN_ID_RE = re.compile(r"SDP-[0-9A-F]{32}\Z")
RECORD_ID_RE = re.compile(r"SDR-[0-9A-F]{32}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

NO_EFFECTS = {
    "authority": "none",
    "cloud": "none",
    "discovery": "none",
    "dns": "none",
    "execution": "none",
    "network": "none",
    "notification": "none",
    "scheduler": "none",
}

HARD_LIMITS = {
    "max_changes": 4096,
    "max_observations": 16384,
    "max_plan_records": 8192,
    "max_triggers": 4096,
}


class SurfaceDriftError(ValueError):
    """Raised when a surface drift contract fails closed."""


class SurfaceKind(StrEnum):
    """Supported admitted attack-surface observation kinds."""

    ASSET = "asset"
    ENDPOINT = "endpoint"
    SCHEMA = "schema"
    IDENTITY = "identity"
    TRUST_EDGE = "trust_edge"
    CONTROL = "control"
    DEPLOYMENT = "deployment"


class ObservationState(StrEnum):
    """Evidence meaning retained on each observation."""

    VERIFIED = "verified"
    NEGATIVE = "negative"
    HYPOTHESIS = "hypothesis"
    ABSTAINED = "abstained"


class ChangeKind(StrEnum):
    """Deterministic drift classifications."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class ChangeCertainty(StrEnum):
    """Certainty carried into a drift record."""

    VERIFIED = "verified"
    NEGATIVE = "negative"
    HYPOTHESIS = "hypothesis"
    ABSTAINED = "abstained"
    UNCERTAIN_ABSENCE = "uncertain_absence"
    STALE_PROVENANCE = "stale_provenance"


class PlanAction(StrEnum):
    """Effect-free follow-up plan record types."""

    NOTIFICATION = "notification"
    RESCAN = "rescan"


class PlanDisposition(StrEnum):
    """Disposition assigned without performing an effect."""

    PLANNED = "planned"
    BLOCKED = "blocked"
    DEDUPLICATED = "deduplicated"
    COOLDOWN_SUPPRESSED = "cooldown_suppressed"


@dataclass(frozen=True)
class DriftLimits:
    """Resource ceilings for snapshots, diffs, triggers, and plans."""

    max_observations: int = 4096
    max_changes: int = 1024
    max_triggers: int = 1024
    max_plan_records: int = 2048

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SurfaceDriftError(f"{name} must be a positive integer")
            if value > HARD_LIMITS[name]:
                raise SurfaceDriftError(f"{name} exceeds its hard safety limit")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_changes": self.max_changes,
            "max_observations": self.max_observations,
            "max_plan_records": self.max_plan_records,
            "max_triggers": self.max_triggers,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DriftLimits:
        _exact_fields(raw, set(HARD_LIMITS), "drift limits")
        return cls(**raw)


@dataclass(frozen=True)
class SurfaceObservation:
    """One admitted observation with provenance, scope, and routing bindings."""

    surface_id: str
    surface_kind: SurfaceKind | str
    content_sha256: str
    provenance_sha256: str
    observed_at: str
    freshness_expires_at: str
    observation_state: ObservationState | str
    scope_binding_sha256: str
    technique_ids: tuple[str, ...]
    profile_ids: tuple[str, ...]
    commander_ids: tuple[str, ...]
    risk_score: int

    def __post_init__(self) -> None:
        _identifier(self.surface_id, "surface_id")
        try:
            kind = SurfaceKind(self.surface_kind)
        except (TypeError, ValueError) as exc:
            raise SurfaceDriftError("surface_kind is invalid") from exc
        object.__setattr__(self, "surface_kind", kind)
        _sha256(self.content_sha256, "content_sha256")
        _sha256(self.provenance_sha256, "provenance_sha256")
        _sha256(self.scope_binding_sha256, "scope_binding_sha256")
        observed = _utc(self.observed_at, "observed_at")
        expires = _utc(self.freshness_expires_at, "freshness_expires_at")
        if expires <= observed:
            raise SurfaceDriftError("freshness_expires_at must follow observed_at")
        try:
            state = ObservationState(self.observation_state)
        except (TypeError, ValueError) as exc:
            raise SurfaceDriftError("observation_state is invalid") from exc
        object.__setattr__(self, "observation_state", state)
        object.__setattr__(self, "technique_ids", _refs(self.technique_ids, "technique_ids"))
        object.__setattr__(self, "profile_ids", _refs(self.profile_ids, "profile_ids"))
        object.__setattr__(self, "commander_ids", _refs(self.commander_ids, "commander_ids"))
        if not self.technique_ids or not self.profile_ids or not self.commander_ids:
            raise SurfaceDriftError(
                "observations require technique, profile, and commander bindings"
            )
        if (
            isinstance(self.risk_score, bool)
            or not isinstance(self.risk_score, int)
            or not 0 <= self.risk_score <= 100
        ):
            raise SurfaceDriftError("risk_score must be an integer from 0 through 100")

    def is_stale(self, as_of: str) -> bool:
        return _utc(self.freshness_expires_at, "freshness_expires_at") <= _utc(as_of, "as_of")

    def to_dict(self) -> dict[str, Any]:
        return {
            "commander_ids": list(self.commander_ids),
            "content_sha256": self.content_sha256,
            "freshness_expires_at": self.freshness_expires_at,
            "observation_state": self.observation_state.value,
            "observed_at": self.observed_at,
            "profile_ids": list(self.profile_ids),
            "provenance_sha256": self.provenance_sha256,
            "risk_score": self.risk_score,
            "scope_binding_sha256": self.scope_binding_sha256,
            "surface_id": self.surface_id,
            "surface_kind": self.surface_kind.value,
            "technique_ids": list(self.technique_ids),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SurfaceObservation:
        _exact_fields(
            raw,
            {
                "commander_ids",
                "content_sha256",
                "freshness_expires_at",
                "observation_state",
                "observed_at",
                "profile_ids",
                "provenance_sha256",
                "risk_score",
                "scope_binding_sha256",
                "surface_id",
                "surface_kind",
                "technique_ids",
            },
            "surface observation",
        )
        return cls(
            surface_id=raw["surface_id"],
            surface_kind=raw["surface_kind"],
            content_sha256=raw["content_sha256"],
            provenance_sha256=raw["provenance_sha256"],
            observed_at=raw["observed_at"],
            freshness_expires_at=raw["freshness_expires_at"],
            observation_state=raw["observation_state"],
            scope_binding_sha256=raw["scope_binding_sha256"],
            technique_ids=tuple(raw["technique_ids"]),
            profile_ids=tuple(raw["profile_ids"]),
            commander_ids=tuple(raw["commander_ids"]),
            risk_score=raw["risk_score"],
        )


@dataclass(frozen=True)
class SurfaceSnapshot:
    """Immutable content-addressed observation snapshot."""

    schema_version: int
    snapshot_id: str
    snapshot_sha256: str
    sequence: int
    captured_at: str
    scope_binding_sha256: str
    parent_snapshot_sha256: str | None
    observations: tuple[SurfaceObservation, ...]
    protected_endpoint_ids: tuple[str, ...]
    excluded_surface_ids: tuple[str, ...]
    limits: DriftLimits
    no_effects: Mapping[str, str]

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SurfaceDriftError("snapshot schema_version is unsupported")
        if not SNAPSHOT_ID_RE.fullmatch(self.snapshot_id):
            raise SurfaceDriftError("snapshot_id is invalid")
        _sha256(self.snapshot_sha256, "snapshot_sha256")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            raise SurfaceDriftError("sequence must be a nonnegative integer")
        _utc(self.captured_at, "captured_at")
        _sha256(self.scope_binding_sha256, "scope_binding_sha256")
        if self.sequence == 0:
            if self.parent_snapshot_sha256 is not None:
                raise SurfaceDriftError("root snapshot cannot have a parent")
        else:
            if self.parent_snapshot_sha256 is None:
                raise SurfaceDriftError("non-root snapshot requires a parent")
            _sha256(self.parent_snapshot_sha256, "parent_snapshot_sha256")
        if not isinstance(self.limits, DriftLimits):
            raise SurfaceDriftError("limits must be DriftLimits")
        observations = tuple(self.observations)
        if len(observations) > self.limits.max_observations:
            raise SurfaceDriftError("observation count exceeds max_observations")
        if any(not isinstance(item, SurfaceObservation) for item in observations):
            raise SurfaceDriftError("observations must contain SurfaceObservation values")
        ordered = tuple(sorted(observations, key=lambda item: item.surface_id))
        if observations != ordered:
            raise SurfaceDriftError("observations are not in canonical ordering")
        if len({item.surface_id for item in observations}) != len(observations):
            raise SurfaceDriftError("surface_id values must be unique")
        if any(item.scope_binding_sha256 != self.scope_binding_sha256 for item in observations):
            raise SurfaceDriftError("observation scope binding does not match snapshot")
        protected = _refs(self.protected_endpoint_ids, "protected_endpoint_ids")
        excluded = _refs(self.excluded_surface_ids, "excluded_surface_ids")
        object.__setattr__(self, "protected_endpoint_ids", protected)
        object.__setattr__(self, "excluded_surface_ids", excluded)
        kind_by_id = {item.surface_id: item.surface_kind for item in observations}
        for surface_id in protected:
            if surface_id in kind_by_id and kind_by_id[surface_id] is not SurfaceKind.ENDPOINT:
                raise SurfaceDriftError("protected surface entries must be endpoints")
        object.__setattr__(self, "no_effects", _no_effects(self.no_effects))
        expected_sha256 = _digest(SNAPSHOT_DOMAIN, self._identity_payload())
        expected_id = _derived_id("SDS", expected_sha256)
        if self.snapshot_sha256 != expected_sha256 or self.snapshot_id != expected_id:
            raise SurfaceDriftError("snapshot identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "excluded_surface_ids": list(self.excluded_surface_ids),
            "limits": self.limits.to_dict(),
            "no_effects": dict(self.no_effects),
            "observations": [item.to_dict() for item in self.observations],
            "parent_snapshot_sha256": self.parent_snapshot_sha256,
            "protected_endpoint_ids": list(self.protected_endpoint_ids),
            "schema_version": self.schema_version,
            "scope_binding_sha256": self.scope_binding_sha256,
            "sequence": self.sequence,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "snapshot_id": self.snapshot_id,
            "snapshot_sha256": self.snapshot_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SurfaceSnapshot:
        _exact_fields(
            raw,
            {
                "captured_at",
                "excluded_surface_ids",
                "limits",
                "no_effects",
                "observations",
                "parent_snapshot_sha256",
                "protected_endpoint_ids",
                "schema_version",
                "scope_binding_sha256",
                "sequence",
                "snapshot_id",
                "snapshot_sha256",
            },
            "surface snapshot",
        )
        result = cls(
            schema_version=raw["schema_version"],
            snapshot_id=raw["snapshot_id"],
            snapshot_sha256=raw["snapshot_sha256"],
            sequence=raw["sequence"],
            captured_at=raw["captured_at"],
            scope_binding_sha256=raw["scope_binding_sha256"],
            parent_snapshot_sha256=raw["parent_snapshot_sha256"],
            observations=tuple(SurfaceObservation.from_dict(item) for item in raw["observations"]),
            protected_endpoint_ids=tuple(raw["protected_endpoint_ids"]),
            excluded_surface_ids=tuple(raw["excluded_surface_ids"]),
            limits=DriftLimits.from_dict(raw["limits"]),
            no_effects=raw["no_effects"],
        )
        if result.to_dict() != dict(raw):
            raise SurfaceDriftError("surface snapshot document is not canonical")
        return result


@dataclass(frozen=True)
class SurfaceChange:
    """One added, removed, or materially changed surface item."""

    surface_id: str
    surface_kind: SurfaceKind | str
    change_kind: ChangeKind | str
    certainty: ChangeCertainty | str
    before: SurfaceObservation | None
    after: SurfaceObservation | None
    changed_fields: tuple[str, ...]
    protected: bool
    excluded: bool
    risk_score: int

    def __post_init__(self) -> None:
        _identifier(self.surface_id, "change surface_id")
        try:
            surface_kind = SurfaceKind(self.surface_kind)
            change_kind = ChangeKind(self.change_kind)
            certainty = ChangeCertainty(self.certainty)
        except (TypeError, ValueError) as exc:
            raise SurfaceDriftError("change enum value is invalid") from exc
        object.__setattr__(self, "surface_kind", surface_kind)
        object.__setattr__(self, "change_kind", change_kind)
        object.__setattr__(self, "certainty", certainty)
        if self.before is not None and not isinstance(self.before, SurfaceObservation):
            raise SurfaceDriftError("change before value is invalid")
        if self.after is not None and not isinstance(self.after, SurfaceObservation):
            raise SurfaceDriftError("change after value is invalid")
        if change_kind is ChangeKind.ADDED and (self.before is not None or self.after is None):
            raise SurfaceDriftError("added change requires only an after observation")
        if change_kind is ChangeKind.REMOVED and (self.before is None or self.after is not None):
            raise SurfaceDriftError("removed change requires only a before observation")
        if change_kind is ChangeKind.CHANGED and (self.before is None or self.after is None):
            raise SurfaceDriftError("changed change requires before and after observations")
        for item in (self.before, self.after):
            if item is not None and (
                item.surface_id != self.surface_id or item.surface_kind != surface_kind
            ):
                raise SurfaceDriftError("change observations do not match the surface identity")
        fields = _refs(
            self.changed_fields, "changed_fields", allow_empty=change_kind is not ChangeKind.CHANGED
        )
        object.__setattr__(self, "changed_fields", fields)
        if change_kind is ChangeKind.CHANGED and not fields:
            raise SurfaceDriftError("changed records require changed_fields")
        if not isinstance(self.protected, bool) or not isinstance(self.excluded, bool):
            raise SurfaceDriftError("protected and excluded must be booleans")
        if (
            isinstance(self.risk_score, bool)
            or not isinstance(self.risk_score, int)
            or not 0 <= self.risk_score <= 100
        ):
            raise SurfaceDriftError("change risk_score is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "after": None if self.after is None else self.after.to_dict(),
            "before": None if self.before is None else self.before.to_dict(),
            "certainty": self.certainty.value,
            "change_kind": self.change_kind.value,
            "changed_fields": list(self.changed_fields),
            "excluded": self.excluded,
            "protected": self.protected,
            "risk_score": self.risk_score,
            "surface_id": self.surface_id,
            "surface_kind": self.surface_kind.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SurfaceChange:
        _exact_fields(
            raw,
            {
                "after",
                "before",
                "certainty",
                "change_kind",
                "changed_fields",
                "excluded",
                "protected",
                "risk_score",
                "surface_id",
                "surface_kind",
            },
            "surface change",
        )
        return cls(
            surface_id=raw["surface_id"],
            surface_kind=raw["surface_kind"],
            change_kind=raw["change_kind"],
            certainty=raw["certainty"],
            before=None if raw["before"] is None else SurfaceObservation.from_dict(raw["before"]),
            after=None if raw["after"] is None else SurfaceObservation.from_dict(raw["after"]),
            changed_fields=tuple(raw["changed_fields"]),
            protected=raw["protected"],
            excluded=raw["excluded"],
            risk_score=raw["risk_score"],
        )


@dataclass(frozen=True)
class RevalidationTrigger:
    """Risk-weighted, identity-bound revalidation trigger."""

    trigger_id: str
    change_sha256: str
    surface_id: str
    change_kind: ChangeKind | str
    reason: str
    risk_score: int
    technique_ids: tuple[str, ...]
    profile_ids: tuple[str, ...]
    commander_ids: tuple[str, ...]
    notification_permitted: bool
    rescan_permitted: bool

    def __post_init__(self) -> None:
        if not TRIGGER_ID_RE.fullmatch(self.trigger_id):
            raise SurfaceDriftError("trigger_id is invalid")
        _sha256(self.change_sha256, "trigger change_sha256")
        _identifier(self.surface_id, "trigger surface_id")
        try:
            change_kind = ChangeKind(self.change_kind)
        except (TypeError, ValueError) as exc:
            raise SurfaceDriftError("trigger change_kind is invalid") from exc
        object.__setattr__(self, "change_kind", change_kind)
        _identifier(self.reason, "trigger reason")
        if (
            isinstance(self.risk_score, bool)
            or not isinstance(self.risk_score, int)
            or not 0 <= self.risk_score <= 100
        ):
            raise SurfaceDriftError("trigger risk_score is invalid")
        object.__setattr__(
            self, "technique_ids", _refs(self.technique_ids, "trigger technique_ids")
        )
        object.__setattr__(self, "profile_ids", _refs(self.profile_ids, "trigger profile_ids"))
        object.__setattr__(
            self, "commander_ids", _refs(self.commander_ids, "trigger commander_ids")
        )
        if not self.technique_ids or not self.profile_ids or not self.commander_ids:
            raise SurfaceDriftError("triggers require technique, profile, and commander bindings")
        if not isinstance(self.notification_permitted, bool) or not isinstance(
            self.rescan_permitted, bool
        ):
            raise SurfaceDriftError("trigger permission fields must be booleans")
        expected = _derived_id(
            "SDT", _digest("sunderkey.surface-drift-trigger.v1", self._identity_payload())
        )
        if self.trigger_id != expected:
            raise SurfaceDriftError("trigger identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "change_sha256": self.change_sha256,
            "change_kind": self.change_kind.value,
            "commander_ids": list(self.commander_ids),
            "notification_permitted": self.notification_permitted,
            "profile_ids": list(self.profile_ids),
            "reason": self.reason,
            "rescan_permitted": self.rescan_permitted,
            "risk_score": self.risk_score,
            "surface_id": self.surface_id,
            "technique_ids": list(self.technique_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._identity_payload(), "trigger_id": self.trigger_id}

    @classmethod
    def from_dict(cls, raw: Any) -> RevalidationTrigger:
        _exact_fields(
            raw,
            {
                "change_sha256",
                "change_kind",
                "commander_ids",
                "notification_permitted",
                "profile_ids",
                "reason",
                "rescan_permitted",
                "risk_score",
                "surface_id",
                "technique_ids",
                "trigger_id",
            },
            "revalidation trigger",
        )
        return cls(
            trigger_id=raw["trigger_id"],
            change_sha256=raw["change_sha256"],
            surface_id=raw["surface_id"],
            change_kind=raw["change_kind"],
            reason=raw["reason"],
            risk_score=raw["risk_score"],
            technique_ids=tuple(raw["technique_ids"]),
            profile_ids=tuple(raw["profile_ids"]),
            commander_ids=tuple(raw["commander_ids"]),
            notification_permitted=raw["notification_permitted"],
            rescan_permitted=raw["rescan_permitted"],
        )


@dataclass(frozen=True)
class DriftAssessment:
    """Content-addressed comparison of a baseline and direct descendant."""

    schema_version: int
    assessment_id: str
    assessment_sha256: str
    assessed_at: str
    scope_binding_sha256: str
    baseline: SurfaceSnapshot
    current: SurfaceSnapshot
    changes: tuple[SurfaceChange, ...]
    triggers: tuple[RevalidationTrigger, ...]
    no_effects: Mapping[str, str]

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SurfaceDriftError("assessment schema_version is unsupported")
        if not ASSESSMENT_ID_RE.fullmatch(self.assessment_id):
            raise SurfaceDriftError("assessment_id is invalid")
        _sha256(self.assessment_sha256, "assessment_sha256")
        _utc(self.assessed_at, "assessed_at")
        _sha256(self.scope_binding_sha256, "scope_binding_sha256")
        if not isinstance(self.baseline, SurfaceSnapshot) or not isinstance(
            self.current, SurfaceSnapshot
        ):
            raise SurfaceDriftError("assessment snapshots are invalid")
        _validate_lineage(self.baseline, self.current)
        if self.scope_binding_sha256 != self.baseline.scope_binding_sha256:
            raise SurfaceDriftError("assessment scope binding does not match snapshots")
        changes = tuple(self.changes)
        triggers = tuple(self.triggers)
        if changes != tuple(
            sorted(changes, key=lambda item: (item.surface_id, item.change_kind.value))
        ):
            raise SurfaceDriftError("changes are not in canonical ordering")
        if triggers != tuple(sorted(triggers, key=lambda item: item.trigger_id)):
            raise SurfaceDriftError("triggers are not in canonical ordering")
        if len(changes) > self.current.limits.max_changes:
            raise SurfaceDriftError("change count exceeds max_changes")
        if len(triggers) > self.current.limits.max_triggers:
            raise SurfaceDriftError("trigger count exceeds max_triggers")
        object.__setattr__(self, "no_effects", _no_effects(self.no_effects))
        expected_sha256 = _digest(ASSESSMENT_DOMAIN, self._identity_payload())
        expected_id = _derived_id("SDA", expected_sha256)
        if self.assessment_sha256 != expected_sha256 or self.assessment_id != expected_id:
            raise SurfaceDriftError("assessment identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "assessed_at": self.assessed_at,
            "baseline": self.baseline.to_dict(),
            "changes": [item.to_dict() for item in self.changes],
            "current": self.current.to_dict(),
            "no_effects": dict(self.no_effects),
            "schema_version": self.schema_version,
            "scope_binding_sha256": self.scope_binding_sha256,
            "triggers": [item.to_dict() for item in self.triggers],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "assessment_id": self.assessment_id,
            "assessment_sha256": self.assessment_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> DriftAssessment:
        _exact_fields(
            raw,
            {
                "assessed_at",
                "assessment_id",
                "assessment_sha256",
                "baseline",
                "changes",
                "current",
                "no_effects",
                "schema_version",
                "scope_binding_sha256",
                "triggers",
            },
            "drift assessment",
        )
        result = cls(
            schema_version=raw["schema_version"],
            assessment_id=raw["assessment_id"],
            assessment_sha256=raw["assessment_sha256"],
            assessed_at=raw["assessed_at"],
            scope_binding_sha256=raw["scope_binding_sha256"],
            baseline=SurfaceSnapshot.from_dict(raw["baseline"]),
            current=SurfaceSnapshot.from_dict(raw["current"]),
            changes=tuple(SurfaceChange.from_dict(item) for item in raw["changes"]),
            triggers=tuple(RevalidationTrigger.from_dict(item) for item in raw["triggers"]),
            no_effects=raw["no_effects"],
        )
        if result.to_dict() != dict(raw):
            raise SurfaceDriftError("drift assessment document is not canonical")
        return result


@dataclass(frozen=True)
class RevalidationPlanRecord:
    """One notification or rescan plan record with no external effect."""

    record_id: str
    action: PlanAction | str
    disposition: PlanDisposition | str
    reason: str
    planned_at: str
    trigger_id: str
    surface_id: str
    dedupe_key_sha256: str
    technique_ids: tuple[str, ...]
    profile_ids: tuple[str, ...]
    commander_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not RECORD_ID_RE.fullmatch(self.record_id):
            raise SurfaceDriftError("record_id is invalid")
        try:
            action = PlanAction(self.action)
            disposition = PlanDisposition(self.disposition)
        except (TypeError, ValueError) as exc:
            raise SurfaceDriftError("plan record enum value is invalid") from exc
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "disposition", disposition)
        _identifier(self.reason, "plan reason")
        _utc(self.planned_at, "planned_at")
        if not TRIGGER_ID_RE.fullmatch(self.trigger_id):
            raise SurfaceDriftError("plan trigger_id is invalid")
        _identifier(self.surface_id, "plan surface_id")
        _sha256(self.dedupe_key_sha256, "dedupe_key_sha256")
        object.__setattr__(self, "technique_ids", _refs(self.technique_ids, "plan technique_ids"))
        object.__setattr__(self, "profile_ids", _refs(self.profile_ids, "plan profile_ids"))
        object.__setattr__(self, "commander_ids", _refs(self.commander_ids, "plan commander_ids"))
        expected = _derived_id(
            "SDR", _digest("sunderkey.surface-drift-plan-record.v1", self._identity_payload())
        )
        if self.record_id != expected:
            raise SurfaceDriftError("plan record identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "commander_ids": list(self.commander_ids),
            "dedupe_key_sha256": self.dedupe_key_sha256,
            "disposition": self.disposition.value,
            "planned_at": self.planned_at,
            "profile_ids": list(self.profile_ids),
            "reason": self.reason,
            "surface_id": self.surface_id,
            "technique_ids": list(self.technique_ids),
            "trigger_id": self.trigger_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._identity_payload(), "record_id": self.record_id}

    @classmethod
    def from_dict(cls, raw: Any) -> RevalidationPlanRecord:
        _exact_fields(
            raw,
            {
                "action",
                "commander_ids",
                "dedupe_key_sha256",
                "disposition",
                "planned_at",
                "profile_ids",
                "reason",
                "record_id",
                "surface_id",
                "technique_ids",
                "trigger_id",
            },
            "revalidation plan record",
        )
        result = cls(
            record_id=raw["record_id"],
            action=raw["action"],
            disposition=raw["disposition"],
            reason=raw["reason"],
            planned_at=raw["planned_at"],
            trigger_id=raw["trigger_id"],
            surface_id=raw["surface_id"],
            dedupe_key_sha256=raw["dedupe_key_sha256"],
            technique_ids=tuple(raw["technique_ids"]),
            profile_ids=tuple(raw["profile_ids"]),
            commander_ids=tuple(raw["commander_ids"]),
        )
        if result.to_dict() != dict(raw):
            raise SurfaceDriftError("revalidation plan record is not canonical")
        return result


@dataclass(frozen=True)
class RevalidationPlanSet:
    """Content-addressed collection of effect-free plan records."""

    schema_version: int
    plan_id: str
    plan_sha256: str
    assessment_sha256: str
    planned_at: str
    cooldown_seconds: int
    records: tuple[RevalidationPlanRecord, ...]
    no_effects: Mapping[str, str]

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SurfaceDriftError("plan schema_version is unsupported")
        if not PLAN_ID_RE.fullmatch(self.plan_id):
            raise SurfaceDriftError("plan_id is invalid")
        _sha256(self.plan_sha256, "plan_sha256")
        _sha256(self.assessment_sha256, "assessment_sha256")
        _utc(self.planned_at, "planned_at")
        if (
            isinstance(self.cooldown_seconds, bool)
            or not isinstance(self.cooldown_seconds, int)
            or not 0 <= self.cooldown_seconds <= 2_592_000
        ):
            raise SurfaceDriftError("cooldown_seconds is invalid")
        records = tuple(self.records)
        if records != tuple(sorted(records, key=lambda item: (item.trigger_id, item.action.value))):
            raise SurfaceDriftError("plan records are not in canonical ordering")
        object.__setattr__(self, "no_effects", _no_effects(self.no_effects))
        expected_sha256 = _digest(PLAN_DOMAIN, self._identity_payload())
        expected_id = _derived_id("SDP", expected_sha256)
        if self.plan_sha256 != expected_sha256 or self.plan_id != expected_id:
            raise SurfaceDriftError("plan identity does not match canonical content")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "assessment_sha256": self.assessment_sha256,
            "cooldown_seconds": self.cooldown_seconds,
            "no_effects": dict(self.no_effects),
            "planned_at": self.planned_at,
            "records": [item.to_dict() for item in self.records],
            "schema_version": self.schema_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._identity_payload(),
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RevalidationPlanSet:
        _exact_fields(
            raw,
            {
                "assessment_sha256",
                "cooldown_seconds",
                "no_effects",
                "plan_id",
                "plan_sha256",
                "planned_at",
                "records",
                "schema_version",
            },
            "revalidation plan set",
        )
        result = cls(
            schema_version=raw["schema_version"],
            plan_id=raw["plan_id"],
            plan_sha256=raw["plan_sha256"],
            assessment_sha256=raw["assessment_sha256"],
            planned_at=raw["planned_at"],
            cooldown_seconds=raw["cooldown_seconds"],
            records=tuple(RevalidationPlanRecord.from_dict(item) for item in raw["records"]),
            no_effects=raw["no_effects"],
        )
        if result.to_dict() != dict(raw):
            raise SurfaceDriftError("revalidation plan set document is not canonical")
        return result


def build_surface_snapshot(
    observations: Iterable[SurfaceObservation],
    *,
    captured_at: str,
    scope_binding_sha256: str,
    parent: SurfaceSnapshot | None = None,
    protected_endpoint_ids: Iterable[str] = (),
    excluded_surface_ids: Iterable[str] = (),
    limits: DriftLimits | None = None,
) -> SurfaceSnapshot:
    """Build an immutable snapshot from already admitted observations."""

    _utc(captured_at, "captured_at")
    _sha256(scope_binding_sha256, "scope_binding_sha256")
    selected_limits = limits or (parent.limits if parent is not None else DriftLimits())
    ordered = tuple(sorted(tuple(observations), key=lambda item: item.surface_id))
    protected = _refs(tuple(protected_endpoint_ids), "protected_endpoint_ids")
    excluded = _refs(tuple(excluded_surface_ids), "excluded_surface_ids")
    if parent is None:
        sequence = 0
        parent_sha256 = None
    else:
        if scope_binding_sha256 != parent.scope_binding_sha256:
            raise SurfaceDriftError("child snapshot scope does not match parent")
        if selected_limits != parent.limits:
            raise SurfaceDriftError("child snapshot cannot replace lineage limits")
        if _utc(captured_at, "captured_at") <= _utc(parent.captured_at, "parent captured_at"):
            raise SurfaceDriftError("child captured_at must follow parent captured_at")
        if not set(parent.protected_endpoint_ids).issubset(protected):
            raise SurfaceDriftError("child snapshot cannot drop protected endpoints")
        if not set(parent.excluded_surface_ids).issubset(excluded):
            raise SurfaceDriftError("child snapshot cannot drop exclusions")
        sequence = parent.sequence + 1
        parent_sha256 = parent.snapshot_sha256
    payload = {
        "captured_at": captured_at,
        "excluded_surface_ids": list(excluded),
        "limits": selected_limits.to_dict(),
        "no_effects": dict(NO_EFFECTS),
        "observations": [item.to_dict() for item in ordered],
        "parent_snapshot_sha256": parent_sha256,
        "protected_endpoint_ids": list(protected),
        "schema_version": SCHEMA_VERSION,
        "scope_binding_sha256": scope_binding_sha256,
        "sequence": sequence,
    }
    digest = _digest(SNAPSHOT_DOMAIN, payload)
    return SurfaceSnapshot(
        schema_version=SCHEMA_VERSION,
        snapshot_id=_derived_id("SDS", digest),
        snapshot_sha256=digest,
        sequence=sequence,
        captured_at=captured_at,
        scope_binding_sha256=scope_binding_sha256,
        parent_snapshot_sha256=parent_sha256,
        observations=ordered,
        protected_endpoint_ids=protected,
        excluded_surface_ids=excluded,
        limits=selected_limits,
        no_effects=dict(NO_EFFECTS),
    )


def assess_surface_drift(
    baseline: SurfaceSnapshot,
    current: SurfaceSnapshot,
    *,
    assessed_at: str,
    minimum_trigger_risk: int = 1,
) -> DriftAssessment:
    """Compare a direct descendant with its baseline and derive triggers."""

    assessed = _utc(assessed_at, "assessed_at")
    _validate_lineage(baseline, current)
    if assessed < _utc(current.captured_at, "current captured_at"):
        raise SurfaceDriftError("assessed_at cannot precede current captured_at")
    if (
        isinstance(minimum_trigger_risk, bool)
        or not isinstance(minimum_trigger_risk, int)
        or not 0 <= minimum_trigger_risk <= 100
    ):
        raise SurfaceDriftError("minimum_trigger_risk is invalid")
    before = {item.surface_id: item for item in baseline.observations}
    after = {item.surface_id: item for item in current.observations}
    changes: list[SurfaceChange] = []
    for surface_id in sorted(set(before) | set(after)):
        prior = before.get(surface_id)
        present = after.get(surface_id)
        if prior is None:
            change_kind = ChangeKind.ADDED
            changed_fields: tuple[str, ...] = ()
        elif present is None:
            change_kind = ChangeKind.REMOVED
            changed_fields = ()
        else:
            if prior.surface_kind is not present.surface_kind:
                raise SurfaceDriftError("surface kind cannot change for an existing surface_id")
            changed_fields = _material_changed_fields(prior, present)
            if not changed_fields:
                continue
            change_kind = ChangeKind.CHANGED
        reference = present or prior
        assert reference is not None
        protected = surface_id in set(baseline.protected_endpoint_ids) | set(
            current.protected_endpoint_ids
        )
        excluded = surface_id in set(baseline.excluded_surface_ids) | set(
            current.excluded_surface_ids
        )
        certainty = _change_certainty(change_kind, present, assessed_at)
        risk_score = _change_risk(change_kind, reference.surface_kind, prior, present, certainty)
        changes.append(
            SurfaceChange(
                surface_id=surface_id,
                surface_kind=reference.surface_kind,
                change_kind=change_kind,
                certainty=certainty,
                before=prior,
                after=present,
                changed_fields=changed_fields,
                protected=protected,
                excluded=excluded,
                risk_score=risk_score,
            )
        )
    if len(changes) > current.limits.max_changes:
        raise SurfaceDriftError("drift exceeds max_changes")
    triggers = tuple(
        sorted(
            (
                _build_trigger(change)
                for change in changes
                if change.risk_score >= minimum_trigger_risk
            ),
            key=lambda item: item.trigger_id,
        )
    )
    if len(triggers) > current.limits.max_triggers:
        raise SurfaceDriftError("drift exceeds max_triggers")
    payload = {
        "assessed_at": assessed_at,
        "baseline": baseline.to_dict(),
        "changes": [item.to_dict() for item in changes],
        "current": current.to_dict(),
        "no_effects": dict(NO_EFFECTS),
        "schema_version": SCHEMA_VERSION,
        "scope_binding_sha256": current.scope_binding_sha256,
        "triggers": [item.to_dict() for item in triggers],
    }
    digest = _digest(ASSESSMENT_DOMAIN, payload)
    return DriftAssessment(
        schema_version=SCHEMA_VERSION,
        assessment_id=_derived_id("SDA", digest),
        assessment_sha256=digest,
        assessed_at=assessed_at,
        scope_binding_sha256=current.scope_binding_sha256,
        baseline=baseline,
        current=current,
        changes=tuple(changes),
        triggers=triggers,
        no_effects=dict(NO_EFFECTS),
    )


def plan_revalidation(
    assessment: DriftAssessment,
    *,
    planned_at: str,
    prior_records: Sequence[RevalidationPlanRecord] = (),
    cooldown_seconds: int = 3600,
) -> RevalidationPlanSet:
    """Create notification and rescan records without dispatching either."""

    planned = _utc(planned_at, "planned_at")
    if planned < _utc(assessment.assessed_at, "assessment assessed_at"):
        raise SurfaceDriftError("planned_at cannot precede assessed_at")
    if (
        isinstance(cooldown_seconds, bool)
        or not isinstance(cooldown_seconds, int)
        or not 0 <= cooldown_seconds <= 2_592_000
    ):
        raise SurfaceDriftError("cooldown_seconds is invalid")
    prior = tuple(prior_records)
    if any(not isinstance(item, RevalidationPlanRecord) for item in prior):
        raise SurfaceDriftError("prior_records contains an invalid record")
    if any(_utc(item.planned_at, "prior planned_at") > planned for item in prior):
        raise SurfaceDriftError("prior record cannot be from the future")
    records: list[RevalidationPlanRecord] = []
    for trigger in assessment.triggers:
        for action in PlanAction:
            permitted = (
                trigger.notification_permitted
                if action is PlanAction.NOTIFICATION
                else trigger.rescan_permitted
            )
            dedupe_key = _digest(
                "sunderkey.surface-drift-dedupe.v1",
                {"action": action.value, "trigger_id": trigger.trigger_id},
            )
            if not permitted:
                disposition = PlanDisposition.BLOCKED
                reason = "excluded_or_protected"
            elif any(item.dedupe_key_sha256 == dedupe_key for item in prior):
                disposition = PlanDisposition.DEDUPLICATED
                reason = "matching_plan_exists"
            elif _within_cooldown(prior, trigger.surface_id, action, planned, cooldown_seconds):
                disposition = PlanDisposition.COOLDOWN_SUPPRESSED
                reason = "surface_action_cooldown"
            else:
                disposition = PlanDisposition.PLANNED
                reason = "risk_weighted_revalidation"
            identity = {
                "action": action.value,
                "commander_ids": list(trigger.commander_ids),
                "dedupe_key_sha256": dedupe_key,
                "disposition": disposition.value,
                "planned_at": planned_at,
                "profile_ids": list(trigger.profile_ids),
                "reason": reason,
                "surface_id": trigger.surface_id,
                "technique_ids": list(trigger.technique_ids),
                "trigger_id": trigger.trigger_id,
            }
            record_digest = _digest("sunderkey.surface-drift-plan-record.v1", identity)
            records.append(
                RevalidationPlanRecord(
                    record_id=_derived_id("SDR", record_digest),
                    action=action,
                    disposition=disposition,
                    reason=reason,
                    planned_at=planned_at,
                    trigger_id=trigger.trigger_id,
                    surface_id=trigger.surface_id,
                    dedupe_key_sha256=dedupe_key,
                    technique_ids=trigger.technique_ids,
                    profile_ids=trigger.profile_ids,
                    commander_ids=trigger.commander_ids,
                )
            )
    records.sort(key=lambda item: (item.trigger_id, item.action.value))
    if len(records) > assessment.current.limits.max_plan_records:
        raise SurfaceDriftError("plan exceeds max_plan_records")
    payload = {
        "assessment_sha256": assessment.assessment_sha256,
        "cooldown_seconds": cooldown_seconds,
        "no_effects": dict(NO_EFFECTS),
        "planned_at": planned_at,
        "records": [item.to_dict() for item in records],
        "schema_version": SCHEMA_VERSION,
    }
    digest = _digest(PLAN_DOMAIN, payload)
    return RevalidationPlanSet(
        schema_version=SCHEMA_VERSION,
        plan_id=_derived_id("SDP", digest),
        plan_sha256=digest,
        assessment_sha256=assessment.assessment_sha256,
        planned_at=planned_at,
        cooldown_seconds=cooldown_seconds,
        records=tuple(records),
        no_effects=dict(NO_EFFECTS),
    )


def canonical_json(value: Any) -> str:
    """Serialize a supported contract value as canonical JSON."""

    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _validate_lineage(baseline: SurfaceSnapshot, current: SurfaceSnapshot) -> None:
    if baseline.scope_binding_sha256 != current.scope_binding_sha256:
        raise SurfaceDriftError("snapshot scope binding mismatch")
    if current.parent_snapshot_sha256 != baseline.snapshot_sha256:
        raise SurfaceDriftError("current snapshot is not a direct baseline descendant")
    if current.sequence != baseline.sequence + 1:
        raise SurfaceDriftError("snapshot sequence rollback or gap detected")
    if _utc(current.captured_at, "current captured_at") <= _utc(
        baseline.captured_at, "baseline captured_at"
    ):
        raise SurfaceDriftError("current snapshot time does not advance baseline")
    if not set(baseline.protected_endpoint_ids).issubset(current.protected_endpoint_ids):
        raise SurfaceDriftError("current snapshot dropped protected endpoints")
    if not set(baseline.excluded_surface_ids).issubset(current.excluded_surface_ids):
        raise SurfaceDriftError("current snapshot dropped exclusions")


def _material_changed_fields(
    before: SurfaceObservation, after: SurfaceObservation
) -> tuple[str, ...]:
    fields = (
        "commander_ids",
        "content_sha256",
        "freshness_expires_at",
        "observation_state",
        "observed_at",
        "profile_ids",
        "provenance_sha256",
        "risk_score",
        "technique_ids",
    )
    return tuple(
        sorted(field for field in fields if getattr(before, field) != getattr(after, field))
    )


def _change_certainty(
    change_kind: ChangeKind,
    after: SurfaceObservation | None,
    assessed_at: str,
) -> ChangeCertainty:
    if change_kind is ChangeKind.REMOVED:
        return ChangeCertainty.UNCERTAIN_ABSENCE
    assert after is not None
    if after.is_stale(assessed_at):
        return ChangeCertainty.STALE_PROVENANCE
    return ChangeCertainty(after.observation_state.value)


def _change_risk(
    change_kind: ChangeKind,
    surface_kind: SurfaceKind,
    before: SurfaceObservation | None,
    after: SurfaceObservation | None,
    certainty: ChangeCertainty,
) -> int:
    change_weight = {ChangeKind.ADDED: 15, ChangeKind.REMOVED: 30, ChangeKind.CHANGED: 25}[
        change_kind
    ]
    kind_weight = {
        SurfaceKind.ASSET: 5,
        SurfaceKind.ENDPOINT: 20,
        SurfaceKind.SCHEMA: 12,
        SurfaceKind.IDENTITY: 20,
        SurfaceKind.TRUST_EDGE: 25,
        SurfaceKind.CONTROL: 18,
        SurfaceKind.DEPLOYMENT: 30,
    }[surface_kind]
    evidence_weight = {
        ChangeCertainty.VERIFIED: 5,
        ChangeCertainty.NEGATIVE: 8,
        ChangeCertainty.HYPOTHESIS: 15,
        ChangeCertainty.ABSTAINED: 20,
        ChangeCertainty.UNCERTAIN_ABSENCE: 20,
        ChangeCertainty.STALE_PROVENANCE: 20,
    }[certainty]
    observation_risk = max(
        before.risk_score if before is not None else 0,
        after.risk_score if after is not None else 0,
    )
    return min(100, change_weight + kind_weight + evidence_weight + observation_risk // 2)


def _build_trigger(change: SurfaceChange) -> RevalidationTrigger:
    observations = tuple(item for item in (change.before, change.after) if item is not None)
    techniques = _refs(
        tuple(ref for item in observations for ref in item.technique_ids), "trigger technique_ids"
    )
    profiles = _refs(
        tuple(ref for item in observations for ref in item.profile_ids), "trigger profile_ids"
    )
    commanders = _refs(
        tuple(ref for item in observations for ref in item.commander_ids), "trigger commander_ids"
    )
    reason = (
        "stale_provenance"
        if change.certainty is ChangeCertainty.STALE_PROVENANCE
        else f"surface_{change.change_kind.value}"
    )
    change_sha256 = _digest("sunderkey.surface-drift-change.v1", change.to_dict())
    payload = {
        "change_sha256": change_sha256,
        "change_kind": change.change_kind.value,
        "commander_ids": list(commanders),
        "notification_permitted": not change.excluded,
        "profile_ids": list(profiles),
        "reason": reason,
        "rescan_permitted": not change.excluded and not change.protected,
        "risk_score": change.risk_score,
        "surface_id": change.surface_id,
        "technique_ids": list(techniques),
    }
    digest = _digest("sunderkey.surface-drift-trigger.v1", payload)
    return RevalidationTrigger(
        trigger_id=_derived_id("SDT", digest),
        change_sha256=change_sha256,
        surface_id=change.surface_id,
        change_kind=change.change_kind,
        reason=reason,
        risk_score=change.risk_score,
        technique_ids=techniques,
        profile_ids=profiles,
        commander_ids=commanders,
        notification_permitted=not change.excluded,
        rescan_permitted=not change.excluded and not change.protected,
    )


def _within_cooldown(
    prior: Sequence[RevalidationPlanRecord],
    surface_id: str,
    action: PlanAction,
    planned_at: datetime,
    cooldown_seconds: int,
) -> bool:
    for item in prior:
        if item.surface_id != surface_id or item.action is not action:
            continue
        delta = (planned_at - _utc(item.planned_at, "prior planned_at")).total_seconds()
        if delta < cooldown_seconds:
            return True
    return False


def _digest(domain: str, payload: Any) -> str:
    body = canonical_json({"domain": domain, "payload": payload}).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _derived_id(prefix: str, digest: str) -> str:
    _sha256(digest, "derived digest")
    return f"{prefix}-{digest.removeprefix('sha256:')[:32].upper()}"


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise SurfaceDriftError(f"{label} must be a lowercase SHA-256 reference")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise SurfaceDriftError(f"{label} is invalid")
    return value


def _refs(values: Iterable[Any], label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    try:
        materialized = tuple(values)
    except TypeError as exc:
        raise SurfaceDriftError(f"{label} must be an iterable of identifiers") from exc
    if any(not isinstance(item, str) or not IDENTIFIER_RE.fullmatch(item) for item in materialized):
        raise SurfaceDriftError(f"{label} contains an invalid identifier")
    canonical = tuple(sorted(set(materialized)))
    if not allow_empty and not canonical:
        raise SurfaceDriftError(f"{label} cannot be empty")
    return canonical


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise SurfaceDriftError(f"{label} must be second-precision UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SurfaceDriftError(f"{label} is not a valid UTC instant") from exc


def _no_effects(value: Any) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise SurfaceDriftError("no_effects declaration is invalid")
    snapshot = dict(value)
    if snapshot != NO_EFFECTS:
        raise SurfaceDriftError("no_effects declaration is invalid")
    return MappingProxyType(snapshot)


def _exact_fields(
    raw: Any,
    required: set[str],
    label: str,
    *,
    optional: set[str] | None = None,
) -> None:
    if not isinstance(raw, Mapping):
        raise SurfaceDriftError(f"{label} must be an object")
    optional = optional or set()
    keys = set(raw)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        raise SurfaceDriftError(f"{label} fields are invalid")
