"""Offline finding lifecycle, deduplication, and retest contracts.

This module is deliberately infrastructure independent. It creates immutable,
content-addressed values and performs no network, tool, authority, routing,
qualification, deployment, or execution operation.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = 1
SNAPSHOT_KIND = "sunderkey.finding-lifecycle-snapshot.v1"
EVENT_KIND = "sunderkey.finding-event.v1"
CANONICALIZATION_KIND = "sunderkey.finding-canonicalization.v1"
RETEST_PLAN_KIND = "sunderkey.finding-retest-plan.v1"
RETEST_ATTEMPT_KIND = "sunderkey.finding-retest-attempt.v1"
REPORT_KIND = "sunderkey.finding-report-view.v1"

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
CWE_RE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
CVSS_RE = re.compile(r"CVSS:(?:3\.[01]|4\.0)(?:/[A-Z][A-Z0-9]*:[A-Za-z0-9.]+)+\Z")
SECRET_RE = re.compile(
    r"(?:"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"
    r")",
    re.IGNORECASE,
)

NO_EFFECTS = {
    "deployment": "none",
    "execution": "none",
    "exploit_generation": "none",
    "network": "none",
    "qualification": "none",
    "routing": "none",
    "target_authority": "none",
    "tools": "none",
}


class FindingLifecycleError(ValueError):
    """Raised when a finding contract is unsafe, ambiguous, or inconsistent."""


class FindingState(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    VALIDATED = "validated"
    ACCEPTED = "accepted"
    REMEDIATION_IN_PROGRESS = "remediation_in_progress"
    RETEST_PENDING = "retest_pending"
    RESOLVED = "resolved"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"
    REOPENED = "reopened"


ALLOWED_TRANSITIONS: Mapping[FindingState, frozenset[FindingState]] = {
    FindingState.NEW: frozenset({FindingState.TRIAGED, FindingState.FALSE_POSITIVE}),
    FindingState.TRIAGED: frozenset({FindingState.VALIDATED, FindingState.FALSE_POSITIVE}),
    FindingState.VALIDATED: frozenset({FindingState.ACCEPTED, FindingState.FALSE_POSITIVE}),
    FindingState.ACCEPTED: frozenset(
        {FindingState.REMEDIATION_IN_PROGRESS, FindingState.RISK_ACCEPTED}
    ),
    FindingState.REMEDIATION_IN_PROGRESS: frozenset(
        {FindingState.RETEST_PENDING, FindingState.RISK_ACCEPTED}
    ),
    FindingState.RETEST_PENDING: frozenset({FindingState.RESOLVED, FindingState.REOPENED}),
    FindingState.RESOLVED: frozenset({FindingState.REOPENED}),
    FindingState.RISK_ACCEPTED: frozenset({FindingState.REOPENED}),
    FindingState.FALSE_POSITIVE: frozenset({FindingState.REOPENED}),
    FindingState.REOPENED: frozenset(
        {
            FindingState.TRIAGED,
            FindingState.REMEDIATION_IN_PROGRESS,
            FindingState.RETEST_PENDING,
        }
    ),
}


class FindingEventType(StrEnum):
    CREATED = "created"
    STATE_TRANSITION = "state_transition"
    EVIDENCE_ADDED = "evidence_added"
    RETEST_RECORDED = "retest_recorded"


class ReviewDecision(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ABSTAINED = "abstained"
    NOT_REQUIRED = "not_required"


class Severity(StrEnum):
    UNRATED = "unrated"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DedupeOutcome(StrEnum):
    EXACT_DUPLICATE = "exact_duplicate"
    LIKELY_RELATED = "likely_related"
    DISTINCT = "distinct"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class DedupeReason(StrEnum):
    FINGERPRINT_MATCH = "fingerprint_match"
    INCOMPLETE_SEMANTICS = "incomplete_semantics"
    ASSET_MISMATCH = "asset_mismatch"
    VULNERABILITY_CLASS_MISMATCH = "vulnerability_class_mismatch"
    STRONG_SEMANTIC_OVERLAP = "strong_semantic_overlap"
    OPERATION_OBJECT_BOUNDARY_CONFLICT = "operation_object_boundary_conflict"
    WEAK_SIGNAL_ONLY = "weak_signal_only"


class CanonicalizationType(StrEnum):
    MERGE = "merge"
    SUPERSESSION = "supersession"


class RetestResult(StrEnum):
    FIXED = "fixed"
    PERSISTS = "persists"
    REGRESSED = "regressed"
    INCONCLUSIVE = "inconclusive"
    ABSTAINED = "abstained"


class ValidationResult(StrEnum):
    VALIDATED = "validated"
    NOT_VALIDATED = "not_validated"
    INCONCLUSIVE = "inconclusive"
    ABSTAINED = "abstained"


class RetestTechniqueMode(StrEnum):
    ORIGINAL = "original"
    ALTERNATE = "alternate"


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON."""

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
        raise FindingLifecycleError("value cannot be serialized as canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    """Return a prefixed SHA-256 over canonical JSON."""

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class FindingIdentity:
    """Evidence-independent semantic identity used by deduplication."""

    asset: str
    surface: str
    vulnerability_class: str
    root_cause: str
    affected_boundary: str
    semantic_claim: str

    def __post_init__(self) -> None:
        for name in (
            "asset",
            "surface",
            "vulnerability_class",
            "root_cause",
            "affected_boundary",
            "semantic_claim",
        ):
            value = _normalize_semantic(getattr(self, name), name)
            object.__setattr__(self, name, value)

    @property
    def dedupe_fingerprint(self) -> str:
        return canonical_sha256(self.to_dict())

    @property
    def is_complete(self) -> bool:
        return all(value != "unknown" for value in self.to_dict().values())

    def to_dict(self) -> dict[str, str]:
        return {
            "affected_boundary": self.affected_boundary,
            "asset": self.asset,
            "root_cause": self.root_cause,
            "semantic_claim": self.semantic_claim,
            "surface": self.surface,
            "vulnerability_class": self.vulnerability_class,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> FindingIdentity:
        fields = {
            "affected_boundary",
            "asset",
            "root_cause",
            "semantic_claim",
            "surface",
            "vulnerability_class",
        }
        _exact_fields(raw, fields, "finding identity")
        candidate = cls(**raw)
        if raw != candidate.to_dict():
            raise FindingLifecycleError("finding identity is not canonically normalized")
        return candidate


@dataclass(frozen=True)
class FindingClassification:
    """Caller supplied severity and taxonomy references without score inference."""

    severity: Severity | str = Severity.UNRATED
    cwe_refs: tuple[str, ...] = ()
    cvss_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            severity = Severity(self.severity)
        except (TypeError, ValueError) as exc:
            raise FindingLifecycleError("severity is invalid") from exc
        object.__setattr__(self, "severity", severity)
        cwes = _canonical_pattern_refs(self.cwe_refs, CWE_RE, "CWE references")
        cvss = _canonical_pattern_refs(self.cvss_refs, CVSS_RE, "CVSS references")
        object.__setattr__(self, "cwe_refs", cwes)
        object.__setattr__(self, "cvss_refs", cvss)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cvss_refs": list(self.cvss_refs),
            "cwe_refs": list(self.cwe_refs),
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> FindingClassification:
        _exact_fields(raw, {"cvss_refs", "cwe_refs", "severity"}, "classification")
        _require_list(raw["cwe_refs"], "classification cwe_refs")
        _require_list(raw["cvss_refs"], "classification cvss_refs")
        candidate = cls(raw["severity"], tuple(raw["cwe_refs"]), tuple(raw["cvss_refs"]))
        if raw != candidate.to_dict():
            raise FindingLifecycleError("classification ordering is not canonical")
        return candidate


@dataclass(frozen=True)
class FindingEvent:
    """One typed, append-only, hash-chained lifecycle event."""

    event_id: str
    event_sha256: str
    finding_id: str
    sequence: int
    finding_version: int
    event_type: FindingEventType
    occurred_at: str
    actor_id: str
    authority_ref: str
    provenance_digests: tuple[str, ...]
    review_decision: ReviewDecision
    previous_event_sha256: str | None
    from_state: FindingState | None
    to_state: FindingState
    evidence_digests: tuple[str, ...]
    subject_digest: str | None
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "authority_ref": self.authority_ref,
            "effects": dict(NO_EFFECTS),
            "event_id": self.event_id,
            "event_sha256": self.event_sha256,
            "event_type": self.event_type.value,
            "evidence_digests": list(self.evidence_digests),
            "finding_id": self.finding_id,
            "finding_version": self.finding_version,
            "from_state": None if self.from_state is None else self.from_state.value,
            "kind": EVENT_KIND,
            "occurred_at": self.occurred_at,
            "previous_event_sha256": self.previous_event_sha256,
            "provenance_digests": list(self.provenance_digests),
            "reason_code": self.reason_code,
            "review_decision": self.review_decision.value,
            "schema_version": SCHEMA_VERSION,
            "sequence": self.sequence,
            "subject_digest": self.subject_digest,
            "to_state": self.to_state.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> FindingEvent:
        fields = {
            "actor_id",
            "authority_ref",
            "effects",
            "event_id",
            "event_sha256",
            "event_type",
            "evidence_digests",
            "finding_id",
            "finding_version",
            "from_state",
            "kind",
            "occurred_at",
            "previous_event_sha256",
            "provenance_digests",
            "reason_code",
            "review_decision",
            "schema_version",
            "sequence",
            "subject_digest",
            "to_state",
        }
        _exact_fields(raw, fields, "finding event")
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != EVENT_KIND:
            raise FindingLifecycleError("finding event kind or schema_version is invalid")
        _require_no_effects(raw["effects"], "finding event")
        _require_list(raw["evidence_digests"], "event evidence_digests")
        _require_list(raw["provenance_digests"], "event provenance_digests")
        event = _make_event(
            finding_id=raw["finding_id"],
            sequence=raw["sequence"],
            finding_version=raw["finding_version"],
            event_type=raw["event_type"],
            occurred_at=raw["occurred_at"],
            actor_id=raw["actor_id"],
            authority_ref=raw["authority_ref"],
            provenance_digests=tuple(raw["provenance_digests"]),
            review_decision=raw["review_decision"],
            previous_event_sha256=raw["previous_event_sha256"],
            from_state=raw["from_state"],
            to_state=raw["to_state"],
            evidence_digests=tuple(raw["evidence_digests"]),
            subject_digest=raw["subject_digest"],
            reason_code=raw["reason_code"],
        )
        if canonical_json(raw) != canonical_json(event.to_dict()):
            raise FindingLifecycleError("finding event identity or contents are invalid")
        return event


@dataclass(frozen=True)
class FindingReplay:
    """Deterministic state reconstructed from an append-only event sequence."""

    finding_id: str
    finding_version: int
    current_state: FindingState
    evidence_digests: tuple[str, ...]
    last_event_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_state": self.current_state.value,
            "effects": dict(NO_EFFECTS),
            "evidence_digests": list(self.evidence_digests),
            "finding_id": self.finding_id,
            "finding_version": self.finding_version,
            "last_event_sha256": self.last_event_sha256,
        }


@dataclass(frozen=True)
class FindingSnapshot:
    """An immutable, content-addressed current view plus complete event history."""

    snapshot_id: str
    snapshot_sha256: str
    parent_snapshot_sha256: str | None
    finding_id: str
    finding_version: int
    state: FindingState
    identity: FindingIdentity
    classification: FindingClassification
    evidence_digests: tuple[str, ...]
    created_at: str
    updated_at: str
    actor_id: str
    authority_ref: str
    provenance_digests: tuple[str, ...]
    review_decision: ReviewDecision
    events: tuple[FindingEvent, ...]

    @property
    def dedupe_fingerprint(self) -> str:
        return self.identity.dedupe_fingerprint

    def to_dict(self) -> dict[str, Any]:
        return _snapshot_document(
            snapshot_id=self.snapshot_id,
            snapshot_sha256=self.snapshot_sha256,
            parent_snapshot_sha256=self.parent_snapshot_sha256,
            finding_id=self.finding_id,
            finding_version=self.finding_version,
            state=self.state,
            identity=self.identity,
            classification=self.classification,
            evidence_digests=self.evidence_digests,
            created_at=self.created_at,
            updated_at=self.updated_at,
            actor_id=self.actor_id,
            authority_ref=self.authority_ref,
            provenance_digests=self.provenance_digests,
            review_decision=self.review_decision,
            events=self.events,
        )

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        expected_parent: FindingSnapshot | None = None,
    ) -> FindingSnapshot:
        fields = {
            "actor_id",
            "authority_ref",
            "classification",
            "created_at",
            "dedupe_fingerprint",
            "effects",
            "events",
            "evidence_digests",
            "finding_id",
            "finding_version",
            "identity",
            "kind",
            "parent_snapshot_sha256",
            "provenance_digests",
            "review_decision",
            "schema_version",
            "snapshot_id",
            "snapshot_sha256",
            "state",
            "updated_at",
        }
        _exact_fields(raw, fields, "finding snapshot")
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != SNAPSHOT_KIND:
            raise FindingLifecycleError("finding snapshot kind or schema_version is invalid")
        _require_no_effects(raw["effects"], "finding snapshot")
        _require_list(raw["events"], "snapshot events")
        _require_list(raw["evidence_digests"], "snapshot evidence_digests")
        _require_list(raw["provenance_digests"], "snapshot provenance_digests")
        identity = FindingIdentity.from_dict(raw["identity"])
        classification = FindingClassification.from_dict(raw["classification"])
        events = tuple(FindingEvent.from_dict(item) for item in raw["events"])
        candidate = _assemble_snapshot(
            parent_snapshot_sha256=raw["parent_snapshot_sha256"],
            finding_id=raw["finding_id"],
            identity=identity,
            classification=classification,
            created_at=raw["created_at"],
            events=events,
        )
        if canonical_json(raw) != canonical_json(candidate.to_dict()):
            raise FindingLifecycleError("finding snapshot identity or contents are invalid")
        if expected_parent is not None:
            candidate.verify_parent(expected_parent)
        return candidate

    def verify_parent(self, parent: FindingSnapshot) -> None:
        """Verify append-only version succession against an immediate parent."""

        if not isinstance(parent, FindingSnapshot):
            raise FindingLifecycleError("expected parent must be a FindingSnapshot")
        current = FindingSnapshot.from_dict(self.to_dict())
        prior = FindingSnapshot.from_dict(parent.to_dict())
        if current.finding_id != prior.finding_id:
            raise FindingLifecycleError("finding identity changed across snapshots")
        if current.parent_snapshot_sha256 != prior.snapshot_sha256:
            raise FindingLifecycleError("snapshot parent digest does not match")
        if current.finding_version != prior.finding_version + 1:
            raise FindingLifecycleError("finding version rollback or jump detected")
        if current.identity != prior.identity or current.classification != prior.classification:
            raise FindingLifecycleError("immutable finding semantics changed")
        if current.events[:-1] != prior.events:
            raise FindingLifecycleError("event history is not append-only")


@dataclass(frozen=True)
class DedupeDecision:
    """Advisory duplicate comparison that never performs a merge."""

    outcome: DedupeOutcome
    reason_codes: tuple[DedupeReason, ...]
    left_fingerprint: str
    right_fingerprint: str
    matched_dimensions: tuple[str, ...]
    differing_dimensions: tuple[str, ...]
    auto_merge_permitted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "auto_merge_permitted": self.auto_merge_permitted,
            "differing_dimensions": list(self.differing_dimensions),
            "effects": dict(NO_EFFECTS),
            "left_fingerprint": self.left_fingerprint,
            "matched_dimensions": list(self.matched_dimensions),
            "outcome": self.outcome.value,
            "reason_codes": [item.value for item in self.reason_codes],
            "right_fingerprint": self.right_fingerprint,
        }


@dataclass(frozen=True)
class FindingCanonicalizationRecord:
    """Reviewed merge or supersession relation preserving every source ID."""

    record_id: str
    record_sha256: str
    record_type: CanonicalizationType
    canonical_finding_id: str
    canonical_snapshot_sha256: str
    source_bindings: tuple[tuple[str, str], ...]
    created_at: str
    actor_id: str
    authority_ref: str
    provenance_digests: tuple[str, ...]
    review_decision: ReviewDecision
    reason_code: str

    @property
    def source_finding_ids(self) -> tuple[str, ...]:
        return tuple(item[0] for item in self.source_bindings)

    @property
    def all_finding_ids(self) -> tuple[str, ...]:
        return tuple(sorted((self.canonical_finding_id, *self.source_finding_ids)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "all_finding_ids": list(self.all_finding_ids),
            "authority_ref": self.authority_ref,
            "canonical_finding_id": self.canonical_finding_id,
            "canonical_snapshot_sha256": self.canonical_snapshot_sha256,
            "created_at": self.created_at,
            "effects": dict(NO_EFFECTS),
            "kind": CANONICALIZATION_KIND,
            "provenance_digests": list(self.provenance_digests),
            "reason_code": self.reason_code,
            "record_id": self.record_id,
            "record_sha256": self.record_sha256,
            "record_type": self.record_type.value,
            "review_decision": self.review_decision.value,
            "schema_version": SCHEMA_VERSION,
            "source_bindings": [
                {"finding_id": item[0], "snapshot_sha256": item[1]} for item in self.source_bindings
            ],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> FindingCanonicalizationRecord:
        fields = {
            "actor_id",
            "all_finding_ids",
            "authority_ref",
            "canonical_finding_id",
            "canonical_snapshot_sha256",
            "created_at",
            "effects",
            "kind",
            "provenance_digests",
            "reason_code",
            "record_id",
            "record_sha256",
            "record_type",
            "review_decision",
            "schema_version",
            "source_bindings",
        }
        _exact_fields(raw, fields, "canonicalization record")
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != CANONICALIZATION_KIND:
            raise FindingLifecycleError("canonicalization kind or schema_version is invalid")
        _require_no_effects(raw["effects"], "canonicalization record")
        _require_list(raw["source_bindings"], "source_bindings")
        _require_list(raw["provenance_digests"], "provenance_digests")
        bindings: list[tuple[str, str]] = []
        for item in raw["source_bindings"]:
            _exact_fields(item, {"finding_id", "snapshot_sha256"}, "source binding")
            bindings.append((item["finding_id"], item["snapshot_sha256"]))
        candidate = _make_canonicalization_record(
            record_type=raw["record_type"],
            canonical_finding_id=raw["canonical_finding_id"],
            canonical_snapshot_sha256=raw["canonical_snapshot_sha256"],
            source_bindings=tuple(bindings),
            created_at=raw["created_at"],
            actor_id=raw["actor_id"],
            authority_ref=raw["authority_ref"],
            provenance_digests=tuple(raw["provenance_digests"]),
            review_decision=raw["review_decision"],
            reason_code=raw["reason_code"],
        )
        if canonical_json(raw) != canonical_json(candidate.to_dict()):
            raise FindingLifecycleError("canonicalization identity or contents are invalid")
        return candidate


@dataclass(frozen=True)
class RetestPlan:
    """A separately authorized, non-executing retest description."""

    plan_id: str
    plan_sha256: str
    finding_id: str
    prior_finding_version: int
    prior_snapshot_sha256: str
    original_validation_result: ValidationResult
    original_validation_evidence_digests: tuple[str, ...]
    scope_ref: str
    technique_ref: str
    technique_mode: RetestTechniqueMode
    candidate_validator_versions: tuple[str, ...]
    authorized_at: str
    actor_id: str
    authority_ref: str
    provenance_digests: tuple[str, ...]
    review_decision: ReviewDecision

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "authority_ref": self.authority_ref,
            "authorized_at": self.authorized_at,
            "candidate_validator_versions": list(self.candidate_validator_versions),
            "effects": dict(NO_EFFECTS),
            "finding_id": self.finding_id,
            "kind": RETEST_PLAN_KIND,
            "original_validation_evidence_digests": list(self.original_validation_evidence_digests),
            "original_validation_result": self.original_validation_result.value,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "prior_finding_version": self.prior_finding_version,
            "prior_snapshot_sha256": self.prior_snapshot_sha256,
            "provenance_digests": list(self.provenance_digests),
            "review_decision": self.review_decision.value,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "status": "authorized_plan_only",
            "technique_mode": self.technique_mode.value,
            "technique_ref": self.technique_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RetestPlan:
        fields = {
            "actor_id",
            "authority_ref",
            "authorized_at",
            "candidate_validator_versions",
            "effects",
            "finding_id",
            "kind",
            "original_validation_evidence_digests",
            "original_validation_result",
            "plan_id",
            "plan_sha256",
            "prior_finding_version",
            "prior_snapshot_sha256",
            "provenance_digests",
            "review_decision",
            "schema_version",
            "scope_ref",
            "status",
            "technique_mode",
            "technique_ref",
        }
        _exact_fields(raw, fields, "retest plan")
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != RETEST_PLAN_KIND:
            raise FindingLifecycleError("retest plan kind or schema_version is invalid")
        if raw["status"] != "authorized_plan_only":
            raise FindingLifecycleError("retest plans must remain plan-only")
        _require_no_effects(raw["effects"], "retest plan")
        _require_list(raw["candidate_validator_versions"], "candidate validators")
        _require_list(
            raw["original_validation_evidence_digests"],
            "original validation evidence",
        )
        _require_list(raw["provenance_digests"], "plan provenance")
        candidate = create_retest_plan(
            finding_id=raw["finding_id"],
            prior_finding_version=raw["prior_finding_version"],
            prior_snapshot_sha256=raw["prior_snapshot_sha256"],
            original_validation_result=raw["original_validation_result"],
            original_validation_evidence_digests=tuple(raw["original_validation_evidence_digests"]),
            scope_ref=raw["scope_ref"],
            technique_ref=raw["technique_ref"],
            candidate_validator_versions=tuple(raw["candidate_validator_versions"]),
            authorized_at=raw["authorized_at"],
            actor_id=raw["actor_id"],
            authority_ref=raw["authority_ref"],
            provenance_digests=tuple(raw["provenance_digests"]),
            review_decision=raw["review_decision"],
            technique_mode=raw["technique_mode"],
        )
        if canonical_json(raw) != canonical_json(candidate.to_dict()):
            raise FindingLifecycleError("retest plan identity or contents are invalid")
        return candidate


@dataclass(frozen=True)
class RetestAttempt:
    """A recorded result bound to an original-technique authorized plan."""

    attempt_id: str
    attempt_sha256: str
    plan_id: str
    plan_sha256: str
    finding_id: str
    prior_finding_version: int
    prior_snapshot_sha256: str
    original_validation_result: ValidationResult
    original_validation_evidence_digests: tuple[str, ...]
    scope_ref: str
    technique_ref: str
    candidate_validator_versions: tuple[str, ...]
    result: RetestResult
    new_evidence_digests: tuple[str, ...]
    recorded_at: str
    actor_id: str
    authority_ref: str
    provenance_digests: tuple[str, ...]
    review_decision: ReviewDecision

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "attempt_id": self.attempt_id,
            "attempt_sha256": self.attempt_sha256,
            "authority_ref": self.authority_ref,
            "candidate_validator_versions": list(self.candidate_validator_versions),
            "effects": dict(NO_EFFECTS),
            "finding_id": self.finding_id,
            "kind": RETEST_ATTEMPT_KIND,
            "new_evidence_digests": list(self.new_evidence_digests),
            "original_validation_evidence_digests": list(self.original_validation_evidence_digests),
            "original_validation_result": self.original_validation_result.value,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "prior_finding_version": self.prior_finding_version,
            "prior_snapshot_sha256": self.prior_snapshot_sha256,
            "provenance_digests": list(self.provenance_digests),
            "recorded_at": self.recorded_at,
            "result": self.result.value,
            "review_decision": self.review_decision.value,
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "technique_ref": self.technique_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any, *, expected_plan: RetestPlan | None = None) -> RetestAttempt:
        fields = {
            "actor_id",
            "attempt_id",
            "attempt_sha256",
            "authority_ref",
            "candidate_validator_versions",
            "effects",
            "finding_id",
            "kind",
            "new_evidence_digests",
            "original_validation_evidence_digests",
            "original_validation_result",
            "plan_id",
            "plan_sha256",
            "prior_finding_version",
            "prior_snapshot_sha256",
            "provenance_digests",
            "recorded_at",
            "result",
            "review_decision",
            "schema_version",
            "scope_ref",
            "technique_ref",
        }
        _exact_fields(raw, fields, "retest attempt")
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != RETEST_ATTEMPT_KIND:
            raise FindingLifecycleError("retest attempt kind or schema_version is invalid")
        _require_no_effects(raw["effects"], "retest attempt")
        for name in (
            "candidate_validator_versions",
            "new_evidence_digests",
            "original_validation_evidence_digests",
            "provenance_digests",
        ):
            _require_list(raw[name], f"attempt {name}")
        candidate = _make_retest_attempt(
            plan_id=raw["plan_id"],
            plan_sha256=raw["plan_sha256"],
            finding_id=raw["finding_id"],
            prior_finding_version=raw["prior_finding_version"],
            prior_snapshot_sha256=raw["prior_snapshot_sha256"],
            original_validation_result=raw["original_validation_result"],
            original_validation_evidence_digests=tuple(raw["original_validation_evidence_digests"]),
            scope_ref=raw["scope_ref"],
            technique_ref=raw["technique_ref"],
            candidate_validator_versions=tuple(raw["candidate_validator_versions"]),
            result=raw["result"],
            new_evidence_digests=tuple(raw["new_evidence_digests"]),
            recorded_at=raw["recorded_at"],
            actor_id=raw["actor_id"],
            authority_ref=raw["authority_ref"],
            provenance_digests=tuple(raw["provenance_digests"]),
            review_decision=raw["review_decision"],
        )
        if canonical_json(raw) != canonical_json(candidate.to_dict()):
            raise FindingLifecycleError("retest attempt identity or contents are invalid")
        if expected_plan is not None:
            _verify_attempt_plan_binding(candidate, expected_plan)
        return candidate


@dataclass(frozen=True)
class FindingReportView:
    """Stable reporting projection with current state and complete history."""

    report_id: str
    report_sha256: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def create_finding(
    identity: FindingIdentity | Mapping[str, Any],
    *,
    classification: FindingClassification | Mapping[str, Any] | None = None,
    evidence_digests: Sequence[str] = (),
    created_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str = ReviewDecision.PENDING,
) -> FindingSnapshot:
    """Create the first immutable snapshot and its typed creation event."""

    identity_value = _coerce_identity(identity)
    classification_value = _coerce_classification(classification)
    created = _timestamp(created_at, "created_at")
    actor = _identifier(actor_id, "actor_id")
    authority = _identifier(authority_ref, "authority_ref")
    provenance = _digests(provenance_digests, "provenance_digests", allow_empty=False)
    evidence = _digests(evidence_digests, "evidence_digests")
    decision = _review(review_decision)
    finding_seed = {
        "actor_id": actor,
        "authority_ref": authority,
        "classification": classification_value.to_dict(),
        "created_at": created,
        "evidence_digests": list(evidence),
        "identity": identity_value.to_dict(),
        "provenance_digests": list(provenance),
        "review_decision": decision.value,
    }
    finding_id = _derived_id("FND", finding_seed)
    subject_digest = canonical_sha256(
        {
            "classification": classification_value.to_dict(),
            "identity": identity_value.to_dict(),
        }
    )
    event = _make_event(
        finding_id=finding_id,
        sequence=1,
        finding_version=1,
        event_type=FindingEventType.CREATED,
        occurred_at=created,
        actor_id=actor,
        authority_ref=authority,
        provenance_digests=provenance,
        review_decision=decision,
        previous_event_sha256=None,
        from_state=None,
        to_state=FindingState.NEW,
        evidence_digests=evidence,
        subject_digest=subject_digest,
        reason_code="finding_recorded",
    )
    return _assemble_snapshot(
        parent_snapshot_sha256=None,
        finding_id=finding_id,
        identity=identity_value,
        classification=classification_value,
        created_at=created,
        events=(event,),
    )


def transition_finding(
    snapshot: FindingSnapshot,
    to_state: FindingState | str,
    *,
    occurred_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    reason_code: str,
) -> FindingSnapshot:
    """Append one legal state transition to a finding."""

    current = _require_snapshot(snapshot)
    try:
        target = FindingState(to_state)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("target finding state is invalid") from exc
    if target not in ALLOWED_TRANSITIONS[current.state]:
        raise FindingLifecycleError(
            f"illegal finding transition: {current.state.value} to {target.value}"
        )
    event = _next_event(
        current,
        event_type=FindingEventType.STATE_TRANSITION,
        occurred_at=occurred_at,
        actor_id=actor_id,
        authority_ref=authority_ref,
        provenance_digests=provenance_digests,
        review_decision=review_decision,
        from_state=current.state,
        to_state=target,
        evidence_digests=(),
        subject_digest=None,
        reason_code=reason_code,
    )
    return _append_event(current, event)


def add_finding_evidence(
    snapshot: FindingSnapshot,
    evidence_digests: Sequence[str],
    *,
    occurred_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    reason_code: str = "evidence_added",
) -> FindingSnapshot:
    """Append new immutable digest references without changing lifecycle state."""

    current = _require_snapshot(snapshot)
    new_evidence = _digests(evidence_digests, "new evidence", allow_empty=False)
    if set(new_evidence) & set(current.evidence_digests):
        raise FindingLifecycleError("new evidence already exists on the finding")
    event = _next_event(
        current,
        event_type=FindingEventType.EVIDENCE_ADDED,
        occurred_at=occurred_at,
        actor_id=actor_id,
        authority_ref=authority_ref,
        provenance_digests=provenance_digests,
        review_decision=review_decision,
        from_state=current.state,
        to_state=current.state,
        evidence_digests=new_evidence,
        subject_digest=None,
        reason_code=reason_code,
    )
    return _append_event(current, event)


def replay_finding_events(events: Sequence[FindingEvent | Mapping[str, Any]]) -> FindingReplay:
    """Validate and replay an append-only event sequence."""

    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence) or not events:
        raise FindingLifecycleError("event history must be a nonempty sequence")
    parsed = tuple(
        FindingEvent.from_dict(item.to_dict())
        if isinstance(item, FindingEvent)
        else FindingEvent.from_dict(item)
        for item in events
    )
    first = parsed[0]
    if first.event_type is not FindingEventType.CREATED:
        raise FindingLifecycleError("event history must start with a created event")
    if (
        first.sequence != 1
        or first.finding_version != 1
        or first.previous_event_sha256 is not None
        or first.from_state is not None
        or first.to_state is not FindingState.NEW
        or first.subject_digest is None
    ):
        raise FindingLifecycleError("created event fields are invalid")
    finding_id = first.finding_id
    state = FindingState.NEW
    evidence = set(first.evidence_digests)
    previous = first
    for index, event in enumerate(parsed[1:], start=2):
        if event.finding_id != finding_id:
            raise FindingLifecycleError("event history mixes finding IDs")
        if event.sequence != index or event.finding_version != index:
            raise FindingLifecycleError("event version rollback, gap, or reordering detected")
        if event.previous_event_sha256 != previous.event_sha256:
            raise FindingLifecycleError("event hash chain is broken")
        if _timestamp_value(event.occurred_at, "event occurred_at") < _timestamp_value(
            previous.occurred_at, "prior event occurred_at"
        ):
            raise FindingLifecycleError("event timestamps are not monotonic")
        if event.event_type is FindingEventType.STATE_TRANSITION:
            if event.from_state is not state or event.to_state not in ALLOWED_TRANSITIONS[state]:
                raise FindingLifecycleError("event contains an illegal state transition")
            if event.evidence_digests or event.subject_digest is not None:
                raise FindingLifecycleError("state transition event has unexpected bindings")
            state = event.to_state
        elif event.event_type is FindingEventType.EVIDENCE_ADDED:
            if event.from_state is not state or event.to_state is not state:
                raise FindingLifecycleError("evidence event changed state")
            if not event.evidence_digests or event.subject_digest is not None:
                raise FindingLifecycleError("evidence event bindings are invalid")
            if evidence & set(event.evidence_digests):
                raise FindingLifecycleError("evidence history contains substitution or reuse")
            evidence.update(event.evidence_digests)
        elif event.event_type is FindingEventType.RETEST_RECORDED:
            if event.from_state is not state:
                raise FindingLifecycleError("retest event prior state is invalid")
            if state is not FindingState.RETEST_PENDING:
                raise FindingLifecycleError("retest events require retest_pending state")
            if event.subject_digest is None or not event.evidence_digests:
                raise FindingLifecycleError("retest event is missing immutable bindings")
            if event.to_state is not state and event.to_state not in ALLOWED_TRANSITIONS[state]:
                raise FindingLifecycleError("retest event contains an illegal transition")
            if evidence & set(event.evidence_digests):
                raise FindingLifecycleError("retest evidence substitutes existing evidence")
            evidence.update(event.evidence_digests)
            state = event.to_state
        else:
            raise FindingLifecycleError("created event may only occur first")
        previous = event
    return FindingReplay(
        finding_id=finding_id,
        finding_version=len(parsed),
        current_state=state,
        evidence_digests=tuple(sorted(evidence)),
        last_event_sha256=previous.event_sha256,
    )


def compare_findings(
    left: FindingSnapshot | FindingIdentity,
    right: FindingSnapshot | FindingIdentity,
) -> DedupeDecision:
    """Return a deterministic advisory duplicate outcome with reason codes."""

    left_identity = left.identity if isinstance(left, FindingSnapshot) else left
    right_identity = right.identity if isinstance(right, FindingSnapshot) else right
    if not isinstance(left_identity, FindingIdentity) or not isinstance(
        right_identity, FindingIdentity
    ):
        raise FindingLifecycleError("dedupe inputs must be findings or FindingIdentity values")
    dimensions = tuple(left_identity.to_dict())
    left_values = left_identity.to_dict()
    right_values = right_identity.to_dict()
    matched = tuple(name for name in dimensions if left_values[name] == right_values[name])
    differing = tuple(name for name in dimensions if left_values[name] != right_values[name])
    reasons: tuple[DedupeReason, ...]
    if not left_identity.is_complete or not right_identity.is_complete:
        outcome = DedupeOutcome.INSUFFICIENT_EVIDENCE
        reasons = (DedupeReason.INCOMPLETE_SEMANTICS,)
    elif left_identity.dedupe_fingerprint == right_identity.dedupe_fingerprint:
        outcome = DedupeOutcome.EXACT_DUPLICATE
        reasons = (DedupeReason.FINGERPRINT_MATCH,)
    elif left_identity.asset != right_identity.asset:
        outcome = DedupeOutcome.DISTINCT
        reasons = (DedupeReason.ASSET_MISMATCH,)
    elif left_identity.vulnerability_class != right_identity.vulnerability_class:
        outcome = DedupeOutcome.DISTINCT
        reasons = (DedupeReason.VULNERABILITY_CLASS_MISMATCH,)
    elif left_identity.affected_boundary != right_identity.affected_boundary:
        outcome = DedupeOutcome.DISTINCT
        reasons = (DedupeReason.OPERATION_OBJECT_BOUNDARY_CONFLICT,)
    elif len(matched) >= 4:
        outcome = DedupeOutcome.LIKELY_RELATED
        reasons = (DedupeReason.STRONG_SEMANTIC_OVERLAP,)
    else:
        outcome = DedupeOutcome.INSUFFICIENT_EVIDENCE
        reasons = (DedupeReason.WEAK_SIGNAL_ONLY,)
    return DedupeDecision(
        outcome=outcome,
        reason_codes=reasons,
        left_fingerprint=left_identity.dedupe_fingerprint,
        right_fingerprint=right_identity.dedupe_fingerprint,
        matched_dimensions=matched,
        differing_dimensions=differing,
        auto_merge_permitted=False,
    )


def create_merge_record(
    canonical: FindingSnapshot,
    sources: Sequence[FindingSnapshot],
    *,
    existing_records: Sequence[FindingCanonicalizationRecord] = (),
    created_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    reason_code: str,
) -> FindingCanonicalizationRecord:
    """Create a reviewed canonical merge record without mutating any finding."""

    return _create_canonicalization(
        CanonicalizationType.MERGE,
        canonical,
        sources,
        existing_records=existing_records,
        created_at=created_at,
        actor_id=actor_id,
        authority_ref=authority_ref,
        provenance_digests=provenance_digests,
        review_decision=review_decision,
        reason_code=reason_code,
    )


def create_supersession_record(
    successor: FindingSnapshot,
    superseded: Sequence[FindingSnapshot],
    *,
    existing_records: Sequence[FindingCanonicalizationRecord] = (),
    created_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    reason_code: str,
) -> FindingCanonicalizationRecord:
    """Create a reviewed supersession record preserving every predecessor ID."""

    return _create_canonicalization(
        CanonicalizationType.SUPERSESSION,
        successor,
        superseded,
        existing_records=existing_records,
        created_at=created_at,
        actor_id=actor_id,
        authority_ref=authority_ref,
        provenance_digests=provenance_digests,
        review_decision=review_decision,
        reason_code=reason_code,
    )


def create_retest_plan(
    *,
    finding: FindingSnapshot | None = None,
    finding_id: str | None = None,
    prior_finding_version: int | None = None,
    prior_snapshot_sha256: str | None = None,
    original_validation_result: ValidationResult | str,
    original_validation_evidence_digests: Sequence[str],
    scope_ref: str,
    technique_ref: str,
    candidate_validator_versions: Sequence[str],
    authorized_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    technique_mode: RetestTechniqueMode | str = RetestTechniqueMode.ORIGINAL,
) -> RetestPlan:
    """Create a plan that describes but never executes a retest."""

    if finding is not None:
        current = _require_snapshot(finding)
        if current.state is not FindingState.RETEST_PENDING:
            raise FindingLifecycleError("retest plans require a retest_pending finding")
        supplied = (finding_id, prior_finding_version, prior_snapshot_sha256)
        if any(value is not None for value in supplied):
            raise FindingLifecycleError("do not combine finding with explicit prior bindings")
        finding_id = current.finding_id
        prior_finding_version = current.finding_version
        prior_snapshot_sha256 = current.snapshot_sha256
    if finding_id is None or prior_finding_version is None or prior_snapshot_sha256 is None:
        raise FindingLifecycleError("retest plan requires complete prior finding bindings")
    finding_value = _identifier(finding_id, "retest finding_id")
    version = _positive_int(prior_finding_version, "prior finding version")
    prior_digest = _sha256(prior_snapshot_sha256, "prior snapshot digest")
    try:
        validation = ValidationResult(original_validation_result)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("original validation result is invalid") from exc
    original_evidence = _digests(
        original_validation_evidence_digests,
        "original validation evidence",
        allow_empty=False,
    )
    scope = _identifier(scope_ref, "scope_ref")
    technique = _identifier(technique_ref, "technique_ref")
    validators = _identifiers(
        candidate_validator_versions,
        "candidate validator versions",
        allow_empty=False,
    )
    authorized = _timestamp(authorized_at, "authorized_at")
    actor = _identifier(actor_id, "actor_id")
    authority = _identifier(authority_ref, "authority_ref")
    provenance = _digests(provenance_digests, "plan provenance", allow_empty=False)
    decision = _review(review_decision)
    if decision is not ReviewDecision.APPROVED:
        raise FindingLifecycleError("retest plans require an approved review decision")
    try:
        mode = RetestTechniqueMode(technique_mode)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("retest technique mode is invalid") from exc
    body = {
        "actor_id": actor,
        "authority_ref": authority,
        "authorized_at": authorized,
        "candidate_validator_versions": list(validators),
        "effects": dict(NO_EFFECTS),
        "finding_id": finding_value,
        "kind": RETEST_PLAN_KIND,
        "original_validation_evidence_digests": list(original_evidence),
        "original_validation_result": validation.value,
        "prior_finding_version": version,
        "prior_snapshot_sha256": prior_digest,
        "provenance_digests": list(provenance),
        "review_decision": decision.value,
        "schema_version": SCHEMA_VERSION,
        "scope_ref": scope,
        "status": "authorized_plan_only",
        "technique_mode": mode.value,
        "technique_ref": technique,
    }
    digest = canonical_sha256(body)
    return RetestPlan(
        plan_id=_id_from_digest("RTP", digest),
        plan_sha256=digest,
        finding_id=finding_value,
        prior_finding_version=version,
        prior_snapshot_sha256=prior_digest,
        original_validation_result=validation,
        original_validation_evidence_digests=original_evidence,
        scope_ref=scope,
        technique_ref=technique,
        technique_mode=mode,
        candidate_validator_versions=validators,
        authorized_at=authorized,
        actor_id=actor,
        authority_ref=authority,
        provenance_digests=provenance,
        review_decision=decision,
    )


def record_retest_attempt(
    plan: RetestPlan,
    finding: FindingSnapshot,
    *,
    result: RetestResult | str,
    new_evidence_digests: Sequence[str],
    recorded_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
) -> tuple[RetestAttempt, FindingSnapshot]:
    """Record an original-technique result and append its finding event."""

    if not isinstance(plan, RetestPlan):
        raise FindingLifecycleError("plan must be a RetestPlan")
    plan = RetestPlan.from_dict(plan.to_dict())
    current = _require_snapshot(finding)
    if plan.technique_mode is RetestTechniqueMode.ALTERNATE:
        raise FindingLifecycleError(
            "alternate-technique retests are separately authorized plans only"
        )
    if current.state is not FindingState.RETEST_PENDING:
        raise FindingLifecycleError("retest attempts require retest_pending state")
    if (
        plan.finding_id != current.finding_id
        or plan.prior_finding_version != current.finding_version
        or plan.prior_snapshot_sha256 != current.snapshot_sha256
    ):
        raise FindingLifecycleError("retest plan does not bind the current finding version")
    try:
        result_value = RetestResult(result)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("retest result is invalid") from exc
    new_evidence = _digests(new_evidence_digests, "new retest evidence", allow_empty=False)
    if set(new_evidence) & set(current.evidence_digests):
        raise FindingLifecycleError("retest evidence must be new and cannot be substituted")
    recorded = _timestamp(recorded_at, "recorded_at")
    if _timestamp_value(recorded, "recorded_at") < _timestamp_value(
        plan.authorized_at, "plan authorized_at"
    ):
        raise FindingLifecycleError("retest result predates its authorization")
    attempt = _make_retest_attempt(
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        finding_id=plan.finding_id,
        prior_finding_version=plan.prior_finding_version,
        prior_snapshot_sha256=plan.prior_snapshot_sha256,
        original_validation_result=plan.original_validation_result,
        original_validation_evidence_digests=plan.original_validation_evidence_digests,
        scope_ref=plan.scope_ref,
        technique_ref=plan.technique_ref,
        candidate_validator_versions=plan.candidate_validator_versions,
        result=result_value,
        new_evidence_digests=new_evidence,
        recorded_at=recorded,
        actor_id=actor_id,
        authority_ref=authority_ref,
        provenance_digests=tuple(provenance_digests),
        review_decision=review_decision,
    )
    next_state = {
        RetestResult.FIXED: FindingState.RESOLVED,
        RetestResult.PERSISTS: FindingState.REOPENED,
        RetestResult.REGRESSED: FindingState.REOPENED,
        RetestResult.INCONCLUSIVE: FindingState.RETEST_PENDING,
        RetestResult.ABSTAINED: FindingState.RETEST_PENDING,
    }[result_value]
    event = _next_event(
        current,
        event_type=FindingEventType.RETEST_RECORDED,
        occurred_at=recorded,
        actor_id=actor_id,
        authority_ref=authority_ref,
        provenance_digests=provenance_digests,
        review_decision=review_decision,
        from_state=current.state,
        to_state=next_state,
        evidence_digests=new_evidence,
        subject_digest=attempt.attempt_sha256,
        reason_code=f"retest_{result_value.value}",
    )
    return attempt, _append_event(current, event)


def build_finding_report(
    snapshot: FindingSnapshot,
    *,
    canonicalization_records: Sequence[FindingCanonicalizationRecord] = (),
    retest_attempts: Sequence[RetestAttempt] = (),
) -> FindingReportView:
    """Build a deterministic, content-addressed view of state and history."""

    current = _require_snapshot(snapshot)
    checked_records: list[FindingCanonicalizationRecord] = []
    for record in canonicalization_records:
        if not isinstance(record, FindingCanonicalizationRecord):
            raise FindingLifecycleError("report canonicalizations must be records")
        checked_records.append(FindingCanonicalizationRecord.from_dict(record.to_dict()))
    checked_attempts: list[RetestAttempt] = []
    for attempt in retest_attempts:
        if not isinstance(attempt, RetestAttempt):
            raise FindingLifecycleError("report retest attempts must be records")
        checked_attempts.append(RetestAttempt.from_dict(attempt.to_dict()))
    records = tuple(sorted(checked_records, key=lambda item: item.record_id))
    attempts = tuple(sorted(checked_attempts, key=lambda item: item.attempt_id))
    for record in records:
        if current.finding_id not in record.all_finding_ids:
            raise FindingLifecycleError("report canonicalization is unrelated to finding")
    for attempt in attempts:
        if attempt.finding_id != current.finding_id:
            raise FindingLifecycleError("report retest attempt is unrelated to finding")
    body = {
        "canonicalizations": [item.to_dict() for item in records],
        "classification": current.classification.to_dict(),
        "current_state": current.state.value,
        "dedupe_fingerprint": current.dedupe_fingerprint,
        "effects": dict(NO_EFFECTS),
        "evidence_digests": list(current.evidence_digests),
        "finding_id": current.finding_id,
        "finding_version": current.finding_version,
        "history": [item.to_dict() for item in current.events],
        "identity": current.identity.to_dict(),
        "kind": REPORT_KIND,
        "retest_attempts": [item.to_dict() for item in attempts],
        "schema_version": SCHEMA_VERSION,
        "snapshot_sha256": current.snapshot_sha256,
    }
    digest = canonical_sha256(body)
    document = dict(body)
    document["report_id"] = _id_from_digest("FRV", digest)
    document["report_sha256"] = digest
    return FindingReportView(document["report_id"], digest, canonical_json(document))


def _create_canonicalization(
    record_type: CanonicalizationType,
    canonical: FindingSnapshot,
    sources: Sequence[FindingSnapshot],
    *,
    existing_records: Sequence[FindingCanonicalizationRecord],
    created_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    reason_code: str,
) -> FindingCanonicalizationRecord:
    canonical_value = _require_snapshot(canonical)
    if isinstance(sources, (str, bytes)) or not isinstance(sources, Sequence) or not sources:
        raise FindingLifecycleError("canonicalization requires source findings")
    source_values = tuple(_require_snapshot(item) for item in sources)
    source_ids = tuple(item.finding_id for item in source_values)
    if len(set(source_ids)) != len(source_ids):
        raise FindingLifecycleError("canonicalization source IDs must be unique")
    if canonical_value.finding_id in source_ids:
        raise FindingLifecycleError("a finding cannot canonicalize itself")
    decision = _review(review_decision)
    if decision is not ReviewDecision.APPROVED:
        raise FindingLifecycleError("canonicalization requires approved review")
    records: tuple[FindingCanonicalizationRecord, ...] = tuple(
        FindingCanonicalizationRecord.from_dict(item.to_dict())
        if isinstance(item, FindingCanonicalizationRecord)
        else _raise_invalid_canonicalization()
        for item in existing_records
    )
    _reject_canonicalization_cycle(canonical_value.finding_id, source_ids, records)
    bindings = tuple(sorted((item.finding_id, item.snapshot_sha256) for item in source_values))
    return _make_canonicalization_record(
        record_type=record_type,
        canonical_finding_id=canonical_value.finding_id,
        canonical_snapshot_sha256=canonical_value.snapshot_sha256,
        source_bindings=bindings,
        created_at=created_at,
        actor_id=actor_id,
        authority_ref=authority_ref,
        provenance_digests=tuple(provenance_digests),
        review_decision=decision,
        reason_code=reason_code,
    )


def _make_canonicalization_record(
    *,
    record_type: CanonicalizationType | str,
    canonical_finding_id: str,
    canonical_snapshot_sha256: str,
    source_bindings: Sequence[tuple[str, str]],
    created_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    reason_code: str,
) -> FindingCanonicalizationRecord:
    try:
        type_value = CanonicalizationType(record_type)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("canonicalization type is invalid") from exc
    canonical_id = _identifier(canonical_finding_id, "canonical finding_id")
    canonical_digest = _sha256(canonical_snapshot_sha256, "canonical snapshot digest")
    bindings = tuple(sorted(source_bindings))
    if not bindings or len(set(bindings)) != len(bindings):
        raise FindingLifecycleError("source bindings must be nonempty and unique")
    checked_bindings = tuple(
        (
            _identifier(item[0], "source finding_id"),
            _sha256(item[1], "source snapshot digest"),
        )
        for item in bindings
    )
    if tuple(sorted(checked_bindings)) != checked_bindings:
        raise FindingLifecycleError("source bindings are not canonical")
    if canonical_id in {item[0] for item in checked_bindings}:
        raise FindingLifecycleError("canonical finding cannot appear in source bindings")
    created = _timestamp(created_at, "canonicalization created_at")
    actor = _identifier(actor_id, "actor_id")
    authority = _identifier(authority_ref, "authority_ref")
    provenance = _digests(provenance_digests, "canonicalization provenance", allow_empty=False)
    decision = _review(review_decision)
    if decision is not ReviewDecision.APPROVED:
        raise FindingLifecycleError("canonicalization requires approved review")
    reason = _token(reason_code, "canonicalization reason_code")
    all_ids = tuple(sorted((canonical_id, *(item[0] for item in checked_bindings))))
    body = {
        "actor_id": actor,
        "all_finding_ids": list(all_ids),
        "authority_ref": authority,
        "canonical_finding_id": canonical_id,
        "canonical_snapshot_sha256": canonical_digest,
        "created_at": created,
        "effects": dict(NO_EFFECTS),
        "kind": CANONICALIZATION_KIND,
        "provenance_digests": list(provenance),
        "reason_code": reason,
        "record_type": type_value.value,
        "review_decision": decision.value,
        "schema_version": SCHEMA_VERSION,
        "source_bindings": [
            {"finding_id": item[0], "snapshot_sha256": item[1]} for item in checked_bindings
        ],
    }
    digest = canonical_sha256(body)
    return FindingCanonicalizationRecord(
        record_id=_id_from_digest("FCR", digest),
        record_sha256=digest,
        record_type=type_value,
        canonical_finding_id=canonical_id,
        canonical_snapshot_sha256=canonical_digest,
        source_bindings=checked_bindings,
        created_at=created,
        actor_id=actor,
        authority_ref=authority,
        provenance_digests=provenance,
        review_decision=decision,
        reason_code=reason,
    )


def _reject_canonicalization_cycle(
    canonical_id: str,
    source_ids: Sequence[str],
    records: Sequence[FindingCanonicalizationRecord],
) -> None:
    graph: dict[str, set[str]] = {}
    for record in records:
        for source_id in record.source_finding_ids:
            graph.setdefault(source_id, set()).add(record.canonical_finding_id)
    for source_id in source_ids:
        graph.setdefault(source_id, set()).add(canonical_id)
    for start in graph:
        stack: list[tuple[str, tuple[str, ...]]] = [(start, ())]
        while stack:
            node, path = stack.pop()
            if node in path:
                raise FindingLifecycleError("canonicalization cycle detected")
            stack.extend((target, (*path, node)) for target in graph.get(node, ()))


def _make_retest_attempt(
    *,
    plan_id: str,
    plan_sha256: str,
    finding_id: str,
    prior_finding_version: int,
    prior_snapshot_sha256: str,
    original_validation_result: ValidationResult | str,
    original_validation_evidence_digests: Sequence[str],
    scope_ref: str,
    technique_ref: str,
    candidate_validator_versions: Sequence[str],
    result: RetestResult | str,
    new_evidence_digests: Sequence[str],
    recorded_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
) -> RetestAttempt:
    plan_id_value = _identifier(plan_id, "plan_id")
    plan_digest = _sha256(plan_sha256, "plan digest")
    finding_value = _identifier(finding_id, "finding_id")
    version = _positive_int(prior_finding_version, "prior finding version")
    prior_digest = _sha256(prior_snapshot_sha256, "prior snapshot digest")
    try:
        validation = ValidationResult(original_validation_result)
        result_value = RetestResult(result)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("retest result binding is invalid") from exc
    original_evidence = _digests(
        original_validation_evidence_digests,
        "original validation evidence",
        allow_empty=False,
    )
    new_evidence = _digests(new_evidence_digests, "new retest evidence", allow_empty=False)
    if set(original_evidence) & set(new_evidence):
        raise FindingLifecycleError("new retest evidence substitutes original evidence")
    scope = _identifier(scope_ref, "scope_ref")
    technique = _identifier(technique_ref, "technique_ref")
    validators = _identifiers(
        candidate_validator_versions,
        "candidate validator versions",
        allow_empty=False,
    )
    recorded = _timestamp(recorded_at, "recorded_at")
    actor = _identifier(actor_id, "actor_id")
    authority = _identifier(authority_ref, "authority_ref")
    provenance = _digests(provenance_digests, "attempt provenance", allow_empty=False)
    decision = _review(review_decision)
    body = {
        "actor_id": actor,
        "authority_ref": authority,
        "candidate_validator_versions": list(validators),
        "effects": dict(NO_EFFECTS),
        "finding_id": finding_value,
        "kind": RETEST_ATTEMPT_KIND,
        "new_evidence_digests": list(new_evidence),
        "original_validation_evidence_digests": list(original_evidence),
        "original_validation_result": validation.value,
        "plan_id": plan_id_value,
        "plan_sha256": plan_digest,
        "prior_finding_version": version,
        "prior_snapshot_sha256": prior_digest,
        "provenance_digests": list(provenance),
        "recorded_at": recorded,
        "result": result_value.value,
        "review_decision": decision.value,
        "schema_version": SCHEMA_VERSION,
        "scope_ref": scope,
        "technique_ref": technique,
    }
    digest = canonical_sha256(body)
    return RetestAttempt(
        attempt_id=_id_from_digest("RTA", digest),
        attempt_sha256=digest,
        plan_id=plan_id_value,
        plan_sha256=plan_digest,
        finding_id=finding_value,
        prior_finding_version=version,
        prior_snapshot_sha256=prior_digest,
        original_validation_result=validation,
        original_validation_evidence_digests=original_evidence,
        scope_ref=scope,
        technique_ref=technique,
        candidate_validator_versions=validators,
        result=result_value,
        new_evidence_digests=new_evidence,
        recorded_at=recorded,
        actor_id=actor,
        authority_ref=authority,
        provenance_digests=provenance,
        review_decision=decision,
    )


def _verify_attempt_plan_binding(attempt: RetestAttempt, plan: RetestPlan) -> None:
    expected = (
        plan.plan_id,
        plan.plan_sha256,
        plan.finding_id,
        plan.prior_finding_version,
        plan.prior_snapshot_sha256,
        plan.original_validation_result,
        plan.original_validation_evidence_digests,
        plan.scope_ref,
        plan.technique_ref,
        plan.candidate_validator_versions,
    )
    actual = (
        attempt.plan_id,
        attempt.plan_sha256,
        attempt.finding_id,
        attempt.prior_finding_version,
        attempt.prior_snapshot_sha256,
        attempt.original_validation_result,
        attempt.original_validation_evidence_digests,
        attempt.scope_ref,
        attempt.technique_ref,
        attempt.candidate_validator_versions,
    )
    if actual != expected:
        raise FindingLifecycleError("retest attempt does not bind the expected plan")
    if plan.technique_mode is not RetestTechniqueMode.ORIGINAL:
        raise FindingLifecycleError("alternate-technique plans cannot produce attempts")


def _next_event(
    snapshot: FindingSnapshot,
    *,
    event_type: FindingEventType,
    occurred_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    from_state: FindingState,
    to_state: FindingState,
    evidence_digests: Sequence[str],
    subject_digest: str | None,
    reason_code: str,
) -> FindingEvent:
    occurred = _timestamp(occurred_at, "event occurred_at")
    if _timestamp_value(occurred, "event occurred_at") < _timestamp_value(
        snapshot.updated_at, "snapshot updated_at"
    ):
        raise FindingLifecycleError("event timestamp predates the current snapshot")
    return _make_event(
        finding_id=snapshot.finding_id,
        sequence=snapshot.finding_version + 1,
        finding_version=snapshot.finding_version + 1,
        event_type=event_type,
        occurred_at=occurred,
        actor_id=actor_id,
        authority_ref=authority_ref,
        provenance_digests=tuple(provenance_digests),
        review_decision=review_decision,
        previous_event_sha256=snapshot.events[-1].event_sha256,
        from_state=from_state,
        to_state=to_state,
        evidence_digests=tuple(evidence_digests),
        subject_digest=subject_digest,
        reason_code=reason_code,
    )


def _make_event(
    *,
    finding_id: str,
    sequence: int,
    finding_version: int,
    event_type: FindingEventType | str,
    occurred_at: str,
    actor_id: str,
    authority_ref: str,
    provenance_digests: Sequence[str],
    review_decision: ReviewDecision | str,
    previous_event_sha256: str | None,
    from_state: FindingState | str | None,
    to_state: FindingState | str,
    evidence_digests: Sequence[str],
    subject_digest: str | None,
    reason_code: str,
) -> FindingEvent:
    finding = _identifier(finding_id, "event finding_id")
    sequence_value = _positive_int(sequence, "event sequence")
    version_value = _positive_int(finding_version, "event finding_version")
    if sequence_value != version_value:
        raise FindingLifecycleError("event sequence and finding version must match")
    try:
        event_type_value = FindingEventType(event_type)
        to_state_value = FindingState(to_state)
        from_state_value = None if from_state is None else FindingState(from_state)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("event type or state is invalid") from exc
    occurred = _timestamp(occurred_at, "event occurred_at")
    actor = _identifier(actor_id, "event actor_id")
    authority = _identifier(authority_ref, "event authority_ref")
    provenance = _digests(provenance_digests, "event provenance", allow_empty=False)
    decision = _review(review_decision)
    previous = (
        None
        if previous_event_sha256 is None
        else _sha256(previous_event_sha256, "previous event digest")
    )
    evidence = _digests(evidence_digests, "event evidence")
    subject = None if subject_digest is None else _sha256(subject_digest, "subject digest")
    reason = _token(reason_code, "event reason_code")
    body = {
        "actor_id": actor,
        "authority_ref": authority,
        "effects": dict(NO_EFFECTS),
        "event_type": event_type_value.value,
        "evidence_digests": list(evidence),
        "finding_id": finding,
        "finding_version": version_value,
        "from_state": None if from_state_value is None else from_state_value.value,
        "kind": EVENT_KIND,
        "occurred_at": occurred,
        "previous_event_sha256": previous,
        "provenance_digests": list(provenance),
        "reason_code": reason,
        "review_decision": decision.value,
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence_value,
        "subject_digest": subject,
        "to_state": to_state_value.value,
    }
    digest = canonical_sha256(body)
    return FindingEvent(
        event_id=_id_from_digest("FEV", digest),
        event_sha256=digest,
        finding_id=finding,
        sequence=sequence_value,
        finding_version=version_value,
        event_type=event_type_value,
        occurred_at=occurred,
        actor_id=actor,
        authority_ref=authority,
        provenance_digests=provenance,
        review_decision=decision,
        previous_event_sha256=previous,
        from_state=from_state_value,
        to_state=to_state_value,
        evidence_digests=evidence,
        subject_digest=subject,
        reason_code=reason,
    )


def _append_event(snapshot: FindingSnapshot, event: FindingEvent) -> FindingSnapshot:
    if event.finding_id != snapshot.finding_id:
        raise FindingLifecycleError("event finding_id does not match snapshot")
    return _assemble_snapshot(
        parent_snapshot_sha256=snapshot.snapshot_sha256,
        finding_id=snapshot.finding_id,
        identity=snapshot.identity,
        classification=snapshot.classification,
        created_at=snapshot.created_at,
        events=(*snapshot.events, event),
    )


def _assemble_snapshot(
    *,
    parent_snapshot_sha256: str | None,
    finding_id: str,
    identity: FindingIdentity,
    classification: FindingClassification,
    created_at: str,
    events: Sequence[FindingEvent],
) -> FindingSnapshot:
    parent = (
        None
        if parent_snapshot_sha256 is None
        else _sha256(parent_snapshot_sha256, "parent snapshot digest")
    )
    finding = _identifier(finding_id, "finding_id")
    if not isinstance(identity, FindingIdentity) or not isinstance(
        classification, FindingClassification
    ):
        raise FindingLifecycleError("snapshot semantics have invalid types")
    created = _timestamp(created_at, "created_at")
    history = tuple(events)
    replay = replay_finding_events(history)
    if replay.finding_id != finding:
        raise FindingLifecycleError("event replay finding_id does not match snapshot")
    if history[0].occurred_at != created:
        raise FindingLifecycleError("created_at does not match the creation event")
    subject = canonical_sha256(
        {"classification": classification.to_dict(), "identity": identity.to_dict()}
    )
    if history[0].subject_digest != subject:
        raise FindingLifecycleError("creation event semantic binding is invalid")
    last = history[-1]
    body = _snapshot_body(
        parent_snapshot_sha256=parent,
        finding_id=finding,
        finding_version=replay.finding_version,
        state=replay.current_state,
        identity=identity,
        classification=classification,
        evidence_digests=replay.evidence_digests,
        created_at=created,
        updated_at=last.occurred_at,
        actor_id=last.actor_id,
        authority_ref=last.authority_ref,
        provenance_digests=last.provenance_digests,
        review_decision=last.review_decision,
        events=history,
    )
    digest = canonical_sha256(body)
    return FindingSnapshot(
        snapshot_id=_id_from_digest("FSN", digest),
        snapshot_sha256=digest,
        parent_snapshot_sha256=parent,
        finding_id=finding,
        finding_version=replay.finding_version,
        state=replay.current_state,
        identity=identity,
        classification=classification,
        evidence_digests=replay.evidence_digests,
        created_at=created,
        updated_at=last.occurred_at,
        actor_id=last.actor_id,
        authority_ref=last.authority_ref,
        provenance_digests=last.provenance_digests,
        review_decision=last.review_decision,
        events=history,
    )


def _snapshot_body(**values: Any) -> dict[str, Any]:
    return {
        "actor_id": values["actor_id"],
        "authority_ref": values["authority_ref"],
        "classification": values["classification"].to_dict(),
        "created_at": values["created_at"],
        "dedupe_fingerprint": values["identity"].dedupe_fingerprint,
        "effects": dict(NO_EFFECTS),
        "events": [item.to_dict() for item in values["events"]],
        "evidence_digests": list(values["evidence_digests"]),
        "finding_id": values["finding_id"],
        "finding_version": values["finding_version"],
        "identity": values["identity"].to_dict(),
        "kind": SNAPSHOT_KIND,
        "parent_snapshot_sha256": values["parent_snapshot_sha256"],
        "provenance_digests": list(values["provenance_digests"]),
        "review_decision": values["review_decision"].value,
        "schema_version": SCHEMA_VERSION,
        "state": values["state"].value,
        "updated_at": values["updated_at"],
    }


def _snapshot_document(**values: Any) -> dict[str, Any]:
    body = _snapshot_body(**values)
    body["snapshot_id"] = values["snapshot_id"]
    body["snapshot_sha256"] = values["snapshot_sha256"]
    return body


def _coerce_identity(value: FindingIdentity | Mapping[str, Any]) -> FindingIdentity:
    if isinstance(value, FindingIdentity):
        return value
    raw = dict(value) if isinstance(value, Mapping) else value
    fields = {
        "affected_boundary",
        "asset",
        "root_cause",
        "semantic_claim",
        "surface",
        "vulnerability_class",
    }
    _exact_fields(raw, fields, "finding identity")
    return FindingIdentity(**raw)


def _coerce_classification(
    value: FindingClassification | Mapping[str, Any] | None,
) -> FindingClassification:
    if value is None:
        return FindingClassification()
    if isinstance(value, FindingClassification):
        return value
    raw = dict(value) if isinstance(value, Mapping) else value
    _exact_fields(raw, {"cvss_refs", "cwe_refs", "severity"}, "classification")
    return FindingClassification(
        severity=raw["severity"],
        cwe_refs=tuple(raw["cwe_refs"]),
        cvss_refs=tuple(raw["cvss_refs"]),
    )


def _require_snapshot(value: Any) -> FindingSnapshot:
    if not isinstance(value, FindingSnapshot):
        raise FindingLifecycleError("value must be a FindingSnapshot")
    return FindingSnapshot.from_dict(value.to_dict())


def _raise_invalid_canonicalization() -> Any:
    raise FindingLifecycleError("existing canonicalizations contain an invalid record")


def _normalize_semantic(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise FindingLifecycleError(f"{label} must be text")
    normalized = unicodedata.normalize("NFKC", value).strip().lower()
    normalized = re.sub(r"\s+", " ", normalized)
    if label in {"asset", "surface", "affected_boundary"}:
        normalized = normalized.rstrip("/")
    if not normalized or len(normalized) > 1024:
        raise FindingLifecycleError(f"{label} must contain 1 to 1024 characters")
    if not normalized.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in normalized):
        raise FindingLifecycleError(f"{label} must contain printable ASCII")
    _reject_secret(normalized, label)
    return normalized


def _validate_json_value(value: Any, label: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**63 - 1:
            raise FindingLifecycleError(f"{label} integer is out of range")
        return
    if isinstance(value, float):
        raise FindingLifecycleError(f"{label} cannot contain floating-point numbers")
    if isinstance(value, str):
        if not value.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in value):
            raise FindingLifecycleError(f"{label} must contain printable ASCII")
        _reject_secret(value, label)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{label}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise FindingLifecycleError(f"{label} has an invalid object key")
            _validate_json_value(item, f"{label}.{key}")
        return
    raise FindingLifecycleError(f"{label} has an unsupported JSON type")


def _exact_fields(raw: Any, expected: set[str], label: str) -> None:
    if not isinstance(raw, dict):
        raise FindingLifecycleError(f"{label} must be an object")
    missing = expected - set(raw)
    unknown = set(raw) - expected
    if missing or unknown:
        raise FindingLifecycleError(
            f"{label} fields are invalid: missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _require_list(value: Any, label: str) -> None:
    if not isinstance(value, list):
        raise FindingLifecycleError(f"{label} must be a list")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise FindingLifecycleError(f"{label} is not a portable identifier")
    _reject_secret(value, label)
    return value


def _token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise FindingLifecycleError(f"{label} is not a lowercase token")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise FindingLifecycleError(f"{label} must be a lowercase sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise FindingLifecycleError(f"{label} must use second-precision UTC Z format")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise FindingLifecycleError(f"{label} is not a valid UTC timestamp") from exc
    return value


def _timestamp_value(value: Any, label: str) -> datetime:
    checked = _timestamp(value, label)
    return datetime.strptime(checked, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**31 - 1:
        raise FindingLifecycleError(f"{label} must be a positive 32-bit integer")
    return value


def _review(value: ReviewDecision | str) -> ReviewDecision:
    try:
        return ReviewDecision(value)
    except (TypeError, ValueError) as exc:
        raise FindingLifecycleError("review decision is invalid") from exc


def _digests(
    values: Sequence[str],
    label: str,
    *,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise FindingLifecycleError(f"{label} must be a sequence of digests")
    checked = tuple(_sha256(value, label) for value in values)
    canonical = tuple(sorted(set(checked)))
    if len(checked) != len(canonical):
        raise FindingLifecycleError(f"{label} must not contain duplicates")
    if not allow_empty and not canonical:
        raise FindingLifecycleError(f"{label} must not be empty")
    if len(canonical) > 1024:
        raise FindingLifecycleError(f"{label} exceeds the reference limit")
    return canonical


def _identifiers(
    values: Sequence[str],
    label: str,
    *,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise FindingLifecycleError(f"{label} must be a sequence")
    checked = tuple(_identifier(value, label) for value in values)
    canonical = tuple(sorted(set(checked)))
    if len(checked) != len(canonical):
        raise FindingLifecycleError(f"{label} must not contain duplicates")
    if not allow_empty and not canonical:
        raise FindingLifecycleError(f"{label} must not be empty")
    return canonical


def _canonical_pattern_refs(
    values: Sequence[str],
    pattern: re.Pattern[str],
    label: str,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise FindingLifecycleError(f"{label} must be a sequence")
    checked: list[str] = []
    for value in values:
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise FindingLifecycleError(f"{label} contains an invalid reference")
        checked.append(value)
    canonical = tuple(sorted(set(checked)))
    if len(checked) != len(canonical):
        raise FindingLifecycleError(f"{label} must not contain duplicates")
    return canonical


def _reject_secret(value: str, label: str) -> None:
    if SECRET_RE.search(value):
        raise FindingLifecycleError(f"{label} appears to contain secret material")


def _require_no_effects(value: Any, label: str) -> None:
    if value != NO_EFFECTS:
        raise FindingLifecycleError(f"{label} effects must all be none")


def _derived_id(prefix: str, value: Any) -> str:
    return _id_from_digest(prefix, canonical_sha256(value))


def _id_from_digest(prefix: str, digest: str) -> str:
    return f"{prefix}-{digest.removeprefix('sha256:')[:32].upper()}"


# Compatibility aliases for callers that prefer explicit lifecycle names.
deduplicate_findings = compare_findings
render_finding_report = build_finding_report
replay_events = replay_finding_events


__all__ = [
    "ALLOWED_TRANSITIONS",
    "CanonicalizationType",
    "DedupeDecision",
    "DedupeOutcome",
    "DedupeReason",
    "FindingCanonicalizationRecord",
    "FindingClassification",
    "FindingEvent",
    "FindingEventType",
    "FindingIdentity",
    "FindingLifecycleError",
    "FindingReplay",
    "FindingReportView",
    "FindingSnapshot",
    "FindingState",
    "NO_EFFECTS",
    "RetestAttempt",
    "RetestPlan",
    "RetestResult",
    "RetestTechniqueMode",
    "ReviewDecision",
    "Severity",
    "ValidationResult",
    "add_finding_evidence",
    "build_finding_report",
    "canonical_json",
    "canonical_sha256",
    "compare_findings",
    "create_finding",
    "create_merge_record",
    "create_retest_plan",
    "create_supersession_record",
    "deduplicate_findings",
    "record_retest_attempt",
    "render_finding_report",
    "replay_events",
    "replay_finding_events",
    "transition_finding",
]
