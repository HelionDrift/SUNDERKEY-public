"""Effect-free change-event intake and assessment candidate planning.

Typed, already supplied evidence is the only source of events here. An event or
candidate is not authenticated authority, a scheduled job, or target permission.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .api_release_delta_review import ApiReleaseDelta, ApiReleaseDeltaError
from .api_release_role_response_review import (
    ApiReleaseRoleResponseReview,
    ApiReleaseRoleResponseReviewError,
)
from .surface_drift_detection import DriftAssessment, SurfaceDriftError
from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

MAX_EVENTS = 256
MAX_PRIOR_CANDIDATES = 4096
MAX_DAILY_CANDIDATES = 64
MAX_AGE_SECONDS = 30 * 24 * 60 * 60
NO_EFFECTS = MappingProxyType(
    {
        "authority": "none",
        "execution": "none",
        "network": "none",
        "notification": "none",
        "scheduler": "none",
    }
)


class EventAssessmentError(ValueError):
    """Change evidence or candidate planning failed closed."""


class EventKind(StrEnum):
    API_RELEASE_DELTA = "api_release_delta"
    SURFACE_DRIFT = "surface_drift"


class CandidateDisposition(StrEnum):
    REVIEW_CANDIDATE = "review_candidate"
    NO_CHANGE_SIGNAL = "no_change_signal"
    DUPLICATE = "duplicate"
    COOLDOWN = "cooldown_suppressed"
    BUDGET = "budget_suppressed"
    STOPPED = "stop_suppressed"
    STALE = "stale_evidence"


def _sha(value: str, name: str) -> None:
    try:
        _digest(value, name)
    except TrafficApiInventoryError as exc:
        raise EventAssessmentError(f"{name} is invalid") from exc


def _time(value: str, name: str):
    try:
        return _timestamp(value, name)
    except TrafficApiInventoryError as exc:
        raise EventAssessmentError(f"{name} is invalid") from exc


def _id(value: str, name: str) -> None:
    try:
        _identifier(value, name)
    except TrafficApiInventoryError as exc:
        raise EventAssessmentError(f"{name} is invalid") from exc


def _positive_limit(value: int, maximum: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise EventAssessmentError(f"{name} is outside its hard limit")


@dataclass(frozen=True, slots=True)
class AssessmentChangeEvent:
    event_id: str
    source_id: str
    kind: EventKind | str
    scope_sha256: str
    evidence_sha256: str
    occurred_at: str
    change_signal: bool
    reason_codes: tuple[str, ...]
    event_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.source_id, "source_id")
        try:
            kind = EventKind(self.kind)
        except (TypeError, ValueError) as exc:
            raise EventAssessmentError("event kind is invalid") from exc
        object.__setattr__(self, "kind", kind)
        _sha(self.scope_sha256, "scope_sha256")
        _sha(self.evidence_sha256, "evidence_sha256")
        _time(self.occurred_at, "occurred_at")
        if not isinstance(self.change_signal, bool):
            raise EventAssessmentError("change_signal must be a boolean")
        if (
            not isinstance(self.reason_codes, tuple)
            or len(self.reason_codes) > 32
            or tuple(sorted(set(self.reason_codes))) != self.reason_codes
        ):
            raise EventAssessmentError("reason_codes must be unique and canonical")
        for reason in self.reason_codes:
            _id(reason, "reason code")
        if self.change_signal and not self.reason_codes:
            raise EventAssessmentError("a change signal requires a reason")
        expected = _canonical_sha("sunderkey.assessment-change-event.v1", self._payload())
        if self.event_sha256 and self.event_sha256 != expected:
            raise EventAssessmentError("event_sha256 does not match event content")
        object.__setattr__(self, "event_sha256", expected)
        if self.event_id != f"ACE-{expected[7:39].upper()}":
            raise EventAssessmentError("event_id does not match event content")

    def _payload(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "kind": self.kind.value,
            "scope_sha256": self.scope_sha256,
            "evidence_sha256": self.evidence_sha256,
            "occurred_at": self.occurred_at,
            "change_signal": self.change_signal,
            "reason_codes": list(self.reason_codes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "event_id": self.event_id, "event_sha256": self.event_sha256}


def _event(
    *,
    source_id: str,
    kind: EventKind,
    scope_sha256: str,
    evidence_sha256: str,
    occurred_at: str,
    change_signal: bool,
    reason_codes: tuple[str, ...],
) -> AssessmentChangeEvent:
    payload = {
        "source_id": source_id,
        "kind": kind.value,
        "scope_sha256": scope_sha256,
        "evidence_sha256": evidence_sha256,
        "occurred_at": occurred_at,
        "change_signal": change_signal,
        "reason_codes": list(reason_codes),
    }
    digest = _canonical_sha("sunderkey.assessment-change-event.v1", payload)
    return AssessmentChangeEvent(
        event_id=f"ACE-{digest[7:39].upper()}",
        source_id=source_id,
        kind=kind,
        scope_sha256=scope_sha256,
        evidence_sha256=evidence_sha256,
        occurred_at=occurred_at,
        change_signal=change_signal,
        reason_codes=reason_codes,
        event_sha256=digest,
    )


def event_from_evidence(
    evidence: ApiReleaseDelta | ApiReleaseRoleResponseReview | DriftAssessment,
    *,
    observed_at: str | None = None,
) -> AssessmentChangeEvent:
    """Normalize typed release or drift evidence without treating it as authority."""
    if isinstance(evidence, ApiReleaseRoleResponseReview):
        try:
            review = ApiReleaseRoleResponseReview.from_dict(evidence.to_dict())
        except ApiReleaseRoleResponseReviewError as exc:
            raise EventAssessmentError("release role-response review integrity is invalid") from exc
        if observed_at is None or _time(observed_at, "observed_at") < _time(
            review.current_snapshot_at, "current_snapshot_at"
        ):
            raise EventAssessmentError(
                "release review event requires a current-snapshot observed_at"
            )
        return _event(
            source_id=review.release_id,
            kind=EventKind.API_RELEASE_DELTA,
            scope_sha256=review.scope_sha256,
            evidence_sha256=review.review_sha256,
            occurred_at=observed_at,
            change_signal=review.gate_status == "review_required",
            reason_codes=review.review_reasons,
        )
    if isinstance(evidence, ApiReleaseDelta):
        try:
            replace(evidence)
        except ApiReleaseDeltaError as exc:
            raise EventAssessmentError("release delta integrity is invalid") from exc
        if observed_at is None or _time(observed_at, "observed_at") < _time(
            evidence.release_at, "release_at"
        ):
            raise EventAssessmentError("release event requires a post-release observed_at")
        return _event(
            source_id=evidence.release_id,
            kind=EventKind.API_RELEASE_DELTA,
            scope_sha256=evidence.scope_sha256,
            evidence_sha256=evidence.delta_sha256,
            occurred_at=observed_at,
            change_signal=evidence.gate_status == "review_required",
            reason_codes=evidence.review_reasons,
        )
    if isinstance(evidence, DriftAssessment):
        try:
            replace(evidence)
        except SurfaceDriftError as exc:
            raise EventAssessmentError("drift assessment integrity is invalid") from exc
        if observed_at is not None:
            raise EventAssessmentError("drift event time comes from the assessment")
        reasons = tuple(sorted({f"drift_{item.change_kind.value}" for item in evidence.changes}))
        return _event(
            source_id=evidence.assessment_id,
            kind=EventKind.SURFACE_DRIFT,
            scope_sha256=evidence.scope_binding_sha256,
            evidence_sha256=evidence.assessment_sha256,
            occurred_at=evidence.assessed_at,
            change_signal=bool(evidence.changes),
            reason_codes=reasons,
        )
    raise EventAssessmentError("typed release delta, role-response review or drift is required")


@dataclass(frozen=True, slots=True)
class AssessmentCandidate:
    event: AssessmentChangeEvent
    disposition: CandidateDisposition | str
    evaluated_at: str
    candidate_sha256: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.event, AssessmentChangeEvent):
            raise EventAssessmentError("candidate event is invalid")
        replace(self.event)
        try:
            disposition = CandidateDisposition(self.disposition)
        except (TypeError, ValueError) as exc:
            raise EventAssessmentError("candidate disposition is invalid") from exc
        object.__setattr__(self, "disposition", disposition)
        if _time(self.evaluated_at, "evaluated_at") < _time(self.event.occurred_at, "occurred_at"):
            raise EventAssessmentError("candidate predates its event")
        if not self.event.change_signal and disposition not in (
            CandidateDisposition.NO_CHANGE_SIGNAL,
            CandidateDisposition.STOPPED,
        ):
            raise EventAssessmentError("no-change evidence cannot produce an assessment candidate")
        expected = _canonical_sha("sunderkey.assessment-candidate.v1", self._payload())
        if self.candidate_sha256 and self.candidate_sha256 != expected:
            raise EventAssessmentError("candidate_sha256 does not match content")
        object.__setattr__(self, "candidate_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "disposition": self.disposition.value,
            "evaluated_at": self.evaluated_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "candidate_sha256": self.candidate_sha256}


@dataclass(frozen=True, slots=True)
class AssessmentCandidateBatch:
    as_of: str
    scope_sha256: str
    max_event_age_seconds: int
    cooldown_seconds: int
    daily_candidate_budget: int
    intake_stopped: bool
    event_set_sha256: str
    prior_candidate_set_sha256: str
    candidates: tuple[AssessmentCandidate, ...]
    batch_sha256: str = ""

    def __post_init__(self) -> None:
        _time(self.as_of, "as_of")
        _sha(self.scope_sha256, "scope_sha256")
        _sha(self.event_set_sha256, "event_set_sha256")
        _sha(self.prior_candidate_set_sha256, "prior_candidate_set_sha256")
        _positive_limit(self.max_event_age_seconds, MAX_AGE_SECONDS, "max_event_age_seconds")
        _positive_limit(self.cooldown_seconds, MAX_AGE_SECONDS, "cooldown_seconds")
        _positive_limit(self.daily_candidate_budget, MAX_DAILY_CANDIDATES, "daily_candidate_budget")
        if not isinstance(self.intake_stopped, bool):
            raise EventAssessmentError("intake_stopped must be a boolean")
        if (
            len(self.candidates) > MAX_EVENTS
            or tuple(sorted(self.candidates, key=lambda item: item.event.event_sha256))
            != self.candidates
        ):
            raise EventAssessmentError("candidates are not bounded and canonical")
        if any(item.event.scope_sha256 != self.scope_sha256 for item in self.candidates):
            raise EventAssessmentError("candidate scope differs from batch scope")
        if any(item.evaluated_at != self.as_of for item in self.candidates):
            raise EventAssessmentError("candidate evaluation time differs from batch time")
        expected_events = _canonical_sha(
            "sunderkey.assessment-event-input-set.v1",
            {"event_sha256s": sorted(item.event.event_sha256 for item in self.candidates)},
        )
        if self.event_set_sha256 != expected_events:
            raise EventAssessmentError("event set does not match batch candidates")
        expected = _canonical_sha("sunderkey.assessment-candidate-batch.v1", self._payload())
        if self.batch_sha256 and self.batch_sha256 != expected:
            raise EventAssessmentError("batch_sha256 does not match content")
        object.__setattr__(self, "batch_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "scope_sha256": self.scope_sha256,
            "max_event_age_seconds": self.max_event_age_seconds,
            "cooldown_seconds": self.cooldown_seconds,
            "daily_candidate_budget": self.daily_candidate_budget,
            "event_set_sha256": self.event_set_sha256,
            "intake_stopped": self.intake_stopped,
            "prior_candidate_set_sha256": self.prior_candidate_set_sha256,
            "candidates": [item.to_dict() for item in self.candidates],
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "batch_sha256": self.batch_sha256}


def plan_event_assessments(
    *,
    events: tuple[AssessmentChangeEvent, ...],
    scope_sha256: str,
    as_of: str,
    prior_candidates: tuple[AssessmentCandidate, ...] = (),
    max_event_age_seconds: int = 86400,
    cooldown_seconds: int = 3600,
    daily_candidate_budget: int = 8,
    intake_stopped: bool = False,
) -> AssessmentCandidateBatch:
    """Return review candidates with bounded dedupe, cooldown, budget, and stop logic."""
    now = _time(as_of, "as_of")
    _sha(scope_sha256, "scope_sha256")
    _positive_limit(max_event_age_seconds, MAX_AGE_SECONDS, "max_event_age_seconds")
    _positive_limit(cooldown_seconds, MAX_AGE_SECONDS, "cooldown_seconds")
    _positive_limit(daily_candidate_budget, MAX_DAILY_CANDIDATES, "daily_candidate_budget")
    if not isinstance(intake_stopped, bool):
        raise EventAssessmentError("intake_stopped must be a boolean")
    if not isinstance(events, tuple) or len(events) > MAX_EVENTS:
        raise EventAssessmentError("events must be a bounded tuple")
    if not isinstance(prior_candidates, tuple) or len(prior_candidates) > MAX_PRIOR_CANDIDATES:
        raise EventAssessmentError("prior_candidates must be a bounded tuple")
    if any(not isinstance(item, AssessmentChangeEvent) for item in events):
        raise EventAssessmentError("events must be typed change events")
    if any(not isinstance(item, AssessmentCandidate) for item in prior_candidates):
        raise EventAssessmentError("prior_candidates must be typed candidates")
    for item in events:
        replace(item)
        if item.scope_sha256 != scope_sha256:
            raise EventAssessmentError("event scope differs from requested scope")
        if _time(item.occurred_at, "event occurred_at") > now:
            raise EventAssessmentError("event occurred_at is in the future")
    for item in prior_candidates:
        replace(item)
        if item.event.scope_sha256 != scope_sha256:
            raise EventAssessmentError("prior candidate scope differs from requested scope")
        if _time(item.evaluated_at, "prior evaluated_at") > now:
            raise EventAssessmentError("prior candidate is in the future")
    prior_digests = {
        item.event.event_sha256
        for item in prior_candidates
        if item.disposition is CandidateDisposition.REVIEW_CANDIDATE
    }
    review_times = [
        _time(item.evaluated_at, "prior evaluated_at")
        for item in prior_candidates
        if item.disposition is CandidateDisposition.REVIEW_CANDIDATE
    ]
    candidates: list[AssessmentCandidate] = []
    seen: set[str] = set()
    for event in sorted(events, key=lambda item: item.event_sha256):
        occurred = _time(event.occurred_at, "occurred_at")
        active_times = [time for time in review_times if now - timedelta(days=1) < time <= now]
        if intake_stopped:
            disposition = CandidateDisposition.STOPPED
        elif now - occurred > timedelta(seconds=max_event_age_seconds):
            disposition = CandidateDisposition.STALE
        elif not event.change_signal:
            disposition = CandidateDisposition.NO_CHANGE_SIGNAL
        elif event.event_sha256 in prior_digests or event.event_sha256 in seen:
            disposition = CandidateDisposition.DUPLICATE
        elif any(now - timedelta(seconds=cooldown_seconds) < time <= now for time in review_times):
            disposition = CandidateDisposition.COOLDOWN
        elif len(active_times) >= daily_candidate_budget:
            disposition = CandidateDisposition.BUDGET
        else:
            disposition = CandidateDisposition.REVIEW_CANDIDATE
            review_times.append(now)
        seen.add(event.event_sha256)
        candidates.append(AssessmentCandidate(event, disposition, as_of))
    return AssessmentCandidateBatch(
        as_of=as_of,
        scope_sha256=scope_sha256,
        max_event_age_seconds=max_event_age_seconds,
        cooldown_seconds=cooldown_seconds,
        daily_candidate_budget=daily_candidate_budget,
        intake_stopped=intake_stopped,
        event_set_sha256=_canonical_sha(
            "sunderkey.assessment-event-input-set.v1",
            {"event_sha256s": sorted(item.event_sha256 for item in events)},
        ),
        prior_candidate_set_sha256=_canonical_sha(
            "sunderkey.assessment-prior-candidate-set.v1",
            {"candidate_sha256s": sorted(item.candidate_sha256 for item in prior_candidates)},
        ),
        candidates=tuple(candidates),
    )


def verify_assessment_candidate_batch(
    batch: AssessmentCandidateBatch,
    *,
    events: tuple[AssessmentChangeEvent, ...],
    prior_candidates: tuple[AssessmentCandidate, ...] = (),
) -> AssessmentCandidateBatch:
    """Replay a stored batch against its complete caller-supplied inputs."""

    if not isinstance(batch, AssessmentCandidateBatch):
        raise EventAssessmentError("candidate batch is invalid")
    replace(batch)
    expected = plan_event_assessments(
        events=events,
        scope_sha256=batch.scope_sha256,
        as_of=batch.as_of,
        prior_candidates=prior_candidates,
        max_event_age_seconds=batch.max_event_age_seconds,
        cooldown_seconds=batch.cooldown_seconds,
        daily_candidate_budget=batch.daily_candidate_budget,
        intake_stopped=batch.intake_stopped,
    )
    if expected != batch:
        raise EventAssessmentError("candidate batch does not match source replay")
    return batch
