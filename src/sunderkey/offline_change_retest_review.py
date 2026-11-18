"""Durable change intake to conditional retest review, without target effects.

The caller must inject independently trusted, current source, authority, and
clock ports. This module supplies none of those trust roots. Its only write is
to the existing offline candidate-history store. A packet is not admission,
execution permission, a retest plan, or evidence that a target changed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .durable_scheduler_contracts import ScheduleDefinition
from .event_assessment_history import OfflineEventAssessmentHistoryStore
from .event_assessment_planning import AssessmentChangeEvent, CandidateDisposition
from .finding_lifecycle import FindingSnapshot, FindingState

DOMAIN = "sunderkey.offline-change-retest-review.v1"
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
NO_TARGET_EFFECTS = {
    "assessment_admission": "none",
    "execution": "none",
    "finding_transition": "none",
    "publication": "none",
    "scheduler_activation": "none",
    "target_interaction": "none",
}


class ChangeRetestReviewError(ValueError):
    """A source, authority, history, or finding binding failed closed."""


class TrustedClock(Protocol):
    def now_utc(self) -> str: ...


class CurrentSourceVerifier(Protocol):
    def verify_event(self, event: AssessmentChangeEvent, *, as_of: str) -> str: ...


class CurrentAuthorityVerifier(Protocol):
    def verify_scope(
        self, *, tenant_id: str, scope_sha256: str, purpose: str, as_of: str
    ) -> str: ...


class FindingBindingVerifier(Protocol):
    def verify_finding(
        self, *, event: AssessmentChangeEvent, finding: FindingSnapshot, as_of: str
    ) -> bool: ...


class CurrentTimeReceiptVerifier(Protocol):
    def verify_time(
        self, *, packet_sha256: str, event_sha256: str, not_before: str
    ) -> dict[str, object]: ...


class CurrentSourceLineageReceiptVerifier(Protocol):
    def verify_current_lineage(
        self,
        event: AssessmentChangeEvent,
        *,
        packet_sha256: str,
        history_entry_sha256: str,
        checked_at: str,
    ) -> dict[str, object]: ...


class CurrentAuthorityReceiptVerifier(Protocol):
    def verify_current_scope(
        self,
        *,
        tenant_id: str,
        scope_sha256: str,
        purpose: str,
        packet_sha256: str,
        event_sha256: str,
        checked_at: str,
    ) -> dict[str, object]: ...


class CurrentFindingReceiptVerifier(Protocol):
    def verify_current_finding(
        self,
        event: AssessmentChangeEvent,
        finding: FindingSnapshot,
        *,
        packet_sha256: str,
        checked_at: str,
    ) -> dict[str, object]: ...


class CurrentScheduleReceiptVerifier(Protocol):
    def verify_current_schedule(
        self,
        schedule: ScheduleDefinition,
        *,
        packet_sha256: str,
        event_sha256: str,
        checked_at: str,
    ) -> dict[str, object]: ...


def _sha(value: object, label: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        raise ChangeRetestReviewError(f"{label} must be a SHA-256 digest")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or ID_RE.fullmatch(value) is None:
        raise ChangeRetestReviewError(f"{label} is invalid")
    return value


def _timestamp(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ChangeRetestReviewError("trusted clock did not return a UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ChangeRetestReviewError("trusted clock returned an invalid timestamp") from exc
    if parsed.replace(tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ChangeRetestReviewError("trusted clock timestamp is not canonical")
    return value


def _digest(body: dict[str, object]) -> str:
    raw = json.dumps(
        {"domain": DOMAIN, "body": body}, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_event(event: object) -> AssessmentChangeEvent:
    if type(event) is not AssessmentChangeEvent:
        raise ChangeRetestReviewError("typed event is required")
    raw = event.to_dict()
    text_fields = (
        "event_id",
        "source_id",
        "kind",
        "scope_sha256",
        "evidence_sha256",
        "occurred_at",
        "event_sha256",
    )
    if any(type(raw[name]) is not str for name in text_fields):
        raise ChangeRetestReviewError("event fields must be native text")
    if type(raw["change_signal"]) is not bool or type(raw["reason_codes"]) is not list:
        raise ChangeRetestReviewError("event fields are invalid")
    if any(type(reason) is not str for reason in raw["reason_codes"]):
        raise ChangeRetestReviewError("event reason codes must be native text")
    return AssessmentChangeEvent(
        event_id=raw["event_id"],
        source_id=raw["source_id"],
        kind=raw["kind"],
        scope_sha256=raw["scope_sha256"],
        evidence_sha256=raw["evidence_sha256"],
        occurred_at=raw["occurred_at"],
        change_signal=raw["change_signal"],
        reason_codes=tuple(raw["reason_codes"]),
        event_sha256=raw["event_sha256"],
    )


@dataclass(frozen=True, slots=True)
class ChangeRetestReviewPacket:
    packet_id: str
    packet_sha256: str
    request_id: str
    tenant_id: str
    scope_sha256: str
    event_sha256: str
    candidate_sha256: str
    candidate_disposition: str
    history_entry_sha256: str
    history_entry_sequence: int
    source_evidence_sha256: str
    current_authority_sha256: str
    evaluated_at: str
    finding_id: str | None
    finding_snapshot_sha256: str | None
    schedule_id: str | None
    schedule_sha256: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "packet_id": self.packet_id,
            "packet_sha256": self.packet_sha256,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "scope_sha256": self.scope_sha256,
            "event_sha256": self.event_sha256,
            "candidate_sha256": self.candidate_sha256,
            "candidate_disposition": self.candidate_disposition,
            "history_entry_sha256": self.history_entry_sha256,
            "history_entry_sequence": self.history_entry_sequence,
            "source_evidence_sha256": self.source_evidence_sha256,
            "current_authority_sha256": self.current_authority_sha256,
            "evaluated_at": self.evaluated_at,
            "finding_id": self.finding_id,
            "finding_snapshot_sha256": self.finding_snapshot_sha256,
            "schedule_id": self.schedule_id,
            "schedule_sha256": self.schedule_sha256,
            "status": "conditional_human_review_only",
            "qualification_effect": "none",
            "effects": dict(NO_TARGET_EFFECTS),
        }


def stage_change_retest_review(
    *,
    history: OfflineEventAssessmentHistoryStore,
    tenant_id: str,
    event: AssessmentChangeEvent,
    request_id: str,
    clock: TrustedClock,
    source_verifier: CurrentSourceVerifier,
    authority_verifier: CurrentAuthorityVerifier,
    finding: FindingSnapshot | None = None,
    finding_verifier: FindingBindingVerifier | None = None,
    schedule: ScheduleDefinition | None = None,
) -> ChangeRetestReviewPacket:
    """Append a replayable candidate and return a no-effect review packet.

    Verifier ports are deliberately injected and may not be supplied by the
    candidate under review. A production caller must provision independent
    implementations and require fresh verification again before any use.
    """

    if not isinstance(history, OfflineEventAssessmentHistoryStore):
        raise ChangeRetestReviewError("offline history store is required")
    tenant = _identifier(tenant_id, "tenant_id")
    event = _canonical_event(event)
    if event.scope_sha256 != history.scope_sha256:
        raise ChangeRetestReviewError("event and history scopes differ")
    if not event.change_signal:
        raise ChangeRetestReviewError("event has no change signal")
    if (
        clock is source_verifier
        or clock is authority_verifier
        or source_verifier is authority_verifier
    ):
        raise ChangeRetestReviewError("clock, source, and authority ports must be distinct")
    if finding is not None:
        if finding_verifier is None or any(
            finding_verifier is port for port in (source_verifier, authority_verifier, clock)
        ):
            raise ChangeRetestReviewError("independent finding binding verifier is required")
        finding = FindingSnapshot.from_dict(finding.to_dict())
        if finding.state is not FindingState.RETEST_PENDING:
            raise ChangeRetestReviewError("finding must be retest_pending")
    elif finding_verifier is not None:
        raise ChangeRetestReviewError("finding verifier requires a finding")
    if schedule is not None:
        schedule = ScheduleDefinition.from_dict(schedule.to_dict())
        if schedule.tenant_id != tenant or schedule.scope_sha256 != event.scope_sha256:
            raise ChangeRetestReviewError("schedule tenant or scope differs")
    evaluated_at = _timestamp(clock.now_utc())
    source_digest = _sha(source_verifier.verify_event(event, as_of=evaluated_at), "source proof")
    if source_digest != event.evidence_sha256:
        raise ChangeRetestReviewError("source proof does not bind the event evidence")
    authority_digest = _sha(
        authority_verifier.verify_scope(
            tenant_id=tenant,
            scope_sha256=event.scope_sha256,
            purpose="change_assessment_retest_review",
            as_of=evaluated_at,
        ),
        "authority proof",
    )
    if authority_digest == source_digest:
        raise ChangeRetestReviewError("source and authority proof must be distinct")
    if schedule is not None and schedule.authority_evidence_sha256 != authority_digest:
        raise ChangeRetestReviewError("schedule authority is no longer current")
    if (
        finding is not None
        and finding_verifier is not None
        and finding_verifier.verify_finding(
            event=event, finding=finding, as_of=evaluated_at
        ) is not True
    ):
        raise ChangeRetestReviewError("finding does not bind the current event")
    batch = history.append(request_id=request_id, events=(event,), as_of=evaluated_at)
    entry = history.verify_entry(request_id)
    if entry.batch != batch or entry.sequence < 1 or len(batch.candidates) != 1:
        raise ChangeRetestReviewError("durable history did not preserve the exact candidate")
    candidate = batch.candidates[0]
    if (
        candidate.event != event
        or candidate.disposition is not CandidateDisposition.REVIEW_CANDIDATE
    ):
        raise ChangeRetestReviewError("change event was suppressed or deduplicated")
    body: dict[str, object] = {
        "request_id": request_id,
        "tenant_id": tenant,
        "scope_sha256": event.scope_sha256,
        "event_sha256": event.event_sha256,
        "candidate_sha256": candidate.candidate_sha256,
        "candidate_disposition": candidate.disposition.value,
        "history_entry_sha256": entry.entry_sha256,
        "history_entry_sequence": entry.sequence,
        "source_evidence_sha256": source_digest,
        "current_authority_sha256": authority_digest,
        "evaluated_at": evaluated_at,
        "finding_id": None if finding is None else finding.finding_id,
        "finding_snapshot_sha256": None if finding is None else finding.snapshot_sha256,
        "schedule_id": None if schedule is None else schedule.schedule_id,
        "schedule_sha256": None if schedule is None else schedule.schedule_sha256,
        "status": "conditional_human_review_only",
        "qualification_effect": "none",
        "effects": dict(NO_TARGET_EFFECTS),
    }
    digest = _digest(body)
    return ChangeRetestReviewPacket(
        packet_id="CRR-" + digest[7:39].upper(),
        packet_sha256=digest,
        **{
            key: value
            for key, value in body.items()
            if key not in {"status", "qualification_effect", "effects"}
        },
    )


@dataclass(frozen=True, slots=True)
class VerifiedChangeRetestCandidateLink:
    """Historical candidate linkage only, excluding external packet bindings."""

    request_id: str
    scope_sha256: str
    event_sha256: str
    candidate_sha256: str
    history_entry_sha256: str
    history_entry_sequence: int
    current_head_sequence: int
    status: str = "historical_candidate_link_only"
    external_bindings_verified: bool = False


def verify_change_retest_review_history(
    packet: ChangeRetestReviewPacket,
    *,
    history: OfflineEventAssessmentHistoryStore,
) -> VerifiedChangeRetestCandidateLink:
    """Verify only durable event and candidate linkage, not packet authority."""

    if type(packet) is not ChangeRetestReviewPacket:
        raise ChangeRetestReviewError("typed review packet is required")
    if not isinstance(history, OfflineEventAssessmentHistoryStore):
        raise ChangeRetestReviewError("offline history store is required")
    _identifier(packet.tenant_id, "tenant_id")
    if packet.scope_sha256 != history.scope_sha256:
        raise ChangeRetestReviewError("packet and history scopes differ")
    for label in (
        "scope_sha256",
        "event_sha256",
        "candidate_sha256",
        "history_entry_sha256",
        "source_evidence_sha256",
        "current_authority_sha256",
        "packet_sha256",
    ):
        _sha(getattr(packet, label), label)
    if type(packet.history_entry_sequence) is not int or packet.history_entry_sequence < 1:
        raise ChangeRetestReviewError("history entry sequence is invalid")
    _timestamp(packet.evaluated_at)
    if packet.candidate_disposition != CandidateDisposition.REVIEW_CANDIDATE.value:
        raise ChangeRetestReviewError("packet is not a review candidate")
    if (packet.finding_id is None) != (packet.finding_snapshot_sha256 is None):
        raise ChangeRetestReviewError("finding binding is incomplete")
    if packet.finding_id is not None:
        _identifier(packet.finding_id, "finding_id")
        _sha(packet.finding_snapshot_sha256, "finding_snapshot_sha256")
    if (packet.schedule_id is None) != (packet.schedule_sha256 is None):
        raise ChangeRetestReviewError("schedule binding is incomplete")
    if packet.schedule_id is not None:
        _identifier(packet.schedule_id, "schedule_id")
        _sha(packet.schedule_sha256, "schedule_sha256")
    body = {
        key: value
        for key, value in packet.to_dict().items()
        if key not in {"schema_version", "packet_id", "packet_sha256"}
    }
    digest = _digest(body)
    if packet.packet_sha256 != digest or packet.packet_id != "CRR-" + digest[7:39].upper():
        raise ChangeRetestReviewError("packet content address does not match")
    entry = history.verify_entry(packet.request_id)
    if (
        entry.sequence != packet.history_entry_sequence
        or entry.entry_sha256 != packet.history_entry_sha256
        or entry.batch.as_of != packet.evaluated_at
        or len(entry.batch.candidates) != 1
    ):
        raise ChangeRetestReviewError("packet is not bound to the verified history entry")
    candidate = entry.batch.candidates[0]
    if (
        candidate.disposition is not CandidateDisposition.REVIEW_CANDIDATE
        or candidate.candidate_sha256 != packet.candidate_sha256
        or candidate.event.event_sha256 != packet.event_sha256
        or candidate.event.evidence_sha256 != packet.source_evidence_sha256
    ):
        raise ChangeRetestReviewError("packet candidate does not match durable history")
    return VerifiedChangeRetestCandidateLink(
        request_id=entry.request_id,
        scope_sha256=history.scope_sha256,
        event_sha256=candidate.event.event_sha256,
        candidate_sha256=candidate.candidate_sha256,
        history_entry_sha256=entry.entry_sha256,
        history_entry_sequence=entry.sequence,
        current_head_sequence=entry.current_head_sequence,
    )


def _exact_receipt(
    value: object, expected: dict[str, object], label: str
) -> str:
    """Check native, exact receipt fields without treating the issuer as trusted."""

    if (
        type(value) is not dict
        or any(type(key) is not str for key in value)
        or set(value) != set(expected) | {"verifier_id"}
    ):
        raise ChangeRetestReviewError(f"{label} receipt fields are incomplete or unexpected")
    for key, wanted in expected.items():
        actual = value[key]
        if type(actual) is not type(wanted) or actual != wanted:
            raise ChangeRetestReviewError(f"{label} receipt {key} does not match")
    return _identifier(value["verifier_id"], f"{label} verifier_id")


def _receipt_head(value: object, field: str) -> str:
    if type(value) is not dict:
        raise ChangeRetestReviewError(f"{field} receipt is invalid")
    return _sha(value.get(field), field)


def _snapshot_receipt(value: object, label: str) -> dict[str, object]:
    """Freeze a port's native scalar receipt before any later port can mutate it."""
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ChangeRetestReviewError(f"{label} receipt is invalid")
    return dict(value)


def _check_current_originals(
    packet: ChangeRetestReviewPacket,
    *,
    history: OfflineEventAssessmentHistoryStore,
    tenant_id: str,
    event: AssessmentChangeEvent,
    finding: FindingSnapshot | None = None,
    schedule: ScheduleDefinition | None = None,
) -> tuple[
    VerifiedChangeRetestCandidateLink,
    AssessmentChangeEvent,
    str,
    FindingSnapshot | None,
    ScheduleDefinition | None,
]:
    """Replay historical linkage and independently retained originals first."""
    link = verify_change_retest_review_history(packet, history=history)
    original = _canonical_event(event)
    tenant = _identifier(tenant_id, "tenant_id")
    entry = history.verify_entry(packet.request_id)
    if (
        entry.entry_sha256 != link.history_entry_sha256
        or entry.sequence != link.history_entry_sequence
        or len(entry.batch.candidates) != 1
        or entry.batch.candidates[0].candidate_sha256 != link.candidate_sha256
        or entry.batch.candidates[0].event != original
        or original.event_sha256 != packet.event_sha256
        or original.scope_sha256 != packet.scope_sha256
        or original.evidence_sha256 != packet.source_evidence_sha256
        or packet.tenant_id != tenant
        or not original.change_signal
    ):
        raise ChangeRetestReviewError("packet differs from independently supplied originals")
    if (finding is None) != (packet.finding_id is None):
        raise ChangeRetestReviewError("finding original is missing or unexpected")
    if (schedule is None) != (packet.schedule_id is None):
        raise ChangeRetestReviewError("schedule original is missing or unexpected")
    if finding is not None:
        if type(finding) is not FindingSnapshot:
            raise ChangeRetestReviewError("typed finding original is required")
        finding = FindingSnapshot.from_dict(finding.to_dict())
        if (
            finding.finding_id != packet.finding_id
            or finding.snapshot_sha256 != packet.finding_snapshot_sha256
            or finding.state is not FindingState.RETEST_PENDING
        ):
            raise ChangeRetestReviewError("finding original or state differs from packet")
    if schedule is not None:
        if type(schedule) is not ScheduleDefinition:
            raise ChangeRetestReviewError("typed schedule original is required")
        schedule = ScheduleDefinition.from_dict(schedule.to_dict())
        if (
            schedule.schedule_id != packet.schedule_id
            or schedule.schedule_sha256 != packet.schedule_sha256
            or schedule.tenant_id != tenant
            or schedule.scope_sha256 != original.scope_sha256
            or schedule.authority_evidence_sha256 != packet.current_authority_sha256
        ):
            raise ChangeRetestReviewError("schedule original or lineage differs from packet")
    return link, original, tenant, finding, schedule


def _verify_current_with_receipts(
    packet: ChangeRetestReviewPacket,
    *,
    history: OfflineEventAssessmentHistoryStore,
    tenant_id: str,
    event: AssessmentChangeEvent,
    time_verifier: CurrentTimeReceiptVerifier,
    source_verifier: CurrentSourceLineageReceiptVerifier,
    authority_verifier: CurrentAuthorityReceiptVerifier,
    finding: FindingSnapshot | None = None,
    finding_verifier: CurrentFindingReceiptVerifier | None = None,
    schedule: ScheduleDefinition | None = None,
    schedule_verifier: CurrentScheduleReceiptVerifier | None = None,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Return one conditional summary and its exact validated port receipts."""
    link, original, tenant, finding, schedule = _check_current_originals(
        packet, history=history, tenant_id=tenant_id, event=event,
        finding=finding, schedule=schedule,
    )
    if (finding is None) != (finding_verifier is None):
        raise ChangeRetestReviewError("finding and current verifier must be supplied together")
    if (schedule is None) != (schedule_verifier is None):
        raise ChangeRetestReviewError("schedule and current verifier must be supplied together")
    ports = [time_verifier, source_verifier, authority_verifier]
    if finding_verifier is not None:
        ports.append(finding_verifier)
    if schedule_verifier is not None:
        ports.append(schedule_verifier)
    if any(port is None for port in ports) or len({id(port) for port in ports}) != len(ports):
        raise ChangeRetestReviewError("independent currentness verifier ports are required")

    time_receipt = _snapshot_receipt(
        time_verifier.verify_time(
            packet_sha256=packet.packet_sha256,
            event_sha256=original.event_sha256,
            not_before=packet.evaluated_at,
        ),
        "time",
    )
    checked_at = _timestamp(time_receipt.get("checked_at"))
    if checked_at < packet.evaluated_at:
        raise ChangeRetestReviewError("time receipt predates the packet")
    if schedule is not None and (
        checked_at < schedule.starts_at
        or (schedule.ends_at is not None and checked_at >= schedule.ends_at)
    ):
        raise ChangeRetestReviewError("schedule is outside its original time window")
    verifier_ids = [
        _exact_receipt(
            time_receipt,
            {
                "packet_sha256": packet.packet_sha256,
                "event_sha256": original.event_sha256,
                "not_before": packet.evaluated_at,
                "checked_at": checked_at,
                "decision": "trusted_current_instant",
            },
            "time",
        )
    ]
    source_receipt = _snapshot_receipt(
        source_verifier.verify_current_lineage(
            original,
            packet_sha256=packet.packet_sha256,
            history_entry_sha256=link.history_entry_sha256,
            checked_at=checked_at,
        ),
        "source lineage",
    )
    verifier_ids.append(
        _exact_receipt(
            source_receipt,
            {
                "packet_sha256": packet.packet_sha256,
                "event_sha256": original.event_sha256,
                "history_entry_sha256": link.history_entry_sha256,
                "source_id": original.source_id,
                "source_evidence_sha256": original.evidence_sha256,
                "lineage_head_sha256": _receipt_head(
                    source_receipt, "lineage_head_sha256"
                ),
                "checked_at": checked_at,
                "lineage_complete": True,
                "conflict_free": True,
                "not_superseded": True,
            },
            "source lineage",
        )
    )
    authority_receipt = _snapshot_receipt(
        authority_verifier.verify_current_scope(
            tenant_id=tenant,
            scope_sha256=original.scope_sha256,
            purpose="change_assessment_retest_review",
            packet_sha256=packet.packet_sha256,
            event_sha256=original.event_sha256,
            checked_at=checked_at,
        ),
        "authority",
    )
    verifier_ids.append(
        _exact_receipt(
            authority_receipt,
            {
                "packet_sha256": packet.packet_sha256,
                "event_sha256": original.event_sha256,
                "tenant_id": tenant,
                "scope_sha256": original.scope_sha256,
                "purpose": "change_assessment_retest_review",
                "authority_sha256": packet.current_authority_sha256,
                "checked_at": checked_at,
                "current": True,
            },
            "authority",
        )
    )
    finding_receipt = None
    if finding is not None and finding_verifier is not None:
        finding_receipt = _snapshot_receipt(
            finding_verifier.verify_current_finding(
                original, finding, packet_sha256=packet.packet_sha256, checked_at=checked_at
            ),
            "finding",
        )
        verifier_ids.append(
            _exact_receipt(
                finding_receipt,
                {
                    "packet_sha256": packet.packet_sha256,
                    "event_sha256": original.event_sha256,
                    "finding_id": finding.finding_id,
                    "finding_snapshot_sha256": finding.snapshot_sha256,
                    "finding_state": FindingState.RETEST_PENDING.value,
                    "checked_at": checked_at,
                    "current": True,
                },
                "finding",
            )
        )
    schedule_receipt = None
    if schedule is not None and schedule_verifier is not None:
        schedule_receipt = _snapshot_receipt(
            schedule_verifier.verify_current_schedule(
                schedule,
                packet_sha256=packet.packet_sha256,
                event_sha256=original.event_sha256,
                checked_at=checked_at,
            ),
            "schedule",
        )
        verifier_ids.append(
            _exact_receipt(
                schedule_receipt,
                {
                    "packet_sha256": packet.packet_sha256,
                    "event_sha256": original.event_sha256,
                    "schedule_id": schedule.schedule_id,
                    "schedule_sha256": schedule.schedule_sha256,
                    "tenant_id": tenant,
                    "scope_sha256": original.scope_sha256,
                    "authority_sha256": packet.current_authority_sha256,
                    "scheduler_head_sha256": _receipt_head(
                        schedule_receipt, "scheduler_head_sha256"
                    ),
                    "checked_at": checked_at,
                    "current_version": True,
                    "not_cancelled": True,
                },
                "schedule",
            )
        )
    if len(set(verifier_ids)) != len(verifier_ids):
        raise ChangeRetestReviewError("currentness receipt verifier identities must be distinct")
    summary = {
        "packet_sha256": packet.packet_sha256,
        "history_entry_sha256": link.history_entry_sha256,
        "event_sha256": original.event_sha256,
        "checked_at": checked_at,
        "receipt_verifier_ids": tuple(verifier_ids),
        "status": "conditional_revalidation_under_injected_verifiers",
        "currentness_proven": False,
        "external_trust_established": False,
        "positive_use_approved": False,
        "qualification_effect": "none",
        "effects": dict(NO_TARGET_EFFECTS),
    }
    receipts = {
        "time": dict(time_receipt),
        "source_lineage": dict(source_receipt),
        "authority": dict(authority_receipt),
    }
    if finding_receipt is not None:
        receipts["finding"] = dict(finding_receipt)
    if schedule_receipt is not None:
        receipts["schedule"] = dict(schedule_receipt)
    return summary, receipts


def verify_change_retest_review_current(
    packet: ChangeRetestReviewPacket,
    *,
    history: OfflineEventAssessmentHistoryStore,
    tenant_id: str,
    event: AssessmentChangeEvent,
    time_verifier: CurrentTimeReceiptVerifier,
    source_verifier: CurrentSourceLineageReceiptVerifier,
    authority_verifier: CurrentAuthorityReceiptVerifier,
    finding: FindingSnapshot | None = None,
    finding_verifier: CurrentFindingReceiptVerifier | None = None,
    schedule: ScheduleDefinition | None = None,
    schedule_verifier: CurrentScheduleReceiptVerifier | None = None,
) -> dict[str, object]:
    """Conditionally revalidate under injected claims, never live authority."""
    return _verify_current_with_receipts(
        packet, history=history, tenant_id=tenant_id, event=event,
        time_verifier=time_verifier, source_verifier=source_verifier,
        authority_verifier=authority_verifier, finding=finding,
        finding_verifier=finding_verifier, schedule=schedule,
        schedule_verifier=schedule_verifier,
    )[0]
