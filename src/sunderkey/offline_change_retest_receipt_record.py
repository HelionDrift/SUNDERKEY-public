"""Unsigned local records of conditional change-to-retest verifier receipts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from . import offline_change_retest_review as review
from .durable_scheduler_contracts import ScheduleDefinition
from .event_assessment_history import OfflineEventAssessmentHistoryStore
from .event_assessment_planning import AssessmentChangeEvent
from .finding_lifecycle import FindingSnapshot

DOMAIN = "sunderkey.offline-change-retest-receipt-record.v1"
MAX_RECORD_BYTES = 32768
MAX_RECORD_NODES = 256
MAX_RECORD_DEPTH = 8
_FIELDS = {
    "schema_version", "record_id", "record_sha256", "prior_record_sha256",
    "packet_sha256", "history_entry_sha256", "event_sha256", "tenant_id",
    "scope_sha256", "source_evidence_sha256", "current_authority_sha256",
    "evaluated_at", "checked_at", "finding_id", "finding_snapshot_sha256",
    "schedule_id", "schedule_sha256", "receipts", "verifier_ids", "status",
    "currentness_proven", "external_trust_established", "positive_use_approved",
    "qualification_effect", "effects",
}


class ChangeRetestReceiptRecordError(ValueError):
    """A record, its historical originals, or fresh conditional replay failed."""


def _copy(value: object) -> tuple[dict, str]:
    nodes = 0
    active: set[int] = set()

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_RECORD_NODES or depth > MAX_RECORD_DEPTH:
            raise ChangeRetestReceiptRecordError("receipt record exceeds native bounds")
        if type(item) is dict:
            if id(item) in active:
                raise ChangeRetestReceiptRecordError("cyclic receipt record refused")
            active.add(id(item))
            try:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ChangeRetestReceiptRecordError("native receipt keys required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            finally:
                active.remove(id(item))
        elif type(item) is list:
            if id(item) in active:
                raise ChangeRetestReceiptRecordError("cyclic receipt record refused")
            active.add(id(item))
            try:
                for child in item:
                    visit(child, depth + 1)
            finally:
                active.remove(id(item))
        elif type(item) is str:
            if len(item) > 512 or any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise ChangeRetestReceiptRecordError("receipt string limit exceeded")
        elif type(item) is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise ChangeRetestReceiptRecordError("receipt integer limit exceeded")
        elif type(item) not in {bool, type(None)}:
            raise ChangeRetestReceiptRecordError("unsupported receipt value")

    if type(value) is not dict:
        raise ChangeRetestReceiptRecordError("receipt record must be an object")
    visit(value, 1)
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(text.encode("ascii")) > MAX_RECORD_BYTES:
        raise ChangeRetestReceiptRecordError("receipt record exceeds byte limit")
    return json.loads(text), text


def _digest(body: dict) -> str:
    return "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )).encode("ascii")
    ).hexdigest()


def _record(
    packet: review.ChangeRetestReviewPacket,
    *,
    tenant_id: str,
    summary: dict[str, object],
    receipts: dict[str, dict[str, object]],
    prior_record_sha256: str | None,
) -> dict:
    body = {
        "schema_version": 1,
        "prior_record_sha256": prior_record_sha256,
        "packet_sha256": packet.packet_sha256,
        "history_entry_sha256": summary["history_entry_sha256"],
        "event_sha256": summary["event_sha256"],
        "tenant_id": tenant_id,
        "scope_sha256": packet.scope_sha256,
        "source_evidence_sha256": packet.source_evidence_sha256,
        "current_authority_sha256": packet.current_authority_sha256,
        "evaluated_at": packet.evaluated_at,
        "checked_at": summary["checked_at"],
        "finding_id": packet.finding_id,
        "finding_snapshot_sha256": packet.finding_snapshot_sha256,
        "schedule_id": packet.schedule_id,
        "schedule_sha256": packet.schedule_sha256,
        "receipts": receipts,
        "verifier_ids": list(summary["receipt_verifier_ids"]),
        "status": "conditional_record_under_injected_verifiers",
        "currentness_proven": False,
        "external_trust_established": False,
        "positive_use_approved": False,
        "qualification_effect": "none",
        "effects": dict(review.NO_TARGET_EFFECTS),
    }
    checked, _ = _copy(body)
    digest = _digest(checked)
    return _copy({
        **checked,
        "record_id": "CRV-" + digest[7:39].upper(),
        "record_sha256": digest,
    })[0]


def capture_change_retest_receipt_record(
    packet: review.ChangeRetestReviewPacket,
    *,
    history: OfflineEventAssessmentHistoryStore,
    tenant_id: str,
    event: AssessmentChangeEvent,
    time_verifier: review.CurrentTimeReceiptVerifier,
    source_verifier: review.CurrentSourceLineageReceiptVerifier,
    authority_verifier: review.CurrentAuthorityReceiptVerifier,
    finding: FindingSnapshot | None = None,
    finding_verifier: review.CurrentFindingReceiptVerifier | None = None,
    schedule: ScheduleDefinition | None = None,
    schedule_verifier: review.CurrentScheduleReceiptVerifier | None = None,
) -> dict:
    """Capture each injected port once in a nonauthorizing local record."""
    try:
        summary, receipts = review._verify_current_with_receipts(
            packet, history=history, tenant_id=tenant_id, event=event,
            time_verifier=time_verifier, source_verifier=source_verifier,
            authority_verifier=authority_verifier, finding=finding,
            finding_verifier=finding_verifier, schedule=schedule,
            schedule_verifier=schedule_verifier,
        )
        return _record(
            packet, tenant_id=tenant_id, summary=summary, receipts=receipts,
            prior_record_sha256=None,
        )
    except review.ChangeRetestReviewError as exc:
        raise ChangeRetestReceiptRecordError("conditional receipt capture failed") from exc


class _FrozenReceiptPort:
    """Replay stored bytes for historical structure checks, never fresh trust."""

    def __init__(self, receipt: dict) -> None:
        self.receipt = receipt

    def verify_time(self, **_kwargs: Any) -> dict:
        return dict(self.receipt)

    def verify_current_lineage(self, *_args: Any, **_kwargs: Any) -> dict:
        return dict(self.receipt)

    def verify_current_scope(self, **_kwargs: Any) -> dict:
        return dict(self.receipt)

    def verify_current_finding(self, *_args: Any, **_kwargs: Any) -> dict:
        return dict(self.receipt)

    def verify_current_schedule(self, *_args: Any, **_kwargs: Any) -> dict:
        return dict(self.receipt)


def verify_change_retest_receipt_record_history(
    record: object,
    *,
    packet: review.ChangeRetestReviewPacket,
    history: OfflineEventAssessmentHistoryStore,
    tenant_id: str,
    event: AssessmentChangeEvent,
    finding: FindingSnapshot | None = None,
    schedule: ScheduleDefinition | None = None,
) -> dict:
    """Check unsigned stored bytes and originals without any external port call."""
    checked, _ = _copy(record)
    if set(checked) != _FIELDS:
        raise ChangeRetestReceiptRecordError("receipt record fields are invalid")
    if (
        type(checked["schema_version"]) is not int
        or checked["schema_version"] != 1
        or checked["status"] != "conditional_record_under_injected_verifiers"
        or checked["currentness_proven"] is not False
        or checked["external_trust_established"] is not False
        or checked["positive_use_approved"] is not False
        or checked["qualification_effect"] != "none"
        or checked["effects"] != review.NO_TARGET_EFFECTS
        or type(checked["effects"]) is not dict
    ):
        raise ChangeRetestReceiptRecordError("receipt record effect boundary is invalid")
    prior = checked["prior_record_sha256"]
    if prior is not None:
        try:
            review._sha(prior, "prior_record_sha256")
        except review.ChangeRetestReviewError as exc:
            raise ChangeRetestReceiptRecordError("prior record address is invalid") from exc
    body = {key: value for key, value in checked.items() if key not in {
        "record_id", "record_sha256",
    }}
    digest = _digest(body)
    if (
        checked["record_sha256"] != digest
        or checked["record_id"] != "CRV-" + digest[7:39].upper()
    ):
        raise ChangeRetestReceiptRecordError("receipt record content address differs")
    receipts = checked["receipts"]
    expected_keys = {"time", "source_lineage", "authority"}
    if finding is not None:
        expected_keys.add("finding")
    if schedule is not None:
        expected_keys.add("schedule")
    if type(receipts) is not dict or set(receipts) != expected_keys:
        raise ChangeRetestReceiptRecordError("receipt role set differs from originals")
    if any(type(value) is not dict for value in receipts.values()):
        raise ChangeRetestReceiptRecordError("receipt body must be an object")
    try:
        ports = {key: _FrozenReceiptPort(receipts[key]) for key in expected_keys}
        summary, replayed_receipts = review._verify_current_with_receipts(
            packet, history=history, tenant_id=tenant_id, event=event,
            time_verifier=ports["time"], source_verifier=ports["source_lineage"],
            authority_verifier=ports["authority"], finding=finding,
            finding_verifier=ports.get("finding"), schedule=schedule,
            schedule_verifier=ports.get("schedule"),
        )
    except review.ChangeRetestReviewError as exc:
        raise ChangeRetestReceiptRecordError("stored receipt bindings are invalid") from exc
    if (
        checked["packet_sha256"] != packet.packet_sha256
        or checked["history_entry_sha256"] != summary["history_entry_sha256"]
        or checked["event_sha256"] != summary["event_sha256"]
        or checked["tenant_id"] != tenant_id
        or checked["scope_sha256"] != packet.scope_sha256
        or checked["source_evidence_sha256"] != packet.source_evidence_sha256
        or checked["current_authority_sha256"] != packet.current_authority_sha256
        or checked["evaluated_at"] != packet.evaluated_at
        or checked["checked_at"] != summary["checked_at"]
        or checked["finding_id"] != packet.finding_id
        or checked["finding_snapshot_sha256"] != packet.finding_snapshot_sha256
        or checked["schedule_id"] != packet.schedule_id
        or checked["schedule_sha256"] != packet.schedule_sha256
        or checked["verifier_ids"] != list(summary["receipt_verifier_ids"])
        or replayed_receipts != receipts
    ):
        raise ChangeRetestReceiptRecordError("receipt record differs from original binding")
    return {
        "record_sha256": digest,
        "packet_sha256": packet.packet_sha256,
        "checked_at": checked["checked_at"],
        "status": "historical_unsigned_receipt_integrity_only",
        "currentness_proven": False,
        "external_trust_established": False,
        "positive_use_approved": False,
        "qualification_effect": "none",
        "effects": dict(review.NO_TARGET_EFFECTS),
    }


def revalidate_change_retest_receipt_record_current(
    record: object,
    *,
    packet: review.ChangeRetestReviewPacket,
    history: OfflineEventAssessmentHistoryStore,
    tenant_id: str,
    event: AssessmentChangeEvent,
    time_verifier: review.CurrentTimeReceiptVerifier,
    source_verifier: review.CurrentSourceLineageReceiptVerifier,
    authority_verifier: review.CurrentAuthorityReceiptVerifier,
    finding: FindingSnapshot | None = None,
    finding_verifier: review.CurrentFindingReceiptVerifier | None = None,
    schedule: ScheduleDefinition | None = None,
    schedule_verifier: review.CurrentScheduleReceiptVerifier | None = None,
) -> dict:
    """Replay history, then issue a new later conditional record from fresh ports."""
    historical = verify_change_retest_receipt_record_history(
        record, packet=packet, history=history, tenant_id=tenant_id,
        event=event, finding=finding, schedule=schedule,
    )
    try:
        summary, receipts = review._verify_current_with_receipts(
            packet, history=history, tenant_id=tenant_id, event=event,
            time_verifier=time_verifier, source_verifier=source_verifier,
            authority_verifier=authority_verifier, finding=finding,
            finding_verifier=finding_verifier, schedule=schedule,
            schedule_verifier=schedule_verifier,
        )
    except review.ChangeRetestReviewError as exc:
        raise ChangeRetestReceiptRecordError("fresh conditional replay failed") from exc
    if summary["checked_at"] <= historical["checked_at"]:
        raise ChangeRetestReceiptRecordError("fresh receipt time must advance")
    return _record(
        packet, tenant_id=tenant_id, summary=summary, receipts=receipts,
        prior_record_sha256=historical["record_sha256"],
    )


__all__ = [
    "ChangeRetestReceiptRecordError",
    "capture_change_retest_receipt_record",
    "verify_change_retest_receipt_record_history",
    "revalidate_change_retest_receipt_record_current",
]
