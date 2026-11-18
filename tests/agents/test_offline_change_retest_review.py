"""Offline change history to conditional retest review composition tests."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sunderkey import offline_change_retest_review as review_module
from sunderkey.durable_scheduler_contracts import (
    create_retry_backoff_plan,
    create_schedule_definition,
)
from sunderkey.event_assessment_history import OfflineEventAssessmentHistoryStore
from sunderkey.event_assessment_planning import EventKind, _event
from sunderkey.finding_lifecycle import (
    FindingState,
    create_finding,
    transition_finding,
)
from sunderkey.offline_change_retest_review import (
    ChangeRetestReviewError,
    stage_change_retest_review,
    verify_change_retest_review_current,
    verify_change_retest_review_history,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
AUTHORITY = "sha256:" + "c" * 64
LINEAGE_HEAD = "sha256:" + "e" * 64
SCHEDULER_HEAD = "sha256:" + "f" * 64
AS_OF = "2026-09-20T03:00:00Z"
CHECKED_AT = "2026-09-20T03:01:00Z"


class Clock:
    def __init__(self, value: str = AS_OF) -> None:
        self.value = value

    def now_utc(self) -> str:
        return self.value


class Source:
    def __init__(self, digest: str = SOURCE) -> None:
        self.digest = digest
        self.calls = 0

    def verify_event(self, event, *, as_of: str) -> str:
        self.calls += 1
        assert as_of == AS_OF
        return self.digest


class Authority:
    def __init__(self, digest: str = AUTHORITY) -> None:
        self.digest = digest
        self.calls = 0

    def verify_scope(self, *, tenant_id, scope_sha256, purpose, as_of) -> str:
        self.calls += 1
        assert tenant_id == "tenant:one"
        assert scope_sha256 == SCOPE
        assert purpose == "change_assessment_retest_review"
        assert as_of == AS_OF
        return self.digest


class FindingBinding:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.calls = 0

    def verify_finding(self, *, event, finding, as_of) -> bool:
        self.calls += 1
        assert event.scope_sha256 == SCOPE
        assert finding.state is FindingState.RETEST_PENDING
        assert as_of == AS_OF
        return self.result


class EqualText(str):
    def __eq__(self, other):
        return True

    __hash__ = str.__hash__


class TimeReceipt:
    def __init__(self, **changes) -> None:
        self.changes = changes
        self.verifier_id = "verifier:time"
        self.calls = 0

    def verify_time(self, *, packet_sha256, event_sha256, not_before):
        self.calls += 1
        return {
            "packet_sha256": packet_sha256,
            "event_sha256": event_sha256,
            "not_before": not_before,
            "checked_at": CHECKED_AT,
            "decision": "trusted_current_instant",
            "verifier_id": self.verifier_id,
            **self.changes,
        }


class SourceLineageReceipt:
    def __init__(self, **changes) -> None:
        self.changes = changes
        self.verifier_id = "verifier:source"
        self.calls = 0

    def verify_current_lineage(
        self, supplied_event, *, packet_sha256, history_entry_sha256, checked_at
    ):
        self.calls += 1
        return {
            "packet_sha256": packet_sha256,
            "event_sha256": supplied_event.event_sha256,
            "history_entry_sha256": history_entry_sha256,
            "source_id": supplied_event.source_id,
            "source_evidence_sha256": supplied_event.evidence_sha256,
            "lineage_head_sha256": LINEAGE_HEAD,
            "checked_at": checked_at,
            "lineage_complete": True,
            "conflict_free": True,
            "not_superseded": True,
            "verifier_id": self.verifier_id,
            **self.changes,
        }


class AuthorityReceipt:
    def __init__(self, **changes) -> None:
        self.changes = changes
        self.verifier_id = "verifier:authority"
        self.calls = 0

    def verify_current_scope(
        self, *, tenant_id, scope_sha256, purpose, packet_sha256, event_sha256, checked_at
    ):
        self.calls += 1
        return {
            "packet_sha256": packet_sha256,
            "event_sha256": event_sha256,
            "tenant_id": tenant_id,
            "scope_sha256": scope_sha256,
            "purpose": purpose,
            "authority_sha256": AUTHORITY,
            "checked_at": checked_at,
            "current": True,
            "verifier_id": self.verifier_id,
            **self.changes,
        }


class FindingReceipt:
    def __init__(self, **changes) -> None:
        self.changes = changes
        self.verifier_id = "verifier:finding"

    def verify_current_finding(
        self, supplied_event, supplied_finding, *, packet_sha256, checked_at
    ):
        return {
            "packet_sha256": packet_sha256,
            "event_sha256": supplied_event.event_sha256,
            "finding_id": supplied_finding.finding_id,
            "finding_snapshot_sha256": supplied_finding.snapshot_sha256,
            "finding_state": supplied_finding.state.value,
            "checked_at": checked_at,
            "current": True,
            "verifier_id": self.verifier_id,
            **self.changes,
        }


class ScheduleReceipt:
    def __init__(self, **changes) -> None:
        self.changes = changes
        self.verifier_id = "verifier:schedule"

    def verify_current_schedule(
        self, supplied_schedule, *, packet_sha256, event_sha256, checked_at
    ):
        return {
            "packet_sha256": packet_sha256,
            "event_sha256": event_sha256,
            "schedule_id": supplied_schedule.schedule_id,
            "schedule_sha256": supplied_schedule.schedule_sha256,
            "tenant_id": supplied_schedule.tenant_id,
            "scope_sha256": supplied_schedule.scope_sha256,
            "authority_sha256": supplied_schedule.authority_evidence_sha256,
            "scheduler_head_sha256": SCHEDULER_HEAD,
            "checked_at": checked_at,
            "current_version": True,
            "not_cancelled": True,
            "verifier_id": self.verifier_id,
            **self.changes,
        }


def event(*, signal: bool = True, scope: str = SCOPE):
    return _event(
        source_id="release:one",
        kind=EventKind.API_RELEASE_DELTA,
        scope_sha256=scope,
        evidence_sha256=SOURCE,
        occurred_at="2026-09-20T02:00:00Z",
        change_signal=signal,
        reason_codes=("response_changed",) if signal else (),
    )


def finding(*, pending: bool = True):
    current = create_finding(
        {
            "asset": "api.example.test",
            "surface": "account API",
            "vulnerability_class": "CWE-79",
            "root_cause": "missing output encoding",
            "affected_boundary": "GET /account/{id}",
            "semantic_claim": "stored content reaches HTML",
        },
        evidence_digests=(SOURCE,),
        created_at="2026-09-20T00:00:00Z",
        actor_id="reviewer:one",
        authority_ref="authority:one",
        provenance_digests=(SOURCE,),
    )
    states = (
        FindingState.TRIAGED,
        FindingState.VALIDATED,
        FindingState.ACCEPTED,
        FindingState.REMEDIATION_IN_PROGRESS,
    )
    if pending:
        states += (FindingState.RETEST_PENDING,)
    for minute, state in enumerate(states, start=1):
        current = transition_finding(
            current,
            state,
            occurred_at=f"2026-09-20T01:{minute:02d}:00Z",
            actor_id="reviewer:one",
            authority_ref="authority:one",
            provenance_digests=(SOURCE,),
            review_decision="approved",
            reason_code="reviewed_transition",
        )
    return current


def schedule(
    *,
    authority: str = AUTHORITY,
    scope: str = SCOPE,
    starts_at: str = "2026-09-20T00:00:00Z",
    ends_at: str | None = "2026-09-21T00:00:00Z",
):
    retry = create_retry_backoff_plan(
        max_attempts=2,
        retry_budget_units=2,
        retry_cost_units=1,
        base_delay_seconds=60,
        multiplier=2,
        maximum_delay_seconds=120,
    )
    return create_schedule_definition(
        tenant_id="tenant:one",
        assessment_template_ref="template:one",
        scope_sha256=scope,
        authority_evidence_sha256=authority,
        definition_version=1,
        starts_at=starts_at,
        ends_at=ends_at,
        interval_seconds=3600,
        max_occurrences=12,
        max_occurrences_per_evaluation=2,
        concurrency_limit=1,
        lease_duration_seconds=600,
        clock_skew_tolerance_seconds=60,
        misfire_policy="fire_once",
        max_catch_up_occurrences=1,
        retry_plan=retry,
    )


class ChangeRetestReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="change-retest-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "history.sqlite3"
        self.history = OfflineEventAssessmentHistoryStore(self.path, SCOPE)
        self.history.initialize()
        self.source = Source()
        self.authority = Authority()
        self.clock = Clock()

    def stage(self, **changes):
        values = {
            "history": self.history,
            "tenant_id": "tenant:one",
            "event": event(),
            "request_id": "eventreq:change-one",
            "clock": self.clock,
            "source_verifier": self.source,
            "authority_verifier": self.authority,
        }
        values.update(changes)
        return stage_change_retest_review(**values)

    def test_replayable_candidate_and_no_effect_packet(self) -> None:
        binding = FindingBinding()
        packet = self.stage(
            finding=finding(), finding_verifier=binding, schedule=schedule()
        )
        verified = OfflineEventAssessmentHistoryStore(self.path, SCOPE).verify()
        self.assertEqual(verified.head_sequence, 1)
        self.assertEqual(verified.head_sha256, packet.history_entry_sha256)
        self.assertEqual(packet.finding_snapshot_sha256, finding().snapshot_sha256)
        self.assertEqual(packet.schedule_sha256, schedule().schedule_sha256)
        self.assertEqual(packet.candidate_disposition, "review_candidate")
        self.assertEqual(packet.to_dict()["status"], "conditional_human_review_only")
        self.assertEqual(packet.to_dict()["qualification_effect"], "none")
        self.assertTrue(all(effect == "none" for effect in packet.to_dict()["effects"].values()))
        self.assertEqual((self.source.calls, self.authority.calls, binding.calls), (1, 1, 1))
        link = verify_change_retest_review_history(packet, history=self.history)
        self.assertEqual(link.request_id, "eventreq:change-one")
        self.assertEqual(link.history_entry_sequence, 1)
        self.assertEqual(link.status, "historical_candidate_link_only")
        self.assertFalse(link.external_bindings_verified)

    def test_exact_request_replay_does_not_add_history(self) -> None:
        first = self.stage()
        second = self.stage()
        self.assertEqual(second, first)
        self.assertEqual(self.history.verify().head_sequence, 1)

    def test_bad_source_or_authority_is_rejected_before_history_write(self) -> None:
        for key, bad in (
            ("source_verifier", Source(AUTHORITY)),
            ("authority_verifier", Authority(SOURCE)),
        ):
            with self.subTest(key=key), self.assertRaises(ChangeRetestReviewError):
                self.stage(**{key: bad})
        self.assertEqual(self.history.verify().head_sequence, 0)

    def test_no_signal_foreign_scope_and_invalid_time_fail_closed(self) -> None:
        for changes in (
            {"event": event(signal=False)},
            {"event": event(scope="sha256:" + "d" * 64)},
            {"clock": Clock("2026-02-30T03:00:00Z")},
        ):
            with self.subTest(changes=changes), self.assertRaises(ChangeRetestReviewError):
                self.stage(**changes)
        self.assertEqual(self.history.verify().head_sequence, 0)

    def test_finding_and_schedule_bindings_fail_before_history_write(self) -> None:
        for changes in (
            {"finding": finding()},
            {"finding": finding(pending=False), "finding_verifier": FindingBinding()},
            {"finding": finding(), "finding_verifier": FindingBinding(False)},
            {"schedule": schedule(authority="sha256:" + "d" * 64)},
            {"schedule": schedule(scope="sha256:" + "d" * 64)},
        ):
            with self.subTest(changes=changes), self.assertRaises(ChangeRetestReviewError):
                self.stage(**changes)
        self.assertEqual(self.history.verify().head_sequence, 0)

    def test_duplicate_is_durable_but_not_returned_as_review_packet(self) -> None:
        self.stage()
        with self.assertRaisesRegex(ChangeRetestReviewError, "suppressed or deduplicated"):
            self.stage(request_id="eventreq:change-two")
        verified = self.history.verify()
        self.assertEqual(verified.head_sequence, 2)
        self.assertEqual(verified.last_batch.candidates[0].disposition.value, "duplicate")

    def test_same_object_cannot_supply_source_and_authority(self) -> None:
        with self.assertRaisesRegex(ChangeRetestReviewError, "must be distinct"):
            self.stage(authority_verifier=self.source)
        self.assertEqual(self.history.verify().head_sequence, 0)

    def test_non_native_event_field_cannot_mask_foreign_source(self) -> None:
        supplied = event()
        object.__setattr__(supplied, "source_id", EqualText("release:foreign"))
        with self.assertRaisesRegex(ChangeRetestReviewError, "native text"):
            self.stage(event=supplied)
        self.assertEqual((self.source.calls, self.authority.calls), (0, 0))
        self.assertEqual(self.history.verify().head_sequence, 0)

    def test_packet_hash_tamper_fails_but_external_fields_are_not_verified(self) -> None:
        packet = self.stage()
        with self.assertRaisesRegex(ChangeRetestReviewError, "content address"):
            verify_change_retest_review_history(
                replace(packet, current_authority_sha256="sha256:" + "d" * 64),
                history=self.history,
            )
        changed = replace(packet, current_authority_sha256="sha256:" + "d" * 64)
        body = {
            key: value
            for key, value in changed.to_dict().items()
            if key not in {"schema_version", "packet_id", "packet_sha256"}
        }
        digest = review_module._digest(body)
        changed = replace(
            changed,
            packet_id="CRR-" + digest[7:39].upper(),
            packet_sha256=digest,
        )
        link = verify_change_retest_review_history(changed, history=self.history)
        self.assertFalse(link.external_bindings_verified)
        self.assertEqual(link.event_sha256, packet.event_sha256)

    def test_interleaved_append_does_not_strand_replayable_candidate(self) -> None:
        original_append = self.history.append

        def append_with_interleaving(**kwargs):
            batch = original_append(**kwargs)
            original_append(
                request_id="eventreq:interleaved",
                events=(event(),),
                as_of=AS_OF,
            )
            return batch

        self.history.append = append_with_interleaving
        packet = self.stage()
        self.history.append = original_append
        self.assertEqual(packet.history_entry_sequence, 1)
        self.assertEqual(self.history.verify().head_sequence, 2)
        self.assertEqual(self.stage(), packet)
        link = verify_change_retest_review_history(packet, history=self.history)
        self.assertEqual(link.current_head_sequence, 2)
        self.assertFalse(link.external_bindings_verified)

    def test_advanced_history_preserves_old_candidate_link_only(self) -> None:
        packet = self.stage()
        with self.assertRaises(ChangeRetestReviewError):
            self.stage(request_id="eventreq:change-two")
        link = verify_change_retest_review_history(packet, history=self.history)
        self.assertEqual(link.history_entry_sequence, 1)
        self.assertEqual(link.current_head_sequence, 2)


class CurrentChangeRetestReviewTests(unittest.TestCase):
    stage = ChangeRetestReviewTests.stage

    def setUp(self) -> None:
        ChangeRetestReviewTests.setUp(self)
        self.original_event = event()
        self.original_finding = finding()
        self.original_schedule = schedule()
        self.time_port = TimeReceipt()
        self.source_port = SourceLineageReceipt()
        self.authority_port = AuthorityReceipt()
        self.finding_port = FindingReceipt()
        self.schedule_port = ScheduleReceipt()

    def stage_full(self):
        return self.stage(
            event=self.original_event,
            finding=self.original_finding,
            finding_verifier=FindingBinding(),
            schedule=self.original_schedule,
        )

    def current(self, packet, **changes):
        values = {
            "history": self.history,
            "tenant_id": "tenant:one",
            "event": self.original_event,
            "time_verifier": self.time_port,
            "source_verifier": self.source_port,
            "authority_verifier": self.authority_port,
            "finding": self.original_finding,
            "finding_verifier": self.finding_port,
            "schedule": self.original_schedule,
            "schedule_verifier": self.schedule_port,
        }
        values.update(changes)
        return verify_change_retest_review_current(packet, **values)

    @staticmethod
    def readdress(packet, **changes):
        changed = replace(packet, **changes)
        body = {
            key: value
            for key, value in changed.to_dict().items()
            if key not in {"schema_version", "packet_id", "packet_sha256"}
        }
        digest = review_module._digest(body)
        return replace(changed, packet_id="CRR-" + digest[7:39].upper(), packet_sha256=digest)

    def test_full_revalidation_is_conditional_and_does_not_write(self) -> None:
        packet = self.stage_full()
        before = self.path.read_bytes()
        result = self.current(packet)
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(result["status"], "conditional_revalidation_under_injected_verifiers")
        self.assertEqual(result["checked_at"], CHECKED_AT)
        self.assertFalse(result["currentness_proven"])
        self.assertFalse(result["external_trust_established"])
        self.assertFalse(result["positive_use_approved"])
        self.assertTrue(all(value == "none" for value in result["effects"].values()))
        self.assertEqual(self.history.verify().head_sequence, 1)

    def test_recomputed_packet_hash_cannot_rebind_external_fields(self) -> None:
        packet = self.stage_full()
        for changes in (
            {"tenant_id": "tenant:other"},
            {"current_authority_sha256": "sha256:" + "d" * 64},
            {"finding_snapshot_sha256": "sha256:" + "d" * 64},
            {"schedule_sha256": "sha256:" + "d" * 64},
        ):
            forged = self.readdress(packet, **changes)
            verify_change_retest_review_history(forged, history=self.history)
            with self.subTest(changes=changes), self.assertRaises(ChangeRetestReviewError):
                self.current(forged)
        self.assertEqual(self.time_port.calls, 0)

    def test_missing_or_conflicting_source_lineage_fails(self) -> None:
        packet = self.stage_full()
        for changes in (
            {"lineage_complete": False},
            {"conflict_free": False},
            {"not_superseded": False},
            {"source_evidence_sha256": "sha256:" + "d" * 64},
            {"history_entry_sha256": "sha256:" + "d" * 64},
            {"lineage_head_sha256": "sha256:" + "d" * 63},
        ):
            with self.subTest(changes=changes), self.assertRaises(ChangeRetestReviewError):
                self.current(packet, source_verifier=SourceLineageReceipt(**changes))

    def test_rotated_or_stale_authority_fails(self) -> None:
        packet = self.stage_full()
        for changes in (
            {"authority_sha256": "sha256:" + "d" * 64},
            {"current": False},
            {"tenant_id": "tenant:other"},
            {"scope_sha256": "sha256:" + "d" * 64},
        ):
            with self.subTest(changes=changes), self.assertRaises(ChangeRetestReviewError):
                self.current(packet, authority_verifier=AuthorityReceipt(**changes))

    def test_finding_and_schedule_drift_fail(self) -> None:
        packet = self.stage_full()
        for changes in (
            {"finding_snapshot_sha256": "sha256:" + "d" * 64},
            {"finding_state": "accepted"},
            {"current": False},
        ):
            with self.subTest(finding=changes), self.assertRaises(ChangeRetestReviewError):
                self.current(packet, finding_verifier=FindingReceipt(**changes))
        for changes in (
            {"schedule_sha256": "sha256:" + "d" * 64},
            {"scheduler_head_sha256": "sha256:" + "d" * 63},
            {"current_version": False},
            {"not_cancelled": False},
            {"authority_sha256": "sha256:" + "d" * 64},
        ):
            with self.subTest(schedule=changes), self.assertRaises(ChangeRetestReviewError):
                self.current(packet, schedule_verifier=ScheduleReceipt(**changes))

    def test_schedule_must_be_within_original_time_window(self) -> None:
        future_schedule = schedule(starts_at="2026-09-20T04:00:00Z")
        packet = self.stage(
            event=self.original_event,
            finding=self.original_finding,
            finding_verifier=FindingBinding(),
            schedule=future_schedule,
        )
        with self.assertRaisesRegex(ChangeRetestReviewError, "time window"):
            self.current(packet, schedule=future_schedule)
        with self.assertRaisesRegex(ChangeRetestReviewError, "time window"):
            self.current(
                packet,
                schedule=future_schedule,
                time_verifier=TimeReceipt(checked_at="2026-09-21T00:01:00Z"),
            )

    def test_open_ended_schedule_can_be_conditionally_revalidated(self) -> None:
        open_schedule = schedule(ends_at=None)
        packet = self.stage(
            event=self.original_event,
            finding=self.original_finding,
            finding_verifier=FindingBinding(),
            schedule=open_schedule,
        )
        result = self.current(
            packet,
            schedule=open_schedule,
            time_verifier=TimeReceipt(checked_at="2026-09-21T00:01:00Z"),
        )
        self.assertFalse(result["currentness_proven"])

    def test_same_port_or_verifier_identity_fails(self) -> None:
        packet = self.stage_full()
        with self.assertRaisesRegex(ChangeRetestReviewError, "ports are required"):
            self.current(packet, authority_verifier=self.source_port)
        duplicate_id = AuthorityReceipt()
        duplicate_id.verifier_id = self.source_port.verifier_id
        with self.assertRaisesRegex(ChangeRetestReviewError, "identities must be distinct"):
            self.current(packet, authority_verifier=duplicate_id)

    def test_backdated_or_forged_time_fails(self) -> None:
        packet = self.stage_full()
        for changes in (
            {"checked_at": "2026-09-20T02:59:00Z"},
            {"checked_at": "2026-02-30T03:01:00Z"},
            {"packet_sha256": "sha256:" + "d" * 64},
            {"decision": "untrusted"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ChangeRetestReviewError):
                self.current(packet, time_verifier=TimeReceipt(**changes))

    def test_historical_mutation_fails_before_port_use(self) -> None:
        packet = self.stage_full()
        original_verify = self.history.verify_entry
        self.history.verify_entry = lambda request_id: replace(
            original_verify(request_id), entry_sha256="sha256:" + "d" * 64
        )
        with self.assertRaises(ChangeRetestReviewError):
            self.current(packet)
        self.assertEqual(self.time_port.calls, 0)

    def test_originals_and_optional_receipts_are_required_exactly(self) -> None:
        packet = self.stage_full()
        for changes in (
            {"tenant_id": "tenant:other"},
            {"event": event(scope="sha256:" + "d" * 64)},
            {"finding": finding(pending=False)},
            {"finding_verifier": None},
            {"schedule": schedule(scope="sha256:" + "d" * 64)},
            {"schedule_verifier": None},
        ):
            with self.subTest(changes=changes), self.assertRaises(ChangeRetestReviewError):
                self.current(packet, **changes)

    def test_packet_without_optional_origins_requires_no_optional_ports(self) -> None:
        packet = self.stage(event=self.original_event)
        result = self.current(
            packet,
            finding=None,
            finding_verifier=None,
            schedule=None,
            schedule_verifier=None,
        )
        self.assertFalse(result["positive_use_approved"])
        with self.assertRaises(ChangeRetestReviewError):
            self.current(packet)


if __name__ == "__main__":
    unittest.main()
