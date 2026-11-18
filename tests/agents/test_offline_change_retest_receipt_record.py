"""Historical unsigned receipt custody and fresh conditional replay tests."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from sunderkey import offline_change_retest_receipt_record as records
from sunderkey.event_assessment_history import OfflineEventAssessmentHistoryStore

from . import test_offline_change_retest_review as fixture

LATER = "2026-09-20T03:02:00Z"


class CountingFinding(fixture.FindingReceipt):
    def __init__(self, **changes) -> None:
        super().__init__(**changes)
        self.calls = 0

    def verify_current_finding(self, *args, **kwargs):
        self.calls += 1
        return super().verify_current_finding(*args, **kwargs)


class CountingSchedule(fixture.ScheduleReceipt):
    def __init__(self, **changes) -> None:
        super().__init__(**changes)
        self.calls = 0

    def verify_current_schedule(self, *args, **kwargs):
        self.calls += 1
        return super().verify_current_schedule(*args, **kwargs)


class RetainedTime(fixture.TimeReceipt):
    def verify_time(self, **kwargs):
        self.retained = super().verify_time(**kwargs)
        return self.retained


class MutatingSource(fixture.SourceLineageReceipt):
    def __init__(self, time_port: RetainedTime) -> None:
        super().__init__()
        self.time_port = time_port

    def verify_current_lineage(self, *args, **kwargs):
        self.time_port.retained["decision"] = "later_mutation"
        return super().verify_current_lineage(*args, **kwargs)


class ChangeRetestReceiptRecordTests(unittest.TestCase):
    stage = fixture.ChangeRetestReviewTests.stage

    def setUp(self) -> None:
        fixture.ChangeRetestReviewTests.setUp(self)
        self.original_event = fixture.event()
        self.original_finding = fixture.finding()
        self.original_schedule = fixture.schedule()
        self.time_port = fixture.TimeReceipt()
        self.source_port = fixture.SourceLineageReceipt()
        self.authority_port = fixture.AuthorityReceipt()
        self.finding_port = CountingFinding()
        self.schedule_port = CountingSchedule()
        self.packet = self.stage(
            event=self.original_event,
            finding=self.original_finding,
            finding_verifier=fixture.FindingBinding(),
            schedule=self.original_schedule,
        )

    def sources(self, **changes) -> dict:
        values = {
            "packet": self.packet,
            "history": self.history,
            "tenant_id": "tenant:one",
            "event": self.original_event,
            "finding": self.original_finding,
            "schedule": self.original_schedule,
        }
        values.update(changes)
        return values

    def ports(self, **changes) -> dict:
        values = {
            "time_verifier": self.time_port,
            "source_verifier": self.source_port,
            "authority_verifier": self.authority_port,
            "finding_verifier": self.finding_port,
            "schedule_verifier": self.schedule_port,
        }
        values.update(changes)
        return values

    def capture(self, **changes) -> dict:
        return records.capture_change_retest_receipt_record(
            **self.sources(), **self.ports(**changes)
        )

    @staticmethod
    def readdress(record: dict, **changes) -> dict:
        forged = copy.deepcopy(record)
        forged.update(changes)
        body = {key: value for key, value in forged.items() if key not in {
            "record_id", "record_sha256",
        }}
        digest = records._digest(body)
        forged["record_id"] = "CRV-" + digest[7:39].upper()
        forged["record_sha256"] = digest
        return forged

    def test_capture_calls_each_port_once_and_has_no_store_write(self) -> None:
        before = self.path.read_bytes()
        record = self.capture()
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(
            (
                self.time_port.calls, self.source_port.calls,
                self.authority_port.calls, self.finding_port.calls,
                self.schedule_port.calls,
            ),
            (1, 1, 1, 1, 1),
        )
        self.assertEqual(set(record["receipts"]), {
            "time", "source_lineage", "authority", "finding", "schedule",
        })
        self.assertFalse(record["currentness_proven"])
        self.assertFalse(record["external_trust_established"])
        self.assertFalse(record["positive_use_approved"])
        self.assertTrue(all(value == "none" for value in record["effects"].values()))

    def test_port_retained_receipt_mutation_cannot_change_captured_bytes(self) -> None:
        time_port = RetainedTime()
        record = self.capture(
            time_verifier=time_port,
            source_verifier=MutatingSource(time_port),
        )
        self.assertEqual(time_port.retained["decision"], "later_mutation")
        self.assertEqual(
            record["receipts"]["time"]["decision"], "trusted_current_instant"
        )
        self.assertEqual(
            records.verify_change_retest_receipt_record_history(
                record, **self.sources()
            )["status"],
            "historical_unsigned_receipt_integrity_only",
        )

    def test_historical_replay_does_not_call_external_ports(self) -> None:
        record = self.capture()
        before = (
            self.time_port.calls, self.source_port.calls,
            self.authority_port.calls, self.finding_port.calls, self.schedule_port.calls,
        )
        store_before = self.path.read_bytes()
        result = records.verify_change_retest_receipt_record_history(
            record, **self.sources()
        )
        self.assertEqual(result["status"], "historical_unsigned_receipt_integrity_only")
        self.assertFalse(result["currentness_proven"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(store_before, self.path.read_bytes())
        self.assertEqual(before, (
            self.time_port.calls, self.source_port.calls,
            self.authority_port.calls, self.finding_port.calls, self.schedule_port.calls,
        ))

    def test_fresh_replay_issues_new_later_conditional_record(self) -> None:
        first = self.capture()
        later_time = fixture.TimeReceipt(checked_at=LATER)
        second = records.revalidate_change_retest_receipt_record_current(
            first, **self.sources(), **self.ports(time_verifier=later_time)
        )
        self.assertEqual(later_time.calls, 1)
        self.assertEqual(second["prior_record_sha256"], first["record_sha256"])
        self.assertNotEqual(second["record_sha256"], first["record_sha256"])
        self.assertEqual(second["checked_at"], LATER)
        self.assertFalse(second["positive_use_approved"])
        self.assertEqual(
            records.verify_change_retest_receipt_record_history(second, **self.sources())[
                "status"
            ],
            "historical_unsigned_receipt_integrity_only",
        )

    def test_reused_or_backdated_time_fails_fresh_replay(self) -> None:
        first = self.capture()
        for time_port in (
            fixture.TimeReceipt(),
            fixture.TimeReceipt(checked_at="2026-09-20T03:00:00Z"),
        ):
            with self.subTest(time_port=time_port.changes), self.assertRaises(
                records.ChangeRetestReceiptRecordError
            ):
                records.revalidate_change_retest_receipt_record_current(
                    first, **self.sources(), **self.ports(time_verifier=time_port)
                )

    def test_rotated_or_false_current_sources_fail_fresh_replay(self) -> None:
        first = self.capture()
        for changes in (
            {"source_verifier": fixture.SourceLineageReceipt(not_superseded=False)},
            {"source_verifier": fixture.SourceLineageReceipt(conflict_free=False)},
            {"authority_verifier": fixture.AuthorityReceipt(current=False)},
            {"authority_verifier": fixture.AuthorityReceipt(
                authority_sha256="sha256:" + "d" * 64
            )},
            {"finding_verifier": CountingFinding(current=False)},
            {"schedule_verifier": CountingSchedule(not_cancelled=False)},
        ):
            with self.subTest(changes=changes), self.assertRaises(
                records.ChangeRetestReceiptRecordError
            ):
                records.revalidate_change_retest_receipt_record_current(
                    first, **self.sources(), **self.ports(
                        time_verifier=fixture.TimeReceipt(checked_at=LATER), **changes
                    )
                )

    def test_tamper_and_recomputed_hash_cannot_rebind_originals(self) -> None:
        record = self.capture()
        tampered = copy.deepcopy(record)
        tampered["receipts"]["authority"]["current"] = False
        with self.assertRaises(records.ChangeRetestReceiptRecordError):
            records.verify_change_retest_receipt_record_history(
                tampered, **self.sources()
            )
        for changes in (
            {"tenant_id": "tenant:other"},
            {"positive_use_approved": True},
            {"verifier_ids": ["verifier:time"]},
            {"checked_at": LATER},
        ):
            with self.subTest(changes=changes), self.assertRaises(
                records.ChangeRetestReceiptRecordError
            ):
                records.verify_change_retest_receipt_record_history(
                    self.readdress(record, **changes), **self.sources()
                )
        forged = copy.deepcopy(record)
        forged["receipts"]["source_lineage"]["lineage_complete"] = False
        forged = self.readdress(forged)
        with self.assertRaises(records.ChangeRetestReceiptRecordError):
            records.verify_change_retest_receipt_record_history(forged, **self.sources())

    def test_missing_extra_or_non_native_receipts_fail(self) -> None:
        record = self.capture()
        for changes in (
            {"receipts": {"time": record["receipts"]["time"]}},
            {"receipts": {**record["receipts"], "unexpected": {}}},
            {"schema_version": True},
            {"schema_version": 1 << 100},
        ):
            with self.subTest(changes=changes), self.assertRaises(
                records.ChangeRetestReceiptRecordError
            ):
                records.verify_change_retest_receipt_record_history(
                    self.readdress(record, **changes), **self.sources()
                )

    def test_historical_mutation_fails_before_fresh_port_call(self) -> None:
        record = self.capture()
        original_verify = self.history.verify_entry
        self.history.verify_entry = lambda request_id: replace(
            original_verify(request_id), entry_sha256="sha256:" + "d" * 64
        )
        later_time = fixture.TimeReceipt(checked_at=LATER)
        with self.assertRaises(records.ChangeRetestReceiptRecordError):
            records.revalidate_change_retest_receipt_record_current(
                record, **self.sources(), **self.ports(time_verifier=later_time)
            )
        self.assertEqual(later_time.calls, 0)

    def test_same_port_object_or_identity_fails_capture(self) -> None:
        with self.assertRaises(records.ChangeRetestReceiptRecordError):
            self.capture(authority_verifier=self.source_port)
        duplicate = fixture.AuthorityReceipt()
        duplicate.verifier_id = self.source_port.verifier_id
        with self.assertRaises(records.ChangeRetestReceiptRecordError):
            self.capture(authority_verifier=duplicate)

    def test_optional_receipts_follow_original_packet(self) -> None:
        optional_history = OfflineEventAssessmentHistoryStore(
            self.path.with_name("optional.sqlite3"), fixture.SCOPE
        )
        optional_history.initialize()
        packet = self.stage(
            history=optional_history, event=self.original_event,
            request_id="eventreq:optional",
        )
        values = self.sources(
            history=optional_history, finding=None, schedule=None
        )
        values.pop("packet")
        values.update(self.ports(finding_verifier=None, schedule_verifier=None))
        record = records.capture_change_retest_receipt_record(
            packet, **values
        )
        self.assertEqual(set(record["receipts"]), {
            "time", "source_lineage", "authority",
        })
        self.assertEqual(
            records.verify_change_retest_receipt_record_history(
                record, **self.sources(
                    packet=packet, history=optional_history, finding=None, schedule=None
                )
            )["status"],
            "historical_unsigned_receipt_integrity_only",
        )


if __name__ == "__main__":
    unittest.main()
