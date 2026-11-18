"""Durable local history for effect-free event assessment planning."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import sunderkey.event_assessment_history as history_module
from sunderkey.event_assessment_history import (
    EventAssessmentHistoryError,
    OfflineEventAssessmentHistoryStore,
)
from sunderkey.event_assessment_planning import CandidateDisposition
from tests.agents.test_event_assessment_planning import AT, SCOPE, event


class EventAssessmentHistoryTests(unittest.TestCase):
    def store(self, directory: str) -> OfflineEventAssessmentHistoryStore:
        return OfflineEventAssessmentHistoryStore(Path(directory) / "history.sqlite3", SCOPE)

    def test_append_restarts_replays_and_deduplicates_reviewed_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            self.assertFalse(store.path.exists())
            with self.assertRaisesRegex(EventAssessmentHistoryError, "missing"):
                store.verify()
            self.assertFalse(store.path.exists())
            store.initialize()
            self.assertEqual(store.verify().head_sequence, 0)

            first = event()
            batch = store.append(request_id="eventreq:first", events=(first,), as_of=AT)
            self.assertEqual(batch.candidates[0].disposition, CandidateDisposition.REVIEW_CANDIDATE)
            database_before_verify = store.path.read_bytes()
            original_head = store.verify()
            self.assertEqual(store.path.read_bytes(), database_before_verify)
            self.assertEqual(original_head.head_sequence, 1)

            restarted = self.store(directory)
            self.assertEqual(
                restarted.append(request_id="eventreq:first", events=(first,), as_of=AT),
                batch,
            )
            self.assertEqual(restarted.verify().head_sha256, original_head.head_sha256)
            duplicate = restarted.append(
                request_id="eventreq:second",
                events=(first,),
                as_of="2026-09-23T13:31:00Z",
            )
            self.assertEqual(duplicate.candidates[0].disposition, CandidateDisposition.DUPLICATE)
            self.assertEqual(restarted.verify().head_sequence, 2)

    def test_stopped_event_is_reconsidered_without_losing_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            first = event()
            stopped = store.append(
                request_id="eventreq:stopped",
                events=(first,),
                as_of=AT,
                intake_stopped=True,
            )
            self.assertEqual(stopped.candidates[0].disposition, CandidateDisposition.STOPPED)
            resumed = store.append(
                request_id="eventreq:resumed",
                events=(first,),
                as_of="2026-09-23T14:30:00Z",
            )
            self.assertEqual(
                resumed.candidates[0].disposition,
                CandidateDisposition.REVIEW_CANDIDATE,
            )
            verified = self.store(directory).verify()
            self.assertEqual(verified.head_sequence, 2)
            self.assertEqual(verified.last_batch, resumed)
            self.assertEqual(len(verified.active_candidates), 2)

    def test_exact_freshness_boundary_keeps_reviewed_event_for_deduplication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            first = event()
            store.append(
                request_id="eventreq:boundary-first",
                events=(first,),
                as_of="2026-09-23T12:10:00Z",
            )
            later = store.append(
                request_id="eventreq:boundary-later",
                events=(first,),
                as_of="2026-09-24T12:10:00Z",
            )
            self.assertEqual(later.candidates[0].disposition, CandidateDisposition.DUPLICATE)

    def test_conflicting_request_scope_and_time_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            first = event()
            store.append(request_id="eventreq:one", events=(first,), as_of=AT)
            with self.assertRaisesRegex(EventAssessmentHistoryError, "conflicts"):
                store.append(
                    request_id="eventreq:one",
                    events=(first,),
                    as_of="2026-09-23T13:31:00Z",
                )
            with self.assertRaisesRegex(EventAssessmentHistoryError, "backward"):
                store.append(
                    request_id="eventreq:early",
                    events=(first,),
                    as_of="2026-09-23T13:00:00Z",
                )
            with self.assertRaisesRegex(EventAssessmentHistoryError, "bounded tuple"):
                store.append(request_id="eventreq:empty", events=(), as_of=AT)
            other_scope = OfflineEventAssessmentHistoryStore(store.path, "sha256:" + "b" * 64)
            with self.assertRaisesRegex(EventAssessmentHistoryError, "scope"):
                other_scope.verify()
            self.assertEqual(store.verify().head_sequence, 1)

    def test_tampered_batch_and_deleted_tail_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            store.append(request_id="eventreq:one", events=(event(),), as_of=AT)
            with closing(sqlite3.connect(store.path)) as connection:
                with connection:
                    connection.execute("UPDATE entries SET batch_json = '{}' WHERE sequence = 1")
            with self.assertRaisesRegex(EventAssessmentHistoryError, "batch"):
                store.verify()

        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            store.append(request_id="eventreq:one", events=(event(),), as_of=AT)
            with closing(sqlite3.connect(store.path)) as connection:
                with connection:
                    connection.execute("DELETE FROM entries WHERE sequence = 1")
            with self.assertRaisesRegex(EventAssessmentHistoryError, "head"):
                store.verify()

    def test_schema_drift_is_not_repaired_by_initialize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            with closing(sqlite3.connect(store.path)) as connection:
                connection.execute("PRAGMA user_version = 2")
            with self.assertRaisesRegex(EventAssessmentHistoryError, "schema version"):
                store.initialize()
            with self.assertRaisesRegex(EventAssessmentHistoryError, "schema version"):
                store.verify()

        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            with closing(sqlite3.connect(store.path)) as connection:
                connection.execute(
                    "CREATE TRIGGER extra_trigger AFTER INSERT ON entries "
                    "BEGIN SELECT 1; END"
                )
            with self.assertRaisesRegex(EventAssessmentHistoryError, "schema is invalid"):
                store.verify()

    def test_same_request_concurrency_has_one_durable_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            first = event()

            def submit():
                return self.store(directory).append(
                    request_id="eventreq:concurrent", events=(first,), as_of=AT
                )

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = tuple(executor.map(lambda _: submit(), range(2)))
            self.assertEqual(results[0], results[1])
            self.assertEqual(store.verify().head_sequence, 1)

    def test_database_size_limit_rolls_back_new_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.initialize()
            limit = store.path.stat().st_size + 4096
            with patch.object(history_module, "MAX_DATABASE_BYTES", limit):
                with self.assertRaisesRegex(EventAssessmentHistoryError, "size limit"):
                    store.append(
                        request_id="eventreq:large",
                        events=(event(),) * 256,
                        as_of=AT,
                    )
            self.assertEqual(store.verify().head_sequence, 0)


if __name__ == "__main__":
    unittest.main()
