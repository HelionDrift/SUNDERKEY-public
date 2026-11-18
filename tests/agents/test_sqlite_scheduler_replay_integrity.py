"""Native SQLite scheduler replay controls using synthetic local databases."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from sunderkey.durable_scheduler_contracts import (
    CompletionStatus,
    DurableSchedulerContractError,
    _address_cancellation,
    _address_completion,
    _address_lease,
)
from sunderkey.persistence_scheduler_runtime import (
    SQLITE_MIGRATION_ID,
    SQLITE_MIGRATION_SHA256,
    IdempotencyConflict,
    PersistenceRuntimeError,
    SQLitePersistenceSchedulerRuntime,
)
from tests.agents import test_persistence_scheduler_runtime_phase166 as fixture

LATER = "2026-01-02T12:00:00Z"
KEYS = {
    "claim": "idem:replay:claim-00000001",
    "heartbeat": "idem:replay:heartbeat-001",
    "completion": "idem:replay:completion-01",
    "occurrence": "idem:replay:occurrence-01",
    "schedule": "idem:replay:schedule-0001",
}
RESULT_HASHES = {
    "claim": "sha256:f60972610ce3b0bcc5a0ab83756cbda77e974862776507b49ebe3196d80ebd50",
    "heartbeat": "sha256:c2e114b06ae79d1f58bfdf6abf77cd017293c47f1247fc482b4cf23e51eb7222",
    "completion": "sha256:7bd9911be961ce7390e00e839d4f4557b80188173518388270b0d26ab0210088",
    "occurrence": "sha256:4a0b654cbf2e910af488a95efcea643830b6eb701c185a4bf662b55b0d2d7838",
    "schedule": "sha256:5b1ca0117528a94bb15061fdb4feb4f73870bab7502271bd334e80ac2a91cd82",
}


def _canonical(document) -> str:
    return json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class SQLiteSchedulerReplayIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "runtime.sqlite3"
        self.clock = fixture.FixedClock(datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC))
        self.runtime = SQLitePersistenceSchedulerRuntime(self.path, clock=self.clock)
        self.records, self.arguments = self._flow("tenant-a")

    def _flow(self, tenant: str):
        schedule = self.runtime.register_schedule(fixture._schedule(tenant))
        due = self.runtime.materialize_due(
            tenant, schedule.schedule_id, evaluated_at="2026-01-01T00:03:10Z"
        )
        claim = self.runtime.claim_due(
            tenant,
            schedule.schedule_id,
            worker_ref="worker-1",
            idempotency_key=KEYS["claim"],
            claimed_at="2026-01-01T00:00:10Z",
        )
        assert claim is not None
        heartbeat = self.runtime.heartbeat(
            tenant,
            claim.lease_id,
            expected_lease_version=1,
            expected_fence_epoch=1,
            idempotency_key=KEYS["heartbeat"],
            observed_at="2026-01-01T00:00:20Z",
        )
        completion = self.runtime.complete(
            tenant,
            claim.lease_id,
            expected_lease_version=2,
            expected_fence_epoch=1,
            status=CompletionStatus.SUCCEEDED,
            evidence_sha256s=(fixture.DIGEST_C, fixture.DIGEST_A),
            idempotency_key=KEYS["completion"],
            observed_at="2026-01-01T00:00:25Z",
        )
        occurrence = self.runtime.cancel_occurrence(
            tenant,
            due[1].occurrence_id,
            reason_code="operator_stop",
            idempotency_key=KEYS["occurrence"],
            requested_at="2026-01-01T00:00:30Z",
        )
        cancellation = self.runtime.cancel_schedule(
            tenant,
            schedule.schedule_id,
            reason_code="scope_revoked",
            idempotency_key=KEYS["schedule"],
            requested_at="2026-01-01T00:00:35Z",
        )
        records = {
            "claim": claim,
            "heartbeat": heartbeat,
            "completion": completion,
            "occurrence": occurrence,
            "schedule": cancellation,
        }
        arguments = {
            "claim": {
                "tenant_id": tenant,
                "schedule_id": schedule.schedule_id,
                "worker_ref": "worker-1",
                "idempotency_key": KEYS["claim"],
                "claimed_at": LATER,
            },
            "heartbeat": {
                "tenant_id": tenant,
                "lease_id": claim.lease_id,
                "expected_lease_version": 1,
                "expected_fence_epoch": 1,
                "idempotency_key": KEYS["heartbeat"],
                "observed_at": LATER,
            },
            "completion": {
                "tenant_id": tenant,
                "lease_id": claim.lease_id,
                "expected_lease_version": 2,
                "expected_fence_epoch": 1,
                "status": CompletionStatus.SUCCEEDED,
                "evidence_sha256s": (fixture.DIGEST_C, fixture.DIGEST_A),
                "idempotency_key": KEYS["completion"],
                "observed_at": LATER,
            },
            "occurrence": {
                "tenant_id": tenant,
                "occurrence_id": due[1].occurrence_id,
                "reason_code": "operator_stop",
                "idempotency_key": KEYS["occurrence"],
                "requested_at": LATER,
            },
            "schedule": {
                "tenant_id": tenant,
                "schedule_id": schedule.schedule_id,
                "reason_code": "scope_revoked",
                "idempotency_key": KEYS["schedule"],
                "requested_at": LATER,
            },
        }
        return records, arguments

    def _replay(self, operation: str, *, runtime=None, arguments=None, **changes):
        methods = {
            "claim": "claim_due",
            "heartbeat": "heartbeat",
            "completion": "complete",
            "occurrence": "cancel_occurrence",
            "schedule": "cancel_schedule",
        }
        request = dict((arguments or self.arguments)[operation])
        request.update(changes)
        return getattr(runtime or self.runtime, methods[operation])(**request)

    def _snapshot(self):
        with closing(sqlite3.connect(self.path)) as connection:
            return tuple(connection.iterdump())

    def _reject_unchanged(self, operation: str, *, error=IdempotencyConflict, **changes):
        before = self._snapshot()
        with self.assertRaises(error):
            self._replay(operation, **changes)
        self.assertEqual(self._snapshot(), before)

    def _cached(self, operation: str, tenant: str = "tenant-a"):
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute(
                "SELECT result_json,result_sha256 FROM scheduler_results "
                "WHERE tenant_id=? AND idempotency_key=?",
                (tenant, KEYS[operation]),
            ).fetchone()

    def _replace_cached(self, operation: str, text: str, digest: str | None = None):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                "UPDATE scheduler_results SET result_json=?,result_sha256=? "
                "WHERE tenant_id='tenant-a' AND idempotency_key=?",
                (text, _digest(text) if digest is None else digest, KEYS[operation]),
            )

    def test_original_golden_results_and_migration_identity_are_unchanged(self):
        self.assertEqual(
            self.runtime.migration_identity(), (SQLITE_MIGRATION_ID, SQLITE_MIGRATION_SHA256)
        )
        self.assertEqual(self.records["claim"].lease_id, "DSL-ED944E8CC34D7FA728D3F80771202EBD")
        self.assertEqual(
            self.records["completion"].completion_id,
            "DSC-1EE9A114FBDCC9709CCBF846291F52E2",
        )
        self.assertEqual(
            self.records["occurrence"].cancellation_id,
            "DSX-1C80B9A6362B3DC4158549D1383D5534",
        )
        self.assertEqual(
            self.records["schedule"].cancellation_id,
            "DSX-3AE61264ED3B3BC8A3C88115C9C700FD",
        )
        for operation, digest in RESULT_HASHES.items():
            with self.subTest(operation=operation):
                text, stored = self._cached(operation)
                self.assertEqual(stored, digest)
                self.assertEqual(_digest(text), digest)
                self.assertEqual(text, _canonical(self.records[operation].to_dict()))

    def test_exact_later_retries_reopen_after_terminal_settlement_without_mutation(self):
        reopened = SQLitePersistenceSchedulerRuntime(self.path, clock=self.clock)
        before = self._snapshot()
        with patch.object(self.clock, "now", side_effect=AssertionError("extra clock")):
            for operation, original in self.records.items():
                with self.subTest(operation=operation):
                    self.assertEqual(self._replay(operation, runtime=reopened), original)
        self.assertEqual(self._snapshot(), before)

    def test_completion_enum_string_and_canonical_evidence_order_remain_valid(self):
        before = self._snapshot()
        for status in (CompletionStatus.SUCCEEDED, "succeeded"):
            with self.subTest(status=status):
                self.assertEqual(
                    self._replay(
                        "completion",
                        status=status,
                        evidence_sha256s=[fixture.DIGEST_A, fixture.DIGEST_C],
                    ),
                    self.records["completion"],
                )
        self.assertEqual(self._snapshot(), before)

    def test_claim_changed_schedule_or_worker_rejects_without_mutation(self):
        for change in (
            {"schedule_id": "DSD-" + "A" * 32},
            {"worker_ref": "worker-2"},
        ):
            with self.subTest(change=change):
                self._reject_unchanged("claim", **change)

    def test_heartbeat_changed_lease_version_or_fence_rejects_without_mutation(self):
        for change in (
            {"lease_id": "DSL-" + "A" * 32},
            {"expected_lease_version": 2},
            {"expected_fence_epoch": 2},
        ):
            with self.subTest(change=change):
                self._reject_unchanged("heartbeat", **change)

    def test_completion_changed_immutable_fields_reject_without_mutation(self):
        for change in (
            {"lease_id": "DSL-" + "A" * 32},
            {"expected_lease_version": 3},
            {"expected_fence_epoch": 2},
            {"status": CompletionStatus.RETRYABLE_FAILURE},
            {"evidence_sha256s": (fixture.DIGEST_B,)},
            {"evidence_sha256s": ()},
        ):
            with self.subTest(change=change):
                self._reject_unchanged("completion", **change)

    def test_replayed_version_and_fence_numeric_aliases_reject_without_mutation(self):
        class IntegerAlias(int):
            pass

        for operation in ("heartbeat", "completion"):
            for field in ("expected_lease_version", "expected_fence_epoch"):
                expected = self.arguments[operation][field]
                aliases = (float(expected), IntegerAlias(expected))
                if expected == 1:
                    aliases += (True,)
                for alias in aliases:
                    with self.subTest(operation=operation, field=field, alias=alias):
                        self._reject_unchanged(operation, **{field: alias})

    def test_duplicate_or_invalid_completion_evidence_does_not_replay(self):
        for evidence in (
            (fixture.DIGEST_A, fixture.DIGEST_A, fixture.DIGEST_C),
            ("not-a-digest",),
            fixture.DIGEST_A,
        ):
            with self.subTest(evidence=evidence):
                self._reject_unchanged(
                    "completion",
                    error=(IdempotencyConflict, DurableSchedulerContractError),
                    evidence_sha256s=evidence,
                )

    def test_occurrence_cancellation_changed_target_or_reason_rejects(self):
        for change in (
            {"occurrence_id": "DSO-" + "A" * 32},
            {"reason_code": "different_reason"},
        ):
            with self.subTest(change=change):
                self._reject_unchanged("occurrence", **change)

    def test_schedule_cancellation_changed_target_or_reason_rejects(self):
        for change in (
            {"schedule_id": "DSD-" + "A" * 32},
            {"reason_code": "different_reason"},
        ):
            with self.subTest(change=change):
                self._reject_unchanged("schedule", **change)

    def test_cancellation_key_cannot_switch_operation_target(self):
        for operation, key, reason in (
            ("schedule", KEYS["occurrence"], "operator_stop"),
            ("occurrence", KEYS["schedule"], "scope_revoked"),
        ):
            with self.subTest(operation=operation):
                self._reject_unchanged(operation, idempotency_key=key, reason_code=reason)

    def test_same_key_in_distinct_tenants_remains_independent(self):
        other_records, other_arguments = self._flow("tenant-b")
        before = self._snapshot()
        for operation in KEYS:
            with self.subTest(operation=operation):
                self.assertEqual(self._replay(operation), self.records[operation])
                self.assertEqual(
                    self._replay(operation, arguments=other_arguments),
                    other_records[operation],
                )
        self.assertEqual(self._snapshot(), before)

    def test_readdressed_other_tenant_result_cannot_replace_cached_context(self):
        self._flow("tenant-b")
        for operation in KEYS:
            with self.subTest(operation=operation):
                original = self._cached(operation)
                text, digest = self._cached(operation, "tenant-b")
                self._replace_cached(operation, text, digest)
                self._reject_unchanged(operation)
                self._replace_cached(operation, *original)

    def test_readdressed_cached_idempotency_key_cannot_replace_request_binding(self):
        for operation, record in self.records.items():
            with self.subTest(operation=operation):
                changes = {"idempotency_key": "idem:replay:different-001"}
                if operation in ("claim", "heartbeat"):
                    changed = _address_lease(replace(record, lease_sha256="", **changes))
                elif operation == "completion":
                    changed = _address_completion(
                        replace(record, completion_id="", completion_sha256="", **changes)
                    )
                else:
                    changed = _address_cancellation(
                        replace(record, cancellation_id="", cancellation_sha256="", **changes)
                    )
                self._replace_cached(operation, _canonical(changed.to_dict()))
                self._reject_unchanged(operation)

    def test_cached_result_hash_is_verified_for_every_operation(self):
        for operation in KEYS:
            with self.subTest(operation=operation):
                text, _ = self._cached(operation)
                self._replace_cached(operation, text, fixture.DIGEST_B)
                self._reject_unchanged(operation, error=PersistenceRuntimeError)

    def test_malformed_cached_json_rejects_without_logical_store_mutation(self):
        for operation in KEYS:
            original = self._cached(operation)
            for text in ("not JSON", "[]", "NaN", '{"schema_version":NaN}'):
                with self.subTest(operation=operation, text=text):
                    self._replace_cached(operation, text)
                    self._reject_unchanged(operation, error=PersistenceRuntimeError)
            self._replace_cached(operation, *original)

    def test_cached_blob_or_nontext_digest_cannot_replay(self):
        for operation in KEYS:
            text, digest = self._cached(operation)
            for changed_text, changed_digest in (
                (text.encode("utf-8"), digest),
                (text, digest.encode("ascii")),
            ):
                with self.subTest(operation=operation, blob=type(changed_text) is bytes):
                    self._replace_cached(operation, changed_text, changed_digest)
                    self._reject_unchanged(operation, error=PersistenceRuntimeError)
            self._replace_cached(operation, text, digest)

    def test_changed_cached_json_with_original_hash_rejects_for_every_operation(self):
        for operation in KEYS:
            with self.subTest(operation=operation):
                text, digest = self._cached(operation)
                document = json.loads(text)
                document["schema_version"] = True
                self._replace_cached(operation, _canonical(document), digest)
                self._reject_unchanged(operation, error=PersistenceRuntimeError)

    def test_self_hashed_schema_alias_cannot_normalize_on_replay(self):
        for operation in KEYS:
            original = self._cached(operation)
            for alias in (True, 1.0):
                with self.subTest(operation=operation, alias=alias):
                    document = json.loads(original[0])
                    document["schema_version"] = alias
                    self._replace_cached(operation, _canonical(document))
                    self._reject_unchanged(operation, error=PersistenceRuntimeError)
            self._replace_cached(operation, *original)

    def test_self_hashed_noncanonical_or_duplicate_json_cannot_replay(self):
        for operation in KEYS:
            original = self._cached(operation)
            document = json.loads(original[0])
            variants = (
                json.dumps(document, indent=2),
                original[0][:-1] + ',"schema_version":1}',
            )
            for text in variants:
                with self.subTest(operation=operation, text=text[:30]):
                    self._replace_cached(operation, text)
                    self._reject_unchanged(operation, error=PersistenceRuntimeError)
            self._replace_cached(operation, *original)

    def test_claim_cached_result_cannot_contain_heartbeat_transition(self):
        substituted = _address_lease(
            replace(
                self.records["heartbeat"],
                lease_sha256="",
                idempotency_key=KEYS["claim"],
            )
        )
        self._replace_cached("claim", _canonical(substituted.to_dict()))
        self._reject_unchanged("claim")

    def test_other_result_kind_still_rejects_without_mutation(self):
        for operation in ("claim", "heartbeat", "occurrence", "schedule"):
            with self.subTest(operation=operation):
                self._reject_unchanged(operation, idempotency_key=KEYS["completion"])


if __name__ == "__main__":
    unittest.main()
