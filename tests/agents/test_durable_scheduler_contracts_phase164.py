from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path

import jsonschema

import sunderkey
from sunderkey.durable_scheduler_contracts import (
    CancellationRecord,
    CancellationTarget,
    CompletionObservation,
    CompletionResolution,
    CompletionStatus,
    DueOccurrence,
    DurableLease,
    DurableSchedulerContractError,
    MisfirePolicy,
    RecoveryDisposition,
    RecoveryPlan,
    RetryBackoffPlan,
    ScheduleDefinition,
    assert_no_duplicate_active_leases,
    claim_due_occurrence,
    create_cancellation_record,
    create_retry_backoff_plan,
    create_schedule_definition,
    derive_due_occurrences,
    heartbeat_lease,
    observe_completion,
    parse_contract,
    plan_expired_lease_recovery,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "durable-scheduler-contract-v1.schema.json"
MODULE_PATH = ROOT / "src" / "sunderkey" / "durable_scheduler_contracts.py"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


class DurableSchedulerContractsPhase164Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(sunderkey.claim_due_occurrence, claim_due_occurrence)
        self.assertIs(
            sunderkey.create_durable_schedule_definition,
            create_schedule_definition,
        )

    def setUp(self) -> None:
        self.retry = create_retry_backoff_plan(
            max_attempts=4,
            retry_budget_units=30,
            retry_cost_units=10,
            base_delay_seconds=60,
            multiplier=2,
            maximum_delay_seconds=600,
        )
        self.schedule = create_schedule_definition(
            tenant_id="tenant:alpha",
            assessment_template_ref="assessment-template:web-v3",
            scope_sha256=DIGEST_A,
            authority_evidence_sha256=DIGEST_B,
            definition_version=7,
            starts_at="2026-09-20T00:00:00Z",
            ends_at="2026-09-21T00:00:00Z",
            interval_seconds=3600,
            max_occurrences=25,
            max_occurrences_per_evaluation=4,
            concurrency_limit=2,
            lease_duration_seconds=600,
            clock_skew_tolerance_seconds=60,
            misfire_policy=MisfirePolicy.CATCH_UP_BOUNDED,
            max_catch_up_occurrences=2,
            retry_plan=self.retry,
        )
        self.occurrence = derive_due_occurrences(
            self.schedule,
            evaluated_at="2026-09-20T00:00:30Z",
        )[0]
        self.lease = claim_due_occurrence(
            self.schedule,
            self.occurrence,
            worker_ref="worker:alpha",
            attempt_number=1,
            fence_epoch=1,
            expected_occurrence_version=1,
            claimed_at="2026-09-20T00:00:30Z",
            expires_at="2026-09-20T00:10:00Z",
            idempotency_key="idem:claim:alpha:0001",
        )

    def assert_schema_and_round_trip(self, record: object, expected_type: type) -> None:
        raw = record.to_dict()
        jsonschema.validate(raw, self.schema)
        restored = parse_contract(json.loads(json.dumps(raw)))
        self.assertIsInstance(restored, expected_type)
        self.assertEqual(restored.to_dict(), raw)

    def test_retry_and_schedule_are_deterministic_and_strict(self) -> None:
        self.assertEqual(self.retry.delay_for_next_attempt(1), 60)
        self.assertEqual(self.retry.delay_for_next_attempt(3), 240)
        self.assert_schema_and_round_trip(self.retry, RetryBackoffPlan)
        self.assert_schema_and_round_trip(self.schedule, ScheduleDefinition)
        repeated = create_schedule_definition(
            tenant_id="tenant:alpha",
            assessment_template_ref="assessment-template:web-v3",
            scope_sha256=DIGEST_A,
            authority_evidence_sha256=DIGEST_B,
            definition_version=7,
            starts_at="2026-09-20T00:00:00Z",
            ends_at="2026-09-21T00:00:00Z",
            interval_seconds=3600,
            max_occurrences=25,
            max_occurrences_per_evaluation=4,
            concurrency_limit=2,
            lease_duration_seconds=600,
            clock_skew_tolerance_seconds=60,
            misfire_policy="catch_up_bounded",
            max_catch_up_occurrences=2,
            retry_plan=self.retry,
        )
        self.assertEqual(repeated, self.schedule)
        with self.assertRaisesRegex(DurableSchedulerContractError, "retry budget"):
            create_retry_backoff_plan(
                max_attempts=5,
                retry_budget_units=20,
                retry_cost_units=10,
                base_delay_seconds=60,
                multiplier=2,
                maximum_delay_seconds=600,
            )

    def test_due_occurrence_misfire_policies_are_bounded(self) -> None:
        due = derive_due_occurrences(
            self.schedule,
            evaluated_at="2026-09-20T03:00:00Z",
        )
        self.assertEqual([item.occurrence_index for item in due], [1, 2, 3])
        self.assertEqual(
            [item.due_reason.value for item in due],
            ["misfire_catch_up", "misfire_catch_up", "scheduled"],
        )
        self.assertTrue(all(item.tenant_id == self.schedule.tenant_id for item in due))
        self.assert_schema_and_round_trip(due[0], DueOccurrence)

        skipped = create_schedule_definition(
            tenant_id="tenant:alpha",
            assessment_template_ref="assessment-template:web-v3",
            scope_sha256=DIGEST_A,
            authority_evidence_sha256=DIGEST_B,
            definition_version=8,
            starts_at="2026-09-20T00:00:00Z",
            ends_at=None,
            interval_seconds=3600,
            max_occurrences=10,
            max_occurrences_per_evaluation=2,
            concurrency_limit=1,
            lease_duration_seconds=600,
            clock_skew_tolerance_seconds=60,
            misfire_policy=MisfirePolicy.SKIP,
            max_catch_up_occurrences=1,
            retry_plan=self.retry,
        )
        self.assertEqual(
            [
                item.occurrence_index
                for item in derive_due_occurrences(skipped, evaluated_at="2026-09-20T03:00:00Z")
            ],
            [3],
        )
        self.assertEqual(
            derive_due_occurrences(
                self.schedule,
                evaluated_at="2026-09-20T00:00:30Z",
                materialized_occurrence_indices=(0,),
            ),
            (),
        )

    def test_claim_is_fenced_versioned_idempotent_and_exclusive(self) -> None:
        self.assert_schema_and_round_trip(self.lease, DurableLease)
        replay = claim_due_occurrence(
            self.schedule,
            self.occurrence,
            worker_ref="worker:alpha",
            attempt_number=1,
            fence_epoch=1,
            expected_occurrence_version=1,
            claimed_at="2026-09-20T00:00:30Z",
            expires_at="2026-09-20T00:10:00Z",
            idempotency_key="idem:claim:alpha:0001",
            known_leases=(self.lease,),
        )
        self.assertEqual(replay, self.lease)
        with self.assertRaisesRegex(DurableSchedulerContractError, "active lease"):
            claim_due_occurrence(
                self.schedule,
                self.occurrence,
                worker_ref="worker:beta",
                attempt_number=1,
                fence_epoch=2,
                expected_occurrence_version=1,
                claimed_at="2026-09-20T00:01:00Z",
                expires_at="2026-09-20T00:10:30Z",
                idempotency_key="idem:claim:beta:0001",
                known_leases=(self.lease,),
            )
        with self.assertRaisesRegex(DurableSchedulerContractError, "idempotency"):
            claim_due_occurrence(
                self.schedule,
                self.occurrence,
                worker_ref="worker:beta",
                attempt_number=1,
                fence_epoch=2,
                expected_occurrence_version=1,
                claimed_at="2026-09-20T00:01:00Z",
                expires_at="2026-09-20T00:10:30Z",
                idempotency_key="idem:claim:alpha:0001",
                known_leases=(self.lease,),
            )

    def test_schedule_concurrency_is_enforced_across_occurrences(self) -> None:
        occurrences = derive_due_occurrences(
            self.schedule,
            evaluated_at="2026-09-20T03:00:00Z",
        )
        first = claim_due_occurrence(
            self.schedule,
            occurrences[0],
            worker_ref="worker:one",
            attempt_number=1,
            fence_epoch=1,
            expected_occurrence_version=1,
            claimed_at="2026-09-20T03:00:00Z",
            expires_at="2026-09-20T03:10:00Z",
            idempotency_key="idem:claim:concurrency:0001",
        )
        second = claim_due_occurrence(
            self.schedule,
            occurrences[1],
            worker_ref="worker:two",
            attempt_number=1,
            fence_epoch=1,
            expected_occurrence_version=1,
            claimed_at="2026-09-20T03:00:00Z",
            expires_at="2026-09-20T03:10:00Z",
            idempotency_key="idem:claim:concurrency:0002",
            known_leases=(first,),
        )
        with self.assertRaisesRegex(DurableSchedulerContractError, "concurrency"):
            claim_due_occurrence(
                self.schedule,
                occurrences[2],
                worker_ref="worker:three",
                attempt_number=1,
                fence_epoch=1,
                expected_occurrence_version=1,
                claimed_at="2026-09-20T03:00:00Z",
                expires_at="2026-09-20T03:10:00Z",
                idempotency_key="idem:claim:concurrency:0003",
                known_leases=(first, second),
            )

    def test_heartbeat_requires_exact_version_fence_and_bounded_time(self) -> None:
        heartbeat = heartbeat_lease(
            self.schedule,
            self.lease,
            expected_lease_version=1,
            expected_fence_epoch=1,
            observed_at="2026-09-20T00:08:00Z",
            expires_at="2026-09-20T00:18:00Z",
            idempotency_key="idem:heartbeat:alpha:0001",
            known_leases=(self.lease,),
        )
        self.assertEqual(heartbeat.lease_id, self.lease.lease_id)
        self.assertEqual(heartbeat.lease_version, 2)
        self.assertEqual(heartbeat.parent_lease_sha256, self.lease.lease_sha256)
        self.assert_schema_and_round_trip(heartbeat, DurableLease)
        assert_no_duplicate_active_leases((self.lease, heartbeat), as_of="2026-09-20T00:09:00Z")
        with self.assertRaisesRegex(DurableSchedulerContractError, "expected lease version"):
            heartbeat_lease(
                self.schedule,
                self.lease,
                expected_lease_version=2,
                expected_fence_epoch=1,
                observed_at="2026-09-20T00:08:00Z",
                expires_at="2026-09-20T00:18:00Z",
                idempotency_key="idem:heartbeat:alpha:0002",
            )

    def test_completion_plans_retry_and_rejects_duplicate_terminal_use(self) -> None:
        completion = observe_completion(
            self.schedule,
            self.occurrence,
            self.lease,
            expected_lease_version=1,
            expected_fence_epoch=1,
            expected_occurrence_version=1,
            status=CompletionStatus.RETRYABLE_FAILURE,
            observed_at="2026-09-20T00:05:00Z",
            evidence_sha256s=(DIGEST_C,),
            idempotency_key="idem:completion:alpha:0001",
        )
        self.assertEqual(completion.resolution, CompletionResolution.RETRY_PLANNED)
        self.assertEqual(completion.retry_at, "2026-09-20T00:06:00Z")
        self.assertEqual(completion.retry_budget_consumed_units, 10)
        self.assertEqual(completion.new_occurrence_version, 2)
        self.assert_schema_and_round_trip(completion, CompletionObservation)
        replay = observe_completion(
            self.schedule,
            self.occurrence,
            self.lease,
            expected_lease_version=1,
            expected_fence_epoch=1,
            expected_occurrence_version=1,
            status="retryable_failure",
            observed_at="2026-09-20T00:05:00Z",
            evidence_sha256s=(DIGEST_C,),
            idempotency_key="idem:completion:alpha:0001",
            known_observations=(completion,),
        )
        self.assertEqual(replay, completion)
        with self.assertRaisesRegex(DurableSchedulerContractError, "already has"):
            observe_completion(
                self.schedule,
                self.occurrence,
                self.lease,
                expected_lease_version=1,
                expected_fence_epoch=1,
                expected_occurrence_version=1,
                status="succeeded",
                observed_at="2026-09-20T00:05:30Z",
                evidence_sha256s=(DIGEST_C,),
                idempotency_key="idem:completion:alpha:0002",
                known_observations=(completion,),
            )

    def test_final_attempt_and_permanent_failure_dead_letter(self) -> None:
        final_lease = claim_due_occurrence(
            self.schedule,
            self.occurrence,
            worker_ref="worker:alpha",
            attempt_number=4,
            fence_epoch=4,
            expected_occurrence_version=1,
            claimed_at="2026-09-20T00:20:00Z",
            expires_at="2026-09-20T00:30:00Z",
            idempotency_key="idem:claim:alpha:0004",
        )
        final = observe_completion(
            self.schedule,
            self.occurrence,
            final_lease,
            expected_lease_version=1,
            expected_fence_epoch=4,
            expected_occurrence_version=1,
            status="retryable_failure",
            observed_at="2026-09-20T00:25:00Z",
            evidence_sha256s=(),
            idempotency_key="idem:completion:alpha:0004",
        )
        self.assertEqual(final.resolution, CompletionResolution.DEAD_LETTERED)
        self.assertIsNone(final.retry_at)

    def test_expired_lease_recovery_is_replay_safe_and_advances_fence(self) -> None:
        recovery = plan_expired_lease_recovery(
            self.schedule,
            self.occurrence,
            self.lease,
            expected_occurrence_version=1,
            recovered_at="2026-09-20T00:12:00Z",
            idempotency_key="idem:recovery:alpha:0001",
        )
        self.assertEqual(recovery.disposition, RecoveryDisposition.REQUEUE)
        self.assertEqual(recovery.next_attempt_number, 2)
        self.assertEqual(recovery.next_fence_epoch, 2)
        self.assertEqual(recovery.retry_at, "2026-09-20T00:13:00Z")
        self.assert_schema_and_round_trip(recovery, RecoveryPlan)
        replay = plan_expired_lease_recovery(
            self.schedule,
            self.occurrence,
            self.lease,
            expected_occurrence_version=1,
            recovered_at="2026-09-20T00:12:00Z",
            idempotency_key="idem:recovery:alpha:0001",
            known_recoveries=(recovery,),
        )
        self.assertEqual(replay, recovery)
        completion = observe_completion(
            self.schedule,
            self.occurrence,
            self.lease,
            expected_lease_version=1,
            expected_fence_epoch=1,
            expected_occurrence_version=1,
            status="succeeded",
            observed_at="2026-09-20T00:05:00Z",
            evidence_sha256s=(),
            idempotency_key="idem:completion:recovery:0001",
        )
        with self.assertRaisesRegex(DurableSchedulerContractError, "completed lease"):
            plan_expired_lease_recovery(
                self.schedule,
                self.occurrence,
                self.lease,
                expected_occurrence_version=1,
                recovered_at="2026-09-20T00:12:00Z",
                idempotency_key="idem:recovery:alpha:0002",
                known_completions=(completion,),
            )

    def test_cancellation_binds_versions_and_active_lease_revocations(self) -> None:
        cancellation = create_cancellation_record(
            self.schedule,
            target=CancellationTarget.OCCURRENCE,
            occurrence=self.occurrence,
            expected_version=1,
            requested_at="2026-09-20T00:04:00Z",
            reason_code="operator_cancelled",
            active_leases=(self.lease,),
            idempotency_key="idem:cancellation:alpha:0001",
        )
        self.assertEqual(cancellation.revoked_lease_ids, (self.lease.lease_id,))
        self.assertEqual(cancellation.new_version, 2)
        self.assert_schema_and_round_trip(cancellation, CancellationRecord)
        schedule_cancel = create_cancellation_record(
            self.schedule,
            target="schedule",
            expected_version=7,
            requested_at="2026-09-20T00:04:00Z",
            reason_code="scope_revoked",
            active_leases=(self.lease,),
            idempotency_key="idem:cancellation:schedule:0001",
        )
        self.assertIsNone(schedule_cancel.occurrence_id)
        self.assertEqual(schedule_cancel.new_version, 8)
        with self.assertRaisesRegex(DurableSchedulerContractError, "expected schedule version"):
            create_cancellation_record(
                self.schedule,
                target="schedule",
                expected_version=6,
                requested_at="2026-09-20T00:04:00Z",
                reason_code="scope_revoked",
                active_leases=(),
                idempotency_key="idem:cancellation:schedule:0002",
            )

    def test_tamper_extra_fields_and_unknown_record_types_fail_closed(self) -> None:
        for record, field in (
            (self.retry, "retry_plan_sha256"),
            (self.schedule, "schedule_sha256"),
            (self.occurrence, "occurrence_sha256"),
            (self.lease, "lease_sha256"),
        ):
            raw = copy.deepcopy(record.to_dict())
            raw[field] = DIGEST_C
            with self.assertRaises(DurableSchedulerContractError):
                parse_contract(raw)
        raw = self.lease.to_dict()
        raw["unexpected"] = True
        with self.assertRaisesRegex(DurableSchedulerContractError, "fields"):
            parse_contract(raw)
        with self.assertRaisesRegex(DurableSchedulerContractError, "record_type"):
            parse_contract({"record_type": "unknown"})

    def test_module_has_no_runtime_effect_imports_or_clock_reads(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imported.isdisjoint(
                {
                    "asyncio",
                    "multiprocessing",
                    "requests",
                    "socket",
                    "sqlite3",
                    "subprocess",
                    "threading",
                    "time",
                    "urllib",
                }
            )
        )
        self.assertNotIn("datetime.now", source)
        self.assertNotIn("datetime.utcnow", source)


if __name__ == "__main__":
    unittest.main()
