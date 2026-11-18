from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey.authenticated_action_executor as action_execution
import sunderkey.orchestration_journal as orchestration_journal
from sunderkey.orchestration_journal import (
    NO_AUTHORITY_EFFECTS,
    DeliveryOutcome,
    JobKind,
    JobOutcomeCode,
    JobState,
    MessageDirection,
    MessageTopic,
    OrchestrationConflictError,
    OrchestrationIntegrityError,
    OrchestrationValidationError,
    ProjectionKind,
    SagaKind,
    SagaStepState,
    SourceHighWater,
    SourceKind,
    SQLiteOrchestrationJournal,
    action_execution_reconciliation_lineage_sha256,
    authentication_context_sha256,
    build_action_execution_intent,
    build_delivery_attempt,
    build_orchestration_job,
    build_orchestration_message,
    build_read_model_projection,
    build_saga_step,
    canonical_sha256,
    source_bindings_sha256,
)

T0 = "2026-09-20T12:00:00Z"
T1 = "2026-09-20T12:00:10Z"
T2 = "2026-09-20T12:01:01Z"
T3 = "2026-09-20T12:01:10Z"


def digest(label: str) -> str:
    return canonical_sha256({"label": label})


class Phase197JournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "orchestration.sqlite3"
        self._trusted_time = T0
        self._phase196_terminals: dict[str, object] = {}
        self.store = SQLiteOrchestrationJournal(
            self.path,
            trusted_clock=lambda: datetime.strptime(
                self._trusted_time, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=UTC),
            phase196_terminal_resolver=self._phase196_terminals.get,
        )
        self.source = SourceHighWater(
            SourceKind.MISSION_STORE,
            "mission:alpha",
            1,
            digest("mission-head-1"),
            T0,
        )

    def at(self, value: str) -> str:
        self._trusted_time = value
        return value

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def job(self, *, key: str = "job-1", input_label: str = "input-1"):
        return build_orchestration_job(
            tenant_id="tenant-a",
            job_kind=JobKind.SOURCE_RECONCILIATION,
            subject_ref="mission:alpha",
            input_ref="snapshot:alpha",
            input_sha256=digest(input_label),
            source_bindings=(self.source,),
            idempotency_key_sha256=digest(key),
            created_at=T0,
            available_at=T0,
            maximum_attempts=3,
            lease_seconds=60,
        )

    def intent(
        self,
        *,
        key: str = "handoff-1",
        available_at: str = T0,
        authorization_expires_at: str = "2026-09-20T12:10:00Z",
    ):
        request_id = "AXR-" + digest(f"request-id-{key}")[7:39].upper()
        return build_action_execution_intent(
            tenant_id="tenant-a",
            mission_id="mission:alpha",
            action_execution_envelope_ref=f"action-execution-request:{request_id}",
            action_execution_envelope_sha256=digest(f"envelope-{key}"),
            command_sha256=digest(f"command-{key}"),
            action_execution_request_id=request_id,
            action_execution_request_sha256=digest(f"request-{key}"),
            receipt_id="AARX-" + digest(f"receipt-id-{key}")[7:39].upper(),
            receipt_sha256=digest(f"receipt-{key}"),
            action_execute_intent_sha256=digest(f"execute-intent-{key}"),
            assertion_id=f"assertion:{key}",
            assertion_sha256=digest(f"assertion-{key}"),
            authorization_sha256=digest(f"authorization-{key}"),
            authorization_expires_at=authorization_expires_at,
            source_bindings_sha256=source_bindings_sha256((self.source,)),
            source_bindings=(self.source,),
            available_at=available_at,
            requested_at=T0,
            idempotency_key_sha256=digest(key),
            requested_by_subject_id="operator:alpha",
            authentication_context_sha256=authentication_context_sha256(
                tenant_id="tenant-a",
                subject_id="operator:alpha",
                authentication_ref="authentication:alpha",
            ),
        )

    @staticmethod
    def worker() -> dict[str, str]:
        return {
            "worker_id": "worker:alpha",
            "worker_assertion_id": "assertion:worker",
            "worker_assertion_sha256": digest("worker-assertion"),
            "worker_trust_policy_id": "trust:worker",
            "worker_trust_policy_sha256": digest("worker-trust"),
            "worker_scope_id": "scope:worker",
            "worker_scope_sha256": digest("worker-scope"),
            "worker_session_id": "session:worker",
            "worker_session_sha256": digest("worker-session"),
            "worker_lease_id": "lease:worker",
            "worker_lease_sha256": digest("worker-lease"),
            "worker_capability_id": "capability:worker",
            "worker_capability_sha256": digest("worker-capability"),
        }

    @staticmethod
    def outbox_worker() -> dict[str, str]:
        return {
            "worker_id": "worker:outbox",
            "worker_assertion_id": "assertion:outbox",
            "worker_assertion_sha256": digest("outbox-assertion"),
            "worker_session_id": "session:outbox",
            "worker_session_sha256": digest("outbox-session"),
            "worker_capability_id": "capability:outbox",
            "worker_capability_sha256": digest("outbox-capability"),
        }

    @staticmethod
    def reconciler(attempt) -> dict[str, str]:
        return {
            "reconciler_subject_id": "subject:reconciler",
            "reconciler_assertion_id": "assertion:reconciler",
            "reconciler_assertion_sha256": digest("reconciler-assertion"),
            "reconciler_trust_policy_id": "trust:reconciler",
            "reconciler_trust_policy_sha256": digest("reconciler-trust"),
            "reconciler_scope_id": "scope:reconciler",
            "reconciler_scope_sha256": digest("reconciler-scope"),
            "reconciler_session_id": "session:reconciler",
            "reconciler_session_sha256": digest("reconciler-session"),
            "reconciler_capability_id": "capability:reconciler",
            "reconciler_capability_sha256": digest("reconciler-capability"),
            "reconciliation_lineage_sha256": (
                action_execution_reconciliation_lineage_sha256(attempt)
            ),
            "authority_issued_at": T2,
            "authority_expires_at": "2026-09-20T12:10:00Z",
        }

    @staticmethod
    def phase196_terminal(attempt, *, settled_at: str = T1):
        resources = {
            "money_microunits": 1,
            "rate_units": 1,
            "request_bytes": 1,
            "response_bytes": 1,
            "duration_ms": 1,
            "impact_events": 1,
        }
        result_document = {
            "request_id": attempt.action_execution_request_id,
            "request_sha256": attempt.action_execution_request_sha256,
            "action_sha256": digest("terminal-action"),
            "adapter": {
                "adapter_id": "adapter:test",
                "adapter_kind": "http",
                "adapter_version": "v01",
                "adapter_build_sha256": digest("adapter-build"),
                "deployment_binding_sha256": digest("adapter-deployment"),
            },
            "outcome": "succeeded",
            "evidence_status": "complete",
            "cleanup_status": "complete",
            "restoration_status": "complete",
            "result_payload": {"provider_reference": "provider:result"},
            "resources_used": resources,
        }
        body = {
            "schema_version": 1,
            "kind": "action_execution_terminal",
            "request_id": attempt.action_execution_request_id,
            "request_sha256": attempt.action_execution_request_sha256,
            "claim_id": "AXC-" + digest("phase196-claim")[7:39].upper(),
            "claim_sha256": digest("phase196-claim"),
            "terminal_status": "completed",
            "action_outcome": "succeeded",
            "evidence_status": "complete",
            "cleanup_status": "complete",
            "restoration_status": "complete",
            "result_sha256": action_execution._canonical_sha256(
                {
                    "domain": action_execution.RESULT_DOMAIN,
                    "result": result_document,
                }
            ),
            "result_document": result_document,
            "charged_resources": resources,
            "reason_code": "adapter_reported_succeeded",
            "settled_at": settled_at,
            "adapter_call_count": 1,
            "adapter_call_count_status": "exactly_one",
            "automatic_retry_count": 0,
        }
        return action_execution.parse_action_execution_terminal(
            action_execution._record(
                "action_execution_terminal",
                "AXT",
                action_execution.TERMINAL_DOMAIN,
                body,
            )
        )

    def test_job_exact_replay_and_conflicting_replay(self) -> None:
        job = self.job()
        first = self.store.submit_job(job)
        replay = self.store.submit_job(job)
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record, job)
        with self.assertRaises(OrchestrationConflictError):
            self.store.submit_job(self.job(input_label="changed"))
        view = self.store.get_job("tenant-a", job.job_id)
        self.assertIsNotNone(view)
        assert view is not None
        self.assertEqual(view.state, JobState.AVAILABLE)
        self.assertEqual(view.to_dict()["authority_status"], "not_authoritative")

    def test_concurrent_claim_has_one_winner(self) -> None:
        self.store.submit_job(self.job())

        def claim(worker: str):
            return self.store.claim_next_job("tenant-a", worker, now=T0)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(claim, [f"worker-{index}" for index in range(8)]))
        claims = [result for result in results if result is not None]
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0].fence_token, 1)
        self.assertEqual(claims[0].attempt_number, 1)
        self.assertEqual(self.store.verify()["status"], "valid")

    def test_expired_claim_is_fenced_and_recovered(self) -> None:
        job = self.job()
        self.store.submit_job(job)
        first = self.store.claim_next_job("tenant-a", "worker-a", now=T0)
        self.assertIsNotNone(first)
        assert first is not None
        second = self.store.claim_next_job("tenant-a", "worker-b", now=self.at(T2))
        self.assertIsNotNone(second)
        assert second is not None
        self.assertEqual(second.fence_token, 2)
        self.assertEqual(second.attempt_number, 2)
        with self.assertRaises(OrchestrationConflictError):
            self.store.record_job_outcome(
                first,
                outcome_code=JobOutcomeCode.HANDLED_OBSERVATION,
                result_ref="result:stale",
                result_sha256=digest("stale"),
                observed_at=self.at(T1),
            )
        outcome = self.store.record_job_outcome(
            second,
            outcome_code=JobOutcomeCode.HANDLED_OBSERVATION,
            result_ref="result:current",
            result_sha256=digest("current"),
            observed_at=self.at(T3),
        )
        self.assertFalse(outcome.replayed)
        view = self.store.get_job("tenant-a", job.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.WORKER_REPORTED)
        self.assertEqual(view.outcome, outcome.record)

    def test_exhausted_expired_lease_is_durably_dead_lettered(self) -> None:
        job = build_orchestration_job(
            tenant_id="tenant-a",
            job_kind=JobKind.SOURCE_RECONCILIATION,
            subject_ref="mission:alpha",
            input_ref="snapshot:alpha",
            input_sha256=digest("exhausted-input"),
            source_bindings=(self.source,),
            idempotency_key_sha256=digest("exhausted-job"),
            created_at=T0,
            available_at=T0,
            maximum_attempts=1,
            lease_seconds=60,
        )
        self.store.submit_job(job)
        claim = self.store.claim_next_job("tenant-a", "worker-a", now=T0)
        assert claim is not None
        recovered = self.store.recover_expired_jobs("tenant-a", now=self.at(T2))
        self.assertEqual(len(recovered), 1)
        self.assertEqual(
            recovered[0].outcome_code,
            JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION,
        )
        self.assertEqual(self.store.recover_expired_jobs("tenant-a", now=self.at(T3)), ())
        view = self.store.get_job("tenant-a", job.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.DEAD_LETTERED)
        self.assertEqual(view.outcome, recovered[0])
        with self.assertRaises(OrchestrationValidationError):
            self.store.record_job_outcome(
                claim,
                outcome_code=JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION,
                result_ref="lease-expiration:forged",
                result_sha256=digest("forged"),
                observed_at=T1,
            )
        self.assertEqual(SQLiteOrchestrationJournal(self.path).verify()["status"], "valid")

    def test_possible_external_effect_is_not_reclaimed_after_lease_expiration(self) -> None:
        message = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.OUTBOX,
            topic=MessageTopic.PROJECTION_CHANGE,
            external_ref="message:external-effect",
            external_sha256=digest("external-effect-input"),
            source_bindings=(self.source,),
            correlation_ref="correlation:external-effect",
            idempotency_key_sha256=digest("external-effect-message"),
            recorded_at=T0,
        )
        self.store.record_message(message)
        job = build_orchestration_job(
            tenant_id="tenant-a",
            job_kind=JobKind.OUTBOX_DELIVERY,
            subject_ref=message.message_id,
            input_ref=message.external_ref,
            input_sha256=message.external_sha256,
            source_bindings=(self.source,),
            idempotency_key_sha256=digest("external-effect-job"),
            created_at=T0,
            available_at=T0,
            maximum_attempts=1,
            lease_seconds=60,
        )
        self.store.submit_job(job)
        self.assertIsNone(self.store.claim_next_job("tenant-a", "worker-a", now=T0))
        custody = self.store.claim_outbox_delivery(
            "tenant-a", **self.outbox_worker()
        )
        assert custody is not None
        self.at(T2)
        self.assertIsNone(
            self.store.claim_outbox_delivery("tenant-a", **self.outbox_worker())
        )
        recovered = self.store.recover_expired_jobs("tenant-a", now=T2)
        self.assertEqual(recovered, ())
        expired_observation = build_delivery_attempt(
            tenant_id="tenant-a",
            message_id=message.message_id,
            message_sha256=message.message_sha256,
            job_id=job.job_id,
            claim_id=custody.claim_id,
            claim_sha256=custody.claim_sha256,
            fence_token=1,
            attempt_number=1,
            outcome=DeliveryOutcome.PERMANENT_FAILURE_OBSERVATION,
            remote_receipt_ref=None,
            remote_receipt_sha256=None,
            observed_at=T1,
        )
        with self.assertRaises(OrchestrationConflictError):
            self.store.record_outbox_delivery_observation(
                custody, expired_observation
            )
        view = self.store.get_job("tenant-a", job.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.LEASED)
        self.assertEqual(view.attempt_number, 1)
        self.assertEqual(SQLiteOrchestrationJournal(self.path).verify()["status"], "valid")

    def test_renewal_rejects_old_lease_version(self) -> None:
        self.store.submit_job(self.job())
        claim = self.store.claim_next_job("tenant-a", "worker-a", now=T0)
        assert claim is not None
        renewed = self.store.renew_claim(claim, now=self.at(T1))
        self.assertEqual(renewed.fence_token, claim.fence_token)
        self.assertEqual(renewed.lease_version, 2)
        with self.assertRaises(OrchestrationConflictError):
            self.store.renew_claim(claim, now=self.at(T1))

    def test_trusted_clock_prevents_future_capture_and_backdated_lease_use(self) -> None:
        self.store.submit_job(self.job(key="trusted-clock"))
        claim = self.store.claim_next_job("tenant-a", "worker-a", now=T3)
        assert claim is not None
        self.assertEqual(claim.claimed_at, T0)
        self._trusted_time = T2
        with self.assertRaises(OrchestrationConflictError):
            self.store.renew_claim(claim, now=T0)
        with self.assertRaises(OrchestrationConflictError):
            self.store.record_job_outcome(
                claim,
                outcome_code=JobOutcomeCode.HANDLED_OBSERVATION,
                result_ref="observation:backdated",
                result_sha256=digest("backdated"),
                observed_at=T1,
            )

    def test_retry_observation_requeues_without_claiming_authoritative_completion(self) -> None:
        job = self.job()
        self.store.submit_job(job)
        claim = self.store.claim_next_job("tenant-a", "worker-a", now=T0)
        assert claim is not None
        result = self.store.record_job_outcome(
            claim,
            outcome_code=JobOutcomeCode.RETRYABLE_FAILURE_OBSERVATION,
            result_ref="observation:retry",
            result_sha256=digest("retry"),
            observed_at=self.at(T1),
            retry_available_at=T2,
        )
        replay = self.store.record_job_outcome(
            claim,
            outcome_code=JobOutcomeCode.RETRYABLE_FAILURE_OBSERVATION,
            result_ref="observation:retry",
            result_sha256=digest("retry"),
            observed_at=self.at(T1),
            retry_available_at=T2,
        )
        self.assertFalse(result.replayed)
        self.assertTrue(replay.replayed)
        view = self.store.get_job("tenant-a", job.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.AVAILABLE)
        self.assertEqual(view.to_dict()["authority_status"], "not_authoritative")
        second = self.store.claim_next_job("tenant-a", "worker-b", now=self.at(T2))
        self.assertIsNotNone(second)
        assert second is not None
        self.assertEqual((second.attempt_number, second.fence_token), (2, 2))
        self.assertEqual(self.store.verify()["status"], "valid")

    def test_action_execution_handoff_is_atomic_content_addressed_and_replay_safe(self) -> None:
        intent = self.intent()
        first = self.store.enqueue_action_execution_handoff(intent)
        replay = self.store.enqueue_action_execution_handoff(intent)
        self.assertEqual(tuple(item.replayed for item in first), (False, False, False))
        self.assertEqual(tuple(item.replayed for item in replay), (True, True, True))
        message, job, stored_intent = (item.record for item in first)
        self.assertEqual(job.input_ref, stored_intent.intent_id)
        self.assertEqual(job.input_sha256, stored_intent.intent_sha256)
        self.assertEqual(message.external_sha256, intent.action_execution_envelope_sha256)
        self.assertEqual(job.maximum_attempts, 1)
        self.assertEqual(self.store.verify()["status"], "valid")

    def test_verifier_rejects_forged_action_handoff_lease(self) -> None:
        intent = self.intent(key="forged-action-lease")
        message = build_orchestration_message(
            tenant_id=intent.tenant_id,
            direction=MessageDirection.OUTBOX,
            topic=MessageTopic.ACTION_EXECUTION_HANDOFF,
            external_ref=intent.action_execution_envelope_ref,
            external_sha256=intent.action_execution_envelope_sha256,
            source_bindings=intent.source_bindings,
            correlation_ref=intent.action_execution_request_id,
            idempotency_key_sha256=intent.idempotency_key_sha256,
            recorded_at=T0,
        )
        job = build_orchestration_job(
            tenant_id=intent.tenant_id,
            job_kind=JobKind.ACTION_EXECUTION_HANDOFF,
            subject_ref=message.message_id,
            input_ref=intent.intent_id,
            input_sha256=intent.intent_sha256,
            source_bindings=intent.source_bindings,
            idempotency_key_sha256=intent.idempotency_key_sha256,
            created_at=T0,
            available_at=T0,
            maximum_attempts=1,
            lease_seconds=5,
        )
        with self.store._write() as connection:
            connection.execute(
                "INSERT INTO action_execution_intents "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    intent.intent_id,
                    intent.intent_sha256,
                    intent.tenant_id,
                    intent.mission_id,
                    intent.action_execution_request_id,
                    intent.action_execution_request_sha256,
                    intent.action_execution_envelope_ref,
                    intent.action_execution_envelope_sha256,
                    intent.idempotency_key_sha256,
                    intent.authorization_expires_at,
                    intent.source_bindings_sha256,
                    intent.requested_at,
                    intent.requested_by_subject_id,
                    intent.authentication_context_sha256,
                    orchestration_journal.canonical_json(intent.to_dict()),
                ),
            )
            self.store._append_event(
                connection,
                intent.tenant_id,
                "action_execution",
                intent.intent_id,
                "action_execution.intent_recorded",
                intent.intent_id,
                intent.intent_sha256,
                intent.requested_at,
            )
            self.store._record_message(connection, message)
            self.store._insert_job(connection, job)
            self.store._append_event(
                connection,
                job.tenant_id,
                "job",
                job.job_id,
                "job.submitted",
                job.job_id,
                job.job_sha256,
                job.created_at,
            )
        with self.assertRaisesRegex(
            OrchestrationIntegrityError,
            "action execution handoff binding is invalid",
        ):
            self.store.verify()

    def test_reserved_handoff_generic_paths_are_closed(self) -> None:
        intent = self.intent()
        message_result, job_result, _ = self.store.enqueue_action_execution_handoff(intent)
        with self.assertRaises(OrchestrationValidationError):
            self.store.record_message(message_result.record)
        with self.assertRaises(OrchestrationValidationError):
            self.store.submit_job(job_result.record)
        self.assertIsNone(self.store.claim_next_job("tenant-a", "worker:generic", now=T0))

    def test_signed_availability_and_ineligible_window_quarantine(self) -> None:
        delayed = self.intent(key="delayed", available_at=T2)
        self.store.enqueue_action_execution_handoff(delayed)
        self._trusted_time = T1
        self.assertIsNone(
            self.store.claim_action_execution_handoff("tenant-a", **self.worker())
        )
        self._trusted_time = T2
        attempt = self.store.claim_action_execution_handoff("tenant-a", **self.worker())
        self.assertIsNotNone(attempt)
        self.assertEqual(self.store.verify()["status"], "valid")

        other_path = Path(self.temporary.name) / "quarantine.sqlite3"
        self._trusted_time = T0
        other = SQLiteOrchestrationJournal(
            other_path,
            trusted_clock=lambda: datetime.strptime(
                self._trusted_time, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=UTC),
        )
        expiring = self.intent(
            key="expiring",
            authorization_expires_at=T2,
        )
        other.enqueue_action_execution_handoff(expiring)
        self._trusted_time = T2
        self.assertIsNone(other.claim_action_execution_handoff("tenant-a", **self.worker()))
        view = other.get_job("tenant-a", other.list_jobs("tenant-a")[0].job.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.DEAD_LETTERED)
        self.assertEqual(other.verify()["counts"]["action_execution_attempts"], 0)

    def test_action_claim_pages_past_more_than_two_hundred_quarantines(self) -> None:
        for index in range(201):
            self.store.enqueue_action_execution_handoff(
                self.intent(
                    key=f"starvation-{index:03d}",
                    authorization_expires_at=T2,
                )
            )
        eligible = self.intent(key="starvation-eligible", available_at=T1)
        self.store.enqueue_action_execution_handoff(eligible)
        self.at(T2)
        attempt = self.store.claim_action_execution_handoff(
            "tenant-a", **self.worker()
        )
        assert attempt is not None
        self.assertEqual(
            attempt.action_execution_request_id,
            eligible.action_execution_request_id,
        )
        verification = self.store.verify()
        self.assertEqual(
            verification["counts"]["action_execution_handoff_quarantines"],
            201,
        )
        self.assertEqual(verification["counts"]["action_execution_attempts"], 1)

    def test_action_claim_resamples_time_after_quarantine_scan(self) -> None:
        other_path = Path(self.temporary.name) / "claim-clock.sqlite3"
        clock_samples: list[str] = []

        def clock() -> datetime:
            value = clock_samples.pop(0) if clock_samples else self._trusted_time
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            )

        self._trusted_time = T0
        other = SQLiteOrchestrationJournal(other_path, trusted_clock=clock)
        other.enqueue_action_execution_handoff(
            self.intent(
                key="claim-clock-ineligible",
                authorization_expires_at=T1,
            )
        )
        expiring = self.intent(
            key="claim-clock-expiring",
            available_at=T1,
            authorization_expires_at="2026-09-20T12:01:11Z",
        )
        other.enqueue_action_execution_handoff(expiring)
        clock_samples.extend((T1, "2026-09-20T12:01:11Z"))
        self.assertIsNone(
            other.claim_action_execution_handoff("tenant-a", **self.worker())
        )
        verification = other.verify()
        self.assertEqual(verification["counts"]["job_claims"], 0)
        self.assertEqual(verification["counts"]["action_execution_attempts"], 0)
        self.assertEqual(
            verification["counts"]["action_execution_handoff_quarantines"],
            2,
        )

    def test_action_claim_clock_regression_rolls_back_scan(self) -> None:
        other_path = Path(self.temporary.name) / "claim-clock-regression.sqlite3"
        clock_samples: list[str] = []

        def clock() -> datetime:
            value = clock_samples.pop(0) if clock_samples else self._trusted_time
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            )

        self._trusted_time = T0
        other = SQLiteOrchestrationJournal(other_path, trusted_clock=clock)
        other.enqueue_action_execution_handoff(
            self.intent(
                key="claim-clock-regression-ineligible",
                authorization_expires_at=T1,
            )
        )
        available = self.intent(
            key="claim-clock-regression-available",
            available_at=T1,
        )
        other.enqueue_action_execution_handoff(available)
        clock_samples.extend((T1, T0))
        with self.assertRaisesRegex(
            OrchestrationIntegrityError,
            "trusted clock regressed during action claim",
        ):
            other.claim_action_execution_handoff("tenant-a", **self.worker())
        verification = other.verify()
        self.assertEqual(verification["counts"]["job_claims"], 0)
        self.assertEqual(verification["counts"]["action_execution_attempts"], 0)
        self.assertEqual(
            verification["counts"]["action_execution_handoff_quarantines"],
            0,
        )
        views = other.list_jobs("tenant-a")
        self.assertTrue(all(view.state is JobState.AVAILABLE for view in views))

    def test_handoff_replay_under_different_subject_conflicts(self) -> None:
        intent = self.intent(key="principal-bound")
        self.store.enqueue_action_execution_handoff(intent)
        changed = intent.to_dict()
        changed["requested_by_subject_id"] = "operator:other"
        with self.assertRaises(OrchestrationValidationError):
            orchestration_journal.ActionExecutionIntent.from_dict(changed)

    def test_expired_action_attempt_reconciles_exact_durable_terminal(self) -> None:
        self.store.enqueue_action_execution_handoff(self.intent(key="reconcile-terminal"))
        attempt = self.store.claim_action_execution_handoff(
            "tenant-a", **self.worker()
        )
        assert attempt is not None
        terminal = self.phase196_terminal(attempt)
        self._phase196_terminals[attempt.action_execution_request_id] = terminal
        self.at(T2)
        first = self.store.reconcile_expired_action_execution_attempt(
            attempt, **self.reconciler(attempt)
        )
        replay = self.store.reconcile_expired_action_execution_attempt(
            attempt, **self.reconciler(attempt)
        )
        self.assertEqual(tuple(item.replayed for item in first if item), (False, False, False))
        self.assertEqual(tuple(item.replayed for item in replay if item), (True, True, True))
        reconciliation, observation, outcome = (item.record for item in first)
        self.assertEqual(reconciliation.resolution_status, "terminal_observed")
        self.assertEqual(
            observation.journal_effect, "terminal_observed_not_action_success"
        )
        self.assertEqual(outcome.outcome_code, JobOutcomeCode.HANDLED_OBSERVATION)
        view = self.store.get_job("tenant-a", attempt.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.WORKER_REPORTED)
        self.assertIsNone(
            self.store.claim_action_execution_handoff("tenant-a", **self.worker())
        )
        self.assertEqual(self.store.verify()["status"], "valid")

    def test_expired_action_attempt_without_terminal_is_quarantined_once(self) -> None:
        self.store.enqueue_action_execution_handoff(self.intent(key="reconcile-absent"))
        attempt = self.store.claim_action_execution_handoff(
            "tenant-a", **self.worker()
        )
        assert attempt is not None
        self.at(T2)
        authority = self.reconciler(attempt)
        first = self.store.reconcile_expired_action_execution_attempt(
            attempt, **authority
        )
        replay = self.store.reconcile_expired_action_execution_attempt(
            attempt, **authority
        )
        self.assertFalse(first[0].replayed)
        self.assertIsNone(first[1])
        self.assertEqual(
            first[2].record.outcome_code,
            JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION,
        )
        self.assertTrue(replay[0].replayed)
        self.assertIsNone(replay[1])
        view = self.store.get_job("tenant-a", attempt.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.DEAD_LETTERED)
        self._phase196_terminals[attempt.action_execution_request_id] = (
            self.phase196_terminal(attempt)
        )
        with self.assertRaises(OrchestrationConflictError):
            self.store.reconcile_expired_action_execution_attempt(
                attempt, **authority
            )
        self.assertEqual(self.store.verify()["status"], "valid")

    def test_action_reconciliation_rejects_worker_and_lineage_rebinding(self) -> None:
        self.store.enqueue_action_execution_handoff(self.intent(key="reconcile-authority"))
        attempt = self.store.claim_action_execution_handoff(
            "tenant-a", **self.worker()
        )
        assert attempt is not None
        self.at(T2)
        authority = self.reconciler(attempt)
        changed = dict(authority)
        changed["reconciler_subject_id"] = attempt.worker_id
        with self.assertRaises(OrchestrationConflictError):
            self.store.reconcile_expired_action_execution_attempt(
                attempt, **changed
            )
        changed = dict(authority)
        changed["reconciliation_lineage_sha256"] = digest("wrong-lineage")
        with self.assertRaises(OrchestrationConflictError):
            self.store.reconcile_expired_action_execution_attempt(
                attempt, **changed
            )
        self.store.reconcile_expired_action_execution_attempt(attempt, **authority)
        changed = dict(authority)
        changed["reconciler_session_id"] = "session:substituted"
        with self.assertRaises(OrchestrationConflictError):
            self.store.reconcile_expired_action_execution_attempt(
                attempt, **changed
            )

    def test_action_reconciliation_resamples_time_after_terminal_resolution(self) -> None:
        other_path = Path(self.temporary.name) / "resolver-clock.sqlite3"

        def resolver(_request_id: str):
            self._trusted_time = "2026-09-20T12:10:00Z"
            return None

        self._trusted_time = T0
        other = SQLiteOrchestrationJournal(
            other_path,
            trusted_clock=lambda: datetime.strptime(
                self._trusted_time, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=UTC),
            phase196_terminal_resolver=resolver,
        )
        other.enqueue_action_execution_handoff(self.intent(key="resolver-clock"))
        attempt = other.claim_action_execution_handoff(
            "tenant-a", **self.worker()
        )
        assert attempt is not None
        self.at(T2)
        with self.assertRaises(OrchestrationConflictError):
            other.reconcile_expired_action_execution_attempt(
                attempt, **self.reconciler(attempt)
            )
        verification = other.verify()
        self.assertEqual(verification["counts"]["action_execution_reconciliations"], 0)
        self.assertEqual(
            verification["counts"]["action_execution_terminal_observations"], 0
        )
        self.assertEqual(verification["counts"]["job_outcomes"], 0)
        view = other.get_job("tenant-a", attempt.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.LEASED)

    def test_expired_reconciliation_rejects_normally_settled_attempt(self) -> None:
        self.store.enqueue_action_execution_handoff(self.intent(key="already-settled"))
        attempt = self.store.claim_action_execution_handoff(
            "tenant-a", **self.worker()
        )
        assert attempt is not None
        terminal = self.phase196_terminal(attempt)
        self._phase196_terminals[attempt.action_execution_request_id] = terminal
        self.at(T1)
        self.store.record_action_execution_terminal_observation(attempt, terminal)
        before = self.store.verify()
        self.at(T2)
        with self.assertRaises(OrchestrationConflictError):
            self.store.reconcile_expired_action_execution_attempt(
                attempt, **self.reconciler(attempt)
            )
        after = self.store.verify()
        self.assertEqual(after["counts"], before["counts"])
        self.assertEqual(after["event_count"], before["event_count"])
        view = self.store.get_job("tenant-a", attempt.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.WORKER_REPORTED)

    def test_message_external_reference_conflict_fails_closed(self) -> None:
        first = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.INBOX,
            topic=MessageTopic.SOURCE_EVENT,
            external_ref="source-event:1",
            external_sha256=digest("event-1"),
            source_bindings=(self.source,),
            correlation_ref="correlation:1",
            idempotency_key_sha256=digest("inbox-1"),
            recorded_at=T0,
        )
        self.store.record_message(first)
        changed = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.INBOX,
            topic=MessageTopic.SOURCE_EVENT,
            external_ref="source-event:1",
            external_sha256=digest("changed"),
            source_bindings=(self.source,),
            correlation_ref="correlation:1",
            idempotency_key_sha256=digest("inbox-2"),
            recorded_at=T0,
        )
        with self.assertRaises(OrchestrationConflictError):
            self.store.record_message(changed)

    def test_saga_requires_exact_append_only_chain(self) -> None:
        first = build_saga_step(
            tenant_id="tenant-a",
            saga_id="saga:alpha",
            saga_kind=SagaKind.MISSION_LIFECYCLE,
            sequence=1,
            step_state=SagaStepState.PLANNED,
            subject_ref="mission:alpha",
            observation_ref="observation:planned",
            observation_sha256=digest("planned"),
            source_bindings=(self.source,),
            prior_step_sha256=None,
            recorded_at=T0,
        )
        self.store.append_saga_step(first)
        second = build_saga_step(
            tenant_id="tenant-a",
            saga_id="saga:alpha",
            saga_kind=SagaKind.MISSION_LIFECYCLE,
            sequence=2,
            step_state=SagaStepState.WORKER_REPORTED,
            subject_ref="mission:alpha",
            observation_ref="observation:worker",
            observation_sha256=digest("worker"),
            source_bindings=(self.source,),
            prior_step_sha256=first.step_sha256,
            recorded_at=T1,
        )
        self.store.append_saga_step(second)
        gap = build_saga_step(
            tenant_id="tenant-a",
            saga_id="saga:alpha",
            saga_kind=SagaKind.MISSION_LIFECYCLE,
            sequence=4,
            step_state=SagaStepState.PLANNED,
            subject_ref="mission:alpha",
            observation_ref="observation:gap",
            observation_sha256=digest("gap"),
            source_bindings=(self.source,),
            prior_step_sha256=second.step_sha256,
            recorded_at=T2,
        )
        with self.assertRaises(OrchestrationConflictError):
            self.store.append_saga_step(gap)
        substituted = build_saga_step(
            tenant_id="tenant-a",
            saga_id="saga:alpha",
            saga_kind=SagaKind.RECONCILIATION,
            sequence=3,
            step_state=SagaStepState.PLANNED,
            subject_ref="mission:substitute",
            observation_ref="observation:substitute",
            observation_sha256=digest("substitute"),
            source_bindings=(self.source,),
            prior_step_sha256=second.step_sha256,
            recorded_at=T2,
        )
        with self.assertRaises(OrchestrationConflictError):
            self.store.append_saga_step(substituted)

    def test_event_chains_are_partitioned_by_tenant(self) -> None:
        for tenant in ("tenant-a", "tenant-b"):
            step = build_saga_step(
                tenant_id=tenant,
                saga_id="saga:shared-name",
                saga_kind=SagaKind.RECONCILIATION,
                sequence=1,
                step_state=SagaStepState.PLANNED,
                subject_ref="mission:shared-name",
                observation_ref=f"observation:{tenant}",
                observation_sha256=digest(tenant),
                source_bindings=(self.source,),
                prior_step_sha256=None,
                recorded_at=T0,
            )
            self.store.append_saga_step(step)
        for tenant in ("tenant-a", "tenant-b"):
            events = self.store.events_after(tenant)
            self.assertEqual(len(events), 1)
            self.assertIsNone(events[0]["event"]["prior_event_sha256"])
        self.assertEqual(self.store.verify()["status"], "valid")

    def test_delivery_attempt_binds_current_message_job_and_fence(self) -> None:
        message = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.OUTBOX,
            topic=MessageTopic.PROJECTION_CHANGE,
            external_ref="projection-event:1",
            external_sha256=digest("projection-event"),
            source_bindings=(self.source,),
            correlation_ref="correlation:delivery",
            idempotency_key_sha256=digest("message-delivery"),
            recorded_at=T0,
        )
        self.store.record_message(message)
        job = build_orchestration_job(
            tenant_id="tenant-a",
            job_kind=JobKind.OUTBOX_DELIVERY,
            subject_ref=message.message_id,
            input_ref=message.external_ref,
            input_sha256=message.external_sha256,
            source_bindings=message.source_bindings,
            idempotency_key_sha256=digest("delivery-job"),
            created_at=T0,
            available_at=T0,
            maximum_attempts=1,
        )
        self.store.submit_job(job)
        self.assertIsNone(self.store.claim_next_job("tenant-a", "worker-a", now=T0))
        custody = self.store.claim_outbox_delivery(
            "tenant-a", **self.outbox_worker()
        )
        assert custody is not None
        attempt = build_delivery_attempt(
            tenant_id="tenant-a",
            message_id=message.message_id,
            message_sha256=message.message_sha256,
            job_id=job.job_id,
            claim_id=custody.claim_id,
            claim_sha256=custody.claim_sha256,
            fence_token=1,
            attempt_number=1,
            outcome=DeliveryOutcome.ACKNOWLEDGED_OBSERVATION,
            remote_receipt_ref="remote-receipt:1",
            remote_receipt_sha256=digest("remote-receipt"),
            observed_at=self.at(T1),
        )
        first = self.store.record_outbox_delivery_observation(custody, attempt)
        replay = self.store.record_outbox_delivery_observation(custody, attempt)
        self.assertEqual(tuple(item.replayed for item in first), (False, False))
        self.assertEqual(tuple(item.replayed for item in replay), (True, True))
        with self.assertRaises(OrchestrationConflictError):
            self.store.record_outbox_delivery_observation(
                custody,
                build_delivery_attempt(
                    tenant_id="tenant-a",
                    message_id=message.message_id,
                    message_sha256=message.message_sha256,
                    job_id=job.job_id,
                    claim_id=custody.claim_id,
                    claim_sha256=custody.claim_sha256,
                    fence_token=1,
                    attempt_number=1,
                    outcome=DeliveryOutcome.ACKNOWLEDGED_OBSERVATION,
                    remote_receipt_ref="remote-receipt:1",
                    remote_receipt_sha256=digest("substituted-receipt"),
                    observed_at=T1,
                ),
            )
        view = self.store.get_job("tenant-a", job.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.WORKER_REPORTED)
        self.assertEqual(self.store.verify()["status"], "valid")

    def test_delivery_attempt_rejects_non_delivery_job(self) -> None:
        message = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.OUTBOX,
            topic=MessageTopic.PROJECTION_CHANGE,
            external_ref="projection-event:wrong-job",
            external_sha256=digest("wrong-job-message"),
            source_bindings=(self.source,),
            correlation_ref="correlation:wrong-job",
            idempotency_key_sha256=digest("wrong-job-message-key"),
            recorded_at=T0,
        )
        self.store.record_message(message)
        job = build_orchestration_job(
            tenant_id="tenant-a",
            job_kind=JobKind.SOURCE_RECONCILIATION,
            subject_ref=message.message_id,
            input_ref=message.external_ref,
            input_sha256=message.external_sha256,
            source_bindings=message.source_bindings,
            idempotency_key_sha256=digest("wrong-delivery-job"),
            created_at=T0,
            available_at=T0,
        )
        self.store.submit_job(job)
        claim = self.store.claim_next_job("tenant-a", "worker-a", now=T0)
        assert claim is not None
        attempt = build_delivery_attempt(
            tenant_id="tenant-a",
            message_id=message.message_id,
            message_sha256=message.message_sha256,
            job_id=job.job_id,
            claim_id=claim.claim_id,
            claim_sha256=claim.claim_sha256,
            fence_token=claim.fence_token,
            attempt_number=claim.attempt_number,
            outcome=DeliveryOutcome.ACKNOWLEDGED_OBSERVATION,
            remote_receipt_ref="remote-receipt:wrong-job",
            remote_receipt_sha256=digest("wrong-job-receipt"),
            observed_at=T1,
        )
        with self.assertRaises(OrchestrationValidationError):
            self.store.record_delivery_attempt(attempt)

    def test_outbox_retry_observation_is_terminal_and_never_reclaimed(self) -> None:
        message = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.OUTBOX,
            topic=MessageTopic.PROJECTION_CHANGE,
            external_ref="projection-event:retry-terminal",
            external_sha256=digest("retry-terminal-message"),
            source_bindings=(self.source,),
            correlation_ref="correlation:retry-terminal",
            idempotency_key_sha256=digest("retry-terminal-message-key"),
            recorded_at=T0,
        )
        self.store.record_message(message)
        job = build_orchestration_job(
            tenant_id="tenant-a",
            job_kind=JobKind.OUTBOX_DELIVERY,
            subject_ref=message.message_id,
            input_ref=message.external_ref,
            input_sha256=message.external_sha256,
            source_bindings=message.source_bindings,
            idempotency_key_sha256=digest("retry-terminal-job"),
            created_at=T0,
            available_at=T0,
            maximum_attempts=1,
        )
        self.store.submit_job(job)
        custody = self.store.claim_outbox_delivery(
            "tenant-a", **self.outbox_worker()
        )
        assert custody is not None
        attempt = build_delivery_attempt(
            tenant_id="tenant-a",
            message_id=message.message_id,
            message_sha256=message.message_sha256,
            job_id=job.job_id,
            claim_id=custody.claim_id,
            claim_sha256=custody.claim_sha256,
            fence_token=1,
            attempt_number=1,
            outcome=DeliveryOutcome.RETRYABLE_FAILURE_OBSERVATION,
            remote_receipt_ref=None,
            remote_receipt_sha256=None,
            observed_at=self.at(T1),
        )
        _, outcome = self.store.record_outbox_delivery_observation(
            custody, attempt
        )
        self.assertEqual(
            outcome.record.outcome_code,
            JobOutcomeCode.RETRYABLE_FAILURE_OBSERVATION,
        )
        view = self.store.get_job("tenant-a", job.job_id)
        assert view is not None
        self.assertEqual(view.state, JobState.DEAD_LETTERED)
        self.assertIsNone(
            self.store.claim_outbox_delivery("tenant-a", **self.outbox_worker())
        )
        self.assertEqual(self.store.verify()["status"], "valid")

    def test_verifier_rejects_forged_outbox_lease_exhaustion_history(self) -> None:
        message = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.OUTBOX,
            topic=MessageTopic.PROJECTION_CHANGE,
            external_ref="projection-event:forged-lease-exhaustion",
            external_sha256=digest("forged-lease-exhaustion-message"),
            source_bindings=(self.source,),
            correlation_ref="correlation:forged-lease-exhaustion",
            idempotency_key_sha256=digest("forged-lease-exhaustion-message-key"),
            recorded_at=T0,
        )
        self.store.record_message(message)
        job = build_orchestration_job(
            tenant_id="tenant-a",
            job_kind=JobKind.OUTBOX_DELIVERY,
            subject_ref=message.message_id,
            input_ref=message.external_ref,
            input_sha256=message.external_sha256,
            source_bindings=message.source_bindings,
            idempotency_key_sha256=digest("forged-lease-exhaustion-job"),
            created_at=T0,
            available_at=T0,
            maximum_attempts=1,
        )
        self.store.submit_job(job)
        custody = self.store.claim_outbox_delivery(
            "tenant-a", **self.outbox_worker()
        )
        assert custody is not None
        delivery = build_delivery_attempt(
            tenant_id="tenant-a",
            message_id=message.message_id,
            message_sha256=message.message_sha256,
            job_id=job.job_id,
            claim_id=custody.claim_id,
            claim_sha256=custody.claim_sha256,
            fence_token=1,
            attempt_number=1,
            outcome=DeliveryOutcome.ACKNOWLEDGED_OBSERVATION,
            remote_receipt_ref="receipt:forged-lease-exhaustion",
            remote_receipt_sha256=digest("forged-lease-exhaustion-receipt"),
            observed_at=T1,
        )
        outcome = orchestration_journal._build_job_outcome(
            claim_id=custody.claim_id,
            claim_sha256=custody.claim_sha256,
            job_id=job.job_id,
            tenant_id="tenant-a",
            worker_id=custody.worker_id,
            fence_token=1,
            outcome_code=JobOutcomeCode.LEASE_EXHAUSTED_OBSERVATION,
            result_ref=f"lease-expiration:{custody.claim_id}",
            result_sha256=canonical_sha256(
                {
                    "claim_id": custody.claim_id,
                    "claim_sha256": custody.claim_sha256,
                    "expired_at": custody.expires_at,
                    "job_id": job.job_id,
                    "job_sha256": job.job_sha256,
                    "reason": "non_retryable_job_lease_expired",
                }
            ),
            observed_at=T2,
            retry_available_at=None,
        )
        with self.store._write() as connection:
            connection.execute(
                "INSERT INTO delivery_attempts VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    delivery.attempt_id,
                    delivery.attempt_sha256,
                    delivery.tenant_id,
                    delivery.message_id,
                    delivery.job_id,
                    delivery.claim_id,
                    delivery.attempt_number,
                    delivery.observed_at,
                    orchestration_journal.canonical_json(delivery.to_dict()),
                ),
            )
            connection.execute(
                "INSERT INTO job_outcomes VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    outcome.outcome_id,
                    outcome.outcome_sha256,
                    outcome.claim_id,
                    outcome.job_id,
                    outcome.tenant_id,
                    outcome.worker_id,
                    outcome.fence_token,
                    outcome.outcome_code.value,
                    outcome.observed_at,
                    orchestration_journal.canonical_json(outcome.to_dict()),
                ),
            )
            connection.execute(
                "UPDATE job_heads SET state='dead_lettered',revision=revision+1,"
                "current_outcome_id=?,current_outcome_sha256=? WHERE job_id=?",
                (outcome.outcome_id, outcome.outcome_sha256, job.job_id),
            )
            self.store._append_event(
                connection,
                delivery.tenant_id,
                "message",
                delivery.message_id,
                "message.delivery_observed",
                delivery.attempt_id,
                delivery.attempt_sha256,
                delivery.observed_at,
            )
            self.store._append_event(
                connection,
                outcome.tenant_id,
                "job",
                outcome.job_id,
                "job.lease_exhausted",
                outcome.outcome_id,
                outcome.outcome_sha256,
                outcome.observed_at,
            )
        with self.assertRaisesRegex(
            OrchestrationIntegrityError,
            "outbox delivery cannot have a lease exhaustion outcome",
        ):
            self.store.verify()

    def test_outbox_message_cannot_have_multiple_delivery_jobs(self) -> None:
        message = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.OUTBOX,
            topic=MessageTopic.PROJECTION_CHANGE,
            external_ref="projection-event:single-delivery",
            external_sha256=digest("single-delivery-message"),
            source_bindings=(self.source,),
            correlation_ref="correlation:single-delivery",
            idempotency_key_sha256=digest("single-delivery-message-key"),
            recorded_at=T0,
        )
        self.store.record_message(message)

        def delivery_job(key: str):
            return build_orchestration_job(
                tenant_id="tenant-a",
                job_kind=JobKind.OUTBOX_DELIVERY,
                subject_ref=message.message_id,
                input_ref=message.external_ref,
                input_sha256=message.external_sha256,
                source_bindings=message.source_bindings,
                idempotency_key_sha256=digest(key),
                created_at=T0,
                available_at=T0,
                maximum_attempts=1,
            )

        first = delivery_job("single-delivery-job-1")
        self.store.submit_job(first)
        self.assertTrue(self.store.submit_job(first).replayed)
        with self.assertRaises(OrchestrationConflictError):
            self.store.submit_job(delivery_job("single-delivery-job-2"))
        self.assertEqual(self.store.verify()["counts"]["jobs"], 1)

    def test_projection_reconciliation_detects_stale_and_drifting_sources(self) -> None:
        first = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.MISSION,
            subject_ref="mission:alpha",
            projection_version=1,
            source_bindings=(self.source,),
            payload={"state": "observed_active"},
            projected_at=T0,
        )
        self.store.reconcile_projection(first)
        next_source = SourceHighWater(
            SourceKind.MISSION_STORE,
            "mission:alpha",
            2,
            digest("mission-head-2"),
            T1,
        )
        second = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.MISSION,
            subject_ref="mission:alpha",
            projection_version=2,
            source_bindings=(next_source,),
            payload={"state": "observed_stopped"},
            projected_at=T2,
        )
        self.store.reconcile_projection(second)
        self.assertEqual(
            self.store.get_projection("tenant-a", ProjectionKind.MISSION, "mission:alpha"),
            second,
        )
        drifting = SourceHighWater(
            SourceKind.MISSION_STORE,
            "mission:alpha",
            2,
            digest("different-head-at-same-revision"),
            T2,
        )
        third = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.MISSION,
            subject_ref="mission:alpha",
            projection_version=3,
            source_bindings=(drifting,),
            payload={"state": "untrusted"},
            projected_at=T2,
        )
        with self.assertRaises(OrchestrationConflictError):
            self.store.reconcile_projection(third)
        advanced = SourceHighWater(
            SourceKind.MISSION_STORE,
            "mission:alpha",
            3,
            digest("mission-head-3"),
            T1,
        )
        third = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.MISSION,
            subject_ref="mission:alpha",
            projection_version=3,
            source_bindings=(advanced,),
            payload={"state": "chronology-regression"},
            projected_at=T1,
        )
        with self.assertRaises(OrchestrationConflictError):
            self.store.reconcile_projection(third)
        regressed_observation = SourceHighWater(
            SourceKind.MISSION_STORE,
            "mission:alpha",
            2,
            digest("mission-head-2"),
            T0,
        )
        third = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.MISSION,
            subject_ref="mission:alpha",
            projection_version=3,
            source_bindings=(regressed_observation,),
            payload={"state": "stale_observation"},
            projected_at=T2,
        )
        with self.assertRaises(OrchestrationConflictError):
            self.store.reconcile_projection(third)

    def test_restart_and_whole_store_verification(self) -> None:
        job = self.job()
        self.store.submit_job(job)
        reopened = SQLiteOrchestrationJournal(self.path)
        view = reopened.get_job("tenant-a", job.job_id)
        self.assertIsNotNone(view)
        result = reopened.verify()
        self.assertEqual(result["counts"]["jobs"], 1)
        self.assertEqual(result["event_count"], 1)

    def test_foreign_unversioned_database_is_rejected_without_mutation(self) -> None:
        foreign_path = Path(self.temporary.name) / "foreign.sqlite3"
        connection = sqlite3.connect(foreign_path)
        try:
            connection.execute("CREATE TABLE unrelated(value TEXT)")
            connection.commit()
            before_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            connection.close()
        with self.assertRaises(OrchestrationIntegrityError):
            SQLiteOrchestrationJournal(foreign_path)
        connection = sqlite3.connect(foreign_path)
        try:
            objects = connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            after_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(objects, [("unrelated",)])
        self.assertEqual(after_mode, before_mode)

    def test_concurrent_initialization_converges_on_one_exact_schema(self) -> None:
        concurrent_path = Path(self.temporary.name) / "concurrent.sqlite3"

        def initialize(_: int) -> str:
            return SQLiteOrchestrationJournal(concurrent_path).verify()["status"]

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(initialize, range(8)))
        self.assertEqual(results, ["valid"] * 8)

    def test_corrupted_head_and_schema_are_rejected(self) -> None:
        job = self.job()
        self.store.submit_job(job)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("UPDATE job_heads SET revision=0 WHERE job_id=?", (job.job_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(OrchestrationIntegrityError):
            self.store.verify()

        other_path = Path(self.temporary.name) / "schema-corrupt.sqlite3"
        other = SQLiteOrchestrationJournal(other_path)
        connection = sqlite3.connect(other_path)
        try:
            connection.execute("DROP TRIGGER jobs_no_delete")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(OrchestrationIntegrityError):
            other.verify()

    def test_extra_migration_and_event_sequence_tampering_are_rejected(self) -> None:
        migration_path = Path(self.temporary.name) / "migration-corrupt.sqlite3"
        migration_store = SQLiteOrchestrationJournal(migration_path)
        connection = sqlite3.connect(migration_path)
        try:
            connection.execute(
                "INSERT INTO schema_migrations VALUES(2,'foreign','sha256:' || ?,?)",
                ("0" * 64, T0),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(OrchestrationIntegrityError):
            migration_store.verify()
        with self.assertRaises(OrchestrationIntegrityError):
            SQLiteOrchestrationJournal(migration_path)

        sequence_path = Path(self.temporary.name) / "sequence-corrupt.sqlite3"
        sequence_store = SQLiteOrchestrationJournal(sequence_path)
        sequence_store.submit_job(self.job(key="sequence-job"))
        connection = sqlite3.connect(sequence_path)
        try:
            connection.execute("UPDATE sqlite_sequence SET seq=100 WHERE name='journal_events'")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(OrchestrationIntegrityError):
            sequence_store.verify()

    def test_corrupted_event_record_binding_is_rejected(self) -> None:
        job = self.job()
        self.store.submit_job(job)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("DROP TRIGGER journal_events_no_update")
            connection.execute(
                "UPDATE journal_events SET event_type='job.claimed' WHERE record_id=?",
                (job.job_id,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(OrchestrationIntegrityError):
            self.store.verify()

    def test_action_attempt_worker_identity_substitution_is_rejected(self) -> None:
        self.store.enqueue_action_execution_handoff(self.intent(key="tamper-attempt"))
        attempt = self.store.claim_action_execution_handoff(
            "tenant-a", **self.worker()
        )
        assert attempt is not None
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("DROP TRIGGER action_execution_attempts_no_update")
            connection.execute(
                "UPDATE action_execution_attempts SET worker_session_id=? WHERE attempt_id=?",
                ("session:substituted", attempt.attempt_id),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(OrchestrationIntegrityError):
            self.store.verify()

    def test_event_reads_reject_noncanonical_stored_json(self) -> None:
        job = self.job(key="noncanonical-event")
        self.store.submit_job(job)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("DROP TRIGGER journal_events_no_update")
            connection.execute(
                "UPDATE journal_events SET event_json=' ' || event_json WHERE record_id=?",
                (job.job_id,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(OrchestrationIntegrityError):
            self.store.events_after("tenant-a")

    def test_whole_store_verification_reconstructs_exact_claim_deadline(self) -> None:
        job = self.job(key="claim-deadline")
        self.store.submit_job(job)
        claim = self.store.claim_next_job("tenant-a", "worker-a", now=T0)
        assert claim is not None
        altered = orchestration_journal._build_job_claim(
            job_id=claim.job_id,
            job_sha256=claim.job_sha256,
            tenant_id=claim.tenant_id,
            worker_id=claim.worker_id,
            attempt_number=claim.attempt_number,
            fence_token=claim.fence_token,
            lease_version=claim.lease_version,
            claimed_at=claim.claimed_at,
            expires_at=T2,
            prior_claim_sha256=claim.prior_claim_sha256,
        )
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            event_row = connection.execute(
                "SELECT * FROM journal_events WHERE record_id=?", (claim.claim_id,)
            ).fetchone()
            assert event_row is not None
            event = json.loads(event_row["event_json"])
            event["record_id"] = altered.claim_id
            event["record_sha256"] = altered.claim_sha256
            body = {
                key: value
                for key, value in event.items()
                if key not in {"event_id", "event_sha256"}
            }
            event_id, event_sha256 = orchestration_journal._identity(
                "JEV-", "sunderkey.orchestration-journal-event.v1", body
            )
            event["event_id"] = event_id
            event["event_sha256"] = event_sha256

            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("DROP TRIGGER job_claims_no_update")
            connection.execute("DROP TRIGGER journal_events_no_update")
            connection.execute(
                "UPDATE job_claims SET claim_id=?,claim_sha256=?,expires_at=?,claim_json=? "
                "WHERE claim_id=?",
                (
                    altered.claim_id,
                    altered.claim_sha256,
                    altered.expires_at,
                    orchestration_journal.canonical_json(altered.to_dict()),
                    claim.claim_id,
                ),
            )
            connection.execute(
                "UPDATE job_heads SET current_claim_id=?,current_claim_sha256=? WHERE job_id=?",
                (altered.claim_id, altered.claim_sha256, job.job_id),
            )
            connection.execute(
                "UPDATE journal_events SET event_id=?,event_sha256=?,record_id=?,"
                "record_sha256=?,event_json=? WHERE event_sequence=?",
                (
                    event_id,
                    event_sha256,
                    altered.claim_id,
                    altered.claim_sha256,
                    orchestration_journal.canonical_json(event),
                    event_row["event_sequence"],
                ),
            )
            connection.execute(
                "UPDATE event_heads SET event_sha256=? WHERE event_sequence=?",
                (event_sha256, event_row["event_sequence"]),
            )
            connection.execute(
                "CREATE TRIGGER job_claims_no_update BEFORE UPDATE ON job_claims"
                "\n BEGIN SELECT RAISE(ABORT,'claims are immutable'); END"
            )
            connection.execute(
                "CREATE TRIGGER journal_events_no_update BEFORE UPDATE ON journal_events"
                "\n BEGIN SELECT RAISE(ABORT,'events are immutable'); END"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(OrchestrationIntegrityError, "claim custody"):
            self.store.verify()

    def test_records_reject_secret_material_unicode_and_bool_integer(self) -> None:
        with self.assertRaises(OrchestrationValidationError):
            build_read_model_projection(
                tenant_id="tenant-a",
                projection_kind=ProjectionKind.EVIDENCE,
                subject_ref="evidence:1",
                projection_version=1,
                source_bindings=(self.source,),
                payload={"api_key": "value"},
                projected_at=T0,
            )
        with self.assertRaises(OrchestrationValidationError):
            build_read_model_projection(
                tenant_id="tenant-a",
                projection_kind=ProjectionKind.EVIDENCE,
                subject_ref="evidence:1",
                projection_version=True,
                source_bindings=(self.source,),
                payload={"summary": "clean"},
                projected_at=T0,
            )
        with self.assertRaises(OrchestrationValidationError):
            SourceHighWater(
                SourceKind.MISSION_STORE,
                "mission:alpha",
                1,
                digest("head"),
                "2026-09-20T12:00:00\u2013Z",
            )
        for payload in (
            {"nested": {"accessToken": "redacted"}},
            {"nested": {"field\x7f": "value"}},
            {"nested": {"value": "eyJabcdefgh.abcdefgh.abcdefgh"}},
        ):
            with self.assertRaises(OrchestrationValidationError):
                build_read_model_projection(
                    tenant_id="tenant-a",
                    projection_kind=ProjectionKind.AUDIT,
                    subject_ref="audit:secret-shape",
                    projection_version=1,
                    source_bindings=(self.source,),
                    payload=payload,
                    projected_at=T0,
                )

    def test_projection_property_limit_matches_closed_schema(self) -> None:
        schema = json.loads(
            Path("registry/schemas/orchestration-journal-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        projection = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.AUDIT,
            subject_ref="audit:property-limit",
            projection_version=1,
            source_bindings=(self.source,),
            payload={f"field_{index}": index for index in range(256)},
            projected_at=T0,
        )
        Draft202012Validator(schema).validate(projection.to_dict())
        with self.assertRaises(OrchestrationValidationError):
            build_read_model_projection(
                tenant_id="tenant-a",
                projection_kind=ProjectionKind.AUDIT,
                subject_ref="audit:property-limit",
                projection_version=1,
                source_bindings=(self.source,),
                payload={f"field_{index}": index for index in range(257)},
                projected_at=T0,
            )

    def test_nested_values_and_effect_constants_cannot_be_mutated_through_records(self) -> None:
        projection = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.AUDIT,
            subject_ref="mission:alpha",
            projection_version=1,
            source_bindings=(self.source,),
            payload={"nested": {"items": ["one"]}},
            projected_at=T0,
        )
        with self.assertRaises(TypeError):
            projection.payload["nested"]["items"] = ("changed",)
        portable = projection.to_dict()
        portable["payload"]["nested"]["items"].append("changed")
        portable["effects"]["network"] = "allowed"
        self.assertEqual(projection.to_dict()["payload"], {"nested": {"items": ["one"]}})
        self.assertEqual(NO_AUTHORITY_EFFECTS["network"], "none")

    def test_closed_schema_accepts_every_record_and_rejects_kind_substitution(self) -> None:
        schema = json.loads(
            Path("registry/schemas/orchestration-journal-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        job = self.job()
        self.store.submit_job(job)
        claim = self.store.claim_next_job("tenant-a", "worker-a", now=T0)
        assert claim is not None
        outcome = self.store.record_job_outcome(
            claim,
            outcome_code=JobOutcomeCode.HANDLED_OBSERVATION,
            result_ref="result:handled",
            result_sha256=digest("handled"),
            observed_at=self.at(T1),
        ).record
        message = build_orchestration_message(
            tenant_id="tenant-a",
            direction=MessageDirection.OUTBOX,
            topic=MessageTopic.PROJECTION_CHANGE,
            external_ref="projection-event:2",
            external_sha256=digest("projection-event-2"),
            source_bindings=(self.source,),
            correlation_ref="correlation:schema",
            idempotency_key_sha256=digest("schema-message"),
            recorded_at=T0,
        )
        saga = build_saga_step(
            tenant_id="tenant-a",
            saga_id="saga:schema",
            saga_kind=SagaKind.RECONCILIATION,
            sequence=1,
            step_state=SagaStepState.PLANNED,
            subject_ref="mission:alpha",
            observation_ref="observation:schema",
            observation_sha256=digest("schema-observation"),
            source_bindings=(self.source,),
            prior_step_sha256=None,
            recorded_at=T0,
        )
        attempt = build_delivery_attempt(
            tenant_id="tenant-a",
            message_id=message.message_id,
            message_sha256=message.message_sha256,
            job_id=job.job_id,
            claim_id=claim.claim_id,
            claim_sha256=claim.claim_sha256,
            fence_token=claim.fence_token,
            attempt_number=claim.attempt_number,
            outcome=DeliveryOutcome.ACKNOWLEDGED_OBSERVATION,
            remote_receipt_ref="receipt:schema",
            remote_receipt_sha256=digest("schema-receipt"),
            observed_at=T1,
        )
        projection = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.AUDIT,
            subject_ref="mission:alpha",
            projection_version=1,
            source_bindings=(self.source,),
            payload={"state": "observed"},
            projected_at=T0,
        )
        intent = self.intent(key="schema-action")
        self.store.enqueue_action_execution_handoff(intent)
        action_attempt = self.store.claim_action_execution_handoff(
            "tenant-a", **self.worker()
        )
        assert action_attempt is not None
        authority = self.reconciler(action_attempt)
        authority["authority_issued_at"] = T3
        authority["authority_expires_at"] = "2026-09-20T12:20:00Z"
        self.at(T3)
        reconciliation = self.store.reconcile_expired_action_execution_attempt(
            action_attempt, **authority
        )[0].record
        self.store.record_message(message)
        outbox_job = build_orchestration_job(
            tenant_id="tenant-a",
            job_kind=JobKind.OUTBOX_DELIVERY,
            subject_ref=message.message_id,
            input_ref=message.external_ref,
            input_sha256=message.external_sha256,
            source_bindings=message.source_bindings,
            idempotency_key_sha256=digest("schema-outbox-job"),
            created_at=T0,
            available_at=T0,
            maximum_attempts=1,
        )
        self.store.submit_job(outbox_job)
        outbox_custody = self.store.claim_outbox_delivery(
            "tenant-a", **self.outbox_worker()
        )
        assert outbox_custody is not None
        records = (
            job,
            claim,
            outcome,
            message,
            saga,
            attempt,
            projection,
            intent,
            action_attempt,
            reconciliation,
            outbox_custody,
        )
        for record in records:
            validator.validate(record.to_dict())
        for reserved_kind in (
            JobKind.OUTBOX_DELIVERY.value,
            JobKind.ACTION_EXECUTION_HANDOFF.value,
        ):
            changed_reserved = outbox_job.to_dict()
            changed_reserved["job_kind"] = reserved_kind
            changed_reserved["maximum_attempts"] = 2
            self.assertTrue(list(validator.iter_errors(changed_reserved)))
        changed_intent = intent.to_dict()
        changed_intent["inline_authorization"] = {"forbidden": True}
        self.assertTrue(list(validator.iter_errors(changed_intent)))
        event = self.store.events_after("tenant-a", limit=1)[0]["event"]
        validator.validate(event)
        changed = copy.deepcopy(job.to_dict())
        changed["kind"] = "sunderkey.orchestration-saga-step.v1"
        self.assertTrue(list(validator.iter_errors(changed)))
        changed = copy.deepcopy(outcome.to_dict())
        changed["retry_available_at"] = T2
        self.assertTrue(list(validator.iter_errors(changed)))
        changed = copy.deepcopy(job.to_dict())
        changed["tenant_id"] = "tenant..substitute"
        self.assertTrue(list(validator.iter_errors(changed)))
        changed = copy.deepcopy(job.to_dict())
        changed["schema_version"] = True
        with self.assertRaises(OrchestrationValidationError):
            type(job).from_dict(changed)
        self.assertTrue(list(validator.iter_errors(changed)))


if __name__ == "__main__":
    unittest.main()
