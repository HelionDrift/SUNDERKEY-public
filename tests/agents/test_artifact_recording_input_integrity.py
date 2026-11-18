"""Artifact input ownership over pure contracts and inert PostgreSQL ports."""

from __future__ import annotations

import copy
import hashlib
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

import sunderkey.durable_artifact_recorder as recorder
from sunderkey.durable_artifact_recorder import (
    ArtifactCommitObservation,
    ArtifactMetadata,
    ArtifactRecordingPlan,
    ArtifactRecordingReceipt,
    ArtifactRecordingRequest,
    DurableArtifactRecorderError,
    OutboxEventMetadata,
    plan_artifact_recording,
    record_artifact,
)
from sunderkey.postgresql_runtime_adapter import (
    PostgreSQLAdapterError,
    PostgreSQLPersistenceSchedulerAdapter,
)
from tests.agents import test_durable_artifact_recorder_phase169 as artifact
from tests.agents.test_postgresql_runtime_adapter_phase170 import FakeStore


def other_request(item):
    return replace(
        item,
        tenant_ref="tenantref:tenant-b",
        assessment_ref="assessmentref:assessment-43",
        scope_ref="scoperef:scope-admitted-43",
        idempotency_key="idem:artifact-evidence-43-00000001",
        artifact=replace(
            item.artifact,
            artifact_ref="artifactref:evidence-43",
            content_sha256="sha256:" + "d" * 64,
            custody_ref="custodyref:evidence-43.entry-7",
        ),
        outbox_event=replace(item.outbox_event, outbox_event_ref="outboxref:artifact-recorded-43"),
    )


def seed(store, plan):
    batch = plan.transaction_batch
    for binding in batch.version_bindings:
        if binding.expected_version:
            store.data["aggregates"][(batch.tenant_ref, binding.aggregate_ref)] = {
                "version": binding.expected_version,
                "content_sha256": artifact.DIGEST_A,
            }
    for fence in batch.fence_bindings:
        store.data["fences"][(batch.tenant_ref, fence.resource_ref)] = {
            "fence_token": fence.fence_token,
            "fence_epoch": fence.fence_epoch,
        }


class ArtifactRecordingInputIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_artifact_recording(artifact.request())
        self.snapshot = self.plan.to_json()
        self.foreign = plan_artifact_recording(other_request(self.plan.request))
        self.store = FakeStore()
        seed(self.store, self.plan)

    def test_preentry_mismatched_plan_denied_before_port_or_factory(self):
        object.__setattr__(self.plan, "request", self.foreign.request)
        port = Mock()
        with self.assertRaises(DurableArtifactRecorderError):
            record_artifact(self.plan, port)
        port.commit_artifact.assert_not_called()
        factory = Mock(side_effect=self.store.factory)
        before = copy.deepcopy(self.store.data)
        with self.assertRaises(PostgreSQLAdapterError):
            PostgreSQLPersistenceSchedulerAdapter(factory).commit_artifact(self.plan)
        factory.assert_not_called()
        self.assertEqual(self.store.data, before)

    def test_preentry_nested_request_mismatch_denied(self):
        object.__setattr__(self.plan.request.artifact, "content_sha256", artifact.DIGEST_C)
        port = Mock()
        with self.assertRaises(DurableArtifactRecorderError):
            record_artifact(self.plan, port)
        port.commit_artifact.assert_not_called()
        factory = Mock(side_effect=self.store.factory)
        with self.assertRaises(PostgreSQLAdapterError):
            PostgreSQLPersistenceSchedulerAdapter(factory).commit_artifact(self.plan)
        factory.assert_not_called()

    def test_direct_facade_preentry_mismatch_keeps_original_store_unchanged(self):
        before = copy.deepcopy(self.store.data)
        for field in ("request", "transaction_batch"):
            with self.subTest(field=field):
                plan = ArtifactRecordingPlan.from_json(self.snapshot)
                object.__setattr__(plan, field, getattr(self.foreign, field))
                factory = Mock(side_effect=self.store.factory)
                with self.assertRaises(PostgreSQLAdapterError):
                    PostgreSQLPersistenceSchedulerAdapter(factory).commit_artifact(plan)
                factory.assert_not_called()
                self.assertEqual(self.store.data, before)
        self.assertEqual(self.store.commit_count, 0)

    def test_facade_captures_caller_plan_before_factory(self):
        original = ArtifactRecordingPlan.from_json(self.snapshot)
        calls = []

        def factory():
            calls.append(1)
            object.__setattr__(self.plan, "request", self.foreign.request)
            return self.store.factory()

        observed = PostgreSQLPersistenceSchedulerAdapter(factory).commit_artifact(self.plan)
        self.assertEqual(observed.tenant_ref, original.request.tenant_ref)
        self.assertEqual(observed.stored_content_sha256, original.request.artifact.content_sha256)
        self.assertEqual(observed.batch_id, original.transaction_batch.batch_id)
        self.assertEqual(self.store.commit_count, 1)
        self.assertEqual(calls, [1])

    def test_facade_captures_nested_request_before_factory(self):
        expected = self.plan.request.to_dict()

        def factory():
            object.__setattr__(self.plan.request, "tenant_ref", "tenantref:tenant-b")
            object.__setattr__(self.plan.request.artifact, "content_sha256", artifact.DIGEST_C)
            return self.store.factory()

        observed = PostgreSQLPersistenceSchedulerAdapter(factory).commit_artifact(self.plan)
        self.assertEqual(observed.tenant_ref, expected["tenant_ref"])
        self.assertEqual(observed.stored_content_sha256, expected["artifact"]["content_sha256"])
        self.assertEqual(self.store.commit_count, 1)

    def test_recorder_private_original_survives_caller_mutation_inside_factory(self):
        expected_plan = ArtifactRecordingPlan.from_json(self.snapshot)
        control_store = FakeStore()
        seed(control_store, expected_plan)
        expected = record_artifact(
            expected_plan, PostgreSQLPersistenceSchedulerAdapter(control_store.factory)
        )

        def factory():
            object.__setattr__(self.plan, "request", self.foreign.request)
            object.__setattr__(self.plan, "plan_id", self.foreign.plan_id)
            return self.store.factory()

        actual = record_artifact(self.plan, PostgreSQLPersistenceSchedulerAdapter(factory))
        self.assertEqual(actual.to_json(), expected.to_json())
        self.assertEqual(self.store.commit_count, 1)

    def test_port_gets_separately_detached_plan(self):
        original = self.plan
        observed = artifact.observation(original)

        class Port:
            def commit_artifact(inner, delivered):
                inner.delivered = delivered
                return observed

        port = Port()
        record_artifact(original, port)
        self.assertEqual(port.delivered.to_json(), self.snapshot)
        for delivered, caller in (
            (port.delivered, original),
            (port.delivered.request, original.request),
            (port.delivered.request.artifact, original.request.artifact),
            (port.delivered.request.outbox_event, original.request.outbox_event),
            (port.delivered.transaction_batch, original.transaction_batch),
        ):
            self.assertIsNot(delivered, caller)

    def test_foreign_port_observation_denied_even_after_delivered_plan_replacement(self):
        seed(self.store, self.foreign)
        foreign = self.foreign
        store = self.store
        original = self.plan

        class Port:
            calls = 0

            def commit_artifact(inner, delivered):
                inner.calls += 1
                for name in ("request", "transaction_batch", "plan_id", "plan_sha256"):
                    object.__setattr__(delivered, name, getattr(foreign, name))
                return PostgreSQLPersistenceSchedulerAdapter(store.factory).commit_artifact(foreign)

        port = Port()
        with self.assertRaisesRegex(DurableArtifactRecorderError, "does not match"):
            record_artifact(original, port)
        self.assertEqual(port.calls, 1)
        self.assertEqual(original.to_json(), self.snapshot)
        # The injected port actually committed its foreign metadata in the fake.
        # Observation rejection makes no external rollback assertion.
        self.assertEqual(self.store.commit_count, 1)
        self.assertEqual(self.store.rollback_count, 0)
        self.assertIn(
            (foreign.request.tenant_ref, foreign.request.idempotency_key),
            self.store.data["batches"],
        )

    def test_mutated_delivered_plan_does_not_rebind_valid_original_observation(self):
        expected = artifact.observation(self.plan)
        foreign = self.foreign

        class Port:
            calls = 0

            def commit_artifact(inner, delivered):
                inner.calls += 1
                for name in ("request", "transaction_batch", "plan_id", "plan_sha256"):
                    object.__setattr__(delivered, name, getattr(foreign, name))
                return expected

        port = Port()
        receipt = record_artifact(self.plan, port)
        self.assertEqual(receipt.plan_id, "DAP-5D28922CFF28F7FCE0570E8BB779E621")
        self.assertEqual(receipt.batch_id, expected.batch_id)
        self.assertEqual(port.calls, 1)
        self.assertEqual(self.plan.to_json(), self.snapshot)

    def test_original_observation_validation_is_not_changed_by_port_lookup(self):
        expected = artifact.observation(self.plan)
        caller, foreign = self.plan, self.foreign
        calls = []

        class Port:
            @property
            def commit_artifact(inner):
                object.__setattr__(caller, "request", foreign.request)

                def commit(delivered):
                    calls.append(1)
                    return expected

                return commit

        receipt = record_artifact(self.plan, Port())
        self.assertEqual(receipt.plan_id, "DAP-5D28922CFF28F7FCE0570E8BB779E621")
        self.assertEqual(calls, [1])

    def test_incomplete_native_wrappers_deny_before_port_or_factory(self):
        replacements = (
            (None, ArtifactRecordingPlan),
            ("request", ArtifactRecordingRequest),
            ("artifact", ArtifactMetadata),
            ("outbox_event", OutboxEventMetadata),
        )
        for field, family in replacements:
            with self.subTest(field=field):
                plan = ArtifactRecordingPlan.from_json(self.snapshot)
                incomplete = object.__new__(family)
                if field is None:
                    plan = incomplete
                elif field == "request":
                    object.__setattr__(plan, field, incomplete)
                else:
                    object.__setattr__(plan.request, field, incomplete)
                port = Mock()
                with self.assertRaises(DurableArtifactRecorderError):
                    record_artifact(plan, port)
                port.commit_artifact.assert_not_called()
                factory = Mock(side_effect=self.store.factory)
                with self.assertRaises(PostgreSQLAdapterError):
                    PostgreSQLPersistenceSchedulerAdapter(factory).commit_artifact(plan)
                factory.assert_not_called()

    def test_native_aliases_reject_before_callback_and_hash(self):
        class StringAlias(str):
            pass

        class IntegerAlias(int):
            pass

        for field, value in (
            ("tenant_ref", StringAlias("tenantref:tenant-a")),
            ("expected_artifact_version", IntegerAlias(6)),
            ("fence_epoch", IntegerAlias(42)),
        ):
            with self.subTest(field=field):
                plan = ArtifactRecordingPlan.from_json(self.snapshot)
                object.__setattr__(plan.request, field, value)
                port = Mock()
                with self.assertRaises(DurableArtifactRecorderError):
                    record_artifact(plan, port)
                port.commit_artifact.assert_not_called()
                factory = Mock(side_effect=self.store.factory)
                with self.assertRaises(PostgreSQLAdapterError):
                    PostgreSQLPersistenceSchedulerAdapter(factory).commit_artifact(plan)
                factory.assert_not_called()

    def test_unreplayed_observation_or_incomplete_wrapper_rejected_after_one_call(self):
        observed = artifact.observation(self.plan)
        object.__setattr__(observed, "observation_sha256", artifact.DIGEST_C)
        for returned in (observed, object.__new__(ArtifactCommitObservation)):
            port = artifact.BoundAdapter(returned)
            with self.assertRaises(DurableArtifactRecorderError):
                record_artifact(self.plan, port)
            self.assertEqual(len(port.calls), 1)

    def test_public_plan_parser_native_cost_bound_precedes_hash(self):
        shared = ['"\\' * 4096] * 64
        document = self.plan.to_dict()
        document["request"]["artifact"]["media_type"] = shared
        with patch.object(recorder, "_identity", side_effect=AssertionError("hash reached")):
            with patch.object(
                recorder.json, "dumps", side_effect=AssertionError("serialize reached")
            ):
                with self.assertRaisesRegex(DurableArtifactRecorderError, "bound"):
                    ArtifactRecordingPlan.from_dict(document)

    def test_wrapped_escaped_metadata_and_shared_tuple_bounds_precede_replay(self):
        for location in ("media_type", "outbox_event_refs"):
            with self.subTest(location=location):
                plan = ArtifactRecordingPlan.from_json(self.snapshot)
                if location == "media_type":
                    object.__setattr__(plan.request.artifact, location, '"\\' * 16384)
                else:
                    object.__setattr__(plan.transaction_batch, location, ('"\\' * 128,) * 512)
                port = Mock()
                factory = Mock(side_effect=self.store.factory)
                with patch.object(
                    ArtifactRecordingPlan, "from_dict", side_effect=AssertionError("replay reached")
                ):
                    with patch.object(
                        recorder.json, "dumps", side_effect=AssertionError("serialize reached")
                    ):
                        with self.assertRaisesRegex(DurableArtifactRecorderError, "bound"):
                            record_artifact(plan, port)
                        with self.assertRaises(PostgreSQLAdapterError):
                            PostgreSQLPersistenceSchedulerAdapter(factory).commit_artifact(plan)
                port.commit_artifact.assert_not_called()
                factory.assert_not_called()

    def test_native_wrapper_aliases_and_observation_aliases_rejected(self):
        class PlanAlias(ArtifactRecordingPlan):
            pass

        class TupleAlias(tuple):
            pass

        class StringAlias(str):
            pass

        alias = PlanAlias(self.plan.request, self.plan.transaction_batch)
        for plan in (alias, ArtifactRecordingPlan.from_json(self.snapshot)):
            if type(plan) is ArtifactRecordingPlan:
                object.__setattr__(
                    plan.transaction_batch,
                    "outbox_event_refs",
                    TupleAlias(plan.transaction_batch.outbox_event_refs),
                )
            port = Mock()
            with self.assertRaises(DurableArtifactRecorderError):
                record_artifact(plan, port)
            port.commit_artifact.assert_not_called()
        observed = artifact.observation(self.plan)
        object.__setattr__(observed, "tenant_ref", StringAlias(observed.tenant_ref))
        port = artifact.BoundAdapter(observed)
        with self.assertRaises(DurableArtifactRecorderError):
            record_artifact(self.plan, port)
        self.assertEqual(len(port.calls), 1)

    def test_public_parser_integer_depth_and_json_byte_bounds_before_hash(self):
        for location in ("integer", "depth", "nodes"):
            document = self.plan.to_dict()
            if location == "integer":
                document["schema_version"] = 1 << 100_000
            elif location == "nodes":
                document["request"]["artifact"]["media_type"] = [None] * 4097
            else:
                selected = document
                for _ in range(15):
                    selected["extra"] = {}
                    selected = selected["extra"]
            with (
                self.subTest(location=location),
                patch.object(recorder, "_identity", side_effect=AssertionError("hash reached")),
            ):
                with self.assertRaises(DurableArtifactRecorderError):
                    ArtifactRecordingPlan.from_dict(document)
        for text in (
            " " * 65537,
            '{"schema_version":1,"schema_version":1}',
            '{"schema_version":1.0}',
            '{"schema_version":NaN}',
        ):
            with self.subTest(text=text[:80]):
                with self.assertRaises(DurableArtifactRecorderError):
                    ArtifactRecordingPlan.from_json(text)

    def test_public_native_schema_aliases_rejected_before_hash(self):
        for alias in (True, 1.0):
            for document, family in (
                (self.plan.to_dict(), ArtifactRecordingPlan),
                (artifact.observation(self.plan).to_dict(), ArtifactCommitObservation),
            ):
                with self.subTest(alias=alias, family=family.__name__):
                    document["schema_version"] = alias
                    with patch.object(
                        recorder, "_identity", side_effect=AssertionError("hash reached")
                    ):
                        with self.assertRaises(DurableArtifactRecorderError):
                            family.from_dict(document)

    def test_valid_original_bodies_roundtrips_and_postgresql_replay_unchanged(self):
        observed = artifact.observation(self.plan)
        receipt = record_artifact(self.plan, artifact.BoundAdapter(observed))
        actual = tuple(
            hashlib.sha256(item.to_json().encode("ascii")).hexdigest()
            for item in (self.plan, observed, receipt)
        )
        self.assertEqual(
            actual,
            (
                "e0adc5ac3b1f5aa34db67fe1c274c324b2d39d43da35cf880b365716a05ac87d",
                "8396e258e06eb7b0a660caa06321f5b9284fa9c73031a77d69a6439d6cf53677",
                "a9d4bb303040a6d3b4034927efb869e7802a10ebf4943258768c97bf33ff4bd8",
            ),
        )
        for item in (self.plan, observed, receipt):
            self.assertEqual(recorder.parse_record(item.to_dict()), item)
            self.assertEqual(type(item).from_json(item.to_json()), item)
        adapter = PostgreSQLPersistenceSchedulerAdapter(self.store.factory)
        first, replay = record_artifact(self.plan, adapter), record_artifact(self.plan, adapter)
        self.assertEqual(
            tuple(
                hashlib.sha256(item.to_json().encode("ascii")).hexdigest()
                for item in (first, replay)
            ),
            (
                "132a39e2aed0304d5ae23a7f8cf9399f9e7b929a559e191266d49f917d4dc7c5",
                "bd631528c73647b5519868573eb57a6069813e7d6dd0e8a782e6c7b0bb69ca6a",
            ),
        )
        self.assertEqual(len(self.store.data["batches"]), 1)
        self.assertEqual(first.plan_id, replay.plan_id)

    def test_first_custody_and_optional_outbox_native_success(self):
        plan = plan_artifact_recording(artifact.request(prior=None, outbox=False))
        observed = artifact.observation(plan)
        receipt = record_artifact(plan, artifact.BoundAdapter(observed))
        self.assertEqual(receipt.plan_id, plan.plan_id)
        self.assertEqual(ArtifactRecordingReceipt.from_json(receipt.to_json()), receipt)
        self.assertIsNone(plan.request.artifact.prior_custody_sha256)
        self.assertIsNone(plan.request.outbox_event)


if __name__ == "__main__":
    unittest.main()
