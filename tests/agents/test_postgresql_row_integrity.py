"""Inert public PostgreSQL row, document and replay integrity controls."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import fields, replace
from typing import Any
from unittest.mock import Mock, patch

import sunderkey.postgresql_runtime_adapter as module
from sunderkey.durable_scheduler_contracts import (
    DurableLease,
    create_schedule_definition,
    derive_due_occurrences,
    heartbeat_lease,
)
from sunderkey.persistence_port_contracts import canonical_json, canonical_sha256
from sunderkey.persistence_scheduler_runtime import (
    ConcurrencyConflict,
    IdempotencyConflict,
)
from sunderkey.postgresql_runtime_adapter import (
    PostgreSQLAdapterError,
    PostgreSQLPersistenceSchedulerAdapter,
    PostgreSQLRuntimeConfig,
    PostgreSQLTerminalError,
    parse_receipt,
)
from tests.agents import test_postgresql_runtime_adapter_phase170 as legacy

NOW = "2026-09-20T12:00:00Z"
KEY = "idem:postgresql-claim-000001"


class ProjectionCursor(legacy.FakeCursor):
    """Expose actual selected key columns without using a database engine."""

    def execute(self, operation: str, parameters: tuple[Any, ...] = ()) -> None:
        self.operation = operation
        super().execute(operation, parameters)
        tag = self.connection.store.executed_tags[-1]
        self.rows = copy.deepcopy(self.rows)
        for row in self.rows:
            if tag == "transaction-prior":
                row.setdefault("tenant_ref", parameters[0])
                row.setdefault("idempotency_key", parameters[1])
            if tag in {"schedule-prior", "schedule-load"}:
                row.setdefault("tenant_id", parameters[0])
                row.setdefault("schedule_id", parameters[1])
            if tag == "scheduler-result":
                row.setdefault("tenant_id", parameters[0])
                row.setdefault("idempotency_key", parameters[1])
            if tag == "claim-candidate":
                row.setdefault("tenant_id", parameters[0])
        transform = self.connection.store.transforms.get(tag)
        if transform is not None:
            transform(self, parameters)

    def _lease_snapshot(self, parameters: tuple[Any, ...]) -> None:
        tenant, lease_id, version = parameters
        row = self.data["leases"].get((tenant, lease_id, version))
        self.rows = (
            []
            if row is None
            else [{"tenant_id": tenant, "lease_id": lease_id, "lease_version": version, **row}]
        )

    def close(self) -> None:
        super().close()
        if self.connection.store.cursor_close_error:
            raise RuntimeError("private cursor cleanup detail")


class ProjectionConnection(legacy.FakeConnection):
    def cursor(self) -> ProjectionCursor:
        return ProjectionCursor(self)

    def commit(self) -> None:
        super().commit()
        if self.store.commit_error:
            raise legacy.FakeDatabaseError("08006")

    def rollback(self) -> None:
        super().rollback()
        if self.store.rollback_error:
            raise RuntimeError("private rollback detail")

    def close(self) -> None:
        super().close()
        if self.store.connection_close_error:
            raise RuntimeError("private connection cleanup detail")


class ProjectionStore(legacy.FakeStore):
    def __init__(self) -> None:
        super().__init__()
        self.transforms: dict[str, Any] = {}
        self.commit_error = False
        self.rollback_error = False
        self.cursor_close_error = False
        self.connection_close_error = False
        self.factory_calls = 0

    def factory(self) -> ProjectionConnection:
        self.factory_calls += 1
        return ProjectionConnection(self)


def changed_schedule(schedule, **changes):
    parameters = {
        field.name: getattr(schedule, field.name)
        for field in fields(schedule)
        if field.name not in {"schedule_id", "schedule_sha256"}
    }
    return create_schedule_definition(**{**parameters, **changes})


def changed_lease(lease: DurableLease, **changes: Any) -> DurableLease:
    document = {**lease.to_dict(), **changes}
    del document["lease_sha256"]
    document["lease_sha256"] = canonical_sha256(
        {"body": document, "domain": "sunderkey.durable-lease.v1"}
    )
    return DurableLease.from_dict(document)


class PostgreSQLRowIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = ProjectionStore()
        self.adapter = PostgreSQLPersistenceSchedulerAdapter(self.store.factory)
        self.store.data["fences"][("tenantref:tenant-a", "resourceref:assessment-1")] = {
            "fence_token": "fence:assessment-000000000001",
            "fence_epoch": 1,
        }

    def seeded(self):
        schedule = self.adapter.register_schedule(legacy._schedule())
        due = self.adapter.materialize_due(
            schedule.tenant_id, schedule.schedule_id, evaluated_at=NOW
        )
        return schedule, due[0]

    def claimed(self):
        schedule, occurrence = self.seeded()
        lease = self.adapter.claim_due(
            schedule.tenant_id, schedule.schedule_id, "worker-1", KEY, claimed_at=NOW
        )
        assert lease is not None
        return schedule, occurrence, lease

    def denied_unchanged(self, operation) -> None:
        before = copy.deepcopy(self.store.data)
        with self.assertRaises((PostgreSQLAdapterError, ConcurrencyConflict, IdempotencyConflict)):
            operation()
        self.assertEqual(self.store.data, before)

    def test_foreign_schedule_document_denied_before_materialization(self) -> None:
        schedule = self.adapter.register_schedule(legacy._schedule())
        row = self.store.data["schedules"][(schedule.tenant_id, schedule.schedule_id)]
        row["schedule_json"] = canonical_json(legacy._schedule("tenant-b").to_dict())
        self.denied_unchanged(
            lambda: self.adapter.materialize_due(
                schedule.tenant_id, schedule.schedule_id, evaluated_at=NOW
            )
        )
        self.assertEqual(self.store.data["occurrences"], {})

    def test_register_replay_requires_complete_schedule_row(self) -> None:
        schedule = self.adapter.register_schedule(legacy._schedule())
        baseline = copy.deepcopy(self.store.data)
        for field, value in (
            ("schedule_json", canonical_json(legacy._schedule("tenant-b").to_dict())),
            ("definition_version", True),
            ("definition_version", 1.0),
            ("cancelled", 0),
        ):
            with self.subTest(field=field, value=value):
                self.store.data = copy.deepcopy(baseline)
                self.store.data["schedules"][(schedule.tenant_id, schedule.schedule_id)][field] = (
                    value
                )
                self.denied_unchanged(lambda: self.adapter.register_schedule(schedule))

    def test_occurrence_substitution_denied_before_selected_row_update(self) -> None:
        schedule, occurrence = self.seeded()
        alternate = derive_due_occurrences(schedule, evaluated_at="2026-09-20T12:01:00Z")[1]
        selected = self.store.data["occurrences"][(schedule.tenant_id, occurrence.occurrence_id)]
        selected["occurrence_json"] = canonical_json(alternate.to_dict())
        # A genuine second row ensures the old consumer can update the wrong row.
        second = {
            **copy.deepcopy(selected),
            "occurrence_id": alternate.occurrence_id,
            "occurrence_index": alternate.occurrence_index,
            "ready_at": alternate.nominal_at,
        }
        self.store.data["occurrences"][(schedule.tenant_id, alternate.occurrence_id)] = second
        self.denied_unchanged(
            lambda: self.adapter.claim_due(
                schedule.tenant_id,
                schedule.schedule_id,
                "worker-1",
                KEY,
                claimed_at="2026-09-20T12:01:00Z",
            )
        )

    def test_candidate_native_versions_attempts_and_fences(self) -> None:
        schedule, occurrence = self.seeded()
        baseline = copy.deepcopy(self.store.data)
        for field in ("occurrence_version", "attempt_number", "fence_epoch"):
            for value in (True, False, 1.0, None, "1"):
                with self.subTest(field=field, value=value):
                    self.store.data = copy.deepcopy(baseline)
                    self.store.data["occurrences"][(schedule.tenant_id, occurrence.occurrence_id)][
                        field
                    ] = value
                    self.denied_unchanged(
                        lambda: self.adapter.claim_due(
                            schedule.tenant_id,
                            schedule.schedule_id,
                            "worker-1",
                            KEY,
                            claimed_at=NOW,
                        )
                    )

    def test_candidate_projection_matrix(self) -> None:
        schedule, occurrence = self.seeded()
        for field, value in (
            ("tenant_id", "tenant-b"),
            ("schedule_id", legacy._schedule("tenant-b").schedule_id),
            ("occurrence_id", "DSO-" + "F" * 32),
            ("occurrence_index", True),
            ("state", "leased"),
            ("ready_at", "2026-09-20T12:00:01Z"),
            ("lease_id", "DSL-" + "F" * 32),
        ):
            with self.subTest(field=field):
                self.store.transforms["claim-candidate"] = (
                    lambda cursor, parameters, f=field, v=value: cursor.rows[0].update({f: v})
                )
                self.denied_unchanged(
                    lambda: self.adapter.claim_due(
                        schedule.tenant_id,
                        schedule.schedule_id,
                        "worker-1",
                        KEY,
                        claimed_at=NOW,
                    )
                )

    def test_cached_claim_context_hash_and_shape_matrix(self) -> None:
        schedule, _, lease = self.claimed()
        baseline = copy.deepcopy(self.store.data)
        heartbeat = heartbeat_lease(
            schedule,
            lease,
            expected_lease_version=1,
            expected_fence_epoch=1,
            observed_at="2026-09-20T12:00:10Z",
            expires_at="2026-09-20T12:00:40Z",
            idempotency_key="idem:postgresql-heartbeat-000001",
        )
        for field, value in (
            ("tenant_id", "tenant-b"),
            ("idempotency_key", "idem:different-claim-000001"),
            ("result_sha256", legacy.DIGEST_C),
            ("result_kind", "heartbeat"),
            ("result_json", canonical_json(heartbeat.to_dict())),
        ):
            with self.subTest(field=field):
                self.store.data = copy.deepcopy(baseline)
                self.store.data["scheduler_results"][(schedule.tenant_id, KEY)][field] = value
                self.denied_unchanged(
                    lambda: self.adapter.claim_due(
                        schedule.tenant_id,
                        schedule.schedule_id,
                        "worker-1",
                        KEY,
                        claimed_at="2026-09-20T12:02:00Z",
                    )
                )

    def test_coherently_readdressed_claim_requires_original_snapshot(self) -> None:
        schedule, _, lease = self.claimed()
        for changes in (
            {"schedule_sha256": legacy.DIGEST_C},
            {"expected_occurrence_version": 2},
            {"idempotency_key": "idem:different-claim-000001"},
            {"occurrence_sha256": legacy.DIGEST_C},
        ):
            with self.subTest(changes=changes):
                altered = changed_lease(lease, **changes)
                row = self.store.data["scheduler_results"][(schedule.tenant_id, KEY)]
                row["result_json"] = canonical_json(altered.to_dict())
                row["result_sha256"] = canonical_sha256(altered.to_dict())
                self.denied_unchanged(
                    lambda: self.adapter.claim_due(
                        schedule.tenant_id,
                        schedule.schedule_id,
                        "worker-1",
                        KEY,
                        claimed_at="2026-09-20T12:02:00Z",
                    )
                )

    def test_missing_or_contradictory_original_snapshot_denied(self) -> None:
        schedule, _, lease = self.claimed()
        baseline = copy.deepcopy(self.store.data)
        for field, value in (
            ("lease_version", True),
            ("fence_epoch", 1.0),
            ("active", 1),
            ("expires_at", "2026-09-20T12:00:29Z"),
            (
                "lease_json",
                canonical_json(changed_lease(lease, expected_occurrence_version=2).to_dict()),
            ),
        ):
            with self.subTest(field=field):
                self.store.data = copy.deepcopy(baseline)
                self.store.data["leases"][(schedule.tenant_id, lease.lease_id, 1)][field] = value
                self.denied_unchanged(
                    lambda: self.adapter.claim_due(
                        schedule.tenant_id,
                        schedule.schedule_id,
                        "worker-1",
                        KEY,
                        claimed_at=NOW,
                    )
                )
        self.store.data = copy.deepcopy(baseline)
        self.store.data["leases"].clear()
        self.denied_unchanged(
            lambda: self.adapter.claim_due(
                schedule.tenant_id, schedule.schedule_id, "worker-1", KEY, claimed_at=NOW
            )
        )

    def test_historical_claim_retry_preserves_original_after_expiry_and_cancellation(self) -> None:
        schedule, _, lease = self.claimed()
        self.store.data["schedules"][(schedule.tenant_id, schedule.schedule_id)]["cancelled"] = True
        self.store.data["leases"][(schedule.tenant_id, lease.lease_id, 1)]["active"] = False
        before = copy.deepcopy(self.store.data)
        returned = self.adapter.claim_due(
            schedule.tenant_id,
            schedule.schedule_id,
            "worker-1",
            KEY,
            claimed_at="2026-09-21T12:00:00Z",
        )
        self.assertEqual(returned, lease)
        self.assertEqual(self.store.data, before)

    def test_transaction_replay_requires_full_original_document(self) -> None:
        batch = legacy._batch()
        self.adapter.apply_transaction_receipt(batch)
        alternate = legacy._batch(key="idem:postgresql-alternate-000001", digest=legacy.DIGEST_B)
        self.store.data["batches"][(batch.tenant_ref, batch.idempotency_key)]["batch_json"] = (
            alternate.to_json()
        )
        self.denied_unchanged(lambda: self.adapter.apply_transaction_receipt(batch))

    def test_transaction_projection_matrix(self) -> None:
        batch = legacy._batch()
        self.adapter.apply_transaction_receipt(batch)
        baseline = copy.deepcopy(self.store.data)
        for field, value in (
            ("tenant_ref", "tenantref:tenant-b"),
            ("idempotency_key", "idem:other-key-000001"),
            ("assessment_ref", "assessmentref:other"),
            ("scope_ref", "scoperef:other"),
            ("batch_id", "PTB-" + "F" * 32),
            ("batch_sha256", legacy.DIGEST_B),
        ):
            with self.subTest(field=field):
                self.store.data = copy.deepcopy(baseline)
                self.store.data["batches"][(batch.tenant_ref, batch.idempotency_key)][field] = value
                self.denied_unchanged(lambda: self.adapter.apply_transaction_receipt(batch))

    def test_aggregate_and_fence_native_integer_matrix(self) -> None:
        batch = legacy._batch()
        for value in (True, 1.0, "1", None):
            with self.subTest(value=value):
                self.store.data["aggregates"][(batch.tenant_ref, "aggregateref:assessment-1")] = {
                    "version": value,
                    "content_sha256": legacy.DIGEST_A,
                }
                self.denied_unchanged(
                    lambda: self.adapter.aggregate_version(
                        batch.tenant_ref, "aggregateref:assessment-1"
                    )
                )
                self.store.data["aggregates"].clear()
                self.store.data["fences"][(batch.tenant_ref, "resourceref:assessment-1")][
                    "fence_epoch"
                ] = value
                self.denied_unchanged(lambda: self.adapter.apply_transaction_receipt(batch))

    def test_native_health_indices_and_rowcount_matrix(self) -> None:
        for alias in (True, 1.0, "1", None):
            with self.subTest(alias=alias):
                self.store.transforms["health"] = lambda cursor, parameters, value=alias: setattr(
                    cursor, "rows", [{"health": value}]
                )
                self.denied_unchanged(lambda: self.adapter.observe_health(observed_at=NOW))
        self.store.transforms.clear()
        schedule, _ = self.seeded()
        for alias in (False, 0.0, "0", None):
            with self.subTest(index=alias):
                self.store.transforms["occurrence-indices"] = (
                    lambda cursor, parameters, value=alias: setattr(
                        cursor, "rows", [{"occurrence_index": value}]
                    )
                )
                self.denied_unchanged(
                    lambda: self.adapter.materialize_due(
                        schedule.tenant_id, schedule.schedule_id, evaluated_at=NOW
                    )
                )
        self.store.transforms.clear()
        for tag in ("aggregate-upsert", "occurrence-claim"):
            self.store.transforms[tag] = lambda cursor, parameters: setattr(
                cursor, "rowcount", True
            )
            if tag == "aggregate-upsert":
                self.denied_unchanged(
                    lambda: self.adapter.apply_transaction_receipt(legacy._batch())
                )
            else:
                self.denied_unchanged(
                    lambda: self.adapter.claim_due(
                        schedule.tenant_id, schedule.schedule_id, "worker-1", KEY, claimed_at=NOW
                    )
                )
            self.store.transforms.clear()

    def test_receipt_schema_and_version_aliases_rejected(self) -> None:
        receipt = self.adapter.apply_transaction_receipt(legacy._batch())
        health = self.adapter.observe_health(observed_at=NOW)
        for original in (receipt.to_dict(), health.to_dict()):
            for alias in (True, 1.0):
                with self.subTest(kind=original["kind"], alias=alias):
                    document = copy.deepcopy(original)
                    document["schema_version"] = alias
                    with self.assertRaises(PostgreSQLAdapterError):
                        parse_receipt(document)
        with self.assertRaises(PostgreSQLAdapterError):
            replace(receipt, aggregate_versions=(("aggregateref:assessment-1", True),))
        with self.assertRaises(PostgreSQLAdapterError):
            PostgreSQLRuntimeConfig(migration_version=True)
        with patch.object(module, "_identity", side_effect=AssertionError("hash reached")):
            with self.assertRaises(PostgreSQLAdapterError):
                replace(receipt, aggregate_versions=(("aggregateref:assessment-1", 1 << 100_000),))

    def test_schedule_and_occurrence_schema_aliases_rejected(self) -> None:
        schedule, occurrence = self.seeded()
        baseline = copy.deepcopy(self.store.data)
        for table, key, field in (
            ("schedules", (schedule.tenant_id, schedule.schedule_id), "schedule_json"),
            ("occurrences", (schedule.tenant_id, occurrence.occurrence_id), "occurrence_json"),
        ):
            for alias in (True, 1.0):
                with self.subTest(table=table, alias=alias):
                    self.store.data = copy.deepcopy(baseline)
                    row = self.store.data[table][key]
                    document = json.loads(row[field])
                    document["schema_version"] = alias
                    row[field] = json.dumps(document, sort_keys=True, separators=(",", ":"))
                    self.denied_unchanged(
                        lambda: self.adapter.claim_due(
                            schedule.tenant_id,
                            schedule.schedule_id,
                            "worker-1",
                            KEY,
                            claimed_at=NOW,
                        )
                    )

    def test_claim_numeric_alias_denied_before_address_replay(self) -> None:
        schedule, _, lease = self.claimed()
        baseline = copy.deepcopy(self.store.data)
        for field in (
            "schema_version",
            "lease_version",
            "attempt_number",
            "fence_epoch",
            "expected_occurrence_version",
        ):
            for alias in (True, 1.0):
                with self.subTest(field=field, alias=alias):
                    self.store.data = copy.deepcopy(baseline)
                    document = lease.to_dict()
                    document[field] = alias
                    row = self.store.data["scheduler_results"][(schedule.tenant_id, KEY)]
                    row["result_json"] = json.dumps(document, separators=(",", ":"), sort_keys=True)
                    # The unchanged address must not mask the primitive boundary.
                    with patch.object(
                        DurableLease, "from_dict", side_effect=AssertionError("replay reached")
                    ):
                        self.denied_unchanged(
                            lambda: self.adapter.claim_due(
                                schedule.tenant_id,
                                schedule.schedule_id,
                                "worker-1",
                                KEY,
                                claimed_at=NOW,
                            )
                        )

    def test_malformed_stored_json_is_bounded_and_rejected(self) -> None:
        schedule = self.adapter.register_schedule(legacy._schedule())
        row = self.store.data["schedules"][(schedule.tenant_id, schedule.schedule_id)]
        for value in (None, "{", '{"schema_version":1,"schema_version":1}', " " * (1_048_576 + 1)):
            with self.subTest(
                shape=type(value).__name__, size=len(value) if isinstance(value, str) else None
            ):
                row["schedule_json"] = value
                self.denied_unchanged(
                    lambda: self.adapter.materialize_due(
                        schedule.tenant_id, schedule.schedule_id, evaluated_at=NOW
                    )
                )

    def test_valid_original_goldens_and_replays_are_unchanged(self) -> None:
        receipt = self.adapter.apply_transaction_receipt(legacy._batch())
        health = self.adapter.observe_health(observed_at=NOW)
        schedule, occurrence, lease = self.claimed()
        actual = (
            (receipt.receipt_id, receipt.receipt_sha256),
            (health.observation_id, health.observation_sha256),
            (schedule.schedule_id, schedule.schedule_sha256),
            (occurrence.occurrence_id, occurrence.occurrence_sha256),
            (lease.lease_id, lease.lease_sha256),
        )
        self.assertEqual(
            actual,
            (
                (
                    "PGR-E082AD1E3F41894B367882632CFF85B7",
                    "sha256:e082ad1e3f41894b367882632cff85b78560482e24347057d004b4ff04a79c2c",
                ),
                (
                    "PGH-39CA5D9D1138BEA6DE070E73E4EE0F47",
                    "sha256:39ca5d9d1138bea6de070e73e4ee0f47cef9bee2a0bc9225b023c2b79d0ed89e",
                ),
                (
                    "DSD-1A7FBBF675CC068798E9F3B76B2701BF",
                    "sha256:1a7fbbf675cc068798e9f3b76b2701bf7ccfab46ee2b0d96463039e938bab024",
                ),
                (
                    "DSO-26017247EE6BB2B4BF5C741679489F4D",
                    "sha256:26017247ee6bb2b4bf5c741679489f4d2a3b2ae668eab533487111de8a0d0bc2",
                ),
                (
                    "DSL-EF5A6982A9A7EAB968324006A467E764",
                    "sha256:c550bd60a8632a8a51ac862f35c46fdadd963c4a558ca255c93b01233926c98d",
                ),
            ),
        )
        self.assertTrue(self.adapter.apply_transaction_receipt(legacy._batch()).replayed)
        self.assertEqual(parse_receipt(receipt.to_dict()), receipt)
        self.assertEqual(parse_receipt(health.to_dict()), health)

    def test_native_tuple_database_rows_preserve_valid_calls(self) -> None:
        def tuples(cursor, parameters):
            columns = cursor.operation.split("SELECT ", 1)[1].split(" FROM ", 1)[0]
            names = [column.strip() for column in columns.split(",")]
            cursor.rows = [tuple(row[name] for name in names) for row in cursor.rows]

        for tag in (
            "migration-identity",
            "transaction-prior",
            "fence-check",
            "aggregate-lock",
            "schedule-prior",
            "schedule-load",
            "occurrence-indices",
            "claim-candidate",
            "scheduler-result",
            "lease-snapshot",
        ):
            self.store.transforms[tag] = tuples
        self.adapter.apply_transaction_receipt(legacy._batch())
        self.assertTrue(self.adapter.apply_transaction_receipt(legacy._batch()).replayed)
        schedule, _, lease = self.claimed()
        self.assertEqual(self.adapter.register_schedule(schedule), schedule)
        self.assertEqual(
            self.adapter.claim_due(
                schedule.tenant_id, schedule.schedule_id, "worker-1", KEY, claimed_at=NOW
            ),
            lease,
        )

    def test_raw_numeric_aliases_and_invalid_inputs_deny_before_factory_or_clock(self) -> None:
        clock = Mock()
        adapter = PostgreSQLPersistenceSchedulerAdapter(self.store.factory, clock=clock)
        for alias in (True, 1.0):
            schedule = legacy._schedule()
            object.__setattr__(schedule, "definition_version", alias)
            with self.assertRaises(PostgreSQLAdapterError):
                adapter.register_schedule(schedule)
        for value in (None, True, 1, ""):
            with self.assertRaises(PostgreSQLAdapterError):
                adapter.materialize_due(value, legacy._schedule().schedule_id)
        with self.assertRaises(PostgreSQLAdapterError):
            adapter.claim_due("tenant-a", legacy._schedule().schedule_id, None, KEY)
        self.assertEqual(self.store.factory_calls, 0)
        clock.now.assert_not_called()

    def test_incomplete_native_wrapper_uses_declared_error(self) -> None:
        with self.assertRaises(PostgreSQLAdapterError):
            self.adapter.register_schedule(object.__new__(type(legacy._schedule())))
        with self.assertRaises(PostgreSQLAdapterError):
            self.adapter.apply_transaction_receipt(object.__new__(type(legacy._batch())))
        self.assertEqual(self.store.factory_calls, 0)

    def test_escaped_shared_graph_budget_denies_before_replay_or_hash(self) -> None:
        schedule = legacy._schedule()
        shared = ['"\\' * 4096] * 512
        object.__setattr__(schedule, "assessment_template_ref", shared)
        with patch.object(
            type(schedule), "from_dict", side_effect=AssertionError("replay reached")
        ):
            with patch.object(module, "canonical_json", side_effect=AssertionError("hash reached")):
                with self.assertRaisesRegex(PostgreSQLAdapterError, "byte bound"):
                    self.adapter.register_schedule(schedule)
        self.assertEqual(self.store.factory_calls, 0)
        with patch.object(module, "canonical_json", side_effect=AssertionError("hash reached")):
            with self.assertRaisesRegex(PostgreSQLAdapterError, "byte bound"):
                parse_receipt({"extra": ["\x7f" * 1024] * 200})

    def test_owned_schedule_not_rebound_by_injected_factory(self) -> None:
        original = legacy._schedule()
        expected = original.to_dict()

        def factory():
            object.__setattr__(original, "tenant_id", "tenant-b")
            object.__setattr__(original, "schedule_sha256", legacy.DIGEST_C)
            return self.store.factory()

        adapter = PostgreSQLPersistenceSchedulerAdapter(factory)
        returned = adapter.register_schedule(original)
        self.assertEqual(returned.to_dict(), expected)
        row = self.store.data["schedules"][(returned.tenant_id, returned.schedule_id)]
        self.assertEqual(json.loads(row["schedule_json"]), expected)

    def test_native_string_aliases_do_not_reach_equality_hooks(self) -> None:
        class Alias(str):
            def __eq__(self, other):
                raise AssertionError("custom equality reached")

            __hash__ = str.__hash__

        schedule, _, _ = self.claimed()
        alias = Alias("claim")
        row = self.store.data["scheduler_results"][(schedule.tenant_id, KEY)]
        row["result_kind"] = alias
        with self.assertRaises(PostgreSQLAdapterError):
            self.adapter.claim_due(
                schedule.tenant_id, schedule.schedule_id, "worker-1", KEY, claimed_at=NOW
            )
        self.assertIs(row["result_kind"], alias)

    def test_rollback_and_cleanup_failures_are_controlled(self) -> None:
        for failure in ("rollback_error", "cursor_close_error", "connection_close_error"):
            with self.subTest(failure=failure):
                self.setUp()
                setattr(self.store, failure, True)
                self.store.failures["transaction-prior"] = legacy.FakeDatabaseError("23505")
                with self.assertRaises(PostgreSQLTerminalError):
                    self.adapter.apply_transaction_receipt(legacy._batch())
                self.assertEqual(self.store.data["batches"], {})
                self.assertEqual(self.store.close_count, 1)

    def test_commit_or_postcommit_cleanup_failure_is_explicitly_uncertain(self) -> None:
        for failure in ("commit_error", "cursor_close_error", "connection_close_error"):
            with self.subTest(failure=failure):
                self.setUp()
                setattr(self.store, failure, True)
                with self.assertRaisesRegex(PostgreSQLTerminalError, "uncertain"):
                    self.adapter.apply_transaction_receipt(legacy._batch())
                self.assertEqual(self.store.factory_calls, 1)
                self.assertEqual(self.store.commit_count, 1)
                self.assertEqual(len(self.store.data["batches"]), 1)


if __name__ == "__main__":
    unittest.main()
