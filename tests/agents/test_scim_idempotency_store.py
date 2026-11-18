"""Durable local SCIM coordination with genuine inert Phase176 inputs."""

from __future__ import annotations

import copy
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from sunderkey import enterprise_identity_runtime as runtime
from sunderkey import scim_idempotency_store as storage
from sunderkey.enterprise_identity_contracts import canonical_json, canonical_sha256
from sunderkey.store import MissionStore
from tests.agents import test_enterprise_identity_runtime_phase176 as fixture


class ScimIdempotencyStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "scim.sqlite3"
        self.fixture = fixture.EnterpriseIdentityRuntimePhase176Tests(
            "test_scim_dispatch_occurs_once_after_exact_admission"
        )
        # Only construct its native SCIM policy/command values. Do not call
        # the unrelated OIDC key-generating setUpClass.
        self.fixture.setUp()
        self.store = storage.SQLiteScimIdempotencyStore(
            self.path, store_id=fixture.AtomicStore.store_id
        )

    def reopen(self, *, busy_timeout_ms: int = 5000):
        return storage.SQLiteScimIdempotencyStore(
            self.path, store_id=self.store.store_id, busy_timeout_ms=busy_timeout_ms
        )

    def values(self, **changes):
        values = {
            "idempotency_key": self.fixture.command.idempotency_key,
            "command_sha256": self.fixture.command.record_sha256,
            "admission_sha256": self.fixture.admission().admission_sha256,
            "dispatcher_id": fixture.TestDispatcher.dispatcher_id,
            "environment": "staging",
            "reserved_at": fixture.NOW,
        }
        values.update(changes)
        return values

    def dispatch(self, callback, *, store=None, **changes):
        dispatcher = fixture.TestDispatcher(callback)
        outcome = self.fixture.dispatch(
            dispatcher, idempotency_store=store or self.store, **changes
        )
        return outcome, dispatcher

    def counts(self):
        with closing(sqlite3.connect(self.path)) as connection:
            return tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("scim_reservations", "scim_completions")
            )

    def dump(self, path=None):
        with closing(sqlite3.connect(path or self.path)) as connection:
            return tuple(connection.iterdump())

    def document(self, table):
        column = "reservation_json" if table == "scim_reservations" else "completion_json"
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute(f"SELECT {column} FROM {table}").fetchone()[0]

    @contextmanager
    def corrupted_document(self, table, changed):
        before = self.dump()
        column = "reservation_json" if table == "scim_reservations" else "completion_json"
        guard = f"{table}_update_guard"
        original = self.document(table)
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            guard_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name = ?", (guard,)
            ).fetchone()[0]
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(f"DROP TRIGGER {guard}")
            connection.execute(f"UPDATE {table} SET {column} = ?", (changed,))
            connection.execute(guard_sql)
            connection.commit()
        try:
            yield
        finally:
            with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(f"DROP TRIGGER {guard}")
                connection.execute(f"UPDATE {table} SET {column} = ?", (original,))
                connection.execute(guard_sql)
                connection.commit()
            # Dropping and restoring a guard changes only its sqlite_master
            # insertion order, not its exact SQL or any logical custody row.
            self.assertEqual(tuple(sorted(self.dump())), tuple(sorted(before)))

    def test_metadata_pins_identity_and_declares_only_local_coordination(self) -> None:
        self.assertEqual(self.counts(), (0, 0))
        with closing(sqlite3.connect(self.path)) as connection:
            metadata = connection.execute("SELECT * FROM scim_store_metadata").fetchone()
            self.assertEqual(metadata[:4], (1, 1, self.store.store_id, storage.COORDINATION_SCOPE))
            self.assertRegex(metadata[4], r"\Asha256:[0-9a-f]{64}\Z")
        with self.assertRaises(FrozenInstanceError):
            self.store.store_id = "store:other"
        self.assertEqual(self.reopen().store_id, self.store.store_id)

    def test_native_reservation_and_completion_replay_existing_addresses(self) -> None:
        reservation = self.store.reserve(**self.values())
        self.assertIs(type(reservation), runtime.ScimIdempotencyReservation)
        self.assertTrue(
            all(
                type(value) is str
                for key, value in reservation._body().items()
                if key != "schema_version"
            )
        )
        self.assertEqual(self.counts(), (1, 0))
        reservation_raw = json.loads(self.document("scim_reservations"))
        self.assertEqual(
            reservation_raw,
            {
                **reservation._body(),
                "reservation_id": reservation.reservation_id,
                "reservation_sha256": reservation.reservation_sha256,
            },
        )
        result_sha = canonical_sha256(self.fixture.result().to_dict())
        completion = self.store.complete(
            reservation, result_sha256=result_sha, completed_at=fixture.NOW
        )
        expected = runtime.ScimIdempotencyCompletion(
            self.store.store_id, reservation.reservation_sha256, result_sha, fixture.NOW
        )
        self.assertEqual(completion, expected)
        self.assertEqual(self.counts(), (1, 1))
        self.assertEqual(
            self.document("scim_completions"),
            canonical_json(
                {
                    **expected._body(),
                    "completion_id": expected.completion_id,
                    "completion_sha256": expected.completion_sha256,
                }
            ),
        )

    def test_test_environment_and_historic_times_do_not_fabricate_live_authority(self) -> None:
        reservation = self.store.reserve(
            **self.values(environment="test", reserved_at="2000-01-01T00:00:00Z")
        )
        self.assertEqual(reservation.environment, "test")
        completion = self.reopen().complete(
            reservation, result_sha256=fixture.DIGEST_B, completed_at="2001-01-01T00:00:00Z"
        )
        self.assertEqual(completion.completed_at, "2001-01-01T00:00:00Z")
        self.assertIsNone(self.reopen().reserve(**self.values()))
        self.assertEqual(self.counts(), (1, 1))

    def test_genuine_dispatch_receipt_remains_valid_and_secret_free(self) -> None:
        outcome, dispatcher = self.dispatch(lambda _command: self.fixture.result())
        receipt = outcome.receipt
        self.assertEqual(dispatcher.calls, [self.fixture.command.record_sha256])
        self.assertEqual(receipt.dispatch_count, 1)
        self.assertEqual(receipt.status, "dispatched_non_production")
        self.assertEqual(receipt.source_sha256, self.fixture.command.record_sha256)
        self.assertEqual(receipt.admission_sha256, self.fixture.admission().admission_sha256)
        self.assertEqual(receipt.idempotency_store_id, self.store.store_id)
        self.assertEqual(receipt.to_dict()["effects"], runtime.NO_EFFECTS)
        self.assertNotIn("attribute_digests", receipt.to_json())
        self.assertEqual(
            receipt.reservation_sha256,
            json.loads(self.document("scim_reservations"))["reservation_sha256"],
        )
        self.assertEqual(
            receipt.completion_sha256,
            json.loads(self.document("scim_completions"))["completion_sha256"],
        )

    def test_committed_reservation_is_visible_inside_dispatch_callback(self) -> None:
        observed = []

        def callback(_command):
            observed.append(self.counts())
            self.assertIsNone(self.reopen().reserve(**self.values()))
            return self.fixture.result()

        self.dispatch(callback)
        self.assertEqual(observed, [(1, 0)])
        self.assertEqual(self.counts(), (1, 1))

    def test_reopen_denies_duplicate_without_second_dispatch(self) -> None:
        calls = []
        self.dispatch(lambda command: calls.append(command.record_sha256) or self.fixture.result())
        before = self.dump()
        dispatcher = fixture.TestDispatcher(
            lambda command: calls.append(command) or self.fixture.result()
        )
        with self.assertRaisesRegex(
            runtime.EnterpriseIdentityRuntimeError, "reserved or completed"
        ):
            self.fixture.dispatch(dispatcher, idempotency_store=self.reopen())
        self.assertEqual(dispatcher.calls, [])
        self.assertEqual(calls, [self.fixture.command.record_sha256])
        self.assertEqual(self.dump(), before)

    def test_independent_workers_compete_for_one_atomic_reservation(self) -> None:
        stores = (self.reopen(), self.reopen())
        barrier = threading.Barrier(2)

        def worker(store):
            barrier.wait(timeout=10)
            return store.reserve(**self.values())

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker, store) for store in stores]
            results = [future.result(timeout=10) for future in futures]
        self.assertEqual(sum(item is not None for item in results), 1)
        self.assertEqual(self.counts(), (1, 0))

    def test_independent_runtime_workers_dispatch_exactly_once(self) -> None:
        stores = (self.reopen(), self.reopen())
        barrier = threading.Barrier(2)
        calls = []
        lock = threading.Lock()

        def callback(command):
            with lock:
                calls.append(command.record_sha256)
            return self.fixture.result()

        def worker(store):
            dispatcher = fixture.TestDispatcher(callback)
            barrier.wait(timeout=10)
            try:
                self.fixture.dispatch(dispatcher, idempotency_store=store)
            except runtime.EnterpriseIdentityRuntimeError as exc:
                self.assertIn("reserved or completed", str(exc))
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker, store) for store in stores]
            results = [future.result(timeout=10) for future in futures]
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(calls, [self.fixture.command.record_sha256])
        self.assertEqual(self.counts(), (1, 1))

    def test_same_key_changed_binding_cannot_rebind_or_dispatch(self) -> None:
        self.store.reserve(**self.values())
        before = self.dump()
        for field, value in (
            ("command_sha256", fixture.DIGEST_A),
            ("admission_sha256", fixture.DIGEST_B),
            ("dispatcher_id", "dispatcher:other"),
            ("environment", "test"),
            ("reserved_at", "2026-09-20T12:00:01Z"),
        ):
            with self.subTest(field=field):
                self.assertIsNone(self.reopen().reserve(**self.values(**{field: value})))
                self.assertEqual(self.dump(), before)
        self.assertIsNotNone(
            self.store.reserve(**self.values(idempotency_key="idempotency:new-key"))
        )

    def test_all_changed_native_reservation_fields_fail_exact_held_binding(self) -> None:
        reservation = self.store.reserve(**self.values())
        before = self.dump()
        for field, value in (
            ("store_id", "store:other"),
            ("reservation_token", "reservation:other"),
            ("idempotency_key", "idempotency:other"),
            ("command_sha256", fixture.DIGEST_A),
            ("admission_sha256", fixture.DIGEST_B),
            ("dispatcher_id", "dispatcher:other"),
            ("environment", "test"),
            ("reserved_at", "2026-09-20T12:00:01Z"),
        ):
            changed = replace(reservation, **{field: value})
            self.assertNotEqual(changed.reservation_sha256, reservation.reservation_sha256)
            with self.subTest(field=field):
                with self.assertRaises(storage.ScimIdempotencyStoreError):
                    self.reopen().complete(
                        changed, result_sha256=fixture.DIGEST_B, completed_at="2026-09-20T12:00:02Z"
                    )
                self.assertEqual(self.dump(), before)
        self.store.complete(reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)

    def test_late_native_mutation_does_not_rehash_or_replace_held_record(self) -> None:
        reservation = self.store.reserve(**self.values())
        before = self.dump()
        changed = copy.deepcopy(reservation)
        object.__setattr__(changed, "dispatcher_id", "dispatcher:other")
        self.assertEqual(changed.reservation_sha256, reservation.reservation_sha256)
        with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "content address"):
            self.store.complete(changed, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)
        self.assertEqual(self.dump(), before)
        self.assertEqual(reservation.dispatcher_id, fixture.TestDispatcher.dispatcher_id)

    def test_terminal_completion_cannot_be_rebound_or_completed_again(self) -> None:
        reservation = self.store.reserve(**self.values())
        self.store.complete(reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)
        before = self.dump()
        for result, instant in (
            (fixture.DIGEST_B, fixture.NOW),
            (fixture.DIGEST_A, fixture.NOW),
            (fixture.DIGEST_B, "2026-09-20T12:00:01Z"),
        ):
            with self.subTest(result=result, instant=instant):
                with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "already completed"):
                    self.reopen().complete(reservation, result_sha256=result, completed_at=instant)
                self.assertEqual(self.dump(), before)

    def test_missing_reservation_and_impossible_chronology_fail_without_writes(self) -> None:
        reservation = runtime.ScimIdempotencyReservation(
            store_id=self.store.store_id, reservation_token="reservation:unheld", **self.values()
        )
        with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "not held"):
            self.store.complete(
                reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW
            )
        held = self.store.reserve(**self.values())
        before = self.dump()
        with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "chronology"):
            self.store.complete(
                held, result_sha256=fixture.DIGEST_B, completed_at="2026-09-20T11:59:59Z"
            )
        self.assertEqual(self.dump(), before)

    def test_native_bounds_and_production_rejection_precede_reservation(self) -> None:
        before = self.dump()
        for field, value in (
            ("idempotency_key", "x" * 257),
            ("command_sha256", True),
            ("admission_sha256", "sha256:" + "a" * 65),
            ("dispatcher_id", 1.0),
            ("environment", "production"),
            ("environment", 1),
            ("reserved_at", "2026-02-30T12:00:00Z"),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(storage.ScimIdempotencyStoreError):
                    self.store.reserve(**self.values(**{field: value}))
                self.assertEqual(self.dump(), before)
        reservation = self.store.reserve(**self.values())
        for value in (None, reservation._body()):
            with self.assertRaises(storage.ScimIdempotencyStoreError):
                self.store.complete(value, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)
        for result, instant in ((1, fixture.NOW), (fixture.DIGEST_B, False)):
            with self.assertRaises(storage.ScimIdempotencyStoreError):
                self.store.complete(reservation, result_sha256=result, completed_at=instant)

    def test_supported_maximum_identifiers_fit_bounded_canonical_storage(self) -> None:
        reservation = self.store.reserve(
            **self.values(idempotency_key="k" * 256, dispatcher_id="d" * 256)
        )
        self.assertEqual(len(reservation.idempotency_key), 256)
        self.assertLessEqual(len(self.document("scim_reservations")), storage.MAX_RECORD_BYTES)
        self.store.complete(reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)

    def test_adverse_dispatch_keeps_held_key_across_reopen_without_retry(self) -> None:
        def failed(_command):
            raise RuntimeError("inert dispatch failed")

        callbacks = (
            failed,
            lambda _command: object(),
            lambda _command: self.fixture.result(resulting_version=6),
            lambda _command: self.fixture.result(applied=False),
        )
        for index, callback in enumerate(callbacks):
            path = self.directory / f"adverse-{index}.sqlite3"
            store = storage.SQLiteScimIdempotencyStore(path, store_id=self.store.store_id)
            dispatcher = fixture.TestDispatcher(callback)
            with self.subTest(index=index):
                with self.assertRaises(runtime.EnterpriseIdentityRuntimeError):
                    self.fixture.dispatch(dispatcher, idempotency_store=store)
                self.assertEqual(dispatcher.calls, [self.fixture.command.record_sha256])
                reopened = storage.SQLiteScimIdempotencyStore(path, store_id=store.store_id)
                self.assertIsNone(reopened.reserve(**self.values()))
                retry = fixture.TestDispatcher(lambda _command: self.fixture.result())
                with self.assertRaisesRegex(
                    runtime.EnterpriseIdentityRuntimeError, "reserved or completed"
                ):
                    self.fixture.dispatch(retry, idempotency_store=reopened)
                self.assertEqual(retry.calls, [])
                with closing(sqlite3.connect(path)) as connection:
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM scim_reservations").fetchone()[0],
                        1,
                    )
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM scim_completions").fetchone()[0], 0
                    )

    def test_failed_postinsert_reservation_rolls_back_before_dispatch(self) -> None:
        actual = storage.SQLiteScimIdempotencyStore._reservation

        def fail_after_read(store, connection, key):
            value = actual(store, connection, key)
            if value is not None:
                raise storage.ScimIdempotencyStoreError("forced postinsert read failure")
            return value

        dispatcher = fixture.TestDispatcher(lambda _command: self.fixture.result())
        before = self.dump()
        with patch.object(storage.SQLiteScimIdempotencyStore, "_reservation", fail_after_read):
            with self.assertRaisesRegex(
                runtime.EnterpriseIdentityRuntimeError, "reservation failed"
            ):
                self.fixture.dispatch(dispatcher, idempotency_store=self.store)
        self.assertEqual(dispatcher.calls, [])
        self.assertEqual(self.dump(), before)
        self.assertIsNotNone(self.store.reserve(**self.values()))

    def test_failed_postinsert_completion_rolls_back_but_keeps_committed_reservation(self) -> None:
        actual = storage.SQLiteScimIdempotencyStore._completion

        def fail_after_read(store, connection, reservation):
            value = actual(store, connection, reservation)
            if value is not None:
                raise storage.ScimIdempotencyStoreError("forced postinsert read failure")
            return value

        dispatcher = fixture.TestDispatcher(lambda _command: self.fixture.result())
        with patch.object(storage.SQLiteScimIdempotencyStore, "_completion", fail_after_read):
            with self.assertRaisesRegex(
                runtime.EnterpriseIdentityRuntimeError, "completion failed"
            ):
                self.fixture.dispatch(dispatcher, idempotency_store=self.store)
        self.assertEqual(dispatcher.calls, [self.fixture.command.record_sha256])
        self.assertEqual(self.counts(), (1, 0))
        self.assertIsNone(self.reopen().reserve(**self.values()))

    def test_lost_completion_acknowledgement_retains_terminal_key_without_redispatch(self) -> None:
        real_store = self.store

        class LostAcknowledgement:
            store_id = real_store.store_id

            def reserve(self, **values):
                return real_store.reserve(**values)

            def complete(self, reservation, **values):
                real_store.complete(reservation, **values)
                raise RuntimeError("inert acknowledgement lost")

        dispatcher = fixture.TestDispatcher(lambda _command: self.fixture.result())
        with self.assertRaisesRegex(runtime.EnterpriseIdentityRuntimeError, "completion failed"):
            self.fixture.dispatch(dispatcher, idempotency_store=LostAcknowledgement())
        self.assertEqual(dispatcher.calls, [self.fixture.command.record_sha256])
        self.assertEqual(self.counts(), (1, 1))
        retry = fixture.TestDispatcher(lambda _command: self.fixture.result())
        with self.assertRaisesRegex(
            runtime.EnterpriseIdentityRuntimeError, "reserved or completed"
        ):
            self.fixture.dispatch(retry, idempotency_store=self.reopen())
        self.assertEqual(retry.calls, [])

    def test_lost_reservation_acknowledgement_keeps_key_without_dispatch(self) -> None:
        real_store = self.store

        class LostAcknowledgement:
            store_id = real_store.store_id

            def reserve(self, **values):
                real_store.reserve(**values)
                raise RuntimeError("inert acknowledgement lost")

            def complete(self, reservation, **values):
                raise AssertionError("unconfirmed reservation must not complete")

        dispatcher = fixture.TestDispatcher(lambda _command: self.fixture.result())
        with self.assertRaisesRegex(runtime.EnterpriseIdentityRuntimeError, "reservation failed"):
            self.fixture.dispatch(dispatcher, idempotency_store=LostAcknowledgement())
        self.assertEqual(dispatcher.calls, [])
        self.assertEqual(self.counts(), (1, 0))
        self.assertIsNone(self.reopen().reserve(**self.values()))

    def test_bounded_busy_reservation_denies_dispatch_without_mutation(self) -> None:
        store = self.reopen(busy_timeout_ms=1)
        before = self.dump()
        dispatcher = fixture.TestDispatcher(lambda _command: self.fixture.result())
        with closing(sqlite3.connect(self.path, isolation_level=None)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")
            try:
                self.assertIsNone(store.reserve(**self.values()))
                with self.assertRaisesRegex(
                    runtime.EnterpriseIdentityRuntimeError, "reserved or completed"
                ):
                    self.fixture.dispatch(dispatcher, idempotency_store=store)
                self.assertEqual(dispatcher.calls, [])
            finally:
                blocker.rollback()
        self.assertEqual(self.dump(), before)
        self.dispatch(lambda _command: self.fixture.result(), store=store)

    def test_bounded_busy_completion_preserves_held_reservation(self) -> None:
        reservation = self.store.reserve(**self.values())
        store = self.reopen(busy_timeout_ms=1)
        before = self.dump()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")
            try:
                with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "completion failed"):
                    store.complete(
                        reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW
                    )
            finally:
                blocker.rollback()
        self.assertEqual(self.dump(), before)
        store.complete(reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)

    def test_existing_foreign_database_and_mission_store_are_not_adopted(self) -> None:
        foreign = self.directory / "foreign.sqlite3"
        with closing(sqlite3.connect(foreign)) as connection:
            connection.execute("CREATE TABLE unrelated (value TEXT)")
            connection.execute("INSERT INTO unrelated VALUES ('preserved')")
            connection.commit()
        mission = self.directory / "mission.sqlite3"
        MissionStore(mission).initialize()
        for path in (foreign, mission):
            before = self.dump(path)
            with self.subTest(path=path.name):
                with self.assertRaises(storage.ScimIdempotencyStoreError):
                    storage.SQLiteScimIdempotencyStore(path, store_id=self.store.store_id)
                self.assertEqual(self.dump(path), before)

    def test_existing_empty_files_are_read_only_rejections_not_new_stores(self) -> None:
        empty = self.directory / "existing-empty.sqlite3"
        empty.write_bytes(b"")
        empty_database = self.directory / "existing-empty-database.sqlite3"
        with closing(sqlite3.connect(empty_database)) as connection:
            connection.execute("CREATE TABLE removed (value TEXT)")
            connection.execute("DROP TABLE removed")
            connection.commit()
        actual_connect = sqlite3.connect
        for path in (empty, empty_database):
            original_bytes = path.read_bytes()
            original_identity = (path.stat().st_dev, path.stat().st_ino)
            calls = []
            statements = []

            def observe(database, *args, **kwargs):
                calls.append(database)
                connection = actual_connect(database, *args, **kwargs)
                connection.set_trace_callback(statements.append)
                return connection

            with self.subTest(path=path.name):
                with patch.object(storage.sqlite3, "connect", observe):
                    with self.assertRaisesRegex(
                        storage.ScimIdempotencyStoreError, "schema identity"
                    ):
                        storage.SQLiteScimIdempotencyStore(path, store_id=self.store.store_id)
                self.assertEqual(calls, [path.as_uri() + "?mode=ro"])
                self.assertFalse(
                    any(
                        statement.lstrip().startswith("PRAGMA") and "=" in statement
                        for statement in statements
                    )
                )
                self.assertEqual(path.read_bytes(), original_bytes)
                self.assertEqual((path.stat().st_dev, path.stat().st_ino), original_identity)

    def test_existing_valid_store_preflights_read_only_before_writer_configuration(self) -> None:
        actual_connect = sqlite3.connect
        connections = []
        statements = []

        def observe(database, *args, **kwargs):
            index = len(connections)
            connections.append(database)
            connection = actual_connect(database, *args, **kwargs)
            connection.set_trace_callback(lambda statement: statements.append((index, statement)))
            return connection

        before = self.dump()
        with patch.object(storage.sqlite3, "connect", observe):
            self.reopen()
        self.assertEqual(
            connections, [self.path.as_uri() + "?mode=ro", self.path.as_uri() + "?mode=rw"]
        )
        read_only_statements = [statement for index, statement in statements if index == 0]
        self.assertTrue(
            any("FROM scim_store_metadata" in statement for statement in read_only_statements)
        )
        self.assertFalse(
            any(
                statement.lstrip().startswith("PRAGMA") and "=" in statement
                for statement in read_only_statements
            )
        )
        self.assertTrue(
            any(
                index == 1 and statement == "PRAGMA foreign_keys = ON"
                for index, statement in statements
            )
        )
        self.assertEqual(self.dump(), before)

    def test_files_appearing_before_exclusive_creation_are_preserved_not_adopted(self) -> None:
        actual_open = storage.os.open
        for index, payload in enumerate((b"", b"raced-in unrelated file", self.path.read_bytes())):
            target = self.directory / f"raced-{index}.sqlite3"
            observed_flags = []

            def appear_before_open(path, flags, mode=0o777, *, dir_fd=None):
                self.assertEqual(Path(path), target)
                observed_flags.append(flags)
                target.write_bytes(payload)
                return actual_open(path, flags, mode, dir_fd=dir_fd)

            with self.subTest(index=index):
                with patch.object(storage.os, "open", appear_before_open):
                    with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "appeared"):
                        storage.SQLiteScimIdempotencyStore(target, store_id=self.store.store_id)
                self.assertTrue(observed_flags[0] & os.O_CREAT)
                self.assertTrue(observed_flags[0] & os.O_EXCL)
                self.assertEqual(target.read_bytes(), payload)

    def test_file_replacement_after_exclusive_creation_is_detected_before_pragmas(self) -> None:
        actual_connect = sqlite3.connect
        target = self.directory / "replaced-before-open.sqlite3"
        preserved_created_file = self.directory / "preserved-created-file.sqlite3"
        payload = self.path.read_bytes()
        statements = []

        def replace_before_open(database, *args, **kwargs):
            self.assertEqual(database, target.as_uri() + "?mode=rw")
            target.rename(preserved_created_file)
            target.write_bytes(payload)
            connection = actual_connect(database, *args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        with patch.object(storage.sqlite3, "connect", replace_before_open):
            with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "file identity changed"):
                storage.SQLiteScimIdempotencyStore(target, store_id=self.store.store_id)
        self.assertEqual(statements, [])
        self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(preserved_created_file.read_bytes(), b"")

    def test_failed_initialization_preserves_unmarked_file_and_cannot_reinitialize_it(self) -> None:
        target = self.directory / "unconfirmed-initialization.sqlite3"
        actual = storage.SQLiteScimIdempotencyStore._verify_schema

        def fail_after_verification(store, connection):
            actual(store, connection)
            raise storage.ScimIdempotencyStoreError("forced initialization failure")

        with patch.object(
            storage.SQLiteScimIdempotencyStore, "_verify_schema", fail_after_verification
        ):
            with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "forced initialization"):
                storage.SQLiteScimIdempotencyStore(target, store_id=self.store.store_id)
        self.assertTrue(target.exists())
        uncertain_bytes = target.read_bytes()
        with self.assertRaises(storage.ScimIdempotencyStoreError):
            storage.SQLiteScimIdempotencyStore(target, store_id=self.store.store_id)
        self.assertEqual(target.read_bytes(), uncertain_bytes)

    def test_oversized_schema_names_are_sql_bounded_before_python_retrieval(self) -> None:
        oversized_name = "guard_" + "x" * 65536
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            connection.execute("DROP TRIGGER scim_reservations_update_guard")
            connection.execute(
                f'CREATE TRIGGER "{oversized_name}" BEFORE UPDATE ON scim_reservations '
                "BEGIN SELECT RAISE(ABORT, 'SCIM custody is immutable'); END"
            )
        before = self.path.read_bytes()
        fetched = []
        actual_connect = sqlite3.connect

        class ObservedCursor(sqlite3.Cursor):
            def fetchall(self):
                selected = super().fetchall()
                fetched.extend(selected)
                return selected

        class ObservedConnection(sqlite3.Connection):
            def execute(self, sql, parameters=(), /):
                return self.cursor(factory=ObservedCursor).execute(sql, parameters)

        def observe(database, *args, **kwargs):
            return actual_connect(database, *args, factory=ObservedConnection, **kwargs)

        with patch.object(storage.sqlite3, "connect", observe):
            with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "immutable guards"):
                self.reopen()
        self.assertTrue(fetched)
        self.assertTrue(any(row[1] is None for row in fetched))
        self.assertTrue(
            all(
                value is None or (type(value) is str and len(value.encode("utf-8")) <= maximum)
                for row in fetched
                for value, maximum in zip(row, (16, 256, 8192), strict=True)
            )
        )
        self.assertEqual(self.path.read_bytes(), before)

    def test_wrong_markers_store_identity_and_unknown_tables_fail_without_logical_writes(
        self,
    ) -> None:
        before = self.dump()
        with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "store identity"):
            storage.SQLiteScimIdempotencyStore(self.path, store_id="store:other")
        self.assertEqual(self.dump(), before)
        for pragma, value in (("application_id", 1), ("user_version", 2)):
            with closing(sqlite3.connect(self.path)) as connection:
                original = connection.execute(f"PRAGMA {pragma}").fetchone()[0]
                connection.execute(f"PRAGMA {pragma} = {value}")
                connection.commit()
            altered = self.dump()
            try:
                with self.assertRaises(storage.ScimIdempotencyStoreError):
                    self.reopen()
                self.assertEqual(self.dump(), altered)
            finally:
                with closing(sqlite3.connect(self.path)) as connection:
                    connection.execute(f"PRAGMA {pragma} = {original}")
            self.assertEqual(self.dump(), before)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("CREATE TABLE unknown (value TEXT)")
        altered = self.dump()
        with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "unknown schema"):
            self.reopen()
        self.assertEqual(self.dump(), altered)

    def test_invalid_local_paths_and_missing_parent_create_nothing(self) -> None:
        missing = self.directory / "missing" / "scim.sqlite3"
        invalid = [
            missing,
            "relative.sqlite3",
            ":memory:",
            "file:///tmp/scim.sqlite3",
            "https://example.invalid/scim",
            "//server/share/scim.sqlite3",
            "\\\\server\\share\\scim.sqlite3",
            "\\\\?\\C:\\scim.sqlite3",
            "\\\\.\\NUL",
            str(self.directory) + "/../scim.sqlite3",
            str(self.directory) + "/./scim.sqlite3",
            "x" * 4097,
        ]
        if os.name == "nt":
            invalid.extend(
                (
                    self.directory / "NUL.sqlite3",
                    self.directory / "scim.sqlite3:stream",
                    self.directory / "name. ",
                )
            )
        else:
            invalid.append("/dev/null")
        for path in invalid:
            with self.subTest(path=str(path)[:80]):
                with self.assertRaises(storage.ScimIdempotencyStoreError):
                    storage.SQLiteScimIdempotencyStore(path, store_id=self.store.store_id)
        self.assertFalse(missing.parent.exists())
        self.assertEqual({p.name for p in self.directory.iterdir()}, {"scim.sqlite3"})
        for timeout in (True, 1.0, 0, 120001):
            with self.assertRaises(storage.ScimIdempotencyStoreError):
                storage.SQLiteScimIdempotencyStore(
                    self.path, store_id=self.store.store_id, busy_timeout_ms=timeout
                )

    def test_corrupt_database_fails_without_replacing_its_bytes(self) -> None:
        path = self.directory / "corrupt.sqlite3"
        payload = b"not a SQLite database"
        path.write_bytes(payload)
        with self.assertRaises(storage.ScimIdempotencyStoreError):
            storage.SQLiteScimIdempotencyStore(path, store_id=self.store.store_id)
        self.assertEqual(path.read_bytes(), payload)

    def test_changed_persistent_journal_mode_is_not_silently_reset(self) -> None:
        self.store.reserve(**self.values())
        before = self.dump()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode = WAL").fetchone(), ("wal",))
        with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "coordination settings"):
            self.reopen()
        with self.assertRaisesRegex(storage.ScimIdempotencyStoreError, "coordination settings"):
            self.store.reserve(**self.values(idempotency_key="idempotency:new"))
        self.assertEqual(self.dump(), before)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone(), ("wal",))

    def test_stored_reservation_corruption_is_bounded_and_not_repaired(self) -> None:
        reservation = self.store.reserve(**self.values())
        original = self.document("scim_reservations")
        raw = json.loads(original)
        boolean_schema = {**raw, "schema_version": True}
        wrong_binding = {**raw, "dispatcher_id": "dispatcher:other"}
        malformed = (
            canonical_json(boolean_schema),
            json.dumps({**raw, "schema_version": 1.0}, sort_keys=True, separators=(",", ":")),
            canonical_json(wrong_binding),
            original[:-1] + ',"schema_version":1}',
            original + " ",
            "x" * (storage.MAX_RECORD_BYTES + 1),
            "[" * 1100 + "]" * 1100,
        )
        for changed in malformed:
            with self.subTest(changed=changed[:80]):
                with self.corrupted_document("scim_reservations", changed):
                    with self.assertRaises(storage.ScimIdempotencyStoreError):
                        self.reopen().reserve(**self.values())
                    with self.assertRaises(storage.ScimIdempotencyStoreError):
                        self.store.complete(
                            reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW
                        )
        self.store.complete(reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)

    def test_stored_completion_corruption_cannot_become_a_terminal_receipt(self) -> None:
        reservation = self.store.reserve(**self.values())
        self.store.complete(reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)
        original = self.document("scim_completions")
        raw = json.loads(original)
        for changed in (
            canonical_json({**raw, "schema_version": True}),
            json.dumps({**raw, "schema_version": 1.0}, sort_keys=True, separators=(",", ":")),
            canonical_json({**raw, "result_sha256": fixture.DIGEST_A}),
            canonical_json({**raw, "completed_at": "2026-09-20T11:59:59Z"}),
            "x" * (storage.MAX_RECORD_BYTES + 1),
        ):
            with self.corrupted_document("scim_completions", changed):
                with self.assertRaises(storage.ScimIdempotencyStoreError):
                    self.reopen().reserve(**self.values())
                with self.assertRaises(storage.ScimIdempotencyStoreError):
                    self.store.complete(
                        reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW
                    )

    def test_all_custody_tables_reject_ordinary_update_and_delete(self) -> None:
        reservation = self.store.reserve(**self.values())
        self.store.complete(reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)
        before = self.dump()
        with closing(sqlite3.connect(self.path)) as connection:
            for table, column in (
                ("scim_store_metadata", "store_id"),
                ("scim_reservations", "reservation_id"),
                ("scim_completions", "completion_id"),
            ):
                for statement in (
                    f"UPDATE {table} SET {column} = {column}",
                    f"DELETE FROM {table}",
                ):
                    with self.subTest(statement=statement):
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.execute(statement)
        self.assertEqual(self.dump(), before)

    def test_insert_or_replace_cannot_delete_any_existing_custody_with_recursive_triggers_off(
        self,
    ) -> None:
        reservation = self.store.reserve(**self.values())
        self.store.complete(reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW)
        before = self.dump()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            connection.execute("PRAGMA recursive_triggers = OFF")
            self.assertEqual(connection.execute("PRAGMA recursive_triggers").fetchone(), (0,))
            for table in ("scim_store_metadata", "scim_reservations", "scim_completions"):
                row = connection.execute(f"SELECT * FROM {table}").fetchone()
                parameters = ",".join("?" for _value in row)
                with self.subTest(table=table):
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(
                            f"INSERT OR REPLACE INTO {table} VALUES ({parameters})", row
                        )
        self.assertEqual(self.dump(), before)

    def test_insert_guards_close_each_primary_and_unique_replacement_collision(self) -> None:
        reservation = self.store.reserve(**self.values())
        completion = self.store.complete(
            reservation, result_sha256=fixture.DIGEST_B, completed_at=fixture.NOW
        )
        other = self.store.reserve(**self.values(idempotency_key="idempotency:other-held"))
        before = self.dump()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            connection.execute("PRAGMA recursive_triggers = OFF")
            row = connection.execute(
                "SELECT * FROM scim_reservations WHERE idempotency_key = ?",
                (reservation.idempotency_key,),
            ).fetchone()
            replacement_rows = (
                (row[0], "EIRR-" + "F" * 32, fixture.DIGEST_A, row[3]),
                ("idempotency:new", row[1], fixture.DIGEST_A, row[3]),
                ("idempotency:new", "EIRR-" + "F" * 32, row[2], row[3]),
            )
            for index, changed in enumerate(replacement_rows):
                with self.subTest(table="reservations", index=index):
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(
                            "INSERT OR REPLACE INTO scim_reservations VALUES (?, ?, ?, ?)", changed
                        )
            changed_completion = runtime.ScimIdempotencyCompletion(
                self.store.store_id,
                reservation.reservation_sha256,
                fixture.DIGEST_A,
                "2026-09-20T12:00:01Z",
            )
            changed_document = canonical_json(
                {
                    **changed_completion._body(),
                    "completion_id": changed_completion.completion_id,
                    "completion_sha256": changed_completion.completion_sha256,
                }
            )
            replacement_rows = (
                (
                    reservation.reservation_sha256,
                    changed_completion.completion_id,
                    changed_completion.completion_sha256,
                    changed_document,
                ),
                (
                    other.reservation_sha256,
                    completion.completion_id,
                    fixture.DIGEST_A,
                    changed_document,
                ),
                (
                    other.reservation_sha256,
                    "EIRC-" + "F" * 32,
                    completion.completion_sha256,
                    changed_document,
                ),
            )
            for index, changed in enumerate(replacement_rows):
                with self.subTest(table="completions", index=index):
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(
                            "INSERT OR REPLACE INTO scim_completions VALUES (?, ?, ?, ?)", changed
                        )
        self.assertEqual(self.dump(), before)
        self.assertIsNone(self.reopen().reserve(**self.values()))

    def test_removed_database_is_not_silently_recreated(self) -> None:
        self.store.reserve(**self.values())
        preserved = self.directory / "preserved.sqlite3"
        self.path.rename(preserved)
        before = self.dump(preserved)
        with self.assertRaises(storage.ScimIdempotencyStoreError):
            self.store.reserve(**self.values())
        self.assertFalse(self.path.exists())
        self.assertEqual(self.dump(preserved), before)

    def test_original_authentication_and_admission_denials_write_no_reservation(self) -> None:
        before = self.dump()
        dispatcher = fixture.TestDispatcher(lambda _command: self.fixture.result())
        with self.assertRaisesRegex(
            runtime.EnterpriseIdentityRuntimeError, "authentication failed"
        ):
            self.fixture.dispatch(
                dispatcher,
                idempotency_store=self.store,
                admission_verifier=fixture.AdmissionVerifier(authenticated=False),
            )
        expired = self.fixture.admission(
            issued_at="2026-09-20T11:00:00Z", expires_at="2026-09-20T11:30:00Z"
        )
        with self.assertRaisesRegex(runtime.EnterpriseIdentityRuntimeError, "not active"):
            self.fixture.dispatch(dispatcher, idempotency_store=self.store, admission=expired)
        self.assertEqual(dispatcher.calls, [])
        self.assertEqual(self.dump(), before)


if __name__ == "__main__":
    unittest.main()
