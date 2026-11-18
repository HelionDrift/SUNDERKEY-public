"""Local durable replay behavior with native requests and inert specialist adapters."""

from __future__ import annotations

import copy
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from sunderkey import specialist_cloud_identity_adapters as cloud
from sunderkey import specialist_durable_replay as durable
from sunderkey import specialist_web_api_adapters as web
from sunderkey.store import MissionStore
from tests.agents import test_specialist_cloud_identity_adapters_phase167 as cloud_fixture
from tests.agents import test_specialist_web_api_adapters_phase166 as web_fixture

NOW = datetime(2026, 9, 20, 10, 10, tzinfo=UTC)
NAMESPACE = "replayns:synthetic-specialists"
TENANT = "tenantref:acme"


class NativeStringAlias(str):
    pass


class NativeIntegerAlias(int):
    pass


class SpecialistDurableReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sunderkey-specialist-replay-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "replay.sqlite3"
        self.store = self.open_store()

    def open_store(self, *, tenant: str = TENANT, namespace: str = NAMESPACE):
        return durable.SQLiteSpecialistReplayStore(
            self.path, namespace=namespace, tenant_ref=tenant
        )

    def web_guard(self, request, store=None):
        return durable.SQLiteWebApiReplayGuard(
            store or self.store, expected_context=request.context
        )

    def cloud_guard(self, request, store=None):
        return durable.SQLiteCloudIdentityReplayGuard(
            store or self.store, expected_request=request, expected_context=request.context
        )

    def run_web(self, request, adapter, guard):
        return web.execute_specialist_action(
            request,
            expected_context=request.context,
            adapter=adapter,
            replay_guard=guard,
            evaluated_at=NOW,
        )

    def run_cloud(self, request, adapter, guard, *, context=None):
        return durable.execute_cloud_identity_with_durable_replay(
            request,
            expected_context=context or request.context,
            adapter=adapter,
            replay_guard=guard,
            evaluated_at=NOW,
        )

    def record_count(self) -> int:
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute("SELECT count(*) FROM specialist_reservations").fetchone()[0]

    def corrupt_record(
        self, assignments: str, values: tuple, *, ignore_checks: bool = False
    ) -> None:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            if ignore_checks:
                connection.execute("PRAGMA ignore_check_constraints=ON")
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name='specialist_reservations_immutable'"
            ).fetchone()[0]
            connection.execute("DROP TRIGGER specialist_reservations_immutable")
            connection.execute("UPDATE specialist_reservations SET " + assignments, values)
            connection.execute(trigger)

    def foreign_hot_journal(self, path: Path) -> tuple[bytes, bytes]:
        child = """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA journal_mode=DELETE')
connection.execute('PRAGMA synchronous=FULL')
connection.execute('PRAGMA cache_size=5')
connection.execute('CREATE TABLE foreign_data(id INTEGER PRIMARY KEY, value TEXT)')
connection.executemany('INSERT INTO foreign_data(value) VALUES (?)', [('a' * 4000,)] * 128)
connection.commit()
connection.execute('BEGIN IMMEDIATE')
connection.execute('UPDATE foreign_data SET value=?', ('b' * 4000,))
os._exit(0)
"""
        subprocess.run(
            [sys.executable, "-B", "-c", child, str(path)],
            check=True,
            capture_output=True,
            timeout=30,
        )
        journal = Path(str(path) + "-journal")
        self.assertTrue(journal.is_file())
        journal_bytes = journal.read_bytes()
        self.assertEqual(journal_bytes[:8], bytes.fromhex("d9d505f920a163d7"))
        return path.read_bytes(), journal_bytes

    def test_existing_fresh_process_guards_demonstrate_the_durability_gap(self) -> None:
        selected = web_fixture.request()
        adapter = web_fixture.FakeAdapter()
        for _ in range(2):
            self.run_web(selected, adapter, web.SpecialistReplayGuard())
        self.assertEqual(len(adapter.calls), 2)
        selected_cloud = cloud_fixture.request()
        cloud_adapter = cloud_fixture.FakeAdapter(selected_cloud)
        for _ in range(2):
            cloud.execute_specialist_action(
                selected_cloud,
                expected_context=selected_cloud.context,
                adapter=cloud_adapter,
                replay_guard=cloud.SpecialistReplayGuard(),
                evaluated_at=NOW,
            )
        self.assertEqual(len(cloud_adapter.calls), 2)

    def test_web_native_success_reopen_and_zero_second_invocation(self) -> None:
        selected = web_fixture.request()
        original = selected.to_dict()
        adapter = web_fixture.FakeAdapter()
        guard = self.web_guard(selected)
        self.assertFalse(guard.contains(selected.idempotency_key))
        receipt = self.run_web(selected, adapter, guard)
        self.assertEqual(receipt.state, web.ResultState.COMPLETED)
        self.assertTrue(guard.contains(selected.idempotency_key))
        with self.assertRaisesRegex(durable.SpecialistDurableReplayError, "already reserved"):
            self.run_web(selected, adapter, self.web_guard(selected, self.open_store()))
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(self.record_count(), 1)
        self.assertEqual(selected.to_dict(), original)

    def test_cloud_native_success_reopen_and_detached_expected_request(self) -> None:
        selected = cloud_fixture.request()
        original = selected.to_dict()
        adapter = cloud_fixture.FakeAdapter(selected)
        guard = self.cloud_guard(selected)
        delivered = guard.expected_request
        self.assertIsNot(delivered, selected)
        self.assertIsNot(delivered.context, selected.context)
        self.assertEqual(delivered.to_dict(), original)
        receipt = self.run_cloud(delivered, adapter, guard)
        self.assertEqual(receipt.state, cloud.ResultState.COMPLETED)
        reopened = self.cloud_guard(selected, self.open_store())
        with self.assertRaisesRegex(durable.SpecialistDurableReplayError, "already reserved"):
            self.run_cloud(reopened.expected_request, adapter, reopened)
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(self.record_count(), 1)
        self.assertEqual(selected.to_dict(), original)

    def test_cloud_helper_rejects_valid_same_key_different_native_request_before_call(self) -> None:
        selected = cloud_fixture.request()
        changes = (
            replace(
                selected,
                budget=cloud.ExecutionBudget(3, 100, 0, 8),
                request_id="",
                request_sha256="",
            ),
            replace(selected, expires_at="2026-09-20T10:29:00Z", request_id="", request_sha256=""),
            cloud_fixture.request(
                selected_context=cloud_fixture.context(action="different-action")
            ),
        )
        for altered in changes:
            with self.subTest(request_id=altered.request_id):
                self.assertEqual(altered.idempotency_key, selected.idempotency_key)
                adapter = cloud_fixture.FakeAdapter(altered)
                adapter.restoration_calls = []
                original_execute = adapter.execute

                def execute_and_restore(
                    request, execute=original_execute, selected_adapter=adapter
                ):
                    observation = execute(request)
                    selected_adapter.restoration_calls.append(request.request_id)
                    return observation

                adapter.execute = execute_and_restore
                with self.assertRaisesRegex(durable.SpecialistDurableReplayError, "Actual cloud"):
                    self.run_cloud(altered, adapter, self.cloud_guard(selected))
                self.assertEqual(adapter.calls, [])
                self.assertEqual(adapter.restoration_calls, [])
                self.assertEqual(self.record_count(), 0)

    def test_cloud_helper_rejects_alternate_valid_expected_context(self) -> None:
        selected = cloud_fixture.request()
        adapter = cloud_fixture.FakeAdapter(selected)
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_cloud(
                selected,
                adapter,
                self.cloud_guard(selected),
                context=cloud_fixture.context(action="different-context"),
            )
        self.assertEqual(adapter.calls, [])
        self.assertEqual(self.record_count(), 0)

    def test_cloud_string_facade_has_only_its_existing_key_correlation(self) -> None:
        selected = cloud_fixture.request()
        guard = self.cloud_guard(selected)
        with self.assertRaisesRegex(durable.SpecialistDurableReplayError, "reserve key"):
            guard.reserve("idem:unrelated-request")
        self.assertEqual(self.record_count(), 0)
        guard.reserve(selected.idempotency_key)
        with self.assertRaises(durable.SpecialistDurableReplayError):
            guard.reserve(selected.idempotency_key)
        self.assertTrue(self.store.contains(selected.idempotency_key))

    def test_foreign_tenant_is_rejected_without_invocation(self) -> None:
        selected = web_fixture.request(
            selected_context=replace(web_fixture.context(), tenant_ref="tenantref:foreign")
        )
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.web_guard(selected)
        guard = self.web_guard(web_fixture.request())
        adapter = web_fixture.FakeAdapter()
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_web(selected, adapter, guard)
        cloud_selected = cloud_fixture.request(
            selected_context=cloud_fixture.context(tenant="foreign")
        )
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.cloud_guard(cloud_selected)
        self.assertEqual(adapter.calls, [])
        self.assertEqual(self.record_count(), 0)

    def test_changed_valid_web_context_rejects_before_storage_or_callback(self) -> None:
        selected = web_fixture.request()
        other = web_fixture.request(selected_context=web_fixture.context(target="different-target"))
        adapter = web_fixture.FakeAdapter()
        with self.assertRaisesRegex(durable.SpecialistDurableReplayError, "expected context"):
            self.run_web(other, adapter, self.web_guard(selected))
        self.assertEqual(adapter.calls, [])
        self.assertEqual(self.record_count(), 0)

    def test_same_key_cannot_be_rebound_by_a_new_worker_or_family(self) -> None:
        selected = web_fixture.request()
        self.run_web(selected, web_fixture.FakeAdapter(), self.web_guard(selected))
        other_context = replace(web_fixture.context(), worker_ref="workerref:other-worker")
        other = web_fixture.request(selected_context=other_context)
        adapter = web_fixture.FakeAdapter()
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_web(other, adapter, self.web_guard(other, self.open_store()))
        other_cloud = cloud_fixture.request(idempotency_key=selected.idempotency_key)
        cloud_adapter = cloud_fixture.FakeAdapter(other_cloud)
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_cloud(
                other_cloud, cloud_adapter, self.cloud_guard(other_cloud, self.open_store())
            )
        self.assertEqual(adapter.calls, [])
        self.assertEqual(cloud_adapter.calls, [])
        self.assertEqual(self.record_count(), 1)

    def test_explicit_namespaces_and_tenants_are_partitioned_not_implicitly_selected(self) -> None:
        selected = web_fixture.request()
        self.run_web(selected, web_fixture.FakeAdapter(), self.web_guard(selected))
        another_namespace = self.open_store(namespace="replayns:separately-selected")
        self.assertFalse(another_namespace.contains(selected.idempotency_key))
        self.run_web(
            selected, web_fixture.FakeAdapter(), self.web_guard(selected, another_namespace)
        )
        foreign_store = self.open_store(tenant="tenantref:foreign")
        self.assertFalse(foreign_store.contains(selected.idempotency_key))
        self.assertEqual(self.record_count(), 2)

    def test_independent_competing_workers_allow_only_one_adapter_invocation(self) -> None:
        selected = web_fixture.request()
        adapter = web_fixture.FakeAdapter()
        guards = [self.web_guard(selected, self.open_store()) for _ in range(2)]
        start = threading.Barrier(2)

        def invoke(guard):
            start.wait(timeout=5)
            try:
                self.run_web(selected, adapter, guard)
                return "completed"
            except durable.SpecialistDurableReplayError:
                return "blocked"

        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = list(workers.map(invoke, guards))
        self.assertEqual(len(outcomes), 2)
        self.assertTrue(set(outcomes) <= {"blocked", "completed"})
        completed = outcomes.count("completed")
        reservations = self.record_count()
        self.assertLessEqual(completed, 1)
        self.assertEqual(len(adapter.calls), completed)
        self.assertLessEqual(len(adapter.calls), reservations)
        self.assertLessEqual(reservations, 1)

        # Zero-wait SQLite contention may block both workers without reserving.
        # A fresh sequential call can proceed only when no key was committed.
        fresh = self.web_guard(selected, self.open_store())
        if reservations == 0:
            self.run_web(selected, adapter, fresh)
            self.assertEqual(len(adapter.calls), 1)
            self.assertEqual(self.record_count(), 1)
        else:
            with self.assertRaises(durable.SpecialistDurableReplayError):
                self.run_web(selected, adapter, fresh)
            self.assertEqual(len(adapter.calls), completed)
            self.assertEqual(self.record_count(), 1)

    def test_busy_store_fails_closed_without_automatic_retry(self) -> None:
        selected = web_fixture.request()
        adapter = web_fixture.FakeAdapter()
        guard = self.web_guard(selected)
        with closing(sqlite3.connect(self.path, timeout=0)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")
            with self.assertRaises(durable.SpecialistReplayStorageError):
                self.run_web(selected, adapter, guard)
            self.assertEqual(adapter.calls, [])
            blocker.rollback()
        self.assertEqual(self.record_count(), 0)
        self.run_web(selected, adapter, guard)
        self.assertEqual(len(adapter.calls), 1)

    def test_adapter_exception_preserves_web_reservation_after_reopen(self) -> None:
        selected = web_fixture.request()
        adapter = web_fixture.FakeAdapter()
        original = adapter.execute

        def fail(request):
            original(request)
            raise RuntimeError("inert uncertain adapter outcome")

        adapter.execute = fail
        with self.assertRaises(RuntimeError):
            self.run_web(selected, adapter, self.web_guard(selected))
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_web(selected, adapter, self.web_guard(selected, self.open_store()))
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(self.record_count(), 1)

    def test_invalid_cloud_observation_keeps_reservation(self) -> None:
        selected = cloud_fixture.request()
        adapter = cloud_fixture.FakeAdapter(selected)
        adapter.overrides["operations_performed"] = 5
        with self.assertRaises(cloud.CloudIdentityAdapterError):
            self.run_cloud(selected, adapter, self.cloud_guard(selected))
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_cloud(selected, adapter, self.cloud_guard(selected, self.open_store()))
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(self.record_count(), 1)

    def test_lost_local_commit_ack_keeps_key_without_invocation(self) -> None:
        selected = web_fixture.request()
        adapter = web_fixture.FakeAdapter()
        guard = self.web_guard(selected)
        connect = sqlite3.connect

        class LostAcknowledgement:
            def __init__(self, connection):
                object.__setattr__(self, "connection", connection)

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def __setattr__(self, name, value):
                setattr(self.connection, name, value)

            def commit(self):
                self.connection.commit()
                raise sqlite3.OperationalError("inert commit acknowledgement lost")

        with (
            patch.object(
                durable.sqlite3,
                "connect",
                side_effect=lambda *a, **kw: LostAcknowledgement(connect(*a, **kw)),
            ),
            self.assertRaises(durable.SpecialistReplayStorageError),
        ):
            self.run_web(selected, adapter, guard)
        self.assertEqual(adapter.calls, [])
        self.assertEqual(self.record_count(), 1)
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_web(selected, adapter, self.web_guard(selected, self.open_store()))
        self.assertEqual(adapter.calls, [])

    def test_storage_schema_and_metadata_guards_are_immutable(self) -> None:
        selected = web_fixture.request()
        self.run_web(selected, web_fixture.FakeAdapter(), self.web_guard(selected))
        statements = (
            "UPDATE specialist_reservations SET family='cloud_identity'",
            "DELETE FROM specialist_reservations",
            "UPDATE replay_metadata SET format='different'",
            "DELETE FROM replay_metadata",
            "INSERT OR REPLACE INTO replay_metadata SELECT * FROM replay_metadata",
            "INSERT OR REPLACE INTO specialist_reservations SELECT * FROM specialist_reservations",
        )
        with closing(sqlite3.connect(self.path)) as connection, connection:
            for statement in statements:
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement)
        self.assertTrue(self.store.contains(selected.idempotency_key))

    def test_corrupt_record_rejects_even_when_exact_sql_schema_is_restored(self) -> None:
        selected = web_fixture.request()
        self.run_web(selected, web_fixture.FakeAdapter(), self.web_guard(selected))
        self.corrupt_record("context_sha256=?", ("sha256:" + "f" * 64,))
        with self.assertRaises(durable.SpecialistReplayStorageError):
            self.store.contains(selected.idempotency_key)
        adapter = web_fixture.FakeAdapter()
        with self.assertRaises(durable.SpecialistReplayStorageError):
            self.run_web(selected, adapter, self.web_guard(selected, self.open_store()))
        self.assertEqual(adapter.calls, [])

    def test_oversized_corrupt_projection_is_bounded_before_json_decode(self) -> None:
        selected = web_fixture.request()
        self.run_web(selected, web_fixture.FakeAdapter(), self.web_guard(selected))
        self.corrupt_record(
            "model_json=?", ("x" * (durable.MAX_DOCUMENT_BYTES + 1),), ignore_checks=True
        )
        with (
            patch.object(durable.json, "loads") as decode,
            self.assertRaises(durable.SpecialistReplayStorageError),
        ):
            self.store.contains(selected.idempotency_key)
        decode.assert_not_called()

    def test_duplicate_json_and_native_aliases_in_stored_projection_fail_closed(self) -> None:
        for corrupt in ("duplicate", "bool_integer", "float_integer"):
            with self.subTest(corrupt=corrupt):
                selected = web_fixture.request(idempotency_key="idem:stored-probe-" + corrupt)
                self.run_web(selected, web_fixture.FakeAdapter(), self.web_guard(selected))
                with closing(sqlite3.connect(self.path)) as connection:
                    document = connection.execute(
                        "SELECT model_json FROM specialist_reservations WHERE idempotency_key=?",
                        (selected.idempotency_key,),
                    ).fetchone()[0]
                if corrupt == "duplicate":
                    changed = document.replace(
                        '{"approval":', '{"idempotency_key":"idem:duplicate-key","approval":', 1
                    )
                elif corrupt == "bool_integer":
                    changed = document.replace('"max_redirects":2', '"max_redirects":true', 1)
                else:
                    changed = document.replace('"max_redirects":2', '"max_redirects":2.0', 1)
                self.corrupt_record("model_json=?", (changed,))
                with self.assertRaises(durable.SpecialistReplayStorageError):
                    self.store.contains(selected.idempotency_key)

    def test_extra_schema_object_and_removed_database_fail_closed(self) -> None:
        selected = web_fixture.request()
        adapter = web_fixture.FakeAdapter()
        guard = self.web_guard(selected)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("CREATE TABLE sqlitex_hidden(value TEXT)")
        with self.assertRaises(durable.SpecialistReplayStorageError):
            self.run_web(selected, adapter, guard)
        self.assertEqual(adapter.calls, [])
        self.path.unlink()
        with self.assertRaises(durable.SpecialistReplayStorageError):
            guard.contains(selected.idempotency_key)
        self.assertFalse(self.path.exists())

    def test_existing_unknown_database_is_not_initialized_or_rewritten(self) -> None:
        unknown = Path(self.temporary.name) / "unknown.sqlite3"
        with closing(sqlite3.connect(unknown)) as connection, connection:
            connection.execute("CREATE TABLE owner_data(value TEXT)")
            connection.execute("INSERT INTO owner_data VALUES('preserved')")
        before = unknown.read_bytes()
        with self.assertRaises(durable.SpecialistReplayStorageError):
            durable.SQLiteSpecialistReplayStore(unknown, namespace=NAMESPACE, tenant_ref=TENANT)
        self.assertEqual(unknown.read_bytes(), before)

    def test_existing_wrong_markers_or_unknown_schema_are_not_adopted(self) -> None:
        for case, statement in (
            ("application", "PRAGMA application_id=12345"),
            ("version", "PRAGMA user_version=2"),
            ("object", "CREATE TABLE unknown_state(value TEXT)"),
        ):
            with self.subTest(case=case):
                path = Path(self.temporary.name) / (case + ".sqlite3")
                durable.SQLiteSpecialistReplayStore(path, namespace=NAMESPACE, tenant_ref=TENANT)
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(statement)
                before = path.read_bytes()
                with self.assertRaises(durable.SpecialistReplayStorageError):
                    durable.SQLiteSpecialistReplayStore(
                        path, namespace=NAMESPACE, tenant_ref=TENANT
                    )
                self.assertEqual(path.read_bytes(), before)

    def test_actual_mission_store_and_existing_empty_database_are_preserved(self) -> None:
        mission_path = Path(self.temporary.name) / "mission.sqlite3"
        MissionStore(mission_path).initialize()
        empty_path = Path(self.temporary.name) / "empty.sqlite3"
        with closing(sqlite3.connect(empty_path)) as connection:
            connection.execute("PRAGMA user_version=0")
        for path in (mission_path, empty_path):
            with self.subTest(path=path.name):
                before = path.read_bytes()
                with closing(sqlite3.connect(path)) as connection:
                    logical_before = tuple(connection.iterdump())
                with self.assertRaises(durable.SpecialistReplayStorageError):
                    durable.SQLiteSpecialistReplayStore(
                        path, namespace=NAMESPACE, tenant_ref=TENANT
                    )
                self.assertEqual(path.read_bytes(), before)
                with closing(sqlite3.connect(path)) as connection:
                    self.assertEqual(tuple(connection.iterdump()), logical_before)

    def test_foreign_database_is_checked_before_any_write_pragma(self) -> None:
        foreign = Path(self.temporary.name) / "foreign.sqlite3"
        with closing(sqlite3.connect(foreign)) as connection, connection:
            connection.execute("CREATE TABLE foreign_data(value TEXT)")
        before = foreign.read_bytes()
        traced = []
        connect = sqlite3.connect

        def traced_connect(*arguments, **keywords):
            connection = connect(*arguments, **keywords)
            connection.set_trace_callback(traced.append)
            return connection

        with (
            patch.object(durable.sqlite3, "connect", side_effect=traced_connect),
            self.assertRaises(durable.SpecialistReplayStorageError),
        ):
            durable.SQLiteSpecialistReplayStore(foreign, namespace=NAMESPACE, tenant_ref=TENANT)
        write_pragmas = [
            statement
            for statement in traced
            if statement.upper().startswith("PRAGMA") and "=" in statement
        ]
        self.assertEqual(write_pragmas, [])
        self.assertEqual(foreign.read_bytes(), before)

    def test_foreign_hot_journal_recovery_control_and_read_only_constructor_preservation(
        self,
    ) -> None:
        legacy = Path(self.temporary.name) / "legacy-hot.sqlite3"
        legacy_before, _ = self.foreign_hot_journal(legacy)
        legacy_journal = Path(str(legacy) + "-journal")
        # The prior rw identity query performs SQLite recovery before it can
        # refuse the foreign application. This control uses real SQLite, not
        # a replacement constructor or an authorizing stub.
        with closing(sqlite3.connect(legacy.as_uri() + "?mode=rw", uri=True)) as connection:
            self.assertEqual(connection.execute("PRAGMA application_id").fetchone()[0], 0)
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM foreign_data WHERE value=?", ("a" * 4000,)
                ).fetchone()[0],
                128,
            )
        self.assertNotEqual(legacy.read_bytes(), legacy_before)
        self.assertFalse(legacy_journal.exists())

        foreign = Path(self.temporary.name) / "preserved-hot.sqlite3"
        before, journal_before = self.foreign_hot_journal(foreign)
        journal = Path(str(foreign) + "-journal")
        connect = sqlite3.connect
        calls = []
        traced = []

        def observed_connect(database, *arguments, **keywords):
            calls.append(database)
            connection = connect(database, *arguments, **keywords)
            connection.set_trace_callback(traced.append)
            return connection

        with patch.object(durable.sqlite3, "connect", observed_connect):
            with self.assertRaisesRegex(
                durable.SpecialistReplayStorageError, "read-only preflight"
            ):
                durable.SQLiteSpecialistReplayStore(foreign, namespace=NAMESPACE, tenant_ref=TENANT)
        self.assertEqual(calls, [foreign.as_uri() + "?mode=ro"])
        self.assertFalse(
            any(statement.upper().startswith("PRAGMA") and "=" in statement for statement in traced)
        )
        self.assertEqual(foreign.read_bytes(), before)
        self.assertEqual(journal.read_bytes(), journal_before)

        selected = web_fixture.request()
        adapter = web_fixture.FakeAdapter()
        self.run_web(selected, adapter, self.web_guard(selected, self.open_store()))
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(self.record_count(), 1)

    def test_existing_writer_refuses_foreign_hot_journal_before_rw_open_or_callback(self) -> None:
        preserved_owned = Path(self.temporary.name) / "preserved-owned.sqlite3"
        owned_bytes = self.path.read_bytes()
        self.path.rename(preserved_owned)
        before, journal_before = self.foreign_hot_journal(self.path)
        journal = Path(str(self.path) + "-journal")
        selected = web_fixture.request()
        adapter = web_fixture.FakeAdapter()
        guard = self.web_guard(selected)
        connect = sqlite3.connect
        calls = []

        def observed_connect(database, *arguments, **keywords):
            calls.append(database)
            return connect(database, *arguments, **keywords)

        with patch.object(durable.sqlite3, "connect", observed_connect):
            for operation in (
                lambda: guard.contains(selected.idempotency_key),
                lambda: self.run_web(selected, adapter, guard),
            ):
                with self.assertRaises(durable.SpecialistReplayStorageError) as failure:
                    operation()
                self.assertLessEqual(len(str(failure.exception)), 128)
                self.assertEqual(self.path.read_bytes(), before)
                self.assertEqual(journal.read_bytes(), journal_before)
        self.assertEqual(calls, [self.path.as_uri() + "?mode=ro"] * 2)
        self.assertEqual(adapter.calls, [])
        self.assertEqual(preserved_owned.read_bytes(), owned_bytes)

    def test_persistent_wal_rejects_each_owned_connection_without_switching(self) -> None:
        selected = web_fixture.request()
        guard = self.web_guard(selected)
        adapter = web_fixture.FakeAdapter()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        before = self.path.read_bytes()
        with closing(sqlite3.connect(self.path)) as connection:
            logical_before = tuple(connection.iterdump())
        for operation in (
            self.open_store,
            lambda: guard.contains(selected.idempotency_key),
            lambda: self.run_web(selected, adapter, guard),
        ):
            with (
                self.subTest(operation=operation),
                self.assertRaises(durable.SpecialistReplayStorageError),
            ):
                operation()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(tuple(connection.iterdump()), logical_before)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(adapter.calls, [])

    def _race_initialization(self, path: Path, substitute) -> None:
        original_exists = Path.exists
        target_calls = 0
        adapter = web_fixture.FakeAdapter()
        selected = web_fixture.request()

        def racing_exists(candidate):
            nonlocal target_calls
            observed = original_exists(candidate)
            if candidate == path and not observed:
                target_calls += 1
                if target_calls == 2:
                    substitute()
                    return False
            return observed

        with (
            patch.object(durable.Path, "exists", racing_exists),
            self.assertRaises(durable.SpecialistReplayStorageError),
        ):
            store = durable.SQLiteSpecialistReplayStore(
                path, namespace=NAMESPACE, tenant_ref=TENANT
            )
            self.run_web(selected, adapter, self.web_guard(selected, store))
        self.assertEqual(target_calls, 2)
        self.assertEqual(adapter.calls, [])

    def test_absence_race_does_not_adopt_an_empty_foreign_file(self) -> None:
        path = Path(self.temporary.name) / "empty-race.sqlite3"
        captured = []

        def substitute():
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA user_version=0")
            captured.append(path.read_bytes())

        self._race_initialization(path, substitute)
        self.assertEqual(path.read_bytes(), captured[0])
        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(connection.execute("PRAGMA application_id").fetchone()[0], 0)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master").fetchall(), [])

    def test_absence_race_does_not_follow_a_genuine_hardlink_substitution(self) -> None:
        path = Path(self.temporary.name) / "hardlink-race.sqlite3"
        foreign = Path(self.temporary.name) / "hardlink-target.sqlite3"
        foreign.touch()
        self._race_initialization(path, lambda: os.link(foreign, path))
        self.assertEqual(foreign.read_bytes(), b"")
        self.assertEqual(path.read_bytes(), b"")
        self.assertTrue(path.samefile(foreign))

    def test_absence_race_does_not_follow_a_real_final_symlink_when_supported(self) -> None:
        path = Path(self.temporary.name) / "symlink-race.sqlite3"
        foreign = Path(self.temporary.name) / "symlink-target.sqlite3"
        foreign.touch()
        probe = Path(self.temporary.name) / "symlink-support"
        try:
            probe.symlink_to(foreign)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows final symlink fixture requires unavailable privilege")
            raise
        probe.unlink()
        self._race_initialization(path, lambda: path.symlink_to(foreign))
        self.assertTrue(path.is_symlink())
        self.assertEqual(foreign.read_bytes(), b"")

    def test_mocked_late_symlink_flag_denies_before_sqlite_and_preserves_partial_file(self) -> None:
        path = Path(self.temporary.name) / "mocked-link-race.sqlite3"
        original_is_symlink = Path.is_symlink

        def late_flag(candidate):
            if candidate == path and candidate.exists():
                return True
            return original_is_symlink(candidate)

        with (
            patch.object(durable.Path, "is_symlink", late_flag),
            patch.object(durable.sqlite3, "connect") as connect,
            self.assertRaises(durable.SpecialistReplayStorageError),
        ):
            durable.SQLiteSpecialistReplayStore(path, namespace=NAMESPACE, tenant_ref=TENANT)
        connect.assert_not_called()
        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes(), b"")
        with self.assertRaises(durable.SpecialistReplayStorageError):
            durable.SQLiteSpecialistReplayStore(path, namespace=NAMESPACE, tenant_ref=TENANT)

    def test_missing_parent_is_not_created(self) -> None:
        parent = Path(self.temporary.name) / "not-created"
        with self.assertRaises(durable.SpecialistReplayStorageError):
            durable.SQLiteSpecialistReplayStore(
                parent / "replay.sqlite3", namespace=NAMESPACE, tenant_ref=TENANT
            )
        self.assertFalse(parent.exists())

    def test_ambiguous_and_oversized_paths_reject_before_sqlite(self) -> None:
        root = str(Path(self.temporary.name))
        separator = "\\" if os.name == "nt" else "/"
        cases = [
            "file:" + self.path.as_uri(),
            ":memory:",
            "relative.sqlite3",
            "//foreign/share/replay.sqlite3",
            root + separator + "." + separator + "alias.sqlite3",
            root + separator + ".." + separator + "alias.sqlite3",
            root + separator + "long-" + "x" * 4097,
            root + separator + "line\n.sqlite3",
        ]
        if os.name == "nt":
            cases.extend(
                (
                    "\\\\foreign\\share\\replay.sqlite3",
                    "\\\\?\\" + root + "\\replay.sqlite3",
                    "\\\\.\\NUL",
                    "C:replay.sqlite3",
                    root + "\\replay.sqlite3:stream",
                    root + "\\NUL.sqlite3",
                    root + "\\conin$.sqlite3",
                    root + "\\ambiguous.\\replay.sqlite3",
                    root + "\\ambiguous ",
                    root + "\\\\repeated.sqlite3",
                )
            )
        for path in cases:
            with (
                self.subTest(path=path[:100]),
                patch.object(durable.sqlite3, "connect") as connect,
            ):
                with self.assertRaises(durable.SpecialistDurableReplayError):
                    durable.SQLiteSpecialistReplayStore(
                        path, namespace=NAMESPACE, tenant_ref=TENANT
                    )
                connect.assert_not_called()

    def test_bounded_native_intake_denies_before_json_or_storage(self) -> None:
        selected = copy.deepcopy(web_fixture.request())
        object.__setattr__(selected, "sessions", (selected.sessions[0],) * 257)
        guard = self.web_guard(web_fixture.request())
        with (
            patch.object(durable.json, "dumps") as serialize,
            patch.object(durable.sqlite3, "connect") as connect,
            self.assertRaises(durable.SpecialistDurableReplayError),
        ):
            guard.reserve(selected)
        serialize.assert_not_called()
        connect.assert_not_called()
        self.assertEqual(self.record_count(), 0)

    def test_incomplete_facades_fail_closed_before_sqlite(self) -> None:
        selected = web_fixture.request()
        cloud_selected = cloud_fixture.request()
        with patch.object(durable.sqlite3, "connect") as connect:
            with self.assertRaises(durable.SpecialistDurableReplayError):
                object.__new__(durable.SQLiteWebApiReplayGuard).reserve(selected)
            with self.assertRaises(durable.SpecialistDurableReplayError):
                object.__new__(durable.SQLiteCloudIdentityReplayGuard).reserve(
                    cloud_selected.idempotency_key
                )
            with self.assertRaises(durable.SpecialistDurableReplayError):
                object.__new__(durable.SQLiteSpecialistReplayStore).contains(
                    selected.idempotency_key
                )
        connect.assert_not_called()

    def test_cloud_delivered_request_change_denies_positive_receipt_and_holds_key(self) -> None:
        selected = cloud_fixture.request()
        original_projection = selected.to_dict()
        adapter = cloud_fixture.FakeAdapter(selected)
        execute = adapter.execute

        def mutate_after_observation(delivered):
            observation = execute(delivered)
            object.__setattr__(delivered.budget, "max_resources", 101)
            return observation

        adapter.execute = mutate_after_observation
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_cloud(selected, adapter, self.cloud_guard(selected))
        self.assertEqual(selected.to_dict(), original_projection)
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(self.record_count(), 1)
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_cloud(selected, adapter, self.cloud_guard(selected, self.open_store()))
        self.assertEqual(len(adapter.calls), 1)

    def test_input_model_ownership_and_original_addresses_are_checked(self) -> None:
        for field, value in (("request_id", ""), ("request_sha256", "sha256:" + "f" * 64)):
            selected = web_fixture.request()
            altered = copy.deepcopy(selected)
            object.__setattr__(altered, field, value)
            adapter = web_fixture.FakeAdapter()
            with self.subTest(field=field), self.assertRaises(durable.SpecialistDurableReplayError):
                self.run_web(altered, adapter, self.web_guard(selected))
            self.assertEqual(adapter.calls, [])
        self.assertEqual(self.record_count(), 0)

    def test_native_bool_float_and_subclass_budget_values_reject_before_callback(self) -> None:
        for value in (True, 2.0, NativeIntegerAlias(2)):
            selected = web_fixture.request()
            altered = copy.deepcopy(selected)
            object.__setattr__(altered.budget, "max_redirects", value)
            adapter = web_fixture.FakeAdapter()
            with self.subTest(value=value), self.assertRaises(durable.SpecialistDurableReplayError):
                self.run_web(altered, adapter, self.web_guard(selected))
            self.assertEqual(adapter.calls, [])
        self.assertEqual(self.record_count(), 0)

    def test_cloud_native_aliases_and_borrowed_source_changes_do_not_redefine_capture(self) -> None:
        selected = cloud_fixture.request()
        guard = self.cloud_guard(selected)
        original = guard.expected_request.to_dict()
        object.__setattr__(selected.budget, "max_resources", 99)
        self.assertEqual(guard.expected_request.to_dict(), original)
        adapter = cloud_fixture.FakeAdapter(selected)
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_cloud(selected, adapter, guard)
        for value in (1, "false", NativeIntegerAlias(0)):
            altered = copy.deepcopy(guard.expected_request)
            object.__setattr__(altered, "dry_run", value)
            with self.subTest(value=value), self.assertRaises(durable.SpecialistDurableReplayError):
                self.cloud_guard(altered)
        self.assertEqual(adapter.calls, [])
        self.assertEqual(self.record_count(), 0)

    def test_native_text_and_model_subclasses_are_not_normalized(self) -> None:
        for value in (NativeStringAlias("idem:assessment-44-action-77"), "x" * 513):
            with (
                self.subTest(value_length=len(value)),
                self.assertRaises(durable.SpecialistDurableReplayError),
            ):
                self.store.contains(value)
        selected = web_fixture.request()
        altered = copy.deepcopy(selected)
        object.__setattr__(altered, "evidence_refs", list(altered.evidence_refs))
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.web_guard(selected).reserve(altered)

        class RequestAlias(web.SpecialistActionRequest):
            pass

        alias = RequestAlias(
            **{field: getattr(selected, field) for field in selected.__dataclass_fields__}
        )
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.web_guard(selected).reserve(alias)
        self.assertEqual(self.record_count(), 0)

    def test_invalid_enum_hook_never_runs_during_intake(self) -> None:
        selected = copy.deepcopy(web_fixture.request())
        calls = []

        class ValueHook:
            @property
            def value(self):
                calls.append("normalized")
                return "authz_tenant_role"

        object.__setattr__(selected, "operation", ValueHook())
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.web_guard(web_fixture.request()).reserve(selected)
        self.assertEqual(calls, [])
        self.assertEqual(self.record_count(), 0)

    def test_explicit_configuration_and_late_valid_changes_fail_closed(self) -> None:
        for path, namespace, tenant in (
            ("relative.sqlite3", NAMESPACE, TENANT),
            (":memory:", NAMESPACE, TENANT),
            (self.path, "", TENANT),
            (self.path, NAMESPACE, NativeStringAlias(TENANT)),
        ):
            with (
                self.subTest(path=str(path)),
                self.assertRaises(durable.SpecialistDurableReplayError),
            ):
                durable.SQLiteSpecialistReplayStore(path, namespace=namespace, tenant_ref=tenant)
        selected = web_fixture.request()
        guard = self.web_guard(selected)
        self.store._binding = (str(self.path), "replayns:valid-but-changed", TENANT)
        with self.assertRaises(durable.SpecialistDurableReplayError):
            guard.reserve(selected)
        self.assertEqual(self.record_count(), 0)

    def test_facade_cannot_redirect_to_a_different_valid_store(self) -> None:
        other = self.open_store(namespace="replayns:late-redirect")
        selected = web_fixture.request()
        guard = self.web_guard(selected)
        guard._store = other
        adapter = web_fixture.FakeAdapter()
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_web(selected, adapter, guard)
        cloud_selected = cloud_fixture.request()
        cloud_guard = self.cloud_guard(cloud_selected)
        cloud_guard._store = other
        cloud_adapter = cloud_fixture.FakeAdapter(cloud_selected)
        with self.assertRaises(durable.SpecialistDurableReplayError):
            self.run_cloud(cloud_selected, cloud_adapter, cloud_guard)
        self.assertEqual(adapter.calls, [])
        self.assertEqual(cloud_adapter.calls, [])
        self.assertEqual(self.record_count(), 0)


if __name__ == "__main__":
    unittest.main()
