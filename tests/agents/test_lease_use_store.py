from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from sunderkey import authorized_target_session_runtime as session
from sunderkey import lease_use_store as leaf
from sunderkey.assessment_transport_contracts import canonical_json
from sunderkey.authorized_target_session_runtime import (
    CredentialSessionProviderFailure,
    LeaseUseReservationEvidence,
    LeaseUseReservationRequest,
    LeaseUseReservationStatus,
    LeaseUseStoreFailure,
    SessionAcquisitionStatus,
    verify_target_session_receipt,
)
from sunderkey.credential_broker_contracts import LeaseMode
from sunderkey.reference_target_session_adapter import InMemoryAtomicLeaseUseStore
from sunderkey.store import MissionStore
from tests.agents import test_authorized_target_session_runtime_phase174 as phase174

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


class StringAlias(str):
    pass


class IntegerAlias(int):
    pass


def request(**changes) -> LeaseUseReservationRequest:
    values = {
        "lease_id": "lease:phase207",
        "lease_sha256": DIGEST_A,
        "lease_binding_sha256": DIGEST_B,
        "lease_use_number": 1,
        "lease_mode": LeaseMode.ONE_TIME,
        "execution_request_id": "request:phase207",
        "execution_request_sha256": DIGEST_A,
        "execution_binding_sha256": DIGEST_B,
        "requested_session_id": "session:phase207",
    }
    values.update(changes)
    return LeaseUseReservationRequest(**values)


def snapshot(path: Path) -> tuple[str, ...]:
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        return tuple(connection.iterdump())


def rows(path: Path, table: str) -> list[tuple]:
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        return connection.execute(f"SELECT * FROM {table}").fetchall()


def tamper(path: Path, table: str, statement: str, values: tuple = ()) -> None:
    """Test-only corruption with guards restored, not a production repair API."""

    with closing(sqlite3.connect(path)) as connection, connection:
        triggers = connection.execute(
            "SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND tbl_name=?",
            (table,),
        ).fetchall()
        for name, _ in triggers:
            connection.execute(f"DROP TRIGGER {name}")
        connection.execute(statement, values)
        for _, sql in triggers:
            connection.execute(sql)


def runtime_fixture() -> phase174.AuthorizedTargetSessionRuntimePhase174Tests:
    fixture = phase174.AuthorizedTargetSessionRuntimePhase174Tests(
        "test_completed_session_is_single_attempt_content_addressed_and_secret_free"
    )
    fixture.setUp()
    return fixture


def foreign_hot_journal(directory: Path) -> tuple[bytes, bytes]:
    """Crash a disposable native SQLite writer after dirty-page spill."""

    path = directory / "foreign-hot.sqlite3"
    script = (
        "import os, sqlite3, sys\n"
        "connection = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
        "connection.execute('PRAGMA journal_mode=DELETE')\n"
        "connection.execute('PRAGMA synchronous=FULL')\n"
        "connection.execute('PRAGMA cache_size=2')\n"
        "connection.execute('CREATE TABLE foreign_data(value TEXT)')\n"
        "connection.executemany('INSERT INTO foreign_data VALUES (?)', "
        "[('before'*1400,)]*80)\n"
        "connection.execute('BEGIN IMMEDIATE')\n"
        "connection.execute('UPDATE foreign_data SET value=?', ('after!'*1400,))\n"
        "os._exit(0)\n"
    )
    subprocess.run([sys.executable, "-B", "-c", script, str(path)], check=True, timeout=10)
    journal = Path(str(path) + "-journal")
    if not journal.is_file() or journal.stat().st_size <= 512:
        raise AssertionError("native crashed fixture has no hot journal")
    return path.read_bytes(), journal.read_bytes()


class LeaseUseStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name).resolve()
        self.path = self.directory / "lease-use.sqlite3"
        self.store = leaf.SQLiteAtomicLeaseUseStore.create(self.path)

    def assert_failure(self, action, code: str | None = None) -> LeaseUseStoreFailure:
        with self.assertRaises(LeaseUseStoreFailure) as raised:
            action()
        if code is not None:
            self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_explicit_creation_and_native_reference_addresses_survive_restart(self) -> None:
        native_request = request()
        reference = InMemoryAtomicLeaseUseStore()
        expected_reservation = reference.reserve(native_request)
        expected_completion = reference.complete(expected_reservation, "completed", True)
        reserved = self.store.reserve(native_request)
        self.assertEqual(reserved, expected_reservation)
        self.assertIsNot(reserved, expected_reservation)
        reopened = leaf.SQLiteAtomicLeaseUseStore(str(self.path))
        completed = reopened.complete(reserved, "completed", True)
        self.assertEqual(completed, expected_completion)
        original = snapshot(self.path)
        for action, code in (
            (lambda: reopened.reserve(native_request), "lease_use_replayed"),
            (lambda: reopened.complete(reserved, "completed", True), "lease_use_already_completed"),
        ):
            self.assert_failure(action, code)
            self.assertEqual(snapshot(self.path), original)
        leaf.SQLiteAtomicLeaseUseStore(self.path)

    def test_owned_schema_and_durability_configuration_are_explicit(self) -> None:
        with self.store._connection(write=False) as connection:
            self.assertEqual(
                connection.execute("PRAGMA application_id").fetchone()[0], leaf.APPLICATION_ID
            )
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0], leaf.SCHEMA_VERSION
            )
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA query_only").fetchone()[0], 1)
            self.assertEqual(
                connection.execute("SELECT count(*) FROM sqlite_schema").fetchone()[0], 16
            )
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("INSERT INTO lease_use_store_identity VALUES(2,'x','y')")

    def test_session_bound_distinct_use_numbers_are_permanently_consumed(self) -> None:
        first = request(lease_mode=LeaseMode.SESSION_BOUND)
        second = replace(first, lease_use_number=2, reservation_key_sha256="")
        reserved = self.store.reserve(first)
        self.store.complete(reserved, "provider_failed", True)
        self.store.reserve(second)
        original = snapshot(self.path)
        reopened = leaf.SQLiteAtomicLeaseUseStore(self.path)
        for consumed in (first, second):
            self.assert_failure(lambda: reopened.reserve(consumed), "lease_use_replayed")
        self.assertEqual(snapshot(self.path), original)

    def test_one_time_and_mode_pin_cannot_be_evaded_by_new_use_number(self) -> None:
        for index, initial_mode in enumerate(LeaseMode):
            with self.subTest(initial_mode=initial_mode):
                path = self.directory / f"mode-{index}.sqlite3"
                store = leaf.SQLiteAtomicLeaseUseStore.create(path)
                initial = request(lease_mode=initial_mode)
                store.reserve(initial)
                original = snapshot(path)
                other_mode = (
                    LeaseMode.SESSION_BOUND
                    if initial_mode is LeaseMode.ONE_TIME
                    else LeaseMode.ONE_TIME
                )
                rebound = replace(
                    initial, lease_mode=other_mode, lease_use_number=2, reservation_key_sha256=""
                )
                self.assert_failure(lambda: store.reserve(rebound), "lease_mode_rebound")
                if initial_mode is LeaseMode.ONE_TIME:
                    repeated = replace(initial, lease_use_number=2, reservation_key_sha256="")
                    self.assert_failure(lambda: store.reserve(repeated), "lease_use_replayed")
                self.assertEqual(snapshot(path), original)

    def test_same_consumed_use_cannot_be_rebound_to_other_context(self) -> None:
        initial = request(lease_mode=LeaseMode.SESSION_BOUND)
        self.store.reserve(initial)
        original = snapshot(self.path)
        for field, value in (
            ("lease_binding_sha256", DIGEST_C),
            ("execution_request_id", "request:other"),
            ("execution_request_sha256", DIGEST_C),
            ("execution_binding_sha256", DIGEST_C),
            ("requested_session_id", "session:other"),
        ):
            with self.subTest(field=field):
                changed = replace(initial, **{field: value, "reservation_key_sha256": ""})
                self.assertNotEqual(changed.reservation_key_sha256, initial.reservation_key_sha256)
                self.assert_failure(lambda: self.store.reserve(changed), "lease_use_replayed")
                self.assertEqual(snapshot(self.path), original)

    def test_distinct_lease_identity_is_not_invented_as_shared_authority(self) -> None:
        initial = request()
        self.store.reserve(initial)
        self.store.reserve(replace(initial, lease_id="lease:other", reservation_key_sha256=""))
        self.store.reserve(replace(initial, lease_sha256=DIGEST_C, reservation_key_sha256=""))
        self.assertEqual(len(rows(self.path, "lease_use_reservations")), 3)

    def test_every_native_request_field_is_revalidated_before_hash_or_connect(self) -> None:
        initial = request()
        original = snapshot(self.path)
        cases = [
            (name, StringAlias(value))
            for name, value in initial.body().items()
            if type(value) is str
        ]
        cases.extend(
            [("reservation_key_sha256", StringAlias(initial.reservation_key_sha256))]
            + [("lease_use_number", value) for value in (True, 1.0, IntegerAlias(1), 0, 101)]
            + [("lease_id", "x" * 257)]
            + [("lease_mode", str.__new__(LeaseMode, "one_time"))]
        )
        for field, value in cases:
            with self.subTest(field=field, value_type=type(value)):
                changed = copy.copy(initial)
                object.__setattr__(changed, field, value)
                with (
                    mock.patch.object(leaf.sqlite3, "connect") as connect,
                    mock.patch.object(session, "_canonical_sha") as hash_value,
                ):
                    self.assert_failure(
                        lambda: self.store.reserve(changed), "invalid_lease_use_metadata"
                    )
                    connect.assert_not_called()
                    hash_value.assert_not_called()
        self.assertEqual(snapshot(self.path), original)

    def test_exact_family_and_incomplete_wrapper_denial_precedes_connection(self) -> None:
        class RequestSubclass(LeaseUseReservationRequest):
            pass

        subclass = RequestSubclass(**request().body())
        for invalid in (request().body(), subclass, object.__new__(LeaseUseReservationRequest)):
            with (
                self.subTest(family=type(invalid)),
                mock.patch.object(leaf.sqlite3, "connect") as connect,
                mock.patch.object(session, "_canonical_sha") as hash_value,
            ):
                self.assert_failure(
                    lambda: self.store.reserve(invalid), "invalid_lease_use_metadata"
                )
                connect.assert_not_called()
                hash_value.assert_not_called()

    def test_native_readdressed_and_stale_request_addresses_are_distinguished(self) -> None:
        changed = copy.copy(request())
        object.__setattr__(changed, "execution_request_id", "request:changed")
        with mock.patch.object(leaf.sqlite3, "connect") as connect:
            self.assert_failure(lambda: self.store.reserve(changed), "invalid_lease_use_metadata")
            connect.assert_not_called()
        coherent = replace(changed, reservation_key_sha256="")
        self.store.reserve(coherent)

    def test_owned_request_snapshot_precedes_connection_hook(self) -> None:
        native_request = request()
        expected = LeaseUseReservationEvidence(native_request.reservation_key_sha256)
        original_connection = self.store._connection

        @contextmanager
        def mutate_after_capture(*, write):
            object.__setattr__(native_request, "execution_request_id", "request:late-mutation")
            with original_connection(write=write) as connection:
                yield connection

        with mock.patch.object(self.store, "_connection", mutate_after_capture):
            actual = self.store.reserve(native_request)
        self.assertEqual(actual, expected)
        stored = json.loads(rows(self.path, "lease_use_reservations")[0][5])
        self.assertEqual(stored["execution_request_id"], "request:phase207")

    def test_native_completion_and_evidence_guards_precede_hash_or_connection(self) -> None:
        reserved = self.store.reserve(request())
        for outcome, called in (
            (StringAlias("completed"), True),
            ("completed", 1),
            ("completed", 1.0),
            ("completed", IntegerAlias(1)),
            ("x" * 65, True),
        ):
            with (
                self.subTest(outcome=outcome, called=called),
                mock.patch.object(leaf.sqlite3, "connect") as connect,
                mock.patch.object(session, "_canonical_sha") as hash_value,
            ):
                self.assert_failure(
                    lambda: self.store.complete(reserved, outcome, called),
                    "invalid_lease_use_metadata",
                )
                connect.assert_not_called()
                hash_value.assert_not_called()
        for field in ("reservation_id", "reservation_sha256", "reservation_key_sha256"):
            invalid = copy.copy(reserved)
            object.__setattr__(invalid, field, StringAlias(getattr(invalid, field)))
            with (
                self.subTest(field=field),
                mock.patch.object(leaf.sqlite3, "connect") as connect,
                mock.patch.object(session, "_canonical_sha") as hash_value,
            ):
                self.assert_failure(
                    lambda: self.store.complete(invalid, "completed", True),
                    "invalid_lease_use_metadata",
                )
                connect.assert_not_called()
                hash_value.assert_not_called()
        with mock.patch.object(leaf.sqlite3, "connect") as connect:
            self.assert_failure(
                lambda: self.store.complete(
                    object.__new__(LeaseUseReservationEvidence), "completed", True
                ),
                "invalid_lease_use_metadata",
            )
            connect.assert_not_called()

    def test_completion_requires_exact_reserved_address_and_denies_duplicate(self) -> None:
        reserved = self.store.reserve(request())
        unrelated = LeaseUseReservationEvidence(DIGEST_C)
        original = snapshot(self.path)
        self.assert_failure(
            lambda: self.store.complete(unrelated, "completed", True), "reservation_not_found"
        )
        self.assertEqual(snapshot(self.path), original)
        completed = self.store.complete(reserved, "completed", True)
        self.assertTrue(completed.provider_called)
        original = snapshot(self.path)
        for outcome, called in (
            ("completed", True),
            ("provider_failed", True),
            ("rejected_before_authentication", False),
        ):
            self.assert_failure(
                lambda: self.store.complete(reserved, outcome, called),
                "lease_use_already_completed",
            )
            self.assertEqual(snapshot(self.path), original)

    def test_zero_call_settlement_preserves_permanent_use_and_native_body(self) -> None:
        native_request = request()
        reserved = self.store.reserve(native_request)
        original = snapshot(self.path)
        self.assert_failure(
            lambda: self.store.complete(reserved, "completed", False), "invalid_lease_use_metadata"
        )
        self.assertEqual(snapshot(self.path), original)
        completed = self.store.complete(reserved, "rejected_before_authentication", False)
        self.assertIs(completed.provider_called, False)
        reference = InMemoryAtomicLeaseUseStore()
        expected = reference.complete(
            reference.reserve(native_request), "rejected_before_authentication", False
        )
        self.assertEqual(completed, expected)
        self.assert_failure(lambda: self.store.reserve(native_request), "lease_use_replayed")

    def test_explicit_create_never_adopts_existing_empty_or_nonempty_files(self) -> None:
        empty = self.directory / "empty.sqlite3"
        empty.touch()
        for path in (self.path, empty):
            before = path.read_bytes()
            self.assert_failure(
                lambda: leaf.SQLiteAtomicLeaseUseStore.create(path), "lease_use_store_create_denied"
            )
            self.assertEqual(path.read_bytes(), before)
        self.assert_failure(
            lambda: leaf.SQLiteAtomicLeaseUseStore(empty), "lease_use_store_identity_mismatch"
        )
        self.assertEqual(empty.read_bytes(), b"")

    def test_foreign_database_is_not_configured_or_changed_before_denial(self) -> None:
        foreign = self.directory / "foreign.sqlite3"
        with closing(sqlite3.connect(foreign)) as connection, connection:
            connection.execute("CREATE TABLE foreign_data(value TEXT)")
            connection.execute("INSERT INTO foreign_data VALUES('must-remain')")
        before = foreign.read_bytes()
        statements = []
        native_connect = sqlite3.connect

        def observed_connect(*args, **kwargs):
            connection = native_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        with mock.patch.object(leaf.sqlite3, "connect", observed_connect):
            self.assert_failure(
                lambda: leaf.SQLiteAtomicLeaseUseStore(foreign), "lease_use_store_identity_mismatch"
            )
        self.assertFalse(
            any(statement.startswith("PRAGMA") and "=" in statement for statement in statements)
        )
        self.assertEqual(foreign.read_bytes(), before)
        self.assert_failure(
            lambda: leaf.SQLiteAtomicLeaseUseStore.create(foreign), "lease_use_store_create_denied"
        )
        self.assertEqual(foreign.read_bytes(), before)

    def test_real_mission_store_is_never_adopted_or_migrated(self) -> None:
        path = self.directory / "mission.sqlite3"
        MissionStore(path).initialize()
        before = snapshot(path)
        self.assert_failure(
            lambda: leaf.SQLiteAtomicLeaseUseStore(path), "lease_use_store_identity_mismatch"
        )
        self.assert_failure(
            lambda: leaf.SQLiteAtomicLeaseUseStore.create(path), "lease_use_store_create_denied"
        )
        self.assertEqual(snapshot(path), before)

    def test_foreign_hot_journal_is_preserved_on_constructor_and_existing_writer(self) -> None:
        foreign_bytes, journal_bytes = foreign_hot_journal(self.directory)
        identity = (self.path.stat().st_dev, self.path.stat().st_ino)
        self.path.write_bytes(foreign_bytes)
        journal = Path(str(self.path) + "-journal")
        journal.write_bytes(journal_bytes)
        self.assertEqual((self.path.stat().st_dev, self.path.stat().st_ino), identity)
        self.assert_failure(lambda: leaf.SQLiteAtomicLeaseUseStore(self.path))
        self.assertEqual(self.path.read_bytes(), foreign_bytes)
        self.assertEqual(journal.read_bytes(), journal_bytes)
        actual_connect = sqlite3.connect
        opened = []
        statements = []

        def observed_connect(database, *args, **keywords):
            opened.append(database)
            connection = actual_connect(database, *args, **keywords)
            connection.set_trace_callback(statements.append)
            return connection

        provider = phase174.FakeProvider()
        with mock.patch.object(leaf.sqlite3, "connect", observed_connect):
            receipt = runtime_fixture().invoke(lease_use_store=self.store, provider=provider)
        self.assertEqual(receipt.status, SessionAcquisitionStatus.REJECTED_BEFORE_AUTHENTICATION)
        self.assertEqual(provider.calls, 0)
        self.assertFalse(receipt.provider_called)
        self.assertEqual(opened, [self.path.as_uri() + "?mode=ro"])
        self.assertFalse(
            any(statement.startswith("PRAGMA") and "=" in statement for statement in statements)
        )
        self.assertEqual(self.path.read_bytes(), foreign_bytes)
        self.assertEqual(journal.read_bytes(), journal_bytes)
        self.assertEqual((self.path.stat().st_dev, self.path.stat().st_ino), identity)

    def test_exclusive_initialization_rejects_foreign_hot_journal_without_writer_open(self) -> None:
        foreign_bytes, journal_bytes = foreign_hot_journal(self.directory)
        path = self.directory / "foreign-during-initialization.sqlite3"
        journal = Path(str(path) + "-journal")
        actual_initialize = leaf.SQLiteAtomicLeaseUseStore._initialize
        actual_connect = sqlite3.connect
        opened = []

        def substitute_before_initialize(selected, timeout, **keywords):
            selected.write_bytes(foreign_bytes)
            journal.write_bytes(journal_bytes)
            return actual_initialize(selected, timeout, **keywords)

        def observed_connect(database, *args, **keywords):
            opened.append(database)
            return actual_connect(database, *args, **keywords)

        with (
            mock.patch.object(
                leaf.SQLiteAtomicLeaseUseStore,
                "_initialize",
                staticmethod(substitute_before_initialize),
            ),
            mock.patch.object(leaf.sqlite3, "connect", observed_connect),
        ):
            self.assert_failure(
                lambda: leaf.SQLiteAtomicLeaseUseStore.create(path),
                "lease_use_store_initialization_failed",
            )
        self.assertEqual(opened, [path.as_uri() + "?mode=ro"])
        self.assertEqual(path.read_bytes(), foreign_bytes)
        self.assertEqual(journal.read_bytes(), journal_bytes)

    def test_in_place_foreign_database_is_read_only_denial_before_writer_open(self) -> None:
        foreign = self.directory / "foreign-in-place.sqlite3"
        with closing(sqlite3.connect(foreign)) as connection, connection:
            connection.execute("CREATE TABLE foreign_data(value TEXT)")
            connection.execute("INSERT INTO foreign_data VALUES('must-remain')")
        identity = (self.path.stat().st_dev, self.path.stat().st_ino)
        foreign_bytes = foreign.read_bytes()
        self.path.write_bytes(foreign_bytes)
        actual_connect = sqlite3.connect
        opened = []

        def observed_connect(database, *args, **keywords):
            opened.append(database)
            return actual_connect(database, *args, **keywords)

        with mock.patch.object(leaf.sqlite3, "connect", observed_connect):
            self.assert_failure(
                lambda: self.store.reserve(request()), "lease_use_store_identity_mismatch"
            )
        self.assertEqual(opened, [self.path.as_uri() + "?mode=ro"])
        self.assertEqual(self.path.read_bytes(), foreign_bytes)
        self.assertEqual((self.path.stat().st_dev, self.path.stat().st_ino), identity)

    def test_every_normal_writer_has_preceding_read_only_preflight(self) -> None:
        path = self.directory / "writer-open-order.sqlite3"
        actual_connect = sqlite3.connect
        opened = []

        def observed_connect(database, *args, **keywords):
            opened.append(database)
            return actual_connect(database, *args, **keywords)

        with mock.patch.object(leaf.sqlite3, "connect", observed_connect):
            store = leaf.SQLiteAtomicLeaseUseStore.create(path)
            reserved = store.reserve(request())
            store.complete(reserved, "completed", True)
        self.assertEqual(
            opened,
            [
                path.as_uri() + "?mode=" + mode
                for mode in ("ro", "rw", "ro", "ro", "rw", "ro", "rw")
            ],
        )

    def test_owned_hot_journal_is_not_automatically_recovered(self) -> None:
        script = (
            "import os, sqlite3, sys\n"
            "from sunderkey.authorized_target_session_runtime import LeaseUseReservationEvidence\n"
            "from sunderkey.assessment_transport_contracts import canonical_json\n"
            "from tests.agents.test_lease_use_store import request\n"
            "connection = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
            "connection.execute('PRAGMA cache_size=2')\n"
            "connection.execute('BEGIN IMMEDIATE')\n"
            "for index in range(128):\n"
            "    candidate = request(lease_id='lease:uncommitted-' + str(index))\n"
            "    evidence = LeaseUseReservationEvidence(candidate.reservation_key_sha256)\n"
            "    document = canonical_json({**candidate.body(), "
            "'reservation_key_sha256': candidate.reservation_key_sha256})\n"
            "    connection.execute('INSERT INTO lease_use_reservations VALUES(?,?,?,?,?,?,?,?)', "
            "(candidate.reservation_key_sha256,candidate.lease_id,candidate.lease_sha256,"
            "candidate.lease_mode.value,candidate.lease_use_number,document,"
            "evidence.reservation_id,evidence.reservation_sha256))\n"
            "os._exit(0)\n"
        )
        subprocess.run([sys.executable, "-B", "-c", script, str(self.path)], check=True, timeout=10)
        journal = Path(str(self.path) + "-journal")
        self.assertTrue(journal.is_file())
        self.assertGreater(journal.stat().st_size, 512)
        database_bytes = self.path.read_bytes()
        journal_bytes = journal.read_bytes()
        self.assert_failure(lambda: self.store.reserve(request()))
        self.assertEqual(self.path.read_bytes(), database_bytes)
        self.assertEqual(journal.read_bytes(), journal_bytes)

    def test_wrong_identity_schema_and_unknown_objects_fail_without_repair(self) -> None:
        for index, statement in enumerate(
            (
                "PRAGMA application_id=1",
                "PRAGMA user_version=2",
                "CREATE TABLE unknown_table(value TEXT)",
                "CREATE INDEX unknown_index ON lease_use_reservations(lease_id)",
                "DROP TRIGGER lease_use_reservation_no_delete",
            )
        ):
            with self.subTest(statement=statement):
                path = self.directory / f"schema-{index}.sqlite3"
                store = leaf.SQLiteAtomicLeaseUseStore.create(path)
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(statement)
                before = snapshot(path)
                self.assert_failure(lambda: leaf.SQLiteAtomicLeaseUseStore(path))
                self.assert_failure(lambda: store.reserve(request()))
                self.assertEqual(snapshot(path), before)

    def test_identity_metadata_is_sql_bounded_before_python_retrieval(self) -> None:
        for index, (column, value) in enumerate(
            (
                ("store_kind", "other-store"),
                ("schema_sha256", DIGEST_C),
                ("store_kind", "x" * 100000),
                ("schema_sha256", b"x" * 100000),
                ("store_kind", "\u00e9" * 129),
            )
        ):
            with self.subTest(column=column, index=index):
                path = self.directory / f"identity-{index}.sqlite3"
                leaf.SQLiteAtomicLeaseUseStore.create(path)
                tamper(
                    path,
                    "lease_use_store_identity",
                    f"UPDATE lease_use_store_identity SET {column}=?",
                    (value,),
                )
                before = snapshot(path)
                self.assert_failure(
                    lambda: leaf.SQLiteAtomicLeaseUseStore(path),
                    "lease_use_store_identity_mismatch",
                )
                with closing(sqlite3.connect(path)) as connection:
                    bounded = connection.execute(
                        f"SELECT CASE WHEN typeof({column})='text' AND "
                        f"length(CAST({column} AS BLOB))<=? THEN {column} END "
                        "FROM lease_use_store_identity",
                        (256 if column == "store_kind" else 71,),
                    ).fetchone()[0]
                if index >= 2:
                    self.assertIsNone(bounded)
                self.assertEqual(snapshot(path), before)

    def test_initialization_failure_retains_file_and_never_reinitializes_it(self) -> None:
        path = self.directory / "uncertain.sqlite3"
        with mock.patch.object(
            leaf.SQLiteAtomicLeaseUseStore,
            "_initialize",
            side_effect=sqlite3.OperationalError("injected initialization failure"),
        ):
            self.assert_failure(
                lambda: leaf.SQLiteAtomicLeaseUseStore.create(path),
                "lease_use_store_initialization_failed",
            )
        self.assertTrue(path.is_file())
        before = path.read_bytes()
        self.assert_failure(
            lambda: leaf.SQLiteAtomicLeaseUseStore.create(path), "lease_use_store_create_denied"
        )
        self.assert_failure(lambda: leaf.SQLiteAtomicLeaseUseStore(path))
        self.assertEqual(path.read_bytes(), before)

    def test_exclusive_descriptor_identity_rejects_raced_empty_file_or_foreign_hardlink(
        self,
    ) -> None:
        actual_initialize = leaf.SQLiteAtomicLeaseUseStore._initialize
        for index, replacement in enumerate(("empty", "foreign-hardlink")):
            with self.subTest(replacement=replacement):
                path = self.directory / f"creation-replaced-{index}.sqlite3"
                preserved = self.directory / f"creation-original-{index}.sqlite3"
                foreign = self.directory / f"creation-foreign-{index}.sqlite3"

                def replace_before_initialize(selected, timeout, **keywords):
                    selected.rename(preserved)
                    if replacement == "empty":
                        selected.touch()
                    else:
                        foreign.touch()
                        os.link(foreign, selected)
                    return actual_initialize(selected, timeout, **keywords)

                with (
                    mock.patch.object(
                        leaf.SQLiteAtomicLeaseUseStore,
                        "_initialize",
                        staticmethod(replace_before_initialize),
                    ),
                    mock.patch.object(leaf.sqlite3, "connect") as connect,
                ):
                    failure = self.assert_failure(
                        lambda: leaf.SQLiteAtomicLeaseUseStore.create(path),
                        "lease_use_store_initialization_failed",
                    )
                    self.assertEqual(failure.__cause__.code, "lease_use_store_identity_changed")
                    connect.assert_not_called()
                self.assertTrue(preserved.is_file())
                self.assertEqual(preserved.read_bytes(), b"")
                self.assertEqual(path.read_bytes(), b"")
                self.assertNotEqual(path.stat().st_ino, preserved.stat().st_ino)
                if replacement == "foreign-hardlink":
                    self.assertEqual(path.stat().st_ino, foreign.stat().st_ino)
                    self.assertEqual(foreign.read_bytes(), b"")
                self.assert_failure(
                    lambda: leaf.SQLiteAtomicLeaseUseStore.create(path),
                    "lease_use_store_create_denied",
                )

    def test_post_sqlite_open_identity_check_precedes_any_pragma_or_schema_read(self) -> None:
        path = self.directory / "creation-replaced-at-connect.sqlite3"
        preserved = self.directory / "creation-original-at-connect.sqlite3"
        actual_connect = sqlite3.connect
        statements = []
        opened = []

        def replace_during_connect(database, *args, **keywords):
            opened.append(database)
            if database.endswith("?mode=rw"):
                path.rename(preserved)
                path.touch()
            connection = actual_connect(database, *args, **keywords)
            if database.endswith("?mode=rw"):
                connection.set_trace_callback(statements.append)
            return connection

        with mock.patch.object(leaf.sqlite3, "connect", replace_during_connect):
            failure = self.assert_failure(
                lambda: leaf.SQLiteAtomicLeaseUseStore.create(path),
                "lease_use_store_initialization_failed",
            )
            self.assertEqual(failure.__cause__.code, "lease_use_store_identity_changed")
        self.assertEqual(opened, [path.as_uri() + "?mode=ro", path.as_uri() + "?mode=rw"])
        self.assertEqual(statements, [])
        self.assertEqual(preserved.read_bytes(), b"")
        self.assertEqual(path.read_bytes(), b"")

    def test_final_reopen_cannot_rebind_to_a_coherent_replacement(self) -> None:
        path = self.directory / "creation-replaced-after-initialize.sqlite3"
        preserved = self.directory / "creation-original-after-initialize.sqlite3"
        actual_initialize = leaf.SQLiteAtomicLeaseUseStore._initialize
        actual_connect = sqlite3.connect
        opened = []

        def replace_after_initialize(selected, timeout, **keywords):
            actual_initialize(selected, timeout, **keywords)
            selected.rename(preserved)
            selected.write_bytes(preserved.read_bytes())

        def observed_connect(database, *args, **keywords):
            opened.append(database)
            return actual_connect(database, *args, **keywords)

        with (
            mock.patch.object(
                leaf.SQLiteAtomicLeaseUseStore,
                "_initialize",
                staticmethod(replace_after_initialize),
            ),
            mock.patch.object(leaf.sqlite3, "connect", observed_connect),
        ):
            failure = self.assert_failure(
                lambda: leaf.SQLiteAtomicLeaseUseStore.create(path),
                "lease_use_store_initialization_failed",
            )
            self.assertEqual(failure.__cause__.code, "lease_use_store_identity_changed")
        self.assertEqual(opened, [path.as_uri() + "?mode=ro", path.as_uri() + "?mode=rw"])
        self.assertNotEqual(path.stat().st_ino, preserved.stat().st_ino)
        self.assertEqual(path.read_bytes(), preserved.read_bytes())
        self.assertGreater(path.stat().st_size, 0)

    def test_exclusive_descriptor_must_be_regular_before_initialization(self) -> None:
        path = self.directory / "creation-invalid-descriptor.sqlite3"
        with (
            mock.patch.object(leaf.os, "fstat", return_value=self.directory.stat()),
            mock.patch.object(leaf.SQLiteAtomicLeaseUseStore, "_initialize") as initialize,
            mock.patch.object(leaf.sqlite3, "connect") as connect,
        ):
            failure = self.assert_failure(
                lambda: leaf.SQLiteAtomicLeaseUseStore.create(path),
                "lease_use_store_initialization_failed",
            )
            self.assertEqual(failure.__cause__.code, "lease_use_store_identity_changed")
            initialize.assert_not_called()
            connect.assert_not_called()
        self.assertEqual(path.read_bytes(), b"")

    def test_absolute_unambiguous_regular_paths_and_native_timeouts_only(self) -> None:
        cases = (
            "relative.sqlite3",
            ":memory:",
            "file:lease.sqlite3",
            self.path.as_uri(),
            r"\\server\share\lease.sqlite3",
            r"\\?\C:\lease.sqlite3",
            str(self.directory) + "/./new.sqlite3",
            str(self.directory) + "/../new.sqlite3",
            str(self.directory / "bad:stream"),
            str(self.directory / "bad.sqlite3 "),
            str(self.directory / "bad.sqlite3."),
            str(self.directory / "missing" / "new.sqlite3"),
            StringAlias(str(self.path)),
            self.directory,
        )
        for value in cases:
            with (
                self.subTest(value=value),
                mock.patch.object(leaf.sqlite3, "connect") as connect,
                mock.patch.object(leaf.os, "open") as open_file,
            ):
                self.assert_failure(
                    lambda: leaf.SQLiteAtomicLeaseUseStore.create(value), "invalid_lease_use_path"
                )
                connect.assert_not_called()
                open_file.assert_not_called()
        for value in (True, 1.0, IntegerAlias(1), -1, 1001):
            with self.subTest(timeout=value), mock.patch.object(leaf.sqlite3, "connect") as connect:
                self.assert_failure(
                    lambda: leaf.SQLiteAtomicLeaseUseStore(self.path, busy_timeout_ms=value),
                    "invalid_lease_use_timeout",
                )
                connect.assert_not_called()
        self.assertFalse((self.directory / "missing").exists())

    def test_unsafe_owned_connection_modes_are_denied_not_reset(self) -> None:
        before = snapshot(self.path)
        for statement in (
            "PRAGMA journal_mode=MEMORY",
            "PRAGMA synchronous=OFF",
            "PRAGMA foreign_keys=OFF",
        ):
            with self.subTest(statement=statement):
                original_connection = self.store._connection

                @contextmanager
                def unsafe_connection(*, write):
                    with original_connection(write=write) as connection:
                        connection.execute(statement)
                        yield connection

                with mock.patch.object(self.store, "_connection", unsafe_connection):
                    self.assert_failure(lambda: self.store.reserve(request()))
                self.assertEqual(snapshot(self.path), before)

    @unittest.skipUnless(os.name == "nt", "Windows lexical device-name rule")
    def test_windows_device_names_are_rejected_without_attempting_to_open_them(self) -> None:
        for name in (
            "CON",
            "NUL.txt",
            "COM1",
            "LPT9",
            "CONIN$",
            "CONOUT$",
            "CLOCK$",
            "COM\u00b9",
            "LPT\u00b2.txt",
        ):
            with (
                self.subTest(name=name),
                mock.patch.object(leaf.sqlite3, "connect") as connect,
                mock.patch.object(leaf.os, "open") as open_file,
            ):
                self.assert_failure(
                    lambda: leaf.SQLiteAtomicLeaseUseStore.create(str(self.directory / name)),
                    "invalid_lease_use_path",
                )
                connect.assert_not_called()
                open_file.assert_not_called()

    def test_persistent_wal_policy_is_rejected_without_journal_conversion(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        before = snapshot(self.path)
        self.assert_failure(
            lambda: leaf.SQLiteAtomicLeaseUseStore(self.path), "lease_use_store_identity_mismatch"
        )
        self.assert_failure(
            lambda: self.store.reserve(request()), "lease_use_store_identity_mismatch"
        )
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(snapshot(self.path), before)

    def test_append_only_guards_reject_update_delete_and_replace_with_recursive_triggers_off(
        self,
    ) -> None:
        reserved = self.store.reserve(request())
        self.store.complete(reserved, "completed", True)
        before = snapshot(self.path)
        for table in (
            "lease_use_store_identity",
            "lease_use_reservations",
            "lease_use_completions",
        ):
            stored = rows(self.path, table)[0]
            count = len(stored)
            column = "store_kind" if table.endswith("identity") else "reservation_id"
            for operation in (
                f"UPDATE {table} SET {column}={column}",
                f"DELETE FROM {table}",
                f"INSERT OR REPLACE INTO {table} VALUES({','.join('?' for _ in range(count))})",
            ):
                with (
                    self.subTest(table=table, operation=operation),
                    closing(sqlite3.connect(self.path)) as connection,
                ):
                    connection.execute("PRAGMA recursive_triggers=OFF")
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(
                            operation, stored if operation.startswith("INSERT") else ()
                        )
                    connection.rollback()
                self.assertEqual(snapshot(self.path), before)

    def test_replacement_guards_cover_every_unique_projection_and_lease_mode(self) -> None:
        reserved = self.store.reserve(request(lease_mode=LeaseMode.SESSION_BOUND))
        self.store.complete(reserved, "completed", True)
        stored = rows(self.path, "lease_use_reservations")[0]
        original = snapshot(self.path)
        for conflict in (0, 6, 7, "number", "mode"):
            changed = list(stored)
            changed[0] = DIGEST_C
            changed[6] = "LUR-" + "C" * 32
            changed[7] = DIGEST_C
            changed[4] = 2
            if type(conflict) is int:
                changed[conflict] = stored[conflict]
            elif conflict == "number":
                changed[4] = stored[4]
            else:
                changed[3] = LeaseMode.ONE_TIME.value
            with self.subTest(conflict=conflict), closing(sqlite3.connect(self.path)) as connection:
                connection.execute("PRAGMA recursive_triggers=OFF")
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT OR REPLACE INTO lease_use_reservations VALUES(?,?,?,?,?,?,?,?)",
                        changed,
                    )
                connection.rollback()
            self.assertEqual(snapshot(self.path), original)
        completed = rows(self.path, "lease_use_completions")[0]
        for conflict in (0, 2):
            changed = ["LUR-" + "D" * 32, completed[1], DIGEST_C]
            changed[conflict] = completed[conflict]
            with (
                self.subTest(completion_conflict=conflict),
                closing(sqlite3.connect(self.path)) as connection,
            ):
                connection.execute("PRAGMA recursive_triggers=OFF")
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT OR REPLACE INTO lease_use_completions VALUES(?,?,?)", changed
                    )
                connection.rollback()
            self.assertEqual(snapshot(self.path), original)

    def test_corrupt_reservation_documents_and_projections_block_all_positive_use(self) -> None:
        native = request()
        body = {**native.body(), "reservation_key_sha256": native.reservation_key_sha256}
        cases = []
        for field, value in (
            ("lease_use_number", True),
            ("lease_use_number", 1.0),
            ("execution_request_id", "request:other"),
            ("reservation_key_sha256", DIGEST_C),
            ("extra", "ignored"),
        ):
            altered = {**body, field: value}
            cases.append(("request_json", canonical_json(altered)))
        cases.extend(
            (
                ("request_json", json.dumps(body, indent=2)),
                ("request_json", canonical_json(body)[:-1] + ',"lease_id":"lease:duplicate"}'),
                ("request_json", b"not-text"),
                ("lease_use_number", 2),
                ("lease_id", "lease:other"),
                ("reservation_id", "LUR-" + "D" * 32),
                ("reservation_sha256", DIGEST_C),
            )
        )
        for index, (column, value) in enumerate(cases):
            with self.subTest(column=column, index=index):
                path = self.directory / f"corrupt-reservation-{index}.sqlite3"
                store = leaf.SQLiteAtomicLeaseUseStore.create(path)
                store.reserve(native)
                tamper(
                    path,
                    "lease_use_reservations",
                    f"UPDATE lease_use_reservations SET {column}=?",
                    (value,),
                )
                before = snapshot(path)
                self.assert_failure(lambda: store.reserve(request(lease_id="lease:unrelated")))
                self.assert_failure(lambda: leaf.SQLiteAtomicLeaseUseStore(path))
                self.assertEqual(snapshot(path), before)

    def test_corrupt_completion_documents_and_reciprocal_addresses_are_denied(self) -> None:
        for index, change in enumerate(
            (
                {"provider_called": 1},
                {"provider_called": 1.0},
                {"completion_sha256": DIGEST_C},
                {"reservation_sha256": DIGEST_C},
                {"reservation_key_sha256": DIGEST_C},
                {"extra": "ignored"},
            )
        ):
            with self.subTest(change=change):
                path = self.directory / f"corrupt-completion-{index}.sqlite3"
                store = leaf.SQLiteAtomicLeaseUseStore.create(path)
                reserved = store.reserve(request())
                completed = store.complete(reserved, "completed", True)
                body = {
                    **completed.body(),
                    "completion_sha256": completed.completion_sha256,
                    **change,
                }
                tamper(
                    path,
                    "lease_use_completions",
                    "UPDATE lease_use_completions SET completion_json=?",
                    (canonical_json(body),),
                )
                before = snapshot(path)
                self.assert_failure(lambda: store.reserve(request(lease_id="lease:unrelated")))
                self.assert_failure(lambda: leaf.SQLiteAtomicLeaseUseStore(path))
                self.assertEqual(snapshot(path), before)

    def test_stored_document_byte_limits_are_enforced_before_json_decode(self) -> None:
        for index, value in enumerate(("x" * (leaf.MAX_DOCUMENT_BYTES + 1), "\u00e9" * 2049)):
            with self.subTest(index=index):
                path = self.directory / f"oversize-{index}.sqlite3"
                store = leaf.SQLiteAtomicLeaseUseStore.create(path)
                store.reserve(request())
                tamper(
                    path,
                    "lease_use_reservations",
                    "UPDATE lease_use_reservations SET request_json=?",
                    (value,),
                )
                with mock.patch.object(leaf.json, "loads") as decode:
                    self.assert_failure(lambda: store.reserve(request(lease_id="lease:other")))
                    decode.assert_not_called()

    def test_readdressed_completion_cannot_substitute_reciprocal_reservation_metadata(self) -> None:
        for index, change in enumerate(
            (
                {"reservation_sha256": DIGEST_C},
                {"reservation_key_sha256": DIGEST_C},
            )
        ):
            with self.subTest(change=change):
                path = self.directory / f"readdressed-completion-{index}.sqlite3"
                store = leaf.SQLiteAtomicLeaseUseStore.create(path)
                reserved = store.reserve(request())
                completed = store.complete(reserved, "completed", True)
                readdressed = replace(completed, **change, completion_sha256="")
                self.assertNotEqual(readdressed.completion_sha256, completed.completion_sha256)
                document = canonical_json(
                    {**readdressed.body(), "completion_sha256": readdressed.completion_sha256}
                )
                tamper(
                    path,
                    "lease_use_completions",
                    "UPDATE lease_use_completions SET completion_json=?,completion_sha256=?",
                    (document, readdressed.completion_sha256),
                )
                before = snapshot(path)
                self.assert_failure(lambda: store.reserve(request(lease_id="lease:unrelated")))
                self.assert_failure(lambda: leaf.SQLiteAtomicLeaseUseStore(path))
                self.assertEqual(snapshot(path), before)

    def test_missing_store_is_not_implicitly_created_on_reopen(self) -> None:
        path = self.directory / "missing.sqlite3"
        with mock.patch.object(leaf.sqlite3, "connect") as connect:
            self.assert_failure(
                lambda: leaf.SQLiteAtomicLeaseUseStore(path), "invalid_lease_use_path"
            )
            connect.assert_not_called()
        self.assertFalse(path.exists())

    def test_separate_python_worker_observes_permanent_committed_use(self) -> None:
        self.store.reserve(request())
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                (
                    "import sys; "
                    "from sunderkey.lease_use_store import SQLiteAtomicLeaseUseStore; "
                    "from sunderkey.authorized_target_session_runtime import LeaseUseStoreFailure; "
                    "from tests.agents.test_lease_use_store import request; "
                    "store = SQLiteAtomicLeaseUseStore(sys.argv[1]);\n"
                    "try: store.reserve(request())\n"
                    "except LeaseUseStoreFailure as failure: print(failure.code)\n"
                    "else: raise SystemExit('unexpected reservation')\n"
                ),
                str(self.path),
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        self.assertEqual(result.stdout.strip(), "lease_use_replayed")
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(rows(self.path, "lease_use_reservations")), 1)

    def test_sqlite_commit_lost_ack_retains_committed_use_and_completion(self) -> None:
        native_connect = sqlite3.connect

        class LostAcknowledgement(sqlite3.Connection):
            def commit(self):
                super().commit()
                raise sqlite3.OperationalError("injected lost acknowledgement after commit")

        def connect_with_lost_ack(*args, **kwargs):
            return native_connect(*args, **kwargs, factory=LostAcknowledgement)

        for index, lost_at in enumerate(("reserve", "complete")):
            with self.subTest(lost_at=lost_at):
                path = self.directory / f"commit-lost-{index}.sqlite3"
                store = leaf.SQLiteAtomicLeaseUseStore.create(path)
                reserved = None if lost_at == "reserve" else store.reserve(request())
                with mock.patch.object(leaf.sqlite3, "connect", connect_with_lost_ack):
                    action = (
                        (lambda: store.reserve(request()))
                        if reserved is None
                        else (lambda: store.complete(reserved, "completed", True))
                    )
                    self.assert_failure(action, "lease_use_store_database_failure")
                reopened = leaf.SQLiteAtomicLeaseUseStore(path)
                self.assert_failure(lambda: reopened.reserve(request()), "lease_use_replayed")
                self.assertEqual(len(rows(path, "lease_use_reservations")), 1)
                self.assertEqual(
                    len(rows(path, "lease_use_completions")), 0 if lost_at == "reserve" else 1
                )
                if reserved is not None:
                    self.assert_failure(
                        lambda: reopened.complete(reserved, "completed", True),
                        "lease_use_already_completed",
                    )

    def test_capacity_is_a_local_cost_limit_without_eviction_or_extra_lease_authority(self) -> None:
        with mock.patch.object(leaf, "MAX_RECORDS", 1):
            reserved = self.store.reserve(request())
            before = snapshot(self.path)
            self.assert_failure(
                lambda: self.store.reserve(request(lease_id="lease:other")),
                "lease_use_store_capacity",
            )
            self.assertEqual(snapshot(self.path), before)
            self.store.complete(reserved, "provider_failed", True)
        self.assertEqual(len(rows(self.path, "lease_use_reservations")), 1)

    def test_bounded_contention_fails_closed_without_retry_or_logical_writes(self) -> None:
        store = leaf.SQLiteAtomicLeaseUseStore(self.path, busy_timeout_ms=20)
        before = snapshot(self.path)
        with closing(sqlite3.connect(self.path, isolation_level=None)) as holder:
            holder.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            self.assert_failure(lambda: store.reserve(request()), "lease_use_store_busy")
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 2)
            self.assertEqual(snapshot(self.path), before)
            holder.rollback()
        store.reserve(request())

    def test_competing_independent_store_workers_commit_only_one_reservation(self) -> None:
        stores = [leaf.SQLiteAtomicLeaseUseStore(self.path, busy_timeout_ms=500) for _ in range(2)]
        barrier = threading.Barrier(2)

        def reserve_once(store):
            barrier.wait(timeout=5)
            try:
                return store.reserve(request())
            except LeaseUseStoreFailure as failure:
                return failure.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(reserve_once, stores))
        self.assertEqual(sum(type(value) is LeaseUseReservationEvidence for value in outcomes), 1)
        self.assertIn("lease_use_replayed", outcomes)
        self.assertEqual(len(rows(self.path, "lease_use_reservations")), 1)

    def test_late_verification_failure_rolls_back_reserve_or_completion(self) -> None:
        original_verify = self.store._verify

        def fail_second():
            calls = 0

            def verify(connection):
                nonlocal calls
                calls += 1
                original_verify(connection)
                if calls == 2:
                    raise LeaseUseStoreFailure("forced_reconciliation_failure")

            return verify

        before = snapshot(self.path)
        with mock.patch.object(self.store, "_verify", fail_second()):
            self.assert_failure(
                lambda: self.store.reserve(request()), "forced_reconciliation_failure"
            )
        self.assertEqual(snapshot(self.path), before)
        reserved = self.store.reserve(request())
        before = snapshot(self.path)
        with mock.patch.object(self.store, "_verify", fail_second()):
            self.assert_failure(
                lambda: self.store.complete(reserved, "completed", True),
                "forced_reconciliation_failure",
            )
        self.assertEqual(snapshot(self.path), before)
        self.assert_failure(lambda: self.store.reserve(request()), "lease_use_replayed")

    def test_runtime_provider_observes_committed_reservation_and_restart_replay_calls_zero(
        self,
    ) -> None:
        fixture = runtime_fixture()
        path = self.path
        test = self

        class Provider(phase174.FakeProvider):
            def acquire(self, command):
                leaf.SQLiteAtomicLeaseUseStore(path)
                test.assertEqual(len(rows(path, "lease_use_reservations")), 1)
                test.assertEqual(rows(path, "lease_use_completions"), [])
                return super().acquire(command)

        provider = Provider()
        completed = fixture.invoke(lease_use_store=self.store, provider=provider)
        self.assertEqual(completed.status, SessionAcquisitionStatus.COMPLETED)
        self.assertEqual(provider.calls, 1)
        verify_target_session_receipt(canonical_json(completed.to_dict()))
        duplicate_provider = phase174.FakeProvider()
        duplicate = fixture.invoke(
            lease_use_store=leaf.SQLiteAtomicLeaseUseStore(self.path), provider=duplicate_provider
        )
        self.assertEqual(duplicate.reason, "lease_use_replayed")
        self.assertEqual(duplicate_provider.calls, 0)
        self.assertEqual(len(rows(self.path, "lease_use_completions")), 1)

    def test_runtime_competing_workers_dispatch_at_most_once(self) -> None:
        fixture = runtime_fixture()
        stores = [leaf.SQLiteAtomicLeaseUseStore(self.path, busy_timeout_ms=500) for _ in range(2)]
        barrier = threading.Barrier(2)

        class Port:
            def __init__(self, store):
                self.store = store

            def reserve(self, native_request):
                barrier.wait(timeout=5)
                return self.store.reserve(native_request)

            def complete(self, *args):
                return self.store.complete(*args)

        def invoke(store):
            provider = phase174.FakeProvider()
            return fixture.invoke(lease_use_store=Port(store), provider=provider), provider.calls

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(invoke, stores))
        self.assertEqual(sum(calls for _, calls in results), 1)
        self.assertEqual(
            sorted(receipt.reason for receipt, _ in results), ["completed", "lease_use_replayed"]
        )
        for receipt, _ in results:
            verify_target_session_receipt(canonical_json(receipt.to_dict()))
        self.assertEqual(len(rows(self.path, "lease_use_reservations")), 1)
        self.assertEqual(len(rows(self.path, "lease_use_completions")), 1)

    def test_runtime_late_stop_after_reserve_settles_zero_calls_without_refund(self) -> None:
        fixture = runtime_fixture()
        store = self.store
        safety = fixture.safety()

        class Port:
            def reserve(self, native_request):
                evidence = store.reserve(native_request)
                safety.snapshot = replace(safety.snapshot, canceled=True)
                return evidence

            def complete(self, *args):
                return store.complete(*args)

        provider = phase174.FakeProvider()
        receipt = fixture.invoke(lease_use_store=Port(), safety_monitor=safety, provider=provider)
        self.assertEqual(receipt.reason, "canceled")
        self.assertEqual(receipt.lease_use_reservation_status, LeaseUseReservationStatus.COMPLETED)
        self.assertFalse(receipt.provider_called)
        self.assertEqual(provider.calls, 0)
        verify_target_session_receipt(canonical_json(receipt.to_dict()))
        completion = json.loads(rows(self.path, "lease_use_completions")[0][1])
        self.assertEqual(completion["outcome"], "rejected_before_authentication")
        self.assertIs(completion["provider_called"], False)
        duplicate_provider = phase174.FakeProvider()
        duplicate = fixture.invoke(
            lease_use_store=leaf.SQLiteAtomicLeaseUseStore(self.path), provider=duplicate_provider
        )
        self.assertEqual(duplicate.reason, "lease_use_replayed")
        self.assertEqual(duplicate_provider.calls, 0)

    def test_runtime_adverse_provider_outcome_permanently_consumes_use(self) -> None:
        fixture = runtime_fixture()
        provider = phase174.FakeProvider(
            failure=CredentialSessionProviderFailure("authentication_denied")
        )
        receipt = fixture.invoke(lease_use_store=self.store, provider=provider)
        self.assertEqual(receipt.status, SessionAcquisitionStatus.PROVIDER_FAILED)
        self.assertTrue(receipt.provider_called)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(receipt.lease_use_reservation_status, LeaseUseReservationStatus.COMPLETED)
        completion = json.loads(rows(self.path, "lease_use_completions")[0][1])
        self.assertEqual(completion["outcome"], "provider_failed")
        subsequent_provider = phase174.FakeProvider()
        subsequent = fixture.invoke(
            lease_use_store=leaf.SQLiteAtomicLeaseUseStore(self.path), provider=subsequent_provider
        )
        self.assertEqual(subsequent.reason, "lease_use_replayed")
        self.assertEqual(subsequent_provider.calls, 0)

    def test_runtime_uncertain_acknowledgements_never_trigger_retry_or_refund(self) -> None:
        fixture = runtime_fixture()
        for index, lost_at in enumerate(("reserve", "complete")):
            with self.subTest(lost_at=lost_at):
                path = self.directory / f"lost-{index}.sqlite3"
                store = leaf.SQLiteAtomicLeaseUseStore.create(path)
                calls = {"reserve": 0, "complete": 0}

                class Port:
                    def reserve(self, native_request):
                        calls["reserve"] += 1
                        evidence = store.reserve(native_request)
                        if lost_at == "reserve":
                            raise LeaseUseStoreFailure("lease_use_reservation_failure")
                        return evidence

                    def complete(self, *args):
                        calls["complete"] += 1
                        store.complete(*args)
                        raise LeaseUseStoreFailure("lease_use_completion_failure")

                provider = phase174.FakeProvider()
                receipt = fixture.invoke(lease_use_store=Port(), provider=provider)
                self.assertEqual(calls["reserve"], 1)
                self.assertEqual(provider.calls, 0 if lost_at == "reserve" else 1)
                self.assertEqual(calls["complete"], 0 if lost_at == "reserve" else 1)
                self.assertEqual(len(rows(path, "lease_use_reservations")), 1)
                self.assertEqual(
                    len(rows(path, "lease_use_completions")), 0 if lost_at == "reserve" else 1
                )
                self.assertEqual(
                    receipt.lease_use_reservation_status,
                    LeaseUseReservationStatus.NOT_RESERVED
                    if lost_at == "reserve"
                    else LeaseUseReservationStatus.COMPLETION_FAILED,
                )
                verify_target_session_receipt(canonical_json(receipt.to_dict()))
                retry_provider = phase174.FakeProvider()
                retry = fixture.invoke(
                    lease_use_store=leaf.SQLiteAtomicLeaseUseStore(path), provider=retry_provider
                )
                self.assertEqual(retry.reason, "lease_use_replayed")
                self.assertEqual(retry_provider.calls, 0)

    def test_runtime_failed_completion_preserves_reservation_and_zero_duplicate_calls(self) -> None:
        fixture = runtime_fixture()
        store = self.store

        class Port:
            def reserve(self, native_request):
                return store.reserve(native_request)

            def complete(self, *args):
                raise LeaseUseStoreFailure("lease_use_completion_failure")

        provider = phase174.FakeProvider()
        receipt = fixture.invoke(lease_use_store=Port(), provider=provider)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(
            receipt.lease_use_reservation_status, LeaseUseReservationStatus.COMPLETION_FAILED
        )
        self.assertEqual(len(rows(self.path, "lease_use_reservations")), 1)
        self.assertEqual(rows(self.path, "lease_use_completions"), [])
        verify_target_session_receipt(canonical_json(receipt.to_dict()))
        retry_provider = phase174.FakeProvider()
        retry = fixture.invoke(
            lease_use_store=leaf.SQLiteAtomicLeaseUseStore(self.path), provider=retry_provider
        )
        self.assertEqual(retry.reason, "lease_use_replayed")
        self.assertEqual(retry_provider.calls, 0)


if __name__ == "__main__":
    unittest.main()
