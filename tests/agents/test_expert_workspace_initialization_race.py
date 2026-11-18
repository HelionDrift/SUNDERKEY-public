"""Real SQLite initialization interleaving and strict store-identity controls."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any
from unittest.mock import patch

from sunderkey import expert_workspace as workspace
from sunderkey.errors import StoreIntegrityError
from tests.agents import test_expert_workspace_phase191 as fixtures


def _metadata_read(statement: str) -> bool:
    normalized = statement.strip().rstrip(";").lower()
    if normalized in {"pragma application_id", "pragma user_version"}:
        return True
    return "pragma_application_id" in normalized or "pragma_user_version" in normalized


class _PeerPublication:
    """Schedule a real peer initializer after a genuine metadata statement."""

    def __init__(self, peer: workspace.SQLiteExpertWorkspaceStore) -> None:
        self.peer = peer
        self.reads: list[tuple[str, tuple[Any, ...] | None]] = []
        self.scheduled = False
        self.published = False
        self.deferred_for_transaction = False

    def after_read(self, connection: sqlite3.Connection, statement: str, row: Any) -> None:
        self.reads.append((statement, tuple(row) if row is not None else None))
        if self.scheduled:
            return
        self.scheduled = True
        if connection.in_transaction:
            # A coherent explicit snapshot must not wait on a peer writer that
            # cannot commit until that snapshot is released.
            self.deferred_for_transaction = True
            return
        self.publish()

    def publish(self) -> None:
        if not self.published:
            self.peer.initialize()
            self.published = True


class _MetadataCursor:
    """Return unchanged native rows; schedule only after releasing the cursor."""

    def __init__(
        self,
        cursor: sqlite3.Cursor,
        connection: sqlite3.Connection,
        publication: _PeerPublication,
        statement: str | None = None,
    ) -> None:
        self.native = cursor
        self.connection = connection
        self.publication = publication
        self.statement = statement

    def execute(self, statement: str, *args: Any) -> _MetadataCursor:
        self.native.execute(statement, *args)
        self.statement = statement if _metadata_read(statement) else None
        return self

    def fetchone(self) -> Any:
        row = self.native.fetchone()
        if self.statement is not None:
            statement = self.statement
            self.statement = None
            self.native.close()
            self.publication.after_read(self.connection, statement, row)
        return row

    def fetchall(self) -> list[Any]:
        rows = self.native.fetchall()
        if self.statement is not None:
            statement = self.statement
            self.statement = None
            self.native.close()
            self.publication.after_read(self.connection, statement, rows[0] if rows else None)
        return rows

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native, name)


class _MetadataConnection:
    """Faithful connection instrumentation, with no synthetic query results."""

    def __init__(self, connection: sqlite3.Connection, publication: _PeerPublication) -> None:
        self.native = connection
        self.publication = publication

    def execute(self, statement: str, *args: Any) -> Any:
        cursor = self.native.execute(statement, *args)
        if _metadata_read(statement):
            return _MetadataCursor(cursor, self.native, self.publication, statement)
        return cursor

    def cursor(self, *args: Any, **kwargs: Any) -> _MetadataCursor:
        return _MetadataCursor(self.native.cursor(*args, **kwargs), self.native, self.publication)

    def close(self) -> None:
        self.native.close()
        if self.publication.deferred_for_transaction:
            self.publication.publish()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native, name)


class ExpertWorkspaceInitializationRaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Reuse the genuine Phase 191 catalog sources without rediscovering its
        # TestCase or invoking any builder that writes artifacts.
        cls.catalog = fixtures.load_runtime_pack_catalog(
            fixtures.CATALOG_PATH, *fixtures.load_sources()
        )

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    @staticmethod
    def _logical_snapshot(path: Path) -> tuple[Any, ...]:
        with closing(sqlite3.connect(path)) as connection:
            return (
                connection.execute("PRAGMA application_id").fetchone()[0],
                connection.execute("PRAGMA user_version").fetchone()[0],
                tuple(connection.iterdump()),
            )

    def _assert_current_store(self, store: workspace.SQLiteExpertWorkspaceStore) -> str:
        with closing(store._connect()) as connection:
            store._verify_identity(connection)
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            rows = connection.execute("SELECT * FROM workspace_store_identity").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["singleton"], 1)
            self.assertEqual(rows[0]["schema_version"], workspace.SCHEMA_VERSION)
            self.assertEqual(rows[0]["created_at"], 0)
            self.assertRegex(rows[0]["store_id"], r"^EWI-[0-9A-F]{32}$")
            store_id = rows[0]["store_id"]
        report = store.verify_store(self.catalog)
        self.assertEqual(report.status, "valid")
        self.assertEqual(report.schema_version, workspace.SCHEMA_VERSION)
        self.assertEqual(
            (
                report.workspace_count,
                report.assignment_count,
                report.lease_count,
                report.product_count,
                report.event_count,
            ),
            (0, 0, 0, 0, 0),
        )
        return store_id

    def _assert_refused_without_change(self, path: Path) -> None:
        before = self._logical_snapshot(path)
        with self.assertRaises(StoreIntegrityError):
            workspace.SQLiteExpertWorkspaceStore(path, timeout_seconds=2).initialize()
        self.assertEqual(self._logical_snapshot(path), before)

    @staticmethod
    def _create_header(path: Path, *, application_id: int, version: int, body: str = "") -> None:
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.executescript(
                "BEGIN IMMEDIATE;\n"
                + f"PRAGMA application_id = {application_id};\n"
                + f"PRAGMA user_version = {version};\n"
                + body
                + "\nCOMMIT;"
            )

    def _create_legacy(self, path: Path, version: int) -> None:
        schema = workspace._SCHEMA_SQL_V1
        if version == 2:
            schema += workspace._SCHEMA_SQL_V2
        self._create_header(
            path,
            application_id=workspace.APPLICATION_ID,
            version=version,
            body=(
                schema
                + "\nINSERT INTO workspace_store_identity"
                + "(singleton, schema_version, created_at) "
                + f"VALUES (1, {version}, 0);"
            ),
        )
        with closing(workspace.SQLiteExpertWorkspaceStore(path)._connect()) as connection:
            workspace.SQLiteExpertWorkspaceStore._verify_identity_version(connection, version)

    def test_two_real_initializers_converge_across_metadata_publication(self) -> None:
        path = self.directory / "interleaved.sqlite3"
        reader = workspace.SQLiteExpertWorkspaceStore(path, timeout_seconds=2)
        peer = workspace.SQLiteExpertWorkspaceStore(path, timeout_seconds=2)
        publication = _PeerPublication(peer)
        original_connect = workspace.SQLiteExpertWorkspaceStore._connect

        def instrumented_connect(store: workspace.SQLiteExpertWorkspaceStore) -> Any:
            connection = original_connect(store)
            if store is reader:
                return _MetadataConnection(connection, publication)
            return connection

        failure = None
        with patch.object(workspace.SQLiteExpertWorkspaceStore, "_connect", instrumented_connect):
            try:
                reader.initialize()
            except StoreIntegrityError as error:
                # Preserve the product failure only to assert public convergence;
                # never retry, skip, or accept it as a successful initialization.
                failure = error
        self.assertTrue(publication.scheduled)
        self.assertTrue(publication.published)
        peer_id = self._assert_current_store(peer)
        self.assertIsNone(
            failure,
            f"Real metadata observations {publication.reads!r} rejected: {failure}",
        )
        self.assertEqual(self._assert_current_store(reader), peer_id)

    def test_fresh_initialization_and_reopen_preserve_one_verified_identity(self) -> None:
        path = self.directory / "fresh.sqlite3"
        store = workspace.SQLiteExpertWorkspaceStore(path)
        store.initialize()
        store_id = self._assert_current_store(store)
        before = self._logical_snapshot(path)
        reopened = workspace.SQLiteExpertWorkspaceStore(path)
        reopened.initialize()
        self.assertEqual(self._assert_current_store(reopened), store_id)
        self.assertEqual(self._logical_snapshot(path), before)

    def test_exact_legacy_schema_versions_migrate_and_preserve_reopen_identity(self) -> None:
        for version in (1, 2):
            with self.subTest(version=version):
                path = self.directory / f"legacy-{version}.sqlite3"
                self._create_legacy(path, version)
                store = workspace.SQLiteExpertWorkspaceStore(path)
                store.initialize()
                store_id = self._assert_current_store(store)
                before = self._logical_snapshot(path)
                store.initialize()
                self.assertEqual(self._assert_current_store(store), store_id)
                self.assertEqual(self._logical_snapshot(path), before)

    def test_nonempty_unclaimed_database_is_refused_without_adoption(self) -> None:
        path = self.directory / "unclaimed.sqlite3"
        self._create_header(
            path,
            application_id=0,
            version=0,
            body="CREATE TABLE unrelated(value TEXT);INSERT INTO unrelated VALUES ('preserved');",
        )
        self._assert_refused_without_change(path)

    def test_foreign_nonempty_database_is_refused_without_adoption(self) -> None:
        path = self.directory / "foreign.sqlite3"
        self._create_header(
            path,
            application_id=workspace.APPLICATION_ID + 1,
            version=workspace.SCHEMA_VERSION,
            body="CREATE TABLE unrelated(value TEXT);INSERT INTO unrelated VALUES ('preserved');",
        )
        self._assert_refused_without_change(path)

    def test_partial_unknown_and_missing_legacy_headers_still_fail_closed(self) -> None:
        cases = (
            (0, workspace.SCHEMA_VERSION),
            (workspace.APPLICATION_ID, 0),
            (workspace.APPLICATION_ID, workspace.SCHEMA_VERSION + 1),
            (workspace.APPLICATION_ID, 1),
            (workspace.APPLICATION_ID, 2),
        )
        for index, (application_id, version) in enumerate(cases):
            with self.subTest(application_id=application_id, version=version):
                path = self.directory / f"invalid-header-{index}.sqlite3"
                self._create_header(path, application_id=application_id, version=version)
                self._assert_refused_without_change(path)

    def test_current_header_without_complete_identity_and_schema_is_refused(self) -> None:
        path = self.directory / "missing-schema.sqlite3"
        self._create_header(
            path,
            application_id=workspace.APPLICATION_ID,
            version=workspace.SCHEMA_VERSION,
        )
        self._assert_refused_without_change(path)

    def test_extra_schema_object_and_substituted_trigger_are_not_repaired(self) -> None:
        for case in ("extra_table", "changed_trigger"):
            with self.subTest(case=case):
                path = self.directory / f"schema-{case}.sqlite3"
                workspace.SQLiteExpertWorkspaceStore(path).initialize()
                with closing(sqlite3.connect(path)) as connection:
                    if case == "extra_table":
                        connection.execute("CREATE TABLE unrelated(value TEXT)")
                    else:
                        connection.execute("DROP TRIGGER workspace_events_no_update")
                        connection.execute(
                            "CREATE TRIGGER workspace_events_no_update "
                            "AFTER INSERT ON workspace_events BEGIN SELECT 1; END"
                        )
                    connection.commit()
                self._assert_refused_without_change(path)

    def test_incomplete_legacy_schema_is_not_accepted_or_migrated(self) -> None:
        for version in (1, 2):
            with self.subTest(version=version):
                path = self.directory / f"incomplete-legacy-{version}.sqlite3"
                self._create_legacy(path, version)
                with closing(sqlite3.connect(path)) as connection:
                    connection.execute("DROP TRIGGER workspace_events_no_update")
                    connection.commit()
                self._assert_refused_without_change(path)


if __name__ == "__main__":
    unittest.main()
