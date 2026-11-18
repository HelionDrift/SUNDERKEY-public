"""Path identity checks for the local SQLite service repository."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sunderkey.local_api_runtime_adapter import (
    _MIGRATION_1,
    _MIGRATION_TABLE_SQL,
    SQLITE_MIGRATION_ID,
    SQLITE_MIGRATION_SHA256,
    LocalApiAsgiApp,
    LocalApiRuntimeError,
    MigrationIdentityError,
    SQLiteServiceRepository,
)
from sunderkey.local_api_service import ResourceKind
from tests.agents.test_local_api_runtime_adapter_phase168 import (
    BoundAdmitter,
    BoundAuthorizer,
    create_request,
    invoke,
)


class LocalApiRepositoryPathIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_fresh_creation_and_valid_reopen(self) -> None:
        path = self.root / "nested" / "service.sqlite3"
        first = SQLiteServiceRepository(path)
        self.assertTrue(path.is_file())
        self.assertEqual(first.verify_integrity()["sqlite"], "ok")
        second = SQLiteServiceRepository(path)
        self.assertEqual(second.migration_identity(), first.migration_identity())

    def test_foreign_existing_database_is_not_adopted_or_mutated(self) -> None:
        path = self.root / "foreign.sqlite3"
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE marker (value TEXT NOT NULL)")
            connection.execute("INSERT INTO marker VALUES ('preserve')")
            connection.commit()
        original_bytes = path.read_bytes()

        with self.assertRaises(MigrationIdentityError):
            SQLiteServiceRepository(path)

        self.assertEqual(path.read_bytes(), original_bytes)
        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            self.assertEqual(
                connection.execute("SELECT value FROM marker").fetchone()[0], "preserve"
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='schema_migrations'"
                ).fetchone()
            )

    def test_preexisting_empty_sqlite_database_is_not_adopted(self) -> None:
        path = self.root / "empty.sqlite3"
        with closing(sqlite3.connect(path)):
            pass
        original_bytes = path.read_bytes()
        with self.assertRaises(MigrationIdentityError):
            SQLiteServiceRepository(path)
        self.assertEqual(path.read_bytes(), original_bytes)

    def test_foreign_wal_database_is_rejected_without_main_database_mutation(self) -> None:
        path = self.root / "foreign-wal.sqlite3"
        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            connection.execute("CREATE TABLE marker (value TEXT NOT NULL)")
            connection.execute("INSERT INTO marker VALUES ('preserve')")
            connection.commit()
        main_before = path.read_bytes()
        with self.assertRaises(MigrationIdentityError):
            SQLiteServiceRepository(path)
        self.assertEqual(path.read_bytes(), main_before)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists():
                self.assertTrue(sidecar.is_file())

    def test_preexisting_non_sqlite_file_is_not_adopted(self) -> None:
        path = self.root / "text.sqlite3"
        path.write_bytes(b"not a SQLite database")
        with self.assertRaises(MigrationIdentityError):
            SQLiteServiceRepository(path)
        self.assertEqual(path.read_bytes(), b"not a SQLite database")

    def test_many_foreign_schema_objects_are_rejected_without_adoption(self) -> None:
        path = self.root / "many-foreign-tables.sqlite3"
        with closing(sqlite3.connect(path)) as connection:
            for index in range(32):
                connection.execute(f"CREATE TABLE foreign_{index} (value TEXT)")
            connection.commit()
        original_bytes = path.read_bytes()

        with self.assertRaises(MigrationIdentityError):
            SQLiteServiceRepository(path)

        self.assertEqual(path.read_bytes(), original_bytes)

    def test_matching_object_names_and_migration_row_do_not_adopt_foreign_ddl(self) -> None:
        path = self.root / "forged-schema.sqlite3"
        altered = _MIGRATION_1.replace(
            "resource_json TEXT NOT NULL", "resource_json BLOB NOT NULL", 1
        )
        self.assertNotEqual(altered, _MIGRATION_1)
        with closing(sqlite3.connect(path)) as connection:
            connection.executescript(_MIGRATION_TABLE_SQL + ";\n" + altered)
            connection.execute(
                "INSERT INTO schema_migrations VALUES (1, ?, ?)",
                (SQLITE_MIGRATION_ID, SQLITE_MIGRATION_SHA256),
            )
            connection.commit()
        original_bytes = path.read_bytes()
        with self.assertRaises(MigrationIdentityError):
            SQLiteServiceRepository(path)
        self.assertEqual(path.read_bytes(), original_bytes)

    def test_extra_migration_row_is_rejected_with_exact_schema(self) -> None:
        path = self.root / "extra-migration.sqlite3"
        SQLiteServiceRepository(path)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "INSERT INTO schema_migrations VALUES (2, 'foreign-migration', 'sha256:foreign')"
            )
            connection.commit()
        main_before = path.read_bytes()
        with self.assertRaises(MigrationIdentityError):
            SQLiteServiceRepository(path)
        self.assertEqual(path.read_bytes(), main_before)

    def test_relative_path_is_pinned_across_working_directory_change(self) -> None:
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        first_dir.mkdir()
        second_dir.mkdir()
        original_cwd = Path.cwd()
        try:
            os.chdir(first_dir)
            first = SQLiteServiceRepository("service.sqlite3")
            os.chdir(second_dir)
            second = SQLiteServiceRepository("service.sqlite3")
            app = LocalApiAsgiApp(first, BoundAuthorizer(), BoundAdmitter())
            status, _, _ = asyncio.run(invoke(app, create_request("asset-pinned")))
            self.assertEqual(status, 200)
            self.assertEqual(first.path, first_dir / "service.sqlite3")
            self.assertIsNotNone(
                first.get(ResourceKind.ASSET, "tenant-a", "context-red", "asset-pinned")
            )
            self.assertIsNone(
                second.get(ResourceKind.ASSET, "tenant-a", "context-red", "asset-pinned")
            )
        finally:
            os.chdir(original_cwd)

    def test_missing_file_after_initialization_is_not_recreated(self) -> None:
        path = self.root / "removed.sqlite3"
        repository = SQLiteServiceRepository(path)
        path.unlink()
        with self.assertRaises(LocalApiRuntimeError):
            repository.migration_identity()
        self.assertFalse(path.exists())

    def test_database_link_is_rejected_before_target_mutation(self) -> None:
        target = self.root / "target.sqlite3"
        SQLiteServiceRepository(target)
        link = self.root / "alias.sqlite3"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"file symlinks unavailable: {exc}")
        original_bytes = target.read_bytes()
        with self.assertRaises(LocalApiRuntimeError):
            SQLiteServiceRepository(link)
        self.assertEqual(target.read_bytes(), original_bytes)

    def test_sidecar_links_are_rejected_before_existing_store_open(self) -> None:
        path = self.root / "service.sqlite3"
        SQLiteServiceRepository(path)
        target = self.root / "sentinel.txt"
        target.write_bytes(b"preserve sidecar target")
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                alias = Path(str(path) + suffix)
                try:
                    alias.symlink_to(target)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"file symlinks unavailable: {exc}")
                try:
                    with self.assertRaises(LocalApiRuntimeError):
                        SQLiteServiceRepository(path)
                    self.assertEqual(target.read_bytes(), b"preserve sidecar target")
                finally:
                    alias.unlink()

    def test_sidecar_directories_are_rejected_without_sqlite_open(self) -> None:
        path = self.root / "service.sqlite3"
        SQLiteServiceRepository(path)
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                sidecar = Path(str(path) + suffix)
                sidecar.mkdir()
                try:
                    with self.assertRaises(LocalApiRuntimeError):
                        SQLiteServiceRepository(path)
                finally:
                    sidecar.rmdir()

    @unittest.skipUnless(os.name == "nt", "Windows reparse attributes are Windows-only")
    def test_windows_reparse_attribute_rejects_main_and_sidecar_paths(self) -> None:
        path = self.root / "service.sqlite3"
        repository = SQLiteServiceRepository(path)
        real_lstat = os.lstat
        for flagged in (path, Path(str(path) + "-wal")):
            with self.subTest(path=flagged):

                def flagged_lstat(candidate: str | os.PathLike[str], target: Path = flagged):
                    if Path(candidate) == target:
                        return SimpleNamespace(
                            st_mode=stat.S_IFREG,
                            st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                        )
                    return real_lstat(candidate)

                with (
                    patch(
                        "sunderkey.local_api_runtime_adapter.os.lstat",
                        side_effect=flagged_lstat,
                    ),
                    self.assertRaises(LocalApiRuntimeError),
                ):
                    repository._inspect_path(require_file=True)

    def test_linked_parent_directory_is_rejected(self) -> None:
        target = self.root / "real"
        target.mkdir()
        alias = self.root / "alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")
        with self.assertRaises(LocalApiRuntimeError):
            SQLiteServiceRepository(alias / "service.sqlite3")
        self.assertFalse((target / "service.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
