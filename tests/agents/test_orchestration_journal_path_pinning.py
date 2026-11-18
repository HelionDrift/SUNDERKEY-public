"""Absolute path pinning for the local orchestration journal."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sunderkey.orchestration_journal import (
    OrchestrationValidationError,
    SQLiteOrchestrationJournal,
)


class OrchestrationJournalPathPinningTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_fresh_normalized_path_and_reopen(self) -> None:
        supplied = self.root / "nested" / ".." / "journal.sqlite3"
        expected = self.root / "journal.sqlite3"
        first = SQLiteOrchestrationJournal(supplied)
        self.assertEqual(first.path, expected)
        self.assertTrue(first.path.is_absolute())
        self.assertTrue(expected.is_file())
        self.assertEqual(first.verify()["status"], "valid")

        reopened = SQLiteOrchestrationJournal(supplied)
        self.assertEqual(reopened.path, expected)
        self.assertEqual(reopened.verify()["status"], "valid")

    def test_relative_path_stays_on_original_store_after_cwd_change(self) -> None:
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        first_dir.mkdir()
        second_dir.mkdir()
        original_cwd = Path.cwd()
        try:
            os.chdir(first_dir)
            first = SQLiteOrchestrationJournal("journal.sqlite3")
            self.assertEqual(first.verify()["status"], "valid")

            os.chdir(second_dir)
            second = SQLiteOrchestrationJournal("journal.sqlite3")
            self.assertEqual(second.verify()["status"], "valid")
            self.assertEqual(first.path, first_dir / "journal.sqlite3")
            self.assertEqual(second.path, second_dir / "journal.sqlite3")

            with first._read() as connection:
                first_opened_path = Path(connection.execute("PRAGMA database_list").fetchone()[2])
            with second._read() as connection:
                second_opened_path = Path(connection.execute("PRAGMA database_list").fetchone()[2])
            self.assertEqual(first_opened_path, first.path)
            self.assertEqual(second_opened_path, second.path)
            self.assertNotEqual(first_opened_path, second_opened_path)
            self.assertEqual(first.verify()["status"], "valid")
        finally:
            os.chdir(original_cwd)

    def test_in_memory_path_remains_rejected(self) -> None:
        with self.assertRaises(OrchestrationValidationError):
            SQLiteOrchestrationJournal(":memory:")


if __name__ == "__main__":
    unittest.main()
