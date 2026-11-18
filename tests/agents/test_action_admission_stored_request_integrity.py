"""Disposable signed-custody regression with no provider or target dispatch."""

from __future__ import annotations

import json
import sqlite3
import unittest
from collections.abc import Iterator
from contextlib import contextmanager

from sunderkey import action_admission_contracts as action
from sunderkey.errors import StoreIntegrityError
from tests.agents import test_mission_store_action_admission_phase195b as fixture_module


class ActionAdmissionStoredRequestIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_module.MissionStoreActionAdmissionPhase195bTests.setUpClass()

    def setUp(self) -> None:
        # The existing fixture constructs signed synthetic local metadata only.
        self.fixture = fixture_module.MissionStoreActionAdmissionPhase195bTests(
            methodName="runTest"
        )
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.store = self.fixture.store
        self.service = self.fixture.service
        self.registry = self.fixture.registry
        self.mission_id = self.fixture.mission_id
        self.receipt = self.fixture._admit_complete_sources()[-1]
        self.assertTrue(self.store.path.is_relative_to(self.fixture.root.directory))
        self.ordinary = self.service.verify_current(self.receipt.receipt_id)
        self.assertEqual(self.ordinary.receipt, self.receipt)
        self.store.verify_mission(self.registry, self.mission_id)
        self.store.verify_store(self.registry)
        with self.store._read_connection() as connection:
            self.original = dict(self._row(connection))
            guards = connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
                "AND tbl_name = 'action_admission_receipts' AND sql LIKE '%BEFORE UPDATE%'"
            ).fetchall()
            self.assertEqual(len(guards), 1)
            self.guard_name, self.guard_sql = guards[0]
            self.assertEqual(self.guard_name, "action_admission_receipts_immutable")

    def _row(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
            (self.receipt.receipt_id,),
        ).fetchone()
        self.assertIsNotNone(row)
        return row

    def _logical_dump(self) -> tuple[str, ...]:
        with self.store._read_connection() as connection:
            return tuple(sorted(connection.iterdump()))

    def _table_counts(self) -> dict[str, int]:
        with self.store._read_connection() as connection:
            names = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            ]
            return {
                name: connection.execute(
                    'SELECT count(*) FROM "' + name.replace('"', '""') + '"'
                ).fetchone()[0]
                for name in names
            }

    def _replace_only(self, field: str, document: str) -> None:
        self.assertIn(field, {"request_json", "decision_json"})
        # Corrupt one disposable row, then restore the original immutable guard
        # in the same transaction before any historical or positive consumer.
        with self.store._write_connection() as connection:
            connection.execute("DROP TRIGGER action_admission_receipts_immutable")
            connection.execute(
                f"UPDATE action_admission_receipts SET {field} = ? WHERE receipt_id = ?",
                (document, self.receipt.receipt_id),
            )
            connection.execute(self.guard_sql)
            self.assertEqual(
                connection.execute(
                    "SELECT sql FROM sqlite_master WHERE name = ?", (self.guard_name,)
                ).fetchone()[0],
                self.guard_sql,
            )

    @contextmanager
    def _changed_json(self, field: str, raw: dict[str, object]) -> Iterator[None]:
        self._replace_only(field, action.canonical_json(raw))
        try:
            with self.store._read_connection() as connection:
                row = dict(self._row(connection))
                self.assertEqual(
                    {key: value for key, value in row.items() if key != field},
                    {key: value for key, value in self.original.items() if key != field},
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT sql FROM sqlite_master WHERE name = ?", (self.guard_name,)
                    ).fetchone()[0],
                    self.guard_sql,
                )
            yield
        finally:
            self._replace_only(field, self.original[field])
            self._assert_row_and_guard_restored()

    def _assert_row_and_guard_restored(self) -> None:
        with self.store._read_connection() as connection:
            self.assertEqual(dict(self._row(connection)), self.original)
            self.assertEqual(
                connection.execute(
                    "SELECT sql FROM sqlite_master WHERE name = ?", (self.guard_name,)
                ).fetchone()[0],
                self.guard_sql,
            )

    def _read_historical(self):
        with self.store._read_connection() as connection:
            return self.service._stored_from_row(connection, self._row(connection))

    def _consumers(self):
        return (
            ("private_reconstruction", self._read_historical),
            ("verify_mission", lambda: self.store.verify_mission(self.registry, self.mission_id)),
            ("verify_store", lambda: self.store.verify_store(self.registry)),
            ("verify_current", lambda: self.service.verify_current(self.receipt.receipt_id)),
        )

    def test_request_native_schema_corruption_fails_history_and_current_verification(self) -> None:
        for replacement in (True, 1.0):
            baseline = self._logical_dump()
            raw = json.loads(self.original["request_json"])
            raw["schema_version"] = replacement
            body = {
                key: value
                for key, value in raw.items()
                if key not in {"request_id", "request_sha256"}
            }
            self.assertNotEqual(
                action.canonical_sha256({"content": body, "domain": raw["kind"]}),
                raw["request_sha256"],
            )
            self.assertEqual(
                raw["request_sha256"], json.loads(self.original["request_json"])["request_sha256"]
            )
            with self._changed_json("request_json", raw):
                for name, verify in self._consumers():
                    with self.subTest(native_type=type(replacement).__name__, consumer=name):
                        with self.assertRaisesRegex(
                            StoreIntegrityError, "^Stored action admission custody is invalid$"
                        ):
                            verify()
            with self.subTest(native_type=type(replacement).__name__, consumer="no_effects"):
                self.assertEqual(self._logical_dump(), baseline)
        self.store.verify_mission(self.registry, self.mission_id)
        self.store.verify_store(self.registry)
        self.assertEqual(self.service.verify_current(self.receipt.receipt_id).receipt, self.receipt)
        self._assert_row_and_guard_restored()

    def test_decision_native_schema_corruption_remains_a_raw_custody_hash_rejection(self) -> None:
        for replacement in (True, 1.0):
            baseline = self._logical_dump()
            raw = json.loads(self.original["decision_json"])
            raw["schema_version"] = replacement
            body = {
                key: value
                for key, value in raw.items()
                if key not in {"decision_id", "decision_sha256"}
            }
            self.assertNotEqual(
                action.canonical_sha256({"content": body, "domain": raw["kind"]}),
                raw["decision_sha256"],
            )
            with self._changed_json("decision_json", raw):
                for name, verify in self._consumers():
                    with self.subTest(native_type=type(replacement).__name__, consumer=name):
                        with self.assertRaisesRegex(
                            StoreIntegrityError, "^Stored action admission custody hash is invalid$"
                        ):
                            verify()
            self.assertEqual(self._logical_dump(), baseline)
        self.store.verify_mission(self.registry, self.mission_id)
        self.store.verify_store(self.registry)
        self._assert_row_and_guard_restored()

    def test_genuine_current_verification_preserves_signed_identity_and_consumption(self) -> None:
        baseline_counts = self._table_counts()
        stored = self._read_historical()
        self.assertIs(type(stored.request.to_dict()["schema_version"]), int)
        self.assertEqual(stored.request.to_json(), self.original["request_json"])
        self.store.verify_mission(self.registry, self.mission_id)
        self.store.verify_store(self.registry)
        current = self.service.verify_current(self.receipt.receipt_id)
        self.assertEqual(current.receipt, self.receipt)
        self.assertEqual(current.custody_sha256, self.original["custody_sha256"])
        self._assert_row_and_guard_restored()
        current_counts = self._table_counts()
        self.assertEqual(
            {
                name: current_counts[name] - count
                for name, count in baseline_counts.items()
                if current_counts[name] != count
            },
            {
                "target_health_gate_observations": 1,
                "target_health_gate_transitions": 1,
                "action_target_health_gate_uses": 1,
            },
        )
