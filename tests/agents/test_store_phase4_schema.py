from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import sunderkey.store as store_module
from sunderkey.errors import StoreConflictError, StoreError, StoreIntegrityError
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import (
    APPLICATION_ID,
    MISSION_CONTROL_SCHEMA_VERSION,
    SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    principal_ledger_baseline_root_hash,
    sha256_text,
)

from .test_store import (
    MISSION_ID,
    REGISTRY_PATH,
    mission_data,
    observation,
    remove_schema_v5_objects,
)

FIXED_TIME = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


class Phase4StoreSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.mission = MissionRequest.from_dict(mission_data())

    def new_store(self, path: Path | None = None) -> MissionStore:
        return MissionStore(path or self.path, clock=lambda: FIXED_TIME)

    def initialized_store(self, *, with_event: bool = False) -> MissionStore:
        store = self.new_store()
        store.initialize()
        store.create_mission(self.registry, self.mission)
        if with_event:
            store.append_event(
                self.registry,
                observation("EVT-PHASE4-SCHEMA-001"),
                expected_revision=0,
            )
        return store

    def downgrade_to_v2(self, path: Path | None = None) -> None:
        target = path or self.path
        with closing(sqlite3.connect(target)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v5_objects(connection)
            for table in (
                "mission_scope_grant_revocations",
                "mission_scope_revocation_baselines",
                "principal_assertion_effects",
                "principal_assertion_uses",
                "mission_principal_ledgers",
                "mission_scope_grants",
                "trust_policy_history",
                "store_identity",
            ):
                connection.execute(f"DROP TABLE {table}")
            connection.execute(
                """
                UPDATE store_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (str(MISSION_CONTROL_SCHEMA_VERSION),),
            )
            connection.execute(
                f"PRAGMA user_version = {MISSION_CONTROL_SCHEMA_VERSION}"
            )
            connection.commit()

    def downgrade_to_v1(self, path: Path | None = None) -> None:
        target = path or self.path
        self.downgrade_to_v2(target)
        with closing(sqlite3.connect(target)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("DROP TABLE approval_revocations")
            connection.execute("DROP TABLE mission_controls")
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '1'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 1")
            connection.commit()

    def table_rows(
        self,
        path: Path,
        table: str,
        order_by: str,
    ) -> tuple[tuple[object, ...], ...]:
        with closing(sqlite3.connect(path)) as connection:
            return tuple(
                tuple(row)
                for row in connection.execute(
                    f"SELECT * FROM {table} ORDER BY {order_by}"
                ).fetchall()
            )

    def test_fresh_v3_has_random_identity_and_empty_baseline(self) -> None:
        store = self.initialized_store()

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA application_id").fetchone()[0],
                APPLICATION_ID,
            )
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            identity = connection.execute(
                "SELECT * FROM store_identity"
            ).fetchone()
            ledger = connection.execute(
                """
                SELECT * FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert identity is not None
        assert ledger is not None
        store_id = str(identity[1])
        self.assertRegex(store_id, r"\ASTR-[0-9A-F]{32}\Z")
        self.assertTrue(all(value is None for value in identity[3:]))
        baseline = json.loads(str(ledger[3]))
        self.assertEqual(baseline["baseline_kind"], "empty")
        self.assertEqual(
            baseline["authentication_status"],
            "no_authenticated_principal_uses",
        )
        self.assertEqual(ledger[4], sha256_text(str(ledger[3])))
        self.assertEqual(
            ledger[5],
            principal_ledger_baseline_root_hash(
                MISSION_ID,
                str(ledger[4]),
            ),
        )
        self.assertEqual(ledger[5], ledger[6])
        self.assertEqual((ledger[7], ledger[8]), (0, 0))
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_empty_baseline_is_deterministic_across_stores(self) -> None:
        first = self.initialized_store()
        second_path = self.directory / "second.sqlite3"
        second = self.new_store(second_path)
        second.initialize()
        second.create_mission(self.registry, self.mission)

        with closing(sqlite3.connect(self.path)) as connection:
            first_values = connection.execute(
                """
                SELECT baseline_json, baseline_hash, baseline_root_hash
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            first_store_id = connection.execute(
                "SELECT store_id FROM store_identity"
            ).fetchone()[0]
        with closing(sqlite3.connect(second_path)) as connection:
            second_values = connection.execute(
                """
                SELECT baseline_json, baseline_hash, baseline_root_hash
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            second_store_id = connection.execute(
                "SELECT store_id FROM store_identity"
            ).fetchone()[0]
        self.assertNotEqual(first_store_id, second_store_id)
        self.assertEqual(first_values, second_values)
        self.assertEqual(first.verify_store(self.registry).status, "valid")
        self.assertEqual(second.verify_store(self.registry).status, "valid")

    def test_v2_to_v3_preserves_state_and_backup_version(self) -> None:
        store = self.initialized_store(with_event=True)
        before = {
            table: self.table_rows(self.path, table, order)
            for table, order in {
                "missions": "mission_id",
                "mission_events": "mission_id, sequence",
                "approval_queue": "approval_id",
                "simulation_receipts": "mission_id, simulation_id",
                "mission_controls": "mission_id",
                "approval_revocations": "approval_id",
            }.items()
        }
        self.downgrade_to_v2()
        backup = self.directory / "before-v3.sqlite3"

        report = store.migrate(self.registry, backup)

        self.assertEqual(report.source_version, MISSION_CONTROL_SCHEMA_VERSION)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                MISSION_CONTROL_SCHEMA_VERSION,
            )
        for table, order in {
            "missions": "mission_id",
            "mission_events": "mission_id, sequence",
            "approval_queue": "approval_id",
            "simulation_receipts": "mission_id, simulation_id",
            "mission_controls": "mission_id",
            "approval_revocations": "approval_id",
        }.items():
            self.assertEqual(
                self.table_rows(self.path, table, order),
                before[table],
            )
        with closing(sqlite3.connect(self.path)) as connection:
            ledger = connection.execute(
                """
                SELECT baseline_kind, baseline_json
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert ledger is not None
        baseline = json.loads(str(ledger[1]))
        self.assertEqual(ledger[0], "historical_v2")
        self.assertEqual(
            baseline["authentication_status"],
            "historical_state_not_authenticated",
        )
        self.assertEqual(
            baseline["source_schema_version"],
            MISSION_CONTROL_SCHEMA_VERSION,
        )
        self.assertEqual(
            baseline["historical_tables"]["mission_events"]["count"],
            1,
        )
        self.assertEqual(store.verify_store(self.registry).status, "valid")
        self.assertEqual(
            MissionStore(backup).verify_store(self.registry).status,
            "valid",
        )

    def test_direct_v1_to_v3_preserves_state_and_marks_source(self) -> None:
        store = self.initialized_store(with_event=True)
        before_missions = self.table_rows(
            self.path,
            "missions",
            "mission_id",
        )
        before_events = self.table_rows(
            self.path,
            "mission_events",
            "mission_id, sequence",
        )
        self.downgrade_to_v1()
        backup = self.directory / "before-v1.sqlite3"

        report = store.migrate(self.registry, backup)

        self.assertEqual(report.source_version, 1)
        self.assertEqual(report.target_version, SCHEMA_VERSION)
        self.assertEqual(
            self.table_rows(self.path, "missions", "mission_id"),
            before_missions,
        )
        self.assertEqual(
            self.table_rows(
                self.path,
                "mission_events",
                "mission_id, sequence",
            ),
            before_events,
        )
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                1,
            )
        with closing(sqlite3.connect(self.path)) as connection:
            baseline_json = connection.execute(
                """
                SELECT baseline_json FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
            control = connection.execute(
                """
                SELECT state, version FROM mission_controls
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        baseline = json.loads(baseline_json)
        self.assertEqual(baseline["source_schema_version"], 1)
        self.assertEqual(
            baseline["normalized_schema_version"],
            MISSION_CONTROL_SCHEMA_VERSION,
        )
        self.assertEqual(control, ("active", 1))
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_migration_failure_rolls_back_but_keeps_v2_backup(self) -> None:
        store = self.initialized_store(with_event=True)
        self.downgrade_to_v2()
        backup = self.directory / "rollback-v2.sqlite3"
        broken = (
            *store_module.SCHEMA_V3_ADDITION_STATEMENTS,
            "THIS IS NOT VALID SQL",
        )

        with (
            mock.patch.object(
                store_module,
                "SCHEMA_V3_ADDITION_STATEMENTS",
                broken,
            ),
            self.assertRaises(StoreError),
        ):
            store.migrate(self.registry, backup)

        self.assertTrue(backup.is_file())
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                MISSION_CONTROL_SCHEMA_VERSION,
            )
            self.assertIsNone(
                connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE name = 'store_identity'
                    """
                ).fetchone()
            )
        self.assertEqual(store.verify_store(self.registry).status, "valid")
        self.assertEqual(
            MissionStore(backup).verify_store(self.registry).status,
            "valid",
        )

    def test_migration_backup_race_never_overwrites(self) -> None:
        store = self.initialized_store()
        self.downgrade_to_v2()
        backup = self.directory / "raced-v2.sqlite3"
        competing_content = b"created-by-another-process"

        def raced_publish(source: Path, destination: Path) -> None:
            del source
            Path(destination).write_bytes(competing_content)
            raise FileExistsError("destination won the race")

        with (
            mock.patch(
                "sunderkey.store.os.link",
                side_effect=raced_publish,
            ),
            self.assertRaises(StoreConflictError),
        ):
            store.migrate(self.registry, backup)

        self.assertEqual(backup.read_bytes(), competing_content)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                MISSION_CONTROL_SCHEMA_VERSION,
            )
        self.assertEqual(store.verify_store(self.registry).status, "valid")

    def test_tampered_identity_and_baseline_are_detected(self) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path)) as connection:
            identity_trigger = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                AND name = 'store_identity_immutable'
                """
            ).fetchone()[0]
            connection.execute("DROP TRIGGER store_identity_immutable")
            connection.execute(
                """
                UPDATE store_identity
                SET store_id = 'STR-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
                WHERE singleton_id = 1
                """
            )
            connection.execute(identity_trigger)
            connection.commit()
        with self.assertRaises(StoreIntegrityError):
            store.verify_store(self.registry)

        second_path = self.directory / "baseline-tamper.sqlite3"
        second = self.new_store(second_path)
        second.initialize()
        second.create_mission(self.registry, self.mission)
        with closing(sqlite3.connect(second_path)) as connection:
            baseline_trigger = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                AND name = 'mission_principal_baseline_immutable'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER mission_principal_baseline_immutable"
            )
            row = connection.execute(
                """
                SELECT baseline_json FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            baseline = json.loads(row[0])
            baseline["authentication_status"] = "tampered"
            connection.execute(
                """
                UPDATE mission_principal_ledgers
                SET baseline_json = ?
                WHERE mission_id = ?
                """,
                (canonical_json(baseline), MISSION_ID),
            )
            connection.execute(baseline_trigger)
            connection.commit()
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "baseline",
        ):
            second.verify_store(self.registry)


if __name__ == "__main__":
    unittest.main()
