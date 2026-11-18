"""Durable replacement authority guards and truthful schema 38 migration."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import (
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V37,
    EXPECTED_SCHEMA_MANIFEST_V38,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import remove_schema_v38_objects

ROOT = Path(__file__).resolve().parents[2]


class PlanReplacementSchema38Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "custody.sqlite3"
        self.store = MissionStore(self.path)
        self.store.initialize()
        self.registry = load_registry(ROOT / "registry" / "army-v2.json")

    def test_current_schema_preserves_old_manifest_and_foreign_keys(self) -> None:
        self.assertEqual(SCHEMA_VERSION, 39)
        old = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V37}
        current = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V38}
        changed = {name for name in old if old[name] != current[name]}
        self.assertEqual(
            changed,
            {
                "collaboration_plan_replacement_authentications",
                "collaboration_plan_replacement_authentications_insert_guard",
            },
        )
        table = "collaboration_plan_replacement_authentications"
        self.assertIn("requirement_count = 16", old[table][3])
        self.assertIn("requirement_count BETWEEN 1 AND 4100", current[table][3])
        with self.store._read_connection() as connection:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)

    def test_raw_unsigned_commit_is_rejected_by_database_not_only_service(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "requires signed authority custody"
            ):
                connection.execute(
                    "INSERT INTO collaboration_plan_replacement_commits(preflight_id,mission_id) "
                    "VALUES ('unsigned', 'not-authorized')"
                )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_commits"
                ).fetchone()[0],
                0,
            )

    def test_raw_reviewer_admission_cannot_skip_dual_signed_custody(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "admission custody is inconsistent"
            ):
                connection.execute(
                    "INSERT INTO plan_replacement_reviewer_admissions(admission_id,mission_id) "
                    "VALUES (?, 'not-authorized')",
                    ("RVA-" + "A" * 32,),
                )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM plan_replacement_reviewer_admissions"
                ).fetchone()[0],
                0,
            )

    def test_database_cardinality_rejects_missing_mismatched_and_unbounded_arrays(self) -> None:
        mission = MissionRequest.from_dict(
            json.loads(
                (ROOT / "examples" / "missions" / "internet-api-to-data.json").read_text(
                    encoding="utf-8"
                )
            )
        )
        self.store.create_mission(self.registry, mission)
        statement = """INSERT INTO collaboration_plan_replacement_authentications(
            preflight_id,mission_id,authority_plan_id,authority_plan_sha256,authority_plan_json,
            authority_upgrade_id,authority_upgrade_sha256,authority_upgrade_json,composition_sha256,
            trust_policy_id,trust_policy_version,trust_policy_sha256,authenticated_at,consumed_at,
            requirement_count,authentication_sha256
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN")
            try:
                for plan, upgrade, count in (
                    ({}, {}, 25),
                    ({"assertion_requirements": None}, {"authority_requirements": []}, 1),
                    ({"assertion_requirements": [{}] * 25}, {"authority_requirements": [{}]}, 25),
                    (
                        {"assertion_requirements": [{}] * 25},
                        {"authority_requirements": [{}] * 25},
                        24,
                    ),
                    ({"assertion_requirements": []}, {"authority_requirements": []}, 0),
                    (
                        {"assertion_requirements": [{}] * 4101},
                        {"authority_requirements": [{}] * 4101},
                        4101,
                    ),
                ):
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK constraint failed"):
                        connection.execute(
                            statement,
                            (
                                "unpublished",
                                mission.mission_id,
                                "plan",
                                "digest",
                                json.dumps(plan),
                                "upgrade",
                                "digest",
                                json.dumps(upgrade),
                                "composition",
                                "policy",
                                1,
                                "digest",
                                "2026-07-30T10:10:00Z",
                                "2026-07-30T10:10:00Z",
                                count,
                                "auth",
                            ),
                        )
                # Table shape only. No synthetic row is published or verified as authority.
                connection.execute(
                    statement,
                    (
                        "unpublished",
                        mission.mission_id,
                        "plan",
                        "digest",
                        json.dumps({"assertion_requirements": [{}] * 25}),
                        "upgrade",
                        "digest",
                        json.dumps({"authority_requirements": [{}] * 25}),
                        "composition",
                        "policy",
                        1,
                        "digest",
                        "2026-07-30T10:10:00Z",
                        "2026-07-30T10:10:00Z",
                        25,
                        "auth",
                    ),
                )
            finally:
                connection.rollback()
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_authentications"
                ).fetchone()[0],
                0,
            )

    def test_empty_v37_migration_has_exact_backup_and_no_fabricated_admissions(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            remove_schema_v38_objects(connection)
            connection.execute("UPDATE store_metadata SET value='37' WHERE key='schema_version'")
            connection.execute("PRAGMA user_version = 37")
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V37)
        backup = self.path.with_name("before-v38.sqlite3")
        report = self.store.migrate(self.registry, backup)
        self.assertEqual((report.source_version, report.target_version), (37, 39))
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V37)
        with self.store._read_connection() as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM plan_replacement_reviewer_admissions"
                ).fetchone()[0],
                0,
            )
        self.assertEqual(self.store.verify_store(self.registry).status, "valid")


if __name__ == "__main__":
    unittest.main()
