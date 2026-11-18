from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from collections.abc import Callable
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from sunderkey.cli import main as legacy_main
from sunderkey.cli import main
from sunderkey.store import SCHEMA_VERSION

from .test_store import downgrade_connection_to_schema_v1

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
MISSION_PATH = ROOT / "examples" / "missions" / "internet-api-to-data.json"
EVENTS_PATH = ROOT / "examples" / "events" / "internet-api-to-data-proposal.jsonl"
MISSION_ID = "EXAMPLE-API-DATA-001"
PROPOSAL_ID = "EVT-003"
SPECIALIST_ID = "AOE-GB-D06-S09"
CONTROL_ID = "AOE-HQ-12"


def run_cli(
    *arguments: str,
    entrypoint: Callable[[], None] = main,
    program: str = "sunderkey",
) -> dict[str, object]:
    output = io.StringIO()
    with patch("sys.argv", [program, *arguments]), redirect_stdout(output):
        entrypoint()
    return json.loads(output.getvalue())


def run_cli_failure(
    *arguments: str,
    entrypoint: Callable[[], None] = main,
    program: str = "sunderkey",
) -> tuple[SystemExit, str]:
    output = io.StringIO()
    errors = io.StringIO()
    with (
        patch("sys.argv", [program, *arguments]),
        redirect_stdout(output),
        redirect_stderr(errors),
    ):
        try:
            entrypoint()
        except SystemExit as exc:
            return exc, errors.getvalue()
    raise AssertionError("CLI command unexpectedly succeeded")


def initialize_mission(store_path: Path) -> tuple[str, ...]:
    common = (
        "--store",
        str(store_path),
        "--registry",
        str(REGISTRY_PATH),
    )
    run_cli("init-store", "--store", str(store_path))
    run_cli(
        "create-mission",
        *common,
        "--mission",
        str(MISSION_PATH),
    )
    run_cli(
        "append-events",
        *common,
        "--events",
        str(EVENTS_PATH),
        "--expected-revision",
        "0",
    )
    return common


class Phase3CliTests(unittest.TestCase):
    def test_mission_status_stop_and_legacy_entrypoint_parity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "missions.sqlite3"
            common = initialize_mission(store_path)
            status_arguments = (
                "mission-status",
                *common,
                "--mission-id",
                MISSION_ID,
            )

            active = run_cli(*status_arguments)
            self.assertEqual(
                active,
                {
                    "mission_id": MISSION_ID,
                    "schema_version": 2,
                    "state": "active",
                    "stop_actor_profile_id": None,
                    "stop_decision_owner": None,
                    "stop_event_id": None,
                    "stop_reason": None,
                    "stop_reason_code": None,
                    "stop_risk": None,
                    "stopped_at": None,
                    "version": 1,
                },
            )
            legacy_active = run_cli(
                *status_arguments,
                entrypoint=legacy_main,
                program="sunderkey",
            )
            self.assertEqual(legacy_active, active)

            stopped = run_cli(
                "mission-stop",
                *common,
                "--mission-id",
                MISSION_ID,
                "--reason-code",
                "operator_request",
                "--reason",
                "Operator requested a terminal stop",
                "--risk",
                "Continued work is no longer authorized",
                "--decision-owner",
                "range-control",
                "--idempotency-key",
                "cli-phase3-stop",
                "--expected-version",
                "1",
                "--principal-profile-id",
                CONTROL_ID,
            )
            self.assertEqual(stopped["state"], "stopped")
            self.assertEqual(stopped["version"], 2)
            self.assertEqual(
                stopped["stop_reason_code"],
                "operator_request",
            )
            self.assertEqual(
                stopped["stop_actor_profile_id"],
                CONTROL_ID,
            )
            self.assertEqual(
                stopped["stop_decision_owner"],
                "range-control",
            )
            self.assertTrue(str(stopped["stop_event_id"]).startswith("EVT-STOP-"))
            self.assertEqual(run_cli(*status_arguments), stopped)

    def test_approval_revoke_returns_record_and_audit_detail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = Path(temporary) / "missions.sqlite3"
            common = initialize_mission(store_path)
            submitted = run_cli(
                "approval-submit",
                *common,
                "--mission-id",
                MISSION_ID,
                "--proposal-id",
                PROPOSAL_ID,
                "--executor-profile-id",
                SPECIALIST_ID,
                "--review-expires-at",
                "2099-01-01T00:00:00Z",
                "--idempotency-key",
                "cli-phase3-submit",
                "--principal-profile-id",
                SPECIALIST_ID,
            )
            approval_id = str(submitted["approval_id"])
            approved = run_cli(
                "approval-approve",
                *common,
                "--approval-id",
                approval_id,
                "--authority",
                "delegated-control",
                "--constraint",
                "Synthetic data only",
                "--authorization-expires-at",
                "2099-01-01T01:00:00Z",
                "--idempotency-key",
                "cli-phase3-approve",
                "--expected-version",
                "1",
                "--principal-profile-id",
                CONTROL_ID,
            )

            result = run_cli(
                "approval-revoke",
                *common,
                "--approval-id",
                approval_id,
                "--reason-code",
                "scope-withdrawn",
                "--reason",
                "The delegated scope was withdrawn",
                "--risk",
                "Simulation would use stale authority",
                "--decision-owner",
                "range-control",
                "--idempotency-key",
                "cli-phase3-revoke",
                "--expected-version",
                "2",
                "--principal-profile-id",
                CONTROL_ID,
            )

            approval = result["approval"]
            revocation = result["revocation"]
            self.assertIsInstance(approval, dict)
            self.assertIsInstance(revocation, dict)
            assert isinstance(approval, dict)
            assert isinstance(revocation, dict)
            self.assertEqual(approval["approval_id"], approval_id)
            self.assertEqual(approval["state"], "revoked")
            self.assertEqual(approval["version"], 3)
            self.assertEqual(
                approval["authorization_event_id"],
                approved["authorization_event_id"],
            )
            self.assertEqual(revocation["approval_id"], approval_id)
            self.assertEqual(revocation["mission_id"], MISSION_ID)
            self.assertEqual(revocation["actor_profile_id"], CONTROL_ID)
            self.assertEqual(revocation["reason_code"], "scope-withdrawn")
            self.assertEqual(revocation["expected_version"], 2)
            self.assertTrue(str(revocation["revocation_event_id"]).startswith("EVT-REVOKE-"))

            listed = run_cli(
                "approval-list",
                *common,
                "--mission-id",
                MISSION_ID,
                "--state",
                "revoked",
            )
            self.assertEqual(listed["count"], 1)
            self.assertEqual(listed["approvals"], [approval])

    def test_migrate_store_requires_backup_and_rejects_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            store_path = directory / "legacy.sqlite3"
            backup_path = directory / "legacy-v1-backup.sqlite3"
            run_cli("init-store", "--store", str(store_path))
            with closing(sqlite3.connect(store_path)) as connection:
                downgrade_connection_to_schema_v1(connection)

            required, required_errors = run_cli_failure(
                "migrate-store",
                "--store",
                str(store_path),
                "--registry",
                str(REGISTRY_PATH),
            )
            self.assertEqual(required.code, 2)
            self.assertIn(
                "the following arguments are required: --backup-destination",
                required_errors,
            )

            source_collision, _ = run_cli_failure(
                "migrate-store",
                "--store",
                str(store_path),
                "--registry",
                str(REGISTRY_PATH),
                "--backup-destination",
                str(store_path),
            )
            self.assertEqual(
                source_collision.code,
                "Validation error: --backup-destination must not replace --store",
            )

            output_collision, _ = run_cli_failure(
                "migrate-store",
                "--store",
                str(store_path),
                "--registry",
                str(REGISTRY_PATH),
                "--backup-destination",
                str(backup_path),
                "--output",
                str(backup_path),
            )
            self.assertEqual(
                output_collision.code,
                "Validation error: --output and --backup-destination must differ",
            )
            self.assertFalse(backup_path.exists())

            result = run_cli(
                "migrate-store",
                "--store",
                str(store_path),
                "--registry",
                str(REGISTRY_PATH),
                "--backup-destination",
                str(backup_path),
            )
            self.assertEqual(result["status"], "migrated")
            self.assertEqual(result["source_version"], 1)
            self.assertEqual(result["target_version"], SCHEMA_VERSION)
            self.assertEqual(result["store"], str(store_path.resolve()))
            self.assertEqual(result["backup"], str(backup_path.resolve()))
            self.assertTrue(backup_path.is_file())
            with closing(sqlite3.connect(store_path)) as connection:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION,
                )
            with closing(sqlite3.connect(backup_path)) as connection:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0],
                    1,
                )


if __name__ == "__main__":
    unittest.main()
