from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from sunderkey.cli import main

ROOT = Path(__file__).resolve().parents[2]


def run_cli(*arguments: str) -> dict[str, object]:
    output = io.StringIO()
    with patch("sys.argv", ["sunderkey", *arguments]), redirect_stdout(output):
        main()
    return json.loads(output.getvalue())


class Phase2CliTests(unittest.TestCase):
    def test_route_command_uses_the_explicit_pilot_catalog(self) -> None:
        result = run_cli(
            "route",
            "--registry",
            str(ROOT / "registry" / "army-v1.json"),
            "--capabilities",
            str(ROOT / "registry" / "capabilities-pilot-v1.json"),
            "--policy",
            str(ROOT / "registry" / "routing-policy-pilot-v1.json"),
            "--request",
            str(ROOT / "examples" / "routing" / "internet-api-to-data.json"),
        )
        self.assertEqual(result["status"], "routed")
        self.assertEqual(
            result["selected_specialist_ids"],
            [
                "AOE-GA-D03-S13",
                "AOE-GB-D06-S09",
                "AOE-GB-D07-S01",
            ],
        )
        self.assertEqual(result["joint_mission_cell"]["size"], 19)

    def test_route_can_write_a_create_mission_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mission_output = Path(temporary) / "resolved-mission.json"
            result = run_cli(
                "route",
                "--registry",
                str(ROOT / "registry" / "army-v1.json"),
                "--capabilities",
                str(
                    ROOT / "registry" / "capabilities-pilot-v1.json"
                ),
                "--policy",
                str(
                    ROOT / "registry" / "routing-policy-pilot-v1.json"
                ),
                "--request",
                str(
                    ROOT
                    / "examples"
                    / "routing"
                    / "internet-api-to-data.json"
                ),
                "--mission-output",
                str(mission_output),
            )
            mission = json.loads(mission_output.read_text(encoding="utf-8"))
            self.assertEqual(mission["mission_id"], result["mission_id"])
            self.assertEqual(
                mission["requested_specialist_ids"],
                result["selected_specialist_ids"],
            )

    def test_route_output_cannot_replace_its_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            request_path = Path(temporary) / "request.json"
            original = (
                ROOT / "examples" / "routing" / "internet-api-to-data.json"
            ).read_bytes()
            request_path.write_bytes(original)
            with self.assertRaisesRegex(
                SystemExit,
                "--mission-output must not replace --request",
            ):
                run_cli(
                    "route",
                    "--registry",
                    str(ROOT / "registry" / "army-v1.json"),
                    "--capabilities",
                    str(
                        ROOT / "registry" / "capabilities-pilot-v1.json"
                    ),
                    "--policy",
                    str(
                        ROOT / "registry" / "routing-policy-pilot-v1.json"
                    ),
                    "--request",
                    str(request_path),
                    "--mission-output",
                    str(request_path),
                )
            self.assertEqual(request_path.read_bytes(), original)

    def test_invalid_utf8_event_file_has_a_controlled_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            events_path = Path(temporary) / "events.jsonl"
            events_path.write_bytes(b"\xff")
            with self.assertRaisesRegex(
                SystemExit,
                "Could not read event file as UTF-8 text",
            ):
                run_cli(
                    "validate-events",
                    "--registry",
                    str(ROOT / "registry" / "army-v1.json"),
                    "--mission",
                    str(
                        ROOT
                        / "examples"
                        / "missions"
                        / "internet-api-to-data.json"
                    ),
                    "--events",
                    str(events_path),
                )

    def test_store_approval_and_simulation_commands_form_one_safe_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store_path = str(Path(temporary) / "missions.sqlite3")
            common = (
                "--store",
                store_path,
                "--registry",
                str(ROOT / "registry" / "army-v1.json"),
            )
            initialized = run_cli("init-store", "--store", store_path)
            self.assertEqual(initialized["status"], "initialized")
            created = run_cli(
                "create-mission",
                *common,
                "--mission",
                str(
                    ROOT
                    / "examples"
                    / "missions"
                    / "internet-api-to-data.json"
                ),
            )
            self.assertEqual(created["revision"], 0)
            appended = run_cli(
                "append-events",
                *common,
                "--events",
                str(
                    ROOT
                    / "examples"
                    / "events"
                    / "internet-api-to-data-proposal.jsonl"
                ),
                "--expected-revision",
                "0",
            )
            self.assertEqual(len(appended["receipts"]), 3)

            submitted = run_cli(
                "approval-submit",
                *common,
                "--mission-id",
                "EXAMPLE-API-DATA-001",
                "--proposal-id",
                "EVT-003",
                "--executor-profile-id",
                "AOE-GB-D06-S09",
                "--review-expires-at",
                "2099-01-01T00:00:00Z",
                "--idempotency-key",
                "cli-submit-test",
                "--principal-profile-id",
                "AOE-GB-D06-S09",
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
                "--constraint",
                "No external actions",
                "--authorization-expires-at",
                "2099-01-01T01:00:00Z",
                "--idempotency-key",
                "cli-approve-test",
                "--expected-version",
                "1",
                "--principal-profile-id",
                "AOE-HQ-12",
            )
            self.assertEqual(approved["state"], "approved")
            receipt = run_cli(
                "simulate",
                *common,
                "--approval-id",
                approval_id,
                "--idempotency-key",
                "cli-simulate-test",
                "--principal-profile-id",
                "AOE-GB-D06-S09",
            )
            self.assertFalse(receipt["external_actions_performed"])
            self.assertEqual(receipt["evidence_level"], "E0")
            verified = run_cli("verify-store", *common)
            self.assertEqual(
                verified,
                {
                    "event_count": 4,
                    "mission_count": 1,
                    "status": "valid",
                },
            )
            with self.assertRaisesRegex(
                SystemExit,
                "--output must not replace --store",
            ):
                run_cli(
                    "verify-store",
                    *common,
                    "--output",
                    store_path,
                )
            self.assertEqual(
                run_cli("verify-store", *common),
                verified,
            )
            store_alias = Path(temporary) / "store-alias.sqlite3"
            store_alias.hardlink_to(store_path)
            with self.assertRaisesRegex(
                SystemExit,
                "--output must not replace --store",
            ):
                run_cli(
                    "verify-store",
                    *common,
                    "--output",
                    str(store_alias),
                )
            self.assertEqual(
                run_cli("verify-store", *common),
                verified,
            )
            colliding_backup_path = (
                Path(temporary) / "colliding-backup.sqlite3"
            )
            with self.assertRaisesRegex(
                SystemExit,
                "--output and --destination must differ",
            ):
                run_cli(
                    "backup-store",
                    *common,
                    "--destination",
                    str(colliding_backup_path),
                    "--output",
                    str(colliding_backup_path),
                )
            self.assertFalse(colliding_backup_path.exists())
            backup_path = Path(temporary) / "missions-backup.sqlite3"
            backup = run_cli(
                "backup-store",
                *common,
                "--destination",
                str(backup_path),
            )
            self.assertEqual(backup["status"], "created")
            self.assertTrue(backup_path.is_file())


if __name__ == "__main__":
    unittest.main()
