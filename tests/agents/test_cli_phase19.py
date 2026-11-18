"""Command-line coverage for Phase 19 mission audit snapshots."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, call, patch

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.cli import build_parser

from .test_cli_phase5 import run_cli
from .test_cli_phase9 import (
    command_parser,
    option_strings,
    required_destinations,
)
from .test_store import REGISTRY_PATH

STORE_PATH = "missions.sqlite3"
MISSION_ID = "MISSION-CLI-PHASE19"


class Phase19CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(
            build_parser(),
            "mission-audit-snapshot",
        )
        self.assertEqual(
            required_destinations(command),
            {"mission_id", "registry", "store"},
        )
        self.assertFalse(
            option_strings(command)
            & {
                "--actor",
                "--audience",
                "--issuer",
                "--key-id",
                "--policy",
                "--principal-assertion",
                "--principal-profile-id",
                "--private-key",
                "--secret",
                "--signing-key",
                "--subject",
            }
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "mission-audit-snapshot",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "mission-audit-snapshot",
        )
        self.assertEqual(
            option_strings(legacy),
            option_strings(current),
        )
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_handler_forwards_read_only_contract(self) -> None:
        registry = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "snapshot_id": "MAS-" + "A" * 32,
        }
        service.snapshot.return_value = receipt
        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ) as load_registry,
            patch(
                "sunderkey.cli.MissionStore",
                return_value=store,
            ) as mission_store,
            patch(
                "sunderkey.cli.MissionAuditSnapshotService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(
                "mission-audit-snapshot",
                "--store",
                STORE_PATH,
                "--registry",
                str(REGISTRY_PATH),
                "--mission-id",
                MISSION_ID,
            )

        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(
            load_registry.call_args_list,
            [call(str(REGISTRY_PATH))],
        )
        self.assertEqual(
            mission_store.call_args_list,
            [call(STORE_PATH)],
        )
        self.assertEqual(
            service_type.call_args_list,
            [call(store, registry)],
        )
        service.snapshot.assert_called_once_with(MISSION_ID)


if __name__ == "__main__":
    unittest.main()
