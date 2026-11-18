"""Command-line coverage for authenticated Phase 13 mission creation."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path
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

ASSERTION_PATH = "principal-assertion.json"
MISSION_PATH = "mission.json"
SCOPE_GRANT_PATH = "scope-grant.json"
STORE_PATH = "missions.sqlite3"
ROOT = Path(__file__).resolve().parents[2]


def creation_arguments() -> list[str]:
    return [
        "mission-create-authenticated",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--mission",
        MISSION_PATH,
        "--scope-grant",
        SCOPE_GRANT_PATH,
        "--principal-assertion",
        ASSERTION_PATH,
    ]


class Phase13CliTests(unittest.TestCase):
    def test_authenticated_creation_parser_contract(self) -> None:
        command = command_parser(
            build_parser(),
            "mission-create-authenticated",
        )

        self.assertEqual(
            required_destinations(command),
            {
                "mission",
                "principal_assertion",
                "registry",
                "scope_grant",
                "store",
            },
        )
        options = option_strings(command)
        for forbidden in (
            "--audience",
            "--issuer",
            "--key-id",
            "--mission-id",
            "--policy",
            "--principal-profile-id",
            "--private-key",
            "--secret",
            "--signing-key",
            "--subject",
        ):
            self.assertNotIn(forbidden, options)

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "mission-create-authenticated",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "mission-create-authenticated",
        )

        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_handler_forwards_only_closed_artifacts(self) -> None:
        registry = object()
        mission = object()
        grant = object()
        assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "mission": {"mission": {"mission_id": "MISSION-CLI"}},
            "operation": "sunderkey.mission.create.v1",
        }
        service.create.return_value = receipt

        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ) as load_registry,
            patch(
                "sunderkey.cli.load_mission_request",
                return_value=mission,
            ) as load_mission,
            patch(
                "sunderkey.cli.load_scope_grant",
                return_value=grant,
            ) as load_grant,
            patch(
                "sunderkey.cli.load_principal_assertion",
                return_value=assertion,
            ) as load_assertion,
            patch(
                "sunderkey.cli.MissionStore",
                return_value=store,
            ) as mission_store,
            patch(
                "sunderkey.cli.AuthenticatedMissionCreationService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*creation_arguments())

        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(load_registry.call_args, call(str(REGISTRY_PATH)))
        self.assertEqual(load_mission.call_args, call(MISSION_PATH))
        self.assertEqual(load_grant.call_args, call(SCOPE_GRANT_PATH))
        self.assertEqual(
            load_assertion.call_args,
            call(ASSERTION_PATH),
        )
        self.assertEqual(mission_store.call_args, call(STORE_PATH))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.create.assert_called_once_with(
            assertion,
            grant,
            mission,
        )

    def test_migrate_help_names_every_v10_source(self) -> None:
        help_text = " ".join(build_parser().format_help().split())
        self.assertIn(
            "Migrate a verified v1 through v15 mission store to v16",
            help_text,
        )

    def test_project_version_is_phase13(self) -> None:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
