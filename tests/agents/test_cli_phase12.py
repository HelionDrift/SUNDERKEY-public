"""Command-line coverage for authenticated Phase 12 simulation."""

from __future__ import annotations

import tempfile
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
APPROVAL_ID = "APR-CLI-PHASE12"
STORE_PATH = "missions.sqlite3"
ROOT = Path(__file__).resolve().parents[2]


def simulate_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "simulate-authenticated",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--principal-assertion",
        ASSERTION_PATH,
        "--approval-id",
        APPROVAL_ID,
        "--idempotency-key",
        "phase12-cli-simulate",
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


class Phase12CliTests(unittest.TestCase):
    def test_authenticated_simulation_parser_contract(self) -> None:
        command = command_parser(
            build_parser(),
            "simulate-authenticated",
        )

        self.assertEqual(
            required_destinations(command),
            {
                "approval_id",
                "idempotency_key",
                "principal_assertion",
                "registry",
                "store",
            },
        )
        options = option_strings(command)
        for forbidden in (
            "--authorization-event-id",
            "--issuer",
            "--key-id",
            "--mission-id",
            "--policy",
            "--principal-profile-id",
            "--private-key",
            "--scope-grant",
            "--secret",
            "--signing-key",
            "--subject",
        ):
            self.assertNotIn(forbidden, options)

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "simulate-authenticated",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "simulate-authenticated",
        )

        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )
        self.assertIn(
            "principal_profile_id",
            required_destinations(
                command_parser(build_parser(), "simulate")
            ),
        )

    def test_handler_forwards_only_closed_arguments(self) -> None:
        registry = object()
        assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "simulation": {
                "approval_id": APPROVAL_ID,
                "external_actions_performed": False,
            },
            "approval": {
                "approval_id": APPROVAL_ID,
                "state": "consumed",
                "version": 3,
            },
            "operation": "sunderkey.simulation.run.v1",
        }
        service.simulate.return_value = receipt

        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ) as load_registry,
            patch(
                "sunderkey.cli.load_principal_assertion",
                return_value=assertion,
            ) as load_assertion,
            patch(
                "sunderkey.cli.MissionStore",
                return_value=store,
            ) as mission_store,
            patch(
                "sunderkey.cli.AuthenticatedSimulationService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*simulate_arguments())

        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(load_registry.call_args, call(str(REGISTRY_PATH)))
        self.assertEqual(load_assertion.call_args, call(ASSERTION_PATH))
        self.assertEqual(mission_store.call_args, call(STORE_PATH))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.simulate.assert_called_once_with(
            assertion,
            APPROVAL_ID,
            idempotency_key="phase12-cli-simulate",
        )

    def test_output_cannot_replace_principal_assertion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assertion_path = Path(temporary) / ASSERTION_PATH
            assertion_path.write_text(
                "principal assertion input\n",
                encoding="utf-8",
            )
            arguments = simulate_arguments(output=str(assertion_path))
            assertion_option = arguments.index("--principal-assertion")
            arguments[assertion_option + 1] = str(assertion_path)
            original = assertion_path.read_bytes()

            with self.assertRaisesRegex(
                SystemExit,
                "--output must not replace --principal-assertion",
            ):
                run_cli(*arguments)
            self.assertEqual(assertion_path.read_bytes(), original)

    def test_migrate_help_names_every_v9_source_version(self) -> None:
        help_text = " ".join(build_parser().format_help().split())
        self.assertIn(
            (
                "Migrate a verified v1 through v15 mission store to v16"
            ),
            help_text,
        )

    def test_project_version_is_phase12(self) -> None:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
