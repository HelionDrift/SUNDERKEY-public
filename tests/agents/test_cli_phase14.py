"""Command-line coverage for authenticated Phase 14 plan activation."""

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
PLAN_PATH = "collaboration-plan.json"
STORE_PATH = "missions.sqlite3"
ROOT = Path(__file__).resolve().parents[2]


def activation_arguments() -> list[str]:
    return [
        "collaboration-activate-authenticated",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--plan",
        PLAN_PATH,
        "--principal-assertion",
        ASSERTION_PATH,
    ]


def status_arguments() -> list[str]:
    return [
        "collaboration-status",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--mission-id",
        "MISSION-CLI-PHASE14",
    ]


class Phase14CliTests(unittest.TestCase):
    def test_authenticated_activation_parser_contract(self) -> None:
        command = command_parser(
            build_parser(),
            "collaboration-activate-authenticated",
        )

        self.assertEqual(
            required_destinations(command),
            {
                "plan",
                "principal_assertion",
                "registry",
                "store",
            },
        )
        options = option_strings(command)
        for forbidden in (
            "--actor",
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
        for name in (
            "collaboration-activate-authenticated",
            "collaboration-status",
        ):
            with self.subTest(name=name):
                current = command_parser(
                    build_parser(),
                    name,
                )
                legacy = command_parser(
                    legacy_build_parser(),
                    name,
                )

                self.assertEqual(
                    option_strings(legacy),
                    option_strings(current),
                )
                self.assertEqual(
                    required_destinations(legacy),
                    required_destinations(current),
                )

    def test_handler_forwards_only_closed_artifacts(self) -> None:
        registry = object()
        plan = object()
        assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "plan": {"plan_id": "CLP-" + "A" * 24},
            "operation": (
                "sunderkey.collaboration.activate.v1"
            ),
        }
        service.activate.return_value = receipt

        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ) as load_registry,
            patch(
                "sunderkey.cli.load_collaboration_plan",
                return_value=plan,
            ) as load_plan,
            patch(
                "sunderkey.cli.load_principal_assertion",
                return_value=assertion,
            ) as load_assertion,
            patch(
                "sunderkey.cli.MissionStore",
                return_value=store,
            ) as mission_store,
            patch(
                (
                    "sunderkey.cli."
                    "AuthenticatedCollaborationActivationService"
                ),
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*activation_arguments())

        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(
            load_registry.call_args,
            call(str(REGISTRY_PATH)),
        )
        self.assertEqual(load_plan.call_args, call(PLAN_PATH))
        self.assertEqual(
            load_assertion.call_args,
            call(ASSERTION_PATH),
        )
        self.assertEqual(mission_store.call_args, call(STORE_PATH))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.activate.assert_called_once_with(assertion, plan)

    def test_status_reads_verified_activation(self) -> None:
        registry = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "plan": {"plan_id": "CLP-" + "A" * 24},
        }
        service.get.return_value = receipt

        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ),
            patch(
                "sunderkey.cli.MissionStore",
                return_value=store,
            ),
            patch(
                (
                    "sunderkey.cli."
                    "AuthenticatedCollaborationActivationService"
                ),
                return_value=service,
            ),
        ):
            output = run_cli(*status_arguments())

        self.assertEqual(output, receipt.to_dict.return_value)
        service.get.assert_called_once_with(
            "MISSION-CLI-PHASE14"
        )

    def test_migrate_help_names_every_v11_source(self) -> None:
        help_text = " ".join(build_parser().format_help().split())
        self.assertIn(
            "Migrate a verified v1 through v15 mission store to v16",
            help_text,
        )

    def test_project_version_is_phase14(self) -> None:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
