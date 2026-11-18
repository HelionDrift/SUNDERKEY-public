"""Command-line coverage for Phase 89 mission policy operations."""

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

STORE_PATH = "missions.sqlite3"
AUTHORITY_POLICY_PATH = "authority-policy.json"
MISSION_POLICY_PATH = "mission-policy.json"
OWNER_ASSERTION_PATH = "owner-assertion.json"
CONTROL_ASSERTION_PATH = "control-assertion.json"
MISSION_ID = "MISSION-CLI-PHASE89"
ROOT = Path(__file__).resolve().parents[2]


def commit_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "collaboration-mission-policy-commit",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--authority-policy",
        AUTHORITY_POLICY_PATH,
        "--mission-policy",
        MISSION_POLICY_PATH,
        "--mission-owner-assertion",
        OWNER_ASSERTION_PATH,
        "--independent-control-assertion",
        CONTROL_ASSERTION_PATH,
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


def status_arguments(*, policy_version: int | None = None) -> list[str]:
    arguments = [
        "collaboration-mission-policy-status",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--mission-id",
        MISSION_ID,
    ]
    if policy_version is not None:
        arguments.extend(("--policy-version", str(policy_version)))
    return arguments


class Phase89CliTests(unittest.TestCase):
    def test_command_contracts_are_closed(self) -> None:
        required = {
            "collaboration-mission-policy-commit": {
                "authority_policy",
                "independent_control_assertion",
                "mission_owner_assertion",
                "mission_policy",
                "registry",
                "store",
            },
            "collaboration-mission-policy-status": {
                "mission_id",
                "registry",
                "store",
            },
        }
        forbidden = {
            "--actor",
            "--audience",
            "--issuer",
            "--key-id",
            "--principal-profile-id",
            "--private-key",
            "--secret",
            "--signing-key",
            "--subject",
        }

        for name, destinations in required.items():
            with self.subTest(name=name):
                command = command_parser(build_parser(), name)
                self.assertEqual(
                    required_destinations(command),
                    destinations,
                )
                self.assertFalse(option_strings(command) & forbidden)

    def test_current_and_compatibility_commands_match(self) -> None:
        for name in (
            "collaboration-mission-policy-commit",
            "collaboration-mission-policy-status",
        ):
            with self.subTest(name=name):
                current = command_parser(build_parser(), name)
                legacy = command_parser(legacy_build_parser(), name)
                self.assertEqual(
                    option_strings(legacy),
                    option_strings(current),
                )
                self.assertEqual(
                    required_destinations(legacy),
                    required_destinations(current),
                )

    def test_commit_forwards_only_loaded_closed_artifacts(self) -> None:
        registry = object()
        mission_policy = object()
        authority_policy = object()
        owner_assertion = object()
        control_assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "mission_id": MISSION_ID,
            "commit_status": "committed_inactive",
        }
        service.commit.return_value = receipt

        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ) as load_registry,
            patch(
                "sunderkey.cli.load_collaboration_mission_reconfiguration_policy",
                return_value=mission_policy,
            ) as load_mission_policy,
            patch(
                "sunderkey.cli.load_collaboration_reconfiguration_authority_policy",
                return_value=authority_policy,
            ) as load_authority_policy,
            patch(
                "sunderkey.cli.load_principal_assertion",
                side_effect=(owner_assertion, control_assertion),
            ) as load_assertion,
            patch(
                "sunderkey.cli.MissionStore",
                return_value=store,
            ) as mission_store,
            patch(
                "sunderkey.cli.AuthenticatedCollaborationMissionPolicyService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*commit_arguments())

        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(load_registry.call_args, call(str(REGISTRY_PATH)))
        self.assertEqual(
            load_mission_policy.call_args,
            call(MISSION_POLICY_PATH),
        )
        self.assertEqual(
            load_authority_policy.call_args,
            call(AUTHORITY_POLICY_PATH),
        )
        self.assertEqual(
            load_assertion.call_args_list,
            [call(OWNER_ASSERTION_PATH), call(CONTROL_ASSERTION_PATH)],
        )
        self.assertEqual(mission_store.call_args, call(STORE_PATH))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.commit.assert_called_once_with(
            mission_policy,
            authority_policy=authority_policy,
            mission_owner_assertion=owner_assertion,
            independent_control_assertion=control_assertion,
        )

    def test_status_reads_latest_or_exact_verified_policy(self) -> None:
        registry = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "mission_id": MISSION_ID,
            "policy_version": 1,
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
                "sunderkey.cli.AuthenticatedCollaborationMissionPolicyService",
                return_value=service,
            ),
        ):
            latest = run_cli(*status_arguments())
            exact = run_cli(*status_arguments(policy_version=3))

        self.assertEqual(latest, receipt.to_dict.return_value)
        self.assertEqual(exact, receipt.to_dict.return_value)
        self.assertEqual(
            service.get.call_args_list,
            [
                call(MISSION_ID, policy_version=None),
                call(MISSION_ID, policy_version=3),
            ],
        )

    def test_output_cannot_replace_any_commit_input(self) -> None:
        protected_options = (
            "--authority-policy",
            "--mission-policy",
            "--mission-owner-assertion",
            "--independent-control-assertion",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "protected.json"
            path.write_text("protected input\n", encoding="utf-8")
            original = path.read_bytes()
            for option in protected_options:
                with self.subTest(option=option):
                    arguments = commit_arguments(output=str(path))
                    arguments[arguments.index(option) + 1] = str(path)
                    with self.assertRaisesRegex(
                        SystemExit,
                        f"--output must not replace {option}",
                    ):
                        run_cli(*arguments)
                    self.assertEqual(path.read_bytes(), original)

    def test_project_version_is_phase89(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
