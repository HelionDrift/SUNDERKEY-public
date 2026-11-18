"""Phase 100 command-line ownership revocation coverage."""

from __future__ import annotations

import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.cli import build_parser

from .test_cli_phase5 import run_cli
from .test_cli_phase9 import command_parser, option_strings, required_destinations
from .test_store import REGISTRY_PATH

ROOT = Path(__file__).resolve().parents[2]
STORE_PATH = "missions.sqlite3"
MISSION_ID = "MISSION-CLI-PHASE100"
WORK_ITEM_ID = "WIT-SPECIALIST-1234567890ABCDEF"
ENTRY_ID = "OCE-" + "A" * 32
REVOCATION_PATH = "ownership-revocation.json"
PREFLIGHT_PATH = "ownership-revocation-preflight.json"
PLANNED_ASSERTION_PATH = "planned-owner-assertion.json"
CONTROL_ASSERTION_PATH = "control-assertion.json"


def preflight_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "collaboration-ownership-revocation-preflight",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--revocation",
        REVOCATION_PATH,
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


def commit_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "collaboration-ownership-revocation-commit",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--preflight",
        PREFLIGHT_PATH,
        "--planned-owner-assertion",
        PLANNED_ASSERTION_PATH,
        "--independent-control-assertion",
        CONTROL_ASSERTION_PATH,
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


def status_arguments(*, entry_id: str | None = None) -> list[str]:
    arguments = [
        "collaboration-ownership-revocation-status",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--mission-id",
        MISSION_ID,
        "--work-item-id",
        WORK_ITEM_ID,
    ]
    if entry_id is not None:
        arguments.extend(("--entry-id", entry_id))
    return arguments


class Phase100CliTests(unittest.TestCase):
    def test_command_contracts_are_closed_and_legacy_equal(self) -> None:
        required = {
            "collaboration-ownership-revocation-preflight": {
                "registry",
                "revocation",
                "store",
            },
            "collaboration-ownership-revocation-commit": {
                "independent_control_assertion",
                "planned_owner_assertion",
                "preflight",
                "registry",
                "store",
            },
            "collaboration-ownership-revocation-status": {
                "mission_id",
                "registry",
                "store",
                "work_item_id",
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
                current = command_parser(build_parser(), name)
                legacy = command_parser(legacy_build_parser(), name)
                self.assertEqual(required_destinations(current), destinations)
                self.assertEqual(option_strings(legacy), option_strings(current))
                self.assertEqual(
                    required_destinations(legacy),
                    required_destinations(current),
                )
                self.assertFalse(option_strings(current) & forbidden)

    def test_preflight_forwards_only_loaded_revocation(self) -> None:
        registry = object()
        revocation = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "admission_status": "admissible_pending_dual_authenticated_commit",
        }
        service.preflight.return_value = receipt
        with (
            patch("sunderkey.cli.load_registry", return_value=registry),
            patch(
                "sunderkey.cli.load_collaboration_ownership_revocation",
                return_value=revocation,
            ) as load_revocation,
            patch("sunderkey.cli.MissionStore", return_value=store),
            patch(
                "sunderkey.cli.CollaborationOwnershipRevocationPreflightService",
                return_value=service,
            ),
        ):
            output = run_cli(*preflight_arguments())
        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(load_revocation.call_args, call(REVOCATION_PATH))
        service.preflight.assert_called_once_with(revocation)

    def test_commit_forwards_only_loaded_closed_artifacts(self) -> None:
        registry = object()
        preflight = object()
        planned_assertion = object()
        control_assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "commit_status": "committed_active",
        }
        service.commit.return_value = receipt
        with (
            patch("sunderkey.cli.load_registry", return_value=registry),
            patch(
                "sunderkey.cli.load_collaboration_ownership_revocation_preflight",
                return_value=preflight,
            ) as load_preflight,
            patch(
                "sunderkey.cli.load_principal_assertion",
                side_effect=(planned_assertion, control_assertion),
            ) as load_assertion,
            patch("sunderkey.cli.MissionStore", return_value=store) as store_type,
            patch(
                "sunderkey.cli.AuthenticatedCollaborationOwnershipRevocationService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*commit_arguments())
        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(load_preflight.call_args, call(PREFLIGHT_PATH))
        self.assertEqual(
            load_assertion.call_args_list,
            [call(PLANNED_ASSERTION_PATH), call(CONTROL_ASSERTION_PATH)],
        )
        self.assertEqual(store_type.call_args, call(STORE_PATH))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.commit.assert_called_once_with(
            preflight,
            planned_owner_assertion=planned_assertion,
            independent_control_assertion=control_assertion,
        )

    def test_status_reads_latest_or_exact_verified_revocation(self) -> None:
        registry = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "commit_status": "committed_active",
        }
        service.get.return_value = receipt
        with (
            patch("sunderkey.cli.load_registry", return_value=registry),
            patch("sunderkey.cli.MissionStore", return_value=store),
            patch(
                "sunderkey.cli.AuthenticatedCollaborationOwnershipRevocationService",
                return_value=service,
            ),
        ):
            latest = run_cli(*status_arguments())
            exact = run_cli(*status_arguments(entry_id=ENTRY_ID))
        self.assertEqual(latest, receipt.to_dict.return_value)
        self.assertEqual(exact, receipt.to_dict.return_value)
        self.assertEqual(
            service.get.call_args_list,
            [
                call(MISSION_ID, WORK_ITEM_ID, entry_id=None),
                call(MISSION_ID, WORK_ITEM_ID, entry_id=ENTRY_ID),
            ],
        )

    def test_output_cannot_replace_any_mutating_command_input(self) -> None:
        cases = (
            (preflight_arguments, ("--revocation",)),
            (
                commit_arguments,
                (
                    "--preflight",
                    "--planned-owner-assertion",
                    "--independent-control-assertion",
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "protected.json"
            path.write_text("protected input\n", encoding="utf-8")
            original = path.read_bytes()
            for argument_builder, protected_options in cases:
                for option in protected_options:
                    with self.subTest(option=option):
                        arguments = argument_builder(output=str(path))
                        arguments[arguments.index(option) + 1] = str(path)
                        with self.assertRaisesRegex(
                            SystemExit,
                            f"--output must not replace {option}",
                        ):
                            run_cli(*arguments)
                        self.assertEqual(path.read_bytes(), original)

    def test_project_version_is_phase100(self) -> None:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
