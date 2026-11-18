"""Phase 106 privileged ownership reassignment CLI coverage."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.cli import build_parser

from .test_cli_phase5 import run_cli
from .test_cli_phase9 import command_parser, option_strings, required_destinations
from .test_store import REGISTRY_PATH

STORE_PATH = "missions.sqlite3"
MISSION_ID = "MISSION-CLI-PHASE106"
WORK_ITEM_ID = "WIT-CONTROL-1234567890ABCDEF"
ENTRY_ID = "OCE-" + "A" * 32
ENTRY_PATH = "privileged-reassignment-entry.json"
PREFLIGHT_PATH = "privileged-reassignment-preflight.json"
CURRENT_ASSERTION_PATH = "current-owner-assertion.json"
PROPOSED_ASSERTION_PATH = "proposed-owner-assertion.json"
CONTROL_ASSERTION_PATH = "independent-control-assertion.json"
SECOND_ASSERTION_PATH = "second-authority-assertion.json"


def preflight_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "collaboration-ownership-privileged-reassignment-preflight",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--ownership-entry",
        ENTRY_PATH,
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


def commit_arguments(
    *,
    output: str | None = None,
    include_second: bool = True,
) -> list[str]:
    arguments = [
        "collaboration-ownership-privileged-reassignment-commit",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--preflight",
        PREFLIGHT_PATH,
        "--current-owner-assertion",
        CURRENT_ASSERTION_PATH,
        "--proposed-owner-assertion",
        PROPOSED_ASSERTION_PATH,
        "--independent-control-assertion",
        CONTROL_ASSERTION_PATH,
    ]
    if include_second:
        arguments.extend(
            ("--second-authority-assertion", SECOND_ASSERTION_PATH)
        )
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


def status_arguments(*, entry_id: str | None = None) -> list[str]:
    arguments = [
        "collaboration-ownership-privileged-reassignment-status",
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


class Phase106CliTests(unittest.TestCase):
    def test_command_contracts_are_closed_and_legacy_equal(self) -> None:
        required = {
            "collaboration-ownership-privileged-reassignment-preflight": {
                "ownership_entry",
                "registry",
                "store",
            },
            "collaboration-ownership-privileged-reassignment-commit": {
                "current_owner_assertion",
                "independent_control_assertion",
                "preflight",
                "proposed_owner_assertion",
                "registry",
                "store",
            },
            "collaboration-ownership-privileged-reassignment-status": {
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
        commit = command_parser(
            build_parser(),
            "collaboration-ownership-privileged-reassignment-commit",
        )
        self.assertIn("--second-authority-assertion", option_strings(commit))

    def test_preflight_forwards_only_loaded_entry(self) -> None:
        registry = object()
        entry = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {"admission_status": "admissible"}
        service.preflight.return_value = receipt
        with (
            patch("sunderkey.cli.load_registry", return_value=registry),
            patch(
                "sunderkey.cli.load_collaboration_ownership_chain_entry",
                return_value=entry,
            ) as load_entry,
            patch("sunderkey.cli.MissionStore", return_value=store),
            patch(
                "sunderkey.cli."
                "CollaborationOwnershipPrivilegedReassignmentPreflightService",
                return_value=service,
            ),
        ):
            output = run_cli(*preflight_arguments())
        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(load_entry.call_args, call(ENTRY_PATH))
        service.preflight.assert_called_once_with(entry)

    def test_commit_forwards_exact_three_or_four_authority_artifacts(self) -> None:
        registry = object()
        preflight = object()
        assertions = [object(), object(), object(), object()]
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {"commit_status": "committed_active"}
        service.commit.return_value = receipt
        with (
            patch("sunderkey.cli.load_registry", return_value=registry),
            patch(
                "sunderkey.cli."
                "load_collaboration_ownership_privileged_reassignment_preflight",
                return_value=preflight,
            ),
            patch(
                "sunderkey.cli.load_principal_assertion",
                side_effect=assertions,
            ) as load_assertion,
            patch("sunderkey.cli.MissionStore", return_value=store),
            patch(
                "sunderkey.cli."
                "AuthenticatedCollaborationOwnershipPrivilegedReassignmentService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*commit_arguments())
        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(
            load_assertion.call_args_list,
            [
                call(CURRENT_ASSERTION_PATH),
                call(PROPOSED_ASSERTION_PATH),
                call(CONTROL_ASSERTION_PATH),
                call(SECOND_ASSERTION_PATH),
            ],
        )
        self.assertEqual(service_type.call_args, call(store, registry))
        service.commit.assert_called_once_with(
            preflight,
            current_owner_assertion=assertions[0],
            proposed_owner_assertion=assertions[1],
            independent_control_assertion=assertions[2],
            second_authority_assertion=assertions[3],
        )

    def test_optional_second_authority_forwards_none(self) -> None:
        service = Mock()
        service.commit.return_value.to_dict.return_value = {"status": "valid"}
        assertions = [object(), object(), object()]
        with (
            patch("sunderkey.cli.load_registry", return_value=object()),
            patch(
                "sunderkey.cli."
                "load_collaboration_ownership_privileged_reassignment_preflight",
                return_value=object(),
            ),
            patch(
                "sunderkey.cli.load_principal_assertion",
                side_effect=assertions,
            ),
            patch("sunderkey.cli.MissionStore", return_value=object()),
            patch(
                "sunderkey.cli."
                "AuthenticatedCollaborationOwnershipPrivilegedReassignmentService",
                return_value=service,
            ),
        ):
            run_cli(*commit_arguments(include_second=False))
        self.assertIsNone(
            service.commit.call_args.kwargs["second_authority_assertion"]
        )

    def test_status_reads_latest_or_exact_verified_commit(self) -> None:
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {"commit_status": "committed_active"}
        service.get.return_value = receipt
        with (
            patch("sunderkey.cli.load_registry", return_value=object()),
            patch("sunderkey.cli.MissionStore", return_value=object()),
            patch(
                "sunderkey.cli."
                "AuthenticatedCollaborationOwnershipPrivilegedReassignmentService",
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
            (preflight_arguments, ("--ownership-entry",)),
            (
                commit_arguments,
                (
                    "--preflight",
                    "--current-owner-assertion",
                    "--proposed-owner-assertion",
                    "--independent-control-assertion",
                    "--second-authority-assertion",
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


if __name__ == "__main__":
    unittest.main()
