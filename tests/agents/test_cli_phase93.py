"""Phase 93 command-line ownership transition coverage."""

from __future__ import annotations

import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.cli import build_parser
from sunderkey.collaboration_ownership_preflight import (
    load_collaboration_ownership_transition_preflight,
)
from sunderkey.errors import CollaborationPlanError

from . import test_collaboration_ownership_authentication_phase91 as phase91
from .test_cli_phase5 import run_cli
from .test_cli_phase9 import command_parser, option_strings, required_destinations
from .test_store import REGISTRY_PATH

ROOT = Path(__file__).resolve().parents[2]
STORE_PATH = "missions.sqlite3"
MISSION_ID = "MISSION-CLI-PHASE93"
WORK_ITEM_ID = "WIT-SPECIALIST-1234567890ABCDEF"
ENTRY_ID = "OCE-" + "A" * 32
PREFLIGHT_PATH = "ownership-preflight.json"
CURRENT_ASSERTION_PATH = "current-owner-assertion.json"
PROPOSED_ASSERTION_PATH = "proposed-owner-assertion.json"
CONTROL_ASSERTION_PATH = "control-assertion.json"


def commit_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "collaboration-ownership-transition-commit",
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
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


def status_arguments(*, entry_id: str | None = None) -> list[str]:
    arguments = [
        "collaboration-ownership-transition-status",
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


class Phase93CliTests(unittest.TestCase):
    def test_command_contracts_are_closed_and_legacy_equal(self) -> None:
        required = {
            "collaboration-ownership-transition-commit": {
                "current_owner_assertion",
                "independent_control_assertion",
                "preflight",
                "proposed_owner_assertion",
                "registry",
                "store",
            },
            "collaboration-ownership-transition-status": {
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

    def test_commit_forwards_only_loaded_closed_artifacts(self) -> None:
        registry = object()
        preflight = object()
        current_assertion = object()
        proposed_assertion = object()
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
            patch("sunderkey.cli.load_registry", return_value=registry) as load_registry,
            patch(
                "sunderkey.cli.load_collaboration_ownership_transition_preflight",
                return_value=preflight,
            ) as load_preflight,
            patch(
                "sunderkey.cli.load_principal_assertion",
                side_effect=(
                    current_assertion,
                    proposed_assertion,
                    control_assertion,
                ),
            ) as load_assertion,
            patch("sunderkey.cli.MissionStore", return_value=store) as store_type,
            patch(
                "sunderkey.cli.AuthenticatedCollaborationOwnershipService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*commit_arguments())
        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(load_registry.call_args, call(str(REGISTRY_PATH)))
        self.assertEqual(load_preflight.call_args, call(PREFLIGHT_PATH))
        self.assertEqual(
            load_assertion.call_args_list,
            [
                call(CURRENT_ASSERTION_PATH),
                call(PROPOSED_ASSERTION_PATH),
                call(CONTROL_ASSERTION_PATH),
            ],
        )
        self.assertEqual(store_type.call_args, call(STORE_PATH))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.commit.assert_called_once_with(
            preflight,
            current_owner_assertion=current_assertion,
            proposed_owner_assertion=proposed_assertion,
            independent_control_assertion=control_assertion,
        )

    def test_status_reads_latest_or_exact_verified_entry(self) -> None:
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
                "sunderkey.cli.AuthenticatedCollaborationOwnershipService",
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

    def test_output_cannot_replace_any_commit_input(self) -> None:
        protected_options = (
            "--preflight",
            "--current-owner-assertion",
            "--proposed-owner-assertion",
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

    def test_project_version_is_phase93(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["version"], "0.1.0")


class Phase93PreflightLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase91.CollaborationOwnershipAuthenticationPhase91Tests(methodName="runTest")
        phase91.CollaborationOwnershipAuthenticationPhase91Tests.setUpClass()
        fixture.setUp()
        self.preflight = fixture.preflight

    def test_loader_round_trips_exact_content_addressed_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "preflight.json"
            path.write_text(
                json.dumps(self.preflight.to_dict()),
                encoding="utf-8",
            )
            self.assertEqual(
                load_collaboration_ownership_transition_preflight(path),
                self.preflight,
            )

    def test_loader_rejects_changed_or_duplicate_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            changed_path = Path(temporary) / "changed.json"
            changed = self.preflight.to_dict()
            changed["work_fence"]["expected_generation"] = 1
            changed_path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(CollaborationPlanError, "identity"):
                load_collaboration_ownership_transition_preflight(changed_path)

            duplicate_path = Path(temporary) / "duplicate.json"
            duplicate_path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_ownership_transition_preflight(duplicate_path)


if __name__ == "__main__":
    unittest.main()
