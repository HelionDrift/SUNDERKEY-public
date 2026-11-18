"""Command-line coverage for authenticated Phase 18 handoff."""

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

OWNER_ASSERTION_PATH = "owner-assertion.json"
CANDIDATE_ASSERTION_PATH = "candidate-assertion.json"
STORE_PATH = "missions.sqlite3"
MISSION_ID = "MISSION-CLI-PHASE18"
WORK_ITEM_ID = "WIT-SPEC-0123456789ABCDEF"
HANDOFF_ID = "WHF-" + "A" * 32
TRANSITION_ID = "WLT-" + "B" * 32
LEASE_EXPIRES_AT = "2026-07-30T10:20:00Z"


class Phase18CliTests(unittest.TestCase):
    def test_command_contracts_are_closed(self) -> None:
        required = {
            "work-handoff-authenticated": {
                "candidate_assertion",
                "expected_generation",
                "mission_id",
                "owner_assertion",
                "reason",
                "reason_code",
                "registry",
                "store",
                "work_item_id",
            },
            "work-handoff-status": {
                "handoff_id",
                "registry",
                "store",
            },
        }
        forbidden = {
            "--actor",
            "--audience",
            "--candidate-profile-id",
            "--issuer",
            "--key-id",
            "--owner-profile-id",
            "--policy",
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
            "work-handoff-authenticated",
            "work-handoff-status",
        ):
            with self.subTest(name=name):
                current = command_parser(build_parser(), name)
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

    def test_handlers_forward_handoff_contracts(self) -> None:
        registry = object()
        owner_assertion = object()
        candidate_assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "handoff_id": HANDOFF_ID,
        }
        service.handoff.return_value = receipt
        service.get.return_value = receipt
        common = [
            "--store",
            STORE_PATH,
            "--registry",
            str(REGISTRY_PATH),
        ]
        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ) as load_registry,
            patch(
                "sunderkey.cli.load_principal_assertion",
                side_effect=[
                    owner_assertion,
                    candidate_assertion,
                ],
            ) as load_assertion,
            patch(
                "sunderkey.cli.MissionStore",
                return_value=store,
            ) as mission_store,
            patch(
                "sunderkey.cli.AuthenticatedWorkHandoffService",
                return_value=service,
            ) as service_type,
        ):
            handoff_output = run_cli(
                "work-handoff-authenticated",
                *common,
                "--owner-assertion",
                OWNER_ASSERTION_PATH,
                "--candidate-assertion",
                CANDIDATE_ASSERTION_PATH,
                "--mission-id",
                MISSION_ID,
                "--work-item-id",
                WORK_ITEM_ID,
                "--expected-generation",
                "1",
                "--previous-transition-id",
                TRANSITION_ID,
                "--expected-lease-expires-at",
                LEASE_EXPIRES_AT,
                "--reason-code",
                "load_balance",
                "--reason",
                "Balance the assigned specialist workload",
            )
            status_output = run_cli(
                "work-handoff-status",
                *common,
                "--handoff-id",
                HANDOFF_ID,
            )
        self.assertEqual(
            handoff_output,
            receipt.to_dict.return_value,
        )
        self.assertEqual(
            status_output,
            receipt.to_dict.return_value,
        )
        self.assertEqual(
            load_registry.call_args_list,
            [call(str(REGISTRY_PATH))] * 2,
        )
        self.assertEqual(
            load_assertion.call_args_list,
            [
                call(OWNER_ASSERTION_PATH),
                call(CANDIDATE_ASSERTION_PATH),
            ],
        )
        self.assertEqual(
            mission_store.call_args_list,
            [call(STORE_PATH)] * 2,
        )
        self.assertEqual(
            service_type.call_args_list,
            [call(store, registry)] * 2,
        )
        service.handoff.assert_called_once_with(
            owner_assertion,
            candidate_assertion,
            MISSION_ID,
            WORK_ITEM_ID,
            expected_generation=1,
            previous_transition_id=TRANSITION_ID,
            expected_lease_expires_at=LEASE_EXPIRES_AT,
            reason_code="load_balance",
            reason="Balance the assigned specialist workload",
        )
        service.get.assert_called_once_with(HANDOFF_ID)


if __name__ == "__main__":
    unittest.main()
