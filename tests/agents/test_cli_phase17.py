"""Command-line coverage for authenticated Phase 17 cancellation."""

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

ASSERTION_PATH = "principal-assertion.json"
STORE_PATH = "missions.sqlite3"
MISSION_ID = "MISSION-CLI-PHASE17"
WORK_ITEM_ID = "WIT-RDY-0123456789ABCDEF"
CANCELLATION_ID = "WCN-" + "A" * 32
TRANSITION_ID = "WLT-" + "B" * 32
LEASE_EXPIRES_AT = "2026-07-30T10:20:00Z"


class Phase17CliTests(unittest.TestCase):
    def test_command_contracts_are_closed(self) -> None:
        required = {
            "work-cancel-authenticated": {
                "decision_owner",
                "expected_generation",
                "mission_id",
                "principal_assertion",
                "reason",
                "reason_code",
                "registry",
                "risk",
                "store",
                "work_item_id",
            },
            "work-cancellation-status": {
                "cancellation_id",
                "registry",
                "store",
            },
        }
        forbidden = {
            "--actor",
            "--audience",
            "--issuer",
            "--key-id",
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
            "work-cancel-authenticated",
            "work-cancellation-status",
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

    def test_handlers_forward_cancellation_contracts(self) -> None:
        registry = object()
        assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "cancellation_id": CANCELLATION_ID,
        }
        service.cancel.return_value = receipt
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
                return_value=assertion,
            ) as load_assertion,
            patch(
                "sunderkey.cli.MissionStore",
                return_value=store,
            ) as mission_store,
            patch(
                "sunderkey.cli.AuthenticatedWorkCancellationService",
                return_value=service,
            ) as service_type,
        ):
            cancel_output = run_cli(
                "work-cancel-authenticated",
                *common,
                "--principal-assertion",
                ASSERTION_PATH,
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
                "scope_reduced",
                "--reason",
                "Work is no longer required",
                "--risk",
                "Continuing exceeds the revised mission need",
                "--decision-owner",
                "independent-control",
            )
            status_output = run_cli(
                "work-cancellation-status",
                *common,
                "--cancellation-id",
                CANCELLATION_ID,
            )
        self.assertEqual(
            cancel_output,
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
        load_assertion.assert_called_once_with(ASSERTION_PATH)
        self.assertEqual(
            mission_store.call_args_list,
            [call(STORE_PATH)] * 2,
        )
        self.assertEqual(
            service_type.call_args_list,
            [call(store, registry)] * 2,
        )
        service.cancel.assert_called_once_with(
            assertion,
            MISSION_ID,
            WORK_ITEM_ID,
            expected_generation=1,
            previous_transition_id=TRANSITION_ID,
            expected_lease_expires_at=LEASE_EXPIRES_AT,
            reason_code="scope_reduced",
            reason="Work is no longer required",
            risk="Continuing exceeds the revised mission need",
            decision_owner="independent-control",
        )
        service.get.assert_called_once_with(CANCELLATION_ID)


if __name__ == "__main__":
    unittest.main()
