"""Command-line coverage for authenticated Phase 16 recovery."""

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
MISSION_ID = "MISSION-CLI-PHASE16"
WORK_ITEM_ID = "WIT-RDY-0123456789ABCDEF"
REQUEST_ID = "WRQ-" + "A" * 32
TRANSITION_ID = "WLT-" + "B" * 32
LEASE_EXPIRES_AT = "2026-07-30T10:20:00Z"


class Phase16CliTests(unittest.TestCase):
    def test_command_contracts_are_closed(self) -> None:
        required = {
            "work-recovery-request-authenticated": {
                "expected_generation",
                "expected_lease_expires_at",
                "mission_id",
                "previous_transition_id",
                "principal_assertion",
                "reason",
                "reason_code",
                "registry",
                "remediation",
                "store",
                "work_item_id",
            },
            "work-recovery-approve-authenticated": {
                "authority",
                "constraint",
                "decision_owner",
                "principal_assertion",
                "recovery_request_id",
                "registry",
                "store",
            },
            "work-recovery-deny-authenticated": {
                "decision_owner",
                "principal_assertion",
                "reason",
                "reason_code",
                "recovery_request_id",
                "registry",
                "risk",
                "store",
            },
            "work-recovery-status": {
                "recovery_request_id",
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
            "work-recovery-request-authenticated",
            "work-recovery-approve-authenticated",
            "work-recovery-deny-authenticated",
            "work-recovery-status",
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

    def test_handlers_forward_recovery_contracts(self) -> None:
        registry = object()
        assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "recovery_request_id": REQUEST_ID,
        }
        service.request.return_value = receipt
        service.approve.return_value = receipt
        service.deny.return_value = receipt
        service.get.return_value = receipt.to_dict.return_value
        common = [
            "--store",
            STORE_PATH,
            "--registry",
            str(REGISTRY_PATH),
        ]
        authenticated = [
            *common,
            "--principal-assertion",
            ASSERTION_PATH,
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
                "sunderkey.cli.AuthenticatedWorkRecoveryService",
                return_value=service,
            ) as service_type,
        ):
            request_output = run_cli(
                "work-recovery-request-authenticated",
                *authenticated,
                "--mission-id",
                MISSION_ID,
                "--work-item-id",
                WORK_ITEM_ID,
                "--expected-generation",
                "3",
                "--previous-transition-id",
                TRANSITION_ID,
                "--expected-lease-expires-at",
                LEASE_EXPIRES_AT,
                "--reason-code",
                "attempts_exhausted",
                "--reason",
                "Three attempts exhausted",
                "--remediation",
                "Apply reviewed recovery",
            )
            approve_output = run_cli(
                "work-recovery-approve-authenticated",
                *authenticated,
                "--recovery-request-id",
                REQUEST_ID,
                "--decision-owner",
                "independent-control",
                "--authority",
                "Independent Control",
                "--constraint",
                "same owner only",
            )
            deny_output = run_cli(
                "work-recovery-deny-authenticated",
                *authenticated,
                "--recovery-request-id",
                REQUEST_ID,
                "--decision-owner",
                "independent-control",
                "--reason-code",
                "risk_unacceptable",
                "--reason",
                "Risk is not acceptable",
                "--risk",
                "Boundary would be exceeded",
            )
            status_output = run_cli(
                "work-recovery-status",
                *common,
                "--recovery-request-id",
                REQUEST_ID,
            )
        for output in (
            request_output,
            approve_output,
            deny_output,
            status_output,
        ):
            self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(
            load_registry.call_args_list,
            [call(str(REGISTRY_PATH))] * 4,
        )
        self.assertEqual(
            load_assertion.call_args_list,
            [call(ASSERTION_PATH)] * 3,
        )
        self.assertEqual(
            mission_store.call_args_list,
            [call(STORE_PATH)] * 4,
        )
        self.assertEqual(
            service_type.call_args_list,
            [call(store, registry)] * 4,
        )
        service.request.assert_called_once_with(
            assertion,
            MISSION_ID,
            WORK_ITEM_ID,
            expected_generation=3,
            previous_transition_id=TRANSITION_ID,
            expected_lease_expires_at=LEASE_EXPIRES_AT,
            reason_code="attempts_exhausted",
            reason="Three attempts exhausted",
            remediation="Apply reviewed recovery",
        )
        service.approve.assert_called_once_with(
            assertion,
            REQUEST_ID,
            decision_owner="independent-control",
            authority="Independent Control",
            constraints=["same owner only"],
        )
        service.deny.assert_called_once_with(
            assertion,
            REQUEST_ID,
            decision_owner="independent-control",
            reason_code="risk_unacceptable",
            reason="Risk is not acceptable",
            risk="Boundary would be exceeded",
        )
        service.get.assert_called_once_with(REQUEST_ID)


if __name__ == "__main__":
    unittest.main()
