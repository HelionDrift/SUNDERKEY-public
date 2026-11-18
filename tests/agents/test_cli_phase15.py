"""Command-line coverage for authenticated Phase 15 owner leases."""

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
STORE_PATH = "missions.sqlite3"
MISSION_ID = "MISSION-CLI-PHASE15"
WORK_ITEM_ID = "WIT-RDY-0123456789ABCDEF"
PREVIOUS_TRANSITION_ID = "WLT-" + "A" * 32
LEASE_EXPIRES_AT = "2026-07-30T10:20:00Z"
ROOT = Path(__file__).resolve().parents[2]


def common_arguments(command: str) -> list[str]:
    return [
        command,
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--principal-assertion",
        ASSERTION_PATH,
        "--mission-id",
        MISSION_ID,
        "--work-item-id",
        WORK_ITEM_ID,
    ]


def active_arguments(command: str) -> list[str]:
    return [
        *common_arguments(command),
        "--claim-generation",
        "2",
        "--previous-transition-id",
        PREVIOUS_TRANSITION_ID,
        "--expected-lease-expires-at",
        LEASE_EXPIRES_AT,
    ]


class Phase15CliTests(unittest.TestCase):
    def test_command_contracts_are_closed(self) -> None:
        required = {
            "work-claim-authenticated": {
                "expected_generation",
                "mission_id",
                "principal_assertion",
                "registry",
                "store",
                "work_item_id",
            },
            "work-renew-authenticated": {
                "claim_generation",
                "expected_lease_expires_at",
                "mission_id",
                "previous_transition_id",
                "principal_assertion",
                "registry",
                "store",
                "work_item_id",
            },
            "work-release-authenticated": {
                "claim_generation",
                "expected_lease_expires_at",
                "mission_id",
                "previous_transition_id",
                "principal_assertion",
                "reason",
                "reason_code",
                "registry",
                "store",
                "work_item_id",
            },
            "work-complete-authenticated": {
                "claim_generation",
                "evidence_manifest_sha256",
                "expected_lease_expires_at",
                "mission_id",
                "previous_transition_id",
                "principal_assertion",
                "registry",
                "result_id",
                "result_sha256",
                "store",
                "work_item_id",
            },
            "work-status": {
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
                self.assertFalse(
                    option_strings(command) & forbidden
                )

    def test_current_and_compatibility_commands_match(self) -> None:
        for name in (
            "work-claim-authenticated",
            "work-renew-authenticated",
            "work-release-authenticated",
            "work-complete-authenticated",
            "work-status",
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

    def test_handlers_forward_exact_fences_and_result_bindings(
        self,
    ) -> None:
        registry = object()
        assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "mission_id": MISSION_ID,
        }
        service.claim.return_value = receipt
        service.renew.return_value = receipt
        service.release.return_value = receipt
        service.complete.return_value = receipt
        service.status.return_value = receipt

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
                "sunderkey.cli.AuthenticatedWorkItemLeaseService",
                return_value=service,
            ) as service_type,
        ):
            claim_output = run_cli(
                *common_arguments(
                    "work-claim-authenticated"
                ),
                "--expected-generation",
                "1",
            )
            renew_output = run_cli(
                *active_arguments(
                    "work-renew-authenticated"
                )
            )
            release_output = run_cli(
                *active_arguments(
                    "work-release-authenticated"
                ),
                "--reason-code",
                "owner_release",
                "--reason",
                "Owner cannot continue",
            )
            complete_output = run_cli(
                *active_arguments(
                    "work-complete-authenticated"
                ),
                "--result-id",
                "RES-CLI-001",
                "--result-sha256",
                "sha256:" + "7" * 64,
                "--evidence-manifest-sha256",
                "sha256:" + "6" * 64,
            )
            status_output = run_cli(
                "work-status",
                "--store",
                STORE_PATH,
                "--registry",
                str(REGISTRY_PATH),
                "--mission-id",
                MISSION_ID,
                "--work-item-id",
                WORK_ITEM_ID,
            )

        for output in (
            claim_output,
            renew_output,
            release_output,
            complete_output,
            status_output,
        ):
            self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(
            load_registry.call_args_list,
            [call(str(REGISTRY_PATH))] * 5,
        )
        self.assertEqual(
            load_assertion.call_args_list,
            [call(ASSERTION_PATH)] * 4,
        )
        self.assertEqual(
            mission_store.call_args_list,
            [call(STORE_PATH)] * 5,
        )
        self.assertEqual(
            service_type.call_args_list,
            [call(store, registry)] * 5,
        )
        service.claim.assert_called_once_with(
            assertion,
            MISSION_ID,
            WORK_ITEM_ID,
            expected_generation=1,
        )
        service.renew.assert_called_once_with(
            assertion,
            MISSION_ID,
            WORK_ITEM_ID,
            claim_generation=2,
            previous_transition_id=PREVIOUS_TRANSITION_ID,
            expected_lease_expires_at=LEASE_EXPIRES_AT,
        )
        service.release.assert_called_once_with(
            assertion,
            MISSION_ID,
            WORK_ITEM_ID,
            claim_generation=2,
            previous_transition_id=PREVIOUS_TRANSITION_ID,
            expected_lease_expires_at=LEASE_EXPIRES_AT,
            reason_code="owner_release",
            reason="Owner cannot continue",
        )
        service.complete.assert_called_once_with(
            assertion,
            MISSION_ID,
            WORK_ITEM_ID,
            claim_generation=2,
            previous_transition_id=PREVIOUS_TRANSITION_ID,
            expected_lease_expires_at=LEASE_EXPIRES_AT,
            result_id="RES-CLI-001",
            result_sha256="sha256:" + "7" * 64,
            evidence_manifest_sha256="sha256:" + "6" * 64,
        )
        service.status.assert_called_once_with(
            MISSION_ID,
            work_item_id=WORK_ITEM_ID,
        )

    def test_migrate_help_and_project_version_are_phase15(
        self,
    ) -> None:
        help_text = " ".join(build_parser().format_help().split())
        self.assertIn(
            "Migrate a verified v1 through v15 mission store to v16",
            help_text,
        )
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
