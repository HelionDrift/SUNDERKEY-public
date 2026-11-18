"""Command-line coverage for authenticated Phase 10 approval submission."""

from __future__ import annotations

import tempfile
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
MISSION_ID = "MISSION-CLI-PHASE10"
PROPOSAL_ID = "EVT-PROP-CLI-PHASE10"
EXECUTOR_ID = "AOE-GB-D06-S09"
STORE_PATH = "missions.sqlite3"


def submit_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "approval-submit-authenticated",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--principal-assertion",
        ASSERTION_PATH,
        "--mission-id",
        MISSION_ID,
        "--proposal-id",
        PROPOSAL_ID,
        "--executor-profile-id",
        EXECUTOR_ID,
        "--review-expires-at",
        "2030-01-01T00:00:00Z",
        "--idempotency-key",
        "phase10-cli-submit",
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


class Phase10CliTests(unittest.TestCase):
    def test_authenticated_submit_parser_contract(self) -> None:
        command = command_parser(
            build_parser(),
            "approval-submit-authenticated",
        )

        self.assertEqual(
            required_destinations(command),
            {
                "executor_profile_id",
                "idempotency_key",
                "mission_id",
                "principal_assertion",
                "proposal_id",
                "registry",
                "review_expires_at",
                "store",
            },
        )
        options = option_strings(command)
        self.assertNotIn("--principal-profile-id", options)
        for unsafe in (
            "--private-key",
            "--signing-key",
            "--secret",
            "--subject",
            "--issuer",
            "--key-id",
            "--scope-grant",
            "--policy",
        ):
            self.assertNotIn(unsafe, options)

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "approval-submit-authenticated",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "approval-submit-authenticated",
        )

        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )
        self.assertIn(
            "principal_profile_id",
            required_destinations(
                command_parser(build_parser(), "approval-submit")
            ),
        )

    def test_handler_forwards_only_closed_arguments(self) -> None:
        registry = object()
        assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "approval_id": "APR-CLI-PHASE10",
            "operation": "approval_submit",
        }
        service.submit.return_value = receipt

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
                "sunderkey.cli.AuthenticatedApprovalSubmissionService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*submit_arguments())

        self.assertEqual(
            output,
            {
                "approval_id": "APR-CLI-PHASE10",
                "operation": "approval_submit",
            },
        )
        self.assertEqual(load_registry.call_args, call(str(REGISTRY_PATH)))
        self.assertEqual(load_assertion.call_args, call(ASSERTION_PATH))
        self.assertEqual(mission_store.call_args, call(STORE_PATH))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.submit.assert_called_once_with(
            assertion,
            mission_id=MISSION_ID,
            proposal_id=PROPOSAL_ID,
            executor_profile_id=EXECUTOR_ID,
            review_expires_at="2030-01-01T00:00:00Z",
            idempotency_key="phase10-cli-submit",
        )

    def test_output_cannot_replace_principal_assertion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assertion_path = Path(temporary) / ASSERTION_PATH
            assertion_path.write_text(
                "principal assertion input\n",
                encoding="utf-8",
            )
            arguments = submit_arguments(output=str(assertion_path))
            assertion_option = arguments.index("--principal-assertion")
            arguments[assertion_option + 1] = str(assertion_path)
            original = assertion_path.read_bytes()

            with self.assertRaisesRegex(
                SystemExit,
                "--output must not replace --principal-assertion",
            ):
                run_cli(*arguments)
            self.assertEqual(assertion_path.read_bytes(), original)

    def test_principal_assertion_file_uses_strict_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assertion_path = Path(temporary) / ASSERTION_PATH
            assertion_path.write_text(
                '{"schema_version":1,"schema_version":1}\n',
                encoding="utf-8",
            )
            arguments = submit_arguments()
            assertion_option = arguments.index("--principal-assertion")
            arguments[assertion_option + 1] = str(assertion_path)

            with self.assertRaisesRegex(
                SystemExit,
                "Duplicate JSON object key: schema_version",
            ):
                run_cli(*arguments)

    def test_migrate_help_names_every_v8_source_version(self) -> None:
        help_text = " ".join(build_parser().format_help().split())
        self.assertIn(
            (
                "Migrate a verified v1 through v15 mission store to v16"
            ),
            help_text,
        )


if __name__ == "__main__":
    unittest.main()
