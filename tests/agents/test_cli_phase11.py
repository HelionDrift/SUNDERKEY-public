"""Command-line coverage for authenticated Phase 11 approval revocation."""

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

ASSERTION_PATH = "principal-assertion.json"
APPROVAL_ID = "APR-CLI-PHASE11"
STORE_PATH = "missions.sqlite3"
ROOT = Path(__file__).resolve().parents[2]


def revoke_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "approval-revoke-authenticated",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--principal-assertion",
        ASSERTION_PATH,
        "--approval-id",
        APPROVAL_ID,
        "--reason-code",
        "authorization_withdrawn",
        "--reason",
        "Control withdrew the simulation authorization",
        "--risk",
        "The authorization is no longer current",
        "--decision-owner",
        "range-control",
        "--idempotency-key",
        "phase11-cli-revoke",
        "--expected-version",
        "2",
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


class Phase11CliTests(unittest.TestCase):
    def test_authenticated_revoke_parser_contract(self) -> None:
        command = command_parser(
            build_parser(),
            "approval-revoke-authenticated",
        )

        self.assertEqual(
            required_destinations(command),
            {
                "approval_id",
                "decision_owner",
                "expected_version",
                "idempotency_key",
                "principal_assertion",
                "reason",
                "reason_code",
                "registry",
                "risk",
                "store",
            },
        )
        options = option_strings(command)
        for forbidden in (
            "--authorization-event-id",
            "--issuer",
            "--key-id",
            "--mission-id",
            "--policy",
            "--principal-profile-id",
            "--private-key",
            "--scope-grant",
            "--secret",
            "--signing-key",
            "--subject",
        ):
            self.assertNotIn(forbidden, options)

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "approval-revoke-authenticated",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "approval-revoke-authenticated",
        )

        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )
        self.assertIn(
            "principal_profile_id",
            required_destinations(
                command_parser(build_parser(), "approval-revoke")
            ),
        )

    def test_handler_forwards_only_closed_arguments(self) -> None:
        registry = object()
        assertion = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "approval": {
                "approval_id": APPROVAL_ID,
                "state": "revoked",
                "version": 3,
            },
            "revocation": {
                "approval_id": APPROVAL_ID,
                "expected_version": 2,
            },
            "operation": "sunderkey.approval.revoke.v1",
        }
        service.revoke.return_value = receipt

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
                (
                    "sunderkey.cli."
                    "AuthenticatedApprovalRevocationService"
                ),
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*revoke_arguments())

        self.assertEqual(
            output,
            receipt.to_dict.return_value,
        )
        self.assertEqual(load_registry.call_args, call(str(REGISTRY_PATH)))
        self.assertEqual(load_assertion.call_args, call(ASSERTION_PATH))
        self.assertEqual(mission_store.call_args, call(STORE_PATH))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.revoke.assert_called_once_with(
            assertion,
            APPROVAL_ID,
            reason_code="authorization_withdrawn",
            reason="Control withdrew the simulation authorization",
            risk="The authorization is no longer current",
            decision_owner="range-control",
            idempotency_key="phase11-cli-revoke",
            expected_version=2,
        )

    def test_output_cannot_replace_principal_assertion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assertion_path = Path(temporary) / ASSERTION_PATH
            assertion_path.write_text(
                "principal assertion input\n",
                encoding="utf-8",
            )
            arguments = revoke_arguments(output=str(assertion_path))
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
            arguments = revoke_arguments()
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

    def test_project_version_is_phase11(self) -> None:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
