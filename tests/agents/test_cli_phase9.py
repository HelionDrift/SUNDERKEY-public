"""Command-line coverage for authenticated Phase 9 approval decisions."""

from __future__ import annotations

import argparse
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from sunderkey.cli import (
    build_parser as legacy_build_parser,
)
from sunderkey.cli import build_parser

from .test_cli_phase5 import run_cli
from .test_store import REGISTRY_PATH

APPROVAL_ID = "APR-CLI-PHASE9"
ASSERTION_PATH = "principal-assertion.json"
STORE_PATH = "missions.sqlite3"


def command_parser(
    parser: argparse.ArgumentParser,
    command: str,
) -> argparse.ArgumentParser:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[command]
    raise AssertionError("CLI parser has no subcommands")


def required_destinations(
    parser: argparse.ArgumentParser,
) -> set[str]:
    return {
        action.dest
        for action in parser._actions
        if getattr(action, "required", False)
    }


def option_strings(parser: argparse.ArgumentParser) -> set[str]:
    return {
        option
        for action in parser._actions
        for option in action.option_strings
    }


def approve_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "approval-approve-authenticated",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--principal-assertion",
        ASSERTION_PATH,
        "--approval-id",
        APPROVAL_ID,
        "--authority",
        "range-control",
        "--constraint",
        "simulation-only",
        "--constraint",
        "no-network",
        "--authorization-expires-at",
        "2030-01-01T00:00:00Z",
        "--idempotency-key",
        "phase9-cli-approve",
        "--expected-version",
        "1",
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


def deny_arguments(*, output: str | None = None) -> list[str]:
    arguments = [
        "approval-deny-authenticated",
        "--store",
        STORE_PATH,
        "--registry",
        str(REGISTRY_PATH),
        "--principal-assertion",
        ASSERTION_PATH,
        "--approval-id",
        APPROVAL_ID,
        "--reason-code",
        "scope_mismatch",
        "--reason",
        "The proposed action exceeds the approved scope",
        "--risk",
        "The action could cross the authorized boundary",
        "--decision-owner",
        "range-control",
        "--idempotency-key",
        "phase9-cli-deny",
        "--expected-version",
        "1",
    ]
    if output is not None:
        arguments.extend(("--output", output))
    return arguments


class Phase9CliTests(unittest.TestCase):
    def test_authenticated_approval_parser_contracts(self) -> None:
        parser = build_parser()
        approve_parser = command_parser(
            parser,
            "approval-approve-authenticated",
        )
        deny_parser = command_parser(
            parser,
            "approval-deny-authenticated",
        )

        self.assertEqual(
            required_destinations(approve_parser),
            {
                "approval_id",
                "authority",
                "authorization_expires_at",
                "constraint",
                "expected_version",
                "idempotency_key",
                "principal_assertion",
                "registry",
                "store",
            },
        )
        self.assertEqual(
            required_destinations(deny_parser),
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

        for command in (
            "approval-approve-authenticated",
            "approval-deny-authenticated",
        ):
            with self.subTest(command=command):
                command_actions = command_parser(
                    parser,
                    command,
                )._actions
                expected_version = next(
                    action
                    for action in command_actions
                    if action.dest == "expected_version"
                )
                self.assertIs(expected_version.type, int)
                output = next(
                    action
                    for action in command_actions
                    if action.dest == "output"
                )
                self.assertFalse(output.required)

        parsed = parser.parse_args(approve_arguments())
        self.assertEqual(
            parsed.constraint,
            ["simulation-only", "no-network"],
        )
        self.assertEqual(parsed.expected_version, 1)

    def test_authenticated_commands_expose_no_credential_or_override_options(
        self,
    ) -> None:
        parser = build_parser()
        forbidden_destinations = {
            "generate_key",
            "issuer",
            "key_generation",
            "mission_id",
            "principal_profile_id",
            "private_key",
            "signing",
            "signing_key",
            "subject",
        }
        forbidden_options = {
            "--generate-key",
            "--issuer",
            "--key-generation",
            "--mission-id",
            "--principal-profile-id",
            "--private-key",
            "--signing",
            "--signing-key",
            "--subject",
        }

        for command in (
            "approval-approve-authenticated",
            "approval-deny-authenticated",
        ):
            with self.subTest(command=command):
                command_value = command_parser(parser, command)
                destinations = {
                    action.dest for action in command_value._actions
                }
                self.assertTrue(
                    forbidden_destinations.isdisjoint(destinations)
                )
                self.assertTrue(
                    forbidden_options.isdisjoint(
                        option_strings(command_value)
                    )
                )

    def test_direct_and_compatibility_commands_remain_exposed(self) -> None:
        current = build_parser()
        legacy = legacy_build_parser()
        commands = (
            "approval-approve",
            "approval-deny",
            "approval-approve-authenticated",
            "approval-deny-authenticated",
        )

        for command in commands:
            with self.subTest(command=command):
                current_command = command_parser(current, command)
                legacy_command = command_parser(legacy, command)
                self.assertEqual(
                    option_strings(legacy_command),
                    option_strings(current_command),
                )
                self.assertEqual(
                    required_destinations(legacy_command),
                    required_destinations(current_command),
                )

        self.assertIn(
            "principal_profile_id",
            required_destinations(
                command_parser(current, "approval-approve")
            ),
        )
        self.assertIn(
            "principal_profile_id",
            required_destinations(
                command_parser(current, "approval-deny")
            ),
        )
        help_text = current.format_help().lower()
        self.assertIn("approval-approve-authenticated", help_text)
        self.assertIn("approval-deny-authenticated", help_text)

        pyproject_path = Path(__file__).parents[2] / "pyproject.toml"
        with pyproject_path.open("rb") as stream:
            scripts = tomllib.load(stream)["project"]["scripts"]
        self.assertEqual(scripts["sunderkey"], scripts["sunderkey"])

    def test_migrate_help_names_every_v8_source_version(self) -> None:
        help_text = " ".join(build_parser().format_help().split())

        self.assertIn(
            (
                "Migrate a verified v1 through v15 mission store to v16"
            ),
            help_text,
        )

    def test_output_cannot_replace_principal_assertion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assertion_path = Path(temporary) / ASSERTION_PATH
            assertion_path.write_text(
                "principal assertion input\n",
                encoding="utf-8",
            )
            original = assertion_path.read_bytes()

            for arguments in (
                approve_arguments(output=str(assertion_path)),
                deny_arguments(output=str(assertion_path)),
            ):
                with self.subTest(command=arguments[0]):
                    assertion_option = arguments.index(
                        "--principal-assertion"
                    )
                    arguments[assertion_option + 1] = str(assertion_path)
                    with self.assertRaisesRegex(
                        SystemExit,
                        (
                            "--output must not replace "
                            "--principal-assertion"
                        ),
                    ):
                        run_cli(*arguments)
                    self.assertEqual(
                        assertion_path.read_bytes(),
                        original,
                    )

    def test_principal_assertion_file_uses_strict_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assertion_path = Path(temporary) / ASSERTION_PATH
            assertion_path.write_text(
                '{"schema_version":1,"schema_version":1}\n',
                encoding="utf-8",
            )
            arguments = approve_arguments()
            assertion_option = arguments.index("--principal-assertion")
            arguments[assertion_option + 1] = str(assertion_path)

            with self.assertRaisesRegex(
                SystemExit,
                "Duplicate JSON object key: schema_version",
            ):
                run_cli(*arguments)

    def test_authenticated_handlers_forward_closed_arguments(self) -> None:
        registry = object()
        assertion = object()
        store = object()
        service = Mock()
        approve_receipt = Mock()
        approve_receipt.to_dict.return_value = {
            "approval_id": APPROVAL_ID,
            "operation": "approval_approve",
        }
        deny_receipt = Mock()
        deny_receipt.to_dict.return_value = {
            "approval_id": APPROVAL_ID,
            "operation": "approval_deny",
        }
        service.approve.return_value = approve_receipt
        service.deny.return_value = deny_receipt

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
                "sunderkey.cli.AuthenticatedApprovalDecisionService",
                return_value=service,
            ) as service_type,
        ):
            approved = run_cli(*approve_arguments())
            denied = run_cli(*deny_arguments())

        self.assertEqual(
            approved,
            {
                "approval_id": APPROVAL_ID,
                "operation": "approval_approve",
            },
        )
        self.assertEqual(
            denied,
            {
                "approval_id": APPROVAL_ID,
                "operation": "approval_deny",
            },
        )
        self.assertEqual(
            load_registry.call_args_list,
            [call(str(REGISTRY_PATH)), call(str(REGISTRY_PATH))],
        )
        self.assertEqual(
            load_assertion.call_args_list,
            [call(ASSERTION_PATH), call(ASSERTION_PATH)],
        )
        self.assertEqual(
            mission_store.call_args_list,
            [call(STORE_PATH), call(STORE_PATH)],
        )
        self.assertEqual(
            service_type.call_args_list,
            [call(store, registry), call(store, registry)],
        )
        service.approve.assert_called_once_with(
            assertion,
            APPROVAL_ID,
            authority="range-control",
            constraints=["simulation-only", "no-network"],
            authorization_expires_at="2030-01-01T00:00:00Z",
            idempotency_key="phase9-cli-approve",
            expected_version=1,
        )
        service.deny.assert_called_once_with(
            assertion,
            APPROVAL_ID,
            reason_code="scope_mismatch",
            reason="The proposed action exceeds the approved scope",
            risk="The action could cross the authorized boundary",
            decision_owner="range-control",
            idempotency_key="phase9-cli-deny",
            expected_version=1,
        )


if __name__ == "__main__":
    unittest.main()
