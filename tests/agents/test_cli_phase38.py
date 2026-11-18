"""Command-line coverage for the Phase 38 D009 decision dossier."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.cli import build_parser, main

from .test_cli_phase5 import run_cli
from .test_cli_phase9 import (
    command_parser,
    option_strings,
    required_destinations,
)


class Phase38CliTests(unittest.TestCase):
    OPTIONS = (
        "registry",
        "capabilities",
        "standard",
        "authority-decision",
    )

    def test_command_contract_is_closed(self) -> None:
        command = command_parser(
            build_parser(),
            "candidate-enrollment-dossier",
        )
        self.assertEqual(
            required_destinations(command),
            {item.replace("-", "_") for item in self.OPTIONS},
        )
        self.assertFalse(
            option_strings(command)
            & {
                "--actor",
                "--decision",
                "--endpoint",
                "--evidence",
                "--issuer",
                "--model",
                "--owner",
                "--owner-public-key",
                "--principal-assertion",
                "--private-key",
                "--provider",
                "--repository-credential",
                "--repository-endpoint",
                "--reviewer",
                "--secret",
                "--signing-key",
                "--store",
                "--target",
                "--tool",
                "--worker",
            }
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "candidate-enrollment-dossier",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "candidate-enrollment-dossier",
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_output_cannot_replace_any_dossier_input(self) -> None:
        for protected in self.OPTIONS:
            with self.subTest(protected=protected):
                arguments = ["sunderkey", "candidate-enrollment-dossier"]
                for option in self.OPTIONS:
                    arguments.extend([f"--{option}", f"{option}.json"])
                arguments.extend(["--output", f"{protected}.json"])
                with (
                    patch("sys.argv", arguments),
                    self.assertRaisesRegex(
                        SystemExit,
                        "Validation error: --output must not replace "
                        f"--{protected}",
                    ),
                ):
                    main()

    def test_handler_forwards_validated_contracts(self) -> None:
        objects = [object() for _ in range(4)]
        registry, capabilities, standard, authority_decision = objects
        dossier = Mock()
        dossier.to_dict.return_value = {
            "schema_version": 1,
            "status": "decision_required",
        }
        with (
            patch("sunderkey.cli.load_registry", return_value=registry),
            patch(
                "sunderkey.cli.load_capability_catalog",
                return_value=capabilities,
            ),
            patch(
                "sunderkey.cli.load_qualification_standard",
                return_value=standard,
            ),
            patch(
                "sunderkey.cli.load_qualification_authority_decision_record",
                return_value=authority_decision,
            ),
            patch(
                "sunderkey.cli.assess_candidate_enrollment_decision",
                return_value=dossier,
            ) as assess,
        ):
            arguments: list[str] = ["candidate-enrollment-dossier"]
            for option in self.OPTIONS:
                arguments.extend([f"--{option}", f"{option}.json"])
            output = run_cli(*arguments)

        self.assertEqual(output, dossier.to_dict.return_value)
        assess.assert_called_once_with(*objects)


if __name__ == "__main__":
    unittest.main()
