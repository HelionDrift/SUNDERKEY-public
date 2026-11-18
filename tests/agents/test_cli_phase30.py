"""Command-line coverage for the Phase 30 D008 decision dossier."""

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


class Phase30CliTests(unittest.TestCase):
    OPTIONS = (
        "registry",
        "capabilities",
        "standard",
        "roadmap",
        "packages",
    )

    def test_command_contract_is_closed(self) -> None:
        command = command_parser(
            build_parser(),
            "qualification-authority-dossier",
        )
        self.assertEqual(required_destinations(command), set(self.OPTIONS))
        self.assertFalse(
            option_strings(command)
            & {
                "--actor",
                "--decision",
                "--endpoint",
                "--evidence",
                "--issuer",
                "--model",
                "--principal-assertion",
                "--private-key",
                "--provider",
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
            "qualification-authority-dossier",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "qualification-authority-dossier",
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_output_cannot_replace_any_dossier_input(self) -> None:
        for protected in self.OPTIONS:
            with self.subTest(protected=protected):
                arguments = ["sunderkey", "qualification-authority-dossier"]
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
        objects = [object() for _ in range(5)]
        registry, capabilities, standard, roadmap, packages = objects
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
                "sunderkey.cli.load_specialist_implementation_roadmap",
                return_value=roadmap,
            ),
            patch(
                "sunderkey.cli.load_implementation_work_package_report",
                return_value=packages,
            ),
            patch(
                "sunderkey.cli.assess_qualification_authority_decision",
                return_value=dossier,
            ) as assess,
        ):
            arguments: list[str] = ["qualification-authority-dossier"]
            for option in self.OPTIONS:
                arguments.extend([f"--{option}", f"{option}.json"])
            output = run_cli(*arguments)

        self.assertEqual(output, dossier.to_dict.return_value)
        assess.assert_called_once_with(*objects)


if __name__ == "__main__":
    unittest.main()
