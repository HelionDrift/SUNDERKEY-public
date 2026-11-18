"""Command-line coverage for Phase 29 implementation wave selection."""

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


class Phase29CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(
            build_parser(),
            "implementation-wave-package",
        )
        self.assertEqual(
            required_destinations(command),
            {"packages", "wave_id"},
        )
        self.assertFalse(
            option_strings(command)
            & {
                "--actor",
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
            "implementation-wave-package",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "implementation-wave-package",
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_output_cannot_replace_package_input(self) -> None:
        with (
            patch(
                "sys.argv",
                [
                    "sunderkey",
                    "implementation-wave-package",
                    "--packages",
                    "packages.json",
                    "--wave-id",
                    "IW-001",
                    "--output",
                    "packages.json",
                ],
            ),
            self.assertRaisesRegex(
                SystemExit,
                "Validation error: --output must not replace --packages",
            ),
        ):
            main()

    def test_handler_forwards_validated_report_and_wave(self) -> None:
        packages = object()
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "implementation_wave_package_selected",
        }
        with (
            patch(
                "sunderkey.cli.load_implementation_work_package_report",
                return_value=packages,
            ) as load,
            patch(
                "sunderkey.cli.select_implementation_wave_package",
                return_value=report,
            ) as select,
        ):
            output = run_cli(
                "implementation-wave-package",
                "--packages",
                "packages.json",
                "--wave-id",
                "IW-014",
            )

        self.assertEqual(output, report.to_dict.return_value)
        load.assert_called_once_with("packages.json")
        select.assert_called_once_with(packages, "IW-014")


if __name__ == "__main__":
    unittest.main()
