"""Command-line coverage for the Phase 118 capability roadmap."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.cli import build_parser, main

from .test_cli_phase5 import run_cli
from .test_cli_phase9 import command_parser, option_strings, required_destinations


class Phase118CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(build_parser(), "capability-roadmap")
        self.assertEqual(required_destinations(command), {"roadmap"})
        self.assertEqual(
            option_strings(command),
            {
                "--completed-package-id",
                "--help",
                "--output",
                "--roadmap",
                "-h",
            },
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(build_parser(), "capability-roadmap")
        legacy = command_parser(legacy_build_parser(), "capability-roadmap")
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(required_destinations(legacy), required_destinations(current))

    def test_output_cannot_replace_roadmap(self) -> None:
        with (
            patch(
                "sys.argv",
                [
                    "sunderkey",
                    "capability-roadmap",
                    "--roadmap",
                    "roadmap.json",
                    "--output",
                    "roadmap.json",
                ],
            ),
            self.assertRaisesRegex(
                SystemExit,
                "Validation error: --output must not replace --roadmap",
            ),
        ):
            main()

    def test_handler_forwards_completion_claims(self) -> None:
        roadmap = Mock()
        report = {"status": "valid", "package_counts": {"ready": 1}}
        with (
            patch("sunderkey.cli.load_capability_roadmap", return_value=roadmap),
            patch(
                "sunderkey.cli.assess_capability_roadmap",
                return_value=report,
            ) as assess,
        ):
            output = run_cli(
                "capability-roadmap",
                "--roadmap",
                "roadmap.json",
                "--completed-package-id",
                "R0.1",
            )
        self.assertEqual(output, report)
        assess.assert_called_once_with(roadmap, ["R0.1"])


if __name__ == "__main__":
    unittest.main()
