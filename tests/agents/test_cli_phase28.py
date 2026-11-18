"""Command-line coverage for Phase 28 implementation work packages."""

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


class Phase28CliTests(unittest.TestCase):
    OPTIONS = (
        "registry",
        "capabilities",
        "policy",
        "standard",
        "plans",
        "blueprints",
        "components",
        "candidates",
        "roadmap",
    )

    def test_command_contract_is_closed(self) -> None:
        command = command_parser(
            build_parser(),
            "implementation-work-packages",
        )
        self.assertEqual(required_destinations(command), set(self.OPTIONS))
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
            "implementation-work-packages",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "implementation-work-packages",
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_output_cannot_replace_any_work_package_input(self) -> None:
        for protected in self.OPTIONS:
            with self.subTest(protected=protected):
                arguments = ["sunderkey", "implementation-work-packages"]
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
        objects = [object() for _ in range(9)]
        (
            registry,
            capabilities,
            policy,
            standard,
            plans,
            blueprints,
            components,
            candidates,
            roadmap,
        ) = objects
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "implementation_work_packages_ready",
        }
        with (
            patch("sunderkey.cli.load_registry", return_value=registry),
            patch(
                "sunderkey.cli.load_capability_catalog",
                return_value=capabilities,
            ),
            patch(
                "sunderkey.cli.load_routing_policy",
                return_value=policy,
            ),
            patch(
                "sunderkey.cli.load_qualification_standard",
                return_value=standard,
            ),
            patch(
                "sunderkey.cli.load_qualification_plan_catalog",
                return_value=plans,
            ),
            patch(
                "sunderkey.cli.load_candidate_blueprint_catalog",
                return_value=blueprints,
            ),
            patch(
                "sunderkey.cli.load_candidate_component_catalog",
                return_value=components,
            ),
            patch(
                "sunderkey.cli.load_candidate_implementation_catalog",
                return_value=candidates,
            ),
            patch(
                "sunderkey.cli.load_specialist_implementation_roadmap",
                return_value=roadmap,
            ),
            patch(
                "sunderkey.cli.assess_implementation_work_packages",
                return_value=report,
            ) as assess,
        ):
            arguments: list[str] = ["implementation-work-packages"]
            for option in self.OPTIONS:
                arguments.extend([f"--{option}", f"{option}.json"])
            output = run_cli(*arguments)

        self.assertEqual(output, report.to_dict.return_value)
        assess.assert_called_once_with(*objects)


if __name__ == "__main__":
    unittest.main()
