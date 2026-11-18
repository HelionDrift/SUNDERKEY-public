"""Command-line coverage for Phase 27 implementation roadmaps."""

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


class Phase27CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(build_parser(), "implementation-roadmap")
        self.assertEqual(
            required_destinations(command),
            {
                "blueprints",
                "candidates",
                "capabilities",
                "components",
                "plans",
                "policy",
                "registry",
                "standard",
            },
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
                "--secret",
                "--signing-key",
                "--store",
                "--target",
                "--tool",
            }
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(build_parser(), "implementation-roadmap")
        legacy = command_parser(
            legacy_build_parser(),
            "implementation-roadmap",
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_output_cannot_replace_any_roadmap_input(self) -> None:
        options = (
            "registry",
            "capabilities",
            "policy",
            "standard",
            "plans",
            "blueprints",
            "components",
            "candidates",
        )
        for protected in options:
            with self.subTest(protected=protected):
                arguments = ["sunderkey", "implementation-roadmap"]
                for option in options:
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
        objects = [object() for _ in range(8)]
        (
            registry,
            capabilities,
            policy,
            standard,
            plans,
            blueprints,
            components,
            candidates,
        ) = objects
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "implementation_roadmap_ready",
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
                "sunderkey.cli.assess_specialist_implementation_roadmap",
                return_value=report,
            ) as assess,
        ):
            output = run_cli(
                "implementation-roadmap",
                "--registry",
                "registry.json",
                "--capabilities",
                "capabilities.json",
                "--policy",
                "policy.json",
                "--standard",
                "standard.json",
                "--plans",
                "plans.json",
                "--blueprints",
                "blueprints.json",
                "--components",
                "components.json",
                "--candidates",
                "candidates.json",
            )

        self.assertEqual(output, report.to_dict.return_value)
        assess.assert_called_once_with(*objects)


if __name__ == "__main__":
    unittest.main()
