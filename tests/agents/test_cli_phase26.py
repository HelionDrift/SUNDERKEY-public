"""Command-line coverage for Phase 26 candidate evaluation preflight."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.cli import build_parser

from .test_cli_phase5 import run_cli
from .test_cli_phase9 import (
    command_parser,
    option_strings,
    required_destinations,
)


class Phase26CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(build_parser(), "candidate-preflight")
        self.assertEqual(
            required_destinations(command),
            {
                "blueprints",
                "candidates",
                "capabilities",
                "components",
                "onboarding",
                "plans",
                "registry",
                "standard",
                "submission",
                "suite",
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
                "--observations",
                "--principal-assertion",
                "--principal-profile-id",
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
        current = command_parser(build_parser(), "candidate-preflight")
        legacy = command_parser(
            legacy_build_parser(), "candidate-preflight"
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_handler_forwards_validated_contracts(self) -> None:
        objects = [object() for _ in range(10)]
        (
            registry,
            capabilities,
            standard,
            plans,
            blueprints,
            components,
            candidates,
            onboarding,
            suite,
            submission,
        ) = objects
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "synthetic_fixture_preflight_complete",
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
                "sunderkey.cli.load_candidate_onboarding_report",
                return_value=onboarding,
            ),
            patch(
                "sunderkey.cli.load_qualification_evaluation_suite",
                return_value=suite,
            ),
            patch(
                "sunderkey.cli.load_candidate_evaluation_submission",
                return_value=submission,
            ),
            patch(
                "sunderkey.cli.assess_candidate_evaluation_preflight",
                return_value=report,
            ) as assess,
        ):
            output = run_cli(
                "candidate-preflight",
                "--registry",
                "registry.json",
                "--capabilities",
                "capabilities.json",
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
                "--onboarding",
                "onboarding.json",
                "--suite",
                "suite.json",
                "--submission",
                "submission.json",
            )

        self.assertEqual(output, report.to_dict.return_value)
        assess.assert_called_once_with(*objects)


if __name__ == "__main__":
    unittest.main()
