"""Command-line coverage for Phase 25 candidate onboarding."""

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

REGISTRY_PATH = "registry/army-v1.json"
CAPABILITY_PATH = "registry/capabilities-army-v1.json"
STANDARD_PATH = "registry/qualification-standard-v1.json"
PLANS_PATH = "registry/qualification-plans-army-v1.json"
BLUEPRINTS_PATH = "registry/candidate-blueprints-army-v1.json"
COMPONENTS_PATH = "registry/candidate-components-v1.json"
CANDIDATES_PATH = "registry/candidate-implementations-v1.json"


class Phase25CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(build_parser(), "candidate-onboarding")
        self.assertEqual(
            required_destinations(command),
            {
                "blueprints",
                "candidates",
                "capabilities",
                "components",
                "plans",
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
                "--observations",
                "--principal-assertion",
                "--principal-profile-id",
                "--private-key",
                "--provider",
                "--secret",
                "--signing-key",
                "--store",
                "--suite",
                "--target",
                "--tool",
            }
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(build_parser(), "candidate-onboarding")
        legacy = command_parser(
            legacy_build_parser(), "candidate-onboarding"
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_handler_forwards_validated_contracts(self) -> None:
        registry = object()
        capabilities = object()
        standard = object()
        plans = object()
        blueprints = object()
        components = object()
        candidates = object()
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "candidate_component_fixture_only",
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
            ) as load_components,
            patch(
                "sunderkey.cli.load_candidate_implementation_catalog",
                return_value=candidates,
            ) as load_candidates,
            patch(
                "sunderkey.cli.assess_candidate_onboarding",
                return_value=report,
            ) as assess,
        ):
            output = run_cli(
                "candidate-onboarding",
                "--registry",
                REGISTRY_PATH,
                "--capabilities",
                CAPABILITY_PATH,
                "--standard",
                STANDARD_PATH,
                "--plans",
                PLANS_PATH,
                "--blueprints",
                BLUEPRINTS_PATH,
                "--components",
                COMPONENTS_PATH,
                "--candidates",
                CANDIDATES_PATH,
            )

        self.assertEqual(output, report.to_dict.return_value)
        load_components.assert_called_once_with(COMPONENTS_PATH, blueprints)
        load_candidates.assert_called_once_with(
            CANDIDATES_PATH,
            registry,
            capabilities,
            standard,
            plans,
            blueprints,
        )
        assess.assert_called_once_with(
            registry,
            capabilities,
            standard,
            plans,
            blueprints,
            components,
            candidates,
        )


if __name__ == "__main__":
    unittest.main()
