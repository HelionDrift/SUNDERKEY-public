"""Command-line coverage for Phase 23 candidate inventory."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, call, patch

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
CANDIDATES_PATH = "registry/candidate-implementations-v1.json"
BLUEPRINTS_PATH = "registry/candidate-blueprints-army-v1.json"


class Phase23CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(build_parser(), "candidate-inventory")
        self.assertEqual(
            required_destinations(command),
            {
                "blueprints",
                "candidates",
                "capabilities",
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
                "--secret",
                "--signing-key",
                "--store",
                "--suite",
                "--target",
                "--tool",
            }
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(build_parser(), "candidate-inventory")
        legacy = command_parser(
            legacy_build_parser(),
            "candidate-inventory",
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
        candidates = object()
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "candidate_implementation_incomplete",
        }
        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ) as load_registry,
            patch(
                "sunderkey.cli.load_capability_catalog",
                return_value=capabilities,
            ) as load_capabilities,
            patch(
                "sunderkey.cli.load_qualification_standard",
                return_value=standard,
            ) as load_standard,
            patch(
                "sunderkey.cli.load_qualification_plan_catalog",
                return_value=plans,
            ) as load_plans,
            patch(
                "sunderkey.cli.load_candidate_blueprint_catalog",
                return_value=blueprints,
            ) as load_blueprints,
            patch(
                "sunderkey.cli.load_candidate_implementation_catalog",
                return_value=candidates,
            ) as load_candidates,
            patch(
                "sunderkey.cli.assess_candidate_inventory",
                return_value=report,
            ) as assess,
        ):
            output = run_cli(
                "candidate-inventory",
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
                "--candidates",
                CANDIDATES_PATH,
            )

        self.assertEqual(output, report.to_dict.return_value)
        self.assertEqual(load_registry.call_args_list, [call(REGISTRY_PATH)])
        self.assertEqual(
            load_capabilities.call_args_list,
            [call(CAPABILITY_PATH, registry)],
        )
        self.assertEqual(
            load_standard.call_args_list,
            [call(STANDARD_PATH, registry, capabilities)],
        )
        self.assertEqual(
            load_plans.call_args_list,
            [call(PLANS_PATH, registry, capabilities, standard)],
        )
        self.assertEqual(
            load_blueprints.call_args_list,
            [
                call(
                    BLUEPRINTS_PATH,
                    registry,
                    capabilities,
                    standard,
                    plans,
                )
            ],
        )
        self.assertEqual(
            load_candidates.call_args_list,
            [
                call(
                    CANDIDATES_PATH,
                    registry,
                    capabilities,
                    standard,
                    plans,
                    blueprints,
                )
            ],
        )
        assess.assert_called_once_with(
            registry,
            capabilities,
            standard,
            plans,
            blueprints,
            candidates,
        )


if __name__ == "__main__":
    unittest.main()
