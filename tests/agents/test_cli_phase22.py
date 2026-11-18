"""Command-line coverage for Phase 22 qualification evaluation."""

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
SUITE_PATH = "examples/qualification/passive-osint-suite.json"
OBSERVATIONS_PATH = (
    "examples/qualification/passive-osint-observations.json"
)


class Phase22CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(
            build_parser(),
            "qualification-evaluate",
        )
        self.assertEqual(
            required_destinations(command),
            {
                "capabilities",
                "observations",
                "plans",
                "registry",
                "standard",
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
                "--principal-assertion",
                "--principal-profile-id",
                "--private-key",
                "--secret",
                "--signing-key",
                "--store",
                "--subject",
                "--target",
                "--tool",
            }
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "qualification-evaluate",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "qualification-evaluate",
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_handler_forwards_validated_contracts(self) -> None:
        registry = object()
        catalog = object()
        standard = object()
        plans = object()
        suite = object()
        observations = object()
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "advisory_thresholds_met",
        }
        with (
            patch(
                "sunderkey.cli.load_registry",
                return_value=registry,
            ) as load_registry,
            patch(
                "sunderkey.cli.load_capability_catalog",
                return_value=catalog,
            ) as load_catalog,
            patch(
                "sunderkey.cli.load_qualification_standard",
                return_value=standard,
            ) as load_standard,
            patch(
                "sunderkey.cli.load_qualification_plan_catalog",
                return_value=plans,
            ) as load_plans,
            patch(
                "sunderkey.cli.load_qualification_evaluation_suite",
                return_value=suite,
            ) as load_suite,
            patch(
                "sunderkey.cli.load_qualification_observation_set",
                return_value=observations,
            ) as load_observations,
            patch(
                "sunderkey.cli.evaluate_qualification_observations",
                return_value=report,
            ) as evaluate,
        ):
            output = run_cli(
                "qualification-evaluate",
                "--registry",
                REGISTRY_PATH,
                "--capabilities",
                CAPABILITY_PATH,
                "--standard",
                STANDARD_PATH,
                "--plans",
                PLANS_PATH,
                "--suite",
                SUITE_PATH,
                "--observations",
                OBSERVATIONS_PATH,
            )

        self.assertEqual(output, report.to_dict.return_value)
        self.assertEqual(load_registry.call_args_list, [call(REGISTRY_PATH)])
        self.assertEqual(
            load_catalog.call_args_list,
            [call(CAPABILITY_PATH, registry)],
        )
        self.assertEqual(
            load_standard.call_args_list,
            [call(STANDARD_PATH, registry, catalog)],
        )
        self.assertEqual(
            load_plans.call_args_list,
            [call(PLANS_PATH, registry, catalog, standard)],
        )
        self.assertEqual(
            load_suite.call_args_list,
            [
                call(
                    SUITE_PATH,
                    registry,
                    catalog,
                    standard,
                    plans,
                )
            ],
        )
        self.assertEqual(
            load_observations.call_args_list,
            [call(OBSERVATIONS_PATH, suite)],
        )
        evaluate.assert_called_once_with(
            registry,
            catalog,
            standard,
            plans,
            suite,
            observations,
        )


if __name__ == "__main__":
    unittest.main()
