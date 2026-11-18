"""Command-line coverage for Phase 21 qualification planning."""

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


class Phase21CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(
            build_parser(),
            "qualification-coverage",
        )
        self.assertEqual(
            required_destinations(command),
            {"capabilities", "plans", "registry", "standard"},
        )
        self.assertFalse(
            option_strings(command)
            & {
                "--actor",
                "--evidence",
                "--issuer",
                "--principal-assertion",
                "--principal-profile-id",
                "--private-key",
                "--secret",
                "--signing-key",
                "--store",
                "--subject",
            }
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "qualification-coverage",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "qualification-coverage",
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
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "qualification_execution_pending",
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
                "sunderkey.cli.assess_qualification_coverage",
                return_value=report,
            ) as assess,
        ):
            output = run_cli(
                "qualification-coverage",
                "--registry",
                REGISTRY_PATH,
                "--capabilities",
                CAPABILITY_PATH,
                "--standard",
                STANDARD_PATH,
                "--plans",
                PLANS_PATH,
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
        assess.assert_called_once_with(
            registry,
            catalog,
            standard,
            plans,
        )


if __name__ == "__main__":
    unittest.main()
