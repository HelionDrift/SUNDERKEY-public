"""Command-line coverage for Phase 20 Army readiness."""

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
POLICY_PATH = "registry/routing-policy-army-qualified-v1.json"


class Phase20CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(build_parser(), "army-readiness")
        self.assertEqual(
            required_destinations(command),
            {"capabilities", "policy", "registry"},
        )
        self.assertFalse(
            option_strings(command)
            & {
                "--actor",
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
        current = command_parser(build_parser(), "army-readiness")
        legacy = command_parser(
            legacy_build_parser(),
            "army-readiness",
        )
        self.assertEqual(
            option_strings(legacy),
            option_strings(current),
        )
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_handler_forwards_validated_contracts(self) -> None:
        registry = object()
        catalog = object()
        policy = object()
        report = Mock()
        report.to_dict.return_value = {
            "schema_version": 1,
            "status": "qualification_incomplete",
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
                "sunderkey.cli.load_routing_policy",
                return_value=policy,
            ) as load_policy,
            patch(
                "sunderkey.cli.assess_army_readiness",
                return_value=report,
            ) as assess,
        ):
            output = run_cli(
                "army-readiness",
                "--registry",
                REGISTRY_PATH,
                "--capabilities",
                CAPABILITY_PATH,
                "--policy",
                POLICY_PATH,
            )

        self.assertEqual(output, report.to_dict.return_value)
        self.assertEqual(
            load_registry.call_args_list,
            [call(REGISTRY_PATH)],
        )
        self.assertEqual(
            load_catalog.call_args_list,
            [call(CAPABILITY_PATH, registry)],
        )
        self.assertEqual(
            load_policy.call_args_list,
            [call(POLICY_PATH, catalog)],
        )
        assess.assert_called_once_with(registry, catalog, policy)


if __name__ == "__main__":
    unittest.main()
