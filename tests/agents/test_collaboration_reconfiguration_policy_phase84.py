"""Phase 84 collaboration reconfiguration authority policy coverage."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_collaboration_reconfiguration_policy import build_parser, build_policy
from sunderkey.collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import CollaborationPlanError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
POLICY_PATH = REGISTRY / "collaboration-reconfiguration-policy-d001-d005.json"
SCHEMA_PATH = (
    REGISTRY
    / "schemas"
    / "collaboration-reconfiguration-authority-policy-v1.schema.json"
)


class CollaborationReconfigurationPolicyPhase84Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_collaboration_reconfiguration_authority_policy(POLICY_PATH)

    def test_checked_policy_matches_deterministic_builder(self) -> None:
        expected = build_policy(build_parser().parse_args([]))
        self.assertEqual(
            POLICY_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.policy.to_dict(), expected)

    def test_policy_maps_all_five_decisions_and_required_parties(self) -> None:
        document = self.policy.to_dict()
        self.assertEqual(
            [item["decision_id"] for item in document["transition_rules"]],
            ["D001", "D002", "D003", "D004", "D005"],
        )
        for rule in document["transition_rules"]:
            self.assertTrue(rule["required_parties"])
            self.assertTrue(rule["conditional_parties"])
            self.assertTrue(rule["result_boundary"])

    def test_parameters_are_bounded_but_unselected(self) -> None:
        parameters = self.policy.to_dict()["parameter_contracts"]
        self.assertEqual(len(parameters), 4)
        for parameter in parameters:
            self.assertLessEqual(parameter["minimum"], parameter["maximum"])
            self.assertIsNone(parameter["selected_value"])

    def test_current_runtime_boundary_stays_closed(self) -> None:
        document = self.policy.to_dict()
        boundary = document["current_boundary"]
        self.assertEqual(boundary["policy_status"], "contract_defined_inactive")
        self.assertEqual(boundary["maximum_handoffs_per_work_item"], 1)
        self.assertFalse(boundary["cross_command_handoff_enabled"])
        self.assertFalse(boundary["activated_plan_replacement_enabled"])
        self.assertFalse(boundary["distributed_execution_acknowledgement_enabled"])
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["registry_effect"], "none")

    def test_tampered_parameter_or_boundary_is_rejected(self) -> None:
        parameter = copy.deepcopy(self.policy.to_dict())
        parameter["parameter_contracts"][0]["selected_value"] = 8
        with self.assertRaisesRegex(CollaborationPlanError, "parameter_contracts"):
            CollaborationReconfigurationAuthorityPolicy.from_dict(parameter)
        boundary = copy.deepcopy(self.policy.to_dict())
        boundary["current_boundary"]["cross_command_handoff_enabled"] = True
        with self.assertRaisesRegex(CollaborationPlanError, "current_boundary"):
            CollaborationReconfigurationAuthorityPolicy.from_dict(boundary)

    def test_policy_contains_no_live_values_secrets_or_markers(self) -> None:
        serialized = json.dumps(self.policy.to_dict(), sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key":',
            '"credential":',
            '"signature":',
            '"network_endpoint":',
            '"mission_id":',
            '"work_item_id":',
        ):
            with self.subTest(field=field):
                self.assertNotIn(field, serialized)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_policy_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.policy.to_dict())

    def test_builder_has_no_network_storage_or_execution_imports(self) -> None:
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        for relative in (
            "src/sunderkey/collaboration_reconfiguration_policy.py",
            "scripts/build_collaboration_reconfiguration_policy.py",
        ):
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            imported = {
                alias.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported.update(
                str(node.module).split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            )
            self.assertFalse(imported & prohibited)


if __name__ == "__main__":
    unittest.main()
