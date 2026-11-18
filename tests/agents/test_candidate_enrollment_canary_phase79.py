"""Phase 79 single-candidate canary preparation coverage."""

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

from scripts.build_candidate_enrollment_canary_preparation import (
    build_packet,
    build_parser,
)
from sunderkey.candidate_enrollment_canary import (
    CandidateEnrollmentCanaryPreparationPacket,
    load_candidate_enrollment_canary_preparation,
)
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
PACKET_PATH = REGISTRY / "candidate-enrollment-canary-preparation-d011.json"
SCHEMA_PATH = (
    REGISTRY / "schemas" / "candidate-enrollment-canary-preparation-v1.schema.json"
)


class CandidateEnrollmentCanaryPhase79Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packet = load_candidate_enrollment_canary_preparation(PACKET_PATH)

    def test_checked_packet_matches_deterministic_builder(self) -> None:
        expected = build_packet(build_parser().parse_args([]))
        self.assertEqual(
            PACKET_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.packet.to_dict(), expected)
        self.assertEqual(self.packet.packet_id, "CAP-7DD087F0CB4534F965889790D2FA5260")

    def test_packet_requires_one_candidate_and_nine_external_inputs(self) -> None:
        document = self.packet.to_dict()
        self.assertEqual(document["canary_scope"]["maximum_candidate_count"], 1)
        self.assertFalse(document["canary_scope"]["automatic_expansion_allowed"])
        self.assertEqual(len(document["required_external_inputs"]), 9)
        self.assertEqual(len(document["activation_gates"]), 11)
        self.assertEqual(len(document["critical_stop_conditions"]), 10)
        self.assertEqual(
            document["authorized_next_action"],
            "collect_inputs_and_record_separate_canary_go_no_go",
        )

    def test_packet_contains_no_live_values_secrets_or_activation_effect(self) -> None:
        document = self.packet.to_dict()
        serialized = json.dumps(document, sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key":',
            '"credential":',
            '"signature":',
            '"network_endpoint":',
            '"candidate_id":',
            '"deployment_id":',
        ):
            with self.subTest(field=field):
                self.assertNotIn(field, serialized)
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(document["registry_effect"], "none")
        self.assertFalse(document["network_call_performed"])

    def test_tampered_scope_or_next_action_is_rejected(self) -> None:
        scope = copy.deepcopy(self.packet.to_dict())
        scope["canary_scope"]["maximum_candidate_count"] = 2
        with self.assertRaisesRegex(QualificationError, "scope"):
            CandidateEnrollmentCanaryPreparationPacket.from_dict(scope)
        action = copy.deepcopy(self.packet.to_dict())
        action["authorized_next_action"] = "activate_live_candidate"
        with self.assertRaisesRegex(QualificationError, "next_action"):
            CandidateEnrollmentCanaryPreparationPacket.from_dict(action)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_packet_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.packet.to_dict())

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
            "src/sunderkey/candidate_enrollment_canary.py",
            "scripts/build_candidate_enrollment_canary_preparation.py",
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
