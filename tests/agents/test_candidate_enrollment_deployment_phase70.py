"""Phase 70 candidate enrollment deployment preparation coverage."""

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

from scripts.build_candidate_enrollment_deployment_preparation import (
    build_packet,
    build_parser,
)
from sunderkey.candidate_enrollment_deployment import (
    CEREMONIES,
    EXTERNAL_INPUTS,
    CandidateEnrollmentDeploymentPreparationPacket,
    build_candidate_enrollment_deployment_preparation,
    load_candidate_enrollment_deployment_preparation,
)
from sunderkey.candidate_enrollment_implementation import (
    OPERATIONAL_PREREQUISITES,
    load_candidate_enrollment_implementation_report,
)
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
IMPLEMENTATION_PATH = REGISTRY / "candidate-enrollment-implementation-d009.json"
PACKET_PATH = REGISTRY / "candidate-enrollment-deployment-preparation-d009.json"
SCHEMA_PATH = (
    REGISTRY
    / "schemas"
    / "candidate-enrollment-deployment-preparation-v1.schema.json"
)


class CandidateEnrollmentDeploymentPhase70Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.implementation = load_candidate_enrollment_implementation_report(
            IMPLEMENTATION_PATH
        )
        cls.packet = load_candidate_enrollment_deployment_preparation(PACKET_PATH)

    def test_checked_packet_matches_deterministic_builder(self) -> None:
        expected = build_packet(build_parser().parse_args([]))
        self.assertEqual(
            PACKET_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.packet.to_dict(), expected)
        self.assertEqual(
            build_candidate_enrollment_deployment_preparation(self.implementation),
            self.packet,
        )

    def test_packet_has_stable_identity_and_no_operational_effect(self) -> None:
        document = self.packet.to_dict()
        self.assertEqual(document["packet_id"], "CDP-C0D97BCF4BD9F24EF4E4F3D388DEFB2A")
        self.assertEqual(
            document["packet_sha256"],
            "sha256:c0d97bcf4bd9f24ef4e4f3d388defb2a"
            "b5d7a26d86624bc605f9039245fe235f",
        )
        self.assertEqual(document["deployment_status"], "awaiting_external_inputs")
        self.assertFalse(document["readiness"]["ready_for_live_enrollment"])
        self.assertEqual(document["readiness"]["pending_input_count"], 9)
        self.assertFalse(document["network_call_performed"])
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(document["registry_effect"], "none")

    def test_every_operational_prerequisite_is_assigned_once(self) -> None:
        input_ids = [item["input_id"] for item in EXTERNAL_INPUTS]
        self.assertEqual(input_ids, list(OPERATIONAL_PREREQUISITES))
        ceremony_inputs = [
            input_id
            for ceremony in CEREMONIES
            for input_id in ceremony["input_ids"]
        ]
        self.assertCountEqual(ceremony_inputs, input_ids)
        self.assertEqual(len(ceremony_inputs), len(set(ceremony_inputs)))

    def test_ceremonies_form_one_dependency_order(self) -> None:
        seen: list[str] = []
        for expected_sequence, ceremony in enumerate(CEREMONIES, start=1):
            self.assertEqual(ceremony["sequence"], expected_sequence)
            self.assertTrue(set(ceremony["depends_on"]).issubset(seen))
            seen.append(ceremony["ceremony_id"])

    def test_packet_contains_no_live_values_or_secret_fields(self) -> None:
        serialized = json.dumps(self.packet.to_dict(), sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key":',
            '"signature":',
            '"credential":',
            '"network_endpoint":',
            '"repository_connection":',
        ):
            with self.subTest(field=field):
                self.assertNotIn(field, serialized)

    def test_tampering_with_readiness_is_rejected(self) -> None:
        document = copy.deepcopy(self.packet.to_dict())
        document["readiness"]["ready_for_live_enrollment"] = True
        with self.assertRaisesRegex(QualificationError, "readiness"):
            CandidateEnrollmentDeploymentPreparationPacket.from_dict(document)

    def test_tampering_with_ceremony_order_is_rejected(self) -> None:
        document = copy.deepcopy(self.packet.to_dict())
        document["ceremonies"][1]["sequence"] = 4
        with self.assertRaisesRegex(QualificationError, "ceremonies"):
            CandidateEnrollmentDeploymentPreparationPacket.from_dict(document)

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
            "src/sunderkey/candidate_enrollment_deployment.py",
            "scripts/build_candidate_enrollment_deployment_preparation.py",
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
