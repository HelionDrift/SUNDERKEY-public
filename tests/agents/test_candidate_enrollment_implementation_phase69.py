"""Phase 69 D009 contract implementation completion report coverage."""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_candidate_enrollment_implementation_report import (
    build_parser,
    build_report,
)
from sunderkey.candidate_enrollment_decision import (
    load_candidate_enrollment_decision_record,
)
from sunderkey.candidate_enrollment_implementation import (
    IMPLEMENTED_STEPS,
    build_candidate_enrollment_implementation_report,
    load_candidate_enrollment_implementation_report,
)

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DECISION_PATH = REGISTRY / "candidate-enrollment-decision-d009.json"
REPORT_PATH = REGISTRY / "candidate-enrollment-implementation-d009.json"
SCHEMA_PATH = (
    REGISTRY / "schemas" / "candidate-enrollment-implementation-report.schema.json"
)


class CandidateEnrollmentImplementationPhase69Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.decision = load_candidate_enrollment_decision_record(DECISION_PATH)
        cls.report = load_candidate_enrollment_implementation_report(REPORT_PATH)

    def test_checked_report_matches_deterministic_builder(self) -> None:
        expected = build_report(build_parser().parse_args([]))
        self.assertEqual(
            REPORT_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.report.to_dict(), expected)
        self.assertEqual(
            build_candidate_enrollment_implementation_report(self.decision),
            self.report,
        )

    def test_report_has_stable_identity_and_no_operational_effect(self) -> None:
        document = self.report.to_dict()
        self.assertEqual(document["report_id"], "CEI-D1B281DE3CA3249C30A0090844BDD2BB")
        self.assertEqual(
            document["report_sha256"],
            "sha256:d1b281de3ca3249c30a0090844bdd2bb"
            "15928efdb3738f5b84c5cbf8407cc47d",
        )
        self.assertEqual(document["implementation_status"], "contract_implementation_complete")
        self.assertEqual(document["live_enrollment_status"], "not_started")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(document["registry_effect"], "none")

    def test_every_authorized_step_maps_to_existing_artifacts(self) -> None:
        self.assertEqual(
            [item["step_id"] for item in IMPLEMENTED_STEPS],
            self.decision.to_dict()["authorized_next_steps"],
        )
        for step in IMPLEMENTED_STEPS:
            for relative in step["artifacts"]:
                with self.subTest(step=step["step_id"], artifact=relative):
                    self.assertTrue((ROOT / relative).is_file())

    def test_report_contains_no_live_identity_or_key_material(self) -> None:
        serialized = json.dumps(self.report.to_dict(), sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key"',
            '"public_key"',
            '"signature"',
            '"repository_endpoint"',
            '"credential_id"',
        ):
            self.assertNotIn(field, serialized)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_report_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.report.to_dict())

    def test_modules_have_no_network_storage_or_execution_imports(self) -> None:
        prohibited = {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
        for relative in (
            "src/sunderkey/candidate_enrollment_implementation.py",
            "scripts/build_candidate_enrollment_implementation_report.py",
        ):
            path = ROOT / relative
            tree = ast.parse(path.read_text(encoding="utf-8"))
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
