"""Phase 80 D011 implementation completion report coverage."""

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

from scripts.build_candidate_enrollment_activation_implementation_report import (
    build_parser,
    build_report,
)
from sunderkey.candidate_enrollment_activation_implementation import (
    IMPLEMENTED_STEPS,
    CandidateEnrollmentActivationImplementationReport,
    load_candidate_enrollment_activation_implementation_report,
)
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
REPORT_PATH = REGISTRY / "candidate-enrollment-activation-implementation-d011.json"
SCHEMA_PATH = (
    REGISTRY
    / "schemas"
    / "candidate-enrollment-activation-implementation-report-v1.schema.json"
)


class CandidateEnrollmentActivationImplementationPhase80Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = load_candidate_enrollment_activation_implementation_report(
            REPORT_PATH
        )

    def test_checked_report_matches_deterministic_builder(self) -> None:
        expected = build_report(build_parser().parse_args([]))
        self.assertEqual(
            REPORT_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.report.to_dict(), expected)

    def test_all_authorized_steps_map_to_existing_artifacts(self) -> None:
        self.assertEqual(len(IMPLEMENTED_STEPS), 6)
        for step in IMPLEMENTED_STEPS:
            for relative in step["artifacts"]:
                with self.subTest(step=step["step_id"], artifact=relative):
                    self.assertTrue((ROOT / relative).is_file())

    def test_live_activation_remains_closed(self) -> None:
        document = self.report.to_dict()
        self.assertEqual(
            document["implementation_status"],
            "approved_bundle_contract_implementation_complete",
        )
        self.assertEqual(
            document["live_activation_status"],
            "blocked_pending_production_inputs_and_go_no_go",
        )
        self.assertEqual(len(document["production_prerequisites"]), 9)
        self.assertFalse(document["network_call_performed"])
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(document["registry_effect"], "none")

    def test_tampered_status_or_prerequisite_is_rejected(self) -> None:
        status = copy.deepcopy(self.report.to_dict())
        status["live_activation_status"] = "active"
        with self.assertRaisesRegex(QualificationError, "live_activation_status"):
            CandidateEnrollmentActivationImplementationReport.from_dict(status)
        prerequisite = copy.deepcopy(self.report.to_dict())
        prerequisite["production_prerequisites"].pop()
        with self.assertRaisesRegex(QualificationError, "production_prerequisites"):
            CandidateEnrollmentActivationImplementationReport.from_dict(prerequisite)

    def test_report_contains_no_live_values_secrets_or_markers(self) -> None:
        serialized = json.dumps(self.report.to_dict(), sort_keys=True)
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

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_report_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.report.to_dict())

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
            "src/sunderkey/candidate_enrollment_activation_implementation.py",
            "scripts/build_candidate_enrollment_activation_implementation_report.py",
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
