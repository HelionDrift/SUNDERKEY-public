"""Phase 82 approved D012 production custody decision coverage."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_candidate_enrollment_production_custody_decision import (
    build_parser,
    build_record,
)
from sunderkey.candidate_enrollment_production_custody_decision import (
    CandidateEnrollmentProductionCustodyDecisionRecord,
    load_candidate_enrollment_production_custody_decision_record,
    load_candidate_enrollment_production_custody_decision_submission,
    verify_candidate_enrollment_production_custody_decision_record,
)
from sunderkey.candidate_enrollment_production_custody_dossier import (
    load_candidate_enrollment_production_custody_dossier,
)
from sunderkey.cli import build_parser as build_cli_parser
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER_PATH = REGISTRY / "candidate-enrollment-production-custody-dossier-d012.json"
SUBMISSION_PATH = (
    REGISTRY / "candidate-enrollment-production-custody-decision-submission-d012.json"
)
DECISION_PATH = REGISTRY / "candidate-enrollment-production-custody-decision-d012.json"
SCHEMA_PATH = (
    REGISTRY
    / "schemas"
    / "candidate-enrollment-production-custody-decision-record-v1.schema.json"
)


class CandidateEnrollmentProductionCustodyDecisionPhase82Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_candidate_enrollment_production_custody_dossier(DOSSIER_PATH)
        cls.submission = load_candidate_enrollment_production_custody_decision_submission(
            SUBMISSION_PATH
        )
        cls.record = load_candidate_enrollment_production_custody_decision_record(
            DECISION_PATH
        )

    def test_checked_record_matches_deterministic_builder(self) -> None:
        expected = build_record(build_parser().parse_args([]))
        self.assertEqual(
            DECISION_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.record.to_dict(), expected)

    def test_record_has_stable_identity_and_dossier_binding(self) -> None:
        document = self.record.to_dict()
        self.assertEqual(document["source_dossier"], self.submission["source_dossier"])
        self.assertEqual(
            verify_candidate_enrollment_production_custody_decision_record(
                self.record, self.dossier
            ),
            self.record,
        )

    def test_full_recommended_bundle_is_approved(self) -> None:
        document = self.record.to_dict()
        alignment = document["recommendation_alignment"]
        self.assertEqual(alignment["selected_option_count"], 8)
        self.assertEqual(alignment["selected_recommended_option_count"], 8)
        self.assertTrue(alignment["all_recommended_options_selected"])
        self.assertEqual(
            document["decision_effect"],
            "production_custody_contract_implementation_authorized",
        )
        self.assertEqual(document["implementation_status"], "not_started")
        self.assertEqual(len(document["required_owner_inputs"]), 5)

    def test_unknown_option_and_tampered_hash_are_rejected(self) -> None:
        unknown = copy.deepcopy(self.record.to_dict())
        unknown["selected_options"]["deployment_runtime"] = "unreviewed_runtime"
        with self.assertRaisesRegex(QualificationError, "deployment_runtime"):
            CandidateEnrollmentProductionCustodyDecisionRecord.from_dict(unknown)
        tampered = copy.deepcopy(self.record.to_dict())
        tampered["approval"]["rationale"] = "Different approval"
        with self.assertRaisesRegex(QualificationError, "hash"):
            CandidateEnrollmentProductionCustodyDecisionRecord.from_dict(tampered)

    def test_approval_does_not_select_infrastructure_or_activate(self) -> None:
        serialized = json.dumps(self.record.to_dict(), sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key":',
            '"credential":',
            '"network_endpoint":',
            '"bucket_name":',
            '"service_identity":',
            '"candidate_id":',
        ):
            with self.subTest(field=field):
                self.assertNotIn(field, serialized)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_record_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.record.to_dict())

    def test_public_commands_are_registered(self) -> None:
        parser = build_cli_parser()
        with tempfile.TemporaryDirectory() as temporary:
            output = str(Path(temporary) / "record.json")
            args = parser.parse_args(
                [
                    "candidate-enrollment-production-custody-decision-record",
                    "--dossier",
                    str(DOSSIER_PATH),
                    "--submission",
                    str(SUBMISSION_PATH),
                    "--output",
                    output,
                ]
            )
            self.assertTrue(callable(args.handler))
        verify = parser.parse_args(
            [
                "candidate-enrollment-production-custody-decision-record-verify",
                "--dossier",
                str(DOSSIER_PATH),
                "--record",
                str(DECISION_PATH),
            ]
        )
        self.assertTrue(callable(verify.handler))

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
            "src/sunderkey/candidate_enrollment_production_custody_decision.py",
            "scripts/build_candidate_enrollment_production_custody_decision.py",
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
