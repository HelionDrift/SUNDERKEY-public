"""Phase 71 deployment-input worksheet and preflight coverage."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None
    FormatChecker = None

from scripts.build_candidate_enrollment_deployment_inputs import (
    build_documents,
    build_parser,
)
from sunderkey.candidate_enrollment_deployment import (
    load_candidate_enrollment_deployment_preparation,
)
from sunderkey.candidate_enrollment_deployment_inputs import (
    CandidateEnrollmentDeploymentPreflightReport,
    CandidateEnrollmentDeploymentWorksheet,
    assess_candidate_enrollment_deployment_inputs,
    build_candidate_enrollment_deployment_worksheet,
    load_candidate_enrollment_deployment_preflight,
    load_candidate_enrollment_deployment_worksheet,
)
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
PREPARATION_PATH = REGISTRY / "candidate-enrollment-deployment-preparation-d009.json"
WORKSHEET_PATH = REGISTRY / "candidate-enrollment-deployment-worksheet-d009.json"
PREFLIGHT_PATH = REGISTRY / "candidate-enrollment-deployment-preflight-d009.json"
WORKSHEET_SCHEMA_PATH = (
    REGISTRY / "schemas" / "candidate-enrollment-deployment-worksheet-v1.schema.json"
)
PREFLIGHT_SCHEMA_PATH = (
    REGISTRY / "schemas" / "candidate-enrollment-deployment-preflight-v1.schema.json"
)


class CandidateEnrollmentDeploymentInputsPhase71Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packet = load_candidate_enrollment_deployment_preparation(PREPARATION_PATH)
        cls.worksheet = load_candidate_enrollment_deployment_worksheet(WORKSHEET_PATH)
        cls.preflight = load_candidate_enrollment_deployment_preflight(PREFLIGHT_PATH)

    def completed_worksheet(self) -> CandidateEnrollmentDeploymentWorksheet:
        document = copy.deepcopy(self.worksheet.to_dict())
        document["deployment_id"] = "deployment.phase71"
        document["prepared_by"] = "deployment.owner"
        document["prepared_at"] = "2026-08-02T18:00:00Z"
        for input_index, item in enumerate(document["inputs"], start=1):
            for role_index, assignment in enumerate(item["role_assignments"], start=1):
                assignment["principal_id"] = (
                    f"principal.input{input_index}.role{role_index}"
                )
            for evidence_index, evidence in enumerate(
                item["completion_evidence"],
                start=1,
            ):
                digest_seed = input_index * 16 + evidence_index
                evidence["artifact_sha256"] = "sha256:" + f"{digest_seed:064x}"
            item["completed_at"] = f"2026-08-02T18:{input_index:02d}:00Z"
        return CandidateEnrollmentDeploymentWorksheet.from_dict(document)

    def test_checked_documents_match_deterministic_builder(self) -> None:
        expected_worksheet, expected_preflight = build_documents(
            build_parser().parse_args([])
        )
        self.assertEqual(
            WORKSHEET_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_worksheet, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            PREFLIGHT_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_preflight, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            build_candidate_enrollment_deployment_worksheet(self.packet),
            self.worksheet,
        )
        self.assertEqual(
            assess_candidate_enrollment_deployment_inputs(
                self.packet,
                self.worksheet,
            ),
            self.preflight,
        )

    def test_blank_documents_have_stable_identity_and_fail_closed(self) -> None:
        self.assertEqual(
            self.worksheet.template_id,
            "CDT-24BECD939568B31ACFBE418C16410DF4",
        )
        self.assertEqual(
            self.worksheet.template_sha256,
            "sha256:24becd939568b31acfbe418c16410df4"
            "bd38ea94c0c69dd8dcef966be841ce3e",
        )
        document = self.preflight.to_dict()
        self.assertEqual(document["report_id"], "CDR-7A1583D0E55E2A36481AB5E665ACDA86")
        self.assertEqual(
            document["report_sha256"],
            "sha256:7a1583d0e55e2a36481ab5e665acda86"
            "084696b8824555dd96361a5356465a22",
        )
        readiness = document["readiness"]
        self.assertEqual(readiness["submission_completeness_status"], "incomplete")
        self.assertFalse(readiness["ready_for_cryptographic_artifact_verification"])
        self.assertFalse(readiness["ready_for_live_enrollment"])
        self.assertEqual(readiness["pending_input_count"], 9)
        self.assertEqual(len(readiness["pending_global_fields"]), 3)

    def test_complete_worksheet_only_reaches_artifact_verification_gate(self) -> None:
        report = assess_candidate_enrollment_deployment_inputs(
            self.packet,
            self.completed_worksheet(),
        ).to_dict()
        readiness = report["readiness"]
        self.assertEqual(readiness["submission_completeness_status"], "complete")
        self.assertTrue(readiness["ready_for_cryptographic_artifact_verification"])
        self.assertFalse(readiness["ready_for_live_enrollment"])
        self.assertTrue(readiness["self_reported_evidence_only"])
        self.assertEqual(readiness["pending_input_count"], 0)
        self.assertEqual(readiness["pending_global_fields"], [])
        self.assertTrue(
            all(
                item["input_status"] == "externally_documented"
                for item in report["input_results"]
            )
        )

    def test_one_missing_digest_keeps_its_input_pending(self) -> None:
        worksheet = self.completed_worksheet().to_dict()
        missing_id = worksheet["inputs"][3]["completion_evidence"][1]["evidence_id"]
        worksheet["inputs"][3]["completion_evidence"][1]["artifact_sha256"] = None
        report = assess_candidate_enrollment_deployment_inputs(
            self.packet,
            CandidateEnrollmentDeploymentWorksheet.from_dict(worksheet),
        ).to_dict()
        result = report["input_results"][3]
        self.assertEqual(result["input_status"], "pending")
        self.assertEqual(result["missing_completion_evidence"], [missing_id])
        self.assertEqual(report["readiness"]["pending_input_count"], 1)
        self.assertFalse(
            report["readiness"]["ready_for_cryptographic_artifact_verification"]
        )

    def test_report_rejects_inconsistent_self_reported_status(self) -> None:
        document = copy.deepcopy(self.preflight.to_dict())
        document["input_results"][0]["input_status"] = "externally_documented"
        with self.assertRaisesRegex(QualificationError, "inconsistent"):
            CandidateEnrollmentDeploymentPreflightReport.from_dict(document)

    def test_worksheet_rejects_unknown_fields_and_bad_evidence_digests(self) -> None:
        unknown = copy.deepcopy(self.worksheet.to_dict())
        unknown["private_key"] = "not-allowed"
        with self.assertRaisesRegex(QualificationError, "unsupported fields"):
            CandidateEnrollmentDeploymentWorksheet.from_dict(unknown)
        bad_digest = copy.deepcopy(self.worksheet.to_dict())
        bad_digest["inputs"][0]["completion_evidence"][0]["artifact_sha256"] = (
            "sha256:not-a-digest"
        )
        with self.assertRaisesRegex(QualificationError, "artifact_sha256"):
            CandidateEnrollmentDeploymentWorksheet.from_dict(bad_digest)

    def test_checked_worksheet_contains_no_live_or_secret_values(self) -> None:
        serialized = json.dumps(self.worksheet.to_dict(), sort_keys=True)
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

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_checked_documents_match_published_schemas(self) -> None:
        assert Draft202012Validator is not None
        worksheet_schema = json.loads(WORKSHEET_SCHEMA_PATH.read_text(encoding="utf-8"))
        preflight_schema = json.loads(PREFLIGHT_SCHEMA_PATH.read_text(encoding="utf-8"))
        checker = FormatChecker() if FormatChecker is not None else None
        Draft202012Validator(
            worksheet_schema,
            format_checker=checker,
        ).validate(self.worksheet.to_dict())
        Draft202012Validator(preflight_schema).validate(self.preflight.to_dict())

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
            "src/sunderkey/candidate_enrollment_deployment_inputs.py",
            "scripts/build_candidate_enrollment_deployment_inputs.py",
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
