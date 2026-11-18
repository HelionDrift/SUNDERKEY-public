"""Phase 72 offline cryptographic deployment verification coverage."""

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

from sunderkey.candidate_enrollment_deployment import (
    load_candidate_enrollment_deployment_preparation,
)
from sunderkey.candidate_enrollment_deployment_inputs import (
    CandidateEnrollmentDeploymentWorksheet,
    assess_candidate_enrollment_deployment_inputs,
    load_candidate_enrollment_deployment_preflight,
    load_candidate_enrollment_deployment_worksheet,
)
from sunderkey.candidate_enrollment_deployment_verification import (
    CandidateEnrollmentDeploymentVerificationContext,
    CandidateEnrollmentDeploymentVerificationReceipt,
    verify_candidate_enrollment_deployment_artifacts,
    verify_candidate_enrollment_deployment_verification_receipt,
)
from sunderkey.candidate_enrollment_verification import (
    CandidateEnrollmentCatalogCheckpoint,
)
from sunderkey.errors import QualificationError
from tests.agents.test_candidate_enrollment_verification_phase67 import (
    NOW,
    CandidateEnrollmentVerificationPhase67Tests,
)
from tests.agents.test_qualification_trust_verification_phase33 import (
    ROOT_KEY_ID,
    ROOT_SEED,
    _encoded,
    _raw_public_key,
)

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
PREPARATION_PATH = REGISTRY / "candidate-enrollment-deployment-preparation-d009.json"
WORKSHEET_PATH = REGISTRY / "candidate-enrollment-deployment-worksheet-d009.json"
PREFLIGHT_PATH = REGISTRY / "candidate-enrollment-deployment-preflight-d009.json"
CONTEXT_SCHEMA_PATH = (
    REGISTRY
    / "schemas"
    / "candidate-enrollment-deployment-verification-context-v1.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    REGISTRY
    / "schemas"
    / "candidate-enrollment-deployment-verification-receipt-v1.schema.json"
)


class CandidateEnrollmentDeploymentVerificationPhase72Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        CandidateEnrollmentVerificationPhase67Tests.setUpClass()
        cls.fixture = CandidateEnrollmentVerificationPhase67Tests(
            methodName="test_complete_chain_verifies_and_resolves_exact_enrollment"
        )
        cls.preparation = load_candidate_enrollment_deployment_preparation(
            PREPARATION_PATH
        )
        cls.blank_worksheet = load_candidate_enrollment_deployment_worksheet(
            WORKSHEET_PATH
        )
        cls.blank_preflight = load_candidate_enrollment_deployment_preflight(
            PREFLIGHT_PATH
        )

    def completed_worksheet(self) -> CandidateEnrollmentDeploymentWorksheet:
        document = copy.deepcopy(self.blank_worksheet.to_dict())
        document["deployment_id"] = "deployment.phase72"
        document["prepared_by"] = "deployment.owner"
        document["prepared_at"] = "2026-02-02T00:00:00Z"
        for input_index, item in enumerate(document["inputs"], start=1):
            for role_index, assignment in enumerate(item["role_assignments"], start=1):
                assignment["principal_id"] = (
                    f"principal.input{input_index}.role{role_index}"
                )
            for evidence_index, evidence in enumerate(
                item["completion_evidence"],
                start=1,
            ):
                value = input_index * 16 + evidence_index
                evidence["artifact_sha256"] = "sha256:" + f"{value:064x}"
            item["completed_at"] = f"2026-02-02T00:{input_index:02d}:00Z"
        return CandidateEnrollmentDeploymentWorksheet.from_dict(document)

    def inputs(self):
        artifacts = self.fixture.artifacts()
        (
            policy,
            _,
            assurance,
            control,
            _,
            _,
            authorization,
            _,
            catalog,
        ) = artifacts
        worksheet = self.completed_worksheet()
        preflight = assess_candidate_enrollment_deployment_inputs(
            self.preparation,
            worksheet,
        )
        context = CandidateEnrollmentDeploymentVerificationContext.from_dict(
            {
                "schema_version": 1,
                "qualification_policy": {
                    "expected_issuer": policy.issuer,
                    "expected_audience": policy.audience,
                    "root_key_id": ROOT_KEY_ID,
                    "root_public_key": _encoded(_raw_public_key(ROOT_SEED)),
                    "minimum_version": 1,
                },
                "signer_authorization": {
                    "expected_issuer": authorization.issuer,
                    "expected_audience": authorization.audience,
                    "minimum_version": 1,
                },
                "catalog": {
                    "expected_catalog_id": catalog.catalog_id,
                    "expected_issuer": catalog.issuer,
                    "expected_audience": catalog.audience,
                    "minimum_version": 1,
                },
                "profile_id": catalog.enrollments[0].profile_id,
                "reviewers": {
                    "independent_control": {"reviewer_id": control.reviewer_id},
                    "independent_assurance": {
                        "reviewer_id": assurance.reviewer_id
                    },
                },
                "verification_time": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_seen_checkpoint": None,
                "context_effect": "verification_inputs_only",
            }
        )
        return (
            worksheet,
            preflight,
            context,
            policy,
            authorization,
            control,
            assurance,
            catalog,
        )

    def verify(self):
        (
            worksheet,
            preflight,
            context,
            policy,
            authorization,
            control,
            assurance,
            catalog,
        ) = self.inputs()
        return verify_candidate_enrollment_deployment_artifacts(
            self.preparation,
            worksheet,
            preflight,
            context,
            self.fixture.standard,
            self.fixture.d008,
            self.fixture.d009,
            policy,
            authorization,
            control,
            assurance,
            catalog,
        )

    def test_complete_chain_derives_uncommitted_checkpoint(self) -> None:
        receipt = self.verify()
        document = receipt.to_dict()
        self.assertEqual(
            document["verification_status"],
            "cryptographic_artifacts_verified",
        )
        self.assertEqual(len(document["verification_gates"]), 8)
        self.assertEqual(document["next_checkpoint"]["catalog_version"], 1)
        readiness = document["readiness"]
        self.assertTrue(readiness["ready_for_checkpoint_commit"])
        self.assertFalse(readiness["ready_for_controlled_catalog_release"])
        self.assertFalse(readiness["ready_for_live_enrollment"])
        self.assertFalse(document["network_call_performed"])
        self.assertEqual(document["qualification_effect"], "none")

    def test_incomplete_or_stale_documentation_fails_before_crypto(self) -> None:
        inputs = list(self.inputs())
        inputs[0] = self.blank_worksheet
        inputs[1] = self.blank_preflight
        with self.assertRaisesRegex(QualificationError, "incomplete"):
            verify_candidate_enrollment_deployment_artifacts(
                self.preparation,
                inputs[0],
                inputs[1],
                inputs[2],
                self.fixture.standard,
                self.fixture.d008,
                self.fixture.d009,
                *inputs[3:],
            )
        inputs = list(self.inputs())
        with self.assertRaisesRegex(QualificationError, "stale"):
            verify_candidate_enrollment_deployment_artifacts(
                self.preparation,
                inputs[0],
                self.blank_preflight,
                inputs[2],
                self.fixture.standard,
                self.fixture.d008,
                self.fixture.d009,
                *inputs[3:],
            )

    def test_wrong_out_of_band_root_fails_closed(self) -> None:
        inputs = list(self.inputs())
        context = inputs[2].to_dict()
        context["qualification_policy"]["root_public_key"] = _encoded(
            _raw_public_key(8)
        )
        inputs[2] = CandidateEnrollmentDeploymentVerificationContext.from_dict(context)
        with self.assertRaisesRegex(QualificationError, "signature"):
            verify_candidate_enrollment_deployment_artifacts(
                self.preparation,
                inputs[0],
                inputs[1],
                inputs[2],
                self.fixture.standard,
                self.fixture.d008,
                self.fixture.d009,
                *inputs[3:],
            )

    def test_stale_checkpoint_and_wrong_expected_scope_fail_closed(self) -> None:
        inputs = list(self.inputs())
        catalog = inputs[-1]
        context = inputs[2].to_dict()
        context["last_seen_checkpoint"] = CandidateEnrollmentCatalogCheckpoint(
            catalog.catalog_id,
            1,
            "sha256:" + "0" * 64,
        ).to_dict()
        inputs[2] = CandidateEnrollmentDeploymentVerificationContext.from_dict(context)
        with self.assertRaisesRegex(QualificationError, "replaced"):
            verify_candidate_enrollment_deployment_artifacts(
                self.preparation,
                inputs[0],
                inputs[1],
                inputs[2],
                self.fixture.standard,
                self.fixture.d008,
                self.fixture.d009,
                *inputs[3:],
            )
        inputs = list(self.inputs())
        context = inputs[2].to_dict()
        context["catalog"]["expected_audience"] = "another-audience"
        inputs[2] = CandidateEnrollmentDeploymentVerificationContext.from_dict(context)
        with self.assertRaisesRegex(QualificationError, "audience"):
            verify_candidate_enrollment_deployment_artifacts(
                self.preparation,
                inputs[0],
                inputs[1],
                inputs[2],
                self.fixture.standard,
                self.fixture.d008,
                self.fixture.d009,
                *inputs[3:],
            )

    def test_receipt_hash_and_readiness_tampering_are_rejected(self) -> None:
        document = self.verify().to_dict()
        document["readiness"]["ready_for_live_enrollment"] = True
        with self.assertRaisesRegex(QualificationError, "readiness"):
            CandidateEnrollmentDeploymentVerificationReceipt.from_dict(document)

    def test_receipt_reverification_requires_every_exact_source(self) -> None:
        receipt = self.verify()
        inputs = self.inputs()
        self.assertEqual(
            verify_candidate_enrollment_deployment_verification_receipt(
                receipt,
                self.preparation,
                inputs[0],
                inputs[1],
                inputs[2],
                self.fixture.standard,
                self.fixture.d008,
                self.fixture.d009,
                *inputs[3:],
            ),
            receipt,
        )
        context = inputs[2].to_dict()
        context["catalog"]["minimum_version"] = 2
        with self.assertRaisesRegex(QualificationError, "version is too old"):
            verify_candidate_enrollment_deployment_verification_receipt(
                receipt,
                self.preparation,
                inputs[0],
                inputs[1],
                CandidateEnrollmentDeploymentVerificationContext.from_dict(context),
                self.fixture.standard,
                self.fixture.d008,
                self.fixture.d009,
                *inputs[3:],
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_context_and_receipt_match_published_schemas(self) -> None:
        inputs = self.inputs()
        receipt = self.verify()
        context_schema = json.loads(CONTEXT_SCHEMA_PATH.read_text(encoding="utf-8"))
        receipt_schema = json.loads(RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8"))
        checker = FormatChecker() if FormatChecker is not None else None
        Draft202012Validator(
            context_schema,
            format_checker=checker,
        ).validate(inputs[2].to_dict())
        Draft202012Validator(
            receipt_schema,
            format_checker=checker,
        ).validate(receipt.to_dict())

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = (
            ROOT
            / "src"
            / "sunderkey"
            / "candidate_enrollment_deployment_verification.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
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
