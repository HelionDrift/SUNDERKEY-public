"""Phase 71 deployment worksheet and preflight CLI coverage."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.agents._public_cli_test_helper import run_cli

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
PREPARATION_PATH = REGISTRY / "candidate-enrollment-deployment-preparation-d009.json"
WORKSHEET_PATH = REGISTRY / "candidate-enrollment-deployment-worksheet-d009.json"


class CandidateEnrollmentDeploymentCliPhase71Tests(unittest.TestCase):
    def test_create_template_requires_a_new_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "worksheet.json"
            result = run_cli(
                "candidate-enrollment-deployment-template-create",
                "--preparation",
                str(PREPARATION_PATH),
                "--output",
                str(output),
            )
            self.assertEqual(result, {})
            self.assertTrue(output.is_file())
            with self.assertRaisesRegex(SystemExit, "already exists"):
                run_cli(
                    "candidate-enrollment-deployment-template-create",
                    "--preparation",
                    str(PREPARATION_PATH),
                    "--output",
                    str(output),
                )

    def test_preflight_reports_incomplete_without_mutation(self) -> None:
        result = run_cli(
            "candidate-enrollment-deployment-preflight",
            "--preparation",
            str(PREPARATION_PATH),
            "--worksheet",
            str(WORKSHEET_PATH),
        )
        readiness = result["readiness"]
        self.assertEqual(readiness["submission_completeness_status"], "incomplete")
        self.assertFalse(readiness["ready_for_cryptographic_artifact_verification"])
        self.assertFalse(readiness["ready_for_live_enrollment"])
        self.assertEqual(readiness["pending_input_count"], 9)
        self.assertFalse(result["network_call_performed"])
        self.assertEqual(result["qualification_effect"], "none")


if __name__ == "__main__":
    unittest.main()
