"""Phase 72 cryptographic deployment verification CLI coverage."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.agents.test_candidate_enrollment_deployment_verification_phase72 import (
    CandidateEnrollmentDeploymentVerificationPhase72Tests,
)
from tests.agents._public_cli_test_helper import run_cli

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"


class CandidateEnrollmentDeploymentCliPhase72Tests(unittest.TestCase):
    def setUp(self) -> None:
        CandidateEnrollmentDeploymentVerificationPhase72Tests.setUpClass()
        self.fixture = CandidateEnrollmentDeploymentVerificationPhase72Tests(
            methodName="test_complete_chain_derives_uncommitted_checkpoint"
        )

    def write_inputs(self, directory: Path) -> dict[str, Path]:
        (
            worksheet,
            preflight,
            context,
            policy,
            authorization,
            control,
            assurance,
            catalog,
        ) = self.fixture.inputs()
        values = {
            "worksheet": worksheet.to_dict(),
            "preflight": preflight.to_dict(),
            "context": context.to_dict(),
            "policy": policy.to_dict(),
            "authorization": authorization.to_dict(),
            "control-credential": control.to_dict(),
            "assurance-credential": assurance.to_dict(),
            "catalog": catalog.to_dict(),
        }
        paths: dict[str, Path] = {}
        for name, value in values.items():
            path = directory / f"{name}.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            paths[name] = path
        return paths

    def arguments(self, paths: dict[str, Path]) -> list[str]:
        values = {
            "preparation": REGISTRY
            / "candidate-enrollment-deployment-preparation-d009.json",
            "worksheet": paths["worksheet"],
            "preflight": paths["preflight"],
            "context": paths["context"],
            "registry": REGISTRY / "army-v1.json",
            "capabilities": REGISTRY / "capabilities-army-v1.json",
            "standard": REGISTRY / "qualification-standard-v1.json",
            "d008-decision": REGISTRY / "qualification-authority-decision-d008.json",
            "d009-decision": REGISTRY / "candidate-enrollment-decision-d009.json",
            "policy": paths["policy"],
            "authorization": paths["authorization"],
            "control-credential": paths["control-credential"],
            "assurance-credential": paths["assurance-credential"],
            "catalog": paths["catalog"],
        }
        arguments: list[str] = []
        for name, path in values.items():
            arguments.extend((f"--{name}", str(path)))
        return arguments

    def test_cli_verifies_offline_and_writes_exclusive_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = self.write_inputs(root)
            output = root / "verification-receipt.json"
            result = run_cli(
                "candidate-enrollment-deployment-verify",
                *self.arguments(paths),
                "--output",
                str(output),
            )
            self.assertEqual(result["status"], "valid")
            self.assertEqual(
                result["verification_status"],
                "cryptographic_artifacts_verified",
            )
            self.assertTrue(result["readiness"]["ready_for_checkpoint_commit"])
            self.assertFalse(result["readiness"]["ready_for_live_enrollment"])
            self.assertFalse(result["network_call_performed"])
            self.assertTrue(output.is_file())
            verified = run_cli(
                "candidate-enrollment-deployment-receipt-verify",
                *self.arguments(paths),
                "--receipt",
                str(output),
            )
            self.assertEqual(verified["receipt_id"], result["receipt_id"])
            self.assertEqual(verified["receipt_sha256"], result["receipt_sha256"])
            with self.assertRaisesRegex(SystemExit, "already exists"):
                run_cli(
                    "candidate-enrollment-deployment-verify",
                    *self.arguments(paths),
                    "--output",
                    str(output),
                )


if __name__ == "__main__":
    unittest.main()
