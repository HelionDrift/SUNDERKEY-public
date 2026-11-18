"""Phase 73 D011 activation dossier CLI coverage."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.agents._public_cli_test_helper import run_cli

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"


class CandidateEnrollmentActivationDossierCliPhase73Tests(unittest.TestCase):
    def test_cli_builds_pending_d011_dossier_without_effect(self) -> None:
        result = run_cli(
            "candidate-enrollment-activation-dossier",
            "--d009-decision",
            str(REGISTRY / "candidate-enrollment-decision-d009.json"),
            "--implementation",
            str(REGISTRY / "candidate-enrollment-implementation-d009.json"),
            "--preparation",
            str(REGISTRY / "candidate-enrollment-deployment-preparation-d009.json"),
            "--verification-receipt-schema",
            str(
                REGISTRY
                / "schemas"
                / "candidate-enrollment-deployment-verification-receipt-v1.schema.json"
            ),
        )
        self.assertEqual(result["decision_id"], "D011")
        self.assertEqual(result["status"], "decision_required")
        self.assertEqual(result["recommendation"]["selection_state"], "not_selected")
        self.assertEqual(result["decision_effect"], "none")
        self.assertEqual(result["qualification_effect"], "none")


if __name__ == "__main__":
    unittest.main()
