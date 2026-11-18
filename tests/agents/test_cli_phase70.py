"""Phase 70 candidate enrollment deployment preparation CLI coverage."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.agents._public_cli_test_helper import run_cli

ROOT = Path(__file__).resolve().parents[2]
IMPLEMENTATION_PATH = ROOT / "registry" / "candidate-enrollment-implementation-d009.json"


class CandidateEnrollmentDeploymentCliPhase70Tests(unittest.TestCase):
    def test_prepare_reports_every_pending_external_input(self) -> None:
        result = run_cli(
            "candidate-enrollment-deployment-prepare",
            "--implementation",
            str(IMPLEMENTATION_PATH),
        )
        self.assertEqual(result["deployment_status"], "awaiting_external_inputs")
        self.assertFalse(result["readiness"]["ready_for_live_enrollment"])
        self.assertEqual(result["readiness"]["pending_input_count"], 9)
        self.assertFalse(result["network_call_performed"])
        self.assertEqual(result["qualification_effect"], "none")

    def test_prepare_can_write_a_deterministic_packet(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "deployment-preparation.json"
            result = run_cli(
                "candidate-enrollment-deployment-prepare",
                "--implementation",
                str(IMPLEMENTATION_PATH),
                "--output",
                str(output),
            )
            self.assertEqual(result, {})
            written = run_cli(
                "candidate-enrollment-deployment-prepare",
                "--implementation",
                str(IMPLEMENTATION_PATH),
            )
            self.assertEqual(output.read_text(encoding="utf-8"), _cli_json(written))


def _cli_json(value: dict[str, object]) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    unittest.main()
