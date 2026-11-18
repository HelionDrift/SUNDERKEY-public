"""Phase 64 candidate enrollment decision CLI coverage."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.agents.test_candidate_enrollment_decision_phase64 import (
    DOSSIER_PATH,
    completed_submission,
)
from tests.agents._public_cli_test_helper import run_cli


class CandidateEnrollmentDecisionCliPhase64Tests(unittest.TestCase):
    def test_create_record_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "template.json"
            submission = root / "submission.json"
            record = root / "record.json"
            run_cli(
                "candidate-enrollment-decision-template-create",
                "--dossier",
                str(DOSSIER_PATH),
                "--output",
                str(template),
            )
            submission.write_text(
                json.dumps(
                    completed_submission(
                        json.loads(template.read_text(encoding="utf-8"))
                    )
                ),
                encoding="utf-8",
            )
            result = run_cli(
                "candidate-enrollment-decision-record",
                "--dossier",
                str(DOSSIER_PATH),
                "--submission",
                str(submission),
                "--output",
                str(record),
            )
            self.assertEqual(result["status"], "valid")
            self.assertFalse(result["network_call_performed"])
            self.assertEqual(result["decision_id"], "D009")
            self.assertEqual(result["implementation_status"], "not_started")
            self.assertEqual(result["qualification_effect"], "none")
            verified = run_cli(
                "candidate-enrollment-decision-record-verify",
                "--dossier",
                str(DOSSIER_PATH),
                "--record",
                str(record),
            )
            self.assertEqual(verified["record_id"], result["record_id"])
            self.assertEqual(verified["status"], "valid")


if __name__ == "__main__":
    unittest.main()
