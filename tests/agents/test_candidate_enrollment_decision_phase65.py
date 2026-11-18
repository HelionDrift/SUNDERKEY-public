"""Phase 65 approved D009 candidate enrollment decision coverage."""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

from scripts.build_candidate_enrollment_decision import build_parser, build_record
from sunderkey.candidate_enrollment_decision import (
    load_candidate_enrollment_decision_record,
    load_candidate_enrollment_decision_submission,
    verify_candidate_enrollment_decision_record,
)
from sunderkey.candidate_enrollment_dossier import (
    load_candidate_enrollment_decision_dossier,
)

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER_PATH = REGISTRY / "candidate-enrollment-dossier-d009.json"
SUBMISSION_PATH = REGISTRY / "candidate-enrollment-decision-submission-d009.json"
DECISION_PATH = REGISTRY / "candidate-enrollment-decision-d009.json"


class CandidateEnrollmentDecisionPhase65Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_candidate_enrollment_decision_dossier(DOSSIER_PATH)
        cls.submission = load_candidate_enrollment_decision_submission(SUBMISSION_PATH)
        cls.record = load_candidate_enrollment_decision_record(DECISION_PATH)

    def test_checked_record_matches_deterministic_builder(self) -> None:
        expected = build_record(build_parser().parse_args([]))
        self.assertEqual(
            DECISION_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.record.to_dict(), expected)

    def test_record_has_stable_identity_and_exact_dossier_binding(self) -> None:
        document = self.record.to_dict()
        self.assertEqual(document["record_id"], "CER-8E14690F10D716F768E1EE474B495F55")
        self.assertEqual(
            document["record_sha256"],
            "sha256:8e14690f10d716f768e1ee474b495f55"
            "6926b88a4119a201e3c67c7aefb44aeb",
        )
        self.assertEqual(document["source_dossier"], self.submission["source_dossier"])
        self.assertEqual(
            verify_candidate_enrollment_decision_record(self.record, self.dossier),
            self.record,
        )

    def test_full_recommended_bundle_is_approved(self) -> None:
        document = self.record.to_dict()
        alignment = document["recommendation_alignment"]
        self.assertEqual(alignment["selected_option_count"], 9)
        self.assertEqual(alignment["selected_recommended_option_count"], 9)
        self.assertTrue(alignment["all_recommended_options_selected"])
        self.assertEqual(document["decision_effect"], "contract_implementation_authorized")
        self.assertEqual(document["qualification_effect"], "none")

    def test_approval_does_not_create_trust_material(self) -> None:
        serialized = json.dumps(self.record.to_dict(), sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key"',
            '"public_key"',
            '"signature"',
            '"repository_endpoint"',
            '"repository_credentials"',
        ):
            with self.subTest(field=field):
                self.assertNotIn(field, serialized)

    def test_builder_has_no_network_or_execution_dependencies(self) -> None:
        prohibited = {"asyncio", "http", "requests", "socket", "subprocess", "urllib"}
        path = ROOT / "scripts" / "build_candidate_enrollment_decision.py"
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
