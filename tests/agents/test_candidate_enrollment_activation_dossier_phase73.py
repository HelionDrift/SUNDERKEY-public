"""Phase 73 D011 checkpoint custody and activation dossier coverage."""

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

from scripts.build_candidate_enrollment_activation_dossier import (
    build_dossier,
    build_parser,
)
from sunderkey.candidate_enrollment_activation_dossier import (
    AUTHORIZED_NEXT_STEPS_IF_APPROVED,
    DECISION_QUESTIONS,
    RECOMMENDED_OPTIONS,
    CandidateEnrollmentActivationDecisionDossier,
    load_candidate_enrollment_activation_decision_dossier,
)
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER_PATH = REGISTRY / "candidate-enrollment-activation-dossier-d011.json"
SCHEMA_PATH = (
    REGISTRY / "schemas" / "candidate-enrollment-activation-dossier-v1.schema.json"
)


class CandidateEnrollmentActivationDossierPhase73Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_candidate_enrollment_activation_decision_dossier(
            DOSSIER_PATH
        )

    def test_checked_dossier_matches_deterministic_builder(self) -> None:
        expected = build_dossier(build_parser().parse_args([]))
        self.assertEqual(
            DOSSIER_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.dossier.to_dict(), expected)

    def test_dossier_has_stable_identity_and_no_decision_effect(self) -> None:
        document = self.dossier.to_dict()
        self.assertEqual(document["report_id"], "CAD-0385A0AC095A34853650213AB5AFB90F")
        self.assertEqual(
            document["report_sha256"],
            "sha256:0385a0ac095a34853650213ab5afb90f"
            "8b818dfb7017ed9d9258914802eb4916",
        )
        self.assertEqual(document["decision_id"], "D011")
        self.assertEqual(document["status"], "decision_required")
        self.assertEqual(document["decision_effect"], "none")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(document["registry_effect"], "none")

    def test_all_eight_questions_have_one_unselected_recommendation(self) -> None:
        document = self.dossier.to_dict()
        self.assertEqual(len(DECISION_QUESTIONS), 8)
        self.assertEqual(
            document["recommendation"]["recommended_options"],
            RECOMMENDED_OPTIONS,
        )
        self.assertEqual(
            document["recommendation"]["selection_state"],
            "not_selected",
        )
        for question in document["decision_questions"]:
            recommended = [
                option for option in question["options"] if option["recommended"]
            ]
            self.assertEqual(len(recommended), 1)
            self.assertEqual(
                recommended[0]["option_id"],
                question["recommended_option_id"],
            )

    def test_implementation_stays_blocked_until_explicit_d011_approval(self) -> None:
        document = self.dossier.to_dict()
        boundary = document["current_boundary"]
        self.assertEqual(boundary["checkpoint_persistence_status"], "not_implemented")
        self.assertEqual(
            boundary["controlled_catalog_release_status"],
            "not_implemented",
        )
        self.assertEqual(boundary["live_enrollment_status"], "not_started")
        self.assertEqual(
            document["authorized_next_steps_if_approved"],
            list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
        )

    def test_tampered_selection_or_effect_is_rejected(self) -> None:
        selected = copy.deepcopy(self.dossier.to_dict())
        selected["recommendation"]["selection_state"] = "selected"
        with self.assertRaisesRegex(QualificationError, "recommendation"):
            CandidateEnrollmentActivationDecisionDossier.from_dict(selected)
        effect = copy.deepcopy(self.dossier.to_dict())
        effect["decision_effect"] = "activation_authorized"
        with self.assertRaisesRegex(QualificationError, "effect"):
            CandidateEnrollmentActivationDecisionDossier.from_dict(effect)

    def test_dossier_contains_no_live_values_or_secret_fields(self) -> None:
        serialized = json.dumps(self.dossier.to_dict(), sort_keys=True)
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
    def test_dossier_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.dossier.to_dict())

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
            "src/sunderkey/candidate_enrollment_activation_dossier.py",
            "scripts/build_candidate_enrollment_activation_dossier.py",
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
