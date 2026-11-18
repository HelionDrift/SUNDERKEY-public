"""Phase 81 D012 production custody decision dossier coverage."""

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

from scripts.build_candidate_enrollment_production_custody_dossier import (
    build_dossier,
    build_parser,
)
from sunderkey.candidate_enrollment_production_custody_dossier import (
    AUTHORIZED_NEXT_STEPS_IF_APPROVED,
    DECISION_QUESTIONS,
    RECOMMENDED_OPTIONS,
    REQUIRED_OWNER_INPUTS,
    CandidateEnrollmentProductionCustodyDossier,
    load_candidate_enrollment_production_custody_dossier,
)
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER_PATH = REGISTRY / "candidate-enrollment-production-custody-dossier-d012.json"
SCHEMA_PATH = (
    REGISTRY / "schemas" / "candidate-enrollment-production-custody-dossier-v1.schema.json"
)


class CandidateEnrollmentProductionCustodyDossierPhase81Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_candidate_enrollment_production_custody_dossier(
            DOSSIER_PATH
        )

    def test_checked_dossier_matches_deterministic_builder(self) -> None:
        expected = build_dossier(build_parser().parse_args([]))
        self.assertEqual(
            DOSSIER_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.dossier.to_dict(), expected)

    def test_dossier_has_no_decision_or_activation_effect(self) -> None:
        document = self.dossier.to_dict()
        self.assertEqual(document["decision_id"], "D012")
        self.assertEqual(document["status"], "decision_required")
        self.assertEqual(document["decision_effect"], "none")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(document["registry_effect"], "none")
        self.assertFalse(document["network_call_performed"])
        self.assertEqual(document["current_boundary"]["live_activation_status"], "blocked")

    def test_all_questions_have_one_unselected_recommendation(self) -> None:
        document = self.dossier.to_dict()
        self.assertEqual(len(DECISION_QUESTIONS), 8)
        self.assertEqual(
            document["recommendation"]["recommended_options"],
            RECOMMENDED_OPTIONS,
        )
        self.assertEqual(document["recommendation"]["selection_state"], "not_selected")
        for question in document["decision_questions"]:
            recommended = [
                option for option in question["options"] if option["recommended"]
            ]
            self.assertEqual(len(recommended), 1)
            self.assertEqual(recommended[0]["option_id"], question["recommended_option_id"])

    def test_owner_inputs_and_authorized_steps_are_explicit(self) -> None:
        document = self.dossier.to_dict()
        self.assertEqual(document["required_owner_inputs"], list(REQUIRED_OWNER_INPUTS))
        self.assertEqual(
            document["authorized_next_steps_if_approved"],
            list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
        )
        self.assertIn(
            "exact_initial_host_operating_system_and_service_manager",
            document["required_owner_inputs"],
        )

    def test_tampered_selection_or_effect_is_rejected(self) -> None:
        selected = copy.deepcopy(self.dossier.to_dict())
        selected["recommendation"]["selection_state"] = "selected"
        with self.assertRaisesRegex(QualificationError, "recommendation"):
            CandidateEnrollmentProductionCustodyDossier.from_dict(selected)
        effect = copy.deepcopy(self.dossier.to_dict())
        effect["decision_effect"] = "production_authorized"
        with self.assertRaisesRegex(QualificationError, "effect"):
            CandidateEnrollmentProductionCustodyDossier.from_dict(effect)

    def test_dossier_contains_no_live_values_secrets_or_markers(self) -> None:
        serialized = json.dumps(self.dossier.to_dict(), sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key":',
            '"credential":',
            '"signature":',
            '"network_endpoint":',
            '"bucket_name":',
            '"service_identity":',
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
            "src/sunderkey/candidate_enrollment_production_custody_dossier.py",
            "scripts/build_candidate_enrollment_production_custody_dossier.py",
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
