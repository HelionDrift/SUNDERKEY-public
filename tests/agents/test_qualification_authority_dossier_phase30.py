"""Phase 30 qualification authority decision dossier."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.build_qualification_authority_dossier import (
    build_parser,
    build_report,
)
from sunderkey.errors import QualificationError
from sunderkey.implementation_roadmap import (
    load_specialist_implementation_roadmap,
)
from sunderkey.implementation_work_packages import (
    load_implementation_work_package_report,
)
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_authority_dossier import (
    QualificationAuthorityDecisionDossier,
    assess_qualification_authority_decision,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
CAPABILITY_PATH = ROOT / "registry" / "capabilities-army-v1.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v1.json"
ROADMAP_PATH = ROOT / "registry" / "implementation-roadmap-army-v1.json"
PACKAGES_PATH = (
    ROOT / "registry" / "implementation-work-packages-army-v1.json"
)
DOSSIER_PATH = (
    ROOT / "registry" / "qualification-authority-dossier-d008.json"
)


class QualificationAuthorityDossierPhase30Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.capabilities = load_capability_catalog(
            CAPABILITY_PATH,
            cls.registry,
        )
        cls.standard = load_qualification_standard(
            STANDARD_PATH,
            cls.registry,
            cls.capabilities,
        )
        cls.roadmap = load_specialist_implementation_roadmap(ROADMAP_PATH)
        cls.packages = load_implementation_work_package_report(PACKAGES_PATH)

    def assess(
        self,
        standard: object | None = None,
    ) -> QualificationAuthorityDecisionDossier:
        return assess_qualification_authority_decision(
            self.registry,
            self.capabilities,
            standard or self.standard,
            self.roadmap,
            self.packages,
        )

    def test_report_is_deterministic_and_self_identifying(self) -> None:
        first = self.assess()
        second = self.assess()
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            QualificationAuthorityDecisionDossier.from_dict(document),
            first,
        )
        self.assertEqual(
            document["report_id"],
            "QAD-74E8D333572C76381196576EEAFEED5C",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:74e8d333572c76381196576eeafeed5c"
            "7d0e01935667e54b42d5f2b6fc212bfb",
        )

    def test_checked_in_dossier_matches_deterministic_builder(self) -> None:
        expected = build_report(build_parser().parse_args([]))
        self.assertEqual(
            DOSSIER_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_dossier_exposes_current_blocked_scope(self) -> None:
        document = self.assess().to_dict()
        self.assertEqual(document["status"], "decision_required")
        self.assertEqual(document["decision_effect"], "none")
        self.assertEqual(document["decision_id"], "D008")
        self.assertEqual(
            document["current_scope"],
            {
                "specialist_count": 348,
                "implementation_gap_count": 348,
                "work_item_count": 3132,
                "authoritative_qualification_work_item_count": 348,
                "decision_blocked_work_item_count": 348,
            },
        )

    def test_nonnegotiable_requirements_match_standard(self) -> None:
        requirements = self.assess().to_dict()[
            "nonnegotiable_requirements"
        ]
        policy = self.standard.decision_policy
        self.assertEqual(
            requirements["minimum_distinct_evaluators"],
            policy.minimum_distinct_evaluators,
        )
        self.assertEqual(
            requirements["independent_control_review_required"],
            policy.require_independent_control_review,
        )
        self.assertEqual(
            requirements["independent_assurance_review_required"],
            policy.require_independent_assurance_review,
        )
        self.assertEqual(
            requirements["self_attestation_allowed"],
            policy.allow_self_attestation,
        )
        self.assertEqual(
            requirements["qualification_validity_days"],
            180,
        )
        self.assertEqual(len(requirements["authority_operations"]), 4)
        self.assertEqual(len(requirements["exact_binding_requirements"]), 11)

    def test_alternatives_are_explicit_and_unselected(self) -> None:
        document = self.assess().to_dict()
        alternatives = document["alternatives"]
        self.assertEqual(len(alternatives), 3)
        recommended = [
            item for item in alternatives if item["recommended"]
        ]
        self.assertEqual(len(recommended), 1)
        self.assertEqual(
            recommended[0]["alternative_id"],
            "repository_revision_signed_manifest",
        )
        self.assertEqual(
            document["recommendation"],
            {
                "alternative_id": "repository_revision_signed_manifest",
                "rationale": [
                    "preserves_versioned_registry_as_routing_source",
                    "keeps_qualification_state_out_of_mutable_runtime_store",
                    "supports_offline_verification_and_review",
                    "provides_immutable_candidate_and_evidence_binding",
                    "matches_existing_externally_issued_credential_boundary",
                ],
                "selection_state": "not_selected",
            },
        )

    def test_every_question_has_a_recommended_listed_option(self) -> None:
        questions = self.assess().to_dict()["decision_questions"]
        self.assertEqual(len(questions), 7)
        for question in questions:
            with self.subTest(question=question["question_id"]):
                self.assertIn(
                    question["recommended_option_id"],
                    question["option_ids"],
                )

    def test_stale_standard_binding_fails_closed(self) -> None:
        changed = replace(self.standard, standard_version="9.9.9")
        with self.assertRaisesRegex(
            QualificationError,
            "qualification standard binding is stale",
        ):
            self.assess(changed)

    def test_report_tampering_fails_closed(self) -> None:
        document = self.assess().to_dict()
        document["recommendation"]["selection_state"] = "selected"
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            QualificationAuthorityDecisionDossier.from_dict(document)

    def test_assessment_does_not_mutate_inputs(self) -> None:
        before = (
            copy.deepcopy(self.registry.to_dict()),
            copy.deepcopy(self.capabilities.to_dict()),
            copy.deepcopy(self.standard.to_dict()),
            copy.deepcopy(self.roadmap.to_dict()),
            copy.deepcopy(self.packages.to_dict()),
        )
        self.assess()
        after = (
            self.registry.to_dict(),
            self.capabilities.to_dict(),
            self.standard.to_dict(),
            self.roadmap.to_dict(),
            self.packages.to_dict(),
        )
        self.assertEqual(after, before)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        for path in (
            ROOT
            / "src"
            / "sunderkey"
            / "qualification_authority_dossier.py",
            ROOT / "scripts" / "build_qualification_authority_dossier.py",
        ):
            with self.subTest(path=path.name):
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
