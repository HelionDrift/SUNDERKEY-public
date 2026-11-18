"""Phase 38 candidate enrollment decision dossier coverage."""

from __future__ import annotations

import argparse
import ast
import copy
import tempfile
import unittest
from pathlib import Path

from scripts.build_candidate_enrollment_dossier import build_report
from sunderkey import candidate_enrollment_dossier as enrollment
from sunderkey.candidate_enrollment_dossier import (
    CandidateEnrollmentDecisionDossier,
    assess_candidate_enrollment_decision,
    load_candidate_enrollment_decision_dossier,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_authority_decision import (
    load_qualification_authority_decision_record,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER = REGISTRY / "candidate-enrollment-dossier-d009.json"


class CandidateEnrollmentDossierPhase38Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY / "army-v1.json")
        cls.capabilities = load_capability_catalog(
            REGISTRY / "capabilities-army-v1.json",
            cls.registry,
        )
        cls.standard = load_qualification_standard(
            REGISTRY / "qualification-standard-v1.json",
            cls.registry,
            cls.capabilities,
        )
        cls.authority_decision = (
            load_qualification_authority_decision_record(
                REGISTRY / "qualification-authority-decision-d008.json"
            )
        )

    def assess(self) -> CandidateEnrollmentDecisionDossier:
        return assess_candidate_enrollment_decision(
            self.registry,
            self.capabilities,
            self.standard,
            self.authority_decision,
        )

    def test_checked_dossier_matches_deterministic_assessment(self) -> None:
        report = self.assess()
        checked = load_candidate_enrollment_decision_dossier(DOSSIER)
        self.assertEqual(report.to_dict(), checked.to_dict())
        self.assertEqual(report.report_id, checked.report_id)
        self.assertEqual(report.report_sha256, checked.report_sha256)

        document = report.to_dict()
        self.assertEqual(document["decision_id"], "D009")
        self.assertEqual(document["status"], "decision_required")
        self.assertEqual(document["decision_effect"], "none")
        self.assertEqual(len(document["alternatives"]), 4)
        self.assertEqual(len(document["decision_questions"]), 9)
        self.assertEqual(
            document["recommendation"]["alternative_id"],
            "organization_signed_enrollment_catalog",
        )
        self.assertEqual(
            document["recommendation"]["selection_state"],
            "not_selected",
        )

    def test_scope_exposes_current_live_enrollment_block(self) -> None:
        scope = self.assess().to_dict()["current_scope"]
        self.assertEqual(scope["specialist_count"], 348)
        self.assertEqual(scope["status_counts"]["defined"], 328)
        self.assertEqual(scope["status_counts"]["qualified"], 20)
        self.assertEqual(
            sum(scope["status_counts"].values()),
            scope["specialist_count"],
        )
        self.assertEqual(scope["profiles_with_qualification_chain_head"], 0)
        self.assertEqual(scope["checked_live_enrollment_artifact_count"], 0)
        self.assertEqual(
            scope["live_evidence_acceptance"],
            "blocked_by_d009",
        )

    def test_recommendation_is_explicit_but_not_authorized(self) -> None:
        document = self.assess().to_dict()
        recommended = [
            item
            for item in document["alternatives"]
            if item["recommended"]
        ]
        self.assertEqual(len(recommended), 1)
        self.assertEqual(
            recommended[0]["alternative_id"],
            document["recommendation"]["alternative_id"],
        )
        self.assertIn(
            "Live evidence acceptance and live qualification remain blocked",
            document["limitations"][-1],
        )
        requirements = document["nonnegotiable_requirements"]
        self.assertFalse(requirements["private_key_storage_in_sunderkey"])
        self.assertFalse(requirements["repository_credentials_in_enrollment"])
        self.assertTrue(requirements["offline_verification_required"])

    def test_dossier_rejects_tampering_and_self_consistent_contract_change(
        self,
    ) -> None:
        document = self.assess().to_dict()
        document["current_scope"]["specialist_count"] = 349
        with self.assertRaises(QualificationError):
            CandidateEnrollmentDecisionDossier.from_dict(document)

        changed = self.assess().to_dict()
        changed["alternatives"][0]["recommended"] = False
        body = {
            key: value
            for key, value in changed.items()
            if key not in {"report_id", "report_sha256"}
        }
        digest = enrollment._report_hash(body)
        changed["report_sha256"] = digest
        changed["report_id"] = enrollment._report_id(digest)
        with self.assertRaisesRegex(QualificationError, "alternatives"):
            CandidateEnrollmentDecisionDossier.from_dict(changed)

    def test_assessment_rejects_wrong_input_types(self) -> None:
        arguments = [
            self.registry,
            self.capabilities,
            self.standard,
            self.authority_decision,
        ]
        labels = (
            "registry",
            "capability_catalog",
            "standard",
            "authority_decision",
        )
        for index, label in enumerate(labels):
            with self.subTest(label=label):
                changed = list(arguments)
                changed[index] = object()
                with self.assertRaisesRegex(QualificationError, label):
                    assess_candidate_enrollment_decision(*changed)

    def test_assessment_does_not_mutate_inputs(self) -> None:
        before = (
            copy.deepcopy(self.registry.to_dict()),
            copy.deepcopy(self.capabilities.to_dict()),
            copy.deepcopy(self.standard.to_dict()),
            copy.deepcopy(self.authority_decision.to_dict()),
        )
        self.assess()
        after = (
            self.registry.to_dict(),
            self.capabilities.to_dict(),
            self.standard.to_dict(),
            self.authority_decision.to_dict(),
        )
        self.assertEqual(after, before)

    def test_builder_and_loader_fail_closed(self) -> None:
        report = build_report(
            argparse.Namespace(
                registry=str(REGISTRY / "army-v1.json"),
                capabilities=str(REGISTRY / "capabilities-army-v1.json"),
                standard=str(REGISTRY / "qualification-standard-v1.json"),
                authority_decision=str(
                    REGISTRY / "qualification-authority-decision-d008.json"
                ),
            )
        )
        self.assertEqual(report, self.assess().to_dict())

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(QualificationError, "Could not load"):
                load_candidate_enrollment_decision_dossier(path)

    def test_modules_have_no_network_storage_or_execution_dependencies(
        self,
    ) -> None:
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        for path in (
            ROOT / "src" / "sunderkey" / "candidate_enrollment_dossier.py",
            ROOT / "scripts" / "build_candidate_enrollment_dossier.py",
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
