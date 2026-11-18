"""Phase 39 collaboration authority decision dossier coverage."""

from __future__ import annotations

import argparse
import ast
import copy
import tempfile
import unittest
from pathlib import Path

from scripts.build_collaboration_authority_dossier import build_report
from sunderkey import collaboration_authority_dossier as authority
from sunderkey.collaboration_authority_dossier import (
    CollaborationAuthorityDecisionDossier,
    assess_collaboration_authority_decisions,
    load_collaboration_authority_decision_dossier,
)
from sunderkey.errors import CollaborationPlanError
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog, load_routing_policy

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER = REGISTRY / "collaboration-authority-dossier-d001-d005.json"


class CollaborationAuthorityDossierPhase39Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY / "army-v1.json")
        cls.capabilities = load_capability_catalog(
            REGISTRY / "capabilities-army-v1.json",
            cls.registry,
        )
        cls.policy = load_routing_policy(
            REGISTRY / "routing-policy-army-qualified-v1.json",
            cls.capabilities,
        )

    def assess(self) -> CollaborationAuthorityDecisionDossier:
        return assess_collaboration_authority_decisions(
            self.registry,
            self.capabilities,
            self.policy,
        )

    def test_checked_dossier_matches_deterministic_assessment(self) -> None:
        report = self.assess()
        checked = load_collaboration_authority_decision_dossier(DOSSIER)
        self.assertEqual(report.to_dict(), checked.to_dict())
        self.assertEqual(report.report_id, checked.report_id)
        self.assertEqual(report.report_sha256, checked.report_sha256)

        document = report.to_dict()
        self.assertEqual(
            document["decision_ids"],
            ["D001", "D002", "D003", "D004", "D005"],
        )
        self.assertEqual(document["status"], "decision_required")
        self.assertEqual(document["decision_effect"], "none")
        self.assertEqual(len(document["alternatives"]), 4)
        self.assertEqual(len(document["decision_questions"]), 5)

    def test_scope_captures_current_collaboration_boundary(self) -> None:
        scope = self.assess().to_dict()["current_scope"]
        self.assertEqual(scope["specialist_count"], 348)
        self.assertEqual(scope["qualified_specialist_count"], 20)
        self.assertEqual(scope["domain_command_count"], 23)
        self.assertEqual(scope["domain_commander_count"], 23)
        self.assertEqual(scope["shared_profile_count"], 32)
        self.assertEqual(scope["sqlite_schema_version"], 15)
        self.assertEqual(scope["transferable_work_item_kinds"], ["specialist_analysis"])
        self.assertEqual(scope["maximum_handoffs_per_work_item"], 1)
        self.assertFalse(scope["cross_command_handoff"])
        self.assertFalse(scope["activated_plan_replacement"])
        self.assertFalse(scope["distributed_execution_acknowledgement"])

    def test_recommendation_is_complete_but_not_authorized(self) -> None:
        document = self.assess().to_dict()
        recommended = [item for item in document["alternatives"] if item["recommended"]]
        self.assertEqual(len(recommended), 1)
        self.assertEqual(
            recommended[0]["alternative_id"],
            "reviewed_reconfiguration_ledger",
        )
        recommendation = document["recommendation"]
        self.assertEqual(recommendation["selection_state"], "not_selected")
        self.assertEqual(
            set(recommendation["recommended_option_bundle"]),
            set(document["decision_ids"]),
        )
        requirements = document["nonnegotiable_requirements"]
        self.assertFalse(requirements["private_key_storage_in_sunderkey"])
        self.assertFalse(requirements["execution_credentials_in_reconfiguration"])
        self.assertFalse(requirements["direct_runtime_control"])

    def test_dossier_rejects_tampering_and_self_consistent_contract_change(self) -> None:
        document = self.assess().to_dict()
        document["current_scope"]["maximum_handoffs_per_work_item"] = 2
        with self.assertRaises(CollaborationPlanError):
            CollaborationAuthorityDecisionDossier.from_dict(document)

        changed = self.assess().to_dict()
        changed["alternatives"][0]["recommended"] = False
        body = {
            key: value
            for key, value in changed.items()
            if key not in {"report_id", "report_sha256"}
        }
        digest = authority._report_hash(body)
        changed["report_sha256"] = digest
        changed["report_id"] = authority._report_id(digest)
        with self.assertRaisesRegex(CollaborationPlanError, "alternatives"):
            CollaborationAuthorityDecisionDossier.from_dict(changed)

    def test_assessment_rejects_wrong_input_types(self) -> None:
        arguments = [self.registry, self.capabilities, self.policy]
        labels = ("registry", "capability_catalog", "routing_policy")
        for index, label in enumerate(labels):
            with self.subTest(label=label):
                changed = list(arguments)
                changed[index] = object()
                with self.assertRaisesRegex(CollaborationPlanError, label):
                    assess_collaboration_authority_decisions(*changed)

    def test_assessment_does_not_mutate_inputs(self) -> None:
        before = (
            copy.deepcopy(self.registry.to_dict()),
            copy.deepcopy(self.capabilities.to_dict()),
            copy.deepcopy(self.policy.to_dict()),
        )
        self.assess()
        after = (
            self.registry.to_dict(),
            self.capabilities.to_dict(),
            self.policy.to_dict(),
        )
        self.assertEqual(after, before)

    def test_builder_and_loader_fail_closed(self) -> None:
        report = build_report(
            argparse.Namespace(
                registry=str(REGISTRY / "army-v1.json"),
                capabilities=str(REGISTRY / "capabilities-army-v1.json"),
                policy=str(REGISTRY / "routing-policy-army-qualified-v1.json"),
            )
        )
        self.assertEqual(report, self.assess().to_dict())

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_authority_decision_dossier(path)

    def test_modules_have_no_network_storage_or_execution_dependencies(self) -> None:
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
            ROOT / "src" / "sunderkey" / "collaboration_authority_dossier.py",
            ROOT / "scripts" / "build_collaboration_authority_dossier.py",
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
