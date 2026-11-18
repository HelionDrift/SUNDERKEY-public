"""Phase 187 provider-neutral D014 deployment dossier coverage."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey.production_deployment_decision_dossier as dossier_module
from scripts.build_production_deployment_decision_dossier import (
    build_dossier,
    build_parser,
)
from sunderkey.errors import QualificationError
from sunderkey.production_deployment_decision_dossier import (
    DECISION_QUESTIONS,
    DOSSIER_DOMAIN,
    EXPECTED_REPOSITORY_EVIDENCE,
    EXPECTED_SOURCE_IDENTITIES,
    NONNEGOTIABLE_REQUIREMENTS,
    RELATED_PENDING_OWNER_DECISIONS,
    REQUIRED_OWNER_INPUTS,
    ProductionDeploymentDecisionDossier,
    load_production_deployment_decision_dossier,
)
from sunderkey.qualification import _canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER_PATH = REGISTRY / "production-deployment-decision-dossier-d014.json"
SCHEMA_PATH = REGISTRY / "schemas" / "production-deployment-decision-dossier-v1.schema.json"
MODULE_PATH = ROOT / "src/sunderkey/production_deployment_decision_dossier.py"
BUILDER_PATH = ROOT / "scripts/build_production_deployment_decision_dossier.py"
DOC_PATH = ROOT / "docs/phase187-production-deployment-decision-dossier.md"

EXPECTED_QUESTION_IDS = (
    "deployment_model",
    "account_boundary",
    "region_topology",
    "data_residency",
    "workload_identity",
    "operator_authentication",
    "postgresql_topology",
    "object_and_evidence_storage",
    "kms_and_release_signing",
    "retention_legal_hold_and_deletion",
    "oci_workers",
    "microvm_workers",
    "browser_workers",
    "specialist_workers",
    "monitoring_and_observability",
    "incident_response",
    "capacity_and_cost",
    "backup_and_disaster_recovery",
    "custodians_and_reviewers",
)


class ProductionDeploymentDecisionDossierPhase187Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_production_deployment_decision_dossier(DOSSIER_PATH)
        cls.document = cls.dossier.to_dict()

    @staticmethod
    def _rehash(document: dict[str, object]) -> dict[str, object]:
        body = {
            key: value
            for key, value in document.items()
            if key not in {"dossier_id", "dossier_sha256"}
        }
        digest = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
        document["dossier_sha256"] = digest
        document["dossier_id"] = "PDD-" + digest.removeprefix("sha256:")[:32].upper()
        return document

    def _assert_runtime_and_schema_reject(self, document: dict[str, object]) -> None:
        rehashed = self._rehash(document)
        with self.assertRaises(QualificationError):
            ProductionDeploymentDecisionDossier.from_dict(rehashed)
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            self.assertTrue(list(Draft202012Validator(schema).iter_errors(rehashed)))

    def test_checked_dossier_rebuilds_exactly(self) -> None:
        rebuilt = build_dossier(build_parser().parse_args([]))
        self.assertEqual(self.document, rebuilt)
        self.assertEqual(
            DOSSIER_PATH.read_text(encoding="utf-8"),
            json.dumps(rebuilt, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            self.dossier.dossier_id,
            "PDD-BE3818A9FB5A0C3EB41502B3F0B50663",
        )
        self.assertEqual(
            self.dossier.dossier_sha256,
            "sha256:be3818a9fb5a0c3eb41502b3f0b50663162cf6412f57e3f7b43d7ae5a468e4e1",
        )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_checked_dossier_matches_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.document)

    def test_exact_current_decisions_and_repository_evidence_are_bound(self) -> None:
        self.assertEqual(self.document["source_bindings"], EXPECTED_SOURCE_IDENTITIES)
        self.assertEqual(
            self.document["repository_evidence"],
            [dict(item) for item in EXPECTED_REPOSITORY_EVIDENCE],
        )
        for binding in EXPECTED_REPOSITORY_EVIDENCE:
            source = ROOT / binding["repository_path"]
            digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
            with self.subTest(source=binding["repository_path"]):
                self.assertEqual(binding["file_sha256"], digest)
        self.assertEqual(
            self.document["source_bindings"]["production_custody_decision"]["record_id"],
            "PCR-A2ACC5733A815AA349F5F6B7F1FBE5A3",
        )
        self.assertEqual(
            self.document["source_bindings"]["provider_evidence_custody_decision"]["record_id"],
            "ECR-24E4D6CE3E9902A20ACCCE2E2C74B6F6",
        )

    def test_every_required_decision_area_has_three_unselected_options(self) -> None:
        questions = self.document["decision_questions"]
        self.assertEqual(
            tuple(question["question_id"] for question in questions),
            EXPECTED_QUESTION_IDS,
        )
        self.assertEqual(questions, [dict(item) for item in DECISION_QUESTIONS])
        for question in questions:
            with self.subTest(question=question["question_id"]):
                self.assertEqual(question["selection_status"], "not_selected")
                self.assertIsNone(question["selected_option_id"])
                self.assertEqual(question["recommendation_status"], "not_provided")
                self.assertIsNone(question["recommended_option_id"])
                self.assertEqual(question["option_order_effect"], "none")
                self.assertEqual(len(question["options"]), 3)
                self.assertEqual(
                    len({option["option_id"] for option in question["options"]}),
                    3,
                )
                self.assertEqual(
                    len({option["name"] for option in question["options"]}),
                    3,
                )
                self.assertEqual(
                    len({option["impact"] for option in question["options"]}),
                    3,
                )
        self.assertEqual(len(self.document["required_owner_inputs"]), 19)
        self.assertEqual(self.document["required_owner_inputs"], list(REQUIRED_OWNER_INPUTS))
        self.assertEqual(
            self.document["nonnegotiable_requirements"],
            list(NONNEGOTIABLE_REQUIREMENTS),
        )

    def test_related_phase186d_owner_decisions_authorize_implementation_only(self) -> None:
        decisions = self.document["related_pending_owner_decisions"]
        self.assertEqual(decisions, [dict(item) for item in RELATED_PENDING_OWNER_DECISIONS])
        self.assertEqual(
            {decision["decision_id"] for decision in decisions},
            {
                "PHASE186D-RUNTIME-ENTRYPOINT",
                "PHASE186D-INDEPENDENT-REVIEWER-ADMISSION",
            },
        )
        for decision in decisions:
            with self.subTest(decision=decision["decision_id"]):
                self.assertEqual(decision["status"], "approved_operator_asserted_unsigned")
                self.assertEqual(decision["selection_status"], "selected_for_implementation_only")
                self.assertIn(
                    decision["selected_option_id"],
                    {
                        "mandatory_phase186d_signed_custody_for_runtime",
                        "explicit_signed_mission_scoped_reserve_pool",
                    },
                )
                self.assertEqual(decision["authority_effect"], "none")

    def test_dossier_has_no_selection_authority_or_runtime_effect(self) -> None:
        self.assertEqual(self.document["status"], "decision_required")
        self.assertEqual(
            self.document["current_boundary"]["d012_production_custody_decision"],
            "approved_contract_partially_implemented_provider_unselected",
        )
        self.assertEqual(
            self.document["current_boundary"]["d013_evidence_custody_decision"],
            "approved_contract_partially_implemented_provider_unselected",
        )
        self.assertEqual(
            self.document["current_boundary"]["provider_account_region_identity_status"],
            "not_selected",
        )
        self.assertEqual(
            self.document["current_boundary"]["live_deployment_status"],
            "not_performed",
        )
        self.assertEqual(
            self.document["current_boundary"]["production_activation_status"],
            "blocked",
        )
        for field in (
            "decision_effect",
            "recommendation_effect",
            "authorization_effect",
            "runtime_effect",
            "qualification_effect",
            "registry_effect",
        ):
            with self.subTest(field=field):
                self.assertEqual(self.document[field], "none")
        self.assertFalse(self.document["network_call_performed"])
        serialized = json.dumps(self.document, sort_keys=True).lower()
        for provider_name in (
            "amazon web services",
            "google cloud",
            "microsoft azure",
            "oracle cloud",
        ):
            self.assertNotIn(provider_name, serialized)

    def test_tampering_sources_questions_and_effects_is_rejected(self) -> None:
        changes: tuple[tuple[str, object], ...] = (
            ("source_bindings", {}),
            ("repository_evidence", []),
            ("related_pending_owner_decisions", []),
            ("decision_questions", []),
            ("required_owner_inputs", []),
            ("authorization_effect", "approved"),
            ("network_call_performed", True),
        )
        for field, replacement in changes:
            changed = copy.deepcopy(self.document)
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaises(QualificationError):
                ProductionDeploymentDecisionDossier.from_dict(changed)
        selected = copy.deepcopy(self.document)
        selected["decision_questions"][0]["selection_status"] = "selected"
        selected["decision_questions"][0]["selected_option_id"] = selected["decision_questions"][0][
            "options"
        ][0]["option_id"]
        with self.assertRaisesRegex(QualificationError, "decision_questions"):
            ProductionDeploymentDecisionDossier.from_dict(selected)

    def test_rehashed_source_question_and_list_substitutions_fail_schema_and_runtime(
        self,
    ) -> None:
        changes = []
        source = copy.deepcopy(self.document)
        source["source_bindings"]["candidate_release_policy"]["sha256"] = "sha256:" + "0" * 64
        changes.append(source)
        evidence = copy.deepcopy(self.document)
        evidence["repository_evidence"][0]["file_sha256"] = "sha256:" + "0" * 64
        changes.append(evidence)
        prompt = copy.deepcopy(self.document)
        prompt["decision_questions"][0]["prompt"] = "A replacement prompt long enough."
        changes.append(prompt)
        option = copy.deepcopy(self.document)
        option["decision_questions"][0]["options"][0]["option_id"] = "unreviewed_option"
        changes.append(option)
        owner_input = copy.deepcopy(self.document)
        owner_input["required_owner_inputs"][0] = "unreviewed_owner_input"
        changes.append(owner_input)
        for changed in changes:
            with self.subTest(changed=changed):
                self._assert_runtime_and_schema_reject(changed)

    def test_public_contract_mutation_cannot_change_builder_or_loader_acceptance(
        self,
    ) -> None:
        original_question = copy.deepcopy(DECISION_QUESTIONS[0])
        original_source = copy.deepcopy(EXPECTED_SOURCE_IDENTITIES["candidate_release_policy"])
        original_evidence = copy.deepcopy(EXPECTED_REPOSITORY_EVIDENCE[0])
        original_related = copy.deepcopy(RELATED_PENDING_OWNER_DECISIONS[0])
        try:
            DECISION_QUESTIONS[0]["selection_status"] = "selected"
            DECISION_QUESTIONS[0]["selected_option_id"] = DECISION_QUESTIONS[0]["options"][0][
                "option_id"
            ]
            EXPECTED_SOURCE_IDENTITIES["candidate_release_policy"]["sha256"] = "sha256:" + "0" * 64
            EXPECTED_REPOSITORY_EVIDENCE[0]["file_sha256"] = "sha256:" + "0" * 64
            RELATED_PENDING_OWNER_DECISIONS[0]["selection_status"] = "selected"
            RELATED_PENDING_OWNER_DECISIONS[0]["selected_option_id"] = "unreviewed_selection"
            rebuilt = build_dossier(build_parser().parse_args([]))
            self.assertEqual(rebuilt, self.document)
            changed = copy.deepcopy(self.document)
            changed["decision_questions"][0] = copy.deepcopy(DECISION_QUESTIONS[0])
            self._assert_runtime_and_schema_reject(changed)
        finally:
            DECISION_QUESTIONS[0].clear()
            DECISION_QUESTIONS[0].update(original_question)
            EXPECTED_SOURCE_IDENTITIES["candidate_release_policy"].clear()
            EXPECTED_SOURCE_IDENTITIES["candidate_release_policy"].update(original_source)
            EXPECTED_REPOSITORY_EVIDENCE[0].clear()
            EXPECTED_REPOSITORY_EVIDENCE[0].update(original_evidence)
            RELATED_PENDING_OWNER_DECISIONS[0].clear()
            RELATED_PENDING_OWNER_DECISIONS[0].update(original_related)

    def test_mutated_frozen_wrapper_is_revalidated_at_use(self) -> None:
        mutated_identity = load_production_deployment_decision_dossier(DOSSIER_PATH)
        object.__setattr__(mutated_identity, "dossier_id", "PDD-" + "0" * 32)
        with self.assertRaisesRegex(QualificationError, "mutated"):
            mutated_identity.to_dict()
        mutated_document = load_production_deployment_decision_dossier(DOSSIER_PATH)
        changed = copy.deepcopy(self.document)
        changed["decision_questions"][0]["selection_status"] = "selected"
        object.__setattr__(
            mutated_document,
            "document_json",
            json.dumps(changed, sort_keys=True, separators=(",", ":")),
        )
        with self.assertRaises(QualificationError):
            mutated_document.to_dict()
        invalid_document = load_production_deployment_decision_dossier(DOSSIER_PATH)
        object.__setattr__(invalid_document, "document_json", "{")
        with self.assertRaises(QualificationError):
            invalid_document.to_dict()

    def test_rebound_question_snapshot_cannot_introduce_a_selection_default(
        self,
    ) -> None:
        original = dossier_module._DECISION_QUESTIONS_JSON
        changed = json.loads(original)
        changed[0]["selection_status"] = "selected"
        changed[0]["selected_option_id"] = changed[0]["options"][0]["option_id"]
        try:
            dossier_module._DECISION_QUESTIONS_JSON = json.dumps(changed)
            with self.assertRaisesRegex(QualificationError, "question contract"):
                build_dossier(build_parser().parse_args([]))
        finally:
            dossier_module._DECISION_QUESTIONS_JSON = original

    def test_hash_tampering_and_duplicate_json_keys_fail_closed(self) -> None:
        changed = copy.deepcopy(self.document)
        changed["dossier_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(QualificationError, "hash"):
            ProductionDeploymentDecisionDossier.from_dict(changed)
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            checked = DOSSIER_PATH.read_text(encoding="utf-8")
            duplicate.write_text(
                checked.replace(
                    '  "status": "decision_required"',
                    ('  "status": "decision_required",\n  "status": "decision_required"'),
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(QualificationError):
                load_production_deployment_decision_dossier(duplicate)

    def test_module_and_builder_have_no_external_effect_imports(self) -> None:
        prohibited = {
            "asyncio",
            "boto3",
            "docker",
            "http",
            "kubernetes",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        for path in (MODULE_PATH, BUILDER_PATH):
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
            with self.subTest(path=path.name):
                self.assertFalse(imported & prohibited)

    def test_documentation_preserves_the_owner_decision_boundary(self) -> None:
        document = DOC_PATH.read_text(encoding="utf-8")
        self.assertIn("D014", document)
        self.assertIn("decision_required", document)
        self.assertIn("No provider, account, region, or identity is selected", document)
        self.assertIn("Option order has no preference or authority effect", document)
        self.assertIn("Publication, review, or acknowledgement", document)
        self.assertIn("dual-control go or no-go decision", document)
        self.assertIn("PHASE186D-RUNTIME-ENTRYPOINT", document)
        self.assertIn("PHASE186D-INDEPENDENT-REVIEWER-ADMISSION", document)


if __name__ == "__main__":
    unittest.main()
