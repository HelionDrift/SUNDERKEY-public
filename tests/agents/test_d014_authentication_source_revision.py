"""Unsigned D014 source revision without historical or authority replacement."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.build_production_deployment_decision_dossier import build_dossier, build_parser
from sunderkey.errors import QualificationError
from sunderkey.production_deployment_decision_dossier import (
    DOSSIER_DOMAIN,
    ProductionDeploymentDecisionDossier,
    expected_repository_evidence,
    load_production_deployment_decision_dossier,
)
from sunderkey.qualification import _canonical_json, _canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
PACKET_PATH = ROOT / "registry/production-deployment-decision-dossier-d014.json"
PACKET_SCHEMA_PATH = ROOT / "registry/schemas/production-deployment-decision-dossier-v1.schema.json"
AUTH_SCHEMA_RELATIVE = "registry/schemas/target-authentication-adapter-contract-v2.schema.json"
AUTH_SCHEMA_PATH = ROOT / AUTH_SCHEMA_RELATIVE
OLD_AUTH_SCHEMA_SHA = "sha256:8fdf107e9509ee856ba5ccd6ea7c9ea163e41986f9f0f125e510a3c9b2d34d9e"
CURRENT_AUTH_SCHEMA_SHA = "sha256:4e6212c31f9d2e461bdb819170624614b9465610a97c60ca11cbdadbbf8064e9"
ORIGINAL_PACKET_ID = "PDD-2C0C8F1A2176ADCAB329A362D5ECA2CF"
ORIGINAL_PACKET_SHA = "sha256:2c0c8f1a2176adcab329a362d5eca2cf9fed4ff1f368e44cfa2724c4bb20635e"
CURRENT_PACKET_ID = "PDD-BE3818A9FB5A0C3EB41502B3F0B50663"
CURRENT_PACKET_SHA = "sha256:be3818a9fb5a0c3eb41502b3f0b50663162cf6412f57e3f7b43d7ae5a468e4e1"

SOURCE_IDENTITIES = {
    "production_custody_decision": {
        "record_id": "PCR-A2ACC5733A815AA349F5F6B7F1FBE5A3",
        "sha256": "sha256:a2acc5733a815aa349f5f6b7f1fbe5a30881446417a9268923e96dea3c1624de",
    },
    "provider_evidence_custody_decision": {
        "record_id": "ECR-24E4D6CE3E9902A20ACCCE2E2C74B6F6",
        "sha256": "sha256:24e4d6ce3e9902a20accce2e2c74b6f61f99e27aff96280ba56178c84e140b9c",
    },
    "deployment_manifest_bundle": {
        "bundle_id": "DMB-3D8C8D4CACA83A3520B7A23B20B43FCB",
        "sha256": "sha256:3d8c8d4caca83a3520b7a23b20b43fcb3006f4007d398ec7b9dd10839594401f",
    },
    "containment_conformance_catalog": {
        "catalog_id": "sunderkey-containment-conformance-suites-v1",
        "sha256": "sha256:857bc288348d5e6bcd15deb92caf2b1a9c48df0678562af835aa7ad8086382c2",
    },
    "candidate_release_policy": {
        "policy_id": "CRP-CB268855D98EC59A1C8D758550848EF5",
        "sha256": "sha256:cb268855d98ec59a1c8d758550848ef5b5e2f0170d2e9f69d855bc7247a6bdde",
    },
}
QUESTION_IDS = (
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


def readdress(document: dict[str, object]) -> dict[str, object]:
    body = {
        key: value for key, value in document.items() if key not in {"dossier_id", "dossier_sha256"}
    }
    digest = _canonical_sha256({"domain": DOSSIER_DOMAIN, "dossier": body})
    document["dossier_sha256"] = digest
    document["dossier_id"] = "PDD-" + digest.removeprefix("sha256:")[:32].upper()
    return document


class D014AuthenticationSourceRevisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.checked_document = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
        self.current_document = copy.deepcopy(self.checked_document)
        self.auth_evidence(self.current_document)["file_sha256"] = CURRENT_AUTH_SCHEMA_SHA
        readdress(self.current_document)
        self.original_document = copy.deepcopy(self.current_document)
        self.auth_evidence(self.original_document)["file_sha256"] = OLD_AUTH_SCHEMA_SHA
        readdress(self.original_document)

    def auth_evidence(self, document: dict[str, object]) -> dict[str, str]:
        matches = [
            item
            for item in document["repository_evidence"]
            if item["repository_path"] == AUTH_SCHEMA_RELATIVE
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["evidence_area"], "target_authentication")
        self.assertEqual(matches[0]["evidence_kind"], "schema_contract")
        return matches[0]

    def schema_validator(self) -> Draft202012Validator:
        schema = json.loads(PACKET_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema)

    def test_actual_schema_bytes_and_current_contract_pin_are_exact(self) -> None:
        actual = "sha256:" + hashlib.sha256(AUTH_SCHEMA_PATH.read_bytes()).hexdigest()
        self.assertEqual(actual, CURRENT_AUTH_SCHEMA_SHA)
        bindings = [
            item
            for item in expected_repository_evidence()
            if item["repository_path"] == AUTH_SCHEMA_RELATIVE
        ]
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0]["file_sha256"], actual)

    def test_pure_current_revision_has_the_new_literal_identity(self) -> None:
        self.assertEqual(self.current_document["dossier_id"], CURRENT_PACKET_ID)
        self.assertEqual(self.current_document["dossier_sha256"], CURRENT_PACKET_SHA)
        self.assertEqual(
            self.auth_evidence(self.current_document)["file_sha256"], CURRENT_AUTH_SCHEMA_SHA
        )

    def test_checked_packet_has_exact_current_identity_and_source_binding(self) -> None:
        self.assertEqual(self.checked_document["dossier_id"], CURRENT_PACKET_ID)
        self.assertEqual(self.checked_document["dossier_sha256"], CURRENT_PACKET_SHA)
        self.assertEqual(
            self.auth_evidence(self.checked_document)["file_sha256"], CURRENT_AUTH_SCHEMA_SHA
        )
        self.assertEqual(
            _canonical_json(self.checked_document), _canonical_json(self.current_document)
        )
        loaded = load_production_deployment_decision_dossier(PACKET_PATH)
        self.assertEqual(_canonical_json(loaded.to_dict()), _canonical_json(self.current_document))

    def test_builder_accepts_real_repository_sources_and_matches_current_packet(self) -> None:
        try:
            rebuilt = build_dossier(build_parser().parse_args([]))
        except QualificationError as exc:
            self.fail(f"current raw schema source is rejected by the stale D014 contract: {exc}")
        self.assertEqual(rebuilt["dossier_id"], CURRENT_PACKET_ID)
        self.assertEqual(rebuilt["dossier_sha256"], CURRENT_PACKET_SHA)
        self.assertEqual(_canonical_json(rebuilt), _canonical_json(self.current_document))
        self.assertEqual(_canonical_json(rebuilt), _canonical_json(self.checked_document))

    def test_current_contract_parser_accepts_the_coherent_new_source_profile(self) -> None:
        try:
            packet = ProductionDeploymentDecisionDossier.from_dict(self.current_document)
        except QualificationError as exc:
            self.fail(f"coherent new unsigned source revision is rejected: {exc}")
        self.assertEqual(packet.dossier_id, CURRENT_PACKET_ID)
        self.assertEqual(packet.dossier_sha256, CURRENT_PACKET_SHA)
        self.assertEqual(_canonical_json(packet.to_dict()), _canonical_json(self.current_document))

    def test_current_contract_parser_rejects_the_original_source_profile(self) -> None:
        with self.assertRaisesRegex(QualificationError, "Repository evidence"):
            ProductionDeploymentDecisionDossier.from_dict(self.original_document)

    def test_current_packet_schema_accepts_only_the_new_source_revision(self) -> None:
        self.assertEqual(list(self.schema_validator().iter_errors(self.current_document)), [])

    def test_current_packet_schema_rejects_the_original_source_profile(self) -> None:
        self.assertTrue(list(self.schema_validator().iter_errors(self.original_document)))

    def test_prior_complete_packet_reconstruction_restores_original_literal_golden(self) -> None:
        """Historical byte meaning is retained, not current parser acceptance."""

        self.assertEqual(self.original_document["dossier_id"], ORIGINAL_PACKET_ID)
        self.assertEqual(self.original_document["dossier_sha256"], ORIGINAL_PACKET_SHA)
        self.assertEqual(
            self.auth_evidence(self.original_document)["file_sha256"], OLD_AUTH_SCHEMA_SHA
        )
        self.assertNotEqual(ORIGINAL_PACKET_ID, CURRENT_PACKET_ID)
        original_body = copy.deepcopy(self.original_document)
        current_body = copy.deepcopy(self.current_document)
        for body in (original_body, current_body):
            body.pop("dossier_id")
            body.pop("dossier_sha256")
        self.auth_evidence(original_body)["file_sha256"] = CURRENT_AUTH_SCHEMA_SHA
        self.assertEqual(_canonical_json(original_body), _canonical_json(current_body))

    def test_all_five_existing_source_identities_are_unchanged(self) -> None:
        self.assertEqual(len(SOURCE_IDENTITIES), 5)
        self.assertEqual(self.current_document["source_bindings"], SOURCE_IDENTITIES)
        self.assertEqual(self.original_document["source_bindings"], SOURCE_IDENTITIES)

    def test_all_nineteen_owner_questions_and_inputs_remain_unselected(self) -> None:
        questions = self.current_document["decision_questions"]
        self.assertEqual(tuple(item["question_id"] for item in questions), QUESTION_IDS)
        self.assertEqual(len(questions), 19)
        for question in questions:
            with self.subTest(question=question["question_id"]):
                self.assertEqual(question["selection_status"], "not_selected")
                self.assertIsNone(question["selected_option_id"])
                self.assertEqual(question["recommendation_status"], "not_provided")
                self.assertIsNone(question["recommended_option_id"])
                self.assertEqual(question["option_order_effect"], "none")
                self.assertEqual(len(question["options"]), 3)
        self.assertEqual(len(self.current_document["required_owner_inputs"]), 19)
        self.assertEqual(
            self.current_document["required_owner_inputs"],
            self.original_document["required_owner_inputs"],
        )
        self.assertEqual(questions, self.original_document["decision_questions"])

    def test_both_related_unsigned_implementation_selections_are_unchanged(self) -> None:
        decisions = self.current_document["related_pending_owner_decisions"]
        selected = {
            "PHASE186D-RUNTIME-ENTRYPOINT": "mandatory_phase186d_signed_custody_for_runtime",
            "PHASE186D-INDEPENDENT-REVIEWER-ADMISSION": (
                "explicit_signed_mission_scoped_reserve_pool"
            ),
        }
        self.assertEqual(len(decisions), 2)
        self.assertEqual({item["decision_id"] for item in decisions}, set(selected))
        for item in decisions:
            with self.subTest(decision=item["decision_id"]):
                self.assertEqual(item["status"], "approved_operator_asserted_unsigned")
                self.assertEqual(item["selection_status"], "selected_for_implementation_only")
                self.assertEqual(item["selected_option_id"], selected[item["decision_id"]])
                self.assertEqual(item["authority_effect"], "none")
        self.assertEqual(decisions, self.original_document["related_pending_owner_decisions"])

    def test_unsigned_revision_does_not_select_or_activate_infrastructure(self) -> None:
        document = self.current_document
        self.assertEqual(document["status"], "decision_required")
        self.assertEqual(document["decision_id"], "D014")
        self.assertIs(document["network_call_performed"], False)
        for field in (
            "decision_effect",
            "recommendation_effect",
            "authorization_effect",
            "runtime_effect",
            "qualification_effect",
            "registry_effect",
        ):
            with self.subTest(effect=field):
                self.assertEqual(document[field], "none")
        boundary = document["current_boundary"]
        self.assertEqual(boundary["provider_account_region_identity_status"], "not_selected")
        self.assertEqual(boundary["live_deployment_status"], "not_performed")
        self.assertEqual(boundary["production_activation_status"], "blocked")
        self.assertEqual(boundary, self.original_document["current_boundary"])


if __name__ == "__main__":
    unittest.main()
