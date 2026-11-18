"""Phase 148 provider evidence lifecycle policy contract coverage."""

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

from sunderkey.errors import QualificationError
from sunderkey.provider_evidence_custody_decision import (
    load_provider_evidence_custody_decision_record,
)
from sunderkey.provider_evidence_lifecycle import (
    ProviderEvidenceLifecyclePolicy,
    build_provider_evidence_lifecycle_policy,
)

ROOT = Path(__file__).resolve().parents[2]
DECISION_PATH = ROOT / "registry/provider-evidence-custody-decision-d013.json"
SCHEMA_PATH = ROOT / "registry/schemas/provider-evidence-lifecycle-policy-v1.schema.json"


class ProviderEvidenceLifecyclePhase148Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.decision = load_provider_evidence_custody_decision_record(DECISION_PATH)

    def _policy(self, **changes):
        values = {
            "policy_version": 1,
            "mission_id": "mission.synthetic-001",
            "mission_sha256": "sha256:" + "91" * 32,
            "scope_reference_sha256": "sha256:" + "92" * 32,
            "retention_seconds": 2_592_000,
            "legal_hold_authority_role": "independent.legal-hold",
            "deletion_deadline_seconds": 86_400,
            "encryption_profile_id": "encryption.synthetic-kms-v1",
            "encryption_profile_sha256": "sha256:" + "93" * 32,
            "access_policy_id": "access.synthetic-mission-v1",
            "access_policy_sha256": "sha256:" + "94" * 32,
            "maximum_access_seconds": 3_600,
            "residency_policy_id": "residency.synthetic-us-v1",
            "residency_policy_sha256": "sha256:" + "95" * 32,
            "allowed_region_ids": ["region.synthetic-a", "region.synthetic-b"],
            "minimum_replica_count": 2,
            "created_at": "2026-07-30T10:09:00Z",
        }
        values.update(changes)
        return build_provider_evidence_lifecycle_policy(self.decision, **values)

    def test_policy_binds_decision_mission_and_all_d013_controls(self) -> None:
        policy = self._policy()
        document = policy.to_dict()
        self.assertEqual(
            document["custody_decision"]["record_id"],
            self.decision.record_id,
        )
        self.assertEqual(document["mission"]["mission_id"], "mission.synthetic-001")
        self.assertEqual(document["classification"]["raw_classification"], "restricted_raw")
        self.assertEqual(document["deletion"]["method"], "cryptographic_erasure")
        self.assertTrue(document["content_safety"]["quarantine_required"])
        self.assertEqual(document["policy_status"], "prepared_not_activated")
        self.assertEqual(document["activation_effect"], "none")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(ProviderEvidenceLifecyclePolicy.from_dict(document), policy)

    def test_retention_access_deletion_and_replication_are_bounded(self) -> None:
        cases = (
            ({"retention_seconds": 3599}, "retention_seconds"),
            ({"maximum_access_seconds": 86_401}, "maximum_access_seconds"),
            ({"deletion_deadline_seconds": 3599}, "deletion_deadline_seconds"),
            ({"minimum_replica_count": 1}, "minimum_replica_count"),
            ({"allowed_region_ids": []}, "regions"),
            (
                {"allowed_region_ids": ["region.synthetic-a", "region.synthetic-a"]},
                "regions",
            ),
        )
        for changes, error in cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(QualificationError, error):
                    self._policy(**changes)

    def test_security_requirements_cannot_be_relaxed_by_tampering(self) -> None:
        tampered = copy.deepcopy(self._policy().to_dict())
        tampered["content_safety"]["direct_execution_prohibited"] = False
        with self.assertRaisesRegex(QualificationError, "content safety"):
            ProviderEvidenceLifecyclePolicy.from_dict(tampered)
        tampered = copy.deepcopy(self._policy().to_dict())
        tampered["classification"]["in_place_redaction_permitted"] = True
        with self.assertRaisesRegex(QualificationError, "classification"):
            ProviderEvidenceLifecyclePolicy.from_dict(tampered)
        tampered = copy.deepcopy(self._policy().to_dict())
        tampered["encryption"]["key_material_in_sunderkey_prohibited"] = False
        with self.assertRaisesRegex(QualificationError, "encryption"):
            ProviderEvidenceLifecyclePolicy.from_dict(tampered)

    def test_policy_contains_references_but_no_secrets_or_endpoints(self) -> None:
        serialized = json.dumps(self._policy().to_dict(), sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"credential":',
            '"private_key":',
            '"kms_key":',
            '"network_endpoint":',
            '"bucket_name":',
            '"evidence_bytes":',
        ):
            with self.subTest(field=field):
                self.assertNotIn(field, serialized)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_policy_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self._policy().to_dict())

    def test_contract_module_has_no_storage_network_or_execution_imports(self) -> None:
        source = (ROOT / "src/sunderkey/provider_evidence_lifecycle.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imports
            & {
                "asyncio",
                "boto3",
                "google",
                "httpx",
                "requests",
                "socket",
                "sqlite3",
                "subprocess",
                "urllib",
            }
        )


if __name__ == "__main__":
    unittest.main()
