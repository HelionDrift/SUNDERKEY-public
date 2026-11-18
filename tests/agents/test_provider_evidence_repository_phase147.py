"""Phase 147 provider-neutral evidence repository contract coverage."""

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

from sunderkey.errors import CollaborationPlanError
from sunderkey.provider_evidence_custody_decision import (
    load_provider_evidence_custody_decision_record,
)
from sunderkey.provider_evidence_repository import (
    REPOSITORY_POLICY,
    ProviderEvidenceRepositoryIngestReceipt,
    ProviderEvidenceRepositoryIngestRequest,
    build_provider_evidence_repository_ingest_receipt,
    build_provider_evidence_repository_ingest_request,
    validate_provider_evidence_repository_ingest_bytes,
    validate_provider_evidence_repository_ingest_receipt,
)

from . import test_collaboration_executor_provider_evidence_service_phase144 as phase144

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
DECISION_PATH = ROOT / "registry/provider-evidence-custody-decision-d013.json"
HASHES = {
    "retention_policy_sha256": "sha256:" + "81" * 32,
    "residency_policy_sha256": "sha256:" + "82" * 32,
    "encryption_profile_sha256": "sha256:" + "83" * 32,
    "access_policy_sha256": "sha256:" + "84" * 32,
}


class ProviderEvidenceRepositoryPhase147Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase144.CollaborationExecutorProviderEvidenceServicePhase144Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.verification = fixture._verify()
        self.decision = load_provider_evidence_custody_decision_record(DECISION_PATH)

    def _request(self, *, expires_at: str = "2026-07-30T10:12:00Z"):
        return build_provider_evidence_repository_ingest_request(
            self.decision,
            self.verification,
            retention_policy_id="retention.synthetic-short-v1",
            retention_policy_sha256=HASHES["retention_policy_sha256"],
            residency_policy_id="residency.synthetic-local-v1",
            residency_policy_sha256=HASHES["residency_policy_sha256"],
            encryption_profile_id="encryption.synthetic-kms-v1",
            encryption_profile_sha256=HASHES["encryption_profile_sha256"],
            access_policy_id="access.synthetic-mission-v1",
            access_policy_sha256=HASHES["access_policy_sha256"],
            requested_at="2026-07-30T10:08:40Z",
            expires_at=expires_at,
        )

    def _receipt(self, request, *, outcome: str = "accepted"):
        return build_provider_evidence_repository_ingest_receipt(
            request,
            adapter_id="repository.contract-test",
            adapter_version="1.0.0",
            adapter_build_sha256="sha256:" + "85" * 32,
            repository_id="repository.synthetic-001",
            object_version_id="version.synthetic-001",
            outcome=outcome,
            responded_at="2026-07-30T10:08:45Z",
        )

    def test_request_binds_approval_verification_policy_and_lifecycle(self) -> None:
        request = self._request()
        document = request.to_dict()
        self.assertEqual(
            document["custody_decision"]["record_id"],
            self.decision.record_id,
        )
        self.assertEqual(
            document["evidence_verification"]["verification_id"],
            self.verification.verification_id,
        )
        self.assertEqual(document["repository_policy"], REPOSITORY_POLICY)
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(
            ProviderEvidenceRepositoryIngestRequest.from_dict(document),
            request,
        )

    def test_out_of_band_bytes_must_match_size_and_digest(self) -> None:
        request = self._request()
        validate_provider_evidence_repository_ingest_bytes(request, phase144.EVIDENCE)
        with self.assertRaisesRegex(CollaborationPlanError, "size"):
            validate_provider_evidence_repository_ingest_bytes(request, b"short")
        changed = bytearray(phase144.EVIDENCE)
        changed[-2] = ord("X")
        with self.assertRaisesRegex(CollaborationPlanError, "bytes"):
            validate_provider_evidence_repository_ingest_bytes(
                request,
                bytes(changed),
            )

    def test_request_rejects_excessive_window_and_tampering(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "time window"):
            self._request(expires_at="2026-07-30T10:20:00Z")
        changed = copy.deepcopy(self._request().to_dict())
        changed["content_address"] = "sha256:" + "00" * 32
        with self.assertRaisesRegex(CollaborationPlanError, "content address"):
            ProviderEvidenceRepositoryIngestRequest.from_dict(changed)

    def test_accepted_receipt_is_bound_but_explicitly_untrusted(self) -> None:
        request = self._request()
        receipt = self._receipt(request)
        document = receipt.to_dict()
        self.assertEqual(
            validate_provider_evidence_repository_ingest_receipt(request, receipt),
            receipt,
        )
        self.assertEqual(
            document["authentication_status"],
            "repository_provider_assertion_unverified",
        )
        self.assertEqual(document["custody_status"], "provider_report_only")
        self.assertFalse(document["raw_evidence_in_contract"])
        self.assertTrue(
            all(
                status == "provider_asserted_satisfied"
                for status in document["provider_assertions"].values()
            )
        )

    def test_rejected_receipt_claims_no_repository_controls(self) -> None:
        receipt = self._receipt(self._request(), outcome="rejected")
        self.assertTrue(
            all(
                status == "not_claimed"
                for status in receipt.to_dict()["provider_assertions"].values()
            )
        )
        self.assertEqual(
            ProviderEvidenceRepositoryIngestReceipt.from_dict(receipt.to_dict()),
            receipt,
        )

    def test_contracts_serialize_no_raw_evidence(self) -> None:
        request = self._request()
        receipt = self._receipt(request)
        serialized = json.dumps(
            {"request": request.to_dict(), "receipt": receipt.to_dict()},
            sort_keys=True,
        )
        self.assertNotIn(phase144.EVIDENCE.decode("ascii"), serialized)
        self.assertNotIn("\u2014", serialized)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_contracts_match_published_schemas(self) -> None:
        request_schema = json.loads(
            (SCHEMAS / "provider-evidence-repository-ingest-request-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        request_schema["properties"]["evidence_verification"] = json.loads(
            (
                SCHEMAS / "collaboration-executor-provider-evidence-verification-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        receipt_schema = json.loads(
            (SCHEMAS / "provider-evidence-repository-ingest-receipt-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(request_schema)
        Draft202012Validator(request_schema).validate(self._request().to_dict())
        Draft202012Validator.check_schema(receipt_schema)
        Draft202012Validator(receipt_schema).validate(self._receipt(self._request()).to_dict())

    def test_contract_module_has_no_provider_or_storage_implementation(self) -> None:
        source = (ROOT / "src/sunderkey/provider_evidence_repository.py").read_text(
            encoding="utf-8"
        )
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
