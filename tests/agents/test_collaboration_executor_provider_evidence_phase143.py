"""Phase 143 provider-evidence digest verification contract coverage."""

from __future__ import annotations

import ast
import hashlib
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor import (
    build_collaboration_executor_acknowledgement,
)
from sunderkey.collaboration_executor_provider_evidence import (
    VerifiedCollaborationExecutorProviderEvidenceDigest,
    validate_collaboration_executor_provider_evidence_digest_document,
    verify_collaboration_executor_provider_evidence_digest,
)
from sunderkey.collaboration_executor_provider_report import (
    build_collaboration_executor_provider_report,
)
from sunderkey.collaboration_executor_provider_report_authentication import (
    bind_authenticated_collaboration_executor_provider_report,
)
from sunderkey.errors import CollaborationPlanError

from . import (
    test_collaboration_executor_provider_report_authentication_phase140 as phase140,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
EVIDENCE = b'{"provider_receipt":"receipt-1","status":"accepted"}'
EVIDENCE_SHA256 = "sha256:" + hashlib.sha256(EVIDENCE).hexdigest()
VERIFIED_AT = "2026-07-30T10:08:36Z"


class CollaborationExecutorProviderEvidencePhase143Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = (
            phase140.CollaborationExecutorProviderReportAuthenticationPhase140Tests(
                methodName="runTest"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        original = fixture.report.provider_acknowledgement.to_dict()
        acknowledgement = build_collaboration_executor_acknowledgement(
            fixture.dispatch,
            adapter_id=original["provider"]["adapter_id"],
            adapter_version=original["provider"]["adapter_version"],
            adapter_build_sha256=original["provider"][
                "adapter_build_sha256"
            ],
            runtime_instance_id=original["worker"]["runtime_instance_id"],
            outcome=original["outcome"],
            provider_worker_state=original["provider_worker_state"],
            provider_evidence_sha256=EVIDENCE_SHA256,
            acknowledged_at=original["acknowledged_at"],
        )
        report = build_collaboration_executor_provider_report(
            fixture.preparation_receipt.preparation,
            acknowledgement,
            received_at=fixture.report.to_dict()["received_at"],
        )
        self.authentication = (
            bind_authenticated_collaboration_executor_provider_report(
                report,
                fixture._authenticate(acknowledgement),
            )
        )

    def _verify(self, evidence: bytes = EVIDENCE):
        return verify_collaboration_executor_provider_evidence_digest(
            self.authentication,
            evidence,
            evidence_media_type="application/json",
            verified_at=VERIFIED_AT,
        )

    def test_exact_bytes_verify_digest_without_claiming_semantics(self) -> None:
        verified = self._verify()
        document = verified.to_dict()
        self.assertEqual(
            document["report_authentication_id"],
            self.authentication.report_authentication_id,
        )
        self.assertEqual(document["provider_evidence_sha256"], EVIDENCE_SHA256)
        self.assertEqual(document["evidence_size_bytes"], len(EVIDENCE))
        self.assertEqual(
            document["evidence_verification_status"],
            "provider_evidence_digest_verified",
        )
        self.assertEqual(
            document["media_type_status"],
            "caller_declared_unverified",
        )
        self.assertEqual(
            document["semantic_verification_status"],
            "not_performed",
        )
        self.assertEqual(
            document["external_effect_status"],
            "authenticated_report_evidence_digest_verified_effect_unverified",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertNotIn(EVIDENCE.decode("utf-8"), json.dumps(document))

    def test_changed_or_empty_evidence_fails_closed(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "do not match"):
            self._verify(b"changed")
        with self.assertRaisesRegex(CollaborationPlanError, "size"):
            self._verify(b"")

    def test_verification_cannot_precede_report_authentication(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "precedes"):
            verify_collaboration_executor_provider_evidence_digest(
                self.authentication,
                EVIDENCE,
                evidence_media_type="application/json",
                verified_at="2026-07-30T10:08:34Z",
            )

    def test_serialized_verification_revalidates(self) -> None:
        document = self._verify().to_dict()
        self.assertEqual(
            validate_collaboration_executor_provider_evidence_digest_document(
                document
            ),
            document,
        )

    def test_verified_wrapper_cannot_be_directly_forged(self) -> None:
        verified = self._verify()
        with self.assertRaisesRegex(TypeError, "created only"):
            VerifiedCollaborationExecutorProviderEvidenceDigest(
                verification_id=verified.verification_id,
                verification_sha256=verified.verification_sha256,
                document=verified.to_dict(),
                _proof=b"wrong",
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_verification_matches_strict_schema(self) -> None:
        schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-provider-evidence-verification-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self._verify().to_dict())

    def test_contract_has_no_network_storage_process_or_adapter(self) -> None:
        source = (
            ROOT / "src/sunderkey/collaboration_executor_provider_evidence.py"
        ).read_text(encoding="utf-8")
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
                "httpx",
                "requests",
                "socket",
                "sqlite3",
                "subprocess",
                "urllib",
            }
        )
        self.assertNotIn("CollaborationExecutorAdapter", source)


if __name__ == "__main__":
    unittest.main()
