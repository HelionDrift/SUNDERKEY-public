"""Phase 144 durable-base provider-evidence verification service coverage."""

from __future__ import annotations

import ast
import hashlib
import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.authenticated_collaboration_executor_provider_report import (
    AuthenticatedCollaborationExecutorProviderReportService,
)
from sunderkey.collaboration_executor_authentication import (
    collaboration_executor_acknowledgement_selection_sha256,
)
from sunderkey.collaboration_executor_provider_evidence_service import (
    CollaborationExecutorProviderEvidenceVerificationService,
)
from sunderkey.errors import CollaborationPlanError, StoreError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.store import canonical_json, sha256_text

from . import (
    test_collaboration_executor_provider_report_authentication_phase140 as phase140,
)
from . import test_collaboration_executor_provider_report_store_phase139 as phase139
from .test_identity_phase4 import AUDIENCE, SUBJECT

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
EVIDENCE = b'{"durable_provider_receipt":"phase-144","status":"accepted"}'
EVIDENCE_SHA256 = "sha256:" + hashlib.sha256(EVIDENCE).hexdigest()


class CollaborationExecutorProviderEvidenceServicePhase144Tests(
    unittest.TestCase
):
    def setUp(self) -> None:
        fixture = phase139.CollaborationExecutorProviderReportStorePhase139Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        preparation = fixture._prepare()
        acknowledgement = fixture._acknowledgement(evidence=EVIDENCE_SHA256)
        fixture.service.commit(
            preparation.attempt_id,
            acknowledgement,
        )
        dispatch = fixture.fixture.fixture.dispatch
        worker_id = dispatch.to_dict()["worker"]["worker_principal_id"]
        policy = self.root.factory.policy(
            max_assertion_lifetime_seconds=900,
            policy_version=phase140.POLICY_VERSION,
            store_id=self.root.store_id,
            allowed_profiles=[worker_id],
            allowed_operations=[
                PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value
            ],
        )
        self.root.trust.apply_policy(policy)
        mission = self.root.mission
        grant = self.root.factory.grant(
            grant_id=phase140.GRANT_ID,
            profile_id=worker_id,
            store_id=self.root.store_id,
            mission_id=mission.mission_id,
            mission_context_hash=self.root.stored.context_hash,
            scope_reference=mission.scope_reference,
            scope_document_hash=mission.scope_document_hash,
            environment=mission.environment.value,
            max_action_tier=mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            ),
            operations=[PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value],
            policy_version=phase140.POLICY_VERSION,
            expires_at="2026-07-30T10:20:00Z",
        )
        self.root.acceptance.accept(grant)
        intent = {
            "acknowledgement_selection_sha256": (
                collaboration_executor_acknowledgement_selection_sha256(
                    acknowledgement
                )
            ),
            "dispatch_sha256": dispatch.dispatch_sha256,
            "mission_id": mission.mission_id,
            "principal_profile_id": worker_id,
        }
        assertion = self.root.factory.assertion(
            grant=grant,
            assertion_id=phase140.ASSERTION_ID,
            policy_version=phase140.POLICY_VERSION,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=worker_id,
            audience=AUDIENCE,
            store_id=self.root.store_id,
            mission_id=mission.mission_id,
            operation=PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
                intent,
            ),
            issued_at="2026-07-30T10:08:34Z",
            not_before="2026-07-30T10:08:34Z",
            expires_at="2026-07-30T10:10:00Z",
        )
        authentication_service = (
            AuthenticatedCollaborationExecutorProviderReportService(
                self.root.store,
                self.root.registry,
                clock=lambda: self.root.now,
            )
        )
        self.authentication_receipt = authentication_service.authenticate(
            preparation.attempt_id,
            worker_assertion=assertion,
        )
        self.root.now = datetime(2026, 7, 30, 10, 8, 36, tzinfo=UTC)
        self.service = (
            CollaborationExecutorProviderEvidenceVerificationService(
                self.root.store,
                self.root.registry,
                clock=lambda: self.root.now,
            )
        )

    def _counts(self) -> tuple[int, int, int]:
        with closing(sqlite3.connect(self.root.path)) as connection:
            return (
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM executor_invocation_provider_report_authentications
                    """
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
            )

    def _verify(self, evidence: bytes = EVIDENCE):
        return self.service.verify(
            self.authentication_receipt.report_authentication_id,
            evidence,
            evidence_media_type="application/json",
        )

    def test_durable_base_verification_is_read_only_and_transient(self) -> None:
        before = self._counts()
        receipt = self._verify()
        document = receipt.to_dict()
        self.assertEqual(
            receipt.report_authentication_id,
            self.authentication_receipt.report_authentication_id,
        )
        self.assertEqual(
            document["base_custody_status"],
            "durable_authenticated_provider_report",
        )
        self.assertEqual(
            document["verification_custody_status"],
            "transient_not_retained",
        )
        self.assertEqual(
            document["evidence_retention_status"],
            "not_retained",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(self._counts(), before)
        self.assertNotIn(EVIDENCE, self.root.path.read_bytes())
        self.assertEqual(self._verify(), receipt)

    def test_changed_evidence_fails_against_durable_authentication(self) -> None:
        before = self._counts()
        with self.assertRaisesRegex(CollaborationPlanError, "do not match"):
            self._verify(b"changed")
        self.assertEqual(self._counts(), before)

    def test_unknown_authentication_fails_closed(self) -> None:
        with self.assertRaisesRegex(StoreError, "not committed"):
            self.service.verify(
                "EPA-" + "00" * 16,
                EVIDENCE,
                evidence_media_type="application/json",
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_receipt_matches_strict_schema(self) -> None:
        receipt_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-provider-evidence-verification-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        receipt_schema["properties"]["evidence_verification"] = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-provider-evidence-verification-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(receipt_schema)
        Draft202012Validator(receipt_schema).validate(self._verify().to_dict())

    def test_service_has_no_network_process_storage_or_adapter(self) -> None:
        source = (
            ROOT
            / "src/sunderkey/collaboration_executor_provider_evidence_service.py"
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
        self.assertNotIn("_write_connection", source)
        self.assertNotIn("CollaborationExecutorAdapter", source)


if __name__ == "__main__":
    unittest.main()
