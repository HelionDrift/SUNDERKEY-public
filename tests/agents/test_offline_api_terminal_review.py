"""Focused negative-only review against a real local SQLite API repository."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from sunderkey.local_api_runtime_adapter import SQLiteServiceRepository
from sunderkey.local_api_service import (
    AccessCheck,
    AccessContext,
    AccessDecision,
    AdmissionStatus,
    DecisionStatus,
    LocalApiService,
    MutationAdmission,
    MutationCheck,
    Operation,
    ResourceKind,
    ServiceRequest,
)
from sunderkey.offline_api_terminal_review import (
    OfflineApiTerminalReviewError,
    review_selected_api_terminal_assertion,
)

NOW = "2026-09-20T12:00:00Z"
LATER = "2026-09-20T12:10:00Z"
HASH_REF = "sha256:" + "a" * 64


class BoundAuthorizer:
    def authorize(self, check: AccessCheck) -> AccessDecision:
        return AccessDecision(
            decision_ref="authzref:terminal-review-test",
            status=DecisionStatus.ALLOWED,
            request_sha256=check.request_sha256,
            tenant_id=check.tenant_id,
            context_id=check.context_id,
            principal_id=check.principal_id,
            session_ref=check.session_ref,
            permission=check.permission,
            valid_through=LATER,
            audit_ref="auditref:terminal-review-authz",
        )


class BoundAdmitter:
    def admit(self, check: MutationCheck) -> MutationAdmission:
        return MutationAdmission(
            admission_ref="admitref:terminal-review-test",
            status=AdmissionStatus.ADMITTED,
            request_sha256=check.request_sha256,
            idempotency_sha256=check.idempotency_sha256,
            authorization_ref=check.authorization_ref,
            tenant_id=check.tenant_id,
            context_id=check.context_id,
            principal_id=check.principal_id,
            operation=check.operation,
            resource_kind=check.resource_kind,
            resource_id=check.resource_id,
            expected_concurrency_token=check.expected_concurrency_token,
            valid_through=LATER,
            audit_ref="auditref:terminal-review-admit",
        )


class OfflineApiTerminalReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / "local-api.sqlite3"
        self.repository = SQLiteServiceRepository(self.database)
        self.service = LocalApiService(self.repository, BoundAuthorizer(), BoundAdmitter())

    def _create(
        self,
        kind: ResourceKind,
        resource_id: str,
        payload: dict,
        *,
        tenant_id: str = "tenant-a",
        context_id: str = "context-a",
    ) -> None:
        operation = (
            Operation.UPSERT_FINDING
            if kind is ResourceKind.FINDING
            else Operation.RECORD_REMEDIATION
        )
        request = ServiceRequest(
            request_id=f"request-{resource_id}",
            operation=operation,
            access=AccessContext(
                tenant_id=tenant_id,
                context_id=context_id,
                principal_id="principal-operator",
                session_ref="session-verified",
            ),
            requested_at=NOW,
            resource_kind=kind,
            resource_id=resource_id,
            payload=payload,
            idempotency_key=f"idem:create-{resource_id}-00000001",
        )
        self.service.handle(request)

    @staticmethod
    def _finding_payload(status: str, retest_refs: list[str] | None = None) -> dict:
        return {
            "title": "Authorized synthetic finding",
            "status": status,
            "severity": "high",
            "affected_asset_refs": ["assetref:asset-a"],
            "evidence_refs": ["evidref:evidence-a"],
            "validation_ref": "validationref:review-a",
            "remediation_ref": "remediationref:review-a",
            "retest_refs": [] if retest_refs is None else retest_refs,
            "owner_ref": "ownerref:team-a",
        }

    @staticmethod
    def _remediation_payload(retest_ref: str) -> dict:
        return {
            "finding_ref": "findingref:finding-a",
            "guidance_ref": "guidanceref:finding-a",
            "developer_evidence_refs": ["evidref:developer-a"],
            "retest_ref": retest_ref,
            "regression_ref": "regressionref:finding-a",
            "closure_status": "closed",
        }

    def _review(
        self,
        kind: ResourceKind,
        resource_id: str,
        *,
        tenant_id: str = "tenant-a",
        context_id: str = "context-a",
    ) -> dict:
        return review_selected_api_terminal_assertion(
            repository=self.repository,
            tenant_id=tenant_id,
            context_id=context_id,
            resource_kind=kind,
            resource_id=resource_id,
        )

    def test_direct_closed_finding_is_flagged_despite_valid_store(self) -> None:
        self._create(ResourceKind.FINDING, "finding-a", self._finding_payload("closed"))
        before = self.repository.verify_integrity()
        with mock.patch.object(
            self.repository,
            "verify_integrity",
            wraps=self.repository.verify_integrity,
        ) as verified:
            result = self._review(ResourceKind.FINDING, "finding-a")
        self.assertEqual(verified.call_count, 2)
        self.assertEqual(self.repository.verify_integrity(), before)
        self.assertEqual(result["status"], "terminal_assertion_unverified")
        self.assertEqual(result["observed_api_status"], "closed")
        self.assertEqual(result["resource_kind"], "finding")
        self.assertFalse(result["closure_verified"])
        self.assertFalse(result["positive_use_approved"])
        for effect in ("authorization_effect", "qualification_effect", "target_effect"):
            self.assertEqual(result[effect], "none")

    def test_hash_only_references_never_upgrade_a_terminal_claim(self) -> None:
        self._create(
            ResourceKind.FINDING,
            "finding-hash",
            self._finding_payload("remediated", [HASH_REF]),
        )
        self._create(
            ResourceKind.REMEDIATION,
            "remediation-hash",
            self._remediation_payload(HASH_REF),
        )
        for kind, resource_id in (
            (ResourceKind.FINDING, "finding-hash"),
            (ResourceKind.REMEDIATION, "remediation-hash"),
        ):
            with self.subTest(kind=kind):
                result = self._review(kind, resource_id)
                self.assertEqual(result["status"], "terminal_assertion_unverified")
                self.assertFalse(result["closure_verified"])

    def test_other_terminal_statuses_and_placeholder_ref_remain_unverified(self) -> None:
        for status in ("accepted_risk", "false_positive"):
            resource_id = f"finding-{status}"
            self._create(
                ResourceKind.FINDING,
                resource_id,
                self._finding_payload(status, ["retestref:placeholder"]),
            )
            self.assertEqual(
                self._review(ResourceKind.FINDING, resource_id)["status"],
                "terminal_assertion_unverified",
            )
        self._create(
            ResourceKind.REMEDIATION,
            "remediation-placeholder",
            self._remediation_payload("retestref:placeholder"),
        )
        self.assertEqual(
            self._review(ResourceKind.REMEDIATION, "remediation-placeholder")["status"],
            "terminal_assertion_unverified",
        )

    def test_nonterminal_state_is_not_mistaken_for_approval(self) -> None:
        self._create(ResourceKind.FINDING, "finding-open", self._finding_payload("validated"))
        result = self._review(ResourceKind.FINDING, "finding-open")
        self.assertEqual(result["status"], "no_terminal_assertion_observed")
        self.assertFalse(result["closure_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(result["live_source_currentness"], "not_proven")
        self.assertEqual(result["cross_read_atomicity"], "not_proven")

    def test_tenant_context_and_kind_are_exact(self) -> None:
        self._create(ResourceKind.FINDING, "finding-a", self._finding_payload("closed"))
        for kwargs in (
            {"tenant_id": "tenant-b"},
            {"context_id": "context-b"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(OfflineApiTerminalReviewError):
                self._review(ResourceKind.FINDING, "finding-a", **kwargs)
        with self.assertRaises(OfflineApiTerminalReviewError):
            self._review(ResourceKind.REMEDIATION, "finding-a")
        with self.assertRaises(OfflineApiTerminalReviewError):
            self._review(ResourceKind.ASSET, "finding-a")

    def test_corrupt_store_and_byte_limit_fail_closed(self) -> None:
        self._create(ResourceKind.FINDING, "finding-a", self._finding_payload("closed"))
        with (
            mock.patch("sunderkey.offline_api_terminal_review.MAX_DATABASE_BYTES", 1),
            self.assertRaisesRegex(OfflineApiTerminalReviewError, "byte limit"),
        ):
            self._review(ResourceKind.FINDING, "finding-a")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE resources SET resource_sha256 = ? WHERE resource_id = ?",
                (HASH_REF, "finding-a"),
            )
        with self.assertRaises(OfflineApiTerminalReviewError):
            self._review(ResourceKind.FINDING, "finding-a")


if __name__ == "__main__":
    unittest.main()
