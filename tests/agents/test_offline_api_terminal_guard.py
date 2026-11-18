"""Focused opt-in terminal mutation suppression tests."""

from __future__ import annotations

import unittest
from unittest import mock

from sunderkey.local_api_service import (
    AccessContext,
    LocalApiService,
    Operation,
    ResourceKind,
    ResponseStatus,
    ServiceRequest,
)
from sunderkey.offline_api_terminal_guard import (
    OfflineApiTerminalGuard,
    OfflineApiTerminalGuardError,
)
from tests.agents import test_local_api_service_phase167 as api_fixture

NOW = api_fixture.NOW


class CountingRepository(api_fixture.FakeRepository):
    def __init__(self) -> None:
        super().__init__()
        self.read_count = 0

    def get(self, kind, tenant_id, context_id, resource_id):
        self.read_count += 1
        return super().get(kind, tenant_id, context_id, resource_id)


class OfflineApiTerminalGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = CountingRepository()
        self.authorizer = api_fixture.FakeAuthorizer()
        self.admitter = api_fixture.FakeAdmitter()
        self.service = LocalApiService(self.repository, self.authorizer, self.admitter)
        self.guard = OfflineApiTerminalGuard(self.service)
        self.access = AccessContext(
            tenant_id="tenant-a",
            context_id="context-red",
            principal_id="principal-operator",
            session_ref="session-verified",
        )

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
    def _remediation_payload(status: str) -> dict:
        return {
            "finding_ref": "findingref:finding-a",
            "guidance_ref": "guidanceref:finding-a",
            "developer_evidence_refs": ["evidref:developer-a"],
            "retest_ref": "retestref:placeholder",
            "regression_ref": "regressionref:finding-a",
            "closure_status": status,
        }

    def _request(
        self,
        operation: Operation,
        kind: ResourceKind,
        resource_id: str,
        payload: dict,
    ) -> ServiceRequest:
        return ServiceRequest(
            request_id=f"request-{resource_id}",
            operation=operation,
            access=self.access,
            requested_at=NOW,
            resource_kind=kind,
            resource_id=resource_id,
            payload=payload,
            idempotency_key=f"idem:create-{resource_id}-00000001",
        )

    def _assert_no_port_calls(self) -> None:
        self.assertEqual(self.authorizer.checks, [])
        self.assertEqual(self.admitter.checks, [])
        self.assertEqual(self.repository.read_count, 0)
        self.assertEqual(self.repository.commits, [])

    def test_all_terminal_finding_statuses_fail_before_any_service_call(self) -> None:
        for status in ("accepted_risk", "false_positive", "remediated", "closed"):
            with self.subTest(status=status):
                request = self._request(
                    Operation.UPSERT_FINDING,
                    ResourceKind.FINDING,
                    f"finding-{status}",
                    self._finding_payload(status, ["sha256:" + "a" * 64]),
                )
                with (
                    mock.patch.object(self.service, "handle", wraps=self.service.handle) as called,
                    self.assertRaisesRegex(OfflineApiTerminalGuardError, "blocked"),
                ):
                    self.guard.handle(request)
                called.assert_not_called()
                self._assert_no_port_calls()

    def test_closed_remediation_fails_despite_placeholder_retest_ref(self) -> None:
        request = self._request(
            Operation.RECORD_REMEDIATION,
            ResourceKind.REMEDIATION,
            "remediation-closed",
            self._remediation_payload("closed"),
        )
        with self.assertRaisesRegex(OfflineApiTerminalGuardError, "blocked"):
            self.guard.handle(request)
        self._assert_no_port_calls()

    def test_nonterminal_delegates_with_same_request_binding(self) -> None:
        request = self._request(
            Operation.UPSERT_FINDING,
            ResourceKind.FINDING,
            "finding-validated",
            self._finding_payload("validated"),
        )
        response = self.guard.handle(request)
        self.assertEqual(response.status, ResponseStatus.COMPLETED)
        self.assertEqual(response.request_sha256, request.request_sha256)
        self.assertEqual(response.resource.payload["status"], "validated")
        self.assertEqual(len(self.authorizer.checks), 1)
        self.assertEqual(len(self.admitter.checks), 1)
        self.assertEqual(len(self.repository.commits), 1)

    def test_unknown_status_fails_before_authorizer(self) -> None:
        request = self._request(
            Operation.UPSERT_FINDING,
            ResourceKind.FINDING,
            "finding-unknown",
            self._finding_payload("unsupported_status"),
        )
        with self.assertRaisesRegex(OfflineApiTerminalGuardError, "unsupported"):
            self.guard.handle(request)
        self._assert_no_port_calls()

    def test_owned_deep_copy_prevents_payload_change_before_delegation(self) -> None:
        request = self._request(
            Operation.UPSERT_FINDING,
            ResourceKind.FINDING,
            "finding-owned",
            self._finding_payload("validated"),
        )
        original_handle = self.service.handle

        def inspect(owned: ServiceRequest):
            self.assertIsNot(owned, request)
            self.assertEqual(owned.request_sha256, request.request_sha256)
            request.payload["retest_refs"].append("retestref:changed-after-capture")
            self.assertEqual(owned.payload["retest_refs"], [])
            return original_handle(owned)

        with mock.patch.object(self.service, "handle", side_effect=inspect):
            response = self.guard.handle(request)
        self.assertEqual(response.status, ResponseStatus.COMPLETED)
        self.assertEqual(response.resource.payload["retest_refs"], [])

    def test_legacy_direct_caller_can_bypass_optional_guard(self) -> None:
        request = self._request(
            Operation.UPSERT_FINDING,
            ResourceKind.FINDING,
            "finding-direct",
            self._finding_payload("closed"),
        )
        response = self.service.handle(request)
        self.assertEqual(response.status, ResponseStatus.COMPLETED)
        self.assertEqual(response.resource.payload["status"], "closed")
        self.assertEqual(len(self.repository.commits), 1)


if __name__ == "__main__":
    unittest.main()
