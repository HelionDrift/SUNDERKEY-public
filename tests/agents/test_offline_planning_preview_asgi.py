"""Bounded ASGI transport for the read-only offline plan preview."""

from __future__ import annotations

import asyncio
import unittest

import tests.agents.test_offline_api_planning_bundle as planning_fixture
import tests.agents.test_offline_planning_preview as preview_fixture
from sunderkey.local_api_runtime_adapter import (
    PLANNING_PREVIEW_PATH,
    OfflinePlanningPreviewAsgiApp,
)
from sunderkey.local_api_service import DecisionStatus
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from tests.agents.test_local_api_runtime_adapter_phase168 import invoke

NOW = "2026-09-24T12:02:00Z"


class OfflinePlanningPreviewAsgiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        bundle = build_offline_api_planning_bundle(**fixture.options())
        self.reader = preview_fixture.Reader(bundle)
        self.authorizer = preview_fixture.Authorizer()
        self.app = OfflinePlanningPreviewAsgiApp(
            self.reader, self.authorizer, fixture.registry, clock=lambda: NOW
        )
        self.document = {
            "request_id": "preview.synthetic.001",
            "access": {
                "tenant_id": "tenant.synthetic.001",
                "context_id": "context.synthetic.001",
                "principal_id": "principal.operator.001",
                "session_ref": "session.synthetic.001",
            },
            "bundle_sha256": bundle["bundle_sha256"],
            "expected_scope_sha256": bundle["scope_sha256"],
        }

    def call(self, document=None, **kwargs):
        return asyncio.run(
            invoke(
                self.app,
                self.document if document is None else document,
                path=kwargs.pop("path", PLANNING_PREVIEW_PATH),
                **kwargs,
            )
        )

    def test_route_returns_historical_preview_without_mutation(self) -> None:
        status, body, _ = self.call()
        self.assertEqual(status, 200)
        self.assertEqual(body["data"]["task_count"], 6)
        self.assertFalse(body["data"]["positive_use_approved"])
        self.assertEqual(body["data"]["effects"]["mutation"], "none")
        self.assertEqual(self.authorizer.checks[0].requested_at, NOW)
        self.assertEqual(len(self.reader.calls), 1)

    def test_route_rejects_tenant_rebind_and_denied_auth(self) -> None:
        other = {**self.document, "access": {**self.document["access"], "tenant_id": "other"}}
        status, body, _ = self.call(other)
        self.assertEqual((status, body["error"]["code"]), (404, "preview_not_found"))
        self.authorizer.status = DecisionStatus.DENIED
        before = len(self.reader.calls)
        status, body, _ = self.call()
        self.assertEqual((status, body["error"]["code"]), (403, "authorization_denied"))
        self.assertEqual(len(self.reader.calls), before)

    def test_route_rejects_unexpected_data_and_transport(self) -> None:
        status, body, _ = self.call({**self.document, "requested_at": NOW})
        self.assertEqual((status, body["error"]["code"]), (400, "invalid_request_shape"))
        status, body, _ = self.call(method="GET")
        self.assertEqual((status, body["error"]["code"]), (405, "method_not_allowed"))
        status, body, _ = self.call(path="/v1/service/requests")
        self.assertEqual((status, body["error"]["code"]), (404, "route_not_found"))
        status, body, _ = self.call(
            headers=(
                (b"content-type", b"application/json"),
                (b"authorization", b"Bearer synthetic"),
            )
        )
        self.assertEqual(
            (status, body["error"]["code"]), (400, "credential_transport_rejected")
        )


if __name__ == "__main__":
    unittest.main()
