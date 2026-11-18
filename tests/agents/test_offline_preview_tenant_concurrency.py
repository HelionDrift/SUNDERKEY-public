"""Concurrent local previews preserve tenant and archive fault boundaries."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import tests.agents.test_offline_api_planning_bundle as planning_fixture
import tests.agents.test_offline_planning_preview as preview_fixture
from sunderkey.local_api_runtime_adapter import (
    PLANNING_PREVIEW_PATH,
    OfflinePlanningPreviewAsgiApp,
)
from sunderkey.local_api_service import AccessCheck, AccessDecision, DecisionStatus
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from sunderkey.offline_planning_preview import PlanningBundleRecord
from sunderkey.offline_planning_preview_store import SQLitePlanningBundleStore
from tests.agents.test_local_api_runtime_adapter_phase168 import invoke

NOW = "2026-09-24T12:02:00Z"


class TenantAuthorizer(preview_fixture.Authorizer):
    def authorize(self, check: AccessCheck) -> AccessDecision:
        decision = super().authorize(check)
        allowed = {
            ("tenant.synthetic.001", "principal.tenant.001"),
            ("tenant.synthetic.002", "principal.tenant.002"),
        }
        if (check.tenant_id, check.principal_id) not in allowed:
            return replace(decision, status=DecisionStatus.DENIED)
        return decision


class OfflinePreviewTenantConcurrencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        options = fixture.options()
        first = build_offline_api_planning_bundle(**options)
        second = build_offline_api_planning_bundle(
            **{**options, "limits": replace(fixture.limits, max_concurrency=1)}
        )
        self.assertNotEqual(first["bundle_sha256"], second["bundle_sha256"])
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "planning.sqlite3"
        self.store = SQLitePlanningBundleStore(self.path, fixture.registry)
        self.bundles = (first, second)
        for index, bundle in enumerate(self.bundles, start=1):
            self.store.put(
                PlanningBundleRecord(
                    f"tenant.synthetic.{index:03d}",
                    f"context.synthetic.{index:03d}",
                    bundle["bundle_sha256"],
                    bundle,
                )
            )
        self.app = OfflinePlanningPreviewAsgiApp(
            self.store, TenantAuthorizer(), fixture.registry, clock=lambda: NOW
        )

    def request(self, index: int, *, principal: int | None = None, bundle: int | None = None):
        selected = self.bundles[index - 1 if bundle is None else bundle - 1]
        request_id = f"preview.synthetic.concurrent.{index}.{principal or index}.{bundle or index}"
        return {
            "request_id": request_id,
            "access": {
                "tenant_id": f"tenant.synthetic.{index:03d}",
                "context_id": f"context.synthetic.{index:03d}",
                "principal_id": f"principal.tenant.{principal or index:03d}",
                "session_ref": f"session.synthetic.{index:03d}",
            },
            "bundle_sha256": selected["bundle_sha256"],
            "expected_scope_sha256": selected["scope_sha256"],
        }

    def preview(self, request):
        return asyncio.run(invoke(self.app, request, path=PLANNING_PREVIEW_PATH))

    def test_concurrent_tenant_isolation_and_authorization(self) -> None:
        cases = [
            (self.request(1), 200),
            (self.request(2), 200),
            (self.request(1, bundle=2), 404),
            (self.request(2, bundle=1), 404),
            (self.request(1, principal=2), 403),
            (self.request(2, principal=1), 403),
        ] * 3
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(self.preview, [item[0] for item in cases]))
        for (request, expected), (status, body, _) in zip(cases, results, strict=True):
            self.assertEqual(status, expected)
            if expected == 200:
                self.assertEqual(body["data"]["tenant_id"], request["access"]["tenant_id"])
                self.assertFalse(body["data"]["positive_use_approved"])
            else:
                self.assertNotIn("task_count", json.dumps(body))
                self.assertNotIn("schedule_sha256", json.dumps(body))
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM planning_bundles").fetchone()[0], 2
            )

    def test_one_tenant_corruption_is_409_without_cross_tenant_loss(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "UPDATE planning_bundles SET bundle_json=? WHERE bundle_sha256=?",
                ("{}", self.bundles[0]["bundle_sha256"]),
            )
            connection.commit()
        first_status, first_body, _ = self.preview(self.request(1))
        second_status, second_body, _ = self.preview(self.request(2))
        self.assertEqual(first_status, 409)
        self.assertNotIn("task_count", json.dumps(first_body))
        self.assertEqual(second_status, 200)
        self.assertEqual(second_body["data"]["tenant_id"], "tenant.synthetic.002")


if __name__ == "__main__":
    unittest.main()
