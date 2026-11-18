"""Local durable planning archive tenant and corruption boundaries."""

from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import tests.agents.test_offline_api_planning_bundle as planning_fixture
import tests.agents.test_offline_planning_preview as preview_fixture
from sunderkey.local_api_runtime_adapter import (
    PLANNING_PREVIEW_PATH,
    OfflinePlanningPreviewAsgiApp,
)
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from sunderkey.offline_planning_preview import PlanningBundleRecord
from sunderkey.offline_planning_preview_store import (
    OfflinePlanningPreviewStoreError,
    SQLitePlanningBundleStore,
)
from tests.agents.test_local_api_runtime_adapter_phase168 import invoke

NOW = "2026-09-24T12:02:00Z"


class OfflinePlanningPreviewStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        self.bundle = build_offline_api_planning_bundle(**fixture.options())
        self.path = Path(self.temporary.name) / "planning.sqlite3"
        self.store = SQLitePlanningBundleStore(self.path, fixture.registry)
        self.record = PlanningBundleRecord(
            "tenant.synthetic.001",
            "context.synthetic.001",
            self.bundle["bundle_sha256"],
            self.bundle,
        )
        self.registry = fixture.registry

    def test_exact_tenant_reader_and_asgi_preview(self) -> None:
        self.store.put(self.record)
        self.store.put(self.record)
        self.assertEqual(
            self.store.get(
                self.record.tenant_id,
                self.record.context_id,
                self.record.bundle_sha256,
            ),
            self.record,
        )
        self.assertIsNone(
            self.store.get("tenant.other", self.record.context_id, self.record.bundle_sha256)
        )
        app = OfflinePlanningPreviewAsgiApp(
            self.store, preview_fixture.Authorizer(), self.registry, clock=lambda: NOW
        )
        status, body, _ = asyncio.run(
            invoke(
                app,
                {
                    "request_id": "preview.synthetic.001",
                    "access": {
                        "tenant_id": self.record.tenant_id,
                        "context_id": self.record.context_id,
                        "principal_id": "principal.operator.001",
                        "session_ref": "session.synthetic.001",
                    },
                    "bundle_sha256": self.record.bundle_sha256,
                    "expected_scope_sha256": self.bundle["scope_sha256"],
                },
                path=PLANNING_PREVIEW_PATH,
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["data"]["task_count"], 6)
        self.assertFalse(body["data"]["positive_use_approved"])

    def test_same_content_cannot_be_rebound_to_another_tenant(self) -> None:
        self.store.put(self.record)
        other = PlanningBundleRecord(
            "tenant.other",
            self.record.context_id,
            self.record.bundle_sha256,
            self.bundle,
        )
        with self.assertRaisesRegex(OfflinePlanningPreviewStoreError, "conflicts"):
            self.store.put(other)

    def test_corruption_and_schema_mismatch_fail_closed(self) -> None:
        self.store.put(self.record)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "UPDATE planning_bundles SET bundle_json=? WHERE bundle_sha256=?",
                ("{}", self.record.bundle_sha256),
            )
            connection.commit()
        with self.assertRaisesRegex(OfflinePlanningPreviewStoreError, "invalid"):
            self.store.get(
                self.record.tenant_id,
                self.record.context_id,
                self.record.bundle_sha256,
            )
        wrong = Path(self.temporary.name) / "wrong.sqlite3"
        with closing(sqlite3.connect(wrong)) as connection:
            connection.execute("CREATE TABLE unrelated (id TEXT PRIMARY KEY)")
            connection.execute("PRAGMA user_version=1")
            connection.commit()
        with self.assertRaisesRegex(OfflinePlanningPreviewStoreError, "schema"):
            SQLitePlanningBundleStore(wrong, self.registry)

    def test_concurrent_idempotent_import_remains_one_record(self) -> None:
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(self.store.put, [self.record] * 12))
        with closing(sqlite3.connect(self.path)) as connection:
            count = connection.execute("SELECT count(*) FROM planning_bundles").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
