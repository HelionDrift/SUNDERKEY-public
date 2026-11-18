"""Tenant-bound, read-only archive preview conformance."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

import tests.agents.test_offline_api_planning_bundle as planning_fixture
from sunderkey.local_api_service import (
    AccessCheck,
    AccessContext,
    AccessDecision,
    DecisionStatus,
)
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from sunderkey.offline_planning_preview import (
    OfflinePlanningPreviewError,
    OfflinePlanningPreviewService,
    PlanningBundleRecord,
    PlanningPreviewRequest,
)

NOW = "2026-09-24T12:02:00Z"


class Reader:
    def __init__(self, bundle):
        self.bundle = bundle
        self.calls = []

    def get(self, tenant_id, context_id, bundle_sha256):
        self.calls.append((tenant_id, context_id, bundle_sha256))
        if (tenant_id, context_id, bundle_sha256) == (
            "tenant.synthetic.001",
            "context.synthetic.001",
            self.bundle["bundle_sha256"],
        ):
            return PlanningBundleRecord(
                tenant_id="tenant.synthetic.001",
                context_id="context.synthetic.001",
                bundle_sha256=self.bundle["bundle_sha256"],
                bundle=self.bundle,
            )
        return None


class Authorizer:
    def __init__(self):
        self.checks = []
        self.status = DecisionStatus.ALLOWED
        self.rebind = False
        self.expired = False

    def authorize(self, check: AccessCheck) -> AccessDecision:
        self.checks.append(check)
        return AccessDecision(
            decision_ref="authzref:planning-preview-001",
            status=self.status,
            request_sha256=check.request_sha256,
            tenant_id="tenant.other" if self.rebind else check.tenant_id,
            context_id=check.context_id,
            principal_id=check.principal_id,
            session_ref=check.session_ref,
            permission=check.permission,
            valid_through=(
                "2026-09-24T12:01:00Z" if self.expired else "2026-09-24T12:10:00Z"
            ),
            audit_ref="auditref:planning-preview-001",
        )


class OfflinePlanningPreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        self.bundle = build_offline_api_planning_bundle(**fixture.options())
        self.registry = fixture.registry
        self.reader = Reader(self.bundle)
        self.authorizer = Authorizer()
        self.service = OfflinePlanningPreviewService(
            self.reader, self.authorizer, self.registry
        )
        self.request = PlanningPreviewRequest(
            request_id="preview.synthetic.001",
            access=AccessContext(
                tenant_id="tenant.synthetic.001",
                context_id="context.synthetic.001",
                principal_id="principal.operator.001",
                session_ref="session.synthetic.001",
            ),
            requested_at=NOW,
            bundle_sha256=self.bundle["bundle_sha256"],
            expected_scope_sha256=self.bundle["scope_sha256"],
        )

    def test_preview_is_deterministic_and_has_no_positive_effect(self) -> None:
        preview = self.service.preview(self.request, as_of=NOW)
        self.assertEqual(preview, self.service.preview(self.request, as_of=NOW))
        self.assertEqual(preview["task_count"], 6)
        self.assertEqual(preview["scope_sha256"], self.bundle["scope_sha256"])
        self.assertEqual(preview["effects"]["execution"], "none")
        self.assertFalse(preview["source_replay_performed"])
        self.assertFalse(preview["positive_use_approved"])
        self.assertEqual(self.authorizer.checks[0].permission, "resource:read")
        self.assertNotIn("evidence", preview)

    def test_tenant_scope_and_authorization_fail_closed(self) -> None:
        other = replace(
            self.request,
            access=replace(self.request.access, tenant_id="tenant.other"),
        )
        with self.assertRaisesRegex(OfflinePlanningPreviewError, "not found"):
            self.service.preview(other, as_of=NOW)
        original_get = self.reader.get
        self.reader.get = lambda *_: PlanningBundleRecord(
            tenant_id="tenant.other",
            context_id="context.synthetic.001",
            bundle_sha256=self.bundle["bundle_sha256"],
            bundle=self.bundle,
        )
        with self.assertRaisesRegex(OfflinePlanningPreviewError, "tenant binding"):
            self.service.preview(self.request, as_of=NOW)
        self.reader.get = original_get
        changed = replace(
            self.request, expected_scope_sha256="sha256:" + "a" * 64
        )
        with self.assertRaisesRegex(OfflinePlanningPreviewError, "binding"):
            self.service.preview(changed, as_of=NOW)
        self.authorizer.rebind = True
        with self.assertRaisesRegex(OfflinePlanningPreviewError, "authorization"):
            self.service.preview(self.request, as_of=NOW)
        self.authorizer.rebind = False
        self.authorizer.expired = True
        with self.assertRaisesRegex(OfflinePlanningPreviewError, "authorization"):
            self.service.preview(self.request, as_of=NOW)
        with self.assertRaisesRegex(OfflinePlanningPreviewError, "trusted clock"):
            self.service.preview(self.request, as_of="2026-09-24T12:03:00Z")

    def test_archive_tamper_is_rejected_before_preview(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["schedule"]["tasks"] = []
        self.reader.bundle = changed
        with self.assertRaisesRegex(OfflinePlanningPreviewError, "sources"):
            self.service.preview(self.request, as_of=NOW)


if __name__ == "__main__":
    unittest.main()
