"""Supplied ownership joins are not target authorization proof."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_tenant_ownership_reconciliation import (
    TenantOwnershipReconciliation,
    TenantOwnershipReconciliationError,
    analyze_supplied_tenant_ownership,
    verify_supplied_tenant_ownership,
)


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def _model() -> dict:
    tenant_a = _ref("tenant", "a")
    tenant_b = _ref("tenant", "b")
    principal = _ref("principal", "c")
    resource_a = _ref("resource", "d")
    resource_b = _ref("resource", "e")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-tenant-ownership-reconciliation-v1",
        "tenants": [tenant_a, tenant_b],
        "memberships": [{"principal_ref": principal, "tenant_ref": tenant_a}],
        "resources": [
            {"resource_ref": resource_a, "owner_tenant_ref": tenant_a},
            {"resource_ref": resource_b, "owner_tenant_ref": tenant_b},
        ],
        "access_events": [
            {
                "event_id": "e1",
                "principal_ref": principal,
                "resource_ref": resource_a,
                "action": "read",
                "declared_allowed": True,
            },
            {
                "event_id": "e2",
                "principal_ref": principal,
                "resource_ref": resource_b,
                "action": "read",
                "declared_allowed": True,
            },
            {
                "event_id": "e3",
                "principal_ref": principal,
                "resource_ref": resource_a,
                "action": "write",
                "declared_allowed": False,
            },
        ],
    }


class TenantOwnershipReconciliationTests(unittest.TestCase):
    def test_declared_membership_and_access_outcome_are_separate(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_tenant_ownership(model)
        body = report.to_dict()
        rows = body["events"]
        self.assertTrue(rows[0]["declared_common_tenant"])
        self.assertEqual(rows[0]["anomaly_flags"], [])
        self.assertFalse(rows[1]["declared_common_tenant"])
        self.assertEqual(
            rows[1]["anomaly_flags"], ["allowed_without_declared_owner_tenant_membership"]
        )
        self.assertTrue(rows[2]["declared_common_tenant"])
        self.assertEqual(
            rows[2]["anomaly_flags"], ["denied_despite_declared_owner_tenant_membership"]
        )
        self.assertFalse(body["flags"]["authorization_defect_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_tenant_ownership(report, model=model).to_dict(), body)

    def test_maximum_event_count_has_bounded_report(self):
        model = _model()
        model["access_events"] = [
            {**model["access_events"][0], "event_id": "e" + str(index).zfill(127)}
            for index in range(512)
        ]
        report = analyze_supplied_tenant_ownership(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertLessEqual(len(report.to_json()), 1_048_576)
        self.assertEqual(
            verify_supplied_tenant_ownership(report, model=model).to_json(),
            report.to_json(),
        )

    def test_duplicate_membership_missing_resource_non_native_and_tamper_are_refused(self):
        model = _model()
        model["memberships"].append(model["memberships"][0].copy())
        with self.assertRaises(TenantOwnershipReconciliationError):
            analyze_supplied_tenant_ownership(model)
        model = _model()
        model["access_events"][0]["resource_ref"] = _ref("resource", "f")
        with self.assertRaises(TenantOwnershipReconciliationError):
            analyze_supplied_tenant_ownership(model)
        model = _model()
        model["access_events"][0]["declared_allowed"] = 1
        with self.assertRaises(TenantOwnershipReconciliationError):
            analyze_supplied_tenant_ownership(model)

        class ComparisonTrap:
            def __eq__(self, other):
                raise AssertionError("Non-native value was compared")

        model = _model()
        model["access_events"][0]["action"] = ComparisonTrap()
        with self.assertRaises(TenantOwnershipReconciliationError):
            analyze_supplied_tenant_ownership(model)
        body = analyze_supplied_tenant_ownership(_model()).to_dict()
        body["flags"]["authorization_defect_proven"] = True
        with self.assertRaises(TenantOwnershipReconciliationError):
            TenantOwnershipReconciliation(body)
        report = analyze_supplied_tenant_ownership(_model())
        model = _model()
        model["access_events"][0]["declared_allowed"] = False
        with self.assertRaises(TenantOwnershipReconciliationError):
            verify_supplied_tenant_ownership(report, model=model)


if __name__ == "__main__":
    unittest.main()
