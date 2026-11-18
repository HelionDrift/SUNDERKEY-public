"""Supplied GPU instance co-tenancy projection tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_gpu_instance_tenant_boundary import (
    GpuInstanceTenantBoundaryError,
    analyze_supplied_gpu_tenant_boundary,
    component_fixture,
    verify_supplied_gpu_tenant_boundary,
    verify_supplied_gpu_tenant_boundary_bytes,
)


class GpuInstanceTenantBoundaryTests(unittest.TestCase):
    def test_mixed_tenants_are_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_gpu_tenant_boundary(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["rows"][0]["tenant_ids"], ["tenant-a", "tenant-b"])
        self.assertFalse(body["gpu_contacted"])
        self.assertFalse(body["hardware_isolation_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_gpu_tenant_boundary(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_gpu_tenant_boundary_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_single_tenant_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["gpu_instances"][0]["compute_instances"][1]["tenant_id"] = "tenant-a"
        self.assertEqual(
            analyze_supplied_gpu_tenant_boundary(model).to_dict()["candidate_count"], 0
        )
        model["inventory_complete"] = False
        self.assertEqual(
            analyze_supplied_gpu_tenant_boundary(model).to_dict()["disposition"], "unknown"
        )

    def test_rejects_duplicate_compute_instance_and_changed_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_gpu_tenant_boundary(model)
        changed = copy.deepcopy(model)
        changed["gpu_instances"][0]["compute_instances"][1]["tenant_id"] = "tenant-a"
        with self.assertRaises(GpuInstanceTenantBoundaryError):
            verify_supplied_gpu_tenant_boundary(report, model=changed)
        with self.assertRaises(GpuInstanceTenantBoundaryError):
            verify_supplied_gpu_tenant_boundary(report.to_dict(), model=model)
        with self.assertRaises(GpuInstanceTenantBoundaryError):
            verify_supplied_gpu_tenant_boundary_bytes(b"{}", model=model)
        model["gpu_instances"][0]["compute_instances"][1]["compute_instance_id"] = "ci-a"
        with self.assertRaises(GpuInstanceTenantBoundaryError):
            analyze_supplied_gpu_tenant_boundary(model)


if __name__ == "__main__":
    unittest.main()
