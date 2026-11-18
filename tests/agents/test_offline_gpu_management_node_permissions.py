"""Supplied NVIDIA MIG configuration capability projection tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_gpu_management_node_permissions import (
    GpuManagementNodePermissionsError,
    analyze_supplied_gpu_management_node_permissions,
    component_fixture,
    verify_supplied_gpu_management_node_permissions,
    verify_supplied_gpu_management_node_permissions_bytes,
)


class GpuManagementNodePermissionsTests(unittest.TestCase):
    def test_devfs_grant_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_gpu_management_node_permissions(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["mismatches"][0]["issue"], "unexpected_capability_grant")
        self.assertTrue(body["rows"][0]["projected_mig_config_capability"])
        self.assertFalse(body["gpu_contacted"])
        self.assertFalse(body["device_nodes_inspected"])
        self.assertFalse(body["management_action_performed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_gpu_management_node_permissions(
                report, model=model
            ).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_gpu_management_node_permissions_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_devfs_denial_and_privileged_override(self) -> None:
        model = component_fixture()
        row = model["principals"][0]
        row["grant"]["cgroup_device_read"] = False
        self.assertEqual(
            analyze_supplied_gpu_management_node_permissions(model)
            .to_dict()["candidate_count"],
            0,
        )
        row["root_or_cap_sys_admin"] = True
        self.assertEqual(
            analyze_supplied_gpu_management_node_permissions(model)
            .to_dict()["candidate_count"],
            1,
        )
        row["expected_capability"] = True
        self.assertEqual(
            analyze_supplied_gpu_management_node_permissions(model)
            .to_dict()["candidate_count"],
            0,
        )

    def test_procfs_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["interface"] = "procfs"
        model["principals"][0]["grant"] = {
            "proc_capability_visible": True,
            "proc_capability_read": False,
        }
        report = analyze_supplied_gpu_management_node_permissions(model).to_dict()
        self.assertFalse(report["rows"][0]["projected_mig_config_capability"])
        self.assertEqual(report["candidate_count"], 0)
        model["principals"][0]["grant"]["proc_capability_read"] = True
        self.assertEqual(
            analyze_supplied_gpu_management_node_permissions(model)
            .to_dict()["candidate_count"],
            1,
        )
        model["inventory_complete"] = False
        report = analyze_supplied_gpu_management_node_permissions(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["unknown_count"], 1)

    def test_rejects_invalid_models_and_changed_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_gpu_management_node_permissions(model)
        changed = copy.deepcopy(model)
        changed["principals"][0]["grant"]["device_node_read"] = False
        with self.assertRaises(GpuManagementNodePermissionsError):
            verify_supplied_gpu_management_node_permissions(report, model=changed)
        with self.assertRaises(GpuManagementNodePermissionsError):
            verify_supplied_gpu_management_node_permissions(report.to_dict(), model=model)
        with self.assertRaises(GpuManagementNodePermissionsError):
            verify_supplied_gpu_management_node_permissions_bytes(b"{}", model=model)
        model["principals"].append(copy.deepcopy(model["principals"][0]))
        with self.assertRaises(GpuManagementNodePermissionsError):
            analyze_supplied_gpu_management_node_permissions(model)

    def test_rejects_wrong_interface_grant_and_non_boolean(self) -> None:
        model = component_fixture()
        model["principals"][0]["grant"]["proc_capability_visible"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_gpu_management_node_permissions(model)
        model = component_fixture()
        model["principals"][0]["grant"]["device_node_read"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_gpu_management_node_permissions(model)


if __name__ == "__main__":
    unittest.main()
