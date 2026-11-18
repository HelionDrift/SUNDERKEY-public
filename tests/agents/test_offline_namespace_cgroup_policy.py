"""Synthetic namespace and cgroup policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_namespace_cgroup_policy import (
    NamespaceCgroupPolicyError,
    NamespaceCgroupPolicyReport,
    analyze_supplied_namespace_cgroups,
    component_fixture,
    verify_supplied_namespace_cgroups,
)


class NamespaceCgroupPolicyTests(unittest.TestCase):
    def test_declared_gap_is_not_kernel_finding(self) -> None:
        report = analyze_supplied_namespace_cgroups(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_workload_ids"], ["a", "b"])
        self.assertEqual(len(report["workload_projections"][0]["declared_policy_flags"]), 2)
        self.assertFalse(report["namespace_entered"])
        self.assertFalse(report["cgroup_modified"])
        self.assertFalse(report["process_started"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_separate_namespaces_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["workloads"][1]["namespace_id"] = "ns-beta"
        model["workloads"][0]["memory_limit_mib"] = 256
        report = analyze_supplied_namespace_cgroups(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_workload_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_tenant_bad_memory_and_nonfixture(self) -> None:
        model = component_fixture()
        model["workloads"][0]["tenant_id"] = "unknown"
        with self.assertRaises(NamespaceCgroupPolicyError):
            analyze_supplied_namespace_cgroups(model)
        model = component_fixture()
        model["workloads"][0]["memory_limit_mib"] = 0
        with self.assertRaises(NamespaceCgroupPolicyError):
            analyze_supplied_namespace_cgroups(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(NamespaceCgroupPolicyError):
            analyze_supplied_namespace_cgroups(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_namespace_cgroups(model)
        self.assertEqual(
            verify_supplied_namespace_cgroups(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["workloads"][0]["memory_limit_mib"] = 256
        with self.assertRaises(NamespaceCgroupPolicyError):
            verify_supplied_namespace_cgroups(report, model=changed)
        with self.assertRaises(NamespaceCgroupPolicyError):
            NamespaceCgroupPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
