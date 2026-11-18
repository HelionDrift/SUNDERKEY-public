"""Supplied IOMMU group separation and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_iommu_group_separation import (
    IommuGroupSeparationError,
    analyze_supplied_iommu_groups,
    component_fixture,
    verify_supplied_iommu_groups,
    verify_supplied_iommu_groups_bytes,
)


class IommuGroupSeparationTests(unittest.TestCase):
    def test_mixed_group_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_iommu_groups(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["gaps"][0]["issue"], "mixed_protected_and_untrusted_dma_roles")
        self.assertFalse(body["hardware_contacted"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_iommu_groups(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_iommu_groups_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_separate_groups_disabled_iommu_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["devices"][1]["group_id"] = "group-8"
        self.assertEqual(analyze_supplied_iommu_groups(model).to_dict()["candidate_count"], 0)
        model["iommu_declared_enabled"] = False
        self.assertEqual(
            analyze_supplied_iommu_groups(model).to_dict()["gaps"][0]["issue"],
            "iommu_declared_disabled_with_untrusted_dma",
        )
        model["inventory_complete"] = False
        self.assertEqual(analyze_supplied_iommu_groups(model).to_dict()["unknown_count"], 1)

    def test_rejects_duplicate_device_and_unknown_role(self) -> None:
        model = component_fixture()
        model["devices"].append(copy.deepcopy(model["devices"][0]))
        with self.assertRaises(IommuGroupSeparationError):
            analyze_supplied_iommu_groups(model)
        model = component_fixture()
        model["devices"][0]["security_role"] = "administrator"
        with self.assertRaises(IommuGroupSeparationError):
            analyze_supplied_iommu_groups(model)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_iommu_groups(model)
        changed = copy.deepcopy(model)
        changed["source_id"] = "other"
        with self.assertRaises(IommuGroupSeparationError):
            verify_supplied_iommu_groups(report, model=changed)
        with self.assertRaises(IommuGroupSeparationError):
            verify_supplied_iommu_groups(report.to_dict(), model=model)
        with self.assertRaises(IommuGroupSeparationError):
            verify_supplied_iommu_groups_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()
