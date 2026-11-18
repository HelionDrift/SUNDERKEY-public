"""Synthetic flash-region projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_flash_region_map import (
    FlashRegionMapError,
    FlashRegionMapReport,
    analyze_supplied_flash_regions,
    component_fixture,
    verify_supplied_flash_regions,
)


class FlashRegionMapTests(unittest.TestCase):
    def test_declared_gap_is_not_hardware_finding(self) -> None:
        report = analyze_supplied_flash_regions(component_fixture()).to_dict()
        self.assertEqual(report["declared_protection_gap_region_ids"], ["config"])
        self.assertEqual(report["declared_overlap_region_pairs"], [])
        self.assertFalse(report["flash_read_performed"])
        self.assertFalse(report["chip_off_performed"])
        self.assertFalse(report["hardware_protection_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_overlap_bounds_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["regions"][1]["offset_bytes"] = 900
        model["regions"][1]["length_bytes"] = 4000
        report = analyze_supplied_flash_regions(model).to_dict()
        self.assertEqual(report["declared_overlap_region_pairs"], [["boot", "config"]])
        self.assertEqual(report["declared_out_of_bounds_region_ids"], ["config"])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_bad_bounds_duplicate_and_nonfixture(self) -> None:
        model = component_fixture()
        model["regions"][0]["length_bytes"] = 0
        with self.assertRaises(FlashRegionMapError):
            analyze_supplied_flash_regions(model)
        model = component_fixture()
        model["regions"][1]["region_id"] = "boot"
        with self.assertRaises(FlashRegionMapError):
            analyze_supplied_flash_regions(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(FlashRegionMapError):
            analyze_supplied_flash_regions(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_flash_regions(model)
        self.assertEqual(
            verify_supplied_flash_regions(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["regions"][1]["protection_declared"] = True
        with self.assertRaises(FlashRegionMapError):
            verify_supplied_flash_regions(report, model=changed)
        with self.assertRaises(FlashRegionMapError):
            FlashRegionMapReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
