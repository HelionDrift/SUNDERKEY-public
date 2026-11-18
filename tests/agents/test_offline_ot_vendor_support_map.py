"""Synthetic OT vendor path declarations remain unverified review cues."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ot_vendor_support_map import (
    OtVendorSupportMapError,
    OtVendorSupportMapReport,
    analyze_supplied_ot_vendor_support_map,
    component_fixture,
    verify_supplied_ot_vendor_support_map,
)


class OtVendorSupportMapTests(unittest.TestCase):
    def test_shared_asset_and_missing_controls_are_review_cues(self) -> None:
        model = component_fixture()
        body = analyze_supplied_ot_vendor_support_map(model).to_dict()
        self.assertEqual(body["vendor_count"], 2)
        self.assertEqual(body["asset_count"], 2)
        self.assertEqual(body["support_path_count"], 2)
        self.assertEqual(len(body["shared_asset_id_sha256"]), 1)
        self.assertEqual(body["review_cue_count"], 1)
        self.assertFalse(body["network_reachability_verified"])
        self.assertFalse(body["safety_boundary_verified"])
        self.assertFalse(body["finding_claimed"])
        self.assertNotIn("vendor-a", str(body))

    def test_unknown_endpoint_and_duplicate_path_reject(self) -> None:
        model = component_fixture()
        model["support_paths"][0]["asset_id"] = "not-an-asset"
        with self.assertRaises(OtVendorSupportMapError):
            analyze_supplied_ot_vendor_support_map(model)
        model = component_fixture()
        model["support_paths"][1]["path_id"] = "path-a"
        with self.assertRaises(OtVendorSupportMapError):
            analyze_supplied_ot_vendor_support_map(model)

    def test_invalid_control_type_and_nonsynthetic_source_reject(self) -> None:
        model = component_fixture()
        model["support_paths"][0]["time_bounded"] = "yes"
        with self.assertRaises(OtVendorSupportMapError):
            analyze_supplied_ot_vendor_support_map(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(OtVendorSupportMapError):
            analyze_supplied_ot_vendor_support_map(model)

    def test_replay_requires_separate_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ot_vendor_support_map(model)
        self.assertEqual(
            verify_supplied_ot_vendor_support_map(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["support_paths"][1]["session_monitored"] = True
        with self.assertRaises(OtVendorSupportMapError):
            verify_supplied_ot_vendor_support_map(report, model=changed)
        with self.assertRaises(OtVendorSupportMapError):
            OtVendorSupportMapReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
