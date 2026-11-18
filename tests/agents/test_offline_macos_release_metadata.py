"""Synthetic macOS release metadata projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_macos_release_metadata import (
    MacosReleaseMetadataError,
    MacosReleaseMetadataReport,
    analyze_supplied_macos_releases,
    component_fixture,
    verify_supplied_macos_releases,
)


class MacosReleaseMetadataTests(unittest.TestCase):
    def test_matching_supplied_release_is_not_verification(self) -> None:
        report = analyze_supplied_macos_releases(component_fixture()).to_dict()
        self.assertEqual(report["baseline_deviation_release_ids"], [])
        self.assertFalse(report["application_inspected"])
        self.assertFalse(report["signature_verified"])
        self.assertFalse(report["entitlement_effect_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_declared_deviations_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["releases"][0]["bundle_id"] = "com.example.other"
        model["releases"][0]["team_id"] = "OTHER"
        model["releases"][0]["build"] = 19
        model["releases"][0]["entitlement_ids"] = ["unexpected"]
        report = analyze_supplied_macos_releases(model).to_dict()
        self.assertEqual(report["baseline_deviation_release_ids"], ["r21"])
        self.assertEqual(report["release_projections"][0]["declared_consistency_flags"], [
            "build_below_declared_minimum", "bundle_differs_from_baseline",
            "team_differs_from_baseline",
        ])
        self.assertEqual(
            report["release_projections"][0]["missing_required_entitlement_ids"],
            ["sandbox"],
        )
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_invalid_baseline_and_duplicate_release(self) -> None:
        model = component_fixture()
        model["baseline"]["allowed_entitlement_ids"] = []
        with self.assertRaises(MacosReleaseMetadataError):
            analyze_supplied_macos_releases(model)
        model = component_fixture()
        model["releases"].append(copy.deepcopy(model["releases"][0]))
        with self.assertRaises(MacosReleaseMetadataError):
            analyze_supplied_macos_releases(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MacosReleaseMetadataError):
            analyze_supplied_macos_releases(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_macos_releases(model)
        self.assertEqual(
            verify_supplied_macos_releases(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["releases"][0]["build"] = 19
        with self.assertRaises(MacosReleaseMetadataError):
            verify_supplied_macos_releases(report, model=changed)
        with self.assertRaises(MacosReleaseMetadataError):
            MacosReleaseMetadataReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
