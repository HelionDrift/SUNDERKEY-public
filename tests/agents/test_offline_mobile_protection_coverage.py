"""Synthetic mobile protection coverage projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_mobile_protection_coverage import (
    MobileProtectionCoverageError,
    MobileProtectionCoverageReport,
    analyze_supplied_mobile_protection,
    component_fixture,
    verify_supplied_mobile_protection,
)


class MobileProtectionCoverageTests(unittest.TestCase):
    def test_variant_specific_declared_gaps_are_not_findings(self) -> None:
        report = analyze_supplied_mobile_protection(component_fixture()).to_dict()
        self.assertEqual(report["declared_coverage_gaps"], [
            {
                "variant_id": "debug", "module_id": "payment",
                "missing_declared_protection_kinds": ["integrity_check", "obfuscation"],
            },
            {
                "variant_id": "release", "module_id": "payment",
                "missing_declared_protection_kinds": ["integrity_check"],
            },
        ])
        self.assertFalse(report["binary_analyzed"])
        self.assertFalse(report["protection_effectiveness_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_full_declared_coverage_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["protections"].append({
            "protection_id": "all-integrity", "kind": "integrity_check",
            "module_ids": ["payment"], "variant_ids": ["debug", "release"],
        })
        model["protections"][0]["variant_ids"].append("debug")
        report = analyze_supplied_mobile_protection(model).to_dict()
        self.assertEqual(report["declared_coverage_gaps"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_or_duplicate_references(self) -> None:
        model = component_fixture()
        model["protections"][0]["module_ids"] = ["missing"]
        with self.assertRaises(MobileProtectionCoverageError):
            analyze_supplied_mobile_protection(model)
        model = component_fixture()
        model["protections"][0]["variant_ids"] = ["release", "release"]
        with self.assertRaises(MobileProtectionCoverageError):
            analyze_supplied_mobile_protection(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MobileProtectionCoverageError):
            analyze_supplied_mobile_protection(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mobile_protection(model)
        self.assertEqual(
            verify_supplied_mobile_protection(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["protections"][0]["variant_ids"] = ["debug"]
        with self.assertRaises(MobileProtectionCoverageError):
            verify_supplied_mobile_protection(report, model=changed)
        with self.assertRaises(MobileProtectionCoverageError):
            MobileProtectionCoverageReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
