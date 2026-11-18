"""Synthetic mobile distribution projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_mobile_distribution import (
    MobileDistributionError,
    MobileDistributionReport,
    analyze_supplied_mobile_distribution,
    component_fixture,
    verify_supplied_mobile_distribution,
)


class MobileDistributionTests(unittest.TestCase):
    def test_consistent_assignment_is_only_a_projection(self) -> None:
        report = analyze_supplied_mobile_distribution(component_fixture()).to_dict()
        self.assertEqual(report["inconsistent_cohort_ids"], [])
        self.assertFalse(report["signature_verified"])
        self.assertFalse(report["mdm_state_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_mismatch_and_missing_release_flags(self) -> None:
        model = component_fixture()
        model["channels"][0]["minimum_build"] = 22
        model["channels"][0]["expected_signer_sha256_hex"] = "b" * 64
        model["assignments"].append({
            "cohort_id": "staff", "channel_id": "managed", "release_id": "absent",
        })
        report = analyze_supplied_mobile_distribution(model).to_dict()
        self.assertEqual(report["inconsistent_cohort_ids"], ["pilot", "staff"])
        self.assertEqual(report["assignment_projections"][0]["declared_consistency_flags"], [
            "build_below_declared_minimum", "signer_differs_from_declared_channel",
        ])
        self.assertEqual(report["assignment_projections"][1]["declared_consistency_flags"], [
            "release_not_supplied",
        ])

    def test_incomplete_and_malformed_declarations(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        self.assertEqual(
            analyze_supplied_mobile_distribution(model).to_dict()["disposition"], "unknown"
        )
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MobileDistributionError):
            analyze_supplied_mobile_distribution(model)
        model = component_fixture()
        model["releases"][0]["signer_sha256_hex"] = "A" * 64
        with self.assertRaises(MobileDistributionError):
            analyze_supplied_mobile_distribution(model)
        model = component_fixture()
        model["assignments"].append(copy.deepcopy(model["assignments"][0]))
        with self.assertRaises(MobileDistributionError):
            analyze_supplied_mobile_distribution(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mobile_distribution(model)
        self.assertEqual(
            verify_supplied_mobile_distribution(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["releases"][0]["build"] = 19
        with self.assertRaises(MobileDistributionError):
            verify_supplied_mobile_distribution(report, model=changed)
        with self.assertRaises(MobileDistributionError):
            MobileDistributionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
