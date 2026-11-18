"""Synthetic SIS/BPCS tests preserve physical safety uncertainty."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_sis_bpcs_resource_projection import (
    SisBpcsResourceProjectionError,
    SisBpcsResourceProjectionReport,
    analyze_supplied_sis_bpcs_resource_projection,
    component_fixture,
    verify_supplied_sis_bpcs_resource_projection,
)


class SisBpcsResourceProjectionTests(unittest.TestCase):
    def test_shared_declaration_is_not_safety_finding(self) -> None:
        report = analyze_supplied_sis_bpcs_resource_projection(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["declared_shared_resource_count"], 1)
        self.assertEqual(body["declared_shared_resources"][0]["sis_role"], "sensors")
        self.assertFalse(body["design_independence_verified"])
        self.assertFalse(body["functional_safety_verified"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertNotIn("shared-sensor-1", report.to_json())

    def test_no_overlap_still_does_not_prove_independence(self) -> None:
        model = component_fixture()
        model["bpcs"]["sensors"][1] = "separate-sensor-2"
        body = analyze_supplied_sis_bpcs_resource_projection(model).to_dict()
        self.assertEqual(body["declared_shared_resource_count"], 0)
        self.assertFalse(body["design_independence_verified"])
        self.assertEqual(body["disposition"], "unknown")

    def test_missing_duplicate_and_nonsynthetic_declaration_rejected(self) -> None:
        model = component_fixture()
        model["sis"]["logic_solvers"] = []
        with self.assertRaises(SisBpcsResourceProjectionError):
            analyze_supplied_sis_bpcs_resource_projection(model)
        model = component_fixture()
        model["sis"]["logic_solvers"] = ["sis-sensor-1"]
        with self.assertRaises(SisBpcsResourceProjectionError):
            analyze_supplied_sis_bpcs_resource_projection(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(SisBpcsResourceProjectionError):
            analyze_supplied_sis_bpcs_resource_projection(model)

    def test_replay_requires_separate_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_sis_bpcs_resource_projection(model)
        self.assertEqual(
            verify_supplied_sis_bpcs_resource_projection(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["bpcs"]["final_elements"] = ["changed-final"]
        with self.assertRaises(SisBpcsResourceProjectionError):
            verify_supplied_sis_bpcs_resource_projection(report, model=changed)
        with self.assertRaises(SisBpcsResourceProjectionError):
            SisBpcsResourceProjectionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
