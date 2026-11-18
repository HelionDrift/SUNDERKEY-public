"""Source-bound synthetic privilege-transition control tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_privilege_transition_controls import (
    PrivilegeTransitionControlError,
    PrivilegeTransitionControlReport,
    analyze_supplied_privilege_transitions,
    component_fixture,
    verify_supplied_privilege_transitions,
)


class PrivilegeTransitionControlTests(unittest.TestCase):
    def test_missing_gate_is_a_supplied_gap_without_escalation(self) -> None:
        body = analyze_supplied_privilege_transitions(component_fixture()).to_dict()
        self.assertEqual(body["review_gap_stage_pairs"], [["observe", "hypothesis"]])
        self.assertEqual(body["review_unknown_stage_pairs"], [["hypothesis", "review"]])
        self.assertEqual(body["disposition"], "supplied_review_gap")
        self.assertFalse(body["privileges_verified"])
        self.assertFalse(body["escalation_executed"])
        self.assertEqual(body["candidate_count"], 0)

    def test_asserted_gate_is_not_verified_authority(self) -> None:
        model = component_fixture()
        for stage in model["scenario_model"]["stages"]:
            stage["evidence_status"] = "supplied"
        for privilege in model["stage_privileges"]:
            privilege["escalation_review_status"] = "asserted"
        body = analyze_supplied_privilege_transitions(model).to_dict()
        self.assertEqual(body["disposition"], "supplied_transition_reviews_only")
        self.assertFalse(body["review_authority_verified"])

    def test_high_tier_root_and_incomplete_inventory_stay_unknown(self) -> None:
        model = component_fixture()
        model["scenario_model"]["stage_inventory_complete"] = False
        model["stage_privileges"][0]["declared_privilege_tier"] = "P2"
        model["stage_privileges"][1]["escalation_review_status"] = "asserted"
        body = analyze_supplied_privilege_transitions(model).to_dict()
        self.assertIn("root_privilege_origin_unassessed", body["uncertainty"])
        self.assertIn("supplied_stage_inventory_incomplete", body["uncertainty"])

    def test_incomplete_coverage_and_nonsynthetic_input_rejected(self) -> None:
        model = component_fixture()
        model["stage_privileges"].pop()
        with self.assertRaises(PrivilegeTransitionControlError):
            analyze_supplied_privilege_transitions(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(PrivilegeTransitionControlError):
            analyze_supplied_privilege_transitions(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_privilege_transitions(model)
        self.assertEqual(
            verify_supplied_privilege_transitions(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["stage_privileges"][1]["declared_privilege_tier"] = "P0"
        with self.assertRaises(PrivilegeTransitionControlError):
            verify_supplied_privilege_transitions(report, model=changed)
        with self.assertRaises(PrivilegeTransitionControlError):
            PrivilegeTransitionControlReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
