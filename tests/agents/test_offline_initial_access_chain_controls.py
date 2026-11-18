"""Source-bound synthetic initial-access chain control tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_initial_access_chain_controls import (
    InitialAccessChainControlError,
    InitialAccessChainControlReport,
    analyze_supplied_initial_access_chain,
    component_fixture,
    verify_supplied_initial_access_chain,
)


class InitialAccessChainControlTests(unittest.TestCase):
    def test_missing_evidence_blocks_dependency_closure_without_execution(self) -> None:
        body = analyze_supplied_initial_access_chain(component_fixture()).to_dict()
        self.assertEqual(body["disposition"], "supplied_chain_control_gap")
        self.assertEqual(body["gap_stage_ids"], ["review"])
        self.assertEqual(
            body["objective_dependency_stage_ids"],
            ["observe", "hypothesis", "review"],
        )
        self.assertFalse(body["authorization_verified"])
        self.assertFalse(body["chain_executed"])
        self.assertEqual(body["candidate_count"], 0)

    def test_tier_ceiling_and_missing_stop_rule_are_gaps(self) -> None:
        model = component_fixture()
        model["stage_controls"][1]["declared_tier"] = "R2"
        model["stage_controls"][1]["stop_rule_status"] = "missing"
        body = analyze_supplied_initial_access_chain(model).to_dict()
        self.assertIn("hypothesis", body["gap_stage_ids"])
        row = body["stage_control_projections"][1]
        self.assertIn("declared_tier_exceeds_supplied_ceiling", row["gap_reasons"])
        self.assertIn("stop_rule_missing", row["gap_reasons"])

    def test_unknown_inventory_and_controls_remain_unknown(self) -> None:
        model = component_fixture()
        model["scenario_model"]["stage_inventory_complete"] = False
        model["scenario_model"]["stages"][2]["evidence_status"] = "supplied"
        model["stage_controls"][1]["authorization_status"] = "unknown"
        body = analyze_supplied_initial_access_chain(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertIn("stage_inventory_incomplete", body["uncertainty"])

    def test_entry_outside_objective_dependency_is_not_a_route(self) -> None:
        model = component_fixture()
        model["scenario_model"]["stages"].append({
            "stage_id": "unrelated", "prerequisite_stage_ids": [],
            "evidence_status": "supplied",
        })
        model["stage_controls"].append({
            "stage_id": "unrelated", "declared_tier": "R0",
            "authorization_status": "asserted", "stop_rule_status": "asserted",
        })
        model["entry_stage_id"] = "unrelated"
        body = analyze_supplied_initial_access_chain(model).to_dict()
        self.assertEqual(
            body["disposition"], "entry_not_in_objective_dependency_closure"
        )
        self.assertFalse(body["entry_in_objective_dependency_closure"])

    def test_incomplete_or_nonsynthetic_controls_rejected(self) -> None:
        model = component_fixture()
        model["stage_controls"].pop()
        with self.assertRaises(InitialAccessChainControlError):
            analyze_supplied_initial_access_chain(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(InitialAccessChainControlError):
            analyze_supplied_initial_access_chain(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_initial_access_chain(model)
        self.assertEqual(
            verify_supplied_initial_access_chain(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["stage_controls"][0]["authorization_status"] = "missing"
        with self.assertRaises(InitialAccessChainControlError):
            verify_supplied_initial_access_chain(report, model=changed)
        with self.assertRaises(InitialAccessChainControlError):
            InitialAccessChainControlReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
