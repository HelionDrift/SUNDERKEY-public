"""Supplied scenario dependency projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_threat_scenario_graph import (
    ThreatScenarioGraphError,
    ThreatScenarioGraphReport,
    analyze_supplied_threat_scenario,
    component_fixture,
    verify_supplied_threat_scenario,
)


class ThreatScenarioGraphTests(unittest.TestCase):
    def test_projects_dependencies_without_feasibility_claim(self) -> None:
        report = analyze_supplied_threat_scenario(component_fixture()).to_dict()
        self.assertEqual(report["topological_stage_ids"], ["observe", "hypothesis", "review"])
        stages = {row["stage_id"]: row for row in report["stages"]}
        self.assertEqual(
            stages["review"]["transitive_prerequisite_stage_ids"],
            ["hypothesis", "observe"],
        )
        self.assertEqual(stages["review"]["prerequisite_disposition"], "unknown")
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["scenario_executed"])
        self.assertFalse(report["positive_use_approved"])

    def test_missing_ancestor_blocks_without_approving_action(self) -> None:
        model = component_fixture()
        model["stages"][0]["evidence_status"] = "missing"
        report = analyze_supplied_threat_scenario(model).to_dict()
        stages = {row["stage_id"]: row for row in report["stages"]}
        self.assertEqual(stages["review"]["prerequisite_disposition"], "blocked_by_supplied_gap")
        self.assertEqual(report["operational_effects"]["authority"], "none")

    def test_incomplete_and_unknown_are_explicit(self) -> None:
        model = component_fixture()
        model["stage_inventory_complete"] = False
        report = analyze_supplied_threat_scenario(model).to_dict()
        self.assertEqual(report["unknown_count"], 2)
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_cycle_and_unresolved_reference(self) -> None:
        model = component_fixture()
        model["stages"][0]["prerequisite_stage_ids"] = ["review"]
        with self.assertRaises(ThreatScenarioGraphError):
            analyze_supplied_threat_scenario(model)
        model = component_fixture()
        model["stages"][0]["prerequisite_stage_ids"] = ["absent"]
        with self.assertRaises(ThreatScenarioGraphError):
            analyze_supplied_threat_scenario(model)

    def test_original_model_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_threat_scenario(model)
        self.assertEqual(
            verify_supplied_threat_scenario(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["stages"][0]["evidence_status"] = "missing"
        with self.assertRaises(ThreatScenarioGraphError):
            verify_supplied_threat_scenario(report, model=changed)
        with self.assertRaises(ThreatScenarioGraphError):
            ThreatScenarioGraphReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
