"""Tests for bounded supplied RMM control metadata."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_rmm_control_posture import (
    RmmControlPostureError,
    analyze_supplied_rmm_control_posture,
    component_fixture,
    verify_supplied_rmm_control_posture,
)
from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)

ROOT = Path(__file__).resolve().parents[2]


class RmmControlPostureTests(unittest.TestCase):
    def test_supplied_signals_have_no_live_effect(self) -> None:
        report = analyze_supplied_rmm_control_posture(component_fixture()).to_dict()
        self.assertEqual(report["candidate_count"], 2)
        self.assertEqual(report["unknown_count"], 1)
        self.assertFalse(report["agent_fleet_contacted"])
        self.assertFalse(report["remote_command_executed"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_disabled_control_has_no_scope_signal(self) -> None:
        model = component_fixture()
        fleet = model["fleets"][0]
        fleet["remote_control_enabled"] = False
        fleet["agent_inventory_complete"] = True
        report = analyze_supplied_rmm_control_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["unknown_count"], 0)

    def test_unknown_and_incomplete_policy_remain_unknown(self) -> None:
        model = component_fixture()
        model["fleets"][0]["policy_assertions_complete"] = False
        model["inventory_complete"] = False
        report = analyze_supplied_rmm_control_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["disposition"], "unknown")

    def test_closed_model_rejects_commands_bad_types_and_duplicates(self) -> None:
        model = component_fixture()
        model["fleets"][0]["command"] = "reject"
        with self.assertRaises(ValueError):
            analyze_supplied_rmm_control_posture(model)
        model = component_fixture()
        model["fleets"][0]["approval_required"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_rmm_control_posture(model)
        model = component_fixture()
        model["fleets"].append(copy.deepcopy(model["fleets"][0]))
        with self.assertRaises(RmmControlPostureError):
            analyze_supplied_rmm_control_posture(model)

    def test_original_model_replay_rejects_tamper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_rmm_control_posture(model)
        self.assertEqual(
            verify_supplied_rmm_control_posture(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        model["fleets"][0]["approval_required"] = True
        with self.assertRaises(RmmControlPostureError):
            verify_supplied_rmm_control_posture(report, model=model)
        with self.assertRaises(RmmControlPostureError):
            verify_supplied_rmm_control_posture(report.to_dict(), model=component_fixture())

    def test_source_bound_catalog_dispatch(self) -> None:
        path = ROOT / "examples/offline-rmm-control-posture-component.json"
        request = json.loads(path.read_text(encoding="utf-8"))
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D16-S11")
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )


if __name__ == "__main__":
    unittest.main()
