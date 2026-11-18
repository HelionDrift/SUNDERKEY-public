"""Tests for bounded supplied hypervisor management metadata review."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_hypervisor_management_posture import (
    HypervisorManagementPostureError,
    analyze_supplied_hypervisor_management_posture,
    component_fixture,
    verify_supplied_hypervisor_management_posture,
)
from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)

ROOT = Path(__file__).resolve().parents[2]


class HypervisorManagementPostureTests(unittest.TestCase):
    def test_declared_management_signals_have_no_live_effect(self) -> None:
        report = analyze_supplied_hypervisor_management_posture(component_fixture()).to_dict()
        self.assertEqual(report["candidate_count"], 3)
        self.assertFalse(report["reachability_verified"])
        self.assertFalse(report["hypervisor_contacted"])
        self.assertFalse(report["vm_state_changed"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_complete_restricted_declaration_has_no_signal(self) -> None:
        model = component_fixture()
        manager = model["managers"][0]
        manager["management_reachability"] = "internal"
        manager["admin_mfa_enforced"] = True
        manager["snapshot_mutation_role_scope"] = "restricted"
        report = analyze_supplied_hypervisor_management_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["unknown_count"], 0)

    def test_incomplete_scope_and_inventory_are_unknown(self) -> None:
        model = component_fixture()
        model["managers"][0]["scope_assertions_complete"] = False
        model["inventory_complete"] = False
        report = analyze_supplied_hypervisor_management_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["disposition"], "unknown")

    def test_closed_model_rejects_commands_bad_types_and_duplicates(self) -> None:
        model = component_fixture()
        model["managers"][0]["command"] = "reject"
        with self.assertRaises(ValueError):
            analyze_supplied_hypervisor_management_posture(model)
        model = component_fixture()
        model["managers"][0]["admin_mfa_enforced"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_hypervisor_management_posture(model)
        model = component_fixture()
        model["managers"].append(copy.deepcopy(model["managers"][0]))
        with self.assertRaises(HypervisorManagementPostureError):
            analyze_supplied_hypervisor_management_posture(model)

    def test_original_model_replay_rejects_tamper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_hypervisor_management_posture(model)
        self.assertEqual(
            verify_supplied_hypervisor_management_posture(
                report, model=copy.deepcopy(model)
            ).to_json(),
            report.to_json(),
        )
        model["managers"][0]["admin_mfa_enforced"] = True
        with self.assertRaises(HypervisorManagementPostureError):
            verify_supplied_hypervisor_management_posture(report, model=model)
        with self.assertRaises(HypervisorManagementPostureError):
            verify_supplied_hypervisor_management_posture(
                report.to_dict(), model=component_fixture()
            )

    def test_source_bound_catalog_dispatch(self) -> None:
        path = ROOT / "examples/offline-hypervisor-management-posture-component.json"
        request = json.loads(path.read_text(encoding="utf-8"))
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D16-S06")
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )


if __name__ == "__main__":
    unittest.main()
