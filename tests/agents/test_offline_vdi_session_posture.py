"""Tests for bounded supplied VDI session metadata review."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)
from sunderkey.offline_vdi_session_posture import (
    VdiSessionPostureError,
    analyze_supplied_vdi_session_posture,
    component_fixture,
    verify_supplied_vdi_session_posture,
)

ROOT = Path(__file__).resolve().parents[2]


class VdiSessionPostureTests(unittest.TestCase):
    def test_declared_session_signals_have_no_live_effect(self) -> None:
        report = analyze_supplied_vdi_session_posture(component_fixture()).to_dict()
        self.assertEqual(report["candidate_count"], 2)
        self.assertFalse(report["remote_entry_verified"])
        self.assertFalse(report["session_started"])
        self.assertFalse(report["data_transferred"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_complete_restricted_declaration_has_no_signal(self) -> None:
        model = component_fixture()
        pool = model["pools"][0]
        pool["remote_entry_scope"] = "internal"
        pool["session_mfa_enforced"] = True
        pool["clipboard_transfer_allowed"] = False
        report = analyze_supplied_vdi_session_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["unknown_count"], 0)

    def test_incomplete_policy_and_inventory_are_unknown(self) -> None:
        model = component_fixture()
        model["pools"][0]["policy_assertions_complete"] = False
        model["inventory_complete"] = False
        report = analyze_supplied_vdi_session_posture(model).to_dict()
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["disposition"], "unknown")

    def test_closed_model_rejects_commands_bad_types_and_duplicates(self) -> None:
        model = component_fixture()
        model["pools"][0]["credential"] = "reject"
        with self.assertRaises(ValueError):
            analyze_supplied_vdi_session_posture(model)
        model = component_fixture()
        model["pools"][0]["clipboard_transfer_allowed"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_vdi_session_posture(model)
        model = component_fixture()
        model["pools"].append(copy.deepcopy(model["pools"][0]))
        with self.assertRaises(VdiSessionPostureError):
            analyze_supplied_vdi_session_posture(model)

    def test_original_model_replay_rejects_tamper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vdi_session_posture(model)
        self.assertEqual(
            verify_supplied_vdi_session_posture(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        model["pools"][0]["session_mfa_enforced"] = True
        with self.assertRaises(VdiSessionPostureError):
            verify_supplied_vdi_session_posture(report, model=model)
        with self.assertRaises(VdiSessionPostureError):
            verify_supplied_vdi_session_posture(report.to_dict(), model=component_fixture())

    def test_source_bound_catalog_dispatch(self) -> None:
        path = ROOT / "examples/offline-vdi-session-posture-component.json"
        request = json.loads(path.read_text(encoding="utf-8"))
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D16-S07")
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )


if __name__ == "__main__":
    unittest.main()
