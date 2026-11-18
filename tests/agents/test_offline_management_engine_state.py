"""Supplied AMT control-state policy and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_management_engine_state import (
    ManagementEngineStateError,
    analyze_supplied_management_engine_state,
    component_fixture,
    verify_supplied_management_engine_state,
    verify_supplied_management_engine_state_bytes,
)


class ManagementEngineStateTests(unittest.TestCase):
    def test_tls_policy_gap_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_management_engine_state(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["gaps"][0]["issue"], "network_policy_tls_mismatch")
        self.assertFalse(body["management_engine_contacted"])
        self.assertFalse(body["network_reachability_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_management_engine_state(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_management_engine_state_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_policy_and_control_state_cases(self) -> None:
        model = component_fixture()
        platform = model["platforms"][0]
        platform["tls_enabled"] = True
        self.assertEqual(
            analyze_supplied_management_engine_state(model).to_dict()["candidate_count"], 0
        )
        platform["provisioning_state"] = "unconfigured"
        self.assertEqual(
            analyze_supplied_management_engine_state(model).to_dict()["gaps"][0]["issue"],
            "control_mode_state_mismatch",
        )
        platform["control_mode"] = "none"
        platform["network_policy"] = "disabled"
        self.assertEqual(
            analyze_supplied_management_engine_state(model).to_dict()["gaps"][0]["issue"],
            "network_policy_disabled_mismatch",
        )
        platform["network_interface_enabled"] = False
        self.assertEqual(
            analyze_supplied_management_engine_state(model).to_dict()["candidate_count"], 0
        )
        model["inventory_complete"] = False
        body = analyze_supplied_management_engine_state(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["unknown_count"], 1)

    def test_rejects_duplicate_and_non_native_or_extra_fields(self) -> None:
        model = component_fixture()
        model["platforms"].append(copy.deepcopy(model["platforms"][0]))
        with self.assertRaises(ManagementEngineStateError):
            analyze_supplied_management_engine_state(model)
        for field, value in (
            ("network_interface_enabled", 1),
            ("tls_enabled", "true"),
            ("control_mode", "admin"),
            ("network_policy", "unknown"),
        ):
            model = component_fixture()
            model["platforms"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                analyze_supplied_management_engine_state(model)
        model = component_fixture()
        model["platforms"][0]["target_address"] = "192.0.2.1"
        with self.assertRaises(ValueError):
            analyze_supplied_management_engine_state(model)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_management_engine_state(model)
        changed = copy.deepcopy(model)
        changed["platforms"][0]["tls_enabled"] = True
        with self.assertRaises(ManagementEngineStateError):
            verify_supplied_management_engine_state(report, model=changed)
        with self.assertRaises(ManagementEngineStateError):
            verify_supplied_management_engine_state(report.to_dict(), model=model)
        with self.assertRaises(ManagementEngineStateError):
            verify_supplied_management_engine_state_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_management_engine_state_bytes(
                report.to_json().encode() + b" ", model=changed
            )

    def test_bounded_platforms(self) -> None:
        model = component_fixture()
        model["platforms"] = [
            {**model["platforms"][0], "platform_id": f"platform-{i}"}
            for i in range(65)
        ]
        with self.assertRaises(ValueError):
            analyze_supplied_management_engine_state(model)


if __name__ == "__main__":
    unittest.main()
