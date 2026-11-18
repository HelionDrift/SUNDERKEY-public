"""Supplied vehicle diagnostic policy projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_vehicle_diagnostic_policy import (
    VehicleDiagnosticPolicyError,
    analyze_supplied_vehicle_diagnostic_policy,
    component_fixture,
    verify_supplied_vehicle_diagnostic_policy,
    verify_supplied_vehicle_diagnostic_policy_bytes,
)


class VehicleDiagnosticPolicyTests(unittest.TestCase):
    def test_missing_local_control_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vehicle_diagnostic_policy(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["rows"][0]["missing_required_controls"], ["supervised"])
        self.assertFalse(body["vehicle_or_network_contacted"])
        self.assertFalse(body["protocol_message_generated"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_vehicle_diagnostic_policy(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_vehicle_diagnostic_policy_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_policy_match_is_not_operational_approval(self) -> None:
        model = component_fixture()
        model["declarations"][0]["controls"].append("supervised")
        body = analyze_supplied_vehicle_diagnostic_policy(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertTrue(body["rows"][0]["computed_policy_match"])
        self.assertFalse(body["positive_use_approved"])
        self.assertFalse(body["vehicle_state_or_service_effect_verified"])

    def test_actor_session_target_and_service_gates(self) -> None:
        for field, replacement, gate in (
            ("actor_role", "unknown-role", "actor_role_listed"),
            ("session_label", "unknown-session", "session_label_listed"),
            ("target_id", "unknown-target", "target_id_listed"),
            ("service_class", "state_change", "service_class_listed"),
        ):
            with self.subTest(field=field):
                model = component_fixture()
                model["declarations"][0]["controls"].append("supervised")
                model["declarations"][0][field] = replacement
                body = analyze_supplied_vehicle_diagnostic_policy(model).to_dict()
                self.assertFalse(body["rows"][0][gate])
                self.assertEqual(body["candidate_count"], 1)

    def test_incomplete_inventory_and_closed_bounded_model(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        body = analyze_supplied_vehicle_diagnostic_policy(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        self.assertIsNone(body["rows"][0]["computed_policy_match"])
        self.assertIsNone(body["rows"][0]["actor_role_listed"])
        self.assertIsNone(body["rows"][0]["missing_required_controls"])
        self.assertEqual(body["rows"][0]["row_disposition"], "unknown_incomplete_inventory")
        self.assertEqual(body["mismatches"], [])
        for alteration in (
            lambda item: item["policy"]["required_controls"].remove("approved_scope"),
            lambda item: item["declarations"].append(copy.deepcopy(item["declarations"][0])),
            lambda item: item["declarations"][0]["context_tags"].append("raw_payload"),
            lambda item: item["declarations"][0].update({"message_bytes": "00"}),
        ):
            invalid = component_fixture()
            alteration(invalid)
            with self.assertRaises(ValueError):
                analyze_supplied_vehicle_diagnostic_policy(invalid)

    def test_original_change_and_forged_report_fail(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vehicle_diagnostic_policy(model)
        changed = copy.deepcopy(model)
        changed["declarations"][0]["target_id"] = "simulated-module-b"
        with self.assertRaises(VehicleDiagnosticPolicyError):
            verify_supplied_vehicle_diagnostic_policy(report, model=changed)
        with self.assertRaises(VehicleDiagnosticPolicyError):
            verify_supplied_vehicle_diagnostic_policy(report.to_dict(), model=model)
        with self.assertRaises(VehicleDiagnosticPolicyError):
            verify_supplied_vehicle_diagnostic_policy_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()
