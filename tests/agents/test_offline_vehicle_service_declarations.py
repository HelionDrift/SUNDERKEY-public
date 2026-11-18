"""Supplied vehicle service declarations remain bounded and inert."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_vehicle_service_declarations import (
    VehicleServiceDeclarationsError,
    analyze_supplied_vehicle_service_declarations,
    component_fixture,
    verify_supplied_vehicle_service_declarations,
    verify_supplied_vehicle_service_declarations_bytes,
)


class VehicleServiceDeclarationsTests(unittest.TestCase):
    def test_claim_conflict_is_a_nonqualifying_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vehicle_service_declarations(model)
        value = report.to_dict()
        self.assertEqual(value["candidate_count"], 1)
        self.assertEqual(value["unknown_count"], 0)
        self.assertEqual(value["rows"][0]["reasons"], ["route_declared_denied"])
        self.assertEqual(value["rows"][0]["disposition"], "candidate_claim_conflict")
        self.assertFalse(value["finding_claimed"])
        self.assertFalse(value["positive_use_approved"])
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_vehicle_service_declarations(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_vehicle_service_declarations_bytes(
                report.to_json().encode("utf-8"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_complete_matching_claim_is_only_a_supplied_consistency_result(self) -> None:
        model = component_fixture()
        model["consumers"][0]["claimed_allowed"] = False
        value = analyze_supplied_vehicle_service_declarations(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(value["rows"][0]["disposition"], "supplied_claim_consistent")
        self.assertFalse(value["vehicle_contacted"])
        self.assertFalse(value["someip_message_parsed"])

    def test_incomplete_route_or_service_context_remains_unknown(self) -> None:
        model = component_fixture()
        model["routes"] = []
        model["route_inventory_complete"] = False
        value = analyze_supplied_vehicle_service_declarations(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(value["unknown_count"], 1)
        self.assertIsNone(value["rows"][0]["projected_allowed"])
        model["services"] = []
        model["service_inventory_complete"] = False
        value = analyze_supplied_vehicle_service_declarations(model).to_dict()
        self.assertEqual(value["unknown_count"], 1)

    def test_closed_model_and_duplicate_route_reject(self) -> None:
        model = component_fixture()
        model["unexpected"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_vehicle_service_declarations(model)
        model = component_fixture()
        model["routes"].append(copy.deepcopy(model["routes"][0]))
        with self.assertRaises(VehicleServiceDeclarationsError):
            analyze_supplied_vehicle_service_declarations(model)

    def test_replay_rejects_mutated_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vehicle_service_declarations(model)
        model["routes"][0]["allowed"] = True
        with self.assertRaises(VehicleServiceDeclarationsError):
            verify_supplied_vehicle_service_declarations(report, model=model)


if __name__ == "__main__":
    unittest.main()
