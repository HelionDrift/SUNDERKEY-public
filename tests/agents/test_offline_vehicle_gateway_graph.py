"""Tests for the inert supplied vehicle gateway graph projection."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_vehicle_gateway_graph import (
    VehicleGatewayGraphError,
    analyze_supplied_vehicle_gateway_graph,
    component_fixture,
    verify_supplied_vehicle_gateway_graph,
    verify_supplied_vehicle_gateway_graph_bytes,
)


class VehicleGatewayGraphTests(unittest.TestCase):
    def test_missing_allowance_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vehicle_gateway_graph(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["mismatches"][0]["issue"], "missing_declared_allowance")
        self.assertFalse(body["vehicle_contacted"])
        self.assertFalse(body["gateway_policy_applied"])
        self.assertFalse(body["actual_vehicle_behavior_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_vehicle_gateway_graph(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_vehicle_gateway_graph_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_directed_gateway_rule_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["allowed_flows"] = [{
            "rule_id": "status-allowance",
            "source_segment": "connected",
            "destination_segment": "internal",
            "channel_id": "status",
            "gateway_id": "boundary-gateway",
        }]
        body = analyze_supplied_vehicle_gateway_graph(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["rows"][0]["matching_rule_ids"], ["status-allowance"])
        model["flows"][0]["source_interface"] = "subsystem-if"
        model["flows"][0]["destination_interface"] = "telemetry-if"
        body = analyze_supplied_vehicle_gateway_graph(model).to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["rows"][0]["matching_rule_ids"], [])
        model["inventory_complete"] = False
        body = analyze_supplied_vehicle_gateway_graph(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        self.assertIsNone(body["rows"][0]["projected_allowed"])
        self.assertEqual(body["rows"][0]["row_disposition"], "unknown_incomplete_inventory")
        self.assertEqual(body["mismatches"], [])

    def test_dense_matching_rules_fit_report_bound(self) -> None:
        model = component_fixture()
        model["allowed_flows"] = [
            {
                "rule_id": f"rule-{index:03d}-" + "x" * 48,
                "source_segment": "connected",
                "destination_segment": "internal",
                "channel_id": "status",
                "gateway_id": "boundary-gateway",
            }
            for index in range(128)
        ]
        model["flows"] = [
            {**model["flows"][0], "flow_id": f"flow-{index:03d}"}
            for index in range(128)
        ]
        report = analyze_supplied_vehicle_gateway_graph(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["flow_count"], 128)
        self.assertEqual(body["rows"][0]["matching_rule_count"], 128)
        self.assertEqual(len(body["rows"][0]["matching_rule_ids"]), 1)
        self.assertTrue(body["rows"][0]["matching_rule_ids_truncated"])
        self.assertEqual(
            verify_supplied_vehicle_gateway_graph(report, model=model).to_json(),
            report.to_json(),
        )

    def test_same_segment_requires_explicit_allowance(self) -> None:
        model = component_fixture()
        model["flows"][0]["destination_interface"] = "gateway-in"
        self.assertEqual(
            analyze_supplied_vehicle_gateway_graph(model).to_dict()["candidate_count"], 1
        )
        model["allowed_flows"] = [{
            "rule_id": "local-status",
            "source_segment": "connected",
            "destination_segment": "connected",
            "channel_id": "status",
            "gateway_id": None,
        }]
        self.assertEqual(
            analyze_supplied_vehicle_gateway_graph(model).to_dict()["candidate_count"], 0
        )

    def test_rejects_invalid_graph_and_changed_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_vehicle_gateway_graph(model)
        changed = copy.deepcopy(model)
        changed["flows"][0]["channel_id"] = "different"
        with self.assertRaises(VehicleGatewayGraphError):
            verify_supplied_vehicle_gateway_graph(report, model=changed)
        with self.assertRaises(VehicleGatewayGraphError):
            verify_supplied_vehicle_gateway_graph(report.to_dict(), model=model)
        with self.assertRaises(VehicleGatewayGraphError):
            verify_supplied_vehicle_gateway_graph_bytes(b"{}", model=model)
        model["gateways"][0]["egress_interface"] = "telemetry-if"
        with self.assertRaises(VehicleGatewayGraphError):
            analyze_supplied_vehicle_gateway_graph(model)

    def test_closed_input_and_export(self) -> None:
        model = component_fixture()
        model["flows"][0]["extra"] = "not-declared"
        with self.assertRaises(ValueError):
            analyze_supplied_vehicle_gateway_graph(model)
        model = component_fixture()
        report = analyze_supplied_vehicle_gateway_graph(model)
        exported = json.loads(report.to_json())
        exported["candidate_count"] = 0
        with self.assertRaises(VehicleGatewayGraphError):
            verify_supplied_vehicle_gateway_graph_bytes(
                json.dumps(exported).encode(), model=model
            )
        with self.assertRaises(ValueError):
            verify_supplied_vehicle_gateway_graph_bytes(
                b'{"schema_version":1,"schema_version":1}', model=model
            )


if __name__ == "__main__":
    unittest.main()
