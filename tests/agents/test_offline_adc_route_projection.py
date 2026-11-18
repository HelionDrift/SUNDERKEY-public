"""Synthetic ADC route projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_adc_route_projection import (
    AdcRouteProjectionError,
    AdcRouteProjectionReport,
    analyze_supplied_adc_routes,
    component_fixture,
    verify_supplied_adc_routes,
)


class AdcRouteProjectionTests(unittest.TestCase):
    def test_declared_flags_do_not_prove_behavior(self) -> None:
        report = analyze_supplied_adc_routes(component_fixture()).to_dict()
        row = report["route_projections"][0]
        self.assertTrue(row["public_to_private_declared"])
        self.assertEqual(row["declared_boundary_flags"], [
            "plaintext_declared_after_edge_termination",
            "trusted_forwarded_header_without_declared_validation",
        ])
        self.assertFalse(report["adc_configuration_inspected"])
        self.assertFalse(report["routing_behavior_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_prefix_overlap_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["routes"].append({
            "route_id": "root", "listener_id": "edge", "path_prefix": "/",
            "backend_id": "app", "upstream_tls_declared": True,
            "forwarded_header_trusted": False,
            "forwarded_header_validation_declared": False,
        })
        report = analyze_supplied_adc_routes(model).to_dict()
        self.assertEqual(report["overlapping_route_id_pairs"], [["app-route", "root"]])
        self.assertEqual(report["disposition"], "unknown")

    def test_public_listener_without_declared_tls(self) -> None:
        model = component_fixture()
        model["listeners"][0]["tls_terminated_at_edge"] = False
        model["routes"][0]["upstream_tls_declared"] = True
        model["routes"][0]["forwarded_header_trusted"] = False
        report = analyze_supplied_adc_routes(model).to_dict()
        self.assertEqual(report["route_projections"][0]["declared_boundary_flags"], [
            "public_listener_without_declared_edge_tls",
        ])

    def test_path_boundary_and_duplicate_rejection(self) -> None:
        model = component_fixture()
        model["routes"].append({
            "route_id": "apple", "listener_id": "edge", "path_prefix": "/apple",
            "backend_id": "app", "upstream_tls_declared": True,
            "forwarded_header_trusted": False,
            "forwarded_header_validation_declared": False,
        })
        self.assertEqual(
            analyze_supplied_adc_routes(model).to_dict()["overlapping_route_id_pairs"], []
        )
        model["routes"].append(copy.deepcopy(model["routes"][0]))
        with self.assertRaises(AdcRouteProjectionError):
            analyze_supplied_adc_routes(model)

    def test_rejects_unknown_backend_and_nonfixture(self) -> None:
        model = component_fixture()
        model["routes"][0]["backend_id"] = "missing"
        with self.assertRaises(AdcRouteProjectionError):
            analyze_supplied_adc_routes(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(AdcRouteProjectionError):
            analyze_supplied_adc_routes(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_adc_routes(model)
        self.assertEqual(
            verify_supplied_adc_routes(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["routes"][0]["upstream_tls_declared"] = True
        with self.assertRaises(AdcRouteProjectionError):
            verify_supplied_adc_routes(report, model=changed)
        with self.assertRaises(AdcRouteProjectionError):
            AdcRouteProjectionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
