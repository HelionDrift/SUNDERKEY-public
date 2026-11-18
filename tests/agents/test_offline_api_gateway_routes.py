"""Finite route projection and adversarial source/replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_api_gateway_routes as analysis


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class ApiGatewayRoutesTests(unittest.TestCase):
    def test_fixture_identity_replay_and_effects(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_api_gateway_routes(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S07")
        self.assertEqual(document["capability_id"], "army.gb.d06.s07")
        self.assertEqual(document["vector_id"], "AV-GB-D06-S07-01")
        self.assertEqual(document["source"]["source_id"], "synthetic-gateway-model")
        self.assertEqual(document["source"]["route_table"]["source_id"], "synthetic-route-table")
        self.assertTrue(document["report_id"].startswith("AGR-"))
        self.assertTrue(document["report_sha256"].startswith("sha256:"))
        self.assertFalse(document["gateway_behavior_verified"])
        self.assertIsNone(document["auth_bypass_verdict"])
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(
            analysis.ApiGatewayRoutesReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.ApiGatewayRoutesReport.from_dict(document).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_api_gateway_routes(report, model=model).to_json(),
            report.to_json(),
        )
        other = analysis.component_fixture()
        other["probes"]["requests"].clear()
        self.assertNotEqual(other, model)

    def test_first_match_shadowing_and_declared_policy_candidates(self):
        document = analysis.analyze_supplied_api_gateway_routes(
            analysis.component_fixture()
        ).to_dict()
        self.assertEqual(document["route_order"], ["admin-route", "api-prefix", "deep-prefix"])
        self.assertEqual(
            [row["selected_route_id"] for row in document["selections"]],
            ["admin-route", "api-prefix", None],
        )
        self.assertEqual(
            document["selections"][0]["matched_route_ids"],
            ["admin-route", "api-prefix"],
        )
        self.assertEqual(
            document["shadowed_routes"],
            [{"route_id": "deep-prefix", "prior_superset_route_ids": ["api-prefix"]}],
        )
        candidates = document["declared_policy_disparity_candidates"]
        self.assertEqual(len(candidates), 2)
        self.assertEqual(
            [(row["earlier_route_id"], row["later_route_id"]) for row in candidates],
            [("admin-route", "api-prefix"), ("api-prefix", "deep-prefix")],
        )
        self.assertEqual(candidates[0]["witness"]["path"], "/api/admin")
        self.assertEqual(candidates[1]["witness_selected_route_id"], "api-prefix")

    def test_priority_tie_uses_declaration_order(self):
        model = analysis.component_fixture()
        routes = model["route_table"]["routes"]
        routes[1]["priority"] = 20
        document = analysis.analyze_supplied_api_gateway_routes(model).to_dict()
        self.assertEqual(document["route_order"][:2], ["admin-route", "api-prefix"])
        self.assertEqual(document["selections"][0]["selected_route_id"], "admin-route")
        routes[0], routes[1] = routes[1], routes[0]
        document = analysis.analyze_supplied_api_gateway_routes(model).to_dict()
        self.assertEqual(document["route_order"][:2], ["api-prefix", "admin-route"])
        self.assertEqual(document["selections"][0]["selected_route_id"], "api-prefix")
        self.assertEqual(document["shadowed_routes"][0]["route_id"], "admin-route")

    def test_literal_prefix_is_not_segment_matching(self):
        model = analysis.component_fixture()
        model["probes"]["requests"] = [
            {"request_id": "literal", "host": "example.invalid", "method": "GET", "path": "/apix"}
        ]
        row = analysis.analyze_supplied_api_gateway_routes(model).to_dict()["selections"][0]
        self.assertEqual(row["selected_route_id"], "api-prefix")

    def test_different_host_method_and_disjoint_paths_do_not_overlap(self):
        model = analysis.component_fixture()
        routes = model["route_table"]["routes"]
        routes[1]["host"] = "other.invalid"
        routes[2]["method"] = "POST"
        document = analysis.analyze_supplied_api_gateway_routes(model).to_dict()
        self.assertEqual(document["shadowed_routes"], [])
        self.assertEqual(document["declared_policy_disparity_candidates"], [])
        self.assertEqual(document["selections"][0]["matched_route_ids"], ["admin-route"])
        routes[1]["host"] = "example.invalid"
        routes[1]["path"] = "/other"
        routes[2]["method"] = "GET"
        routes[2]["path"] = "/elsewhere"
        document = analysis.analyze_supplied_api_gateway_routes(model).to_dict()
        self.assertEqual(document["shadowed_routes"], [])
        self.assertEqual(document["declared_policy_disparity_candidates"], [])

    def test_same_policy_overlap_does_not_create_disparity(self):
        model = analysis.component_fixture()
        for route in model["route_table"]["routes"]:
            route["auth_policy_ref"] = "general-policy"
        document = analysis.analyze_supplied_api_gateway_routes(model).to_dict()
        self.assertEqual(document["declared_policy_disparity_candidates"], [])
        self.assertEqual(len(document["shadowed_routes"]), 1)

    def test_witness_selection_accounts_for_all_routes(self):
        model = analysis.component_fixture()
        model["route_table"]["routes"].insert(
            0,
            {
                "route_id": "deep-exact",
                "host": "example.invalid",
                "method": "GET",
                "path_kind": "exact",
                "path": "/api/deep",
                "priority": 30,
                "backend_ref": "admin-backend",
                "auth_policy_ref": "admin-policy",
            },
        )
        document = analysis.analyze_supplied_api_gateway_routes(model).to_dict()
        rows = [
            row
            for row in document["declared_policy_disparity_candidates"]
            if row["earlier_route_id"] == "api-prefix" and row["later_route_id"] == "deep-prefix"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["witness_selected_route_id"], "deep-exact")

    def test_bytes_duplicate_keys_rejected_at_every_level(self):
        model = analysis.component_fixture()
        original = analysis.analyze_supplied_api_gateway_routes(model).to_json()
        parsed = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.analyze_supplied_api_gateway_routes_bytes(model_bytes=parsed.encode("ascii"))
        parsed = canonical(model).replace('"priority":20', '"priority":20,"priority":21')
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.analyze_supplied_api_gateway_routes_bytes(model_bytes=parsed.encode("ascii"))
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.ApiGatewayRoutesReport.from_json(
                original.replace('"offline_only":true', '"offline_only":true,"offline_only":false')
            )

    def test_rewrite_normalization_and_ambiguous_paths_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        for field, value in (("rewrite", "strip_prefix"), ("normalization", "lowercase")):
            model = copy.deepcopy(base)
            model["route_table"][field] = value
            bad_models.append(model)
        for path in ("/a/../b", "/a//b", "/a%2Fb", "/a?x=1", "\\api", "api"):
            model = copy.deepcopy(base)
            model["route_table"]["routes"][0]["path"] = path
            bad_models.append(model)
        model = copy.deepcopy(base)
        model["probes"]["requests"][0]["host"] = "EXAMPLE.INVALID"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["probes"]["requests"][0]["host"] = "example.invalid:443"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["probes"]["requests"][0]["host"] = "a.-b"
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ApiGatewayRoutesError):
                    analysis.analyze_supplied_api_gateway_routes(model)

    def test_duplicate_and_unknown_identifiers_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["route_table"]["routes"][1]["route_id"] = "admin-route"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_table"]["routes"][1]["path_kind"] = "exact"
        model["route_table"]["routes"][1]["path"] = "/api/admin"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_table"]["backends"].append("general-backend")
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_table"]["routes"][0]["auth_policy_ref"] = "missing"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["probes"]["requests"][1]["request_id"] = "admin"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["probes"]["source_id"] = model["route_table"]["source_id"]
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ApiGatewayRoutesError):
                    analysis.analyze_supplied_api_gateway_routes(model)

    def test_native_type_and_boundaries_fail_closed(self):
        base = analysis.component_fixture()
        for priority in (True, -1, 10_001, 1.5):
            model = copy.deepcopy(base)
            model["route_table"]["routes"][0]["priority"] = priority
            with self.subTest(priority=priority):
                with self.assertRaises(analysis.ApiGatewayRoutesError):
                    analysis.analyze_supplied_api_gateway_routes(model)
        model = copy.deepcopy(base)
        model["unknown"] = True
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.analyze_supplied_api_gateway_routes(model)
        model = copy.deepcopy(base)
        model["route_table"]["routes"] *= analysis.MAX_ROUTES
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.analyze_supplied_api_gateway_routes(model)
        model = copy.deepcopy(base)
        model["probes"]["requests"] *= analysis.MAX_REQUESTS
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.analyze_supplied_api_gateway_routes(model)
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.analyze_supplied_api_gateway_routes_bytes(model_bytes=b"\xff")

    def test_report_tamper_and_separate_source_mismatch(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_api_gateway_routes(model)
        changed = report.to_dict()
        changed["gateway_behavior_verified"] = True
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.ApiGatewayRoutesReport.from_dict(changed)
        changed = report.to_dict()
        changed["selections"][0]["selected_route_id"] = "api-prefix"
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.ApiGatewayRoutesReport.from_json(canonical(changed))
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.ApiGatewayRoutesReport.from_json(" " + report.to_json())
        other = copy.deepcopy(model)
        other["route_table"]["routes"][0]["backend_ref"] = "general-backend"
        with self.assertRaises(analysis.ApiGatewayRoutesError):
            analysis.verify_supplied_api_gateway_routes(report, model=other)

    def test_no_network_process_or_credential_resolution(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            report = analysis.analyze_supplied_api_gateway_routes(analysis.component_fixture())
            self.assertEqual(report.to_dict()["effects"]["credential_resolution"], "none")


if __name__ == "__main__":
    unittest.main()
