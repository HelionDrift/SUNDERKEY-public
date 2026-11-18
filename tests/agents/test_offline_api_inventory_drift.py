"""Supplied API inventory drift, uncertainty, and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_api_inventory_drift as analysis


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class ApiInventoryDriftTests(unittest.TestCase):
    def test_fixture_source_addresses_replay_and_no_effects(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_api_inventory_drift(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S14")
        self.assertEqual(document["capability_id"], "army.gb.d06.s14")
        self.assertEqual(document["vector_id"], "AV-GB-D06-S14-01")
        self.assertEqual(document["source"]["source_id"], "synthetic-api-drift")
        self.assertEqual(
            document["source"]["approved_inventory"]["source_id"],
            "approved-inventory",
        )
        self.assertTrue(document["report_id"].startswith("AID-"))
        self.assertTrue(document["report_sha256"].startswith("sha256:"))
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertFalse(document["live_shadow_api_verified"])
        self.assertEqual(
            analysis.ApiInventoryDriftReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.ApiInventoryDriftReport.from_dict(document).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_api_inventory_drift(report, model=model).to_json(),
            report.to_json(),
        )
        other = analysis.component_fixture()
        other["route_manifest"]["routes"].clear()
        self.assertNotEqual(model, other)

    def test_fixture_exact_version_and_legacy_candidates(self):
        document = analysis.analyze_supplied_api_inventory_drift(
            analysis.component_fixture()
        ).to_dict()
        self.assertEqual(document["analysis_status"], "complete_matching_scope_projection")
        self.assertEqual(
            [(row["route_id"], row["disposition"]) for row in document["route_outcomes"]],
            [
                ("orders-current", "declared_current_route"),
                ("orders-legacy", "legacy_route_candidate"),
                ("orders-undeclared", "undeclared_route_candidate"),
            ],
        )
        self.assertEqual(
            [row["route_id"] for row in document["undeclared_route_candidates"]],
            ["orders-undeclared"],
        )
        self.assertEqual(document["legacy_route_candidates"][0]["declared_lifecycle"], "legacy")
        self.assertEqual(document["unknowns"], [])

    def test_incomplete_sources_withhold_candidates(self):
        for source in ("approved_inventory", "route_manifest"):
            model = analysis.component_fixture()
            model[source]["complete"] = False
            with self.subTest(source=source):
                document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
                self.assertEqual(document["analysis_status"], "unknown_source_premises")
                self.assertEqual(document["undeclared_route_candidates"], [])
                self.assertEqual(document["legacy_route_candidates"], [])
                self.assertEqual(len(document["unknowns"]), 3)
                self.assertEqual(
                    {row["reason"] for row in document["unknowns"]},
                    {"source_incomplete"},
                )

    def test_scope_mismatch_withholds_candidates(self):
        model = analysis.component_fixture()
        model["route_manifest"]["scope_id"] = "other-scope"
        document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
        self.assertEqual(document["analysis_status"], "unknown_source_premises")
        self.assertEqual(document["undeclared_route_candidates"], [])
        self.assertEqual(document["legacy_route_candidates"], [])
        self.assertEqual(
            {row["reason"] for row in document["unknowns"]},
            {"source_scope_mismatch"},
        )

    def test_empty_incomplete_scope_still_unknown(self):
        model = analysis.component_fixture()
        model["approved_inventory"]["complete"] = False
        model["route_manifest"]["routes"] = []
        document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
        self.assertEqual(
            document["unknowns"],
            [{"route_id": None, "reason": "source_incomplete"}],
        )

    def test_disabled_route_or_deployment_is_excluded_not_candidate(self):
        model = analysis.component_fixture()
        model["route_manifest"]["routes"][1]["enabled"] = False
        model["route_manifest"]["deployments"][0]["active"] = False
        document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
        self.assertEqual(document["legacy_route_candidates"], [])
        self.assertEqual(document["undeclared_route_candidates"], [])
        self.assertEqual(
            {row["disposition"] for row in document["route_outcomes"]},
            {"excluded_by_supplied_inactive_state"},
        )
        model["route_manifest"]["deployments"][0]["active"] = True
        document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
        self.assertEqual(document["legacy_route_candidates"], [])
        self.assertEqual(len(document["undeclared_route_candidates"]), 1)

    def test_retired_declared_route_is_legacy_candidate(self):
        model = analysis.component_fixture()
        model["approved_inventory"]["apis"][1]["lifecycle"] = "retired"
        document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
        self.assertEqual(document["legacy_route_candidates"][0]["declared_lifecycle"], "retired")

    def test_exact_api_version_method_and_path_comparison(self):
        model = analysis.component_fixture()
        route = model["route_manifest"]["routes"][0]
        route["path"] = "/Orders"
        document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
        self.assertIn(
            "orders-current",
            [row["route_id"] for row in document["undeclared_route_candidates"]],
        )
        route["path"] = "/orders"
        route["method"] = "POST"
        document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
        self.assertIn(
            "orders-current",
            [row["route_id"] for row in document["undeclared_route_candidates"]],
        )

    def test_complete_empty_sources_are_narrow_negative(self):
        model = analysis.component_fixture()
        model["approved_inventory"]["apis"] = []
        model["route_manifest"]["routes"] = []
        document = analysis.analyze_supplied_api_inventory_drift(model).to_dict()
        self.assertEqual(document["analysis_status"], "complete_matching_scope_projection")
        self.assertEqual(document["route_outcomes"], [])
        self.assertEqual(document["unknowns"], [])
        self.assertEqual(document["undeclared_route_candidates"], [])

    def test_duplicate_json_keys_rejected_at_nested_levels(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.ApiInventoryDriftError):
            analysis.analyze_supplied_api_inventory_drift_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace('"version":"v2"', '"version":"v2","version":"v3"', 1)
        with self.assertRaises(analysis.ApiInventoryDriftError):
            analysis.analyze_supplied_api_inventory_drift_bytes(model_bytes=text.encode("ascii"))
        report = analysis.analyze_supplied_api_inventory_drift(model)
        changed = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.ApiInventoryDriftError):
            analysis.ApiInventoryDriftReport.from_json(changed)

    def test_duplicate_and_unknown_identities_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["approved_inventory"]["apis"].append(
            copy.deepcopy(model["approved_inventory"]["apis"][0])
        )
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["approved_inventory"]["apis"][0]["routes"].append(
            {"method": "GET", "path": "/orders"}
        )
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_manifest"]["deployments"].append(
            copy.deepcopy(model["route_manifest"]["deployments"][0])
        )
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_manifest"]["routes"][1]["route_id"] = "orders-current"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_manifest"]["routes"][0]["deployment_ref"] = "unknown"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_manifest"]["source_id"] = model["approved_inventory"]["source_id"]
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ApiInventoryDriftError):
                    analysis.analyze_supplied_api_inventory_drift(model)

    def test_canonical_identifiers_versions_and_paths_fail_closed(self):
        base = analysis.component_fixture()
        bad_models = []
        for api_id in ("Orders", "orders_api", " orders", "orders/"):
            model = copy.deepcopy(base)
            model["approved_inventory"]["apis"][0]["api_id"] = api_id
            bad_models.append(model)
        for version in ("v0", "v01", "1", "V1"):
            model = copy.deepcopy(base)
            model["route_manifest"]["routes"][0]["version"] = version
            bad_models.append(model)
        for path in ("/a/../b", "/a//b", "/a%2Fb", "/a?x=1", "api"):
            model = copy.deepcopy(base)
            model["route_manifest"]["routes"][0]["path"] = path
            bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ApiInventoryDriftError):
                    analysis.analyze_supplied_api_inventory_drift(model)

    def test_native_types_and_bounds_fail_closed(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["approved_inventory"]["complete"] = 1
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_manifest"]["routes"][0]["enabled"] = 1
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["schema_version"] = True
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["extra"] = "unexpected"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["route_manifest"]["routes"] *= analysis.MAX_MANIFEST_ROUTES
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ApiInventoryDriftError):
                    analysis.analyze_supplied_api_inventory_drift(model)
        with self.assertRaises(analysis.ApiInventoryDriftError):
            analysis.analyze_supplied_api_inventory_drift_bytes(model_bytes=b"\xff")

    def test_report_tamper_and_separate_source_mismatch(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_api_inventory_drift(model)
        changed = report.to_dict()
        changed["live_shadow_api_verified"] = True
        with self.assertRaises(analysis.ApiInventoryDriftError):
            analysis.ApiInventoryDriftReport.from_dict(changed)
        changed = report.to_dict()
        changed["legacy_route_candidates"] = []
        with self.assertRaises(analysis.ApiInventoryDriftError):
            analysis.ApiInventoryDriftReport.from_json(canonical(changed))
        with self.assertRaises(analysis.ApiInventoryDriftError):
            analysis.ApiInventoryDriftReport.from_json(" " + report.to_json())
        other = copy.deepcopy(model)
        other["route_manifest"]["routes"][0]["enabled"] = False
        with self.assertRaises(analysis.ApiInventoryDriftError):
            analysis.verify_supplied_api_inventory_drift(report, model=other)

    def test_no_scanning_network_process_or_credentials(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            report = analysis.analyze_supplied_api_inventory_drift(analysis.component_fixture())
            effects = report.to_dict()["effects"]
            self.assertEqual(effects["network"], "none")
            self.assertEqual(effects["credential_resolution"], "none")


if __name__ == "__main__":
    unittest.main()
