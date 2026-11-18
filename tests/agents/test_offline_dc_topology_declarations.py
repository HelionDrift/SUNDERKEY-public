"""Bounded domain-controller topology declaration tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_dc_topology_declarations import (
    DcTopologyDeclarationsError,
    analyze_supplied_dc_topology,
    component_fixture,
    verify_supplied_dc_topology,
    verify_supplied_dc_topology_bytes,
)


class DcTopologyDeclarationsTests(unittest.TestCase):
    def test_candidate_is_only_a_supplied_topology_mismatch(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        report = analyze_supplied_dc_topology(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 2)
        self.assertIn("backup_age_exceeds_supplied_policy", body["rows"][1]["policy_issues"])
        self.assertIn("expected_link_declared_disabled", body["rows"][2]["policy_issues"])
        self.assertFalse(body["replication_observed"])
        self.assertFalse(body["directory_database_read"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_dc_topology(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_dc_topology_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_clean_and_incomplete_models(self) -> None:
        model = component_fixture()
        model["controllers"][1]["backup_age_days"] = 3
        model["declared_links"][0]["enabled"] = True
        self.assertEqual(analyze_supplied_dc_topology(model).to_dict()["candidate_count"], 0)
        model["inventory_complete"] = False
        model["declared_links"] = []
        body = analyze_supplied_dc_topology(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 3)
        self.assertIsNone(body["rows"][2]["policy_issues"])

    def test_malformed_and_tampered_inputs_fail(self) -> None:
        model = component_fixture()
        model["controllers"][0]["controller_ref"] = "dc01"
        with self.assertRaises(ValueError):
            analyze_supplied_dc_topology(model)
        model = component_fixture()
        model["controllers"].append(copy.deepcopy(model["controllers"][0]))
        with self.assertRaises(ValueError):
            analyze_supplied_dc_topology(model)
        model = component_fixture()
        model["policy"]["max_backup_age_days"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_dc_topology(model)
        model = component_fixture()
        report = analyze_supplied_dc_topology(model)
        changed = copy.deepcopy(model)
        changed["declared_links"][0]["enabled"] = True
        with self.assertRaises(DcTopologyDeclarationsError):
            verify_supplied_dc_topology(report, model=changed)
        with self.assertRaises(DcTopologyDeclarationsError):
            verify_supplied_dc_topology(report.to_dict(), model=model)
        with self.assertRaises(DcTopologyDeclarationsError):
            verify_supplied_dc_topology_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_dc_topology_bytes(b'{"x":1,"x":2}', model=model)


if __name__ == "__main__":
    unittest.main()
