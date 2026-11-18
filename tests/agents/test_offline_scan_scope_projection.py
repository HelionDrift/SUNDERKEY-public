"""Synthetic scan-scope projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_scan_scope_projection import (
    ScanScopeProjectionError,
    ScanScopeProjectionReport,
    analyze_supplied_scan_scopes,
    component_fixture,
    verify_supplied_scan_scopes,
)


class ScanScopeProjectionTests(unittest.TestCase):
    def test_outside_declaration_is_not_scan_or_authorization(self) -> None:
        report = analyze_supplied_scan_scopes(component_fixture()).to_dict()
        self.assertEqual(report["outside_supplied_scope_proposal_ids"], ["outside"])
        self.assertFalse(report["scope_authorized"])
        self.assertFalse(report["dns_resolved"])
        self.assertFalse(report["packet_sent"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_ipv6_containment_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["proposals"] = [{"proposal_id": "v6", "cidr": "2001:db8:1::/48"}]
        model["inventory_complete"] = False
        report = analyze_supplied_scan_scopes(model).to_dict()
        self.assertTrue(report["proposal_projections"][0]["within_supplied_scope"])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_host_bits_duplicate_and_nonfixture(self) -> None:
        model = component_fixture()
        model["proposals"][0]["cidr"] = "192.0.2.129/25"
        with self.assertRaises(ScanScopeProjectionError):
            analyze_supplied_scan_scopes(model)
        model = component_fixture()
        model["proposals"][1]["proposal_id"] = "within"
        with self.assertRaises(ScanScopeProjectionError):
            analyze_supplied_scan_scopes(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(ScanScopeProjectionError):
            analyze_supplied_scan_scopes(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_scan_scopes(model)
        self.assertEqual(
            verify_supplied_scan_scopes(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["proposals"][1]["cidr"] = "203.0.113.0/24"
        with self.assertRaises(ScanScopeProjectionError):
            verify_supplied_scan_scopes(report, model=changed)
        with self.assertRaises(ScanScopeProjectionError):
            ScanScopeProjectionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
