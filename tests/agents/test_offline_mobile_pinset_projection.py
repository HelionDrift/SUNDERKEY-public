"""Bounded synthetic mobile pinset metadata projections."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_mobile_pinset_projection import (
    MobilePinsetProjectionError,
    MobilePinsetProjectionReport,
    analyze_supplied_mobile_pinsets,
    component_fixture,
    verify_supplied_mobile_pinsets,
)


class MobilePinsetProjectionTests(unittest.TestCase):
    def test_declared_subdomain_and_nonexpired_pair_are_only_projections(self) -> None:
        report = analyze_supplied_mobile_pinsets(component_fixture()).to_dict()
        self.assertEqual(report["supplied_host_count"], 2)
        self.assertEqual(report["uncovered_host_ids"], [])
        self.assertEqual(report["pinset_projections"][0]["matched_host_ids"], ["admin", "api"])
        self.assertTrue(report["pinset_projections"][0]["declared_nonexpired_pair_present"])
        self.assertFalse(report["tls_handshake_performed"])
        self.assertFalse(report["pinning_enforced"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_expiry_and_exact_domain_matching(self) -> None:
        model = component_fixture()
        model["pinsets"][0]["include_subdomains"] = False
        model["evaluation_day"] = "2028-01-01"
        report = analyze_supplied_mobile_pinsets(model).to_dict()
        self.assertEqual(report["uncovered_host_ids"], ["admin", "api"])
        self.assertEqual(report["expired_pinset_ids"], ["base"])
        self.assertFalse(report["pinset_projections"][0]["declared_nonexpired_pair_present"])

    def test_overlap_and_incomplete_inventory_remain_uncertain(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["pinsets"].append({
            "pinset_id": "api-only", "domain": "api.example.invalid",
            "include_subdomains": False,
            "pins": [{
                "pin_id": "api-primary", "spki_sha256_hex": "3" * 64,
                "not_after_day": "2027-01-01", "backup": False,
            }],
        })
        report = analyze_supplied_mobile_pinsets(model).to_dict()
        self.assertEqual(report["overlapping_host_ids"], ["api"])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_malformed_and_duplicate_declarations(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MobilePinsetProjectionError):
            analyze_supplied_mobile_pinsets(model)
        model = component_fixture()
        model["hosts"][0]["hostname"] = "API.example.invalid"
        with self.assertRaises(MobilePinsetProjectionError):
            analyze_supplied_mobile_pinsets(model)
        model = component_fixture()
        model["pinsets"][0]["pins"][1]["spki_sha256_hex"] = "1" * 64
        with self.assertRaises(MobilePinsetProjectionError):
            analyze_supplied_mobile_pinsets(model)
        model = component_fixture()
        model["pinsets"][0]["pins"][0]["not_after_day"] = "2027-02-30"
        with self.assertRaises(MobilePinsetProjectionError):
            analyze_supplied_mobile_pinsets(model)

    def test_original_model_replay_and_owned_report(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mobile_pinsets(model)
        self.assertEqual(
            verify_supplied_mobile_pinsets(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["pinsets"][0]["include_subdomains"] = False
        with self.assertRaises(MobilePinsetProjectionError):
            verify_supplied_mobile_pinsets(report, model=changed)
        with self.assertRaises(MobilePinsetProjectionError):
            MobilePinsetProjectionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
