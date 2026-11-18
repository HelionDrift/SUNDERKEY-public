"""Synthetic enterprise legacy grant-policy boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_legacy_platform_grant_policy import (
    LegacyGrantPolicyError,
    LegacyGrantPolicyReport,
    analyze_supplied_ibmi_grants,
    analyze_supplied_oracle_enterprise_grants,
    analyze_supplied_sap_grants,
    analyze_supplied_unix_enterprise_grants,
    analyze_supplied_zos_grants,
    component_fixture,
    verify_supplied_legacy_grants,
)

CASES = (
    ("zos", "AOE-GC-D16-S01", analyze_supplied_zos_grants),
    ("ibmi", "AOE-GC-D16-S02", analyze_supplied_ibmi_grants),
    ("unix_enterprise", "AOE-GC-D16-S03", analyze_supplied_unix_enterprise_grants),
    ("sap", "AOE-GC-D16-S04", analyze_supplied_sap_grants),
    ("oracle_enterprise", "AOE-GC-D16-S05", analyze_supplied_oracle_enterprise_grants),
)


class LegacyGrantPolicyTests(unittest.TestCase):
    def test_each_profile_is_distinct_and_inert(self) -> None:
        for kind, profile, analyze in CASES:
            with self.subTest(profile=profile):
                model = component_fixture(kind)
                report = analyze(model)
                body = report.to_dict()
                self.assertEqual(body["profile_id"], profile)
                self.assertEqual(body["platform_kind"], kind)
                self.assertEqual(len(body["outside_supplied_policy_grants"]), 1)
                self.assertFalse(body["platform_connected"])
                self.assertFalse(body["credential_used"])
                self.assertFalse(body["grant_changed"])
                self.assertEqual(body["candidate_count"], 0)
                self.assertEqual(
                    verify_supplied_legacy_grants(
                        report, model=copy.deepcopy(model), platform_kind=kind
                    ).to_json(), report.to_json(),
                )

    def test_incomplete_inventory_remains_unknown(self) -> None:
        model = component_fixture("zos")
        model["inventory_complete"] = False
        self.assertEqual(analyze_supplied_zos_grants(model).to_dict()["disposition"],
                         "unknown")

    def test_wrong_kind_duplicate_and_nonsynthetic_reject(self) -> None:
        model = component_fixture("sap")
        with self.assertRaises(LegacyGrantPolicyError):
            analyze_supplied_ibmi_grants(model)
        model["declared_grants"].append(copy.deepcopy(model["declared_grants"][0]))
        with self.assertRaises(LegacyGrantPolicyError):
            analyze_supplied_sap_grants(model)
        model = component_fixture("sap")
        model["synthetic_fixture"] = False
        with self.assertRaises(LegacyGrantPolicyError):
            analyze_supplied_sap_grants(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture("ibmi")
        report = analyze_supplied_ibmi_grants(model)
        changed = copy.deepcopy(model)
        changed["declared_grants"][0]["principal_ref"] = "principal-a"
        with self.assertRaises(LegacyGrantPolicyError):
            verify_supplied_legacy_grants(report, model=changed, platform_kind="ibmi")
        with self.assertRaises(LegacyGrantPolicyError):
            LegacyGrantPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
