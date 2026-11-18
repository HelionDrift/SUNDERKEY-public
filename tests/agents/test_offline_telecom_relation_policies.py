"""Synthetic telecom relation-policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_telecom_relation_policies import (
    TelecomRelationPolicyError,
    TelecomRelationPolicyReport,
    analyze_supplied_appliance_management,
    analyze_supplied_mobile_core_relations,
    analyze_supplied_signaling_routes,
    appliance_component_fixture,
    mobile_core_component_fixture,
    signaling_component_fixture,
    verify_supplied_telecom_relations,
)


class TelecomRelationPolicyTests(unittest.TestCase):
    def test_each_specialist_owns_distinct_inert_projection(self) -> None:
        for analyze, fixture, profile, kind in (
            (analyze_supplied_appliance_management, appliance_component_fixture,
             "AOE-GC-D13-S06", "network_appliance"),
            (analyze_supplied_mobile_core_relations, mobile_core_component_fixture,
             "AOE-GC-D13-S11", "mobile_core"),
            (analyze_supplied_signaling_routes, signaling_component_fixture,
             "AOE-GC-D13-S12", "signaling"),
        ):
            with self.subTest(profile=profile):
                model = fixture()
                report = analyze(model)
                body = report.to_dict()
                self.assertEqual(body["profile_id"], profile)
                self.assertEqual(body["relation_kind"], kind)
                self.assertEqual(len(body["outside_supplied_policy_edges"]), 1)
                self.assertFalse(body["network_connected"])
                self.assertFalse(body["packet_sent"])
                self.assertFalse(body["finding_claimed"])
                self.assertEqual(body["candidate_count"], 0)
                self.assertEqual(
                    verify_supplied_telecom_relations(
                        report, model=copy.deepcopy(model), relation_kind=kind
                    ).to_json(), report.to_json(),
                )

    def test_unknown_and_mismatched_kind(self) -> None:
        model = appliance_component_fixture()
        model["inventory_complete"] = False
        self.assertEqual(analyze_supplied_appliance_management(model).to_dict()["disposition"],
                         "unknown")
        with self.assertRaises(TelecomRelationPolicyError):
            analyze_supplied_signaling_routes(model)

    def test_rejects_duplicate_nonsynthetic_and_forged_wrapper(self) -> None:
        model = mobile_core_component_fixture()
        model["declared_edges"].append(copy.deepcopy(model["declared_edges"][0]))
        with self.assertRaises(TelecomRelationPolicyError):
            analyze_supplied_mobile_core_relations(model)
        model = mobile_core_component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(TelecomRelationPolicyError):
            analyze_supplied_mobile_core_relations(model)
        with self.assertRaises(TelecomRelationPolicyError):
            TelecomRelationPolicyReport({})


if __name__ == "__main__":
    unittest.main()
