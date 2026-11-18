"""Synthetic O-RAN policy-target projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_oran_policy_targets import (
    OranPolicyTargetError,
    OranPolicyTargetReport,
    analyze_supplied_oran_policy_targets,
    component_fixture,
    verify_supplied_oran_policy_targets,
)


class OranPolicyTargetTests(unittest.TestCase):
    def test_type_mismatch_is_not_policy_application(self) -> None:
        report = analyze_supplied_oran_policy_targets(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_intent_ids"], ["intent-a"])
        self.assertFalse(report["ric_connected"])
        self.assertFalse(report["a1_request_sent"])
        self.assertFalse(report["policy_applied"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_unknown_ric_remains_unknown(self) -> None:
        model = component_fixture()
        model["policy_intents"][0]["ric_id"] = "ric-b"
        report = analyze_supplied_oran_policy_targets(model).to_dict()
        self.assertEqual(report["unknown_target_intent_ids"], ["intent-a"])
        self.assertEqual(report["declared_policy_deviation_intent_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["policy_intents"].append(copy.deepcopy(model["policy_intents"][0]))
        with self.assertRaises(OranPolicyTargetError):
            analyze_supplied_oran_policy_targets(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(OranPolicyTargetError):
            analyze_supplied_oran_policy_targets(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_oran_policy_targets(model)
        self.assertEqual(
            verify_supplied_oran_policy_targets(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["policy_intents"][0]["policy_type_id"] = "policy-type-a"
        with self.assertRaises(OranPolicyTargetError):
            verify_supplied_oran_policy_targets(report, model=changed)
        with self.assertRaises(OranPolicyTargetError):
            OranPolicyTargetReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
