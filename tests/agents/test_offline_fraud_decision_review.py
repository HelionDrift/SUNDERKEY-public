"""Coarse supplied fraud decisions are not proof of evasion."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_fraud_decision_review import (
    FraudDecisionReview,
    FraudDecisionReviewError,
    analyze_supplied_fraud_decisions,
    verify_supplied_fraud_decisions,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-fraud-decision-review-v1",
        "policy_ref": "policy:sha256:" + "a" * 64,
        "minimum_action_by_band": {"low": "allow", "medium": "challenge", "high": "block"},
        "events": [
            {
                "event_id": "e1",
                "subject_ref": "subject:sha256:" + "b" * 64,
                "risk_band": "low",
                "declared_minimum_action": "allow",
                "decision": "challenge",
            },
            {
                "event_id": "e2",
                "subject_ref": "subject:sha256:" + "c" * 64,
                "risk_band": "high",
                "declared_minimum_action": "challenge",
                "decision": "allow",
            },
        ],
    }


class FraudDecisionReviewTests(unittest.TestCase):
    def test_floor_mismatch_and_below_floor_are_separate_signals(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_fraud_decisions(model)
        body = report.to_dict()
        self.assertEqual(body["events"][0]["expected_minimum_action"], "allow")
        self.assertEqual(body["events"][0]["anomaly_flags"], [])
        self.assertEqual(
            body["events"][1]["anomaly_flags"],
            ["decision_below_supplied_policy_floor", "declared_floor_mismatch"],
        )
        self.assertFalse(body["flags"]["fraud_or_evasion_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_fraud_decisions(report, model=model).to_json(), report.to_json()
        )

    def test_advertised_event_limit_has_bounded_report(self):
        model = _model()
        model["events"] = [
            {**model["events"][0], "event_id": "e" + str(index).zfill(127)} for index in range(512)
        ]
        report = analyze_supplied_fraud_decisions(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertLessEqual(len(report.to_json()), 524_288)

    def test_plain_policy_non_native_action_duplicate_id_and_tamper_are_refused(self):
        model = _model()
        model["policy_ref"] = "production-policy"
        with self.assertRaises(FraudDecisionReviewError):
            analyze_supplied_fraud_decisions(model)
        model = _model()
        model["events"][0]["decision"] = object()
        with self.assertRaises(FraudDecisionReviewError):
            analyze_supplied_fraud_decisions(model)
        model = _model()
        model["events"][1]["event_id"] = "e1"
        with self.assertRaises(FraudDecisionReviewError):
            analyze_supplied_fraud_decisions(model)
        model = _model()
        model["minimum_action_by_band"]["medium"] = True
        with self.assertRaises(FraudDecisionReviewError):
            analyze_supplied_fraud_decisions(model)
        body = analyze_supplied_fraud_decisions(_model()).to_dict()
        body["flags"]["fraud_or_evasion_proven"] = True
        with self.assertRaises(FraudDecisionReviewError):
            FraudDecisionReview(body)
        report = analyze_supplied_fraud_decisions(_model())
        changed = _model()
        changed["minimum_action_by_band"]["high"] = "challenge"
        with self.assertRaises(FraudDecisionReviewError):
            verify_supplied_fraud_decisions(report, model=changed)


if __name__ == "__main__":
    unittest.main()
