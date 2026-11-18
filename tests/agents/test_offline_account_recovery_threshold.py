"""Supplied factor thresholds are not account-recovery proof."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_account_recovery_threshold import (
    AccountRecoveryThreshold,
    AccountRecoveryThresholdError,
    analyze_supplied_account_recovery,
    verify_supplied_account_recovery,
)


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def _model() -> dict:
    a = _ref("factor", "a")
    b = _ref("factor", "b")
    c = _ref("factor", "c")
    unknown = _ref("factor", "d")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-account-recovery-threshold-v1",
        "account_ref": _ref("account", "e"),
        "enrolled_factor_refs": [a, b, c],
        "required_factor_count": 2,
        "attempts": [
            {
                "attempt_id": "a1",
                "presented_factor_refs": [a, b],
                "result": "accepted",
                "declared_reset_performed": True,
            },
            {
                "attempt_id": "a2",
                "presented_factor_refs": [a],
                "result": "accepted",
                "declared_reset_performed": True,
            },
            {
                "attempt_id": "a3",
                "presented_factor_refs": [a, unknown],
                "result": "accepted",
                "declared_reset_performed": True,
            },
            {
                "attempt_id": "a4",
                "presented_factor_refs": [a, b],
                "result": "rejected",
                "declared_reset_performed": False,
            },
            {
                "attempt_id": "a5",
                "presented_factor_refs": [a, b],
                "result": "rejected",
                "declared_reset_performed": True,
            },
        ],
    }


class AccountRecoveryThresholdTests(unittest.TestCase):
    def test_threshold_unenrolled_label_and_reset_mismatch_are_distinct(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_account_recovery(model)
        body = report.to_dict()
        rows = body["attempts"]
        self.assertEqual(rows[0]["anomaly_flags"], [])
        self.assertEqual(rows[1]["anomaly_flags"], ["accepted_below_supplied_factor_threshold"])
        self.assertEqual(
            rows[2]["anomaly_flags"],
            ["accepted_below_supplied_factor_threshold", "accepted_with_unenrolled_factor_label"],
        )
        self.assertEqual(rows[3]["anomaly_flags"], ["rejected_despite_supplied_factor_threshold"])
        self.assertEqual(
            rows[4]["anomaly_flags"],
            ["declared_reset_result_mismatch", "rejected_despite_supplied_factor_threshold"],
        )
        self.assertFalse(body["flags"]["factor_possession_proven"])
        self.assertFalse(body["flags"]["account_takeover_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_account_recovery(report, model=model).to_dict(), body)

    def test_maximum_attempt_count_has_bounded_report(self):
        model = _model()
        model["attempts"] = [
            {**model["attempts"][0], "attempt_id": "a" + str(index).zfill(127)}
            for index in range(256)
        ]
        report = analyze_supplied_account_recovery(model)
        self.assertEqual(len(report.to_dict()["attempts"]), 256)
        self.assertLessEqual(len(report.to_json()), 524_288)
        self.assertEqual(
            verify_supplied_account_recovery(report, model=model).to_json(),
            report.to_json(),
        )

    def test_plain_account_duplicate_factor_non_native_and_tamper_are_refused(self):
        model = _model()
        model["account_ref"] = "customer@example.com"
        with self.assertRaises(AccountRecoveryThresholdError):
            analyze_supplied_account_recovery(model)
        model = _model()
        model["enrolled_factor_refs"].append(model["enrolled_factor_refs"][0])
        with self.assertRaises(AccountRecoveryThresholdError):
            analyze_supplied_account_recovery(model)
        model = _model()
        model["required_factor_count"] = True
        with self.assertRaises(AccountRecoveryThresholdError):
            analyze_supplied_account_recovery(model)
        model = _model()
        model["attempts"][0]["presented_factor_refs"] = [model["enrolled_factor_refs"][0]] * 2
        with self.assertRaises(AccountRecoveryThresholdError):
            analyze_supplied_account_recovery(model)

        class ComparisonTrap:
            def __eq__(self, other):
                raise AssertionError("Non-native value was compared")

        model = _model()
        model["attempts"][0]["result"] = ComparisonTrap()
        with self.assertRaises(AccountRecoveryThresholdError):
            analyze_supplied_account_recovery(model)
        body = analyze_supplied_account_recovery(_model()).to_dict()
        body["flags"]["account_takeover_proven"] = True
        with self.assertRaises(AccountRecoveryThresholdError):
            AccountRecoveryThreshold(body)
        report = analyze_supplied_account_recovery(_model())
        model = _model()
        model["attempts"][0]["result"] = "rejected"
        with self.assertRaises(AccountRecoveryThresholdError):
            verify_supplied_account_recovery(report, model=model)


if __name__ == "__main__":
    unittest.main()
