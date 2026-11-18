"""Supplied sequential trial accounting and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_chain_trial_accounting import (
    ChainTrialAccountingError,
    ChainTrialAccountingReport,
    analyze_supplied_chain_trials,
    component_fixture,
    verify_supplied_chain_trials,
)


class ChainTrialAccountingTests(unittest.TestCase):
    def test_stage_and_environment_counts_are_only_supplied_accounting(self) -> None:
        report = analyze_supplied_chain_trials(component_fixture()).to_dict()
        self.assertEqual(report["trial_count"], 3)
        self.assertEqual(report["complete_success_count"], 1)
        self.assertEqual(report["first_failure_count"], 2)
        self.assertEqual(
            [(row["attempted_count"], row["success_count"], row["first_failure_count"])
             for row in report["stage_summary"]],
            [(3, 2, 1), (2, 1, 1), (1, 1, 0)],
        )
        self.assertEqual(report["environment_summary"][0]["trial_count"], 2)
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["trial_execution_verified"])
        self.assertFalse(report["exploit_reliability_established"])

    def test_trial_order_does_not_change_counts(self) -> None:
        model = component_fixture()
        first = analyze_supplied_chain_trials(model).to_dict()
        model["trials"].reverse()
        second = analyze_supplied_chain_trials(model).to_dict()
        self.assertEqual(first["stage_summary"], second["stage_summary"])
        self.assertEqual(first["environment_summary"], second["environment_summary"])

    def test_incomplete_inventory_is_unknown(self) -> None:
        model = component_fixture()
        model["trial_inventory_complete"] = False
        report = analyze_supplied_chain_trials(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["complete_success_count"], 1)

    def test_rejects_skipped_or_post_failure_stage(self) -> None:
        model = component_fixture()
        model["trials"][1]["stage_outcomes"] = [True, False, True]
        with self.assertRaises(ChainTrialAccountingError):
            analyze_supplied_chain_trials(model)
        model = component_fixture()
        model["trials"][0]["stage_outcomes"] = [None, True, True]
        with self.assertRaises(ChainTrialAccountingError):
            analyze_supplied_chain_trials(model)
        model = component_fixture()
        model["trials"].append(copy.deepcopy(model["trials"][0]))
        with self.assertRaises(ChainTrialAccountingError):
            analyze_supplied_chain_trials(model)

    def test_original_source_replay_required(self) -> None:
        model = component_fixture()
        report = analyze_supplied_chain_trials(model)
        self.assertEqual(
            verify_supplied_chain_trials(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["trials"][0]["environment_id"] = "fixture_b"
        with self.assertRaises(ChainTrialAccountingError):
            verify_supplied_chain_trials(report, model=changed)
        with self.assertRaises(ChainTrialAccountingError):
            ChainTrialAccountingReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
