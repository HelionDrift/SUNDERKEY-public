"""Synthetic receive-only RF declaration boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_rf_capture_declarations import (
    RfReceivePolicyError,
    RfReceivePolicyReport,
    analyze_supplied_rf_receive_policy,
    component_fixture,
    verify_supplied_rf_receive_policy,
)


class RfReceivePolicyTests(unittest.TestCase):
    def test_band_mismatch_has_no_radio_effect(self) -> None:
        body = analyze_supplied_rf_receive_policy(component_fixture()).to_dict()
        self.assertEqual(body["outside_supplied_band_capture_refs"], ["capture-opaque-a"])
        self.assertFalse(body["receiver_connected"])
        self.assertFalse(body["transmitter_connected"])
        self.assertFalse(body["rf_signal_observed"])
        self.assertFalse(body["subscriber_data_accessed"])
        self.assertEqual(body["candidate_count"], 0)

    def test_non_receive_only_declaration_is_unknown(self) -> None:
        model = component_fixture()
        model["capture_declarations"][0]["receive_only_declared"] = False
        body = analyze_supplied_rf_receive_policy(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")

    def test_rejects_duplicates_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["capture_declarations"].append(copy.deepcopy(model["capture_declarations"][0]))
        with self.assertRaises(RfReceivePolicyError):
            analyze_supplied_rf_receive_policy(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(RfReceivePolicyError):
            analyze_supplied_rf_receive_policy(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_rf_receive_policy(model)
        self.assertEqual(
            verify_supplied_rf_receive_policy(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["approved_band_labels"] = ["band-b"]
        with self.assertRaises(RfReceivePolicyError):
            verify_supplied_rf_receive_policy(report, model=changed)
        with self.assertRaises(RfReceivePolicyError):
            RfReceivePolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
