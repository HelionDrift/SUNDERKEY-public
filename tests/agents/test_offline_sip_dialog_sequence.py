"""Synthetic SIP dialog sequence projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_sip_dialog_sequence import (
    SipDialogSequenceError,
    SipDialogSequenceReport,
    analyze_supplied_sip_dialog,
    component_fixture,
    verify_supplied_sip_dialog,
)


class SipDialogSequenceTests(unittest.TestCase):
    def test_declared_sequence_is_not_sip_conformance(self) -> None:
        report = analyze_supplied_sip_dialog(component_fixture()).to_dict()
        self.assertEqual(report["declared_sequence_deviation_event_ids"], [])
        self.assertEqual(report["final_declared_state"], "terminated")
        self.assertFalse(report["sip_messages_parsed"])
        self.assertFalse(report["sip_conformance_verified"])
        self.assertFalse(report["network_call_performed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_ack_cseq_mismatch_and_bye_before_confirmation(self) -> None:
        model = component_fixture()
        model["events"][3]["cseq"] = 3
        report = analyze_supplied_sip_dialog(model).to_dict()
        self.assertEqual(report["declared_sequence_deviation_event_ids"], ["e4", "e5", "e6"])
        self.assertEqual(report["event_projections"][3]["declared_sequence_flags"], [
            "ack_cseq_mismatch",
        ])
        self.assertEqual(report["final_declared_state"], "accepted")

    def test_incomplete_trace_and_invalid_dialog_shape(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        self.assertEqual(analyze_supplied_sip_dialog(model).to_dict()["disposition"], "unknown")
        model = component_fixture()
        model["single_nonforked_dialog_asserted"] = False
        with self.assertRaises(SipDialogSequenceError):
            analyze_supplied_sip_dialog(model)
        model = component_fixture()
        model["events"].append(copy.deepcopy(model["events"][0]))
        with self.assertRaises(SipDialogSequenceError):
            analyze_supplied_sip_dialog(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_sip_dialog(model)
        self.assertEqual(
            verify_supplied_sip_dialog(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["events"][3]["cseq"] = 3
        with self.assertRaises(SipDialogSequenceError):
            verify_supplied_sip_dialog(report, model=changed)
        with self.assertRaises(SipDialogSequenceError):
            SipDialogSequenceReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
