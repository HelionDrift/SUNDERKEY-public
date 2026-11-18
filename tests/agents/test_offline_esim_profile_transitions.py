"""Synthetic eSIM transition projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_esim_profile_transitions import (
    EsimProfileTransitionError,
    EsimProfileTransitionReport,
    analyze_supplied_esim_profile_transitions,
    component_fixture,
    verify_supplied_esim_profile_transitions,
)


class EsimProfileTransitionTests(unittest.TestCase):
    def test_outside_transition_is_not_provisioning(self) -> None:
        report = analyze_supplied_esim_profile_transitions(component_fixture()).to_dict()
        self.assertEqual(report["declared_transition_deviation_event_ids"], ["event-a"])
        self.assertFalse(report["esim_service_connected"])
        self.assertFalse(report["profile_provisioned"])
        self.assertFalse(report["subscriber_data_accessed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_discontinuous_sequence_remains_unknown(self) -> None:
        model = component_fixture()
        model["profile_events"].append({
            "event_id": "event-b", "profile_ref": "profile-opaque-a",
            "sequence": 2, "from_state": "disabled", "to_state": "enabled",
        })
        report = analyze_supplied_esim_profile_transitions(model).to_dict()
        self.assertEqual(report["sequence_uncertainty_event_ids"], ["event-b"])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["profile_events"].append(copy.deepcopy(model["profile_events"][0]))
        with self.assertRaises(EsimProfileTransitionError):
            analyze_supplied_esim_profile_transitions(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(EsimProfileTransitionError):
            analyze_supplied_esim_profile_transitions(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_esim_profile_transitions(model)
        self.assertEqual(
            verify_supplied_esim_profile_transitions(
                report, model=copy.deepcopy(model)
            ).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["profile_events"][0]["to_state"] = "disabled"
        with self.assertRaises(EsimProfileTransitionError):
            verify_supplied_esim_profile_transitions(report, model=changed)
        with self.assertRaises(EsimProfileTransitionError):
            EsimProfileTransitionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
