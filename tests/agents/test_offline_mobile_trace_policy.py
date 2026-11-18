"""Synthetic mobile trace policy boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_mobile_trace_policy import (
    MobileTracePolicyError,
    MobileTracePolicyReport,
    analyze_supplied_android_device_trust,
    analyze_supplied_android_instrumentation,
    analyze_supplied_ios_device_trust,
    analyze_supplied_ios_instrumentation,
    component_fixture,
    verify_supplied_mobile_trace,
)

CASES = (
    ("android_instrumentation", "AOE-GB-D08-S02", analyze_supplied_android_instrumentation),
    ("android_device_trust", "AOE-GB-D08-S04", analyze_supplied_android_device_trust),
    ("ios_instrumentation", "AOE-GB-D08-S06", analyze_supplied_ios_instrumentation),
    ("ios_device_trust", "AOE-GB-D08-S08", analyze_supplied_ios_device_trust),
)


class MobileTracePolicyTests(unittest.TestCase):
    def test_four_profiles_have_distinct_inert_projections(self) -> None:
        for kind, profile, analyze in CASES:
            with self.subTest(profile=profile):
                model = component_fixture(kind)
                report = analyze(model)
                body = report.to_dict()
                self.assertEqual(body["profile_id"], profile)
                self.assertEqual(body["outside_supplied_policy_event_refs"], ["event-opaque-a"])
                self.assertFalse(body["device_connected"])
                self.assertFalse(body["instrumentation_run"])
                self.assertFalse(body["device_trust_changed"])
                self.assertEqual(body["candidate_count"], 0)
                self.assertEqual(
                    verify_supplied_mobile_trace(
                        report, model=copy.deepcopy(model), trace_kind=kind
                    ).to_json(), report.to_json(),
                )

    def test_discontinuity_remains_unknown(self) -> None:
        model = component_fixture("android_instrumentation")
        model["trace_events"].append({
            "event_ref": "event-opaque-b", "sequence": 2,
            "from_state": "baseline", "to_state": "test_observation",
        })
        body = analyze_supplied_android_instrumentation(model).to_dict()
        self.assertEqual(body["discontinuous_event_refs"], ["event-opaque-b"])
        self.assertEqual(body["disposition"], "unknown")

    def test_rejects_wrong_kind_duplicate_and_nonsynthetic(self) -> None:
        model = component_fixture("ios_device_trust")
        with self.assertRaises(MobileTracePolicyError):
            analyze_supplied_android_device_trust(model)
        model["trace_events"].append(copy.deepcopy(model["trace_events"][0]))
        with self.assertRaises(MobileTracePolicyError):
            analyze_supplied_ios_device_trust(model)
        model = component_fixture("ios_device_trust")
        model["synthetic_fixture"] = False
        with self.assertRaises(MobileTracePolicyError):
            analyze_supplied_ios_device_trust(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture("ios_instrumentation")
        report = analyze_supplied_ios_instrumentation(model)
        changed = copy.deepcopy(model)
        changed["trace_events"][0]["to_state"] = "test_observation"
        with self.assertRaises(MobileTracePolicyError):
            verify_supplied_mobile_trace(report, model=changed, trace_kind="ios_instrumentation")
        with self.assertRaises(MobileTracePolicyError):
            MobileTracePolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
