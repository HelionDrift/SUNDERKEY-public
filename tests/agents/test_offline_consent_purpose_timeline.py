"""Supplied consent events are not proof of lawful or unlawful processing."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_consent_purpose_timeline import (
    ConsentPurposeTimeline,
    ConsentPurposeTimelineError,
    analyze_supplied_consent_purposes,
    verify_supplied_consent_purposes,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-consent-purpose-timeline-v1",
        "subject_ref": "subject:sha256:" + "a" * 64,
        "purposes": ["analytics", "marketing"],
        "events": [
            {
                "event_id": "e1",
                "purpose_id": "marketing",
                "action": "grant",
                "declared_active_after": True,
                "source_id": "fixture",
            },
            {
                "event_id": "e2",
                "purpose_id": "marketing",
                "action": "process",
                "declared_active_after": True,
                "source_id": "fixture",
            },
            {
                "event_id": "e3",
                "purpose_id": "marketing",
                "action": "withdraw",
                "declared_active_after": False,
                "source_id": "fixture",
            },
            {
                "event_id": "e4",
                "purpose_id": "marketing",
                "action": "process",
                "declared_active_after": False,
                "source_id": "fixture",
            },
            {
                "event_id": "e5",
                "purpose_id": "analytics",
                "action": "grant",
                "declared_active_after": False,
                "source_id": "fixture",
            },
            {
                "event_id": "e6",
                "purpose_id": "analytics",
                "action": "withdraw",
                "declared_active_after": False,
                "source_id": "fixture",
            },
        ],
    }


class ConsentPurposeTimelineTests(unittest.TestCase):
    def test_purpose_specific_state_and_processing_signal_are_distinct(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_consent_purposes(model)
        body = report.to_dict()
        rows = body["events"]
        self.assertEqual(rows[1]["anomaly_flags"], [])
        self.assertEqual(rows[3]["anomaly_flags"], ["processing_without_local_grant"])
        self.assertEqual(rows[4]["anomaly_flags"], ["declared_active_state_mismatch"])
        self.assertEqual(body["final_active_purposes"], [])
        self.assertFalse(body["flags"]["lawful_basis_assessed"])
        self.assertFalse(body["flags"]["processing_observed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_consent_purposes(report, model=model).to_dict(), body)

    def test_repeated_grant_and_withdrawal_without_local_grant(self):
        model = _model()
        model["events"].append(
            {
                "event_id": "e7",
                "purpose_id": "analytics",
                "action": "withdraw",
                "declared_active_after": False,
                "source_id": "fixture",
            }
        )
        model["events"].insert(
            1,
            {
                "event_id": "e8",
                "purpose_id": "marketing",
                "action": "grant",
                "declared_active_after": True,
                "source_id": "fixture",
            },
        )
        rows = analyze_supplied_consent_purposes(model).to_dict()["events"]
        self.assertEqual(rows[1]["anomaly_flags"], ["repeated_declared_grant"])
        self.assertEqual(rows[-1]["anomaly_flags"], ["withdrawal_without_local_grant"])

    def test_maximum_event_count_has_bounded_report(self):
        model = _model()
        model["events"] = [
            {**model["events"][0], "event_id": "e" + str(index).zfill(127)} for index in range(512)
        ]
        report = analyze_supplied_consent_purposes(model)
        self.assertEqual(len(report.to_dict()["events"]), 512)
        self.assertLessEqual(len(report.to_json()), 524_288)
        self.assertEqual(
            verify_supplied_consent_purposes(report, model=model).to_json(),
            report.to_json(),
        )

    def test_malformed_purpose_boolean_non_native_and_tamper_are_refused(self):
        for field, value in (
            ("subject_ref", "real-email"),
            ("purposes", ["analytics", "analytics"]),
            ("schema_version", True),
        ):
            with self.subTest(field=field):
                model = _model()
                model[field] = value
                with self.assertRaises(ConsentPurposeTimelineError):
                    analyze_supplied_consent_purposes(model)
        model = _model()
        model["events"][0]["purpose_id"] = "other"
        with self.assertRaises(ConsentPurposeTimelineError):
            analyze_supplied_consent_purposes(model)

        class ComparisonTrap:
            def __eq__(self, other):
                raise AssertionError("Non-native value was compared")

        model = _model()
        model["events"][0]["action"] = ComparisonTrap()
        with self.assertRaises(ConsentPurposeTimelineError):
            analyze_supplied_consent_purposes(model)
        body = analyze_supplied_consent_purposes(_model()).to_dict()
        body["flags"]["processing_observed"] = True
        with self.assertRaises(ConsentPurposeTimelineError):
            ConsentPurposeTimeline(body)
        report = analyze_supplied_consent_purposes(_model())
        model = _model()
        model["events"][0]["action"] = "withdraw"
        with self.assertRaises(ConsentPurposeTimelineError):
            verify_supplied_consent_purposes(report, model=model)


if __name__ == "__main__":
    unittest.main()
